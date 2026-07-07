import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from requests.cookies import RequestsCookieJar
from modules.cves import cve_2024_21546 as m

# Regression for the live-validation FAIL on labs :35001 (scart, lfm 2.8.1) and :41013
# (badaso, lfm 2.6.4). Both pin unisharp/laravel-filemanager < 2.9.1 and ALIAS composer.lock
# into the webroot as the authoritative unauth version signal — but the detector had NO
# composer.lock version-gate (0 refs); its only path was the active upload, which both labs
# auth-gate, so an unauthenticated run missed applicability evidence.
# Fix: probe /composer.lock and report version_applicable on lfm < 2.9.1; active upload proves confirmed_vulnerable.

LOCK_VULN = '{"packages":[{"name":"unisharp/laravel-filemanager","version":"2.6.4"}]}'
LOCK_PATCHED = '{"packages":[{"name":"unisharp/laravel-filemanager","version":"2.9.1"}]}'

class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status; self.text = text
    @property
    def ok(self): return 200 <= self.status_code < 400
    def json(self):
        import json as _j
        return _j.loads(self.text)

class FakeSession:
    """Serves composer.lock; the LFM upload route is auth-gated (POST -> 403), so the active
    probe cannot confirm — exactly the scart/badaso live situation on a no-cred run."""
    def __init__(self, lock_body):
        self.lock_body = lock_body; self.gets = []; self.headers = {}
        self.cookies = RequestsCookieJar()
    def get(self, url, **kw):
        self.gets.append(url)
        if url.lower().endswith("/composer.lock"):
            return FakeResp(200, self.lock_body)
        return FakeResp(404, "")            # no CSRF page etc.
    def post(self, url, **kw):
        return FakeResp(403, "")            # upload route present but auth-gated


def test_composer_lock_vuln_version_detects_unauth():
    """lfm 2.6.4 (< 2.9.1) via composer.lock must be reported as applicability evidence."""
    res = m.scan("https://t", session=FakeSession(LOCK_VULN))
    assert res is not None
    assert res.get("verdict") == "version_applicable", f"expected version_applicable via composer.lock gate, got {res!r}"
    assert res.get("vulnerable") is not True
    assert "2.6.4" in str(res.get("evidence", "")) + str(res.get("version", "")), "version not surfaced"


def test_composer_lock_patched_version_not_vulnerable():
    """Negative: lfm 2.9.1 (patched) must NOT mark vulnerable on the version signal."""
    res = m.scan("https://t", session=FakeSession(LOCK_PATCHED))
    # may return a dict with vulnerable False (or None) — must not be a positive finding
    assert not (res and res.get("vulnerable") is True), f"false positive on patched 2.9.1: {res!r}"


def test_no_composer_lock_no_false_positive():
    """No composer.lock + auth-gated upload -> not a positive finding (no version signal)."""
    class NoLock(FakeSession):
        def get(self, url, **kw): return FakeResp(404, "")
    res = m.scan("https://t", session=NoLock(LOCK_VULN))
    assert not (res and res.get("vulnerable") is True)


def test_empty_operator_creds_are_not_replaced_with_lab_defaults(monkeypatch):
    calls = []

    def fake_login(session, base, username, password, timeout):
        calls.append((username, password))
        return None

    monkeypatch.setattr(m.http_config, "get_auth_session", lambda: FakeSession(LOCK_VULN))
    monkeypatch.setattr(m, "_try_login", fake_login)

    m.scan("https://t", username="", password="")

    assert calls == [("", "")]

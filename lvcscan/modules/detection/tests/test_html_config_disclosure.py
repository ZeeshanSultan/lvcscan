import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.core import http_config
from modules.detection.html_config_disclosure import scan, find_config_markers

LEAK = '<a href="https://sso.gameland.vip/#/profile?brandCode=BOREPORTSTAGINGS9">login</a>'
CLEAN = '<html><body>Welcome</body></html>'

def test_finds_sso_and_staging_markers():
    markers = find_config_markers(LEAK)
    assert any("STAGING" in m or "brandCode" in m for m in markers)
    assert any("sso" in m.lower() for m in markers)

def test_clean_page_no_markers():
    assert find_config_markers(CLEAN) == []

def test_bare_brandcode_not_flagged():
    # A brandCode with no env word in the value should NOT be treated as a marker
    bare = '<script>var cfg={brandCode:"ABC123"};</script>'
    markers = find_config_markers(bare)
    assert not any("brandCode" in m for m in markers), \
        "bare opaque brandCode should not be flagged without an env marker word"

class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code=status; self.text=text; self.headers=headers or {}
    @property
    def ok(self): return 200<=self.status_code<400

def test_scan_flags_leak(monkeypatch):
    # scan() must probe the UNAUTHENTICATED surface via http_config.unauth_get
    # (no-redirect), where the SSO/staging marker actually leaks on :58444/login.
    calls = {}
    def fake_unauth_get(url, **kw):
        calls["url"] = url
        calls["allow_redirects"] = kw.get("allow_redirects")
        return FakeResp(200, LEAK)
    monkeypatch.setattr(http_config, "unauth_get", fake_unauth_get)
    res = scan("https://t")
    assert res and res["vulnerable"] is True and res["vuln_class"]=="info_disclosure"
    # the marker page must be fetched without following the 302 to /
    assert calls.get("allow_redirects") is False

def test_scan_none_on_clean(monkeypatch):
    monkeypatch.setattr(http_config, "unauth_get", lambda url, **kw: FakeResp(200, CLEAN))
    assert scan("https://t") is None

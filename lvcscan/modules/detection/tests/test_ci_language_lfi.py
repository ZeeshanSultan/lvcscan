import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.core import http_config
from modules.detection.ci_language_lfi import scan

CANARY = "zzcanaryzz"
LEAK_BODY = f"Unable to load the requested language file: language/../{CANARY}/admin/common_lang.php"

class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code=status; self.text=text; self.headers=headers or {}
    @property
    def ok(self): return 200 <= self.status_code < 400
class FakeSession:
    def __init__(self, routes): self.routes=routes
    def get(self, url, **kw):
        for suf,resp in self.routes.items():
            if suf in url: return resp
        return FakeResp(404,"")
    def post(self,url,**kw): return FakeResp(404,"")


# --- Parse/regex logic, now driven through the unauth helper -----------------
# The detector must probe via http_config.unauth_get, so we monkeypatch it to
# delegate to a FakeSession; the parse/regex assertions are unchanged.
def test_detects_path_disclosure_500(monkeypatch):
    sess = FakeSession({"/admin/login": FakeResp(500, LEAK_BODY)})
    monkeypatch.setattr(http_config, "unauth_get", lambda url, **kw: sess.get(url, **kw))
    res = scan("https://t")
    assert res and res["vulnerable"] is True
    assert res["vuln_class"] == "lfi"
    assert res["exploit_status"] == "needs-validation"
    assert res.get("detonated") is False

def test_no_false_positive_on_200(monkeypatch):
    sess = FakeSession({"/admin/login": FakeResp(200, "<html>normal page</html>")})
    monkeypatch.setattr(http_config, "unauth_get", lambda url, **kw: sess.get(url, **kw))
    assert scan("https://t") is None


# --- New behavior: the probe goes through the UNAUTH helper, not auth sess ----
def test_scan_probes_via_unauth_helper(monkeypatch):
    """scan() must issue its canary probe through http_config.unauth_get so the
    operator's -H auth Cookie is NOT injected (which would override the canary
    and 302 away). A fake unauth_get returning the 500 leak => vulnerable=True."""
    calls = []

    def fake_unauth_get(url, *, cookies=None, allow_redirects=True, **kw):
        calls.append({"url": url, "cookies": cookies, "allow_redirects": allow_redirects})
        return FakeResp(500, LEAK_BODY)

    monkeypatch.setattr(http_config, "unauth_get", fake_unauth_get)
    res = scan("https://t")
    assert res and res["vulnerable"] is True
    # Probe carried the benign canary cookie and disabled redirects.
    assert calls, "unauth_get was never called"
    assert calls[0]["cookies"] == {"session_language_v2": f"../{CANARY}"}
    assert calls[0]["allow_redirects"] is False


def test_scan_does_not_use_auth_session_for_probe(monkeypatch):
    """Even when a session= is passed (API compat), the probe must NOT go through
    it — it must go through the unauth helper. Spy session RECORDS (never raises);
    a non-matching 302 means unfixed code returns None (genuine RED)."""
    class SpySession:
        def __init__(self): self.called = False
        def get(self, url, **kw):
            self.called = True
            return FakeResp(302, "")
        def post(self, url, **kw):
            self.called = True
            return FakeResp(302, "")

    spy = SpySession()
    monkeypatch.setattr(http_config, "unauth_get", lambda url, **kw: FakeResp(500, LEAK_BODY))
    res = scan("https://t", session=spy)
    assert res and res["vulnerable"] is True
    assert spy.called is False, "probe must not go through the auth/passed session"

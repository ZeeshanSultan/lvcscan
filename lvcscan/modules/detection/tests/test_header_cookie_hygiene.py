import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.detection.header_cookie_hygiene import scan, analyze_headers

SEC_HEADERS = ["content-security-policy","strict-transport-security","x-frame-options","x-content-type-options","referrer-policy","permissions-policy"]

def test_flags_missing_headers_eol_php_and_cookie_flags():
    headers = {"X-Powered-By":"PHP/7.4.33", "Set-Cookie":"admin_password=secret; path=/"}
    findings = analyze_headers(headers)
    assert findings["eol_php"] == "PHP/7.4.33"
    assert set(SEC_HEADERS).issubset(set(findings["missing_headers"]))
    assert any("HttpOnly" in c or "httponly" in c.lower() for c in findings["weak_cookies"])

def test_hardened_response_clean():
    headers = {
        "Content-Security-Policy":"default-src 'self'", "Strict-Transport-Security":"max-age=63072000",
        "X-Frame-Options":"DENY", "X-Content-Type-Options":"nosniff",
        "Referrer-Policy":"no-referrer", "Permissions-Policy":"geolocation=()",
        "X-Powered-By":"PHP/8.3.0",
        "Set-Cookie":"sess=abc; HttpOnly; Secure; SameSite=Lax",
    }
    findings = analyze_headers(headers)
    assert findings["missing_headers"] == [] and findings["eol_php"] is None and findings["weak_cookies"] == []

class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code=status; self.text=text; self.headers=headers or {}
    @property
    def ok(self): return 200<=self.status_code<400
class FakeSession:
    def __init__(self, headers): self.headers=headers
    def get(self,url,**kw): return FakeResp(200,"",self.headers)
    def post(self,url,**kw): return FakeResp(404,"")

def test_scan_flags_bad_response():
    sess = FakeSession({"X-Powered-By":"PHP/7.4.33","Set-Cookie":"x=1; path=/"})
    res = scan("https://t", session=sess)
    assert res and res["vulnerable"] is True and res["vuln_class"]=="info_disclosure"

def test_scan_none_on_hardened():
    sess = FakeSession({
        "Content-Security-Policy":"x","Strict-Transport-Security":"x","X-Frame-Options":"DENY",
        "X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","Permissions-Policy":"x",
        "X-Powered-By":"PHP/8.3.0","Set-Cookie":"s=1; HttpOnly; Secure; SameSite=Lax"})
    assert scan("https://t", session=sess) is None

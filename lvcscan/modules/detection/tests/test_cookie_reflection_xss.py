import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.detection.cookie_reflection_xss import scan, find_cookie_dom_sinks

VULN_JS = "function showCheckSecurityDevice(){ var deviceName = Cookies.get('device_name'); $('#dlg').html('Touch device ' + deviceName + ' to continue'); }"
SAFE_JS = "var deviceName = Cookies.get('device_name'); $('#dlg').text('Touch device ' + deviceName);"

class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code=status; self.text=text; self.headers=headers or {}
    @property
    def ok(self): return 200<=self.status_code<400
class FakeSession:
    def __init__(self, routes): self.routes=routes
    def get(self,url,**kw):
        for suf,resp in self.routes.items():
            if suf in url: return resp
        return FakeResp(404,"")
    def post(self,url,**kw): return FakeResp(404,"")

def test_finds_unencoded_cookie_dom_sink():
    sinks = find_cookie_dom_sinks(VULN_JS)
    assert "device_name" in sinks

def test_safe_text_wrapper_not_flagged():
    assert find_cookie_dom_sinks(SAFE_JS) == []

def test_scan_flags_vuln_page():
    sess = FakeSession({"/admin/index.html": FakeResp(200, VULN_JS)})
    res = scan("https://t", session=sess)
    assert res and res["vulnerable"] is True and res["vuln_class"]=="xss"
    assert "device_name" in str(res.get("confirm",""))

def test_scan_none_on_safe_page():
    sess = FakeSession({"/admin/index.html": FakeResp(200, SAFE_JS)})
    assert scan("https://t", session=sess) is None

# Regression: string-concat near Cookies.get() WITHOUT a DOM sink must NOT flag.
# fetch() and path-concat are server-side/network calls — no DOM write involved.
NO_DOM_SINK_JS = (
    "var user = Cookies.get('user');"
    " fetch('/api?v=' + '1.0');"
    " var path = '/admin/' + x;"
)

def test_no_dom_sink_not_flagged():
    """Cookie value used only in fetch/path concat (no DOM write) — must return []."""
    assert find_cookie_dom_sinks(NO_DOM_SINK_JS) == []

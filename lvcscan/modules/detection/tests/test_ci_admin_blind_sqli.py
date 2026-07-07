import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.detection.ci_admin_blind_sqli import scan

class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code=status; self.text=text; self.headers=headers or {}
    @property
    def ok(self): return 200<=self.status_code<400

class FakeSession:
    # diverge=True -> tick value yields different status/len than baseline
    def __init__(self, diverge): self.diverge=diverge; self.gets=[]
    def get(self, url, **kw):
        self.gets.append(url)
        if "%27" in url or "'" in url:   # the single-tick probe
            return FakeResp(500, "x"*20) if self.diverge else FakeResp(200, "y"*100)
        return FakeResp(200, "y"*100)    # baseline
    def post(self,url,**kw): return FakeResp(404,"")

def test_detects_divergence():
    sess = FakeSession(diverge=True)
    res = scan("https://t", session=sess, endpoint="/admin/bank/search.html", params=["bank_account_no"])
    assert res and res["vulnerable"] is True and res["vuln_class"]=="sqli"
    assert res.get("command_capable") is False and res.get("detonated") is False

def test_inconclusive_when_no_divergence():
    sess = FakeSession(diverge=False)
    res = scan("https://t", session=sess, endpoint="/admin/bank/search.html", params=["bank_account_no"])
    assert res is None  # suppressed errors -> no confirmation

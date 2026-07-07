import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.detection.api_tunnel_bypass import scan, looks_like_plaintext_json

PLAIN = '{"notes":[{"id":1,"text":"client note"}],"status":"ok"}'
ENCRYPTED = 'U2FsdGVkX1+abc123base64blobnojsonhere=='

def test_plaintext_json_detected():
    assert looks_like_plaintext_json(PLAIN, "application/json") is True
def test_encrypted_blob_not_flagged():
    assert looks_like_plaintext_json(ENCRYPTED, "text/plain") is False

class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code=status; self.text=text; self.headers=headers or {}
    @property
    def ok(self): return 200<=self.status_code<400
class FakeSession:
    def __init__(self, routes): self.routes=routes; self.posted=[]
    def get(self,url,**kw):
        for suf,resp in self.routes.items():
            if suf in url: return resp
        return FakeResp(404,"")
    def post(self,url,**kw): self.posted.append(url); return FakeResp(404,"")

def test_scan_flags_plaintext_api():
    sess = FakeSession({"/api/tran/searchNote": FakeResp(200, PLAIN, {"Content-Type":"application/json"})})
    res = scan("https://t", session=sess)
    assert res and res["vulnerable"] is True and res["vuln_class"]=="info_disclosure"
    assert sess.posted == [], "must never POST to transaction endpoints (prove-not-detonate)"

def test_scan_none_when_encrypted():
    sess = FakeSession({"/api/tran/searchNote": FakeResp(200, ENCRYPTED, {"Content-Type":"text/plain"})})
    assert scan("https://t", session=sess) is None

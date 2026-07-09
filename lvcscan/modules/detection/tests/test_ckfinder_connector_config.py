import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.detection.ckfinder_connector_config import scan, parse_connector_config

# SAFE config: an allowlist of gif/jpg/png blocks phar/php7 even though they aren't in
# the denylist. This must NOT be flagged (the old code did — a false RCE).
INIT_JSON_SAFE = '{"uploadCheckImages":false,"resourceTypes":[{"name":"Images","allowedExtensions":"gif,jpg,png","deniedExtensions":"php,php3,exe"}]}'
# VULNERABLE config: no allowlist and phar/php7 are not denied -> dangerous ext accepted.
INIT_JSON_VULN = '{"uploadCheckImages":false,"resourceTypes":[{"name":"Files","allowedExtensions":"","deniedExtensions":"php,php3,exe"}]}'
# Kept for the denylist-gap parse assertion (factual gap computation).
INIT_JSON = INIT_JSON_SAFE

class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code=status; self.text=text; self.headers=headers or {}
    @property
    def ok(self): return 200 <= self.status_code < 400
class FakeSession:
    def __init__(self, routes): self.routes=routes; self.posted=[]
    def get(self, url, **kw):
        for suf,resp in self.routes.items():
            if url.endswith(suf): return resp
        return FakeResp(404,"")
    def post(self, url, **kw):
        self.posted.append(url); return FakeResp(404,"")

def test_parse_flags_disabled_validation_and_blocklist_gaps():
    v = parse_connector_config(INIT_JSON)
    assert v["uploadCheckImages"] is False
    assert "php7" in v["blocklist_gaps"] and "phar" in v["blocklist_gaps"]

def test_scan_confirms_reachable_but_never_uploads():
    sess = FakeSession({"/admin/image_manager/connector.html?command=Init": FakeResp(200, INIT_JSON_VULN)})
    res = scan("https://t", session=sess)
    assert res and res["vulnerable"] is True
    assert res["vuln_class"] == "rce"
    assert res.get("command_capable") is True
    assert res.get("detonated") is False
    assert sess.posted == [], "module must not upload (prove-not-detonate)"

def test_scan_safe_allowlist_is_not_flagged():
    # Allowlist blocks dangerous exts -> reachable connector, but NOT an RCE primitive.
    sess = FakeSession({"/admin/image_manager/connector.html?command=Init": FakeResp(200, INIT_JSON_SAFE)})
    assert scan("https://t", session=sess) is None

def test_scan_returns_none_when_no_connector():
    sess = FakeSession({})  # all 404
    assert scan("https://t", session=sess) is None

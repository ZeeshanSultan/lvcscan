import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.detection.ci_role_field_privesc import scan, _references_role_field

BOARD_HTML = "<form action='/admin/admin/updateType.html'><select name='type'><option>ADMIN</option></select></form>"

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

def test_confirms_sink_without_posting():
    sess = FakeSession({"/admin/admin/index.html": FakeResp(200, BOARD_HTML),
                        "/admin/admin/updateType.html": FakeResp(200, "ok")})
    res = scan("https://t", session=sess)
    assert res and res["vulnerable"] is True and res["vuln_class"]=="priv_esc"
    assert res.get("detonated") is False
    assert res.get("command_capable") is False
    assert sess.posted == [], "must never POST a role change (prove-not-detonate)"

def test_none_when_sink_absent():
    sess = FakeSession({})  # all 404
    assert scan("https://t", session=sess) is None

# Regression: generic HTML attribute type="text" and Content-Type header must NOT
# match the role-field check — only form field NAME references should fire.
NO_ROLE_FIELD_HTML = (
    '<input type="text" placeholder="Search">'
    ' <meta charset="utf-8"> Content-Type: application/json'
)

def test_generic_type_attribute_not_flagged():
    """type= as HTML attribute / Content-Type must NOT match _references_role_field."""
    assert _references_role_field(NO_ROLE_FIELD_HTML) is None

def test_name_type_field_flagged():
    """name='type' form field IS a role-field reference and must match."""
    assert _references_role_field(BOARD_HTML) == "type"


# FP: a generic search/filter form with name="type" but NO role-mutation context.
SEARCH_FORM_HTML = "<form action='/search'><select name='type'><option>news</option></select></form>"

def test_search_form_type_not_flagged():
    assert _references_role_field(SEARCH_FORM_HTML) is None

def test_login_redirect_sink_not_reachable():
    # Sink returns 302 -> login (not authenticated). Must NOT be treated as reachable.
    sess = FakeSession({"/admin/admin/index.html": FakeResp(302, "", {"Location": "/login"}),
                        "/admin/admin/updateType.html": FakeResp(302, "", {"Location": "/login"})})
    assert scan("https://t", session=sess) is None

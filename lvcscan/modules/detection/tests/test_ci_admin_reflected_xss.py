import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.detection.ci_admin_reflected_xss import scan, CANARY, is_reflected_unescaped


def test_canary_detection_unescaped():
    assert is_reflected_unescaped(f"<div>search: {CANARY}</div>") is True


def test_escaped_canary_not_flagged():
    esc = CANARY.replace("<", "&lt;").replace(">", "&gt;")
    assert is_reflected_unescaped(f"<div>{esc}</div>") is False


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}

    @property
    def ok(self):
        return 200 <= self.status_code < 400


class FakeSession:
    def __init__(self, reflect):
        self.reflect = reflect
        self.urls = []

    def get(self, url, **kw):
        self.urls.append(url)
        body = f"<html>echo {CANARY}</html>" if self.reflect else "<html>safe</html>"
        return FakeResp(200, body)

    def post(self, url, **kw):
        return FakeResp(404, "")


def test_scan_flags_reflection():
    sess = FakeSession(reflect=True)
    res = scan("https://t", session=sess, endpoints=["/admin/x.html"])
    assert res and res["vulnerable"] is True and res["vuln_class"] == "xss"


def test_scan_none_when_escaped_or_absent():
    sess = FakeSession(reflect=False)
    assert scan("https://t", session=sess, endpoints=["/admin/x.html"]) is None

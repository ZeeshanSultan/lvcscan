"""Phase 4 — missing security headers are INFORMATIONAL, not a vulnerability.
Almost every site lacks CSP/Permissions-Policy/Referrer-Policy; flagging that as
vulnerable=True made the detector fire on nearly everything. Only EOL-PHP
disclosure or weak cookie flags are a (low-severity) confirmed finding.
"""

from modules.detection.header_cookie_hygiene import scan


class _Resp:
    def __init__(self, headers):
        self.status_code, self.text, self.headers = 200, "", headers

    @property
    def ok(self):
        return True


class _Sess:
    def __init__(self, headers):
        self.headers = headers

    def get(self, url, **kw):
        return _Resp(self.headers)


def test_missing_headers_only_is_surface_not_vulnerable():
    # Modern PHP, well-flagged cookie, but no CSP/HSTS/etc.
    sess = _Sess({
        "X-Powered-By": "PHP/8.3.0",
        "Set-Cookie": "sess=abc; HttpOnly; Secure; SameSite=Lax",
    })
    res = scan("https://t", session=sess)
    assert res is not None                       # still reported...
    assert res["vulnerable"] is False            # ...but NOT as a vulnerability
    assert res.get("verdict") == "surface_present"


def test_eol_php_still_vulnerable():
    sess = _Sess({"X-Powered-By": "PHP/7.4.33", "Set-Cookie": "x=1; HttpOnly; Secure; SameSite=Lax"})
    res = scan("https://t", session=sess)
    assert res and res["vulnerable"] is True


def test_weak_cookie_still_vulnerable():
    sess = _Sess({
        "Content-Security-Policy": "x", "Strict-Transport-Security": "x",
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer", "Permissions-Policy": "x",
        "X-Powered-By": "PHP/8.3.0", "Set-Cookie": "s=1; path=/",  # no flags
    })
    res = scan("https://t", session=sess)
    assert res and res["vulnerable"] is True

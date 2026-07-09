import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from urllib.parse import urlparse, parse_qs
from modules.detection.ci_admin_blind_sqli import scan


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status; self.text = text; self.headers = headers or {}
    @property
    def ok(self):
        return 200 <= self.status_code < 400


def _tick_count(url):
    q = parse_qs(urlparse(url).query)
    val = next(iter(q.values()))[0] if q else ""
    return val.count("'")


class InjectableSession:
    """Models a real boolean SQLi: an ODD number of ticks breaks the query (500/short),
    an EVEN number (incl. baseline) is valid and returns the normal page."""
    def __init__(self):
        self.gets = []

    def get(self, url, **kw):
        self.gets.append(url)
        if _tick_count(url) % 2 == 1:
            return FakeResp(500, "SQL error")     # unbalanced -> diverges
        return FakeResp(200, "y" * 100)           # baseline / balanced -> normal

    def post(self, url, **kw):
        return FakeResp(404, "")


class SafeSession:
    """Errors suppressed: every value returns the same page -> no confirmation."""
    def get(self, url, **kw):
        return FakeResp(200, "y" * 100)

    def post(self, url, **kw):
        return FakeResp(404, "")


class NoisySession:
    """Page varies a lot between identical requests (CSRF token/timestamp). The old
    flat-10% check false-flagged this; the variance baseline must reject it."""
    def __init__(self):
        self._n = 0

    def get(self, url, **kw):
        self._n += 1
        # Body length swings ~40% every request regardless of payload.
        return FakeResp(200, "y" * (100 if self._n % 2 else 140))

    def post(self, url, **kw):
        return FakeResp(404, "")


def test_detects_boolean_differential():
    sess = InjectableSession()
    res = scan("https://t", session=sess, endpoint="/admin/bank/search.html", params=["bank_account_no"])
    assert res and res["vulnerable"] is True and res["vuln_class"] == "sqli"
    assert res.get("command_capable") is False and res.get("detonated") is False


def test_inconclusive_when_errors_suppressed():
    res = scan("https://t", session=SafeSession(), endpoint="/admin/bank/search.html", params=["bank_account_no"])
    assert res is None


def test_no_fp_on_naturally_noisy_page():
    res = scan("https://t", session=NoisySession(), endpoint="/admin/bank/search.html", params=["bank_account_no"])
    assert res is None

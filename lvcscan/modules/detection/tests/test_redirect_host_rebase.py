"""Reflected-Host redirect rebasing in the central HTTP patch.

When a Host override is forced (-H 'Host: _'), a server commonly answers with an absolute
redirect whose host is the spoofed Host (e.g. 302 -> http://_/filemanager). Following that
lands on an unresolvable host. _request_following_rebased_redirects re-bases each Location's
host/scheme back onto the host we dialed, preserving path+query. These tests drive that helper
directly with a fake original-request function so no network/DNS is involved — and lock the
critical invariant that it only re-bases a DIFFERENT host (same-host redirects pass through).
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import modules.core.http_config as hc


class FakeResp:
    def __init__(self, status, headers=None, url=None):
        self.status_code = status
        self.headers = headers or {}
        self.url = url
        self.history = []
    @property
    def is_redirect(self):
        return self.status_code in (301, 302, 303, 307, 308) and "location" in {
            k.lower() for k in self.headers}


def _make_orig(script):
    """Return a fake _orig_session_request that pops responses from `script` and records the
    (method, url) it was asked to fetch into `calls`."""
    calls = []
    seq = list(script)
    def orig(self, method, url, **kw):
        calls.append((method, url))
        return seq.pop(0)
    return orig, calls


def _run(monkeypatch_target, url, kwargs, host_ovr, script):
    orig, calls = _make_orig(script)
    saved = hc._orig_session_request
    hc._orig_session_request = orig
    try:
        resp = hc._request_following_rebased_redirects(object(), "GET", url, kwargs, host_ovr)
    finally:
        hc._orig_session_request = saved
    return resp, calls


def test_absolute_reflected_host_is_rebased():
    # 302 Location: http://_/filemanager  -> follower re-requests http://localhost:18081/filemanager
    script = [
        FakeResp(302, {"location": "http://_/filemanager"}, url="http://localhost:18081/"),
        FakeResp(200, {}, url="http://localhost:18081/filemanager"),
    ]
    resp, calls = _run(hc, "http://localhost:18081/", {}, "_", script)
    assert resp.status_code == 200
    # The SECOND fetch must target the real host, not the spoofed '_'.
    assert calls[1] == ("GET", "http://localhost:18081/filemanager")
    assert len(resp.history) == 1


def test_relative_location_resolves_against_real_host():
    script = [
        FakeResp(302, {"location": "/filemanager"}, url="http://localhost:18081/"),
        FakeResp(200, {}, url="http://localhost:18081/filemanager"),
    ]
    resp, calls = _run(hc, "http://localhost:18081/", {}, "_", script)
    assert calls[1] == ("GET", "http://localhost:18081/filemanager")


def test_same_host_redirect_passes_through_unchanged():
    # A redirect to the SAME host must not be rewritten (no spurious host swap).
    script = [
        FakeResp(302, {"location": "http://localhost:18081/login"}, url="http://localhost:18081/"),
        FakeResp(200, {}, url="http://localhost:18081/login"),
    ]
    resp, calls = _run(hc, "http://localhost:18081/", {}, "_", script)
    assert calls[1] == ("GET", "http://localhost:18081/login")


def test_query_string_preserved_on_rebase():
    script = [
        FakeResp(302, {"location": "http://_/x?a=1&b=2"}, url="http://localhost:18081/"),
        FakeResp(200, {}, url="http://localhost:18081/x?a=1&b=2"),
    ]
    resp, calls = _run(hc, "http://localhost:18081/", {}, "_", script)
    assert calls[1] == ("GET", "http://localhost:18081/x?a=1&b=2")


def test_redirect_cap_stops_loop():
    # An infinite same-pattern redirect must terminate at the hop cap, not hang.
    loop = [FakeResp(302, {"location": "http://_/loop"}, url="http://localhost:18081/")
            for _ in range(hc._MAX_REBASED_REDIRECTS + 5)]
    resp, calls = _run(hc, "http://localhost:18081/", {}, "_", loop)
    # 1 initial + up to _MAX_REBASED_REDIRECTS follows.
    assert len(calls) <= hc._MAX_REBASED_REDIRECTS + 1
    assert resp.is_redirect  # gave up while still redirecting (cap hit), did not loop forever


def test_post_redirect_demotes_to_get_on_302():
    # 302 on a POST -> follow as GET, body kwargs dropped (mirrors requests).
    orig, calls = _make_orig([
        FakeResp(302, {"location": "http://_/done"}, url="http://localhost:18081/submit"),
        FakeResp(200, {}, url="http://localhost:18081/done"),
    ])
    saved = hc._orig_session_request
    hc._orig_session_request = orig
    try:
        hc._request_following_rebased_redirects(
            object(), "POST", "http://localhost:18081/submit",
            {"data": b"x", "json": {"k": 1}}, "_")
    finally:
        hc._orig_session_request = saved
    assert calls[0][0] == "POST"
    assert calls[1][0] == "GET"  # demoted

"""Host-header injection detector — offline, fake-session driven, edge-case focused."""
from modules.detection import host_header_injection as hhi

CANARY = hhi.CANARY


class _Resp:
    def __init__(self, status=200, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


class _Session:
    """Fake session: routes each poisoned request through a caller-supplied handler.

    handler(url, header, value) -> _Resp (or None). Records every call so tests can
    assert which vectors were tried and that only GET (no POST) is ever issued.
    """
    def __init__(self, handler):
        self._handler = handler
        self.calls = []

    def get(self, url, headers=None, timeout=None, allow_redirects=None, **kw):
        header = next(iter((headers or {}).items()), (None, None))
        self.calls.append(("GET", url, header[0], header[1]))
        return self._handler(url, header[0], header[1])

    # Intentionally NO post(): a test that triggers one would AttributeError.


def test_location_reflection_is_confirmed():
    def handler(url, header, value):
        if header == "X-Forwarded-Host":
            return _Resp(302, {"Location": f"https://{CANARY}/dashboard"}, "")
        return _Resp(200, {}, "ok")

    r = hhi.scan("http://t.example", session=_Session(handler))
    assert r and r["verdict"] == "confirmed_vulnerable" and r["vulnerable"] is True
    assert r["vuln_class"] == "host_header_injection"
    assert any(h["reflection"] == "location" for h in r["confirm"]["hits"])


def test_body_url_reflection_is_confirmed():
    def handler(url, header, value):
        # Canary comes back as a real URL in a link — exploitable sink.
        return _Resp(200, {}, f'<a href="https://{CANARY}/reset?token=x">reset</a>')

    r = hhi.scan("http://t.example", session=_Session(handler))
    assert r and r["verdict"] == "confirmed_vulnerable"
    assert any(h["reflection"] == "body_url" for h in r["confirm"]["hits"])


def test_bare_echo_is_only_surface():
    def handler(url, header, value):
        # Host echoed as plain text, never in a URL context -> weak signal.
        return _Resp(200, {}, f"<p>Unknown host {CANARY} requested</p>")

    r = hhi.scan("http://t.example", session=_Session(handler))
    assert r and r["verdict"] == "surface_present" and r["vulnerable"] is False


def test_no_reflection_returns_none():
    def handler(url, header, value):
        return _Resp(200, {"Location": "https://real.example/"}, "<p>real.example only</p>")

    assert hhi.scan("http://t.example", session=_Session(handler)) is None


def test_unreachable_host_is_graceful():
    def handler(url, header, value):
        raise OSError("connection refused")

    assert hhi.scan("http://t.example", session=_Session(handler)) is None


def test_default_never_posts_to_reset():
    sess = _Session(lambda u, h, v: _Resp(200, {}, "ok"))
    hhi.scan("http://t.example", session=sess)
    assert all(c[0] == "GET" for c in sess.calls)
    assert not any("/password" in c[1] or "/forgot-password" in c[1] for c in sess.calls)


def test_reset_probe_is_opt_in_and_get_only():
    def handler(url, header, value):
        if "/forgot-password" in url:
            return _Resp(200, {}, f'<form action="https://{CANARY}/pw">x</form>')
        return _Resp(200, {}, "ok")

    sess = _Session(handler)
    r = hhi.scan("http://t.example", session=sess, options={"hhi_probe_reset": True})
    assert r and r["verdict"] == "confirmed_vulnerable"
    assert all(c[0] == "GET" for c in sess.calls)          # opt-in path still GET-only
    assert any("/forgot-password" in c[1] for c in sess.calls)

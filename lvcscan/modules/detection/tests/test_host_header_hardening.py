"""Phase 4/7 — host-header injection hardening: don't over-confirm on a plain
Host-echoing canonical redirect, and never poison a shared cache (cache-buster +
no-store on every probe)."""

from modules.detection import host_header_injection as hhi

CANARY = hhi.CANARY


class _Rec:
    def __init__(self, handler):
        self._h = handler
        self.calls = []  # (url, headers)

    def get(self, url, headers=None, timeout=None, allow_redirects=None, **kw):
        self.calls.append((url, dict(headers or {})))
        return self._h(url, dict(headers or {}))


class _Resp:
    def __init__(self, status=200, headers=None, text=""):
        self.status_code, self.headers, self.text = status, headers or {}, text


def test_raw_host_vector_location_only_is_surface_not_confirmed():
    # Only the raw Host vector reflects, and only into Location (a scheme/canonical
    # redirect that echoes whatever Host it was sent). That is a weak signal, not a
    # confirmed URL-building sink.
    def handler(url, headers):
        if any(k.lower() == "host" for k in headers):
            return _Resp(301, {"Location": f"https://{CANARY}/"}, "")
        return _Resp(200, {}, "ok")

    r = hhi.scan("http://t.example", session=_Rec(handler))
    assert r is not None
    assert r["verdict"] == "surface_present"
    assert r["vulnerable"] is False


def test_forwarded_host_location_still_confirmed():
    # X-Forwarded-Host landing the canary in Location is the genuine trust-the-proxy
    # sink and must stay confirmed.
    def handler(url, headers):
        if any(k.lower() == "x-forwarded-host" for k in headers):
            return _Resp(302, {"Location": f"https://{CANARY}/dashboard"}, "")
        return _Resp(200, {}, "ok")

    r = hhi.scan("http://t.example", session=_Rec(handler))
    assert r["verdict"] == "confirmed_vulnerable"


def test_every_probe_is_cache_busted_and_no_store():
    sess = _Rec(lambda u, h: _Resp(200, {}, "ok"))
    hhi.scan("http://t.example", session=sess)
    assert sess.calls, "no probes issued"
    for url, headers in sess.calls:
        assert "cb=" in url, f"probe not cache-busted: {url}"
        assert any(k.lower() == "cache-control" and "no-store" in v.lower()
                   for k, v in headers.items()), f"missing no-store: {headers}"

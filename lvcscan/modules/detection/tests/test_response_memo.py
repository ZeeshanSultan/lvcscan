import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.probes.response_memo import (
    memo_key, ResponseMemo, ResponseSnapshot, get_run_memo, reset_run_memo,
)

def test_composite_key_distinguishes_redirect_policy():
    # env_exposure's no-redirect /.env GET must NOT collide with a redirect-following GET
    k1 = memo_key("GET", "https://t/.env", allow_redirects=False, headers={}, auth="A")
    k2 = memo_key("GET", "https://t/.env", allow_redirects=True,  headers={}, auth="A")
    assert k1 != k2

def test_composite_key_distinguishes_cookie_context():
    # cve_2017_14775's two cookie-distinct GETs must not merge
    k1 = memo_key("GET", "https://t/login", allow_redirects=False, headers={"Cookie":"a=1"}, auth="A")
    k2 = memo_key("GET", "https://t/login", allow_redirects=False, headers={"Cookie":"a=2"}, auth="A")
    assert k1 != k2

def test_composite_key_distinguishes_auth_context():
    k1 = memo_key("GET", "https://t/x", allow_redirects=False, headers={}, auth="authed")
    k2 = memo_key("GET", "https://t/x", allow_redirects=False, headers={}, auth="anon")
    assert k1 != k2

def test_same_inputs_same_key():
    k1 = memo_key("GET", "https://t/x", allow_redirects=False, headers={"Cookie":"a=1"}, auth="A")
    k2 = memo_key("GET", "https://t/x", allow_redirects=False, headers={"Cookie":"a=1"}, auth="A")
    assert k1 == k2

def test_miss_returns_none_not_assume_absent():
    m = ResponseMemo()
    assert m.get(memo_key("GET","https://t/x",False,{},"A")) is None

def test_put_get_roundtrip_byte_identical():
    m = ResponseMemo()
    snap = ResponseSnapshot(status=200, headers={"Content-Type":"text/plain"}, body=b"APP_KEY=base64:XYZ=")
    k = memo_key("GET","https://t/.env",False,{},"A")
    m.put(k, snap)
    got = m.get(k)
    assert got is not None
    assert got.status == 200 and got.body == b"APP_KEY=base64:XYZ=" and got.headers["Content-Type"]=="text/plain"

def test_get_only_no_cache_bypass():
    # POST must never be cached: memo_key should refuse / or store only marks GET. Enforce GET-only at put.
    m = ResponseMemo()
    snap = ResponseSnapshot(status=200, headers={}, body=b"x")
    # putting a non-GET key is a no-op (returns False) — POST bodies vary, never cache
    k_post = memo_key("POST","https://t/x",False,{},"A")
    assert m.put(k_post, snap) is False
    assert m.get(k_post) is None


# --- Discovery-seed roundtrip (Step 4): after a simulated seed, the shared run memo
#     returns the snapshot for the matching composite key. ---
def test_run_memo_seed_roundtrip():
    reset_run_memo()
    memo = get_run_memo()
    snap = ResponseSnapshot(status=200, headers={"Content-Type": "text/plain"},
                            body=b"APP_KEY=base64:abc=\n")
    k = memo_key("GET", "https://t/.env", allow_redirects=True, headers={}, auth="anon")
    assert memo.put(k, snap) is True
    got = get_run_memo().get(k)
    assert got is not None and got.body == b"APP_KEY=base64:abc=\n"

def test_reset_run_memo_clears_store():
    memo = get_run_memo()
    k = memo_key("GET", "https://t/x", allow_redirects=True, headers={}, auth="anon")
    memo.put(k, ResponseSnapshot(status=200, headers={}, body=b"x"))
    assert get_run_memo().get(k) is not None
    reset_run_memo()
    assert get_run_memo().get(k) is None


# --- Integration: is_laravel() seeds the in-hand /.env Response into the run memo with the
#     FAITHFUL composite key (GET, allow_redirects=True, no headers, run auth-context). ---
class _FakeResp:
    def __init__(self, status=200, headers=None, body=b"", url="", cookies=()):
        self.status_code = status
        self.headers = headers or {}
        self.content = body
        self.text = body.decode("utf-8", "replace")
        self.url = url
        self.cookies = cookies

def test_is_laravel_seeds_env_response_into_run_memo(monkeypatch):
    from modules.detection import detect_laravel
    reset_run_memo()
    base = "https://victim.test"
    env_body = b"APP_KEY=base64:SEEDED==\nDB_PASSWORD=secret\n"

    def fake_safe_get(url, timeout=8, allow_redirects=True, **kw):
        if url.rstrip("/") == base:
            return _FakeResp(200, {"Server": "nginx"}, b"<html>laravel csrf-token</html>", url=base)
        if url.endswith("/.env"):
            return _FakeResp(200, {"Content-Type": "text/plain"}, env_body, url=url)
        return None  # composer.* etc. -> miss

    monkeypatch.setattr(detect_laravel, "_safe_get", fake_safe_get)
    # neutralize the network-touching active probes we don't care about here
    info = detect_laravel.is_laravel(base, active=True, stealth=False)
    assert info is not None  # /.env APP_KEY + body hints -> a real Laravel verdict

    # The seeded key uses the EXACT params of detect_laravel's /.env fetch.
    from modules.core.http_config import app_url, has_extra_headers
    auth = "authed" if has_extra_headers() else "anon"
    k = memo_key("GET", app_url(info["final_url"], "/.env"),
                 allow_redirects=True, headers={}, auth=auth)
    snap = get_run_memo().get(k)
    assert snap is not None, "discovery should have seeded the /.env response"
    assert snap.status == 200 and snap.body == env_body
    reset_run_memo()

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.detection import env_exposure
from modules.detection.env_exposure import _extract_app_key

class R:
    status_code=200
    @property
    def ok(self): return True
    text="APP_NAME=Acme\nAPP_KEY=base64:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK=\nDB_PASSWORD=secret\n"
    headers={}
class S:
    def get(self,u,**k): return R()
    def post(self,u,**k): return R()

def test_env_emits_artifacts_app_key():
    res = env_exposure.scan("https://t", session=S())
    assert res is not None
    assert res.get("artifacts", {}).get("app_key", "").startswith("base64:AAAA")

def test_env_no_appkey_no_artifact():
    class R2(R): text="APP_NAME=Acme\nDB_PASSWORD=secret\n"
    class S2(S):
        def get(self,u,**k): return R2()
    res = env_exposure.scan("https://t", session=S2())
    # still a finding (DB creds), but no app_key artifact
    assert res is not None
    assert not res.get("artifacts", {}).get("app_key")

def test_env_does_not_capture_pusher_app_key():
    # PUSHER_APP_KEY= contains the substring 'APP_KEY=' — extraction must anchor to
    # line-start so the real (blank) APP_KEY wins, never PUSHER_APP_KEY's value.
    class R3(R):
        text=("APP_NAME=Acme\nAPP_KEY=\n"
              "PUSHER_APP_KEY=pusher-should-not-leak\nDB_PASSWORD=secret\n")
    class S3(S):
        def get(self,u,**k): return R3()
    res = env_exposure.scan("https://t", session=S3())
    if res is not None:
        # blank APP_KEY => no artifact, and PUSHER value must never be harvested
        assert "pusher" not in res.get("artifacts", {}).get("app_key", "")
        assert not res.get("artifacts", {}).get("app_key")

def test_env_strips_quotes_keeps_base64_padding():
    class R4(R):
        text='APP_NAME=Acme\nAPP_KEY="base64:ZZZZ1111222233334444555566667777888899990000="\n'
    class S4(S):
        def get(self,u,**k): return R4()
    res = env_exposure.scan("https://t", session=S4())
    assert res is not None
    key = res.get("artifacts", {}).get("app_key", "")
    assert key == "base64:ZZZZ1111222233334444555566667777888899990000="


# --- _extract_app_key unit tests (inline comment stripping) ---

def test_extract_app_key_strips_inline_comment():
    # Comment after whitespace must be removed; base64 padding '=' must be kept
    assert _extract_app_key("APP_KEY=base64:REAL= # inline comment\n") == "base64:REAL="

def test_extract_app_key_placeholder_returns_none():
    # Placeholder with no real key → empty after stripping → None
    assert _extract_app_key("APP_KEY= # generate me\n") is None

def test_extract_app_key_hash_inside_quotes_preserved():
    # No whitespace before '#', so inline-comment strip leaves it alone
    assert _extract_app_key('APP_KEY="abc#def"\n') == "abc#def"

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.cves import cve_2024_47823 as m

# Regression for the live-validation FAIL on lab :37004 (ERPSAAS livewire 2.12.5):
# composer.lock pins livewire/livewire 2.12.5 (< 2.12.7 = VULNERABLE), but a bundled
# livewire.js asset banners a patched-looking version. The detector used to set version
# from the JS scrape in Step 4 and only consult composer.lock when version was empty
# (Step 5 `if not result["version"]`), so the authoritative composer.lock pin was never
# read -> wrong verdict "patched". composer.lock MUST be authoritative.

HOME_HTML = '<html><head><script src="/js/app.js"></script></head><body wire:id="x"></body></html>'
# JS asset banners a PATCHED version (3.5.20-style) — the misleading source
LIVEWIRE_JS = 'window.Livewire = {}; /* livewire */ {version:"3.5.20"}'
# composer.lock pins the VULNERABLE package version (authoritative)
COMPOSER_LOCK = '{"packages":[{"name":"livewire/livewire","version":"v2.12.5"}]}'

class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status; self.text = text
    @property
    def ok(self): return 200 <= self.status_code < 400

class FakeSession:
    """Serves: home HTML, a livewire JS asset (patched banner), composer.lock (vulnerable pin)."""
    def __init__(self):
        self.gets = []
    def get(self, url, **kw):
        self.gets.append(url)
        low = url.lower()
        if low.endswith("/composer.lock"):
            return FakeResp(200, COMPOSER_LOCK)
        if "livewire" in low or low.endswith(".js"):
            return FakeResp(200, LIVEWIRE_JS)
        if low.rstrip("/").endswith(("/v2", "/v3")):
            return FakeResp(404, "")
        return FakeResp(200, HOME_HTML)   # root / candidate bases
    def post(self, url, **kw):
        return FakeResp(404, "")


def test_composer_lock_overrides_js_asset_version():
    """composer.lock's 2.12.5 (vulnerable) must win over the JS asset's patched 3.5.20 banner."""
    res = m.scan("https://t", session=FakeSession(), perform_upload_test=False)
    assert res is not None, "livewire detected but scan returned None"
    assert res.get("version") == "2.12.5", f"expected composer.lock 2.12.5 to win, got {res.get('version')!r}"
    assert res.get("version_status") == "vulnerable", f"expected vulnerable range, got {res.get('version_status')!r}"
    assert res.get("verdict") == "version_applicable"
    assert res.get("vulnerable") is not True


def test_composer_lock_patched_version_marks_patched():
    """Negative: when composer.lock pins a patched version, verdict is patched (no false positive)."""
    class PatchedSession(FakeSession):
        def get(self, url, **kw):
            if url.lower().endswith("/composer.lock"):
                return FakeResp(200, '{"packages":[{"name":"livewire/livewire","version":"v2.12.7"}]}')
            return super().get(url, **kw)
    res = m.scan("https://t", session=PatchedSession(), perform_upload_test=False)
    assert res is not None
    assert res.get("version") == "2.12.7"
    assert res.get("version_status") == "patched"
    assert res.get("vulnerable") is not True

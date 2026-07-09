"""Phase 4 — laravel-filemanager exposure: require UniSharp-specific markers and do
not follow redirects, so a generic page with 'upload/files/images' isn't flagged."""

from modules.detection import laravel_filemanager_exposure as lfm


class _Resp:
    def __init__(self, status=200, text=""):
        self.status_code, self.text, self.content, self.headers = status, text, text.encode(), {}


class _Sess:
    def __init__(self, body_for):
        self._b = body_for

    def get(self, url, **kw):
        assert kw.get("allow_redirects") is False, "must not follow redirects"
        return self._b(url)


def test_generic_upload_page_not_flagged():
    sess = _Sess(lambda u: _Resp(200, "<h1>Upload your files and images here</h1>"))
    assert lfm.scan_detailed("http://t", session=sess) is None


def test_real_unisharp_lfm_flagged():
    def body(u):
        if "filemanager" in u or "/lfm" in u:
            return _Resp(200, '<div class="vendor/laravel-filemanager"><script src="/lfm/js/stand-alone-button.js"></script>unisharp</div>')
        return _Resp(200, "home")
    assert lfm.scan_detailed("http://t", session=_Sess(body)) is not None

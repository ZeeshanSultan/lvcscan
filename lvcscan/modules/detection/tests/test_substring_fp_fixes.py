"""Phase 4 — kill the bare-substring false positives in debug-tools / log / git
detectors, while keeping the real positives."""

from modules.detection import debug_tools_exposure as dbg
from modules.detection import log_exposure as logx
from modules.detection import git_exposure as gitx


class _Resp:
    def __init__(self, status=200, text=""):
        self.status_code, self.text = status, text


class _RouteSession:
    """Returns a 200 page whose body depends on the requested path."""
    def __init__(self, body_for):
        self._body_for = body_for

    def get(self, url, **kw):
        return _Resp(200, self._body_for(url))


# ---- debug_tools: 'nova' in 'innovation' must not flag ----
def test_debug_tools_no_fp_on_generic_words():
    sess = _RouteSession(lambda u: "<h1>We drive innovation on the horizontal axis</h1>")
    assert dbg.scan("http://t", session=sess) is None


def test_debug_tools_flags_real_nova_panel():
    def body(u):
        return "<div>Laravel Nova</div>" if "/nova" in u else "<h1>home</h1>"
    assert dbg.scan("http://t", session=_RouteSession(body)) is not None


# ---- log_exposure: '#0'/'#000' hex color must not flag ----
def test_log_no_fp_on_css_hash_frames():
    sess = _RouteSession(lambda u: "<style>.x{color:#000}#nav{}#0f0</style>")
    assert logx.scan("http://t", session=sess) is None


def test_log_flags_real_laravel_log_line():
    line = "[2024-05-01 12:00:00] production.ERROR: Boom {\"exception\":\"...\"}"
    assert logx.scan("http://t", session=_RouteSession(lambda u: line)) is not None


# ---- git_exposure: 'bare' substring in a soft-404 must not flag ----
def test_git_config_no_fp_on_soft_404():
    html = "<html><body>Nothing to see, the cupboard is bare. filemode of operation.</body></html>"
    assert gitx._is_git_exposed(_Resp(200, html), "/.git/config") is False


def test_git_config_flags_real_config():
    cfg = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
    assert gitx._is_git_exposed(_Resp(200, cfg), "/.git/config") is True

"""Phase 8 — mass_assignment_checker.scan() must be SILENT as a library detector
(no banner/progress pollution on stdout). Under the passive default it is also gated."""

from modules.core import http_config as hc
from modules.detection import mass_assignment_checker as ma


class _Sess:
    def get(self, *a, **k):
        class R:
            status_code = 404
            text = ""
            def json(self):
                return {}
        return R()

    def post(self, *a, **k):
        raise AssertionError("passive scan must not POST")


def test_scan_produces_no_stdout(capsys):
    hc.set_authorized_tier(hc.PASSIVE)
    try:
        ma.scan("http://x.invalid", session=_Sess())
    except hc.RequestBlocked:
        pass
    out = capsys.readouterr().out
    assert out == "", f"library scan leaked stdout: {out!r}"

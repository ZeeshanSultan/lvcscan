"""Integration test for the detect-all SUMMARY path in check.main().

Unlike test_print_summary.py (which unit-tests the renderer in isolation), this drives the REAL
detect-all loop — the `_detect_summary` ledger, the per-iteration `_close_row` closure, the CVE /
non-CVE row split, and per-detector request-delta attribution — by stubbing only the external
seams (registry, detector import, HTTP recon). It locks in the one-row-per-detector invariant and
the late-binding-closure correctness flagged in review (every exit path stamps exactly one row).
"""
import io
import os
import re
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
import check  # noqa: E402
from modules.core import http_config  # noqa: E402

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


# A mixed detector set covering every exit path of the loop:
#   - CVE hit        -> "confirmed_vulnerable"
#   - CVE miss       -> "not_detected"
#   - CVE auth-gated -> "skipped (needs auth)"  (no creds/lab defaults supplied)
#   - generic probe  -> renders in the "Other detectors" block, never as "None (None)"
_FAKE_DETECTORS = [
    {"name": "cve_hit", "cve": "CVE-2025-14894", "category": "cve", "description": "hit"},
    {"name": "cve_miss", "cve": "CVE-2024-47823", "category": "cve", "description": "miss"},
    {"name": "cve_auth", "cve": "CVE-2099-0001", "category": "cve", "description": "auth",
     "requires_auth": True},
    {"name": "generic_probe", "cve": None, "category": "exposure", "description": "a probe"},
]


def _make_scan(verdict_positive, n_requests):
    """Return a fake scan() that issues n_requests counted GETs then returns a hit/miss dict."""
    def _scan(target_url, **kwargs):
        for _ in range(n_requests):
            http_config._record_request_stats()  # simulate a counted HTTP request
        return {"vulnerable": True} if verdict_positive else {"vulnerable": False}
    return _scan


_SCAN_BY_NAME = {
    "cve_hit": _make_scan(True, 2),
    "cve_miss": _make_scan(False, 7),
    "cve_auth": _make_scan(True, 0),   # never called — auth-gated, no creds
    "generic_probe": _make_scan(False, 3),
}


def _run_detect_all(monkeypatch_targets):
    """Run check.main() through the detect-all path with stubbed seams; return cleaned stdout."""
    orig = {}
    for name, val in monkeypatch_targets.items():
        orig[name] = getattr(check, name)
        setattr(check, name, val)
    orig_argv = sys.argv
    try:
        sys.argv = ["check.py", "http://fake.target"]
        buf = io.StringIO()
        with redirect_stdout(buf):
            check.main()
        return _ANSI.sub("", buf.getvalue())
    finally:
        for name, val in orig.items():
            setattr(check, name, val)
        sys.argv = orig_argv


def test_detect_all_summary_one_row_per_detector_correct_verdicts():
    laravel_info = {
        "final_url": "http://fake.target", "cookies": [], "components": [], "route_map": {},
        "_root_resp": None,
    }
    stubs = {
        "get_detectors": lambda: list(_FAKE_DETECTORS),
        "is_laravel": lambda url, **kw: dict(laravel_info),
        "discover_resources": lambda base, **kw: {"components": [], "route_map": {}, "debug_mode": False},
        "_import_detector": lambda det: _SCAN_BY_NAME[det["name"]],
        "_init_http_from_args": lambda args: None,  # don't touch real HTTP config
        "reset_run_memo": lambda: None,
    }
    out = _run_detect_all(stubs)

    # The shared summary header is present (detect-only, NOT exploit).
    assert "Summary (most critical first):" in out
    assert "Exploited:" not in out

    # Headline: exactly one of the four detectors fired a confirmed positive (cve_hit). cve_auth is skipped
    # (counted in denominator, like exploit-mode's scanned count), generic_probe is a non-CVE row.
    # CVE table has 3 rows (the 3 cve detectors); generic_probe is in the "Other detectors" block.
    assert "Confirmed vulnerable: 1 / 3 CVE(s) scanned." in out

    # CVE rows: correct verdicts + request deltas. The confirmed row is HIGHLIGHTED in detect-only
    # mode — a leading "► CONFIRMED" marker, then the bright-green verdict, then the request budget.
    assert re.search(r"CVE-2025-14894 \(rce\) -> ► CONFIRMED\s+scan: confirmed_vulnerable\s+\[requests: detect=2\]", out)
    assert re.search(r"CVE-2024-47823 \(rce\) -> scan: not_detected\s+\[requests: detect=7\]", out)
    assert re.search(r"CVE-2099-0001 \(cve\) -> scan: skipped \(needs auth\)", out)
    # Only the hit row carries the marker — misses must NOT.
    assert "► CONFIRMED" in out
    assert out.count("► CONFIRMED") == 1, "exactly one confirmed CVE row should carry the marker"

    # Generic probe: separate block, real id (NOT "None"), no "None (None)" anywhere.
    assert "Other detectors (non-CVE probes):" in out
    assert re.search(r"generic_probe -> scan: not_detected\s+\[requests: detect=3\]", out)
    assert "None (None)" not in out
    assert "None ->" not in out


def test_detect_all_summary_no_false_positive_when_all_clean():
    laravel_info = {"final_url": "http://fake.target", "cookies": [], "components": [],
                    "route_map": {}, "_root_resp": None}
    all_clean = [d for d in _FAKE_DETECTORS if d["name"] in ("cve_miss", "generic_probe")]
    stubs = {
        "get_detectors": lambda: list(all_clean),
        "is_laravel": lambda url, **kw: dict(laravel_info),
        "discover_resources": lambda base, **kw: {"components": [], "route_map": {}, "debug_mode": False},
        "_import_detector": lambda det: _SCAN_BY_NAME[det["name"]],
        "_init_http_from_args": lambda args: None,
        "reset_run_memo": lambda: None,
    }
    out = _run_detect_all(stubs)
    assert "Confirmed vulnerable: 0 / 1 CVE(s) scanned." in out  # 1 CVE detector (cve_miss), 0 hits

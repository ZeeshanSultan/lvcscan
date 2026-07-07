"""Contract tests for the shared summary renderer check._print_summary.

The detect-only path and the exploit path MUST render through the same function so the
detect-only summary stays "similar to exploitation results" by construction (no drift).
These tests lock in:
  (a) exploit-mode rows still render the `scan: … | exploit: …` two-phase cell + budget note;
      (b) detect-only rows render a `scan: …` cell + a `Confirmed vulnerable: N / M` headline (NOT `Exploited:`);
  (c) the most-critical-first sort (sort=True) used by detect-all;
  (d) no row ever prints a bare "None" id (the generic-probe trap) — CVE rows carry a CVE id.
"""
import io
import os
import re
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
import check  # noqa: E402

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _render(summary, **kw):
    buf = io.StringIO()
    with redirect_stdout(buf):
        check._print_summary(summary, **kw)
    return _ANSI.sub("", buf.getvalue())


def test_exploit_mode_row_shows_both_phases_and_budget():
    summary = [{
        "cve": "CVE-2025-14894", "sev": "Critical", "vclass": "rce",
        "scan": "confirmed_vulnerable", "attempted": True, "success": True,
        "outcome_tag": "exploited", "request_budget": {"detect": 2, "exploit": 8},
    }]
    out = _render(summary, do_exploit=True)
    assert "Exploited: 1 / 1 CVE(s) attempted (1 scanned)." in out
    assert "scan: confirmed_vulnerable | exploit: EXPLOITED" in out
    assert "[requests: detect=2/exploit=8]" in out


def test_exploit_highlight_tiers():
    """highlight=True on the exploit path: EXPLOITED -> ►► PWNED marker; attempted -> no marker
    (normal/working set); n/a -> dimmed, no marker. (ANSI is stripped by _render.)"""
    summary = [
        {"cve": "CVE-2025-14894", "sev": "Critical", "vclass": "rce", "scan": "confirmed_vulnerable",
         "attempted": True, "success": True, "outcome_tag": "exploited",
         "request_budget": {"detect": 2, "exploit": 8}},
        {"cve": "CVE-2021-3129", "sev": "Critical", "vclass": "rce", "scan": "not detected",
         "attempted": True, "success": False, "request_budget": {"detect": 3, "exploit": 1}},
        {"cve": "CVE-2018-15133", "sev": "High", "vclass": "deserialize_rce", "scan": "not detected",
         "attempted": False, "success": False, "request_budget": {"detect": 9}},
    ]
    out = _render(summary, do_exploit=True, highlight=True)
    # The exploited row carries the loud PWNED marker; exactly one (only the success row).
    assert re.search(r"CVE-2025-14894 \(rce\) -> ►► PWNED\s+scan: confirmed_vulnerable \| exploit: EXPLOITED", out)
    assert out.count("►► PWNED") == 1
    # attempted + n/a rows must NOT carry the marker, and must NOT be relabelled as CONFIRMED/PWNED.
    assert "CVE-2021-3129 (rce) -> scan: not detected | exploit: attempted" in out
    assert "CVE-2018-15133 (deserialize_rce) -> scan: not detected | exploit: n/a" in out
    # Detect-only's marker must never appear in exploit mode.
    assert "► CONFIRMED" not in out


def test_detect_only_headline_and_scan_only_cell():
    summary = [
        {"cve": "CVE-2025-14894", "sev": "Critical", "vclass": "rce",
         "scan": "confirmed_vulnerable", "request_budget": {"detect": 2}},
        {"cve": "CVE-2024-47823", "sev": "High", "vclass": "rce",
         "scan": "not detected", "request_budget": {"detect": 7}},
    ]
    out = _render(summary, do_exploit=False)
    # Detect-only headline analog — NOT the exploit headline.
    assert "Confirmed vulnerable: 1 / 2 CVE(s) scanned." in out
    assert "Exploited:" not in out
    # Each row shows only the scan phase (no "| exploit:" segment).
    assert "scan: confirmed_vulnerable" in out
    assert "scan: not detected" in out
    assert "| exploit:" not in out
    # Budget note carried through for detect-only too.
    assert "[requests: detect=2]" in out
    assert "[requests: detect=7]" in out


def test_detect_only_sort_is_most_critical_first():
    # Deliberately out of severity order on input; sort=True must reorder Critical before High before Medium.
    summary = [
        {"cve": "CVE-2024-13918", "sev": "Medium", "vclass": "xss", "scan": "not detected"},
        {"cve": "CVE-2025-14894", "sev": "Critical", "vclass": "rce", "scan": "confirmed_vulnerable"},
        {"cve": "CVE-2024-47823", "sev": "High", "vclass": "rce", "scan": "not detected"},
    ]
    out = _render(summary, do_exploit=False, sort=True)
    order = [m for m in re.findall(r"CVE-\d{4}-\d+", out)]
    assert order == ["CVE-2025-14894", "CVE-2024-47823", "CVE-2024-13918"], order


def test_skipped_and_error_rows_are_not_counted_as_detected():
    summary = [
        {"cve": "CVE-A", "sev": "High", "vclass": "rce", "scan": "skipped (needs auth)"},
        {"cve": "CVE-B", "sev": "High", "vclass": "rce", "scan": "not detected (version-suppressed)"},
        {"cve": "CVE-C", "sev": "High", "vclass": "rce", "scan": "load error"},
        {"cve": "CVE-D", "sev": "High", "vclass": "rce", "scan": "confirmed_vulnerable"},
    ]
    out = _render(summary, do_exploit=False)
    # Only the exact confirmed vulnerability verdict counts as a hit.
    assert "Confirmed vulnerable: 1 / 4 CVE(s) scanned." in out


def test_print_done_can_be_deferred():
    summary = [{"cve": "CVE-X", "sev": "Low", "vclass": "info_disclosure", "scan": "not detected"}]
    assert "Done." not in _render(summary, do_exploit=False, print_done=False)
    assert "Done." in _render(summary, do_exploit=False, print_done=True)


def test_row_emphasis_classification():
    """Direct contract for the emphasis classifier that drives the highlight tiers."""
    em = check._row_emphasis
    oob = {"CVE-OOB"}
    # detect-only: scan verdict is the signal.
    assert em({"cve": "X", "scan": "confirmed_vulnerable"}, do_exploit=False) == "hit"
    assert em({"cve": "X", "scan": "not detected"}, do_exploit=False) == "dim"
    assert em({"cve": "X", "scan": "skipped (needs auth)"}, do_exploit=False) == "dim"
    # exploit: outcome is the signal (EXPLOITED loud, only n/a dimmed).
    assert em({"cve": "X", "success": True, "attempted": True}, do_exploit=True) == "hit"
    assert em({"cve": "X", "success": False, "attempted": True}, do_exploit=True) == "normal"
    assert em({"cve": "CVE-OOB", "success": False, "attempted": False}, do_exploit=True,
              oob_pending_cves=oob) == "normal"   # verify-OOB pending stays visible
    assert em({"cve": "X", "success": False, "attempted": False}, do_exploit=True) == "dim"  # n/a

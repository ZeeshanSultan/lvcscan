"""Phase 0.3 — structured provenance so a lab-only / disputed / unverified sink is
never framed as a working framework RCE. Adds integrity / sink_realism / working_rce
/ nvd_status to CVE metadata and a confirmed-only count for the headline.
"""

from modules.cves import metadata as md


def test_default_cve_is_confirmed_framework():
    m = md.metadata_for("CVE-2021-3129")  # real Ignition RCE against a real sink
    assert m.integrity == "confirmed"
    assert m.sink_realism == "framework"


def test_future_dated_cve_is_unverified_and_not_working_rce():
    m = md.metadata_for("CVE-2026-23524")
    assert m.integrity == "unverified"
    assert m.working_rce is False


def test_lab_invented_2025_14894_is_unverified():
    assert md.metadata_for("CVE-2025-14894").integrity == "unverified"


def test_disputed_vuldb_rows_marked_disputed():
    assert md.metadata_for("CVE-2022-2870").integrity == "disputed"
    assert md.metadata_for("CVE-2022-2886").integrity == "disputed"


def test_lab_only_sinks_flagged_not_working_rce():
    for cve in ("CVE-2018-15133", "CVE-2021-28254", "CVE-2020-19316"):
        m = md.metadata_for(cve)
        assert m.working_rce is False, cve
        assert m.sink_realism in ("app-sink-required", "lab-synthetic"), cve


def test_detector_spec_surfaces_non_confirmed_integrity():
    spec = md.detector_spec_for("CVE-2026-23524")
    assert spec.get("integrity") == "unverified"


def test_confirmed_cves_excludes_disputed_and_unverified():
    confirmed = set(md.confirmed_cves())
    for bad in ("CVE-2026-23524", "CVE-2025-14894", "CVE-2022-2870", "CVE-2022-2886"):
        assert bad not in confirmed
    assert "CVE-2021-3129" in confirmed
    assert md.confirmed_cve_count() == len(confirmed)
    assert md.confirmed_cve_count() < len(md.all_cves())

"""Phase 3 — --list surfaces provenance tags and a confirmed-vs-total count so a
disputed / unverified / lab-only sink never reads as a working framework CVE."""

import re

import check


def _strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def test_list_tags_disputed_and_unverified_and_counts(capsys):
    check._print_cve_list()
    out = _strip_ansi(capsys.readouterr().out)

    # Disputed VulDB row and the future/unverified row are tagged.
    dispute_line = next(l for l in out.splitlines() if "CVE-2022-2870" in l)
    assert "DISPUTED" in dispute_line
    unverified_line = next(l for l in out.splitlines() if "CVE-2026-23524" in l)
    assert "UNVERIFIED" in unverified_line

    # A confirmed framework RCE carries no provenance tag.
    ign_line = next(l for l in out.splitlines() if "CVE-2021-3129" in l)
    assert "DISPUTED" not in ign_line and "UNVERIFIED" not in ign_line and "LAB" not in ign_line

    # Headline splits confirmed vs disputed/unverified/lab-only.
    assert "confirmed;" in out and "disputed/unverified/lab-only" in out

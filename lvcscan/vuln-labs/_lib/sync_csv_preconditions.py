#!/usr/bin/env python3
"""Sync docs/laravel_cves.csv from CVE_METADATA: rewrite the "Exploit Pre-conditions"
column and sort rows by severity (Critical -> Low).

CVE_METADATA (modules/cves/metadata.py) is the source of truth for the canonical
precondition block; this rewrites the catalog CSV's column to match and re-sorts
rows by the headline NVD "Severity" (tie-break: independent severity, then CVE).
All other columns are preserved verbatim.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSV = ROOT / "docs" / "laravel_cves.csv"


def main() -> None:
    sys.path.insert(0, str(ROOT))
    from modules.cves.metadata import CVE_METADATA, SEV_RANK

    with open(CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    updated = 0
    for row in rows:
        cve = (row.get("CVE") or "").strip()
        meta = CVE_METADATA.get(cve)
        if not meta:
            print(f"SKIP {cve}: not in CVE_METADATA")
            continue
        want = "\n".join(meta.preconditions or []).strip()
        if (row.get("Exploit Pre-conditions") or "").strip() != want:
            row["Exploit Pre-conditions"] = want
            updated += 1
            print(f"update {cve}")

    # Sort Critical -> Low by the headline NVD severity; tie-break by the independent
    # severity, then CVE id, so the order is stable and deterministic.
    def _rank(row: dict) -> tuple:
        nvd = SEV_RANK.get((row.get("Severity") or "").strip(), 99)
        indep = SEV_RANK.get((row.get("Severity (Independent)") or "").strip(), 99)
        return (nvd, indep, (row.get("CVE") or "").strip())

    rows.sort(key=_rank)

    with open(CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nSaved {CSV.name}; {updated} precondition rows updated; {len(rows)} rows sorted by severity.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Sync the "Exploit Pre-conditions" column in docs/laravel_cves.csv from CVE_METADATA.

CVE_METADATA (modules/cves/metadata.py) is the source of truth for preconditions; this rewrites
the catalog CSV's column to match. All other columns are preserved verbatim.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSV = ROOT / "docs" / "laravel_cves.csv"


def main() -> None:
    sys.path.insert(0, str(ROOT))
    from modules.cves.metadata import CVE_METADATA

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

    with open(CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nSaved {CSV.name}; {updated} precondition rows updated.")


if __name__ == "__main__":
    main()

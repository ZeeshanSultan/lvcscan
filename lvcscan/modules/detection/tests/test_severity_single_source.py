"""Phase 8 — CVE metadata is the SINGLE SOURCE of severity. No cve_*.py module may
hardcode a "severity" literal that diverges from CVE_METADATA."""

import os
import re

from modules.cves.metadata import CVE_METADATA

_LEVEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "none": "None"}
_CVE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "cves")


def test_no_module_severity_diverges_from_metadata():
    offenders = []
    for cve, meta in CVE_METADATA.items():
        path = os.path.join(_CVE_DIR, meta.slug + ".py")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            txt = f.read()
        for m in re.finditer(r'"severity"\s*:\s*"([^"]+)"', txt):
            canon = _LEVEL.get(m.group(1).lower())
            if canon and canon != meta.severity:
                offenders.append(f"{cve}: module={m.group(1)} metadata={meta.severity}")
    assert not offenders, "severity divergence from metadata:\n" + "\n".join(offenders)


def test_reconciled_values():
    assert CVE_METADATA["CVE-2024-52301"].severity == "High"   # GHSA 8.7
    assert CVE_METADATA["CVE-2024-29291"].severity == "Medium"
    assert CVE_METADATA["CVE-2024-48987"].severity == "High"

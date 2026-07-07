"""Registry helpers re-exported for scan pipeline wiring."""

from modules.registry.detect import DETECTORS, get_detectors, detectors_requiring_auth, _import_detector
from modules.registry.exploit import CVE_META, SEV_RANK, cves_by_criticality, _import_exploit, version_suppresses


def requires_component_map():
    """Build a direct CVE -> required component map from detection registry metadata."""
    return {
        d["cve"]: d["requires_component"]
        for d in get_detectors()
        if d.get("cve") and d.get("requires_component")
    }


def registry_health_check():
    """Return lightweight diagnostics for the unified registry contracts."""
    return {
        "detectors": len(DETECTORS),
        "exploit_cves": len(CVE_META),
    }

import os, sys, importlib
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.registry.detect import get_detectors
from modules.registry.exploit import CVE_META, CVE_SCOPE, _import_exploit
from modules.cves import CVE_METADATA, import_scan, module_path_for

NEW = ["ckfinder_connector_config","ci_language_lfi","cookie_reflection_xss",
       "ci_admin_reflected_xss","ci_admin_blind_sqli","ci_role_field_privesc",
       "api_tunnel_bypass","html_config_disclosure","header_cookie_hygiene",
       "host_header_injection"]

def test_all_new_detectors_registered_and_importable():
    dets = get_detectors()
    names = {d["name"] for d in dets}
    for n in NEW:
        assert n in names, f"{n} not in DETECTORS"
        d = next(d for d in dets if d["name"] == n)
        mod = importlib.import_module(d["module"])
        assert hasattr(mod, d["func"]), f"{n}.{d['func']} missing"

def test_detector_count_is_54():
    assert len(get_detectors()) == 54


def test_all_registered_detectors_import():
    for d in get_detectors():
        mod = importlib.import_module(d["module"])
        assert hasattr(mod, d["func"]), f"{d['name']}.{d['func']} missing"


def test_all_registered_exploits_import():
    for cve in CVE_META:
        fn = _import_exploit(cve)
        assert callable(fn), f"{cve} exploit() missing"


def test_all_cves_are_unified_modules():
    root = Path(__file__).resolve().parents[3]
    assert not list((root / "modules" / "detection").glob("cve_*.py"))
    assert not list((root / "modules" / "exploitation").glob("cve_*.py"))
    for cve in CVE_META:
        module_path = module_path_for(cve)
        assert module_path.startswith("modules.cves.cve_")
        mod = importlib.import_module(module_path)
        assert getattr(mod, "META")["cve"] == cve
        assert callable(import_scan(cve))
        assert callable(_import_exploit(cve))


def test_cve_detector_rows_use_unified_modules():
    for d in get_detectors():
        if d.get("cve"):
            assert d["module"] == module_path_for(d["cve"])

def test_app_root_disclosure_registered_and_importable():
    dets = {d["name"]: d for d in get_detectors()}
    assert "app_root_disclosure" in dets, "app_root_disclosure not in DETECTORS"
    d = dets["app_root_disclosure"]
    mod = importlib.import_module(d["module"])
    assert hasattr(mod, d["func"]), "app_root_disclosure.scan missing"

def test_app_specific_modules_tagged():
    by = {d["name"]: d for d in get_detectors()}
    assert by["ci_role_field_privesc"].get("scope") == "app-specific"
    assert by["api_tunnel_bypass"].get("scope") == "app-specific"
    assert CVE_SCOPE.get("app_ci_role_privesc") == "app-specific"
    assert CVE_SCOPE.get("app_ckfinder_upload") == "generic"
    assert CVE_SCOPE.get("app_ci_blind_sqli") == "generic"


CANON_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
CANON_SCENARIOS = {
    "realistic", "config-dependent", "app-sink-required",
    "lab-unauth/prod-auth", "disputed", "disputed (synthetic sink)", "partial",
}


def test_all_cves_use_canonical_precondition_schema():
    """Every CVE's preconditions are the 6 canonical fixed fields, in order, with
    APP_KEY / Command-capable derived correctly from the structured metadata."""
    for cve, meta in CVE_METADATA.items():
        lines = meta.preconditions or []
        keys = [ln.split(":", 1)[0] for ln in lines]
        assert keys == ["Auth", "APP_KEY", "Affected", "Trigger", "Command-capable", "Scenario"], \
            f"{cve} preconditions not in canonical schema: {keys}"
        fields = {ln.split(":", 1)[0]: ln.split(":", 1)[1].strip() for ln in lines}
        # Derived booleans must match the structured source of truth.
        want_key = "required" if meta.app_key.get("required_for_exploit") else "not required"
        assert fields["APP_KEY"] == want_key, f"{cve} APP_KEY field disagrees with metadata"
        want_cmd = "yes" if meta.command_capable else "no"
        assert fields["Command-capable"] == want_cmd, f"{cve} Command-capable disagrees with metadata"
        assert fields["Scenario"] in CANON_SCENARIOS, f"{cve} unknown Scenario {fields['Scenario']!r}"
        assert fields["Affected"] and fields["Trigger"] and fields["Auth"], f"{cve} has an empty field"
        # Auth must not claim unauthenticated when exploitation structurally needs auth.
        if meta.auth.get("exploit_required"):
            assert not fields["Auth"].startswith("none"), \
                f"{cve} Auth says 'none' but exploit_required=True"


def test_catalog_csv_is_sorted_by_severity():
    import csv
    from modules.cves.metadata import SEV_RANK
    root = Path(__file__).resolve().parents[3]
    with open(root / "docs" / "laravel_cves.csv", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    ranks = [(SEV_RANK.get(r["Severity"], 99), SEV_RANK.get(r["Severity (Independent)"], 99), r["CVE"])
             for r in rows]
    assert ranks == sorted(ranks), "catalog CSV is not sorted Critical -> Low"


def test_catalog_csv_preconditions_match_unified_cve_metadata():
    import csv

    root = Path(__file__).resolve().parents[3]
    catalog = root / "docs" / "laravel_cves.csv"
    with open(catalog, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cve = (row.get("CVE") or "").strip()
            assert cve in CVE_METADATA, f"{cve} missing from unified CVE metadata"
            expected = "\n".join(CVE_METADATA[cve].preconditions or []).strip()
            actual = (row.get("Exploit Pre-conditions") or "").strip()
            assert actual == expected, f"{cve} catalog preconditions drifted from metadata"

from modules.registry.exploit import scope_of, CVE_SCOPE
from modules.registry.detect import DETECTORS

def test_scope_of_defaults_generic():
    # An unknown / untagged CVE is generic by default (back-compat for the 41 existing CVEs).
    assert scope_of("CVE-2017-16894") == "generic"
    assert scope_of("DOES-NOT-EXIST") == "generic"

def test_scope_of_reads_explicit_tag():
    # CVE_SCOPE may carry explicit app-specific tags for new synthetic ids.
    assert CVE_SCOPE.get("app_ckfinder_upload", "generic") in ("generic", "app-specific")

def test_detectors_scope_values_are_valid():
    for d in DETECTORS:
        assert d.get("scope", "generic") in ("generic", "app-specific"), d.get("name")

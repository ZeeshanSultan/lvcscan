import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from modules.cves import cve_2024_47823 as m

# Regression for the silently-swallowed NameError in the LW3 unauthenticated fallback.
#
# The fallback success path (cve_2024_47823.py ~line 1723) resolves the Livewire
# version_status to decide whether a fallback RCE win should be RE-ATTRIBUTED to
# CVE-2025-14894 (via _attribution_for_fallback_success). It used to call
# `_detect_47823(...)`, a symbol that is NEVER defined or imported in the module.
# The call sat inside a bare `try/except Exception` that set `_det = None`, so the
# NameError was swallowed and re-attribution was silently SKIPPED on every fallback
# success (in particular the version_status == "patched" branch could never fire,
# because _vstatus was always None). The detection entry point is scan(); the fix
# points the call at scan(base_url, perform_upload_test=False).


def test_detection_symbol_resolves():
    """The dangling _detect_47823 name must be gone; scan() is the real entry point and
    is a module global, so it resolves from the exploit() fallback path in this module."""
    assert not hasattr(m, "_detect_47823"), (
        "_detect_47823 is undefined; the fallback re-attribution must call scan() instead"
    )
    assert callable(m.scan), "scan() is the detection entry point used by the fallback"

    # Guard against the bug regressing in source: no call site should reference the
    # dangling symbol again.
    src = open(m.__file__).read()
    tree = ast.parse(src)
    bad = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_detect_47823"
    ]
    assert not bad, "found a call to the undefined _detect_47823; use scan() instead"


def test_scan_accepts_fallback_call_signature():
    """The fallback calls scan(base_url, perform_upload_test=False) — that exact
    positional+keyword form must be a valid signature (i.e. scan won't raise TypeError
    on the arguments the fallback passes)."""
    import inspect

    sig = inspect.signature(m.scan)
    # First parameter is positional (the base url); perform_upload_test is keyword-only.
    params = list(sig.parameters.values())
    assert params[0].name in ("target_url", "url", "base", "base_url"), (
        f"scan()'s first parameter should be the target URL, got {params[0].name!r}"
    )
    assert "perform_upload_test" in sig.parameters, (
        "scan() must accept perform_upload_test (the fallback passes it)"
    )
    # bind the exact call the fallback makes — raises TypeError if the signature drifts.
    sig.bind("https://t", perform_upload_test=False)


def test_reattribution_runs_on_patched_version():
    """The re-attribution decision must fire for a PATCHED Livewire version — the branch
    that was dead while _det was always None. _attribution_for_fallback_success is the
    pure decision the fallback feeds version_status into."""
    att = m._attribution_for_fallback_success("patched", filemanager_sink=False)
    assert att is not None, "a patched-version fallback win must re-attribute (was silently skipped)"
    assert att["cve"] == m._FILEMANAGER_CVE == "CVE-2025-14894"
    assert "outcome" in att and "outcome_tag" in att


def test_reattribution_keeps_native_for_unknown_generic():
    """Negative control: an unknown version with no filemanager sink stays native 47823
    (so the fix doesn't over-attribute)."""
    assert m._attribution_for_fallback_success(None, filemanager_sink=False) is None
    assert m._attribution_for_fallback_success("vulnerable", filemanager_sink=False) is None

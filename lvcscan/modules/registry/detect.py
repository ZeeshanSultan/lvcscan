"""Detector registry — ordered list of misconfig + CVE detectors for the default comprehensive scan.

This is the source of truth for what runs in `check.py`'s main path (when not using --cve/--exploit).
Adding a new detector is now a 1-2 line edit here + implementing the module; no more edits to the
long import list or call sequence in check.py.

Each entry:
  name: short label for logging/_safe_scan and HTTP active module
  module: python module path (importlib)
  func: attribute name to call, usually "scan" (some modules expose scan_detailed too)
  category: "exposure" | "cve" | "behavioral" etc for future filtering/grouping
  cve: optional canonical CVE id when applicable
  requires_auth: if True, the main driver skips the detector unless -U/-P or -H auth material is
                 present. Lab run.sh files print any seeded credentials explicitly.
  scope: optional "generic" | "app-specific" — tags whether the detector's LOGIC is
         framework-portable (generic) or hardcodes this-target field-names/paths (app-specific).
         Absent = "generic".
  description: one-liner for help/ --list-detectors
"""

from __future__ import annotations

from typing import Any, Dict, List

from modules.cves.metadata import detector_spec_for

DETECTORS: List[Dict[str, Any]] = [
    # --- Block A: APP_KEY producers (pos 1-4) ---
    {"name": "env", "module": "modules.detection.env_exposure", "func": "scan", "category": "exposure", "description": "Exposed .env file (APP_KEY / DB / mail creds)"},
    detector_spec_for("CVE-2017-16894"),
    detector_spec_for("CVE-2017-14775"),
    {"name": "app_root_disclosure", "module": "modules.detection.app_root_disclosure", "func": "scan", "category": "exposure", "description": "Whole application root served as static files (source/config/DB/.env exfiltrable)"},
    detector_spec_for("CVE-2025-49132"),
    detector_spec_for("CVE-2023-43661"),
    # --- Block B: APP_KEY consumers (pos 5-8) — run immediately after producers so a harvested key chains in ---
    detector_spec_for("CVE-2018-15133"),
    detector_spec_for("CVE-2024-48987"),
    detector_spec_for("CVE-2024-55555"),
    detector_spec_for("CVE-2024-55556"),
    # --- Block C: Cheap exposure detectors (pos 9-15) ---
    {"name": "git", "module": "modules.detection.git_exposure", "func": "scan", "category": "exposure", "description": "Exposed .git directory / config / objects"},
    {"name": "log", "module": "modules.detection.log_exposure", "func": "scan", "category": "exposure", "description": "Readable storage/logs/laravel.log"},
    detector_spec_for("CVE-2024-29291"),
    {"name": "env_backup", "module": "modules.detection.env_backup_exposure", "func": "scan", "category": "exposure", "description": ".env.backup / .env.* variants exposed"},
    {"name": "phpinfo", "module": "modules.detection.phpinfo_exposure", "func": "scan", "category": "exposure", "description": "phpinfo() page leaking environment"},
    {"name": "debug_tools", "module": "modules.detection.debug_tools_exposure", "func": "scan", "category": "exposure", "description": "Debug panels exposed (debugbar / telescope / clockwork)"},
    {"name": "routes", "module": "modules.detection.routes_exposure", "func": "scan", "category": "exposure", "description": "routes/web.php or cached route dump exposed"},
    {"name": "token_leakage", "module": "modules.detection.token_leakage", "func": "scan", "category": "exposure", "description": "XSRF / session token leakage + config"},
    # --- Block D: Gated CVEs (pos 16-20) ---
    # Livewire block (gated — skipped when livewire not detected)
    detector_spec_for("CVE-2024-47823"),
    detector_spec_for("CVE-2025-54068"),
    detector_spec_for("CVE-2025-14894"),
    # Reverb block (gated — skipped when laravel_reverb not detected)
    detector_spec_for("CVE-2026-23524"),
    # --- Block E: Remaining CVEs (pos 21-49) in original relative order ---
    detector_spec_for("CVE-2021-3129"),
    detector_spec_for("CVE-2021-28254"),
    detector_spec_for("CVE-2024-52301"),
    detector_spec_for("CVE-2021-43617"),
    detector_spec_for("CVE-2024-21546"),
    detector_spec_for("CVE-2022-2870"),
    detector_spec_for("CVE-2025-27515"),
    detector_spec_for("CVE-2016-10074"),
    detector_spec_for("CVE-2020-19316"),
    detector_spec_for("CVE-2022-2886"),
    detector_spec_for("CVE-2024-55661"),
    detector_spec_for("CVE-2022-25838"),
    detector_spec_for("CVE-2020-24940"),
    detector_spec_for("CVE-2020-24941"),
    {"name": "sqli_time_api", "module": "modules.detection.sqli_time_api", "func": "scan", "category": "behavioral", "description": "Time-based SQLi probe on common API endpoints (active injection)"},
    detector_spec_for("CVE-2024-22836"),
    detector_spec_for("CVE-2023-46865"),
    detector_spec_for("CVE-2020-5256"),
    # --- Block F: Phase 7 — multi-step / active injection probes (run last, pos 50-53) ---
    {"name": "laravel_filemanager", "module": "modules.detection.laravel_filemanager_exposure", "func": "scan_detailed", "category": "exposure", "description": "Detailed Laravel File Manager exposure"},
    {"name": "queue_deserialization_rce", "module": "modules.detection.queue_deserialization_rce", "func": "scan_detailed", "category": "exposure", "description": "Queue/Horizon endpoint exposure enumeration (passive, GET-only serialized-content surface)"},
    {"name": "mass_assignment", "module": "modules.detection.mass_assignment_checker", "func": "scan", "category": "behavioral", "description": "Generic mass-assignment / guarded-bypass probe (active POST/PUT)"},
    {"name": "deserialization_poi", "module": "modules.detection.deserialization_poi", "func": "scan", "category": "behavioral", "description": "PHP deserialization gadget points-of-interest (active object-injection probe)"},
    # --- Block G: round-3 coverage detectors (2026-06-10) ---
    {"name": "ckfinder_connector_config", "module": "modules.detection.ckfinder_connector_config", "func": "scan", "category": "exposure", "scope": "generic", "requires_auth": True, "description": "CKFinder connector reachable + uploadCheckImages=false / blocklist gaps (upload-RCE primitive, prove-not-detonate)"},
    {"name": "ci_language_lfi", "module": "modules.detection.ci_language_lfi", "func": "scan", "category": "behavioral", "scope": "generic", "description": "CI i18n language-param filesystem path injection (path-disclosure 500; detect-first/needs-validation)"},
    {"name": "cookie_reflection_xss", "module": "modules.detection.cookie_reflection_xss", "func": "scan", "category": "behavioral", "scope": "generic", "description": "Cookie value read into DOM without encoding (DOM/stored XSS, static sink scan)"},
    {"name": "ci_admin_reflected_xss", "module": "modules.detection.ci_admin_reflected_xss", "func": "scan", "category": "behavioral", "scope": "generic", "requires_auth": True, "description": "Reflected XSS on CI admin params (benign-canary reflection)"},
    {"name": "ci_admin_blind_sqli", "module": "modules.detection.ci_admin_blind_sqli", "func": "scan", "category": "behavioral", "scope": "generic", "requires_auth": True, "description": "Blind SQLi differential on authed CI admin search (prove-not-detonate)"},
    {"name": "ci_role_field_privesc", "module": "modules.detection.ci_role_field_privesc", "func": "scan", "category": "behavioral", "scope": "app-specific", "requires_auth": True, "description": "CI role-field privilege escalation sink reachability (prove-not-detonate)"},
    {"name": "api_tunnel_bypass", "module": "modules.detection.api_tunnel_bypass", "func": "scan", "category": "behavioral", "scope": "app-specific", "requires_auth": True, "description": "Transaction API data accessible without ECDH/AES tunnel (plain session)"},
    {"name": "html_config_disclosure", "module": "modules.detection.html_config_disclosure", "func": "scan", "category": "exposure", "scope": "generic", "description": "Cleartext config/SSO/env markers exposed in served HTML"},
    {"name": "header_cookie_hygiene", "module": "modules.detection.header_cookie_hygiene", "func": "scan", "category": "exposure", "scope": "generic", "description": "Missing security headers / EOL PHP disclosure / weak cookie flags"},
    {"name": "host_header_injection", "module": "modules.detection.host_header_injection", "func": "scan", "category": "behavioral", "scope": "generic", "description": "Host / X-Forwarded-Host reflected into redirect targets or body URLs (reset-link poisoning primitive; benign canary, GET-only, non-mutating)"},
]

def get_detectors() -> List[Dict[str, Any]]:
    """Return the ordered list of detectors to run in a default scan."""
    return list(DETECTORS)

def detectors_requiring_auth() -> List[Dict[str, Any]]:
    return [d for d in DETECTORS if d.get("requires_auth")]

def _import_detector(dspec: Dict[str, Any]):
    """Lazy import so a broken detector module never prevents the rest of the scan."""
    import importlib
    mod = importlib.import_module(dspec["module"])
    return getattr(mod, dspec["func"])


# ----------------------------------------------------------------------------
# Recommended result envelope (rec8) for future uniformity.
# Detectors / CVE scan() should return dicts containing a subset of these keys
# so the driver and reporting can be generic. Existing modules are grandfathered;
# new code should prefer this shape.
#
# Common keys:
#   vulnerable: bool
#   severity: "Critical" | "High" | "Medium" | "Low" | "None"
#   category: "rce" | "deserialize_rce" | "xss" | "sqli" | "info_disclosure" | "exposure" | ...
#   endpoint: str (the URL or route that was the vector)
#   evidence: list[str] or str
#   mitigation: short human string ("patch to X, or set APP_DEBUG=false, or move logs out of webroot")
#   confidence: "high" | "medium" | "low"   (distinct from detection confidence)
#   requires_auth: bool
#   requires_app_key: bool
#   artifacts: dict (extra files, tokens, versions, etc.)
#
# The registry-driven driver already tolerates any dict and surfaces a slim view.
# ----------------------------------------------------------------------------
RECOMMENDED_RESULT_KEYS = [
    "vulnerable", "severity", "category", "endpoint", "evidence", "mitigation",
    "confidence", "requires_auth", "requires_app_key", "artifacts", "version_status",
]

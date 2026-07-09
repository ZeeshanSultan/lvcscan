#!/usr/bin/env python3
from __future__ import annotations

import re
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional

import requests

from modules.core import http_config
from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for("CVE-2024-29291")

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def _load_log_exposure_module():
    """Load the generic log detector without executing modules.detection.__init__."""
    module_path = Path(__file__).resolve().parents[1] / "detection" / "log_exposure.py"
    spec = importlib.util.spec_from_file_location("_lvc_log_exposure", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load log_exposure from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_LOG_EXPOSURE = _load_log_exposure_module()

_PDO_CONSTRUCT_RE = re.compile(
    r"PDO->__construct\(\s*"
    r"['\"][^'\"]*(?:mysql|pgsql|sqlsrv):[^'\"]*['\"]\s*,\s*"
    r"['\"](?P<username>[^'\"]{1,128})['\"]\s*,\s*"
    r"['\"](?P<password>[^'\"]{1,256})['\"]",
    re.IGNORECASE,
)

_ENV_DB_RE = re.compile(
    r"^\s*(DB_HOST|DB_DATABASE|DB_USERNAME|DB_PASSWORD)\s*=\s*(?P<value>.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_CONFIG_ARRAY_RE = re.compile(
    r"['\"](?:username|user)['\"]\s*=>\s*['\"](?P<username>[^'\"]{1,128})['\"].{0,240}?"
    r"['\"]password['\"]\s*=>\s*['\"](?P<password>[^'\"]{1,256})['\"]",
    re.IGNORECASE | re.DOTALL,
)


def scan(target_url, *, session=None, username=None, password=None, **kwargs):
    """Confirm CVE-2024-29291 only when a readable Laravel log leaks DB credentials.

    The generic low-hanging detector already proves /storage/logs/laravel.log is
    readable. This CVE wrapper deliberately raises the verdict only when the log
    also contains database credential material, because the CVE is disputed and
    otherwise collapses to a generic log exposure misconfiguration.
    """
    sess = session or http_config.get_auth_session()
    result: Dict[str, object] = {
        "cve_id": "CVE-2024-29291",
        "name": "Laravel laravel.log database credential disclosure",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "endpoint": None,
        "evidence": [],
        "detection_methods": [],
        "confidence": "medium",
        "error": None,
    }

    finding = _LOG_EXPOSURE.scan(target_url, session=sess)
    if not finding:
        result["evidence"].append("Laravel log file was not readable via log_exposure")
        return result

    log_url = str(finding.get("url") or "")
    result["endpoint"] = log_url
    result["detection_methods"].append("log_exposure")

    try:
        response = sess.get(log_url, timeout=10, allow_redirects=False, verify=False)
    except Exception as exc:
        result["error"] = f"failed to re-fetch exposed log: {exc}"
        result["status"] = "surface_present"
        result["verdict"] = "surface_present"
        result["proof_type"] = "log_readable"
        return result

    if response.status_code != 200:
        result["evidence"].append(f"exposed log re-fetch returned HTTP {response.status_code}")
        result["status"] = "surface_present"
        result["verdict"] = "surface_present"
        result["proof_type"] = "log_readable"
        return result

    body = response.text or ""
    credential_evidence = _find_db_credential_evidence(body)
    if not credential_evidence:
        result["status"] = "surface_present"
        result["verdict"] = "surface_present"
        result["proof_type"] = "log_readable"
        result["evidence"].append(
            "Laravel log is readable, but no DB credential evidence was found"
        )
        return result

    result.update(
        {
            "vulnerable": True,
            "status": "confirmed_vulnerable",
            "verdict": "confirmed_vulnerable",
            "proof_type": "read_only_credential_disclosure",
            "severity": "Medium",  # single-source: matches CVE_METADATA (disputed info-disclosure)
            "category": "info_disclosure",
            "cve": "CVE-2024-29291",
            "http_status": response.status_code,
            "confidence": "high",
            "evidence": credential_evidence,
            "mitigation": (
                "Serve Laravel from public/ only, block storage/logs from the web, "
                "rotate exposed database credentials, and reduce sensitive exception logging."
            ),
            "artifacts": {
                "log_url": log_url,
                "evidence_types": [item.split(":", 1)[0] for item in credential_evidence],
            },
        }
    )
    return result


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None, **kwargs):
    """Read-only confirmation for CVE-2024-29291."""
    scan_result = scan(target_url, session=session, username=username, password=password, **kwargs)
    success = scan_result.get("verdict") == "confirmed_vulnerable"
    return {
        "cve": "CVE-2024-29291",
        "attempted": True,
        "success": success,
        "vuln_class": "info_disclosure",
        "evidence": "\n".join(scan_result.get("evidence") or []),
        "detail": (
            "Readable Laravel log contains database credential evidence."
            if success
            else "Readable Laravel log did not expose database credential evidence."
        ),
        "artifacts": scan_result.get("artifacts") or {"endpoint": scan_result.get("endpoint")},
        "requires": [] if success else ["publicly readable laravel.log with DB credential material"],
        "reason": "" if success else scan_result.get("status", "not_detected"),
    }


def _find_db_credential_evidence(body: str) -> List[str]:
    evidence: List[str] = []

    pdo_match = _PDO_CONSTRUCT_RE.search(body or "")
    if pdo_match:
        evidence.append(
            "pdo_construct: PDO connection stack trace exposes DB username/password arguments "
            f"(user={_redact(pdo_match.group('username'))}, password={_redact(pdo_match.group('password'))})"
        )

    env_values: Dict[str, str] = {}
    for match in _ENV_DB_RE.finditer(body or ""):
        key = match.group(1).upper()
        value = _clean_value(match.group("value"))
        if value and value.lower() not in {"null", "false", "none"}:
            env_values[key] = value
    if env_values.get("DB_PASSWORD") and (
        env_values.get("DB_USERNAME") or env_values.get("DB_DATABASE") or env_values.get("DB_HOST")
    ):
        fields = ", ".join(sorted(env_values))
        evidence.append(f"env_db_credentials: Laravel log exposes DB_* credential fields ({fields})")

    config_match = _CONFIG_ARRAY_RE.search(body or "")
    if config_match:
        evidence.append(
            "config_array: Laravel config dump exposes database username/password "
            f"(user={_redact(config_match.group('username'))}, password={_redact(config_match.group('password'))})"
        )

    return evidence


def _clean_value(value: str) -> str:
    value = (value or "").strip()
    value = re.sub(r"\s+#.*$", "", value).strip()
    return value.strip('"').strip("'").strip()


def _redact(value: str) -> str:
    value = _clean_value(value)
    if not value:
        return "<empty>"
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***{value[-2:]} (len={len(value)})"

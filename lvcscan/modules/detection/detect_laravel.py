#!/usr/bin/env python3
"""
Laravel Detection Module — evidence-aggregation rewrite.

Determines whether a target is genuinely Laravel by collecting INDEPENDENT signals, bucketing them
into source families, and scoring with family-independence (correlated signals can't stack). Replaces
the old "any single indicator => detected" logic (evidence-aggregation model documented inline below).

Two orthogonal outputs:
  * confidence_label: confirmed / likely / possible / not_laravel  (how sure it's Laravel-ish)
  * classification:   framework / laravel_like / component_only / not_laravel  (what KIND)

CONTRACT (check.py depends on this): is_laravel(url) returns None ONLY when the verdict is
'not_laravel'; otherwise it returns a truthy dict that is a SUPERSET of the historical keys
(url, status_code, php_version, laravel_version_guess, composer_framework_version,
composer_lock_version, vendor_exposed, cookies, indicators, ecosystem, env_exposed) plus the new
keys (confidence_label, score, classification, evidence). Existing keys are never renamed/removed.

Scope: defensive identification only.
"""

import base64
import json
import re
from urllib.parse import unquote

import requests

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base
from modules.probes.appkey_recovery import classify_laravel_cookie, describe_cookie_variation
from modules.probes.response_memo import (
    ResponseSnapshot, get_run_memo, memo_key,
)

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# Scoring model (pure, unit-testable: see tests/test_detect_laravel.py)
# ============================================================================

TIER_PTS = {"strong": 5, "medium": 3, "weak": 1, "negative": -4}

# Source families — each contributes ONLY its single strongest signal to the score, so multiple
# views of the same source (e.g. three body substrings) cannot inflate confidence.
FAMILIES = ("FILESYSTEM_EXPOSURE", "COOKIES", "HTML_BODY", "HTTP_HEADERS",
            "BEHAVIORAL", "ECOSYSTEM_ROUTES")

# Dispositive-strong: hard-to-spoof, low-FP. ONE alone confirms Laravel.
DISPOSITIVE_STRONG = {
    "composer_lock_framework", "composer_json_framework", "application_version_const",
    "cookie_envelope_shape", "livewire_js", "ignition_debug_page",
}
# Signals that, when present, prove the FRAMEWORK (not merely a component / Laravel-like surface).
FRAMEWORK_SIGNALS = {
    "composer_lock_framework", "composer_json_framework", "application_version_const",
    "framework_health_up", "artisan_file", "bootstrap_app_php",
}
# Component signals: prove a Laravel-ecosystem package, not necessarily the framework.
COMPONENT_SIGNALS = {"livewire_js", "telescope_route", "horizon_route", "laravel_reverb", "inertia"}
# Strong negatives: a non-Laravel stack.
STRONG_NEGATIVES = {
    "symfony_profiler", "wordpress_markers", "non_php_stack",
    "illuminate_without_framework", "lumen",
}


def score_signals(signals):
    """Pure scorer. `signals` = list of dicts {id, tier, family, evidence}. Returns
    (confidence_label, score, classification). No I/O — drives the unit tests and the worked
    traces in the research doc."""
    best = {}          # family -> best tier points
    neg = 0
    ids = set()
    for s in signals:
        ids.add(s["id"])
        if s["family"] == "NEG":
            neg += TIER_PTS["negative"]
            continue
        best[s["family"]] = max(best.get(s["family"], 0), TIER_PTS.get(s["tier"], 0))
    score = sum(best.values()) + neg
    fam_medplus = [f for f, p in best.items() if p >= 3]

    has_dispositive = any(i in DISPOSITIVE_STRONG for i in ids)
    has_shaped_strong = any(
        s["tier"] == "strong" and s["id"] not in DISPOSITIVE_STRONG and s["family"] != "NEG"
        for s in signals)
    strong_neg = any(i in STRONG_NEGATIVES for i in ids)

    # confidence label (top-down; first match wins)
    if strong_neg and not fam_medplus:
        label = "not_laravel"
    elif has_dispositive:
        label = "confirmed"
    elif len(fam_medplus) >= 2 and score >= 8:
        label = "confirmed"
    elif has_shaped_strong or (score >= 5 and len(fam_medplus) >= 2):
        label = "likely"
    elif score >= 1:
        label = "possible"
    else:
        label = "not_laravel"

    # classification (orthogonal axis)
    if label == "not_laravel":
        classification = "not_laravel"
    elif any(i in FRAMEWORK_SIGNALS for i in ids):
        classification = "framework"
    elif any(i in COMPONENT_SIGNALS for i in ids) and not any(
            s["family"] in ("COOKIES", "HTML_BODY", "BEHAVIORAL") and s["tier"] in ("strong", "medium")
            for s in signals):
        # only an ecosystem component signal, no Laravel-app HTTP surface -> component-only
        classification = "component_only"
    else:
        classification = "laravel_like"
    return label, score, classification


# ============================================================================
# HTTP helpers
# ============================================================================

def _safe_get(url, timeout=8, allow_redirects=True, **kw):
    try:
        return requests.get(url, timeout=timeout, verify=False,
                            allow_redirects=allow_redirects, **kw)
    except Exception:
        return None


def _seed_response(method, url, resp, *, allow_redirects, headers=None, auth=None):
    """Snapshot an in-hand Response and put() it into the shared within-run memo.

    Seeds FAITHFULLY: the key records the EXACT params of the fetch that produced `resp`
    (method, url, redirect-policy, injected-header set, auth-context). A future consumer hits
    only if its params match; a mismatch is a safe miss (it refetches). Never reshape the key
    toward a hoped-for consumer — a wrong-param key would serve the wrong body. No-op on a
    None/unsnapshottable response. GET-only is enforced inside ResponseMemo.put()."""
    if resp is None:
        return False
    try:
        snap = ResponseSnapshot(status=resp.status_code,
                                headers=dict(resp.headers),
                                body=resp.content)
    except Exception:
        return False
    if auth is None:
        auth = http_config.run_auth_label()
    key = memo_key(method, url, allow_redirects=allow_redirects,
                   headers=headers or {}, auth=auth)
    return get_run_memo().put(key, snap)


def extract_php_version(resp):
    """PHP version from X-Powered-By, if present. Display-only (NOT a Laravel signal)."""
    if resp is None:
        return None
    xpb = resp.headers.get("X-Powered-By", "")
    m = re.search(r"PHP/([\d.]+)", xpb)
    return m.group(1) if m else None


# ============================================================================
# Cookie envelope (the dispositive-strong COOKIES signal)
# ============================================================================

def _looks_like_laravel_envelope(value):
    """True if a cookie value is a Laravel encryption envelope: url-decode -> base64-decode ->
    JSON object with EXACTLY the keys {iv, value, mac} (+ optional tag). Checkable without APP_KEY;
    hard to spoof. This is far stronger than any cookie NAME."""
    if not value:
        return False
    try:
        raw = unquote(value)
        decoded = base64.b64decode(raw, validate=False)
        obj = json.loads(decoded)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    keys = set(obj.keys())
    return {"iv", "value", "mac"}.issubset(keys) and keys.issubset({"iv", "value", "mac", "tag"})


# ============================================================================
# Signal collection — PASSIVE (the single initial GET)
# ============================================================================

def _passive_signals(resp):
    """Signals derivable from the one initial response: cookies, headers, body."""
    signals = []
    body = (resp.text or "") if resp is not None else ""
    low = body.lower()

    # --- COOKIES family ---
    session_like = xsrf = False
    envelope_cookies = []
    cookie_variations = []
    laravel_named = []
    for c in (resp.cookies if resp is not None else []):
        name = c.name.lower()
        classified = classify_laravel_cookie(c.name, c.value)
        if _looks_like_laravel_envelope(c.value):
            envelope_cookies.append(c.name)
        if classified and classified.get("role") == "session":
            session_like = True
        if classified and classified.get("role") == "xsrf":
            xsrf = True
        if classified and classified.get("is_variation"):
            cookie_variations.append(describe_cookie_variation(classified))
        if "laravel" in name:
            laravel_named.append(c.name)
    # Emit each cookie signal at most ONCE (multiple matching cookies are one signal, not many).
    if envelope_cookies:
        signals.append({"id": "cookie_envelope_shape", "tier": "strong", "family": "COOKIES",
                        "evidence": "Laravel encryption envelope (base64 -> JSON {iv,value,mac[,tag]}) "
                                    "in cookie(s): " + ", ".join(envelope_cookies)})
    if laravel_named:
        signals.append({"id": "laravel_cookie_name", "tier": "weak", "family": "COOKIES",
                        "evidence": "cookie name contains 'laravel': " + ", ".join(laravel_named)})
    if session_like and xsrf:
        signals.append({"id": "cookie_pair_pattern", "tier": "strong", "family": "COOKIES",
                        "evidence": "Laravel session/XSRF cookie pair present, including aliases"
                                    + (": " + "; ".join(cookie_variations) if cookie_variations else "")})

    # --- HTTP_HEADERS family (negatives + weak hints) ---
    server = resp.headers.get("Server", "") if resp is not None else ""
    xpb = resp.headers.get("X-Powered-By", "") if resp is not None else ""
    if resp is not None and ("X-Debug-Token" in resp.headers or "X-Debug-Token-Link" in resp.headers):
        signals.append({"id": "symfony_profiler", "tier": "negative", "family": "NEG",
                        "evidence": "Symfony web-profiler header X-Debug-Token[-Link] (Laravel never emits it)"})
    if resp is not None and "X-Pingback" in resp.headers:
        signals.append({"id": "wordpress_markers", "tier": "negative", "family": "NEG",
                        "evidence": "WordPress X-Pingback header"})
    if re.search(r"ASP\.NET|X-AspNet", server + xpb, re.I):
        signals.append({"id": "non_php_stack", "tier": "negative", "family": "NEG",
                        "evidence": f"non-PHP stack header: {server} {xpb}".strip()})

    # --- HTML_BODY family (collapsed to ONE weak hint; copied templates trip these) ---
    body_hits = [p for p in ("laravel", "csrf-token", "mix-manifest.json", "@vite", "data-page")
                 if p in low]
    if any(m in low for m in ("/wp-content/", "/wp-includes/", "wp-json", "wordpress")):
        signals.append({"id": "wordpress_markers", "tier": "negative", "family": "NEG",
                        "evidence": "WordPress markers in body (wp-content/wp-json/...)"})
    if body_hits:
        signals.append({"id": "body_laravel_hint", "tier": "weak", "family": "HTML_BODY",
                        "evidence": "Laravel-ish body markers: " + ", ".join(body_hits)})
    # Inertia: data-page attribute / X-Inertia header (medium ecosystem)
    if "data-page=" in low or (resp is not None and "X-Inertia" in resp.headers):
        signals.append({"id": "inertia", "tier": "medium", "family": "ECOSYSTEM_ROUTES",
                        "evidence": "Inertia.js (data-page attribute / X-Inertia header)"})

    # Extra behavioral / in-house friendly passive signals (no reliance on public/ fs exposure)
    headers_l = {k.lower(): v for k, v in (getattr(resp, 'headers', {}) or {}).items()}
    if any(h in headers_l for h in ("x-laravel", "x-illuminate", "x-ignition")):
        signals.append({"id": "laravel_custom_header", "tier": "medium", "family": "HEADERS",
                        "evidence": "Laravel/illuminate/ignition custom response header present"})
    if "laravel_session" in " ".join(headers_l.keys()):
        signals.append({"id": "laravel_session_header", "tier": "weak", "family": "HEADERS",
                        "evidence": "laravel_session referenced in headers (often via Set-Cookie)"})
    if "application key" in low or "app_key" in low:
        signals.append({"id": "app_key_mention", "tier": "weak", "family": "BODY",
                        "evidence": "Body mentions APP_KEY or 'application key' (common in debug/error output)"})
    if re.search(r"laravel.*\d+\.\d+", low):
        signals.append({"id": "laravel_version_string", "tier": "medium", "family": "BODY",
                        "evidence": "Literal 'Laravel x.y' version string in page (footer, meta, error)"})

    return signals


# ============================================================================
# Signal collection — ACTIVE (extra requests; opt-in)
# ============================================================================

def _framework_health_up(base):
    """Laravel 11+ default health route: GET /up -> HTML 'Application up' / 'HTTP request received.'
    Strong FRAMEWORK signal. Distinct from the Reverb component (which returns JSON {"health":"OK"})."""
    r = _safe_get(app_url(base, "/up"), timeout=6)
    if r is None or r.status_code != 200:
        return None
    txt = r.text or ""
    if "HTTP request received." in txt and ("Application up" in txt or "Application" in txt):
        return {"id": "framework_health_up", "tier": "strong", "family": "HTTP_HEADERS",
                "evidence": "GET /up -> Laravel 11+ framework health HTML ('HTTP request received.')"}
    return None


def _looks_like_livewire_runtime(text):
    if not text:
        return False
    low = text.lower()
    return (
        "window.livewire" in low
        or "livewire:init" in low
        or "livewire.start" in low
        or "wire:" in low
        or "livewire" in low
    )


def _reverb_signal(base):
    """Laravel Reverb (WebSocket component): GET /up -> JSON {"health":"OK"}, or WS upgrade tagged
    X-Powered-By: Laravel Reverb. A COMPONENT signal (kept from the original detector). Distinct from
    the framework HTML /up above."""
    up = _safe_get(app_url(base, "/up"), timeout=6)
    if up is not None and up.status_code == 200 and '"health"' in (up.text or "") and "OK" in (up.text or ""):
        return {"id": "laravel_reverb", "tier": "medium", "family": "ECOSYSTEM_ROUTES",
                "evidence": 'GET /up -> {"health":"OK"} (Laravel Reverb)'}
    for path in ("/app/probe", "/app/labkey"):
        try:
            ws = requests.get(app_url(base, path), verify=False, timeout=6, allow_redirects=False,
                              headers={"Connection": "Upgrade", "Upgrade": "websocket",
                                       "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                                       "Sec-WebSocket-Version": "13"})
            if "reverb" in ws.headers.get("X-Powered-By", "").lower() or "Laravel Reverb" in (ws.text or ""):
                return {"id": "laravel_reverb", "tier": "medium", "family": "ECOSYSTEM_ROUTES",
                        "evidence": f"WS upgrade {path} -> X-Powered-By: Laravel Reverb"}
        except Exception:
            pass
    return None


def _livewire_signal(base):
    for path in ("/livewire/livewire.js", "/vendor/livewire/livewire.js",
                 "/_livewire/livewire.js", "/livewire.js"):
        r = _safe_get(app_url(base, path), timeout=6)
        if r is not None and r.status_code == 200 and _looks_like_livewire_runtime(r.text or ""):
            return {"id": "livewire_js", "tier": "strong", "family": "ECOSYSTEM_ROUTES",
                    "evidence": f"GET {path} -> Livewire runtime JS"}
    return None


def _component_routes(base):
    """Telescope / Horizon — require the route to respond, recorded as medium ecosystem signals."""
    out = []
    for sid, path in (("telescope_route", "/telescope/requests"), ("horizon_route", "/horizon/api/stats")):
        r = _safe_get(app_url(base, path), timeout=6)
        if r is not None and r.status_code in (200, 302, 401, 403):
            out.append({"id": sid, "tier": "medium", "family": "ECOSYSTEM_ROUTES",
                        "evidence": f"{path} -> HTTP {r.status_code}"})
    return out


def _composer_version_signals(base):
    """Fetch /composer.lock and /composer.json for version inference and Lumen detection.

    Does NOT fetch /.env — that is owned by the Phase 4 env_exposure detector (position 1 in
    the registry) to avoid a double-fetch.  The env_exposure module reads the cached response
    from laravel_info["_env_resp"] when available (set below in is_laravel()).

    Returns a list of signal dicts (composer_lock_framework, composer_json_framework, lumen).
    """
    out = []
    for path, jkey, sid in (("/composer.lock", "packages", "composer_lock_framework"),
                            ("/composer.json", "require", "composer_json_framework")):
        _path_url = app_url(base, path)
        r = _safe_get(_path_url, timeout=6)
        # Seed the in-hand composer Response (GET, allow_redirects=True per _safe_get default,
        # no injected headers, run auth-context). Faithful key; consumers with matching params hit.
        _seed_response("GET", _path_url, r, allow_redirects=True)
        if r is None or r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        ver = None
        if jkey == "packages":
            for pkg in (data.get("packages") or []):
                if pkg.get("name") == "laravel/framework":
                    ver = pkg.get("version")
            for pkg in (data.get("packages") or []):
                if pkg.get("name") == "laravel/lumen-framework":
                    out.append({"id": "lumen", "tier": "negative", "family": "NEG",
                                "evidence": "composer.lock names laravel/lumen-framework (Lumen, not full framework)"})
        else:
            req = data.get("require") or {}
            if "laravel/framework" in req:
                ver = req["laravel/framework"]
            if "laravel/lumen-framework" in req:
                out.append({"id": "lumen", "tier": "negative", "family": "NEG",
                            "evidence": "composer.json requires laravel/lumen-framework (Lumen)"})
        if ver:
            out.append({"id": sid, "tier": "strong", "family": "FILESYSTEM_EXPOSURE",
                        "evidence": f"{path} names laravel/framework ({ver})", "version": ver})
    return out


def _filesystem_exposed_signals(base):
    """Full filesystem signals including /.env — kept for detect_ecosystem() back-compat.
    is_laravel() uses _composer_version_signals() instead (avoids the /.env double-fetch)."""
    out = _composer_version_signals(base)
    env = _safe_get(app_url(base, "/.env"), timeout=6)
    if env is not None and env.status_code == 200 and "APP_KEY" in (env.text or ""):
        out.append({"id": "env_exposed", "tier": "medium", "family": "FILESYSTEM_EXPOSURE",
                    "evidence": "/.env served with APP_KEY"})
    return out


def detect_ecosystem(base):
    """Back-compat helper retained for the legacy 'ecosystem' output key — returns a list of names."""
    eco = []
    for sig_fn in (_livewire_signal, _reverb_signal):
        s = sig_fn(base)
        if s:
            eco.append("livewire" if s["id"] == "livewire_js" else s["id"])
    for s in _component_routes(base):
        eco.append(s["id"].replace("_route", ""))
    return eco


# ============================================================================
# Public API — preserves the historical contract, adds the new keys
# ============================================================================

def is_laravel(url, active=True, stealth=False):
    """Detect Laravel by aggregating independent signals. Returns None ONLY for a 'not_laravel'
    verdict; otherwise a truthy dict (superset of the historical keys). `active=True` performs the
    safe extra probes (/up, /livewire, /composer.*, /.env, component routes); active=False is
    passive-only (the single initial GET).

    stealth=True: skip noisy public/ filesystem probes (.env, composer.*, vendor) that are
    typically blocked or absent on in-house deployments. Still runs cheap behavioral probes.
    """
    resp = _safe_get(url)
    if resp is None:
        return None  # request truly failed (not merely a 4xx/5xx)

    # Canonical base after redirects: adopt the redirect's SCHEME+HOST onto the ORIGINALLY-TARGETED
    # PATH — never adopt resp.url's path. Two cases this must satisfy:
    #   (a) http://host 301 -> https://host  (TLS-forcing proxy): upgrade scheme so detection probes
    #       request https directly and don't each eat a 301 -> https (the duplicate-request fix).
    #   (b) http://host/  302 -> http://host/render  (an app that redirects root to a landing route):
    #       the app root is still '/', NOT '/render'. Keeping resp.url's path here would make every
    #       module build '/render/render', '/upload/upload', etc. -> 404. So we DROP resp.url's path
    #       and keep the path the user targeted.
    # Falls back to the input url if resp.url is unusable.
    final_url = normalize_base(url)
    try:
        ru = getattr(resp, "url", None)
        if ru:
            from urllib.parse import urlparse, urlunparse
            ru_p = urlparse(ru)
            orig_p = urlparse(final_url)  # final_url == normalize_base(url): scheme+host+user-targeted path
            if ru_p.scheme and ru_p.netloc:
                final_url = normalize_base(urlunparse(
                    (ru_p.scheme, ru_p.netloc, orig_p.path, "", "", "")))
    except Exception:
        pass

    base = final_url
    signals = list(_passive_signals(resp))

    fs_signals = []
    _env_resp = None  # cached /.env response — passed to env_exposure detector via laravel_info
    if active and not stealth:
        # composer.lock/json for version inference (no /.env — that belongs to the env detector)
        fs_signals = _composer_version_signals(base)
        signals += fs_signals
        # Pre-fetch /.env once and cache so the env_exposure detector can consume it
        # without issuing a second request.  env_exposed signal is derived from the cache here
        # so the fingerprint score is unaffected.
        _env_url = app_url(base, "/.env")
        _env_resp = _safe_get(_env_url, timeout=6)
        # Seed the /.env Response into the within-run memo, keyed FAITHFULLY to this fetch's
        # params (GET, allow_redirects=True per _safe_get's default, no injected headers, run
        # auth-context). A later exposure consumer that fetches /.env with the SAME params hits;
        # one using different params (e.g. allow_redirects=False) safely misses and refetches.
        _seed_response("GET", _env_url, _env_resp, allow_redirects=True)
        if _env_resp is not None and _env_resp.status_code == 200 and "APP_KEY" in (_env_resp.text or ""):
            signals.append({"id": "env_exposed", "tier": "medium", "family": "FILESYSTEM_EXPOSURE",
                            "evidence": "/.env served with APP_KEY"})

    label, score, classification = score_signals(signals)
    if label == "not_laravel":
        return None

    # legacy-shaped fields
    cookies = []
    for c in resp.cookies:
        cookies.append({"name": c.name, "value": c.value, "secure": c.secure,
                        "httponly": c.has_nonstandard_attr("httponly") or c._rest.get("HttpOnly") is not None,
                        "samesite": c._rest.get("samesite")})
    composer_ver = composer_lock_ver = None
    for s in fs_signals:
        if s["id"] == "composer_json_framework":
            composer_ver = s.get("version")
        if s["id"] == "composer_lock_framework":
            composer_lock_ver = s.get("version")
    ecosystem = [s["id"] for s in signals if s["family"] == "ECOSYSTEM_ROUTES"]
    env_exposed = any(s["id"] == "env_exposed" for s in signals)
    version_guess = composer_lock_ver or composer_ver or "unknown"
    if version_guess == "unknown":
        if any(s["id"] == "framework_health_up" for s in signals):
            version_guess = "Laravel 11.x or 12.x (/up health route)"

    return {
        # --- historical keys (preserved for check.py) ---
        "url": url,
        "final_url": final_url,  # canonical base after redirects (scheme committed for the scan)
        "status_code": resp.status_code,
        "php_version": extract_php_version(resp),
        "laravel_version_guess": version_guess,
        "composer_framework_version": composer_ver,
        "composer_lock_version": composer_lock_ver,
        "vendor_exposed": any(s["id"] in ("composer_lock_framework", "env_exposed") for s in signals),
        "cookies": cookies,
        "indicators": [s["id"] for s in signals],
        "ecosystem": ecosystem,
        "env_exposed": bool(env_exposed),
        # --- new evidence-aggregation keys ---
        "confidence_label": label,
        "score": score,
        "classification": classification,
        "evidence": [{"id": s["id"], "tier": s["tier"], "family": s["family"],
                      "observed": s["evidence"]} for s in signals],
        # --- new keys populated AFTER is_laravel() returns ---
        # "components" is filled by discover_resources(); "env_exposed"/"vendor_exposed" are still
        # accurate (/.env probe still runs in _filesystem_exposed_signals inside active block above).
        # Note: lines 423-425 version_guess from "framework_health_up" become a no-op here since
        # _framework_health_up() is no longer called in is_laravel(); moves to discover_resources().
        "components": [],
        "_root_resp": resp,     # cached GET / response for discover_resources() HTML parse; no re-fetch
        "_env_resp": _env_resp, # cached /.env response; env_exposure detector reads this to avoid double-fetch
    }


# ============================================================================
# Phase 3 — Resource discovery (runs AFTER is_laravel())
# ============================================================================

def discover_resources(base, *, session=None, root_resp=None, budget=30):
    """Probe the target for ecosystem components and route surface.

    Returns {"route_map": dict, "components": list[str], "debug_mode": bool}.
    Uses root_resp (the cached GET /) for HTML link extraction — no re-fetch.
    Budget limits total outbound requests; probing stops when exhausted.
    """
    from modules.core.http_config import get_auth_session
    sess = session or get_auth_session()
    route_map = {}
    components = []
    debug_mode = False
    remaining = [budget]

    def _probe(path, package=None):
        """GET path via sess, decrement budget, record in route_map. Returns response or None."""
        if remaining[0] <= 0:
            return None
        remaining[0] -= 1
        try:
            r = sess.get(app_url(base, path), timeout=6, verify=False, allow_redirects=True)
        except Exception:
            return None
        if r is None:
            return None
        loc = r.headers.get("location", "")
        if r.status_code == 401:
            auth_req = True
        elif r.status_code == 302 and "login" in loc.lower():
            auth_req = True
        elif r.status_code == 200:
            auth_req = False
        else:
            auth_req = None
        route_map[path] = {"method": "GET", "status": r.status_code,
                           "content_type": r.headers.get("Content-Type"),
                           "auth_required": auth_req, "source": "probe", "package": package}
        return r

    # 1. Parse GET / HTML links — zero requests (cached root_resp)
    if root_resp is not None:
        for href in re.findall(r'(?:href|action)=["\']([^"\'#?]+)', root_resp.text or ""):
            href = href.strip()
            if href.startswith("/") and href not in route_map:
                route_map[href] = {"method": "UNKNOWN", "status": None, "content_type": None,
                                   "auth_required": None, "source": "html_parse", "package": None}

    # 2. robots.txt — parse Disallow hints
    r_robots = _probe("/robots.txt")
    if r_robots is not None and r_robots.status_code == 200:
        for ln in (r_robots.text or "").splitlines():
            ln = ln.strip()
            if ln.lower().startswith("disallow:"):
                ph = ln.split(":", 1)[1].strip()
                if ph and ph not in route_map:
                    route_map[ph] = {"method": "UNKNOWN", "status": None, "content_type": None,
                                     "auth_required": None, "source": "robots", "package": None}

    # 3. sitemap.xml — parse <loc> hints (up to 20)
    r_sitemap = _probe("/sitemap.xml")
    if r_sitemap is not None and r_sitemap.status_code == 200:
        for loc_tag in re.findall(r"<loc>([^<]+)</loc>", r_sitemap.text or "")[:20]:
            ph = loc_tag.strip()
            if ph.startswith("/") and ph not in route_map:
                route_map[ph] = {"method": "UNKNOWN", "status": None, "content_type": None,
                                 "auth_required": None, "source": "sitemap", "package": None}

    # 4. 404 probe — debug mode detection
    r_404 = _probe("/_lvc_probe_404_xyz")
    if r_404 is not None:
        if any(tok in (r_404.text or "") for tok in ("Ignition", "Whoops", "IGNITION_ERROR")):
            debug_mode = True

    # 5. Auth surface routes
    for path in ("/login", "/register", "/forgot-password", "/sanctum/csrf-cookie",
                 "/api/user", "/broadcasting/auth"):
        _probe(path)

    # 6. Livewire — require runtime/body evidence for presence and all-404 evidence for absence.
    root_html = (root_resp.text or "") if root_resp is not None else ""
    root_livewire_hint = _looks_like_livewire_runtime(root_html)
    if root_livewire_hint:
        components.append("livewire")

    livewire_responses = []
    for lw_path in ("/livewire/livewire.js", "/vendor/livewire/livewire.js",
                    "/_livewire/livewire.js", "/livewire.js"):
        r_lw = _probe(lw_path, package="livewire")
        if r_lw is not None:
            livewire_responses.append(r_lw)
        if r_lw is not None and r_lw.status_code == 200:
            if _looks_like_livewire_runtime(r_lw.text or ""):
                if "livewire" not in components:
                    components.append("livewire")
                break
            # 200 but no Livewire content — path exists but may be something else; stay open
    if "livewire" not in components:
        # Confirmed absent only when every attempted canonical runtime path returned 404.
        # No-response, 401/403, or mixed statuses remain unknown so Livewire CVEs still self-gate.
        if livewire_responses and all(r.status_code == 404 for r in livewire_responses):
            components.append("livewire_absent")

    # 7. /up — Reverb returns JSON {"health":"OK"}; framework health returns HTML
    r_up = _probe("/up")
    if r_up is not None and r_up.status_code == 200:
        if '"health"' in (r_up.text or "") and "OK" in (r_up.text or ""):
            components.append("laravel_reverb")
    # 8. Status-gated ecosystem components (200/302/401/403 = route exists)
    _eco = [("/telescope/requests", "telescope"), ("/horizon/api/stats", "horizon"),
            ("/pulse/api", "pulse"), ("/nova/api/stats", "nova"),
            ("/filament/", "filament"), ("/_debugbar/open", "debugbar"), ("/clockwork/", "clockwork")]
    for path, comp in _eco:
        r = _probe(path, package=comp)
        if r is not None and r.status_code in (200, 302, 401, 403):
            components.append(comp)

    # 9. Reverb WS upgrade probes. Use the shared session so caller-supplied cookies/headers
    # and any cookies learned during discovery stay in the same jar.
    ws_responses = []
    for ws_path in ("/app/probe", "/app/labkey"):
        if remaining[0] <= 0:
            break
        remaining[0] -= 1
        try:
            ws = sess.get(app_url(base, ws_path), verify=False, timeout=6,
                          allow_redirects=False,
                          headers={"Connection": "Upgrade", "Upgrade": "websocket",
                                   "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                                   "Sec-WebSocket-Version": "13"})
            if ws is not None:
                ws_responses.append(ws)
                route_map[ws_path] = {"method": "GET", "status": ws.status_code,
                                      "content_type": ws.headers.get("Content-Type"),
                                      "auth_required": None, "source": "probe",
                                      "package": "reverb"}
                if "reverb" in ws.headers.get("X-Powered-By", "").lower() \
                        or "Laravel Reverb" in (ws.text or ""):
                    if "laravel_reverb" not in components:
                        components.append("laravel_reverb")
        except Exception:
            pass

    # Reverb confirmed absent only when /up and all attempted WS probes returned 404.
    if "laravel_reverb" not in components:
        if (r_up is not None and r_up.status_code == 404
                and ws_responses
                and all(ws.status_code == 404 for ws in ws_responses)):
            components.append("laravel_reverb_absent")

    return {"route_map": route_map, "components": components, "debug_mode": bool(debug_mode)}

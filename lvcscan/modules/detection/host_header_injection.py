#!/usr/bin/env python3
"""Host-header injection detector (generic, reflection-based, non-mutating by default).

Web apps that build absolute URLs from the request `Host` (or an `X-Forwarded-*`
proxy header the framework trusts) let an attacker who controls that header poison
the URLs the app emits: redirect `Location` targets, absolute links in the body,
and — most damagingly — the password-reset links Laravel mails out. The classic
Laravel sink is `url()` / `URL::to()` / `route()` resolving the host from the
request when `APP_URL` is unset and `TrustProxies` is permissive.

This detector proves the *reflection* primitive without weaponising it:

  * It injects a benign, non-resolving canary host (`*.invalid`, RFC-2606 — never
    a live attacker callback) via several headers and the absolute-URI trick.
  * It reports a finding only when that canary comes back in a URL-building
    context (a redirect `Location`, or a scheme/`//`-prefixed URL in the body) —
    the behaviour that makes the bug exploitable. A bare echo of the host string
    somewhere in the page is reported as weaker `surface_present`.
  * It NEVER POSTs to password-reset / forgot-password (that would trigger real
    e-mail to real users). Reset-link poisoning is called out as the impact, not
    detonated. An explicit opt-in (`options={"hhi_probe_reset": True}`) only adds
    a *GET* of the reset form under the poisoned host — still non-mutating.

Verdict tiers (mapped by the pipeline helper):
  confirmed_vulnerable  — canary reflected into a Location header or a body URL
  surface_present       — canary echoed in the body but not in a URL context
  not_detected          — canary never reflected (or host rejected / unreachable)

The HTTP layer is the injectable `session` the driver already passes, so the whole
flow is unit-testable offline with a fake session.
"""
from __future__ import annotations

import re
import secrets
from typing import Dict, List, Optional

from modules.core import http_config
from modules.core.http_config import normalize_base

# Benign, guaranteed-non-resolving canary host (RFC 2606 reserved TLD). Never a
# live callback — reflection alone proves the sink; we do not need exfil.
CANARY = "lvcscan-hhi.invalid"

# Injection vectors, in priority order. Each is (header-name, value-template).
# "Host" replaces the real Host; the X-Forwarded-* / Forwarded / X-Host family
# are the proxy headers Laravel's TrustProxies may honour when misconfigured.
_VECTORS = [
    ("X-Forwarded-Host", CANARY),
    ("X-Forwarded-Server", CANARY),
    ("X-Host", CANARY),
    ("Forwarded", f"host={CANARY}"),
    ("Host", CANARY),
]

# A URL-building context: canary appears as a real URL (scheme-prefixed or
# scheme-relative `//host`). This is what makes the reflection exploitable.
_URL_CTX_RE = re.compile(r"(?:https?:)?//" + re.escape(CANARY), re.IGNORECASE)


def _header(resp, name: str) -> Optional[str]:
    """Case-insensitive single-header read tolerant of dict / requests headers."""
    try:
        h = resp.headers
    except Exception:
        return None
    getter = getattr(h, "get", None)
    if getter is None:
        return None
    return getter(name) or getter(name.lower()) or getter(name.upper())


def _classify_reflection(resp) -> Optional[str]:
    """Return 'location' / 'body_url' / 'body_echo' for how the canary is reflected,
    or None if it is not reflected at all. Ordered strongest-first."""
    loc = _header(resp, "Location") or ""
    if CANARY in loc:
        return "location"
    body = ""
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    if _URL_CTX_RE.search(body):
        return "body_url"
    if CANARY in body:
        return "body_echo"
    return None


def _probe(sess, url: str, header: str, value: str):
    """One poisoned request. Returns the response or None. Never raises.

    For the `Host` vector we override the Host header directly; the framework/
    server sees the canary as the request host. Redirects are NOT followed — the
    poisoned Location is exactly the signal we want to inspect.
    """
    # Vector header FIRST (callers/tests read the first header item), then no-store.
    # A per-probe cache-buster + Cache-Control: no-store make a poisoned response
    # un-cacheable, so probing a live target can never seed a shared cache/CDN with
    # the canary host and serve it to real users.
    headers = {header: value, "Cache-Control": "no-store", "Pragma": "no-cache"}
    sep = "&" if "?" in url else "?"
    probe_url = f"{url}{sep}cb={secrets.token_hex(6)}"
    try:
        return sess.get(probe_url, headers=headers, timeout=10, allow_redirects=False, verify=False)
    except TypeError:
        # Fake/session without verify= kwarg (unit tests) — retry minimally.
        try:
            return sess.get(probe_url, headers=headers, timeout=10, allow_redirects=False)
        except Exception:
            return None
    except Exception:
        return None


def scan(
    target_url,
    *,
    session=None,
    options=None,
    **kwargs,
) -> Optional[Dict]:
    """Probe `target_url` for host-header injection. Non-mutating by default.

    Returns a finding dict (with an explicit `verdict`) when the canary host is
    reflected, else None. Sends only GET requests; never POSTs to any endpoint.
    """
    if not target_url:
        return None
    sess = session or http_config.get_auth_session()
    base = normalize_base(target_url)
    options = options or {}

    hits: List[Dict] = []
    for header, value in _VECTORS:
        resp = _probe(sess, base, header, value)
        if resp is None:
            continue
        kind = _classify_reflection(resp)
        if kind is None:
            continue
        hits.append({
            "vector": header,
            "reflection": kind,
            "status": getattr(resp, "status_code", None),
            "location": (_header(resp, "Location") or "")[:200] if kind == "location" else None,
        })

    # Opt-in, still non-mutating: GET (never POST) the password-reset form under a
    # poisoned host to show the reset flow reflects it too. Off by default.
    if options.get("hhi_probe_reset"):
        for path in ("/password/reset", "/forgot-password", "/password/email"):
            resp = _probe(sess, base.rstrip("/") + path, "X-Forwarded-Host", CANARY)
            if resp is None:
                continue
            kind = _classify_reflection(resp)
            if kind in ("location", "body_url"):
                hits.append({"vector": "X-Forwarded-Host", "reflection": kind,
                             "status": getattr(resp, "status_code", None), "path": path})
                break

    if not hits:
        return None

    # A body URL context is always strong. A Location reflection is strong ONLY for the
    # X-Forwarded-* / Forwarded family: those prove the app trusts a proxy header to build
    # an absolute URL. The raw `Host` vector landing the canary in Location can be a plain
    # scheme/canonical self-redirect that echoes whatever Host it received — down-ranked to
    # surface so a benign HTTP→HTTPS redirect isn't reported as confirmed reset poisoning.
    strong = [
        h for h in hits
        if h["reflection"] == "body_url"
        or (h["reflection"] == "location" and h["vector"] != "Host")
    ]
    confirmed = bool(strong)
    vectors = sorted({h["vector"] for h in hits})
    return {
        "verdict": "confirmed_vulnerable" if confirmed else "surface_present",
        "vulnerable": confirmed,
        "vuln_class": "host_header_injection",
        "category": "host_header_injection",
        "severity": "Medium",
        "endpoint": base,
        "proof_type": "behavioral" if confirmed else "fingerprint",
        "confidence": "high" if confirmed else "low",
        "detonated": False,
        "confirm": {"canary": CANARY, "hits": hits, "vectors": vectors},
        "evidence": [f"{h['vector']} -> {h['reflection']}" for h in hits],
        "note": (
            "Injected host reflected into "
            + ("a redirect Location / body URL" if confirmed else "the response body")
            + f" via {', '.join(vectors)}. "
            + ("URL-building sink confirmed — poisons redirect targets and (Laravel) "
               "password-reset links built from the request host. Set APP_URL and tighten "
               "TrustProxies/allowed hosts."
               if confirmed else
               "Weak echo only (no URL context) — verify manually whether any generated "
               "link/redirect derives from the request host.")
        ),
    }

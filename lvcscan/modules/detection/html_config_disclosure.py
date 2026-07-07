#!/usr/bin/env python3
"""HTML/JS config disclosure detector (generic, detect-only).

Scans served HTML/JS for cleartext config/SSO/env markers leaked to the client:

  - SSO URLs (https://sso.<domain>)
  - brandCode= values that contain an environment marker
    (STAGING, PROD, PRODUCTION, DEV, TEST, or UAT) — bare opaque codes are NOT
    flagged because they don't confirm a leak by themselves
  - APP_ENV / APP_DEBUG assignment expressions embedded in markup

vuln_class = "info_disclosure"
"""
import re
from typing import Dict, List, Optional

from modules.core import http_config
from modules.core.http_config import normalize_base, app_url

# Pages to probe for client-side config leakage
PROBE_PATHS = ["/login", "/", "/admin/index.html"]

# --- Regex patterns ---
# SSO URL: https://sso.<domain>
_RE_SSO_URL = re.compile(r"https?://sso\.[a-z0-9.\-]+", re.IGNORECASE)

# brandCode= only flagged when the value contains an environment marker
_RE_BRAND_CODE = re.compile(r"brandCode=[A-Za-z0-9]+", re.IGNORECASE)
_ENV_WORDS = re.compile(r"(STAGING|PROD(?:UCTION)?|DEV|TEST|UAT)", re.IGNORECASE)

# APP_ENV or APP_DEBUG followed by = or : (env config assignment)
_RE_ENV_ASSIGN = re.compile(r"\b(APP_ENV|APP_DEBUG)\b\s*[:=]\s*\S+", re.IGNORECASE)


def find_config_markers(html: str) -> List[str]:
    """Return deduplicated list of suspicious config/SSO/env marker strings found in html.

    Flags:
      - SSO URLs (https://sso.<domain>)
      - brandCode= values whose value portion contains an environment word
        (STAGING, PROD, PRODUCTION, DEV, TEST, UAT); bare opaque codes are skipped
      - APP_ENV / APP_DEBUG assignment expressions
    """
    seen: set = set()
    results: List[str] = []

    def _add(m: str) -> None:
        if m not in seen:
            seen.add(m)
            results.append(m)

    # SSO URLs
    for m in _RE_SSO_URL.findall(html):
        _add(m)

    # brandCode= params — only flag when the value contains an env marker word
    for m in _RE_BRAND_CODE.findall(html):
        # m is e.g. "brandCode=BOREPORTSTAGINGS9"; strip the key prefix to check the value
        value = m.split("=", 1)[1] if "=" in m else m
        if _ENV_WORDS.search(value):
            _add(m)

    # APP_ENV / APP_DEBUG assignments
    for mo in _RE_ENV_ASSIGN.finditer(html):
        _add(mo.group(0))

    return results


def scan(
    target_url,
    *,
    session=None,
    username=None,
    password=None,
    laravel_info=None,
    **kwargs,
) -> Optional[Dict]:
    """Probe a handful of pages and return a finding if cleartext config markers
    are present in any 200-response body."""
    if not target_url:
        return None
    base = normalize_base(target_url)

    for path in PROBE_PATHS:
        # Probe the UNAUTHENTICATED surface, no-redirect: the SSO/staging marker
        # (sso.gameland.vip, brandCode=...STAGING...) leaks on the anon /login page,
        # but an authed /login 302s to /. unauth_get builds a fresh anon Session and
        # skips -H auth injection so we observe the pre-302 leak. `session` is accepted
        # (registry uniform call contract) but intentionally ignored here.
        try:
            r = http_config.unauth_get(
                app_url(base, path), allow_redirects=False, timeout=10
            )
        except Exception:
            continue
        if r is not None and r.status_code == 200:
            markers = find_config_markers(r.text or "")
            if markers:
                return {
                    "vulnerable": True,
                    "path": path,
                    "vuln_class": "info_disclosure",
                    "detonated": False,
                    "confirm": {"markers": markers},
                    "note": "Cleartext config/SSO/env markers exposed in served HTML to client.",
                }
    return None

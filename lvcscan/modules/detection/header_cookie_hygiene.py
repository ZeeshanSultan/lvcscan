#!/usr/bin/env python3
"""
Header / Cookie Hygiene Detector (generic, detect-only)

Inspects HTTP response headers for:
  (a) Missing security headers — Content-Security-Policy, Strict-Transport-Security,
      X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
  (b) Session cookies missing HttpOnly / Secure / SameSite flags.
  (c) EOL PHP version disclosure via X-Powered-By matching PHP/7.x or earlier.

vuln_class = "info_disclosure"  |  detect-only  |  generic
"""

import re
from typing import Dict, List, Optional

from modules.core import http_config
from modules.core.http_config import normalize_base, app_url

SECURITY_HEADERS: List[str] = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# Matches PHP/7.x or any earlier major version (0–7)
_EOL_PHP_RE = re.compile(r"PHP/[0-7]\.", re.IGNORECASE)


def analyze_headers(headers: dict) -> Dict:
    """Analyse a headers dict (plain dict or case-insensitive requests mapping).

    Always lowercases keys before lookup so both plain dicts (tests) and
    real requests.Response.headers (already case-insensitive) work correctly.

    Returns:
        {
          "missing_headers": list of canonical lowercase header names,
          "eol_php":         the X-Powered-By value string or None,
          "weak_cookies":    list of human-readable weakness strings,
        }
    """
    # Build a plain lowercase-keyed snapshot so dict.get() is case-insensitive
    lower: Dict[str, str] = {k.lower(): v for k, v in headers.items()}

    # (a) Missing security headers
    missing: List[str] = [h for h in SECURITY_HEADERS if h not in lower]

    # (b) EOL PHP disclosure
    powered_by = lower.get("x-powered-by", "")
    eol_php: Optional[str] = powered_by if _EOL_PHP_RE.search(powered_by) else None

    # (c) Weak cookie flags — inspect Set-Cookie string
    weak_cookies: List[str] = []
    set_cookie = lower.get("set-cookie", "")
    if set_cookie:
        # Lowercase the flags portion for case-insensitive flag checks
        cookie_lower = set_cookie.lower()
        if "httponly" not in cookie_lower:
            weak_cookies.append("cookie missing HttpOnly")
        if "secure" not in cookie_lower:
            weak_cookies.append("cookie missing Secure")
        if "samesite" not in cookie_lower:
            weak_cookies.append("cookie missing SameSite")

    return {
        "missing_headers": missing,
        "eol_php": eol_php,
        "weak_cookies": weak_cookies,
    }


def scan(
    target_url,
    *,
    session=None,
    username=None,
    password=None,
    laravel_info=None,
    **kwargs,
) -> Optional[Dict]:
    """GET the root path and inspect response headers for hygiene issues.

    Returns a finding dict when ANY issue is detected, None when all clean.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()
    base = normalize_base(target_url)
    url = app_url(base, "/")

    try:
        r = sess.get(url, timeout=10)
    except Exception:
        return None
    if r is None:
        return None

    findings = analyze_headers(r.headers)

    if findings["missing_headers"] or findings["eol_php"] or findings["weak_cookies"]:
        return {
            "vulnerable": True,
            "path": "/",
            "vuln_class": "info_disclosure",
            "detonated": False,
            "confirm": findings,
            "note": (
                "Header/cookie hygiene gaps: missing security headers / "
                "EOL PHP disclosure / weak cookie flags."
            ),
        }

    return None

#!/usr/bin/env python3
"""
CodeIgniter i18n Language-Loader Path Injection (LFI path-disclosure)

Detects whether the `session_language_v2` cookie (or equivalent language param)
is interpolated into a filesystem path inside CodeIgniter's language loader.

A traversal-shaped benign canary value triggers a PHP error that leaks the
path template:
    Unable to load the requested language file: language/<injected>/.../*_lang.php

This is a PATH-DISCLOSURE 500, NOT a demonstrated file read.
  - vuln_class    = "lfi"
  - exploit_status = "needs-validation"
  - detonated     = False  (benign canary only — no real traversal target)
"""

import re
from typing import Dict, Optional

from modules.core import http_config
from modules.core.http_config import normalize_base, app_url

CANARY = "zzcanaryzz"
_CANARY_COOKIE_VALUE = f"../{CANARY}"

# Regex that matches the CI error message containing our canary anywhere in the path.
_LEAK_RE = re.compile(
    r"Unable to load the requested language file: language/.*" + re.escape(CANARY),
    re.IGNORECASE,
)

# Routes that CI apps commonly load language files on (admin and public).
_PROBE_PATHS = [
    "/admin/login.html",
    "/admin/login/auth.html",
    "/",
]


def scan(
    target_url: str,
    *,
    session=None,
    username=None,
    password=None,
    laravel_info=None,
    **kwargs,
) -> Optional[Dict]:
    """
    Probe CI language-consuming routes with a benign canary cookie.

    Returns a finding dict (vulnerable=True) when the server returns HTTP 500
    and the body leaks the language/ path template containing our canary.
    Returns None when no signal is found.

    The probe is issued through http_config.unauth_get so the operator's -H auth
    Cookie is NOT injected: that injection would override our canary
    `session_language_v2` value (yielding the benign default) AND 302 the
    authenticated request away from /admin/login.html before the path-disclosure
    500 can fire. Unauthenticated, the same request returns the leak. `session=`
    is accepted for API compatibility but is intentionally NOT used for the probe.
    """
    if not target_url:
        return None

    base = normalize_base(target_url)

    for path in _PROBE_PATHS:
        try:
            url = app_url(base, path)
            r = http_config.unauth_get(
                url,
                cookies={"session_language_v2": _CANARY_COOKIE_VALUE},
                allow_redirects=False,
            )
        except Exception:
            continue

        if r is not None and r.status_code == 500 and _LEAK_RE.search(r.text):
            return {
                "vulnerable": True,
                "path": path,
                "vuln_class": "lfi",
                "exploit_status": "needs-validation",
                "detonated": False,
                "confirm": (
                    "HTTP 500 + 'Unable to load the requested language file: "
                    "language/<injected>/...'"
                ),
                "note": (
                    "CI i18n language param interpolated into FS path "
                    "(path-disclosure 500); NOT a demonstrated file read — "
                    "needs validation. Benign canary only."
                ),
            }

    return None

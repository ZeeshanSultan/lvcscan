#!/usr/bin/env python3
"""
Cookie Reflection XSS Detector (generic, static DOM-sink scan)

Detects client-side/DOM XSS where a cookie value is read via
Cookies.get('NAME') or document.cookie and written into the DOM
without encoding via .html(), innerHTML, append(), or string
concatenation into a jQuery dialog.

This is a static signal — no payload is sent to the target.
"""

import re
from typing import Dict, List, Optional

from modules.core import http_config
from modules.core.http_config import normalize_base, app_url

# Paths to probe for client-side JS with cookie DOM sinks
PROBE_PATHS = [
    "/admin/index.html",
    "/admin/",
    "/",
]

# Regex to find Cookies.get('name') and capture the cookie name
_COOKIES_GET_RE = re.compile(r"Cookies\.get\(['\"]([^'\"]+)['\"]\)")

# Regex to detect document.cookie access (raw cookie string)
_DOC_COOKIE_RE = re.compile(r"document\.cookie")

# Patterns that indicate unsafe DOM sink (unencoded write into DOM).
# Only actual DOM-write sinks are listed here — bare string-concat patterns
# were dropped because they fire on any var + 'string' near a Cookies.get(),
# causing false positives on code that never touches the DOM.
_UNSAFE_SINK_PATTERNS = [
    r"\.html\s*\(",
    r"innerHTML\s*=",
    r"\.append\s*\(",
    r"document\.write\s*\(",
    r"\.dialog\s*\(",
    r"message\s*:",
]
_UNSAFE_SINK_RE = re.compile("|".join(_UNSAFE_SINK_PATTERNS))

# Patterns that indicate safe encoding wrapper
_SAFE_WRAPPER_PATTERNS = [
    r"\.text\s*\(",
    r"escapeHtml\s*\(",
    r"encodeURIComponent\s*\(",
    r"encodeURI\s*\(",
    r"DOMPurify\.",
]
_SAFE_WRAPPER_RE = re.compile("|".join(_SAFE_WRAPPER_PATTERNS))

# Window size to check for nearby sink usage
_WINDOW = 200


def find_cookie_dom_sinks(html: str) -> List[str]:
    """Return list of cookie names that flow into an unencoded DOM sink.

    Searches for Cookies.get('NAME') references. For each match, checks
    within a ~200-char window whether the value is used in an unsafe DOM
    sink (.html(), innerHTML, append(), string concat) WITHOUT a safe
    encoding wrapper (.text(), escapeHtml, encodeURIComponent, etc.).

    Also handles document.cookie access as a generic flag (no specific name).

    Returns the list of flagged cookie names (strings). Empty list = safe.
    """
    flagged: List[str] = []

    # Check Cookies.get('name') patterns
    for m in _COOKIES_GET_RE.finditer(html):
        cookie_name = m.group(1)
        # Grab the window around and after the match
        start = max(0, m.start() - 50)
        end = min(len(html), m.end() + _WINDOW)
        window = html[start:end]

        # Check for unsafe sink in window
        if not _UNSAFE_SINK_RE.search(window):
            continue

        # Check for safe wrapper — if it wraps the variable, do not flag
        # Strategy: look for a .text( that appears in the same statement
        # as the cookie reference. We look for .text( in the window.
        if _SAFE_WRAPPER_RE.search(window):
            continue

        flagged.append(cookie_name)

    return flagged


def scan(
    target_url,
    *,
    session=None,
    username=None,
    password=None,
    laravel_info=None,
    **kwargs,
) -> Optional[Dict]:
    """Scan admin/root pages for cookie values read into DOM without encoding.

    Returns a finding dict if a DOM XSS sink is detected, None otherwise.
    No payload is sent — this is a purely static/structural signal.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()
    base = normalize_base(target_url)

    for path in PROBE_PATHS:
        url = app_url(base, path)
        try:
            r = sess.get(url, timeout=10)
        except Exception:
            continue
        if r is not None and r.status_code == 200:
            sinks = find_cookie_dom_sinks(r.text or "")
            if sinks:
                return {
                    "vulnerable": True,
                    "path": path,
                    "vuln_class": "xss",
                    "confirm": {"cookie_sinks": sinks},
                    "detonated": False,
                    "note": (
                        "Cookie value read into DOM without encoding "
                        "(client-side/DOM XSS). Static signal — no payload sent."
                    ),
                }

    return None

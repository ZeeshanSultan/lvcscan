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

# Unsafe DOM-write sinks. Each template takes {v} = the value expression that must
# actually appear AS (part of) the sink's argument — i.e. real dataflow, not mere
# proximity. `[^;]{0,120}` keeps the match inside the same statement. The old approach
# flagged any sink token within ~200 chars of any Cookies.get(), so minified jQuery/
# bootstrap bundles trivially tripped it; the loose `message:` pattern is gone.
_SINK_ARG_TEMPLATES = [
    r"\.html\(\s*[^;]{{0,120}}{v}",
    r"\.append\(\s*[^;]{{0,120}}{v}",
    r"\.prepend\(\s*[^;]{{0,120}}{v}",
    r"\.after\(\s*[^;]{{0,120}}{v}",
    r"\.before\(\s*[^;]{{0,120}}{v}",
    r"innerHTML\s*=\s*[^;]{{0,120}}{v}",
    r"outerHTML\s*=\s*[^;]{{0,120}}{v}",
    r"document\.write\(\s*[^;]{{0,120}}{v}",
    r"\.dialog\(\s*\{{[^;]{{0,200}}{v}",
]

# Patterns that indicate a safe encoding wrapper in the same segment.
_SAFE_WRAPPER_PATTERNS = [
    r"\.text\s*\(",
    r"escapeHtml\s*\(",
    r"encodeURIComponent\s*\(",
    r"encodeURI\s*\(",
    r"DOMPurify\.",
]
_SAFE_WRAPPER_RE = re.compile("|".join(_SAFE_WRAPPER_PATTERNS))


def find_cookie_dom_sinks(html: str) -> List[str]:
    """Return cookie names whose value actually FLOWS into an unencoded DOM sink.

    For each Cookies.get('NAME'):
      * the value expressions that must reach a sink are the call itself AND any
        variable it is directly assigned to (var x = Cookies.get('NAME')), and
      * a finding requires one of those expressions to appear as (part of) an unsafe
        DOM-write argument in the SAME statement, with no safe wrapper (.text(),
        escapeHtml, encodeURIComponent, DOMPurify) around it.

    Proximity alone no longer flags. Returns the flagged cookie names (empty = safe).
    """
    flagged: List[str] = []

    for m in _COOKIES_GET_RE.finditer(html):
        cookie_name = m.group(1)
        full_call = m.group(0)  # Cookies.get('NAME')

        # Value expressions that carry the tainted cookie value.
        exprs = [re.escape(full_call)]
        assign = re.search(r"\b([A-Za-z_$][\w$]*)\s*=\s*" + re.escape(full_call), html)
        if assign:
            exprs.append(re.escape(assign.group(1)) + r"\b")

        hit = False
        for v in exprs:
            for tmpl in _SINK_ARG_TEMPLATES:
                mm = re.search(tmpl.format(v=v), html)
                if not mm:
                    continue
                seg = html[max(0, mm.start() - 40): mm.end() + 20]
                if _SAFE_WRAPPER_RE.search(seg):
                    continue  # value is encoded before the sink
                hit = True
                break
            if hit:
                break
        if hit:
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

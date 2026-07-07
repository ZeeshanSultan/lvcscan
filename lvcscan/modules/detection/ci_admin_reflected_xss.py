#!/usr/bin/env python3
"""
CodeIgniter Admin Reflected XSS (generic, benign-canary detection)

GETs CI-admin endpoints with a benign canary value injected into common
reflected-XSS-prone query parameters.  If the canary is echoed back
UNESCAPED in the response body the endpoint is flagged.

No real XSS payload is ever sent — this is detect-only.
  - vuln_class = "xss"
  - detonated  = False  (benign canary only)
"""

from typing import Dict, List, Optional
from urllib.parse import quote

from modules.core import http_config
from modules.core.http_config import normalize_base, app_url

# Benign canary — contains an HTML tag character so we can distinguish
# reflected-unescaped from reflected-escaped.
# NOTE: the <b> is load-bearing — it distinguishes unescaped reflection
# (literal <b> present in body) from HTML-entity-encoded reflection
# (&lt;b&gt;), which would NOT be a live XSS sink.
CANARY: str = "zqxjk<b>123"

# Common CI admin parameters that are frequently reflected without encoding.
PARAMS: List[str] = [
    "per_page",
    "pageSize",
    "sort",
    "sort_field",
    "sort_order",
    "type",
    "from_date",
    "to_date",
    "q[search_keyword]",
    "q[user_id]",
    "ip",
]

# Small default endpoint set — keeps request count bounded.
_DEFAULT_ENDPOINTS: List[str] = [
    "/admin/index.html",
]


def is_reflected_unescaped(body: str) -> bool:
    """Return True iff the literal canary (unescaped) is present in *body*."""
    return CANARY in body


def scan(
    target_url: str,
    *,
    session=None,
    username=None,
    password=None,
    laravel_info=None,
    endpoints: Optional[List[str]] = None,
    **kwargs,
) -> Optional[Dict]:
    """
    Probe CI-admin endpoints for reflected-XSS using a benign canary.

    Parameters
    ----------
    target_url : str
        Base URL of the target application.
    session : requests.Session, optional
        Authenticated session; falls back to http_config.get_auth_session().
    endpoints : list[str], optional
        Paths to probe (default: ``_DEFAULT_ENDPOINTS``).

    Returns
    -------
    dict
        Finding dict (vulnerable=True) on first unescaped reflection.
    None
        When no unescaped reflection is detected.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()
    base = normalize_base(target_url)
    probe_endpoints = endpoints if endpoints is not None else _DEFAULT_ENDPOINTS

    for endpoint in probe_endpoints:
        for param in PARAMS:
            try:
                url = app_url(base, endpoint) + f"?{param}={quote(CANARY)}"
                r = sess.get(url, timeout=10, allow_redirects=False)
            except Exception:
                continue

            if r is not None and r.status_code == 200 and is_reflected_unescaped(r.text):
                return {
                    "vulnerable": True,
                    "path": endpoint,
                    "param": param,
                    "vuln_class": "xss",
                    "confirm": f"canary {CANARY!r} reflected unescaped",
                    "detonated": False,
                    "note": (
                        "Reflected XSS — benign canary echoed without HTML-encoding. "
                        "No payload executed."
                    ),
                }

    return None

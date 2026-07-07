#!/usr/bin/env python3
"""
API Tunnel Bypass Detector (App-Specific)

Confirms that /api/tran/* endpoints return structured plaintext JSON with the
plain session cookie and NO ECDH/AES encryption envelope.  The app is supposed
to protect these responses via an encrypted tunnel; plaintext JSON means the
tunnel is bypassed and session-owned transaction data is readable in the clear.

GET-only; never POSTs to transaction endpoints (prove-not-detonate).

vuln_class : info_disclosure
scope      : app-specific (hardcodes /api/tran/* paths)
detonated  : False (reads only own-session data, no destructive action)
"""

import json
from typing import Dict, Optional

from modules.core import http_config
from modules.core.http_config import normalize_base, app_url

API_ENDPOINTS = [
    "/api/tran/searchNote",
    "/api/tran/list",
    "/api/tran/detail",
]


def looks_like_plaintext_json(body: str, content_type: str) -> bool:
    """Return True if body is valid JSON and the Content-Type indicates JSON.

    An encrypted blob (e.g. Salted__ / base64 opaque string) will:
      - not carry an "application/json" content-type, AND/OR
      - fail json.loads.
    Both conditions must pass to be considered plaintext JSON.
    """
    if "json" not in content_type.lower():
        return False
    try:
        parsed = json.loads(body)
        # Must be a non-trivial structure (dict or list), not just a scalar.
        return isinstance(parsed, (dict, list))
    except (ValueError, TypeError):
        return False


def scan(
    target_url: str,
    *,
    session=None,
    username=None,
    password=None,
    laravel_info=None,
    **kwargs,
) -> Optional[Dict]:
    """Scan /api/tran/* endpoints for plaintext JSON responses that should be
    encrypted.  Returns a finding dict if any endpoint leaks structured data,
    or None if all endpoints are encrypted / unreachable.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()

    base = normalize_base(target_url)

    for endpoint in API_ENDPOINTS:
        url = app_url(base, endpoint)
        r = None
        try:
            r = sess.get(url, timeout=10)
        except Exception:
            pass

        if r is not None and r.status_code == 200:
            content_type = r.headers.get("Content-Type", "")
            body = r.text or ""
            if looks_like_plaintext_json(body, content_type):
                return {
                    "vulnerable": True,
                    "path": endpoint,
                    "vuln_class": "info_disclosure",
                    "scope": "app-specific",
                    "detonated": False,
                    "confirm": (
                        "API returned plaintext JSON with plain session cookie "
                        "(no ECDH/AES envelope)"
                    ),
                    "note": (
                        "Transaction API data accessible without the app's intended "
                        "encrypted tunnel. Own-session data only."
                    ),
                }

    return None

#!/usr/bin/env python3
"""
CodeIgniter Admin Blind SQL Injection — Boolean/Error Differential

Sends a benign single-tick probe to an authenticated admin search parameter
and confirms response DIVERGENCE (status code or body length differs between
the baseline value vs a single-tick "'" value).

This is a PROVE-NOT-DETONATE approach:
  - No UNION/extraction payload
  - No sqlmap
  - No data is dumped
  - vuln_class     = "sqli"
  - command_capable = False
  - detonated       = False

If no divergence is observed the result is inconclusive (returns None),
because errors may be suppressed by the application.
"""

from typing import Dict, List, Optional
from urllib.parse import urlencode

from modules.core import http_config
from modules.core.http_config import normalize_base, app_url

# Default seed: common CI admin bank/search params
_DEFAULT_PARAMS: List[str] = ["bank_name", "bank_account_no"]

# Divergence threshold: body length must differ by more than this fraction
_LEN_DIFF_THRESHOLD = 0.10  # 10%


def scan(
    target_url: str,
    *,
    session=None,
    username=None,
    password=None,
    laravel_info=None,
    endpoint: str = "/admin/bank/search.html",
    params: Optional[List[str]] = None,
    **kwargs,
) -> Optional[Dict]:
    """
    Probe CI admin search endpoints with a boolean/error differential.

    For each candidate parameter:
      1. GET baseline: ?param=1
      2. GET tick:     ?param=1%27  (single-tick, URL-encoded)

    If tick response status differs from baseline OR body length differs by
    more than 10%, treat as DIVERGENCE -> blind SQLi candidate.

    Returns a finding dict on divergence, None if inconclusive.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()
    base = normalize_base(target_url)
    probe_params = params if params is not None else _DEFAULT_PARAMS

    def _get(value):
        try:
            u = app_url(base, endpoint) + "?" + urlencode({param: value})
            return sess.get(u, timeout=10, allow_redirects=False)
        except Exception:
            return None

    def _ratio(a, b):
        la, lb = len(a.text), len(b.text)
        base_len = max(la, lb, 1)
        return abs(la - lb) / base_len

    for param in probe_params:
        # Two identical baselines establish the page's NATURAL variance (CSRF tokens,
        # timestamps, rotating banners routinely differ between two identical requests).
        b1, b2 = _get("1"), _get("1")
        if b1 is None or b2 is None:
            continue
        natural = _ratio(b1, b2)
        # A hit must exceed natural variance by a margin, not a flat 10%.
        margin = max(_LEN_DIFF_THRESHOLD, natural * 3)

        # Boolean/error differential: an UNBALANCED tick breaks the query (error/different),
        # while a BALANCED even-tick value is valid SQL and should behave like the baseline.
        err = _get("1'")            # odd quotes -> syntax error if injectable
        valid = _get("1''")         # even quotes -> valid -> baseline-like if injectable
        if err is None or valid is None:
            continue

        err_diverges = (err.status_code != b1.status_code) or (_ratio(err, b1) > margin)
        valid_matches = (valid.status_code == b1.status_code) and (_ratio(valid, b1) <= margin)
        # Baseline must itself be stable, else the endpoint is just noisy (not SQLi).
        baseline_stable = (b1.status_code == b2.status_code) and (natural <= _LEN_DIFF_THRESHOLD)

        if baseline_stable and err_diverges and valid_matches:
            return {
                "vulnerable": True,
                "path": endpoint,
                "param": param,
                "vuln_class": "sqli",
                "command_capable": False,
                "detonated": False,
                "confirm": {
                    "baseline_status": b1.status_code,
                    "error_tick_status": err.status_code,
                    "valid_tick_status": valid.status_code,
                    "natural_variance": round(natural, 4),
                    "error_ratio": round(_ratio(err, b1), 4),
                },
                "note": (
                    "Boolean/error differential: unbalanced tick diverges while the "
                    "balanced even-tick value matches baseline, beyond the page's natural "
                    "variance (prove-not-detonate; no data extracted)."
                ),
            }

    return None

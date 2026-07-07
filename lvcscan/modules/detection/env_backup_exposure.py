#!/usr/bin/env python3
"""
Laravel Environment Backup File Exposure Scanner

This module detects exposed Laravel environment backup files that may contain
sensitive configuration data such as database credentials, API keys, and
application secrets.
"""

import requests
from typing import Dict, List, Optional, Union

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for exposed Laravel environment backup files.

    Args:
        target_url (str): The target URL to scan

    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/.env.bak", "url": "https://example.com/.env.bak", "http_status": 200}
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()

    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = normalize_base(target_url)
        
        # Environment backup file paths to test
        backup_paths = [
            '/.env.bak',
            '/.env.old',
            '/.env.save'
        ]
        
        for path in backup_paths:
            full_url = app_url(target_url, path)
            
            # Make request with short timeout
            response = sess.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            # Check if status is 200 and content contains Laravel env variables
            if response.status_code == 200:
                content = response.text
                
                # Check for Laravel environment variable indicators
                env_indicators = [
                    'APP_KEY=',
                    'DB_PASSWORD=',
                    'MAIL_',
                    'AWS_'
                ]
                
                # If any indicator found, mark as exposed
                if any(indicator in content for indicator in env_indicators):
                    return {
                        "path": path,
                        "url": full_url,
                        "http_status": response.status_code
                    }
        
    except Exception:
        # Silently handle all exceptions
        pass
    
    return None





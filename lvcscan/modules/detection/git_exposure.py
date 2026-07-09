#!/usr/bin/env python3
"""
Git Directory Exposure Scanner

This module detects exposed .git directories in Laravel websites by checking
for accessible git configuration files that may leak sensitive repository
information and source code.
"""

import re
import requests
from typing import Dict, List, Optional, Union

from modules.core.http_config import app_url, normalize_base
from modules.core import http_config


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for exposed .git directory vulnerability.

    Args:
        target_url (str): The target URL to scan

    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/.git/HEAD", "url": "https://example.com/.git/HEAD", "status": "exposed", "http_status": 200}
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()

    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    # Remove trailing slash for consistent path joining
    target_url = normalize_base(target_url)

    # Git paths to test
    git_paths = [
        '/.git/HEAD',
        '/.git/config'
    ]

    for path in git_paths:
        try:
            full_url = app_url(target_url, path)

            response = sess.get(
                full_url,
                timeout=10,
                allow_redirects=False
            )
            
            # Check if response indicates exposed git directory
            if _is_git_exposed(response, path):
                return {
                    "path": path,
                    "url": full_url,
                    "status": "exposed",
                    "http_status": response.status_code
                }
                
        except Exception:
            # Silently continue to next path on any error
            continue
    
    return None


def _is_git_exposed(response: requests.Response, path: str) -> bool:
    """
    Analyze response to determine if git directory is exposed.
    
    Args:
        response: The HTTP response object
        path: The git path that was tested
        
    Returns:
        bool: True if git directory exposure is detected
    """
    # Must have successful status code
    if response.status_code != 200:
        return False
    
    try:
        content = response.text
        
        # Check for git-specific indicators based on the path
        if path.endswith('/HEAD'):
            # HEAD file should contain refs/ or commit hash
            head_indicators = [
                'refs/',
                'ref: refs/',
                'refs/heads/',
                # Also check for direct commit hash (40 character hex)
            ]
            
            # Check for standard HEAD file content
            if any(indicator in content for indicator in head_indicators):
                return True
            
            # Check if content looks like a commit hash (40 hex characters)
            content_stripped = content.strip()
            if len(content_stripped) == 40 and all(c in '0123456789abcdef' for c in content_stripped.lower()):
                return True
        
        elif path.endswith('/config'):
            # Require a STRONG git-config anchor. The old list included bare substrings
            # ('bare', 'filemode') that match unrelated words in an HTML soft-404 served
            # 200 at /.git/config. A real git config always carries a "[core]" section
            # header with "repositoryformatversion"; require that pairing (or an explicit
            # remote/branch section header alongside [core]).
            has_core = '[core]' in content and 'repositoryformatversion' in content
            has_section = bool(re.search(r'^\[(remote |branch |core\])', content, re.MULTILINE))
            if has_core or (has_section and 'repositoryformatversion' in content):
                return True
        
    except Exception:
        pass
    
    return False




def _analyze_git_exposure(response: requests.Response, path: str) -> Dict[str, Union[str, List[str], bool]]:
    """
    Analyze the exposed git file for detailed information.
    
    Args:
        response: The HTTP response object
        path: The git path that was tested
        
    Returns:
        Dict: Analysis of exposed git information
    """
    analysis = {
        "file_type": "",
        "content_preview": "",
        "indicators_found": [],
        "potential_branch": "",
        "repository_info": {}
    }
    
    try:
        content = response.text
        
        if path.endswith('/HEAD'):
            analysis["file_type"] = "git_head"
            analysis["content_preview"] = content.strip()[:100]  # First 100 chars
            
            # Extract branch information
            if 'refs/heads/' in content:
                try:
                    branch_line = [line for line in content.split('\n') if 'refs/heads/' in line][0]
                    branch_name = branch_line.split('refs/heads/')[-1].strip()
                    analysis["potential_branch"] = branch_name
                    analysis["indicators_found"].append(f"Active branch: {branch_name}")
                except:
                    pass
            
            # Check for commit hash
            content_stripped = content.strip()
            if len(content_stripped) == 40 and all(c in '0123456789abcdef' for c in content_stripped.lower()):
                analysis["indicators_found"].append("Direct commit hash found")
        
        elif path.endswith('/config'):
            analysis["file_type"] = "git_config"
            analysis["content_preview"] = content[:200]  # First 200 chars
            
            # Extract repository configuration details
            lines = content.split('\n')
            current_section = ""
            
            for line in lines:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                elif '=' in line and current_section:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if current_section not in analysis["repository_info"]:
                        analysis["repository_info"][current_section] = {}
                    analysis["repository_info"][current_section][key] = value
                    
                    # Add specific indicators
                    if key == 'repositoryformatversion':
                        analysis["indicators_found"].append(f"Repository format version: {value}")
                    elif key == 'url' and 'remote' in current_section:
                        analysis["indicators_found"].append(f"Remote URL found: {value}")
                    elif key == 'merge' and 'branch' in current_section:
                        analysis["indicators_found"].append(f"Branch merge info: {value}")
        
    except Exception:
        pass
    
    return analysis




def check_git_directory_listing(target_url: str, *, session=None) -> Optional[Dict[str, Union[str, int, bool]]]:
    """
    Check if .git directory allows directory listing.

    Args:
        target_url (str): The target URL to scan

    Returns:
        Optional[Dict]: Directory listing vulnerability information
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()

    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    target_url = normalize_base(target_url)

    try:
        git_dir_url = app_url(target_url, '/.git/')
        response = sess.get(git_dir_url, timeout=10, allow_redirects=False)
        
        if response.status_code == 200:
            content = response.text.lower()
            
            # Check for directory listing indicators
            directory_indicators = [
                'index of',
                'directory listing',
                'parent directory',
                '<a href="',
                'head',
                'config',
                'objects',
                'refs'
            ]
            
            # Count indicators
            indicator_count = sum(1 for indicator in directory_indicators if indicator in content)
            
            if indicator_count >= 3:  # Likely directory listing
                return {
                    "path": "/.git/",
                    "url": git_dir_url,
                    "status": "directory_listing",
                    "http_status": response.status_code,
                    "directory_listing_detected": True
                }
                
    except Exception:
        pass
    
    return None



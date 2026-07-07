#!/usr/bin/env python3
"""
Laravel File Manager Exposure Scanner

This module detects whether the Laravel File Manager (typically UniSharp/laravel-filemanager)
is publicly accessible without proper authentication. This can lead to unauthorized file
access, upload capabilities, and potential security vulnerabilities.
"""

import requests
from typing import Dict, List, Optional, Union

from modules.core import http_config




def scan_detailed(url: str, *, session=None, username=None, password=None, **kwargs) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
    """
    Perform detailed scan with comprehensive analysis of Laravel File Manager exposure.

    Args:
        url (str): The target URL to scan

    Returns:
        Optional[Dict]: Detailed exposure information
    """
    if not url:
        return None

    sess = session or http_config.get_auth_session()
    
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        url = url.rstrip('/')
        
        # Extended paths including common variations
        extended_paths = [
            '/laravel-filemanager',
            '/filemanager',
            '/admin/laravel-filemanager',
            '/admin/filemanager',
            '/admin/file-manager',
            '/lfm',
            '/file-manager',
            '/files',
            '/uploads',
            '/media',
            '/assets/filemanager',
            '/public/laravel-filemanager',
            '/backend/filemanager'
        ]
        
        # Extended detection keywords
        extended_keywords = [
            'filemanager',
            'upload',
            'files',
            'images',
            'unisharp',
            'lfm',
            'laravel file manager',
            'file browser',
            'media manager',
            'asset manager',
            'tinymce',
            'ckeditor',
            'browse files'
        ]
        
        for path in extended_paths:
            full_url = url + path
            
            try:
                response = sess.get(
                    full_url,
                    timeout=10,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    found_keywords = []
                    
                    # Find all matching keywords
                    for keyword in extended_keywords:
                        if keyword in content:
                            found_keywords.append(keyword)
                    
                    if found_keywords:
                        # Analyze the response for additional details
                        analysis = _analyze_filemanager_response(response)
                        
                        return {
                            "path": path,
                            "url": full_url,
                            "http_status": response.status_code,
                            "detected_strings": found_keywords,
                            "primary_detected_string": found_keywords[0],
                            "content_size": len(response.content),
                            "analysis": analysis,
                            "response_headers": dict(response.headers)
                        }
            
            except requests.RequestException:
                continue
        
    except Exception:
        pass
    
    return None


def _analyze_filemanager_response(response: requests.Response) -> Dict[str, Union[bool, List[str]]]:
    """
    Analyze file manager response for additional security information.
    
    Args:
        response: HTTP response object
        
    Returns:
        Dict: Analysis results
    """
    analysis = {
        "has_authentication": False,
        "allows_upload": False,
        "shows_file_listing": False,
        "framework_indicators": [],
        "security_concerns": []
    }
    
    try:
        content = response.text.lower()
        
        # Check for authentication indicators
        auth_indicators = [
            'login',
            'password',
            'authenticate',
            'csrf',
            'token',
            'signin',
            'unauthorized'
        ]
        
        if any(indicator in content for indicator in auth_indicators):
            analysis["has_authentication"] = True
        else:
            analysis["security_concerns"].append("No authentication detected")
        
        # Check for upload capabilities
        upload_indicators = [
            'upload',
            'file upload',
            'drag',
            'drop files',
            'choose file',
            'select files'
        ]
        
        if any(indicator in content for indicator in upload_indicators):
            analysis["allows_upload"] = True
            if not analysis["has_authentication"]:
                analysis["security_concerns"].append("Upload functionality without authentication")
        
        # Check for file listing
        listing_indicators = [
            'file list',
            'directory',
            'folder',
            'tree view',
            'file browser',
            'files and folders'
        ]
        
        if any(indicator in content for indicator in listing_indicators):
            analysis["shows_file_listing"] = True
            if not analysis["has_authentication"]:
                analysis["security_concerns"].append("File listing accessible without authentication")
        
        # Framework indicators
        framework_indicators = [
            ('laravel', 'Laravel Framework'),
            ('unisharp', 'UniSharp Laravel File Manager'),
            ('tinymce', 'TinyMCE Integration'),
            ('ckeditor', 'CKEditor Integration'),
            ('bootstrap', 'Bootstrap UI Framework'),
            ('jquery', 'jQuery Library')
        ]
        
        for indicator, description in framework_indicators:
            if indicator in content:
                analysis["framework_indicators"].append(description)
        
    except Exception:
        pass
    
    return analysis







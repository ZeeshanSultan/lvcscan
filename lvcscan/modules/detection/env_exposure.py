#!/usr/bin/env python3
"""
Laravel Environment & Sensitive File Exposure Scanner

This module scans for exposed Laravel environment files (.env) and now also
.htaccess files that may reveal sensitive configuration data.
"""

import re
from typing import Dict, List, Optional, Union

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base

# ------------------------------------------------------------
# Paths updated to include .htaccess checks
# ------------------------------------------------------------
ENV_PATHS = [
    '/.env',
    '/.env.backup',
    '/.env.dev',
    '/.env.local',
    '/backup/.env',

    # NEW SENSITIVE FILES
    '/.htaccess',
    '/public/.htaccess',
    '/storage/.htaccess',
    '/backup/.htaccess'
]

# ------------------------------------------------------------
def scan(target_url: str, *, session=None, username=None, password=None,
         laravel_info=None, **kwargs) -> Optional[Dict[str, Union[str, List[str]]]]:
    """
    Scan for exposed Laravel environment files or .htaccess files.

    laravel_info: optional dict from is_laravel(). When present, the already-fetched /.env
    response is consumed from laravel_info["_env_resp"] to avoid a duplicate HTTP request.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()

    target_url = normalize_base(target_url)

    for path in ENV_PATHS:
        try:
            full_url = app_url(target_url, path)
            # Use the pre-fetched /.env response cached by is_laravel() when available —
            # avoids the double-fetch that occurred on every scan run previously.
            if path == "/.env" and laravel_info is not None:
                _cached = laravel_info.get("_env_resp")
                if _cached is not None:
                    response = _cached
                else:
                    response = sess.get(full_url, timeout=10, allow_redirects=False)
            else:
                response = sess.get(full_url, timeout=10, allow_redirects=False)

            if response.status_code == 200:
                content = response.text

                # Detect .env variables
                env_vars = _check_laravel_env_variables(content)

                # Detect .htaccess patterns
                htaccess_vars = _check_htaccess_exposure(content) if path.endswith('.htaccess') else []

                if env_vars or htaccess_vars:
                    finding = {
                        "path": path,
                        "status": "exposed",
                        "variables": env_vars + htaccess_vars,
                        "variables_type": "env" if env_vars else "htaccess",
                        "url": full_url,
                        "size": len(content)
                    }
                    # Real loot-chain: extract the APP_KEY VALUE from the leaked .env body so
                    # detect-all can chain it into consumer CVEs. Only emit artifacts when a
                    # non-blank key is actually present (skip Laravel's pre-key:generate blank).
                    _app_key = _extract_app_key(content)
                    if _app_key:
                        finding["artifacts"] = {"app_key": _app_key}
                    return finding

        except Exception:
            continue

    return None


# ------------------------------------------------------------
def _extract_app_key(content: str) -> Optional[str]:
    """
    Extract the Laravel APP_KEY VALUE from leaked .env content.

    Anchored to line-start so it never latches onto PUSHER_APP_KEY= (whose value
    is unrelated and would otherwise be captured because the substring 'APP_KEY='
    lives inside 'PUSHER_APP_KEY='). Strips surrounding quotes/whitespace but keeps
    trailing '=' (base64 padding). Returns None for a blank/absent key.
    """
    m = re.search(r'^APP_KEY=(.*)$', content, re.MULTILINE)
    if not m:
        return None
    value = m.group(1)
    value = re.sub(r'\s+#.*$', '', value)   # drop inline comment
    value = value.strip().strip('"').strip("'").strip()
    return value or None


# ------------------------------------------------------------
def _check_laravel_env_variables(content: str) -> List[str]:
    """Identify exposed Laravel .env variables."""
    found = []

    patterns = [
        'APP_KEY=', 'APP_NAME=', 'APP_ENV=', 'APP_DEBUG=', 'APP_URL=',
        'DB_CONNECTION=', 'DB_HOST=', 'DB_PORT=', 'DB_DATABASE=', 'DB_USERNAME=', 'DB_PASSWORD=',
        'MAIL_MAILER=', 'MAIL_HOST=', 'MAIL_PORT=', 'MAIL_USERNAME=', 'MAIL_PASSWORD=', 'MAIL_ENCRYPTION=',
        'MAIL_FROM_ADDRESS=',
        'REDIS_HOST=', 'REDIS_PASSWORD=', 'REDIS_PORT=',
        'AWS_ACCESS_KEY_ID=', 'AWS_SECRET_ACCESS_KEY=', 'AWS_DEFAULT_REGION=', 'AWS_BUCKET=',
        'PUSHER_APP_ID=', 'PUSHER_APP_KEY=', 'PUSHER_APP_SECRET=',
        'SESSION_DRIVER=', 'SESSION_LIFETIME=',
        'QUEUE_CONNECTION=', 'CACHE_DRIVER=', 'FILESYSTEM_DISK=',
        'LOG_CHANNEL=', 'LOG_DEPRECATIONS_CHANNEL=', 'LOG_LEVEL='
    ]

    for pattern in patterns:
        if pattern in content:
            found.append(pattern.rstrip('='))

    return found


# ------------------------------------------------------------
# NEW: Detect .htaccess exposures
# ------------------------------------------------------------
def _check_htaccess_exposure(content: str) -> List[str]:
    """
    Detect dangerous/interesting .htaccess directives.
    Returns a list of matched categories.
    """
    findings = []

    patterns = {
        "rewrite_engine": "RewriteEngine",
        "rewrite_rule": "RewriteRule",
        "php_flag": "php_flag",
        "php_value": "php_value",
        "deny_all": "deny from all",
        "allow_all": "allow from all",
        "options_indexes": "Options Indexes",
        "auth_basic": "AuthType Basic",
        "server_config": "AddHandler",
    }

    lower = content.lower()

    for key, signature in patterns.items():
        if signature.lower() in lower:
            findings.append(key)

    return findings


# ------------------------------------------------------------


# ------------------------------------------------------------
def _categorize_variables(variables: List[str]) -> Dict[str, List[str]]:
    """Group .env variables by risk."""
    categories = {
        "critical": [],
        "sensitive": [],
        "informational": []
    }

    critical = [
        'DB_PASSWORD', 'MAIL_PASSWORD', 'REDIS_PASSWORD',
        'AWS_SECRET_ACCESS_KEY', 'APP_KEY', 'PUSHER_APP_SECRET'
    ]

    sensitive = [
        'DB_HOST', 'DB_DATABASE', 'DB_USERNAME', 'DB_CONNECTION',
        'MAIL_HOST', 'MAIL_USERNAME', 'AWS_ACCESS_KEY_ID',
        'PUSHER_APP_ID', 'PUSHER_APP_KEY'
    ]

    for v in variables:
        if v in critical:
            categories["critical"].append(v)
        elif v in sensitive:
            categories["sensitive"].append(v)
        else:
            categories["informational"].append(v)

    return categories


# ------------------------------------------------------------

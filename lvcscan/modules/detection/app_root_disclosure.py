#!/usr/bin/env python3
"""
Application-root static disclosure scanner.

Detects the misconfiguration where a web server serves the Laravel APPLICATION ROOT
(/var/www/html) as static files instead of only the public/ document root. The classic
cause is a stock vhost (e.g. Debian's `sites-enabled/default`, `root /var/www/html`,
no PHP handler) shadowing the intended app vhost — every project file below the app
root becomes downloadable: source, config, the dependency lockfile, and (worst) the
SQLite database and `.env`.

This is DISTINCT from the single-file `.env` leak that env_exposure / CVE-2017-16894
report: here the WHOLE source tree is exfiltrable, which both leaks every secret and
hands an attacker the exact code + dependency versions to plan further attacks. We
report it as its own info_disclosure finding (and still harvest APP_KEY for the
loot-chain when `.env` is among the exposed files).

The probe is read-only: GETs a curated list of app-root files that should NEVER be
web-reachable on a correctly-rooted deployment, and records each that returns 200 with
a content shape matching its expected type (so a SPA catch-all returning 200-HTML for
everything can't produce false positives).

Scope: defensive identification only.
"""

import re
from typing import Dict, List, Optional

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base


# Curated app-root paths. Each entry: (path, kind, validator-token). The token must
# appear in the body for the hit to count — this rejects a SPA/error page that 200s
# arbitrary paths. `None` token means "any 200 with non-trivial body counts" (used for
# binary files like the SQLite DB, validated separately by magic bytes).
# Tokens are chosen to be hard for a SPA/catch-all 200-HTML page to satisfy: PHP files must
# carry the "<?php" open tag, JSON manifests a specific key, etc. A generic index.html cannot
# match these, so an app that 200s arbitrary paths cannot produce a false positive.
_APP_ROOT_TARGETS = [
    ("/.env",                 "secrets",   "APP_KEY"),
    ("/composer.json",        "manifest",  '"require"'),
    ("/composer.lock",        "lockfile",  '"packages"'),
    ("/artisan",              "source",    "<?php"),
    ("/routes/web.php",       "source",    "<?php"),
    ("/routes/api.php",       "source",    "<?php"),
    ("/routes/console.php",   "source",    "<?php"),
    ("/config/app.php",       "config",    "<?php"),
    ("/config/database.php",  "config",    "<?php"),
    ("/config/auth.php",      "config",    "<?php"),
    ("/config/services.php",  "config",    "<?php"),
    ("/config/mail.php",      "config",    "<?php"),
    ("/phpunit.xml",          "config",    "<phpunit"),
    ("/package.json",         "manifest",  '"name"'),
    ("/database/database.sqlite", "database", None),   # validated by SQLite magic bytes
    ("/storage/logs/laravel.log", "log",    None),
    ("/.git/config",          "vcs",       "[core]"),
]

# SQLite files begin with this 16-byte header. Used to validate a /database/*.sqlite hit
# so a 200-HTML error page can't masquerade as the database.
_SQLITE_MAGIC = b"SQLite format 3\x00"

# Laravel log line shape: "[YYYY-MM-DD HH:MM:SS] <env>.<LEVEL>:" — validates a /storage/logs hit
# so a SPA 200-HTML page can't masquerade as the log.
_LARAVEL_LOG_RE = re.compile(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s+\w+\.\w+:")


def scan(target_url: str, *, session=None, laravel_info=None, **kwargs) -> Optional[Dict]:
    """Probe for whole-app-root static exposure.

    Returns a finding dict when >= 2 distinct app-root files are downloadable (one stray
    file is env_exposure's job; the systemic-exposure finding requires breadth so it does
    not double-report a lone `.env`). Returns None otherwise.

    laravel_info: optional dict from is_laravel(); the pre-fetched /.env response is reused
    when present to avoid a duplicate request.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()
    base = normalize_base(target_url)

    exposed: List[Dict] = []
    app_key = None

    for path, kind, token in _APP_ROOT_TARGETS:
        full_url = app_url(base, path)
        resp = None
        # Reuse the cached /.env response from is_laravel() when available.
        if path == "/.env" and laravel_info is not None and laravel_info.get("_env_resp") is not None:
            resp = laravel_info["_env_resp"]
        else:
            try:
                resp = sess.get(full_url, timeout=8, allow_redirects=False, verify=False)
            except Exception:
                continue
        if resp is None or resp.status_code != 200:
            continue

        body = resp.content or b""
        if not body:
            continue

        # Type-specific validation: avoid counting a generic 200-HTML catch-all.
        if kind == "database":
            if not body.startswith(_SQLITE_MAGIC):
                continue
        elif kind == "log":
            # Laravel log lines look like "[2026-06-11 04:42:28] local.ERROR: ...".
            try:
                text = resp.text or ""
            except Exception:
                text = body.decode("utf-8", "replace")
            if not _LARAVEL_LOG_RE.search(text):
                continue
        elif token is not None:
            try:
                text = resp.text or ""
            except Exception:
                text = body.decode("utf-8", "replace")
            if token not in text:
                continue

        exposed.append({
            "path": path,
            "url": full_url,
            "kind": kind,
            "size": len(body),
        })

        if path == "/.env" and app_key is None:
            try:
                app_key = _extract_app_key(resp.text or "")
            except Exception:
                app_key = None

    # Breadth gate: a single stray file is reported by env_exposure / routes_exposure /
    # log_exposure; the systemic "entire app root served as static files" finding needs
    # at least two distinct app-root files (or the database/source, which alone is severe).
    high_value = any(e["kind"] in ("database", "source", "lockfile") for e in exposed)
    if len(exposed) < 2 and not high_value:
        return None
    if not exposed:
        return None

    kinds = sorted({e["kind"] for e in exposed})
    total_bytes = sum(e["size"] for e in exposed)
    finding = {
        "status": "exposed",
        "vulnerable": True,
        "severity": "high",
        "url": base,
        "exposed_files": exposed,
        "exposed_count": len(exposed),
        "exposed_kinds": kinds,
        "total_bytes": total_bytes,
        "evidence": (
            f"application root served as static files: {len(exposed)} sensitive file(s) "
            f"downloadable ({', '.join(kinds)}); {total_bytes} bytes total exfiltrable"
        ),
        "reason": (
            "web server document root resolves to the application root, not public/ — "
            "every project file (source, config, lockfile, database, .env) is reachable. "
            "Likely a stock vhost shadowing the app vhost."
        ),
    }
    if app_key:
        # Participate in the loot-chain: a key harvested here feeds APP_KEY-gated consumer CVEs.
        finding["artifacts"] = {"app_key": app_key,
                                "exposed_files": [e["path"] for e in exposed]}
    else:
        finding["artifacts"] = {"exposed_files": [e["path"] for e in exposed]}
    return finding


def _extract_app_key(content: str) -> Optional[str]:
    """Extract the APP_KEY value from leaked .env content (line-anchored so PUSHER_APP_KEY
    can't be captured; trailing '=' base64 padding preserved). Mirrors env_exposure."""
    m = re.search(r'^APP_KEY=(.*)$', content, re.MULTILINE)
    if not m:
        return None
    value = re.sub(r'\s+#.*$', '', m.group(1)).strip().strip('"').strip("'").strip()
    return value or None

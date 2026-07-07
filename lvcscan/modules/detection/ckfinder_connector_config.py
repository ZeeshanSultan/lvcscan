#!/usr/bin/env python3
"""CKFinder connector config detector (generic, prove-not-detonate).
Reads the ?command=Init JSON to confirm uploadCheckImages=false + blocklist gaps.
NEVER uploads — confirms reachability of the upload-RCE primitive only."""
import json
from typing import Dict, Optional
from modules.core import http_config
from modules.core.http_config import normalize_base, app_url

CONNECTOR_PATHS = [
    "/admin/image_manager/connector.html?command=Init",
    "/ckfinder/core/connector/php/connector.php?command=Init",
    "/admin/ckfinder/connector?command=Init",
    "/ckfinder/connector?command=Init",
]
BYPASS_EXTS = ("php7", "phar", "shtml", "phtml")


def parse_connector_config(body: str) -> Dict:
    data = json.loads(body)
    rtypes = data.get("resourceTypes") or [{}]
    denied = (rtypes[0].get("deniedExtensions", "") or "").lower()
    # Split on commas so "php,php3,exe" doesn't accidentally substring-match
    # "php7" (which contains "php") — each extension is checked as a full token.
    denied_set = {x.strip() for x in denied.split(",")}
    gaps = [e for e in BYPASS_EXTS if e not in denied_set]
    return {"uploadCheckImages": data.get("uploadCheckImages"),
            "blocklist_gaps": gaps, "deniedExtensions": denied}


def scan(target_url, *, session=None, username=None, password=None, laravel_info=None, **kwargs) -> Optional[Dict]:
    if not target_url:
        return None
    sess = session or http_config.get_auth_session()
    base = normalize_base(target_url)
    for path in CONNECTOR_PATHS:
        try:
            r = sess.get(app_url(base, path), timeout=10)
        except Exception:
            continue
        if r is not None and r.status_code == 200 and "resourceTypes" in (r.text or ""):
            try:
                cfg = parse_connector_config(r.text)
            except Exception:
                continue
            if cfg["uploadCheckImages"] is False or cfg["blocklist_gaps"]:
                return {"vulnerable": True, "path": path, "vuln_class": "rce",
                        "confirm": cfg, "command_capable": True, "detonated": False,
                        "note": "CKFinder connector reachable + validation weak; upload NOT attempted (prove-not-detonate)"}
    return None

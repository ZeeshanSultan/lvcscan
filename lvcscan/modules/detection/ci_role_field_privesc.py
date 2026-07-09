#!/usr/bin/env python3
"""
CI Role-Field Privilege Escalation (app-specific, PROVE-NOT-DETONATE)

Confirms the role-mutation sink EXISTS and references a role-controlling field
WITHOUT ever issuing a POST or changing a role.

Probes (GET only):
  - /admin/admin/index.html     (Board page — confirms role-field reference)
  - /admin/admin/updateType.html  (role-mutation sink)
  - /admin/admin/import.html      (secondary role-mutation sink)

A finding is returned when at least one sink is reachable (non-404 with auth)
AND the Board page (or a sink body) references a known role-controlling field
name ("type", "admin_group").

  vuln_class    = "priv_esc"
  command_capable = False
  detonated     = False
  scope         = "app-specific"
"""

import re
from typing import Dict, Optional

from modules.core import http_config
from modules.core.http_config import normalize_base, app_url

# Role-mutation sinks (GET-probed only — never POSTed to)
ROLE_SINKS = [
    "/admin/admin/updateType.html",
    "/admin/admin/import.html",
]

# Board page that embeds role-field references in its HTML/JS
BOARD = "/admin/admin/index.html"

# Field names that indicate role-controlling inputs.
# Each entry is (field_name, compiled_regex) — the regex matches the field name
# as a FORM FIELD NAME reference only, not as an arbitrary HTML attribute.
# "type" only fires on name="type" / name=type / [type] (param references),
# NOT on <input type="text"> or Content-Type headers.
# "admin_group" is specific enough to match as a bare substring.
_TYPE_FIELD_RE = re.compile(r'name=["\']?type["\']?|\[type\]', re.IGNORECASE)
_ADMIN_GROUP_RE = re.compile(r'admin_group', re.IGNORECASE)
# A role-mutation CONTEXT: the generic field name "type" is a role-controlling input
# only when the page is actually about role mutation (a form posting to the role sink,
# an admin_group field, or explicit role wording). Without this, "type" matched every
# search/filter form's <select name="type">.
_ROLE_CONTEXT_RE = re.compile(
    r'updateType|admin_group|/admin/admin/|user_?role|change_?role|role[_-]?id|privilege',
    re.IGNORECASE,
)


def _references_role_field(text: str) -> Optional[str]:
    """Return a role-controlling field name found in *text*, or None.

    "admin_group" is specific enough to stand alone. "type" is generic (search/filter
    forms use name="type"), so it only counts when a role-mutation context is also
    present. Never matches a generic type="text" attribute or a Content-Type header.
    """
    if _ADMIN_GROUP_RE.search(text):
        return "admin_group"
    if _TYPE_FIELD_RE.search(text) and _ROLE_CONTEXT_RE.search(text):
        return "type"
    return None


def scan(
    target_url: str,
    *,
    session=None,
    username=None,
    password=None,
    laravel_info=None,
    **kwargs,
) -> Optional[Dict]:
    """
    GET-only probe: confirm role-mutation sink reachable + role field present.

    Never issues a POST. Returns a finding dict when the conditions are met,
    None otherwise.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()
    base = normalize_base(target_url)

    # --- 1. Fetch the Board page and look for role-field references ---
    role_field_found: Optional[str] = None
    try:
        board_url = app_url(base, BOARD)
        r_board = sess.get(board_url, timeout=10, allow_redirects=False)
        # Require a real authenticated 200. A 302->login / 401 / 403 is NOT a reachable
        # sink — treating any non-404 as reachable produced false priv-esc findings.
        if r_board is not None and r_board.status_code == 200:
            role_field_found = _references_role_field(r_board.text)
    except Exception:
        pass

    # --- 2. Probe each sink (GET only) ---
    reachable_sink: Optional[str] = None
    for sink in ROLE_SINKS:
        try:
            sink_url = app_url(base, sink)
            r_sink = sess.get(sink_url, timeout=10, allow_redirects=False)
            if r_sink is not None and r_sink.status_code == 200:
                reachable_sink = sink
                # Also check sink body for role-field reference if not found yet
                if role_field_found is None:
                    role_field_found = _references_role_field(r_sink.text)
                break
        except Exception:
            continue

    if reachable_sink is None or role_field_found is None:
        return None

    return {
        "vulnerable": True,
        "path": reachable_sink,
        "vuln_class": "priv_esc",
        "command_capable": False,
        "detonated": False,
        "scope": "app-specific",
        "confirm": {
            "sink": reachable_sink,
            "role_field": role_field_found,
        },
        "note": (
            "Role-mutation sink reachable + role field present; "
            "NO role change attempted (prove-not-detonate)."
        ),
    }

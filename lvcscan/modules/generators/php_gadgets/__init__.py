"""Pure-Python phpggc port — gadget chains + platform features.

Public API mirrors ambionics/phpggc where possible without requiring PHP.
"""
from __future__ import annotations

from .bridge import generate_via_phpggc, locate_phpggc, session_encode_via_php
from .chains import codeigniter4, dompdf, guzzle, grav, laminas, laravel, mediawiki, monolog, pydio, symfony, wordpress
from .phar import build_phar, build_phar_from_options, build_phar_via_php
from .platform import (
    FAST_DESTRUCT_FINAL_KEY,
    FAST_DESTRUCT_TEMP_KEY,
    GenerateOptions,
    apply_ascii_strings,
    apply_encoders,
    apply_platform,
    apply_plus_numbers,
    apply_public_properties,
    finalize_fast_destruct,
    maybe_wrap,
    wrap_fast_destruct,
)
from .registry import CHAINS, generate, get_chain, list_chains, normalize_chain
from .serialize import NUL, php_arr, php_bool, php_int, php_null, php_obj, php_ref, php_str, priv, prot, to_bytes

# --- Backward-compatible chain builders (CVE modules import these directly) ---
build_rce1 = laravel.build_rce1
build_rce2 = laravel.build_rce2
build_rce3 = laravel.build_rce3
build_rce4 = laravel.build_rce4
build_rce5 = laravel.build_rce5
build_rce6 = laravel.build_rce6
build_rce7 = laravel.build_rce7
build_rce8 = laravel.build_rce8
build_rce9 = laravel.build_rce9
build_rce10 = laravel.build_rce10
build_rce11 = laravel.build_rce11
build_rce12 = laravel.build_rce12
build_rce13 = laravel.build_rce13
build_rce14 = laravel.build_rce14
build_rce15 = laravel.build_rce15
build_rce16 = laravel.build_rce16
build_rce17 = laravel.build_rce17
build_rce18 = laravel.build_rce18
build_rce19 = laravel.build_rce19
build_rce20 = laravel.build_rce20
build_rce21 = laravel.build_rce21
build_rce22 = laravel.build_rce22
build_rce22_fast_destruct = laravel.build_rce22_fast_destruct
build_fd1 = laravel.build_fd1

# Legacy aliases used internally
_maybe_wrap = maybe_wrap
_wrap = wrap_fast_destruct

__all__ = [
    "NUL",
    "CHAINS",
    "GenerateOptions",
    "apply_ascii_strings",
    "apply_encoders",
    "apply_platform",
    "apply_plus_numbers",
    "apply_public_properties",
    "build_fd1",
    "build_phar",
    "build_phar_from_options",
    "build_phar_via_php",
    "build_rce1",
    "build_rce2",
    "build_rce3",
    "build_rce4",
    "build_rce5",
    "build_rce6",
    "build_rce7",
    "build_rce8",
    "build_rce9",
    "build_rce10",
    "build_rce11",
    "build_rce12",
    "build_rce13",
    "build_rce14",
    "build_rce15",
    "build_rce16",
    "build_rce17",
    "build_rce18",
    "build_rce19",
    "build_rce20",
    "build_rce21",
    "build_rce22",
    "build_rce22_fast_destruct",
    "finalize_fast_destruct",
    "generate",
    "generate_via_phpggc",
    "get_chain",
    "codeigniter4",
    "dompdf",
    "guzzle",
    "grav",
    "laminas",
    "laravel",
    "mediawiki",
    "list_chains",
    "locate_phpggc",
    "maybe_wrap",
    "monolog",
    "normalize_chain",
    "php_arr",
    "php_bool",
    "php_int",
    "php_null",
    "php_obj",
    "php_ref",
    "php_str",
    "priv",
    "prot",
    "pydio",
    "session_encode_via_php",
    "symfony",
    "to_bytes",
    "wordpress",
    "wrap_fast_destruct",
]

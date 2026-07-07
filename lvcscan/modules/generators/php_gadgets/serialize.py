"""PHP serialization primitives (byte-exact with phpggc output)."""
from __future__ import annotations

NUL = "\x00"


def php_str(s: str | bytes) -> str:
    if isinstance(s, bytes):
        s = s.decode("latin-1")
    return 's:%d:"%s";' % (len(s.encode("latin-1")), s)


def php_int(n: int) -> str:
    return f"i:{n};"


def php_null() -> str:
    return "N;"


def php_bool(v: bool) -> str:
    return "b:" + ("1" if v else "0") + ";"


def php_ref(n: int) -> str:
    return f"R:{n};"


def php_obj_ref(n: int) -> str:
    """Reference to an object (lowercase ``r:``, PHP 7+ object handles)."""
    return f"r:{n};"


def php_enum(enum_class: str, case: str) -> str:
    """PHP 8.1+ backed enum case (E:type:name)."""
    name = f"{enum_class}:{case}"
    return f'E:{len(name.encode("latin-1"))}:"{name}";'


def php_obj(classname: str, props: list[tuple[str, str]]) -> str:
    body = "".join(php_str(name) + value for name, value in props)
    return 'O:%d:"%s":%d:{%s}' % (len(classname.encode("latin-1")), classname, len(props), body)


def php_arr(pairs: list[tuple[str, str]]) -> str:
    return "a:%d:{%s}" % (len(pairs), "".join(k + v for k, v in pairs))


def php_empty_obj(classname: str) -> str:
    return 'O:%d:"%s":0:{}' % (len(classname.encode("latin-1")), classname)


def php_spl_iter(classname: str, flag: int, array: str, *, props: str = "a:0:{}", tail: str = "N") -> str:
    """ArrayObject / ArrayIterator internal layout (numeric keys 0–3).

    PHP omits semicolons between ``i:1``/``i:2`` values and the next numeric key.
    """
    cn_len = len(classname.encode("latin-1"))
    return f'O:{cn_len}:"{classname}":4:{{i:0;i:{flag};i:1;{array}i:2;{props}i:3;{tail};}}'


def php_custom(classname: str, inner: str) -> str:
    """PHP ``Serializable`` / ``__serialize`` custom object format (``C:``)."""
    inner_b = inner.encode("latin-1")
    cn_len = len(classname.encode("latin-1"))
    return f'C:{cn_len}:"{classname}":{len(inner_b)}:{{{inner}}}'


def php_datetime_immutable(date: str, *, tz_type: int = 3, timezone: str = "UTC") -> str:
    return php_obj("DateTimeImmutable", [
        ("date", php_str(date)),
        ("timezone_type", php_int(tz_type)),
        ("timezone", php_str(timezone)),
    ])


def prot(name: str) -> str:
    return NUL + "*" + NUL + name


def priv(cls: str, name: str) -> str:
    return NUL + cls + NUL + name


def to_bytes(serialized: str) -> bytes:
    return serialized.encode("latin-1")

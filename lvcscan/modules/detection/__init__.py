"""Detection modules plus compatibility aliases for unified CVE modules."""

from __future__ import annotations

import sys
from importlib import import_module

from modules.cves.metadata import CVE_METADATA, all_slugs


def _module_for_slug(slug: str) -> str:
    for meta in CVE_METADATA.values():
        if meta.slug == slug:
            return meta.module
    raise KeyError(slug)


def _install_legacy_aliases() -> None:
    for slug in all_slugs():
        sys.modules.setdefault(f"{__name__}.{slug}", import_module(_module_for_slug(slug)))


_install_legacy_aliases()


def __getattr__(name: str):
    if name in all_slugs():
        return import_module(_module_for_slug(name))
    raise AttributeError(name)


__all__ = list(all_slugs())

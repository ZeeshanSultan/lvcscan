"""Phase 6 — CSRF meta extraction must be attribute-order independent."""

import types

from modules.helpers import livewire_upload as lw


class _NoCookies:
    cookies = types.SimpleNamespace(get=lambda *a, **k: None)


def test_name_before_content():
    body = '<meta name="csrf-token" content="TOK123">'
    assert lw.resolve_csrf(_NoCookies(), body) == ("X-CSRF-TOKEN", "TOK123", "TOK123")


def test_content_before_name():
    body = '<meta content="TOK456" name="csrf-token">'
    assert lw.resolve_csrf(_NoCookies(), body) == ("X-CSRF-TOKEN", "TOK456", "TOK456")


def test_extra_attributes_and_newlines():
    body = '<meta\n  charset="utf-8"\n  content="TOK789"\n  name="csrf-token"\n  data-x="1">'
    assert lw.resolve_csrf(_NoCookies(), body) == ("X-CSRF-TOKEN", "TOK789", "TOK789")

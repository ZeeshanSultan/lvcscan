"""Phase 0.1 — request-classification safety-tier model in http_config.

The default authorized ceiling is PASSIVE: GET/HEAD/OPTIONS pass, every mutating
method (and any block that declares a higher tier) is BLOCKED with RequestBlocked
until the operator raises the ceiling (--allow-active / --allow-destructive, or the
exploit pipeline). Nothing is deleted — the traffic is gated, not removed.
"""

import threading

import pytest

from modules.core import http_config as hc


@pytest.fixture(autouse=True)
def _reset_tier():
    """Every test starts from the default ceiling and no declared tier."""
    hc.set_authorized_tier(hc.PASSIVE)
    hc._tier_ctx.value = None
    yield
    hc.set_authorized_tier(hc.PASSIVE)
    hc._tier_ctx.value = None


def test_default_authorized_tier_is_passive():
    assert hc.get_authorized_tier() == hc.PASSIVE


def test_tier_rank_orders_passive_active_destructive():
    assert hc._TIER_RANK[hc.PASSIVE] < hc._TIER_RANK[hc.ACTIVE] < hc._TIER_RANK[hc.DESTRUCTIVE]


def test_method_tier_maps_reads_passive_writes_active():
    for m in ("GET", "HEAD", "OPTIONS", "get", "head"):
        assert hc._method_tier(m) == hc.PASSIVE
    for m in ("POST", "PUT", "PATCH", "DELETE", "post"):
        assert hc._method_tier(m) == hc.ACTIVE


def test_request_tier_sets_and_restores_declared_tier():
    assert hc.declared_tier() == hc.PASSIVE
    with hc.request_tier(hc.DESTRUCTIVE):
        assert hc.declared_tier() == hc.DESTRUCTIVE
    assert hc.declared_tier() == hc.PASSIVE


def test_request_tier_restores_on_exception():
    with pytest.raises(ValueError):
        with hc.request_tier(hc.ACTIVE):
            raise ValueError("boom")
    assert hc.declared_tier() == hc.PASSIVE


def test_guard_nonhttp_blocks_active_under_passive_ceiling():
    with pytest.raises(hc.RequestBlocked):
        hc.guard_nonhttp(hc.ACTIVE, "127.0.0.1:6379")


def test_guard_nonhttp_allows_when_ceiling_raised():
    hc.set_authorized_tier(hc.ACTIVE)
    # Should not raise.
    hc.guard_nonhttp(hc.ACTIVE, "127.0.0.1:6379")


def test_patched_post_blocked_under_passive(monkeypatch):
    """A POST through the patched Session raises before any socket work."""
    import requests

    called = {"orig": False}

    def _fake_orig(self, method, url, **kwargs):
        called["orig"] = True
        return "SENT"

    monkeypatch.setattr(hc, "_orig_session_request", _fake_orig)
    with pytest.raises(hc.RequestBlocked):
        requests.Session().post("http://example.invalid/register", json={"x": 1})
    assert called["orig"] is False  # never reached the network layer


def test_patched_get_allowed_under_passive(monkeypatch):
    import requests

    def _fake_orig(self, method, url, **kwargs):
        return "GET-OK"

    monkeypatch.setattr(hc, "_orig_session_request", _fake_orig)
    assert requests.Session().get("http://example.invalid/") == "GET-OK"


def test_patched_post_allowed_when_active_authorized(monkeypatch):
    import requests

    def _fake_orig(self, method, url, **kwargs):
        return "POST-OK"

    monkeypatch.setattr(hc, "_orig_session_request", _fake_orig)
    hc.set_authorized_tier(hc.ACTIVE)
    assert requests.Session().post("http://example.invalid/x") == "POST-OK"


def test_declared_destructive_get_blocked_under_active(monkeypatch):
    """Declared tier escalates a benign GET: a DESTRUCTIVE block needs the
    DESTRUCTIVE ceiling even if the underlying method is a read."""
    import requests

    def _fake_orig(self, method, url, **kwargs):
        return "OK"

    monkeypatch.setattr(hc, "_orig_session_request", _fake_orig)
    hc.set_authorized_tier(hc.ACTIVE)
    with hc.request_tier(hc.DESTRUCTIVE):
        with pytest.raises(hc.RequestBlocked):
            requests.Session().get("http://example.invalid/")


def test_authorized_tier_is_thread_local_for_declared_only(monkeypatch):
    """Declared tier must be per-thread so concurrent recon never cross-contaminates."""
    seen = {}

    def worker():
        seen["before"] = hc.declared_tier()
        with hc.request_tier(hc.ACTIVE):
            seen["inside"] = hc.declared_tier()

    hc._tier_ctx.value = hc.DESTRUCTIVE  # main thread declares destructive
    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert seen["before"] == hc.PASSIVE  # child thread unaffected by main's declaration
    assert seen["inside"] == hc.ACTIVE
    assert hc.declared_tier() == hc.DESTRUCTIVE  # main thread intact

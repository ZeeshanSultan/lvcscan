"""Phase 5 — time-based SQLi: multi-dialect coverage, active-gated, FP-resistant."""

import pytest

from modules.core import http_config as hc
from modules.detection import sqli_time_api as sq


@pytest.fixture(autouse=True)
def _reset_tier():
    hc.set_authorized_tier(hc.PASSIVE)
    yield
    hc.set_authorized_tier(hc.PASSIVE)


def test_covers_all_four_engines():
    dialects = {d for d, _ in sq._PAYLOAD_TEMPLATES}
    assert {"mysql", "postgres", "mssql", "sqlite"} <= dialects


def test_mysql_uses_sleep_not_only_mssql_waitfor():
    joined = " ".join(t for _, t in sq._PAYLOAD_TEMPLATES).lower()
    assert "sleep(" in joined         # MySQL/MariaDB
    assert "pg_sleep(" in joined      # PostgreSQL


def test_active_injection_blocked_under_passive():
    class _Sess:
        def get(self, *a, **k):
            raise AssertionError("should never reach the network under passive")

    with pytest.raises(hc.RequestBlocked):
        sq.scan("http://x.invalid", session=_Sess())


def test_timing_confirmation_rejects_uniformly_slow_endpoint():
    # Slow injection AND slow control (both ~6s over a 0.5 baseline) -> NOT a hit.
    assert sq._timing_confirms(0.5, 6.5, 6.4) is False


def test_timing_confirmation_accepts_scaling_delay():
    # sleep(5) slow, sleep(0) fast -> real time-based injection.
    assert sq._timing_confirms(0.5, 5.7, 0.6) is True

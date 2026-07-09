"""Phase 1.3 — the Reverb CVE's raw Redis PUBLISH bypasses the HTTP choke point,
so it must be gated explicitly. Under the default passive ceiling a scan must never
open a socket and write to the target's Redis; it needs --allow-active/--exploit.
"""

import pytest

from modules.core import http_config as hc
from modules.cves import cve_2026_23524 as reverb


@pytest.fixture(autouse=True)
def _reset_tier():
    hc.set_authorized_tier(hc.PASSIVE)
    yield
    hc.set_authorized_tier(hc.PASSIVE)


def test_redis_publish_blocked_under_passive_before_any_socket():
    # Port chosen so that, absent the gate, we'd see a connection error — proving the
    # RequestBlocked is raised BEFORE the socket work, not after a failed connect.
    with pytest.raises(hc.RequestBlocked):
        reverb._resp_publish("127.0.0.1", 6399, "reverb", "{}")


def test_redis_publish_allowed_under_active_reaches_socket():
    hc.set_authorized_tier(hc.ACTIVE)
    # Now the gate passes; the socket work runs and fails to connect (nothing listening).
    # The point: it is NOT a RequestBlocked — the operator authorized the write.
    with pytest.raises(Exception) as ei:
        reverb._resp_publish("127.0.0.1", 6399, "reverb", "{}")
    assert not isinstance(ei.value, hc.RequestBlocked)

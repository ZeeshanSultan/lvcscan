"""Phase 1.1 — mass-assignment writes create admins / overwrite balances: DESTRUCTIVE.
--allow-active alone must not fire them; only --allow-destructive / --force.
"""

import requests
import pytest

from modules.core import http_config as hc
from modules.detection import mass_assignment_checker as ma


@pytest.fixture(autouse=True)
def _reset_tier():
    hc.set_authorized_tier(hc.PASSIVE)
    yield
    hc.set_authorized_tier(hc.PASSIVE)


def test_write_blocked_under_active_ceiling():
    hc.set_authorized_tier(hc.ACTIVE)
    with pytest.raises(hc.RequestBlocked):
        ma.check_endpoint(requests.Session(), "http://x.invalid", "/register",
                          method="POST", payload={"is_admin": True})


def test_write_allowed_under_destructive_ceiling():
    hc.set_authorized_tier(hc.DESTRUCTIVE)
    # Gate passes; the write fails against the bogus host and is swallowed -> (None, None).
    res, status = ma.check_endpoint(requests.Session(), "http://x.invalid", "/register",
                                    method="POST", payload={"is_admin": True})
    assert res is None

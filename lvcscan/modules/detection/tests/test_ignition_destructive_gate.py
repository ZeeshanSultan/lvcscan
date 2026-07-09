"""Phase 1.4 — the Ignition RCE chain truncates and poisons the target's live log.
Those requests are POSTs (ACTIVE by method) but the ACT is destructive, so the chain
declares DESTRUCTIVE: it is blocked under the default and even under --allow-active,
and only runs with --force / --allow-destructive.
"""

import requests
import pytest

from modules.core import http_config as hc
from modules.cves import cve_2021_3129 as ign


@pytest.fixture(autouse=True)
def _reset_tier():
    hc.set_authorized_tier(hc.PASSIVE)
    yield
    hc.set_authorized_tier(hc.PASSIVE)


def test_chain_blocked_under_active_ceiling():
    hc.set_authorized_tier(hc.ACTIVE)  # e.g. plain --exploit
    with pytest.raises(hc.RequestBlocked):
        ign._run_chain(requests.Session(), "http://x.invalid/_ignition/execute-solution",
                       b"phar", pad_range=(96, 97))


def test_chain_allowed_under_destructive_ceiling():
    hc.set_authorized_tier(hc.DESTRUCTIVE)  # --force / --allow-destructive
    # Gate passes; the posts fail against the bogus host and are swallowed -> (False, ...).
    ok, _body, _pad = ign._run_chain(
        requests.Session(), "http://x.invalid/_ignition/execute-solution",
        b"phar", pad_range=(96, 97))
    assert ok is False

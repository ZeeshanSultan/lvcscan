"""Phase 1.2 — deserialization-POI is active/destructive, not passive.
Under the default passive ceiling the module must not inject; the cookie-stomp
(a GET that overwrites laravel_session) is DESTRUCTIVE despite the verb.
"""

import requests
import pytest

from modules.core import http_config as hc
from modules.detection import deserialization_poi as poi


@pytest.fixture(autouse=True)
def _reset_tier():
    hc.set_authorized_tier(hc.PASSIVE)
    yield
    hc.set_authorized_tier(hc.PASSIVE)


def test_post_injection_blocked_under_passive():
    with pytest.raises(hc.RequestBlocked):
        poi._test_post_injection("http://x.invalid/api/serialize", "O:1:\"x\":0:{}",
                                 requests.Session())


def test_cookie_stomp_blocked_under_active_ceiling():
    hc.set_authorized_tier(hc.ACTIVE)  # GET verb, but stomping a session is destructive
    with pytest.raises(hc.RequestBlocked):
        poi._test_cookie_injection("http://x.invalid/", "O:1:\"x\":0:{}",
                                   requests.Session())


def test_cookie_stomp_allowed_under_destructive():
    hc.set_authorized_tier(hc.DESTRUCTIVE)
    # Gate passes; network failure swallowed -> None (no RequestBlocked).
    assert poi._test_cookie_injection("http://x.invalid/", "O:1:\"x\":0:{}",
                                      requests.Session()) is None

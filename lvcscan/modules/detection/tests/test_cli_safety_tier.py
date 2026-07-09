"""Phase 0.1 wiring — CLI flags map to the authorized ceiling, and a tier-blocked
detector is rendered as a first-class 'blocked_by_policy' verdict, not a crash.
"""

import types

import pytest

import check
from modules.core import http_config as hc
from modules.helpers.pipeline import detection_verdict, is_confirmed_detection


def _args(**kw):
    base = dict(allow_active=False, allow_destructive=False, exploit=False, force=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_default_args_authorize_passive():
    assert check._authorized_tier_from_args(_args()) == hc.PASSIVE


def test_allow_active_flag_authorizes_active():
    assert check._authorized_tier_from_args(_args(allow_active=True)) == hc.ACTIVE


def test_allow_destructive_flag_authorizes_destructive():
    assert check._authorized_tier_from_args(_args(allow_destructive=True)) == hc.DESTRUCTIVE


def test_exploit_raises_ceiling_to_active():
    assert check._authorized_tier_from_args(_args(exploit=True)) == hc.ACTIVE


def test_force_raises_ceiling_to_destructive():
    assert check._authorized_tier_from_args(_args(force=True)) == hc.DESTRUCTIVE


def test_blocked_verdict_is_first_class_and_not_a_hit():
    assert detection_verdict({"verdict": "blocked_by_policy"}) == "blocked_by_policy"
    assert not is_confirmed_detection("blocked_by_policy")


def test_safe_scan_renders_tier_block_as_policy_verdict():
    def blocking_detector(*a, **k):
        raise hc.RequestBlocked(hc.ACTIVE, hc.PASSIVE, "POST /register")

    res = check._safe_scan("mass_assignment", blocking_detector, "http://x")
    assert isinstance(res, dict)
    assert res.get("verdict") == "blocked_by_policy"
    assert res.get("vulnerable") is False

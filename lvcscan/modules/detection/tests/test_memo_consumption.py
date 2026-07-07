#!/usr/bin/env python3
"""Proves cve_2021_28254 CONSUMES the within-run Response memo for /composer.lock.

Discovery (detect_laravel._composer_version_signals) seeds the in-hand /composer.lock
Response into the shared memo with a faithful composite key:
    memo_key("GET", app_url(base, "/composer.lock"), allow_redirects=True,
             headers={}, auth=_run_auth_label())
This test seeds an equivalent snapshot and proves the detector READS it instead of
re-fetching (a real cache hit + a request saved), and that on a MISS it falls through
to the real HTTP fetch byte-identically.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from modules.core import http_config
from modules.probes.response_memo import get_run_memo, reset_run_memo, memo_key, ResponseSnapshot
from modules.cves import cve_2021_28254


COMPOSER_BODY = b'{"packages":[{"name":"laravel/framework","version":"v8.4.0"}]}'


class FakeResp:
    def __init__(self, status=404, text="", content=b""):
        self.status_code = status
        self.text = text
        self.content = content
        self.headers = {}

    @property
    def ok(self):
        return 200 <= self.status_code < 400


class FakeSession:
    """Every GET 404s. composer.lock GETs are counted so we can prove a memo hit
    short-circuits the fetch (count stays 0)."""

    def __init__(self):
        self.composer_fetches = 0

    def get(self, url, **k):
        if "composer.lock" in url:
            self.composer_fetches += 1
        return FakeResp(404, "")

    def post(self, url, **k):
        return FakeResp(404, "")


def _seed_composer(base, auth):
    key = memo_key("GET", http_config.app_url(base, "/composer.lock"),
                   allow_redirects=True, headers={}, auth=auth)
    get_run_memo().put(key, ResponseSnapshot(status=200,
                                             headers={"Content-Type": "application/json"},
                                             body=COMPOSER_BODY))


def test_consumer_hits_seeded_composer_lock(monkeypatch):
    # Pin auth-context so the consumer's key matches the seed regardless of suite-wide
    # header pollution (has_extra_headers() reads a process-global).
    monkeypatch.setattr(http_config, "has_extra_headers", lambda: False)
    reset_run_memo()
    base = "https://t"
    _seed_composer(base, auth="anon")

    sess = FakeSession()
    result = cve_2021_28254.scan(base, session=sess)

    # HIT: composer.lock was served from the memo, so the HTTP fetch was never taken.
    assert sess.composer_fetches == 0, "memo hit must avoid the composer.lock fetch"
    # And the version was parsed from the seeded body, identically to a real fetch.
    assert result["version"] == "8.4.0"
    assert "composer_lock" in result["detection_methods"]


def test_consumer_honors_non200_hit_without_refetch(monkeypatch):
    # Discovery seeds non-200 composer.lock responses too (it put()s before its status
    # check), so a seeded 404 — the common production case — must NOT trigger a re-fetch.
    monkeypatch.setattr(http_config, "has_extra_headers", lambda: False)
    reset_run_memo()
    base = "https://t"
    key = memo_key("GET", http_config.app_url(base, "/composer.lock"),
                   allow_redirects=True, headers={}, auth="anon")
    get_run_memo().put(key, ResponseSnapshot(status=404, headers={}, body=b""))

    sess = FakeSession()
    result = cve_2021_28254.scan(base, session=sess)

    # HIT (non-200): fetch avoided, and no version parsed (same as a real 404 fetch).
    assert sess.composer_fetches == 0, "any memo hit must avoid the composer.lock fetch"
    assert result["version"] is None
    assert "composer_lock" not in result["detection_methods"]


def test_consumer_falls_through_on_miss(monkeypatch):
    monkeypatch.setattr(http_config, "has_extra_headers", lambda: False)
    reset_run_memo()  # empty memo -> miss
    base = "https://t"

    sess = FakeSession()
    cve_2021_28254.scan(base, session=sess)

    # MISS: no seed, so the detector falls through to the real HTTP fetch (count > 0).
    assert sess.composer_fetches == 1, "a memo miss must fall through to the real fetch"

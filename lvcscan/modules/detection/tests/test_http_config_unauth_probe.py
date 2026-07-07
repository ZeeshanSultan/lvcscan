"""Tests for the opt-in unauth-probe helper http_config.unauth_get.

The helper must route through the FULL Session patch (so request stats, proxy
injection, TLS verify resolution, and --trace-http are all preserved) while
surgically skipping ONLY the _extra_headers injection block via a per-request
`no_auth=True` kwarg. The bypass is opt-in per call: a normal sess.get() that
does NOT pass no_auth must still receive the global -H auth injection.

All tests mock at the requests layer (no live network) and use monkeypatch for
every module global they touch so the process-wide patch state is restored and
the rest of modules/detection/tests/ is not corrupted.
"""

import os
import sys

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ),
)

import requests  # noqa: E402

from modules.core import http_config  # noqa: E402


class _Sentinel:
    """Stand-in return value so we can confirm unauth_get returns the response."""


def _install_capture(monkeypatch):
    """Replace _orig_session_request with a capture fn; return the captured-list.

    The patched closure reads _orig_session_request as a module global, so
    monkeypatching it here is honored at call time. Captures each call's kwargs.
    """
    captured = []

    def _fake_orig(self, method, url, **kwargs):
        captured.append({"method": method, "url": url, "kwargs": kwargs})
        return _Sentinel()

    monkeypatch.setattr(http_config, "_orig_session_request", _fake_orig)
    return captured


def test_unauth_get_skips_extra_headers_injection(monkeypatch):
    # Operator supplied a -H Cookie that normally gets force-injected everywhere.
    monkeypatch.setattr(http_config, "_extra_headers", {"Cookie": "operator=SECRET"})
    captured = _install_capture(monkeypatch)

    resp = http_config.unauth_get("https://target/login")

    assert isinstance(resp, _Sentinel)
    assert len(captured) == 1
    sent_headers = captured[0]["kwargs"].get("headers") or {}
    # The operator's auth Cookie must NOT have been injected on the unauth probe.
    assert "Cookie" not in sent_headers
    assert "operator=SECRET" not in (sent_headers.get("Cookie") or "")
    # X-XSRF-TOKEN promotion must also be skipped.
    assert not any(k.lower() == "x-xsrf-token" for k in sent_headers)


def test_unauth_get_is_opt_in_normal_get_still_injects(monkeypatch):
    """CONTRAST/regression guard: a normal sess.get() with no_auth absent still
    gets the global -H auth injection. Proves the bypass is surgical and the
    global auth-forcing path for all other detectors is untouched.
    """
    monkeypatch.setattr(http_config, "_extra_headers", {"Cookie": "operator=SECRET"})
    captured = _install_capture(monkeypatch)

    # Normal authenticated request through the global patch (no no_auth kwarg).
    requests.Session().get("https://target/login")

    assert len(captured) == 1
    sent_headers = captured[0]["kwargs"].get("headers") or {}
    assert sent_headers.get("Cookie") == "operator=SECRET"


def test_unauth_get_still_applies_proxy_and_verify(monkeypatch):
    monkeypatch.setattr(http_config, "_extra_headers", {})
    monkeypatch.setattr(
        http_config, "_proxies", {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    )
    monkeypatch.setattr(http_config, "_verify_default", False)
    captured = _install_capture(monkeypatch)

    http_config.unauth_get("https://target/x")

    assert len(captured) == 1
    kw = captured[0]["kwargs"]
    # Proxy injection (patch responsibility) preserved.
    assert kw.get("proxies") == {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    }
    # TLS verify resolution preserved.
    assert kw.get("verify") is False


def test_unauth_get_passes_through_cookies_and_allow_redirects(monkeypatch):
    monkeypatch.setattr(http_config, "_extra_headers", {})
    captured = _install_capture(monkeypatch)

    http_config.unauth_get(
        "https://target/x",
        cookies={"session_language_v2": "CANARY"},
        allow_redirects=False,
        timeout=10,
    )

    assert len(captured) == 1
    kw = captured[0]["kwargs"]
    assert kw.get("cookies") == {"session_language_v2": "CANARY"}
    assert kw.get("allow_redirects") is False
    assert kw.get("timeout") == 10


def test_unauth_get_increments_request_stats(monkeypatch):
    """Validates the design's central claim: routing through the full patch
    preserves request costing. Catches a future regression to calling the
    unpatched _orig_session_request directly.
    """
    monkeypatch.setattr(http_config, "_extra_headers", {})
    _install_capture(monkeypatch)
    monkeypatch.setattr(
        http_config, "_request_stats", {"total": 0, "module": {}}
    )

    before = http_config.get_request_stats()["total"]
    http_config.unauth_get("https://target/x")
    after = http_config.get_request_stats()["total"]
    assert after == before + 1

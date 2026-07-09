"""Phase 7 — a single hung DNS resolver must not stall enumeration. The old
fut.result(timeout=) inside as_completed() was a no-op and the pool joined every
worker on exit, so one stuck getaddrinfo hung the whole run.
"""

import threading
import time

import pytest

from modules.recon import subdomain_enum as se


def test_hung_resolver_does_not_stall_run():
    release = threading.Event()

    def resolver(host):
        # One label hangs "forever"; the rest resolve instantly.
        if host.startswith("hang."):
            release.wait(timeout=30)  # released in finally so the thread can exit
            return set()
        if host.startswith("www."):
            return {"93.184.216.34"}
        return set()

    try:
        start = time.time()
        res = se.enumerate_subdomains(
            "example.com",
            use_crtsh=False,
            http_probe=None,
            resolver=resolver,
            resolve_timeout=0.2,          # small -> small global budget
            extra_labels=["www", "hang"],
            wordlist=_empty_wordlist(),
            threads=4,
        )
        elapsed = time.time() - start
        assert elapsed < 15, f"run stalled for {elapsed:.1f}s on a hung resolver"
        assert res["ok"] is True
        hosts = {s["host"] for s in res["subdomains"]}
        assert "www.example.com" in hosts       # fast host still found
        assert "hang.example.com" not in hosts   # hung host excluded, not blocking
    finally:
        release.set()


def _empty_wordlist():
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    f.write("")
    f.close()
    return f.name

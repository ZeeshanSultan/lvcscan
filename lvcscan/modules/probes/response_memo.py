#!/usr/bin/env python3
"""Within-run Response memo (OPT-IN read-through, GET-only).

Eliminates discovery<->detector double-fetches for the GET-path exposure family by letting
discovery seed Responses that an exposure detector can consult instead of re-fetching.

NOT a global request hook: data enters ONLY via put(), is read ONLY via get(). A miss returns
None and the caller falls through to a real fetch (never assume-absent). The composite key
captures every dimension an exposure detector varies on (method, url, redirect-policy, the
injected-header set, auth-context) so a hit is byte-identical to the consumer's own fetch.

Imports stdlib only (modules.probes layer rule — no detection/exploitation/check imports).
"""
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ResponseSnapshot:
    status: int
    headers: Dict[str, str]
    body: bytes


def _norm_headers(headers: Optional[Dict[str, str]]) -> str:
    # Only the injected-header SET matters for cache identity; sort for stability, lowercase keys.
    if not headers:
        return ""
    items = sorted((str(k).lower(), str(v)) for k, v in headers.items())
    return "|".join(f"{k}={v}" for k, v in items)


def memo_key(method: str, url: str, allow_redirects: bool, headers: Optional[Dict[str, str]], auth: str) -> str:
    """Composite key. method+url+redirect-policy+injected-header-set+auth-context, hashed.
    The method is preserved in the key so GET-only enforcement at put() can inspect it."""
    raw = "\x00".join([
        method.upper(),
        url,
        "R1" if allow_redirects else "R0",
        _norm_headers(headers),
        str(auth or ""),
    ])
    digest = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()
    # prefix with method so put() can enforce GET-only without re-parsing
    return f"{method.upper()}:{digest}"


class ResponseMemo:
    """In-memory, within-run only. No eviction needed (one scan's lifetime)."""
    def __init__(self) -> None:
        self._store: Dict[str, ResponseSnapshot] = {}

    def put(self, key: str, snapshot: ResponseSnapshot) -> bool:
        # GET-only: POST/PUT bodies vary and must never be served from cache.
        if not key.startswith("GET:"):
            return False
        self._store[key] = snapshot
        return True

    def get(self, key: str) -> Optional[ResponseSnapshot]:
        return self._store.get(key)  # miss -> None, caller falls through (never assume-absent)


# ---------------------------------------------------------------------------
# Shared within-run singleton. Discovery seeds into it via put(); an opt-in
# exposure detector reads from it via get(). reset_run_memo() is called between
# scans (one run's lifetime) so seeds never leak across targets.
# ---------------------------------------------------------------------------
_RUN_MEMO = ResponseMemo()


def get_run_memo() -> ResponseMemo:
    return _RUN_MEMO


def reset_run_memo() -> None:
    global _RUN_MEMO
    _RUN_MEMO = ResponseMemo()

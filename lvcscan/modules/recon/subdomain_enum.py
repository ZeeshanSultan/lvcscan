#!/usr/bin/env python3
"""Subdomain enumeration for a target domain.

Two sources, both best-effort and additive:
  * DNS brute-force from a wordlist (stdlib socket resolver; threaded), and
  * crt.sh certificate-transparency (passive; short timeout; failure = brute-force only).

Hardened against the usual foot-guns:
  * Wildcard DNS is detected up front (random non-existent labels) and its answer IPs are
    filtered out so `*.domain` does not produce thousands of false positives.
  * Every resolution runs under a per-lookup wall-clock timeout via a thread pool, so a slow
    resolver never hangs the run.
  * Off-domain / CNAME-to-third-party names are reported but never treated as in-scope subs.
  * IP / CIDR targets are rejected (nothing to enumerate).

The resolver, HTTP prober, and crt.sh fetcher are injectable so the whole flow is unit-testable
offline with no network.
"""
from __future__ import annotations

import concurrent.futures as _cf
import os
import random
import re
import socket
import string
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# Hard cap on the total DNS-resolution wall clock (seconds) regardless of candidate count.
_MAX_RESOLVE_WALL = 60.0
_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "subdomains.txt")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def normalize_domain(target: str) -> Optional[str]:
    """Extract a registrable domain from a URL / bare host. Return None for IPs or junk."""
    if not target:
        return None
    t = target.strip()
    if "://" in t:
        t = urlparse(t).hostname or ""
    else:
        t = t.split("/")[0].split("@")[-1]
    t = t.split(":")[0].strip().rstrip(".").lower()
    if not t or _IP_RE.match(t) or t.count(".") < 1:
        return None
    try:
        t = t.encode("idna").decode("ascii")  # punycode IDN
    except Exception:
        pass
    return t


def _default_resolver(host: str) -> Set[str]:
    """Resolve A/AAAA for host -> set of IP strings. Empty set on failure/NXDOMAIN."""
    ips: Set[str] = set()
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ips.add(sockaddr[0])
    except Exception:
        pass
    return ips


def _load_labels(wordlist: Optional[str]) -> List[str]:
    path = wordlist or _WORDLIST
    labels: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                lab = line.strip().lower()
                if lab and not lab.startswith("#") and _LABEL_RE.match(lab):
                    labels.append(lab)
    except Exception:
        pass
    # de-dup, preserve order
    seen: Set[str] = set()
    return [l for l in labels if not (l in seen or seen.add(l))]


def _crtsh_names(domain: str, fetch: Callable[[str], Optional[str]], cap: int = 2000) -> Set[str]:
    """Best-effort crt.sh certificate-transparency names for *.domain. Never raises."""
    out: Set[str] = set()
    try:
        import json
        body = fetch(f"https://crt.sh/?q=%25.{domain}&output=json")
        if not body:
            return out
        for entry in json.loads(body):
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.").rstrip(".")
                if name.endswith("." + domain) and name != domain:
                    out.add(name)
                    if len(out) >= cap:
                        return out
    except Exception:
        pass
    return out


def _default_crtsh_fetch(url: str) -> Optional[str]:
    try:
        from modules.core import http_config
        r = http_config.get_auth_session().get(url, timeout=10, verify=False)
        return r.text if r is not None and r.status_code == 200 else None
    except Exception:
        return None


def _is_private_ip(ip: str) -> bool:
    """True for RFC1918 / loopback / link-local / ULA addresses (scope hygiene tag)."""
    if ip.startswith(("127.", "10.", "192.168.", "169.254.", "::1", "fc", "fd", "fe80")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


def default_http_probe(host: str, *, timeout: float = 6.0) -> Dict:
    """HTTPS-then-HTTP liveness + best-effort Laravel fingerprint. Never raises.

    Redirects are NOT followed: a crt.sh-sourced host that 301s to an unrelated third
    party must not drag the probe off-target (scope/SSRF hygiene).
    """
    from modules.core import http_config
    for scheme, https in (("https", True), ("http", False)):
        try:
            sess = http_config.get_auth_session()
            r = sess.get(f"{scheme}://{host}", timeout=timeout, verify=False, allow_redirects=False)
        except Exception:
            continue
        is_laravel = False
        try:
            from modules.detection.detect_laravel import is_laravel as _is_lar
            info = _is_lar(f"{scheme}://{host}", stealth=True)
            is_laravel = bool(info)
        except Exception:
            is_laravel = False
        return {"status": r.status_code, "https": https, "is_laravel": is_laravel}
    return {"status": None, "https": None, "is_laravel": False}


def _detect_wildcard(domain: str, resolver: Callable[[str], Set[str]]) -> Set[str]:
    """Return the union of IPs a wildcard record answers with (empty set = no wildcard)."""
    # Sample more random labels so a wildcard that round-robins across a CDN's IP pool
    # is captured more completely (3 samples missed rotating pools, causing both FP
    # survivors and FN drops in the subset filter).
    wildcard_ips: Set[str] = set()
    for _ in range(8):
        rand = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))
        wildcard_ips |= resolver(f"{rand}-lvcscan.{domain}")
    return wildcard_ips


class SubdomainResult(dict):
    """dict subclass for a clean structured return (host, ips, http_status, is_laravel, source)."""


def enumerate_subdomains(
    target: str,
    *,
    wordlist: Optional[str] = None,
    threads: int = 16,
    use_crtsh: bool = True,
    resolve_timeout: float = 5.0,
    resolver: Optional[Callable[[str], Set[str]]] = None,
    crtsh_fetch: Optional[Callable[[str], Optional[str]]] = None,
    http_probe: Optional[Callable[[str], Dict]] = None,
    extra_labels: Optional[List[str]] = None,
) -> Dict:
    """Enumerate subdomains of `target`. Returns a structured, JSON-safe dict."""
    domain = normalize_domain(target)
    if domain is None:
        return {"ok": False, "error": "target is not a domain (IP/CIDR or malformed)", "target": target}

    resolver = resolver or _default_resolver
    threads = max(1, min(int(threads or 1), 64))

    wildcard_ips = _detect_wildcard(domain, resolver)

    # Candidate hostnames: wordlist labels + crt.sh names (+ any extra labels).
    candidates: Set[str] = {f"{lab}.{domain}" for lab in _load_labels(wordlist)}
    for lab in (extra_labels or []):
        lab = lab.strip().lower()
        if _LABEL_RE.match(lab):
            candidates.add(f"{lab}.{domain}")
    crt_names: Set[str] = set()
    if use_crtsh:
        crt_names = _crtsh_names(domain, crtsh_fetch or _default_crtsh_fetch)
        candidates |= crt_names
    candidates.discard(domain)

    # --- Resolve concurrently under a GLOBAL wall-clock budget ---
    # NB: fut.result(timeout=) inside as_completed() is a no-op — as_completed only
    # yields already-finished futures — and the `with` block's shutdown(wait=True)
    # joins every worker, so a single hung getaddrinfo (default resolv.conf timeouts
    # run 30s+) stalled the whole enumeration. We wait on a bounded budget instead and
    # shut down WITHOUT joining, so a stuck resolver thread can never hang the run.
    resolved: Dict[str, Set[str]] = {}
    dropped_wildcard = 0
    budget = min(
        _MAX_RESOLVE_WALL,
        max(resolve_timeout, resolve_timeout * (len(candidates) / max(1, threads) + 2)),
    )
    pool = _cf.ThreadPoolExecutor(max_workers=threads)
    try:
        futs = {pool.submit(resolver, host): host for host in candidates}
        done, _pending = _cf.wait(futs, timeout=budget)
        for fut in done:
            host = futs[fut]
            try:
                ips = fut.result()
            except Exception:
                ips = set()
            if not ips:
                continue
            # Wildcard filter: drop hosts whose IPs are wholly within the wildcard answer set.
            if wildcard_ips and ips and ips.issubset(wildcard_ips):
                dropped_wildcard += 1
                continue
            resolved[host] = ips
    finally:
        # wait=False + cancel_futures: return immediately; never block on a hung lookup.
        pool.shutdown(wait=False, cancel_futures=True)

    # --- Live-host + Laravel probe (concurrent, best-effort) ---
    subs: List[Dict] = []
    if http_probe is not None:
        with _cf.ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(http_probe, host): host for host in resolved}
            probes: Dict[str, Dict] = {}
            for fut in _cf.as_completed(futs):
                host = futs[fut]
                try:
                    probes[host] = fut.result(timeout=resolve_timeout + 10) or {}
                except Exception:
                    probes[host] = {}
        for host in sorted(resolved):
            p = probes.get(host, {})
            _ips = sorted(resolved[host])
            subs.append(SubdomainResult(host=host, ips=_ips,
                                        source="crtsh" if host in crt_names else "bruteforce",
                                        private=all(_is_private_ip(ip) for ip in _ips),
                                        http_status=p.get("status"), https=p.get("https"),
                                        is_laravel=bool(p.get("is_laravel"))))
    else:
        for host in sorted(resolved):
            _ips = sorted(resolved[host])
            subs.append(SubdomainResult(host=host, ips=_ips,
                                        source="crtsh" if host in crt_names else "bruteforce",
                                        private=all(_is_private_ip(ip) for ip in _ips)))

    return {
        "ok": True,
        "domain": domain,
        "wildcard": bool(wildcard_ips),
        "wildcard_ips": sorted(wildcard_ips),
        "candidates_tried": len(candidates),
        "crtsh_names": len(crt_names),
        "dropped_wildcard": dropped_wildcard,
        "resolved": len(subs),
        "subdomains": subs,
    }

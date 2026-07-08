"""
Central HTTP configuration for check.py and all scanner modules.

When configure() is called with a proxy URL, every requests call (get/post/Session)
is patched to route through that proxy and default verify=False for intercepted TLS.
Request logging is OFF by default; pass --trace-http to enable. Every enabled request
prints:
  [HTTP] [module] METHOD URL
to stdout. Use --no-trace for backward compatibility (no-op, logging is already off).
"""

from __future__ import annotations

import copy
import base64
import http.client
import inspect
import os
import ssl
import threading
from typing import Dict, Optional
from urllib.parse import unquote, urljoin, urlparse

import requests

# Typical local intercepting proxy (Burp, mitmproxy, etc.)
DEFAULT_PROXY = "http://127.0.0.1:8080"

# Single source of truth for the outgoing User-Agent. Every module sends this real
# browser UA so the scanner blends in with ordinary traffic instead of advertising
# itself. The scan's identity (and, where relevant, the CVE under test) is carried
# in the X-lvcscan request header instead — see modules that set X-lvcscan: CVE-….
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

_proxies: Optional[Dict[str, str]] = None
_verify_default: Optional[bool] = None  # None = leave requests library default per call
_trace_http = False  # OFF by default; --trace-http sets this True
# Active-module label is THREAD-LOCAL: a threaded detect phase (--threads N) attributes each
# worker's requests to its own module instead of racing a single global. Off-thread -> None.
_active_module_tls = threading.local()
_extra_headers: Dict[str, str] = {}  # user-supplied -H headers, injected into every request
_patched = False
_orig_session_request = None
_stats_lock = threading.Lock()  # guards _request_stats under concurrent detect
_request_stats = {
    "total": 0,
    "module": {},
}


def _get_active_module() -> Optional[str]:
    """Current thread's active-module label (None if unset on this thread)."""
    return getattr(_active_module_tls, "value", None)


def disable_trace() -> None:
    """Suppress per-request logging (--no-trace). Idempotent."""
    global _trace_http
    _trace_http = False


def enable_trace() -> None:
    """Enable per-request [HTTP] logging (--trace-http). Idempotent."""
    global _trace_http
    _trace_http = True


def configure(
    proxy: Optional[str] = None,
    *,
    verify: Optional[bool] = None,
    trace_http: bool = False,
    headers: Optional[Dict[str, str]] = None,
) -> None:
    """Apply proxy/TLS/trace/header settings process-wide for all modules."""
    global _proxies, _verify_default, _trace_http, _extra_headers

    _trace_http = trace_http
    if headers:
        # User -H headers win over module defaults (so auth Cookie/Authorization
        # forces authenticated scanning). Merge so repeated configure() calls accumulate.
        _extra_headers = {**_extra_headers, **headers}
    if proxy:
        proxy = proxy.strip()
        _proxies = {"http": proxy, "https": proxy}
        # Mirror into env so any code that reads HTTP(S)_PROXY directly still works.
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            os.environ[key] = proxy
        # Intercepting proxies use a custom CA; modules mostly pass verify=False already.
        if verify is None:
            _verify_default = False
        else:
            _verify_default = verify
    else:
        _proxies = None
        if verify is not None:
            _verify_default = verify

    _install_patch()


def clear_proxy_env() -> None:
    """Remove proxy env vars (e.g. when disabling proxy)."""
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
        os.environ.pop(key, None)


def set_active_module(name: Optional[str]) -> None:
    """Label the next HTTP trace lines (check.py sets this per CVE/module).

    Thread-local: safe to call from concurrent detect workers without cross-attribution.
    """
    _active_module_tls.value = name


def reset_request_stats() -> None:
    """Reset request counters used for probe/detect/exploit costing."""
    global _request_stats
    with _stats_lock:
        _request_stats = {"total": 0, "module": {}}


def get_request_stats() -> Dict[str, object]:
    """Return a snapshot of request counters.

    The counters are process-local and include:
      - total: total number of HTTP requests sent through this patch
      - module: per-module call counts (keyed by module label)

    The returned object is a deep copy so callers can safely calculate deltas.
    """
    with _stats_lock:
        return copy.deepcopy(_request_stats)


def _record_request_stats() -> None:
    mod = _guess_caller_module()
    with _stats_lock:
        _request_stats["total"] += 1
        _request_stats["module"][mod] = _request_stats["module"].get(mod, 0) + 1


def record_manual_request(method: str, url: str) -> None:
    """Record/trace a request sent outside the patched requests.Session path.

    A few modules intentionally use lower-level transports when exact request-target bytes matter.
    Calling this keeps the request budget and --trace-http output aligned with that traffic.
    """
    _record_request_stats()
    if _trace_http:
        mod = _guess_caller_module()
        print(f"[HTTP] [{mod}] {method.upper()} {url}", flush=True)


def get_proxies() -> Optional[Dict[str, str]]:
    return _proxies.copy() if _proxies else None


def _proxy_auth_header(proxy) -> Optional[str]:
    if proxy.username is None:
        return None
    username = unquote(proxy.username)
    password = unquote(proxy.password or "")
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def _merge_manual_headers(headers: Optional[Dict[str, str]], *, no_auth: bool = False) -> Dict[str, str]:
    merged = dict(headers or {})
    if _extra_headers and not no_auth:
        merged.update(_extra_headers)
        if not any(k.lower() == "x-xsrf-token" for k in merged):
            cookie_val = next((v for k, v in _extra_headers.items() if k.lower() == "cookie"), "")
            xsrf = _xsrf_token_from_cookie(cookie_val)
            if xsrf:
                merged["X-XSRF-TOKEN"] = xsrf
    return merged


def raw_http_request(
    method: str,
    endpoint_url: str,
    *,
    raw_query: Optional[str] = None,
    body: Optional[bytes | str] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 15,
    no_auth: bool = False,
) -> tuple[int, str, Dict[str, str]]:
    """Send one HTTP request while preserving caller-supplied path/query bytes.

    Use this only when `requests` would normalize data that a probe intentionally needs to send
    verbatim. It still honors global proxy settings, -H header injection, request accounting,
    and --trace-http so lower-level transports do not bypass operator visibility.
    """
    parsed = urlparse(endpoint_url)
    scheme = parsed.scheme or "http"
    if scheme not in {"http", "https"}:
        raise ValueError(f"raw_http_request only supports http/https URLs: {endpoint_url!r}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"invalid endpoint URL: {endpoint_url!r}")

    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    if raw_query:
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}{raw_query}"

    display_url = f"{scheme}://{parsed.netloc}{path}"
    record_manual_request(method, display_url)

    request_headers = {
        "Host": parsed.netloc,
        "User-Agent": BROWSER_USER_AGENT,
        "Connection": "close",
    }
    request_headers.update(_merge_manual_headers(headers, no_auth=no_auth))

    proxies = get_proxies()
    proxy_url = (proxies or {}).get(scheme) or (proxies or {}).get("http")
    ctx = None
    if scheme == "https" or proxy_url:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if proxy_url:
        proxy = urlparse(proxy_url)
        if proxy.scheme not in {"http", "https"}:
            raise ValueError(f"raw_http_request only supports http/https proxies: {proxy_url!r}")
        proxy_host = proxy.hostname
        if not proxy_host:
            raise ValueError(f"invalid proxy URL: {proxy_url!r}")
        proxy_port = proxy.port or (443 if proxy.scheme == "https" else 80)
        proxy_headers = {}
        auth = _proxy_auth_header(proxy)
        if auth:
            proxy_headers["Proxy-Authorization"] = auth

        conn_cls = http.client.HTTPSConnection if proxy.scheme == "https" else http.client.HTTPConnection
        if proxy.scheme == "https":
            conn = conn_cls(proxy_host, port=proxy_port, timeout=timeout, context=ctx)
        else:
            conn = conn_cls(proxy_host, port=proxy_port, timeout=timeout)

        if scheme == "https":
            conn.set_tunnel(host, port=port, headers=proxy_headers)
            request_target = path
        else:
            request_target = display_url
            request_headers.update(proxy_headers)
    elif scheme == "https":
        conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=ctx)
        request_target = path
    else:
        conn = http.client.HTTPConnection(host, port=port, timeout=timeout)
        request_target = path

    if isinstance(body, str):
        body = body.encode()
    try:
        conn.request(method.upper(), request_target, body=body, headers=request_headers)
        resp = conn.getresponse()
        response_body = resp.read().decode("utf-8", errors="replace")
        return resp.status, response_body, dict(resp.getheaders())
    finally:
        conn.close()


def raw_http_get(
    endpoint_url: str,
    raw_query: Optional[str] = None,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 15,
    no_auth: bool = False,
) -> tuple[int, str, Dict[str, str]]:
    return raw_http_request(
        "GET",
        endpoint_url,
        raw_query=raw_query,
        headers=headers,
        timeout=timeout,
        no_auth=no_auth,
    )


def is_enabled() -> bool:
    return _proxies is not None


def _guess_caller_module() -> str:
    """Best-effort module label from the call stack for HTTP trace lines."""
    _am = _get_active_module()
    if _am:
        return _am
    for frame_info in inspect.stack()[2:12]:
        path = frame_info.filename or ""
        func = frame_info.function or ""
        if "/modules/" in path.replace("\\", "/"):
            base = os.path.basename(path)
            if base.endswith(".py"):
                return base[:-3]
        if func.startswith("scan") or func == "exploit":
            return func
    return "?"


def _install_patch() -> None:
    global _patched, _orig_session_request
    if _patched:
        return

    _orig_session_request = requests.Session.request

    def _patched_session_request(self, method, url, **kwargs):
        # Per-request opt-out of -H auth injection (used by unauth_get). Popped
        # UNCONDITIONALLY here — never inside `if _extra_headers:` — so the custom
        # key is always stripped before _orig_session_request (which has no
        # `no_auth` param); otherwise an operator running with no -H headers would
        # leak it through and raise TypeError. Default False keeps every existing
        # call site's auth-forcing behavior byte-for-byte unchanged.
        no_auth = kwargs.pop("no_auth", False)
        _record_request_stats()
        if _proxies is not None and not kwargs.get("proxies"):
            kwargs["proxies"] = _proxies
        # TLS verify resolution:
        #   * operator opted into --secure (_verify_default is True): FORCE verify=True even over a
        #     module's baked-in verify=False — otherwise --secure is silently ignored at the ~127 call
        #     sites that hardcode verify=False (WIRING_AUDIT B5). Operator intent wins.
        #   * proxy default (_verify_default is False): only fill when the module didn't set verify,
        #     so a module that explicitly wants verification is preserved.
        if _verify_default is True:
            kwargs["verify"] = True
        elif _verify_default is not None and "verify" not in kwargs:
            kwargs["verify"] = _verify_default
        if _extra_headers and not no_auth:
            # Non-destructive merge: keep the module's own headers, but let the
            # user's -H values (e.g. Cookie / Authorization) override on conflict.
            #
            # Caveat: requests' prepare_cookies() runs AFTER header prep, so if a
            # module logs into its OWN Session (e.g. Fortify, or the opt-in
            # authenticated Livewire/Snipe probes), that Session's cookie jar
            # overwrites an injected `Cookie` header post-login. The common
            # auth-forcing case — user supplies a session cookie and no module-side
            # login happens — uses an empty jar, so the cookie IS sent as intended.
            merged = dict(kwargs.get("headers") or {})
            merged.update(_extra_headers)
            # X-XSRF-TOKEN promotion (GAP 3): Laravel's stateful (Sanctum/web)
            # routes require the X-XSRF-TOKEN header to match the XSRF-TOKEN cookie,
            # or they 419. When the operator injected that cookie via -H and did NOT
            # set X-XSRF-TOKEN themselves, auto-add the URL-DECODED token so authed
            # POST/PUT/DELETE pass CSRF. Never clobber a caller-set header (matched
            # case-insensitively); harmless on GET. Applied uniformly to all methods.
            if not any(k.lower() == "x-xsrf-token" for k in merged):
                # HTTP header names are case-insensitive: an operator may pass
                # -H 'cookie: ...' (lowercase), so scan for any case-variant of the
                # Cookie key rather than only the canonical "Cookie".
                _cookie_val = next(
                    (v for k, v in _extra_headers.items() if k.lower() == "cookie"), ""
                )
                _xsrf = _xsrf_token_from_cookie(_cookie_val)
                if _xsrf:
                    merged["X-XSRF-TOKEN"] = _xsrf
            kwargs["headers"] = merged
        if _trace_http:
            mod = _guess_caller_module()
            try:
                display_url = url
            except Exception:
                display_url = repr(url)
            print(f"[HTTP] [{mod}] {method.upper()} {display_url}", flush=True)

        # Reflected-Host redirect guard: when the operator forces a Host override
        # (-H 'Host: …') to reach a non-default vhost, the server commonly answers
        # with an absolute redirect whose host is the SPOOFED Host (e.g.
        # 302 -> http://_/filemanager). Following that lands on an unresolvable host
        # and the probe fails (NameResolutionError), making the app look absent. We
        # follow redirects manually here, re-basing each Location's host/scheme back
        # onto the host we actually connected to. Path+query are preserved. Only
        # engages when (a) a Host override is set AND (b) the caller asked to follow
        # redirects — otherwise this is a byte-for-byte no-op.
        _host_ovr = host_override()
        if _host_ovr and kwargs.get("allow_redirects", True) and not no_auth:
            return _request_following_rebased_redirects(
                self, method, url, kwargs, _host_ovr)
        return _orig_session_request(self, method, url, **kwargs)

    requests.Session.request = _patched_session_request  # type: ignore[method-assign]
    _patched = True


# Max manual redirect hops when re-basing under a Host override (mirrors requests' default).
_MAX_REBASED_REDIRECTS = 10


def _request_following_rebased_redirects(session, method, url, kwargs, host_ovr):
    """Issue `method url`, then follow up to _MAX_REBASED_REDIRECTS redirects manually,
    re-basing each absolute Location's scheme+host back onto the host we connected to.

    Engaged only when a Host override is active. The original connection host is taken
    from `url` (the host the caller dialed), NOT from the spoofed Host header — so a
    `Location: http://<spoofed-host>/x` is rewritten to `http://<real-host>/x` while a
    same-host or relative redirect resolves normally. Returns the FINAL response with
    `.history` populated, matching requests' allow_redirects=True contract closely enough
    for the scanner's needs (status, headers, .text, .url, .cookies, .history)."""
    real = urlparse(url)
    real_netloc, real_scheme = real.netloc, (real.scheme or "http")

    # Disable the library's own redirect following; we drive it.
    local_kwargs = dict(kwargs)
    local_kwargs["allow_redirects"] = False

    history = []
    cur_method, cur_url = method, url
    resp = _orig_session_request(session, cur_method, cur_url, **local_kwargs)

    hops = 0
    while resp.is_redirect and hops < _MAX_REBASED_REDIRECTS:
        loc = resp.headers.get("location")
        if not loc:
            break
        nxt = urljoin(cur_url, loc)  # resolve relative against current URL
        np = urlparse(nxt)
        # Re-base only when the redirect points at a DIFFERENT host than the one we
        # dialed (typically the reflected spoofed Host); same-host redirects pass through.
        if np.netloc and np.netloc != real_netloc:
            nxt = np._replace(scheme=real_scheme, netloc=real_netloc).geturl()
        history.append(resp)
        # 301/302/303 -> GET (drop body); 307/308 -> preserve method. Mirror requests.
        if resp.status_code in (301, 302, 303) and cur_method.upper() not in ("GET", "HEAD"):
            cur_method = "GET"
            for k in ("data", "json", "files"):
                local_kwargs.pop(k, None)
        cur_url = nxt
        resp = _orig_session_request(session, cur_method, cur_url, **local_kwargs)
        hops += 1

    resp.history = history
    return resp


def validate_proxy_url(proxy: str) -> str:
    """Normalize and validate --proxy value."""
    proxy = proxy.strip()
    parsed = urlparse(proxy)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Proxy must use http:// or https:// scheme (got {proxy!r}). "
            f"Example: {DEFAULT_PROXY}"
        )
    if not parsed.netloc:
        raise ValueError(f"Invalid proxy URL: {proxy!r}")
    return proxy


def has_extra_headers() -> bool:
    return bool(_extra_headers)


def has_auth_headers() -> bool:
    """True only when -H supplies material that should be treated as authentication."""
    return any(k.lower() in {"cookie", "authorization"} for k in _extra_headers)


def host_override() -> Optional[str]:
    """The operator-forced Host header value (-H 'Host: …'), or None.

    When set, the scan reaches the app through a non-default virtual host. Servers
    frequently reflect this Host into absolute redirect Location / signed URLs, so
    blindly following them lands on a possibly-unresolvable host. The patched request
    layer uses this to re-base such redirects back onto the real connection host.
    """
    for k, v in _extra_headers.items():
        if k.lower() == "host":
            return v
    return None


def run_auth_label() -> str:
    """Auth-context label for the within-run Response memo's composite key.

    Single source of truth so seeder (detect_laravel) and consumers agree — a divergence
    would silently break memo key-matching. 'authed' when -H auth material is present, else 'anon'.
    """
    return "authed" if has_auth_headers() else "anon"


def get_auth_session() -> "requests.Session":
    """Return a fresh requests.Session.

    The returned Session participates in the global patch (proxies, verify, extra -H headers
    such as Cookie:/Authorization:). Modules that perform their own form login can use this
    as a starting point so user-supplied -H material is present for the initial requests.

    Note: after a module calls login and receives Set-Cookie, the jar will take precedence for
    subsequent calls on *that* Session; user -H Cookie will have been used for the login roundtrip.
    """
    return requests.Session()


def unauth_get(
    url,
    *,
    cookies=None,
    headers=None,
    allow_redirects=True,
    timeout=10,
    **kwargs,
) -> "requests.Response":
    """Issue a GET that deliberately SKIPS the global -H auth injection.

    For passive probes (e.g. html_config_disclosure, ci_language_lfi) that need to
    observe the application's UNAUTHENTICATED response even when the operator
    supplied auth material via -H. Builds a FRESH requests.Session() (empty cookie
    jar — no leaked Set-Cookie or operator state) and passes the per-request
    `no_auth=True` opt-out, which the Session patch pops-and-honors to skip ONLY the
    `_extra_headers` cookie/Authorization override and the X-XSRF-TOKEN promotion.

    The request still routes through the full patch, so request-stat costing,
    --trace-http, proxy injection, and TLS verify resolution are all preserved.
    The opt-out is per-request and defaults to inject, so this NEVER disables auth
    injection for any other caller — the worst case of a stray no_auth=True is a
    single unauthenticated request, not a global auth disable.

    Caller `cookies`/`headers` pass through as native requests kwargs (the patch
    never rewrites `cookies=`, and with the injection block skipped, `headers` are
    sent unmodified). `allow_redirects` defaults to True (requests' default); pass
    False to observe a pre-302 signal.
    """
    sess = requests.Session()
    return sess.get(
        url,
        cookies=cookies,
        headers=headers,
        allow_redirects=allow_redirects,
        timeout=timeout,
        no_auth=True,
        **kwargs,
    )


def parse_header(raw: str) -> tuple[str, str]:
    """Parse a single ``-H "Name: Value"`` string into a (name, value) pair.

    Uses partition(':') so it never raises and tolerates colons in the value
    (e.g. ``Authorization: Bearer x`` or a Cookie value containing ':').
    """
    name, sep, value = raw.partition(":")
    name = name.strip()
    if not sep or not name:
        raise ValueError(
            f"Invalid header {raw!r}; expected 'Name: Value' "
            f"(e.g. -H 'Cookie: laravel_session=abc' )"
        )
    return name, value.strip()


def parse_headers(raw_list) -> Dict[str, str]:
    """Parse a list of ``-H`` strings into a {name: value} dict (later wins)."""
    headers: Dict[str, str] = {}
    for raw in raw_list or []:
        name, value = parse_header(raw)
        headers[name] = value
    return headers


def _xsrf_token_from_cookie(cookie_header: str) -> Optional[str]:
    """Extract the XSRF-TOKEN value from a raw Cookie header string, URL-decoded.

    Laravel sets the ``XSRF-TOKEN`` cookie URL-ENCODED; the matching ``X-XSRF-TOKEN``
    request header must carry the URL-DECODED ciphertext, so we unquote() the value.
    Returns None when no XSRF-TOKEN segment is present. Cookie format is
    ``name1=val1; name2=val2; ...`` — we split on ';' and match the first
    ``XSRF-TOKEN=`` segment (case-sensitive name, per Laravel's cookie name).
    """
    if not cookie_header:
        return None
    for segment in cookie_header.split(";"):
        name, sep, value = segment.strip().partition("=")
        if sep and name == "XSRF-TOKEN":
            return unquote(value.strip())
    return None


# ----------------------------------------------------------------------------
# URL construction helpers — critical for subdir mounts / in-house apps
# (e.g. https://corp.example.com/apps/my-laravel  or reverse-proxy prefixes)
# ----------------------------------------------------------------------------
def normalize_base(target: str) -> str:
    """Ensure target has scheme and no trailing slash. Treats it as the app root
    (which may itself be a subpath mount).
    """
    if not target:
        return ""
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "http://" + t
    return t.rstrip("/")


def app_url(base: str, rel: str) -> str:
    """Join a relative (or absolute-path) resource to the app base correctly,
    even when the app is mounted under a sub-directory.

    Examples:
      app_url("https://ex.com/intranet/app", "/.env")   -> https://ex.com/intranet/app/.env
      app_url("https://ex.com/intranet/app", ".env")    -> same
      app_url("https://ex.com/intranet/app", "/login")  -> https://ex.com/intranet/app/login
      app_url("https://ex.com", "/storage/logs/..")     -> https://ex.com/storage/logs/..
    Never use bare urljoin(base, "/abs") or base + "/abs" for app resources.
    """
    b = normalize_base(base)
    if not rel:
        return b
    # Strip leading / from rel so it is treated as relative to the directory base.
    p = rel.lstrip("/")
    if not p:
        return b
    # Append a trailing / to the normalized base so urljoin treats it as directory.
    return urljoin(b + "/", p)


# Install the Session patch eagerly at import time so request logging and proxy/header
# injection work even when configure() is never called (e.g. plain `check.py <url>` with
# no --proxy/--trace-http flags). _trace_http defaults False; pass --trace-http to enable.
_install_patch()

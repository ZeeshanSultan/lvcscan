import importlib
import io
import os
import re
import sys
import types
from contextlib import redirect_stdout

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import check  # noqa: E402

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _laravel_info(version="v11.54.0"):
    return {
        "final_url": "http://target.test",
        "cookies": [],
        "components": [],
        "route_map": {},
        "composer_lock_version": version,
        "_root_resp": None,
    }


def _run_stubbed(
    monkeypatch,
    cve,
    scan_result,
    *,
    policy,
    do_exploit=True,
    components=None,
    version="v11.54.0",
    producer_key=None,
):
    calls = {"scan": [], "exploit": []}

    def fake_scan(target_url, **kwargs):
        calls["scan"].append({"target_url": target_url, **kwargs})
        return dict(scan_result)

    def fake_producer_scan(target_url, **kwargs):
        calls.setdefault("producer_scan", []).append({"target_url": target_url, **kwargs})
        if not producer_key:
            return {"vulnerable": False, "verdict": "not_detected", "status": "not_detected"}
        return {
            "vulnerable": True,
            "verdict": "confirmed_vulnerable",
            "status": "confirmed_vulnerable",
            "artifacts": {"app_key": producer_key},
        }

    def fake_exploit(target_url, **kwargs):
        calls["exploit"].append({"target_url": target_url, **kwargs})
        return {
            "cve": cve,
            "attempted": True,
            "success": False,
            "vuln_class": "rce",
            "detail": "stub exploit reached",
            "artifacts": {},
            "requires": [],
            "reason": "",
        }

    orig_import = importlib.import_module

    def fake_import(name, package=None):
        if name == "modules.cves.cve_" + cve.replace("CVE-", "").replace("-", "_"):
            return types.SimpleNamespace(scan=fake_scan)
        if name in (
            "modules.detection.env_exposure",
            "modules.cves.cve_2017_16894",
            "modules.detection.app_root_disclosure",
        ):
            return types.SimpleNamespace(scan=fake_producer_scan)
        return orig_import(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    monkeypatch.setattr(check, "is_laravel", lambda target_url, **kwargs: _laravel_info(version))
    monkeypatch.setattr(
        check,
        "discover_resources",
        lambda target_url, **kwargs: {
            "components": list(components or []),
            "route_map": {},
            "debug_mode": False,
        },
    )
    monkeypatch.setattr(check, "_run_app_root_disclosure", lambda *args, **kwargs: None)
    monkeypatch.setattr(check, "_import_exploit", lambda wanted: fake_exploit)

    buf = io.StringIO()
    with redirect_stdout(buf):
        payload = check.run_exploitation(
            "http://target.test",
            only_cve=cve,
            do_exploit=do_exploit,
            exploit_policy=policy,
        )
    return payload, calls, _ANSI.sub("", buf.getvalue())


def test_force_bypasses_confirmed_only_detection_gate_and_reaches_exploit(monkeypatch):
    cve = "CVE-2021-3129"
    miss = {"vulnerable": False, "verdict": "not_detected", "status": "not_detected"}

    conservative, conservative_calls, _ = _run_stubbed(
        monkeypatch,
        cve,
        miss,
        policy="confirmed-only",
    )
    row = conservative["summary"][0]
    assert row["scan"] == "not_detected"
    assert row["attempted"] is False
    assert conservative_calls["exploit"] == []

    forced, forced_calls, _ = _run_stubbed(
        monkeypatch,
        cve,
        miss,
        policy="forced",
    )
    row = forced["summary"][0]
    assert row["scan"] == "not_detected"
    assert row["attempted"] is True
    assert len(forced_calls["exploit"]) == 1
    kwargs = forced_calls["exploit"][0]
    assert kwargs["force"] is True
    assert kwargs["exploit_policy"] == "forced"
    assert kwargs["options"]["force"] is True
    assert kwargs["options"]["exploit_policy"] == "forced"


def test_force_bypasses_central_version_suppression(monkeypatch):
    cve = "CVE-2021-28254"
    hit = {"vulnerable": True, "verdict": "confirmed_vulnerable", "status": "confirmed_vulnerable"}

    conservative, conservative_calls, _ = _run_stubbed(
        monkeypatch,
        cve,
        hit,
        policy="confirmed-only",
        version="v11.54.0",
    )
    row = conservative["summary"][0]
    assert row["scan"] == "blocked_by_control"
    assert row["attempted"] is False
    assert row["detection"]["suppressed"] is True
    assert conservative_calls["exploit"] == []

    forced, forced_calls, out = _run_stubbed(
        monkeypatch,
        cve,
        hit,
        policy="forced",
        version="v11.54.0",
    )
    row = forced["summary"][0]
    assert row["scan"] == "confirmed_vulnerable"
    assert row["attempted"] is True
    assert "suppression_bypassed_by_force" in row["detection"]
    assert "bypassed by forced policy" in out
    assert len(forced_calls["exploit"]) == 1


def test_force_bypasses_component_absence_gate(monkeypatch):
    cve = "CVE-2025-14894"
    miss = {"vulnerable": False, "verdict": "not_detected", "status": "not_detected"}

    conservative, conservative_calls, _ = _run_stubbed(
        monkeypatch,
        cve,
        miss,
        policy="aggressive",
        components=["livewire_absent"],
    )
    row = conservative["summary"][0]
    assert row["scan"] == "not_applicable"
    assert row["attempted"] is False
    assert conservative_calls["scan"] == []
    assert conservative_calls["exploit"] == []

    forced, forced_calls, _ = _run_stubbed(
        monkeypatch,
        cve,
        miss,
        policy="forced",
        components=["livewire_absent"],
    )
    row = forced["summary"][0]
    assert row["scan"] == "not_detected"
    assert row["attempted"] is True
    assert "livewire confirmed absent by probe; forced by policy" in row["probe_note"]
    assert len(forced_calls["scan"]) == 1
    assert len(forced_calls["exploit"]) == 1


def test_cli_force_implies_exploit_for_targeted_run(monkeypatch):
    captured = {}

    def fake_run_exploitation(*args, **kwargs):
        captured.update(kwargs)
        return {"ok": True, "summary": []}

    monkeypatch.setattr(check, "show_banner", lambda: None)
    monkeypatch.setattr(check, "print_separator", lambda: None)
    monkeypatch.setattr(check, "_init_http_from_args", lambda args: None)
    monkeypatch.setattr(check, "_warn_if_deep_link", lambda target: None)
    monkeypatch.setattr(check, "reset_run_memo", lambda: None)
    monkeypatch.setattr(check, "run_exploitation", fake_run_exploitation)
    monkeypatch.setattr(sys, "argv", ["check.py", "http://target.test", "--cve", "CVE-2021-3129", "--force"])

    with redirect_stdout(io.StringIO()):
        check.main()

    assert captured["only_cve"] == "CVE-2021-3129"
    assert captured["do_exploit"] is True
    assert captured["exploit_policy"] == "forced"


def test_force_recovers_app_key_from_producer_detection_before_exploit(monkeypatch):
    key = "base64:DETECTIONKEYDETECTIONKEYDETECTIONKEYDETECT="
    forced, calls, _ = _run_stubbed(
        monkeypatch,
        "CVE-2024-48987",
        {"vulnerable": False, "verdict": "not_detected", "status": "not_detected"},
        policy="forced",
        producer_key=key,
    )

    row = forced["summary"][0]
    assert row["attempted"] is True
    assert forced["loot"]["app_key_present"] is True
    assert forced["loot"]["app_key_source"] == "env"
    assert calls["exploit"][0]["options"]["app_key"] == key
    assert calls["producer_scan"], "forced APP_KEY recovery should run producer detections"


def test_force_does_not_use_wordlist_default_when_no_app_key_is_recovered(monkeypatch):
    forced, calls, out = _run_stubbed(
        monkeypatch,
        "CVE-2024-48987",
        {"vulnerable": False, "verdict": "not_detected", "status": "not_detected"},
        policy="forced",
    )

    row = forced["summary"][0]
    assert row["attempted"] is True
    assert "app_key" not in calls["exploit"][0]["options"]
    assert "app_key_source" not in calls["exploit"][0]["options"]
    assert "appkey_wordlist.txt default" not in out


@pytest.mark.parametrize(
    "module_name",
    [
        "modules.cves.cve_2018_15133",
        "modules.cves.cve_2024_48987",
        "modules.cves.cve_2024_55555",
        "modules.cves.cve_2024_55556",
    ],
)
def test_app_key_modules_report_forced_missing_key_as_attempted(module_name):
    mod = importlib.import_module(module_name)

    result = mod.exploit("http://target.test", options={"force": True, "exploit_policy": "forced"})

    assert result["attempted"] is True
    assert result["success"] is False
    assert "app_key" in result.get("requires", [])


@pytest.mark.parametrize(
    "module_name",
    [
        "modules.cves.cve_2022_2870",
        "modules.cves.cve_2022_2886",
    ],
)
def test_2022_laravel_deser_modules_exploit_synthetic_sink(module_name):
    mod = importlib.import_module(module_name)

    class SyntheticSession:
        def __init__(self):
            self.calls = []

        def post(self, url, **kwargs):
            self.calls.append(("POST", url, kwargs))
            return types.SimpleNamespace(
                status_code=200,
                text='{"proof":"execution_model=actual PHP unserialize","hardened":false}',
                json=lambda: {
                    "proof": "execution_model=actual PHP unserialize",
                    "hardened": False,
                    "command_output": "",
                },
            )

        def get(self, url, **kwargs):
            self.calls.append(("GET", url, kwargs))
            return types.SimpleNamespace(
                status_code=200,
                text='{"proof":"execution_model=actual PHP unserialize","command_output":"uid=33(www-data)"}',
                json=lambda: {
                    "proof": "execution_model=actual PHP unserialize",
                    "hardened": False,
                    "command_output": "uid=33(www-data)",
                },
            )

    default_session = SyntheticSession()
    marker = mod.exploit("http://target.test", session=default_session)
    assert marker["attempted"] is True
    assert marker["success"] is True
    assert marker["vuln_class"] == "deserialization"
    assert default_session.calls[0][0] == "POST"
    assert set(default_session.calls[0][2]["data"]) == {"username", "password"}

    command_session = SyntheticSession()
    command = mod.exploit(
        "http://target.test",
        command="id",
        options={"method": "GET", "params": ["sid", "gid"]},
        session=command_session,
    )
    assert command["attempted"] is True
    assert command["success"] is True
    assert command["vuln_class"] == "rce"
    assert command_session.calls[0][0] == "GET"
    assert set(command_session.calls[0][2]["params"]) == {"sid", "gid"}


class _DeadIgnitionSession:
    headers = {}

    def post(self, *args, **kwargs):
        return types.SimpleNamespace(status_code=404, text="", headers={})


def test_ignition_force_bypasses_probe_gate_and_drives_delivery(monkeypatch, tmp_path):
    from modules.cves import cve_2021_3129

    phar = tmp_path / "payload.phar"
    phar.write_bytes(b"fake-phar")
    deliveries = []

    def fake_run_chain(session, url, phar_bytes, **kwargs):
        deliveries.append({"url": url, "phar_bytes": phar_bytes, **kwargs})
        return False, "", None

    monkeypatch.setattr(cve_2021_3129, "_run_chain", fake_run_chain)

    non_forced = cve_2021_3129.exploit(
        "http://target.test",
        options={"phar_file": str(phar)},
        session=_DeadIgnitionSession(),
    )
    assert non_forced["attempted"] is True
    assert non_forced["success"] is False
    assert non_forced["requires"] == ["ignition_debug_endpoint"]
    assert deliveries == []

    forced = cve_2021_3129.exploit(
        "http://target.test",
        options={"phar_file": str(phar), "force": True, "exploit_policy": "forced"},
        session=_DeadIgnitionSession(),
    )
    assert forced["attempted"] is True
    assert forced["success"] is False
    assert "forced_probe_bypass" in forced["artifacts"]
    assert len(deliveries) == 1
    assert deliveries[0]["phar_bytes"] == b"fake-phar"

import importlib
import inspect
import ast
import textwrap
from types import SimpleNamespace

from modules.cves.metadata import CVE_METADATA
from modules.cves import cve_2021_3129


def test_command_capable_exploits_declare_command_parameter():
    missing = []
    for cve, meta in CVE_METADATA.items():
        if not meta.command_capable:
            continue
        module = importlib.import_module(meta.module)
        exploit = getattr(module, "exploit", None)
        if exploit is None or "command" not in inspect.signature(exploit).parameters:
            missing.append(cve)

    assert missing == []


def test_command_capable_exploits_reference_command_input():
    missing = []
    for cve, meta in CVE_METADATA.items():
        if not meta.command_capable:
            continue
        module = importlib.import_module(meta.module)
        exploit = getattr(module, "exploit")
        tree = ast.parse(textwrap.dedent(inspect.getsource(exploit)))
        command_reads = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name) and node.id == "command" and isinstance(node.ctx, ast.Load)
        ]
        if not command_reads or "command_ignored" in inspect.getsource(exploit):
            missing.append(cve)

    assert missing == []


def test_cve_2021_3129_custom_command_is_wrapped_and_reported(monkeypatch):
    captured = {}

    monkeypatch.setattr(cve_2021_3129, "_locate_phpggc", lambda options: (["php"], "phpggc", "/tmp"))

    def fake_gen_phar(php, phpggc, phpggc_dir, chain, cmd):
        captured["cmd"] = cmd
        return b"fake-phar"

    def fake_run_chain(session, url, phar_bytes, **kwargs):
        marker = kwargs["proof_marker"]
        return True, f"noise {marker}_START\nCUSTOM3129\n{marker}_END tail", 101

    monkeypatch.setattr(cve_2021_3129, "_gen_phar_bytes", fake_gen_phar)
    monkeypatch.setattr(cve_2021_3129, "_run_chain", fake_run_chain)

    result = cve_2021_3129.exploit(
        "http://target.test",
        command="printf CUSTOM3129",
        options={"chain": "Laravel/RCE11"},
        session=SimpleNamespace(headers={}),
        detection={"verdict": "sink_reachable", "url": "http://target.test/_ignition/execute-solution"},
    )

    assert result["success"] is True
    assert result["evidence"] == "CUSTOM3129"
    assert result["artifacts"]["command"] == "printf CUSTOM3129"
    assert "printf CUSTOM3129" in captured["cmd"]
    assert "CVE-2021-3129 PoC && id && hostname" not in captured["cmd"]

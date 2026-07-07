import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def test_list_detectors_runs_and_shows_scope_and_auth():
    out = subprocess.run(
        [sys.executable, "check.py", "--list-detectors"],
        capture_output=True, text=True, timeout=60,
        cwd=REPO,
    )
    assert out.returncode == 0, out.stderr
    text = out.stdout
    assert "env" in text
    assert "scope" in text.lower()
    assert "auth" in text.lower()
    # Real rows must be present, not just the header line.
    assert text.count("\n") > 5
    # A real category column value (not just a header word).
    assert "exposure" in text
    # A known auth-required CVE must appear.
    assert "CVE-2024-55661" in text

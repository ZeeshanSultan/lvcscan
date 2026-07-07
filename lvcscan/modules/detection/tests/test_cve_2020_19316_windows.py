import os
import sys

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ),
)

from modules.cves import cve_2020_19316 as detect
from modules.cves import cve_2020_19316 as exploit


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text


class WindowsLinkSession:
    def __init__(self, hardened=False):
        self.hardened = hardened
        self.headers = {}
        self.requests = []

    def get(self, url, params=None, **kwargs):
        self.requests.append((url, params or {}))
        if not url.endswith("/storage/link"):
            return FakeResp(404, "")

        if not params:
            return FakeResp(400, "missing target or link")

        link = params.get("link", "")
        target = params.get("target", "")
        if self.hardened and any(ch in link for ch in "&|;<>"):
            return FakeResp(400, "blocked by hardened Filesystem::link input validation")

        first = f"$ cmd.exe /C mklink /D {link} {target} 2>&1"
        if "CVE19316_DETECT" in link and "&" in link:
            return FakeResp(200, first + "\r\nCVE19316_DETECT\r\n")
        if "CHK49CHK" in link and "&" in link:
            return FakeResp(200, first + "\r\nCHK49CHK\r\nwinlab\\container-user\r\n")
        return FakeResp(200, first + "\r\nThe syntax of the command is incorrect.\r\n")


def test_detector_accepts_windows_cmd_marker():
    res = detect.scan("http://lab", session=WindowsLinkSession())
    assert res["vulnerable"] is True
    assert "windows-cmd_marker_execution" in res["detection_methods"]


def test_exploit_accepts_windows_cmd_marker():
    res = exploit.exploit("http://lab", command="whoami", session=WindowsLinkSession())
    assert res["success"] is True
    assert res["artifacts"]["shell"] == "windows-cmd"
    assert "winlab\\container-user" in res["evidence"]


def test_hardened_windows_profile_blocks_marker_execution():
    res = exploit.exploit("http://lab", command="whoami", session=WindowsLinkSession(hardened=True))
    assert res["success"] is False

"""Reflected-Host signed-URL rebasing (CVE-2025-14894 / CVE-2024-47823 upload primitive).

When the scan reaches the app through a forced Host override (-H 'Host: _'), Livewire builds
the signed upload URL from the request Host and reflects that spoofed host into an ABSOLUTE URL
(`http://_/livewire-XXXX/upload-file?expires=...&signature=...`). POSTing there fails to resolve.
The signed-URL signature covers PATH + QUERY only, so re-basing the host/scheme onto the real
connection target preserves validity. These tests pin that behavior in BOTH consumers and the
critical no-op-when-host-matches invariant (so direct-target scans are unaffected).
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from modules.cves.cve_2025_14894 import _signed_url_from_effects as exp_signed
from modules.helpers.livewire_upload import _signed_url_from_effects as help_signed


def _effects(url):
    return {"dispatches": [{"name": "upload:generatedSignedUrl", "params": {"url": url}}]}


SIG = "?expires=1781161945&signature=5c2af8566bdbdbac4976cc92254624681305a3b259af7a1c698c4607f7a6127e"
PATH = "/livewire-0a110dbe/upload-file"


def test_exploit_rebases_reflected_absolute_host():
    # Reflected spoofed host '_' -> rebased to the real target, path+query preserved.
    out = exp_signed(_effects("http://_" + PATH + SIG), "http://localhost:18081")
    assert out == "http://localhost:18081" + PATH + SIG


def test_exploit_relative_url_joins_onto_base():
    out = exp_signed(_effects(PATH + SIG), "http://localhost:18081")
    assert out == "http://localhost:18081" + PATH + SIG


def test_exploit_noop_when_host_already_matches():
    # Direct-target case (e.g. :19090): host already correct -> returned unchanged.
    same = "http://localhost:19090" + PATH + SIG
    assert exp_signed(_effects(same), "http://localhost:19090") == same


def test_exploit_preserves_scheme_from_base():
    # https target, http-reflected signed URL -> scheme taken from the base.
    out = exp_signed(_effects("http://_" + PATH + SIG), "https://app.example.com")
    assert out == "https://app.example.com" + PATH + SIG


def test_helper_rebases_reflected_absolute_host():
    # The CVE-2024-47823 path uses the helper's copy — same contract.
    out = help_signed(_effects("http://_" + PATH + SIG), "http://localhost:18081/filemanager")
    assert out == "http://localhost:18081" + PATH + SIG


def test_helper_noop_when_host_already_matches():
    same = "http://localhost:19090" + PATH + SIG
    assert help_signed(_effects(same), "http://localhost:19090/filemanager") == same

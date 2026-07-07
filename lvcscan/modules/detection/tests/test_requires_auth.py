from modules.registry.detect import DETECTORS

# Detection-path CVEs whose scan() needs an authenticated session or lab credentials.
AUTH_CVES = {
    "CVE-2024-55661",   # Pulse dashboard scan() treats 403 as the auth-gated hit; genuinely auth-gated detect
}

# CVE_META auth_required=False CVEs — must never carry requires_auth: True
UNAUTH_CVES = {
    "CVE-2017-16894",   # .env/debug disclosure — auth_required=False, app_key_required=False
    "CVE-2021-3129",    # Ignition unauth RCE    — auth_required=False, app_key_required=False
    "CVE-2024-47823",   # file-as-dir unauth RCE — auth_required=False, app_key_required=False
    "CVE-2024-48987",   # unauth deserialize RCE — auth_required=False, app_key_required=True
    "CVE-2024-22836",   # Akaunting public fingerprint/version gate; auth only enhances/exploits
    # Detection is unauthenticated; auth only enhances the version read / gates the EXPLOIT.
    # Verified against scan() (cve_2020_5256.py:33-34 "scan() never requires auth";
    # cve_2023_46865.py scan() resolves the version unauth) — truthful-labs audit 2026-06.
    "CVE-2020-5256",    # BookStack public fingerprint/version; image-upload EXPLOIT needs admin
    "CVE-2023-46865",   # Crater public fingerprint/version; upload-logo EXPLOIT needs superadmin bearer
}


def test_auth_cves_flagged():
    by_cve = {d.get("cve"): d for d in DETECTORS if d.get("cve")}
    for cve in AUTH_CVES:
        assert by_cve.get(cve, {}).get("requires_auth") is True, f"{cve} not flagged requires_auth"


def test_no_spurious_requires_auth():
    """Unauthenticated CVEs must not be accidentally tagged requires_auth: True."""
    by_cve = {d.get("cve"): d for d in DETECTORS if d.get("cve")}
    for cve in UNAUTH_CVES:
        assert by_cve.get(cve, {}).get("requires_auth") is not True, (
            f"{cve} is unauthenticated (CVE_META auth_required=False) "
            f"but is spuriously tagged requires_auth=True"
        )

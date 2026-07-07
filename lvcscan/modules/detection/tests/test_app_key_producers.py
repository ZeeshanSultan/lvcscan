from modules.registry.exploit import APP_KEY_PRODUCERS

def test_producers_are_canonical_set():
    assert set(APP_KEY_PRODUCERS) == {
        "CVE-2017-16894", "CVE-2025-49132", "CVE-2023-43661", "CVE-2024-55661",
    }

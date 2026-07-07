"""Lab-default metadata stays documentation-only for auth-gated CVEs."""

import importlib
import inspect

import pytest

from modules.registry.exploit import (
    LAB_DEFAULT_APP_KEYS,
    LAB_DEFAULT_CREDS,
    lab_default_app_key_for,
    lab_default_creds_for,
)
import check


def test_cve_2020_5256_has_lab_defaults():
    assert "CVE-2020-5256" in LAB_DEFAULT_CREDS
    assert lab_default_creds_for("CVE-2020-5256") == ("admin@admin.com", "password")
    assert lab_default_creds_for("CVE-2024-22836") == ("admin@example.com", "LabAdmin123!")
    assert lab_default_creds_for("CVE-2023-46865") == ("admin@craterapp.com", "crater@123")


def test_detector_candidate_kwargs_does_not_inject_lab_defaults():
    kw = check._detector_candidate_kwargs(None, None, cve="CVE-2020-5256")
    assert kw["username"] is None
    assert kw["password"] is None
    assert kw["session"] is None


def test_detector_candidate_kwargs_has_no_lab_default_opt_in_parameter():
    sig = inspect.signature(check._detector_candidate_kwargs)
    assert list(sig.parameters) == ["username", "password", "cve"]


def test_detector_candidate_kwargs_operator_overrides_lab():
    kw = check._detector_candidate_kwargs("ops@example.com", "secret", cve="CVE-2020-5256")
    assert kw["username"] == "ops@example.com"
    assert kw["password"] == "secret"


def test_detector_candidate_kwargs_preserves_empty_operator_creds():
    kw = check._detector_candidate_kwargs("", "", cve="CVE-2020-5256")
    assert kw["username"] == ""
    assert kw["password"] == ""


def test_provided_or_preserves_empty_operator_values():
    assert check._provided_or("", "admin") == ""
    assert check._provided_or(None, "admin") == "admin"


def test_lab_default_app_keys_are_metadata_only():
    assert "CVE-2018-15133" in LAB_DEFAULT_APP_KEYS
    assert lab_default_app_key_for("CVE-2024-55555").startswith("base64:")
    assert lab_default_app_key_for("CVE-2021-3129") is None


@pytest.mark.parametrize(
    "module_name, expected_requires",
    [
        ("modules.cves.cve_2024_22836", "admin/company-manager credentials"),
        ("modules.cves.cve_2020_5256", "valid BookStack credentials with image-create-all"),
        ("modules.cves.cve_2023_46865", "valid Crater superadmin credentials"),
        ("modules.cves.cve_2023_43661", "Cachet dashboard credentials or X-Cachet-Token"),
        ("modules.cves.cve_2017_14775", "remember_token_or_credentials"),
    ],
)
def test_modules_do_not_inject_lab_auth_material(module_name, expected_requires):
    mod = importlib.import_module(module_name)

    result = mod.exploit("http://target.test")

    assert result["success"] is False
    assert expected_requires in result.get("requires", [])

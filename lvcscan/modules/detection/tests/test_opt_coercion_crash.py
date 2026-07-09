"""Phase 6 — --opt VALUE coercion must never crash. '--5' used to pass
str.lstrip('-').isdigit() and then blow up on int('--5')."""

import check


def test_double_dash_number_stays_string_no_crash():
    assert check._coerce_opt_value("x", "--5") == "--5"


def test_plain_int_coerced():
    assert check._coerce_opt_value("redis_port", "6379") == 6379


def test_signed_negative_int_coerced():
    assert check._coerce_opt_value("offset", "-5") == -5


def test_app_key_never_coerced():
    assert check._coerce_opt_value("app_key", "123456") == "123456"


def test_non_numeric_stays_string():
    assert check._coerce_opt_value("host", "10.0.0.5") == "10.0.0.5"
    assert check._coerce_opt_value("x", "5abc") == "5abc"

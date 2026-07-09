"""Phase 0.2 — a non-empty list from a detector is SURFACE, not a confirmed vuln.

Previously any truthy list collapsed to `confirmed_vulnerable`, which silently
promoted candidate/surface evidence (e.g. mass-assignment's List[Dict]) to a CVE
hit. A list now defaults to `surface_present`; confirmation requires either a dict
verdict or a list whose every element independently confirms.
"""

from modules.helpers.pipeline import detection_verdict, is_confirmed_detection


def test_empty_list_is_not_detected():
    assert detection_verdict([]) == "not_detected"


def test_plain_nonempty_list_is_surface_present_not_confirmed():
    result = [{"endpoint": "/register", "reflected": True}]
    assert detection_verdict(result) == "surface_present"
    assert not is_confirmed_detection(detection_verdict(result))


def test_list_of_behaviorally_proven_dicts_confirms():
    result = [
        {"endpoint": "/register", "proof_type": "behavioral"},
        {"endpoint": "/profile", "proof_type": "behavioral"},
    ]
    assert detection_verdict(result) == "confirmed_vulnerable"


def test_mixed_list_downgrades_to_surface():
    result = [
        {"endpoint": "/register", "proof_type": "behavioral"},
        {"endpoint": "/profile"},  # unproven
    ]
    assert detection_verdict(result) == "surface_present"


def test_dict_behavioral_still_confirms():
    assert detection_verdict({"proof_type": "behavioral"}) == "confirmed_vulnerable"

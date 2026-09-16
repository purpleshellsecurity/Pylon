"""Documented column values: harvested from the reference, enforced only when closed.

A wrong column NAME errors and gets noticed. A wrong column VALUE parses,
validates, executes and matches nothing — the rule is silently dead. These pin
the enforcement boundary, which is the part that can do harm: enforcing a set
that is not actually closed rejects correct queries.
"""

from pylon import column_values
from pylon.validation import validate_kql

# ── the catalog ───────────────────────────────────────────────────────────────

def test_catalog_carries_both_kinds_and_keeps_them_apart():
    signin = column_values.value_sets("SigninLogs")
    assert signin, "SigninLogs value sets should be vendored"
    assert signin["ConditionalAccessStatus"]["exhaustive"] is True

    net = column_values.value_sets("DeviceNetworkEvents")
    assert net["RemoteIPType"]["exhaustive"] is False, (
        'the page says "for example" — a live workspace returned LinkLocal, '
        "which that list does not contain"
    )


def test_only_closed_sets_are_enforceable():
    assert "ConditionalAccessStatus" in column_values.enforceable("SigninLogs")
    assert column_values.enforceable("DeviceNetworkEvents") == {}, (
        "an illustrative set must never reach the enforcement path"
    )


def test_an_unknown_table_grounds_nothing_rather_than_guessing():
    assert column_values.value_sets("NoSuchTable") == {}
    assert column_values.enforceable("NoSuchTable") == {}
    assert column_values.grounding_lines("NoSuchTable") == []


def test_illustrative_sets_are_labelled_as_such_in_the_prompt():
    lines = " ".join(column_values.grounding_lines("DeviceNetworkEvents"))
    assert "not a complete list" in lines, (
        "telling the model a partial list is closed teaches it to exclude a real value"
    )
    closed = " ".join(column_values.grounding_lines("SigninLogs"))
    assert "takes exactly these values" in closed


# ── the validator ─────────────────────────────────────────────────────────────

def _value_errors(kql: str, table: str) -> list[str]:
    return [e for e in validate_kql(kql, table).errors if "matches nothing" in e]


def test_wrong_case_on_a_closed_set_is_a_defect():
    """`== "Success"` against a documented `success` is dead and silent."""
    errs = _value_errors(
        'SigninLogs | where ConditionalAccessStatus == "Success"', "SigninLogs"
    )
    assert errs, "a case-wrong literal on a closed set must be caught"
    assert '"success"' in errs[0], "and the message must name the right spelling"


def test_the_documented_spelling_passes():
    assert not _value_errors(
        'SigninLogs | where ConditionalAccessStatus == "success"', "SigninLogs"
    )


def test_case_insensitive_operators_are_not_case_defects():
    """`=~` matches across case, so a case-only difference is correct there."""
    assert not _value_errors(
        'SigninLogs | where ConditionalAccessStatus =~ "Success"', "SigninLogs"
    )


def test_a_non_member_is_caught_and_the_set_is_named():
    errs = _value_errors('SigninLogs | where RiskState == "Compromised"', "SigninLogs")
    assert errs
    assert "confirmedCompromised" in errs[0]


def test_an_illustrative_set_never_rejects():
    """Measured: a live workspace holds RemoteIPType `LinkLocal`, which the
    page's "for example" list does not contain. Rejecting it would fail a
    correct query — the same defect as the Device* time-column rule."""
    assert not _value_errors(
        'DeviceNetworkEvents | where RemoteIPType == "LinkLocal"', "DeviceNetworkEvents"
    )


def test_a_non_member_shaped_literal_is_left_alone():
    """RiskEventTypes_V2 holds a serialized array; `== "[]"` is an emptiness
    test, not a misspelled member."""
    assert not _value_errors(
        'SigninLogs | where RiskEventTypes_V2 == "[]"', "SigninLogs"
    )

"""A Category value in a LoggedByService filter is a dead detection.

Measured, not theorised. An emulation script was run against a live tenant and the
row it wrote carried:

    OperationName    "Add service principal credentials"
    Category         "ApplicationManagement"
    LoggedByService  "Core Directory"

The generated detection filtered `LoggedByService == "ApplicationManagement"` and
returned 0 rows; removing that one line returned the attack. In that run, 25 of 25
detections carried the same filter and not one of them could ever have fired —
while the run reported "25/25 valid detections".

Both columns exist, so nothing static caught it: valid KQL, real columns, correct
operation string, correct entity normalisation, executes without error. This is
the failure mode CLAUDE.md names as open — knowing a predicate has no support
needs the VALUES a column takes, not just its name.
"""

import pytest

from pylon.validation.validate_kql import validate_kql

_BASE = (
    "AuditLogs\n| where TimeGenerated > ago(1h)\n"
    # `=~`, not `==`: OperationName is matched case-insensitively on AuditLogs
    # (see test_auditlogs_case_sensitivity). This fixture is about
    # LoggedByService; using the wrong operator here would make these tests fail
    # for a reason that has nothing to do with what they assert.
    '| where OperationName =~ "Add service principal credentials"\n'
)


@pytest.mark.parametrize(
    "value",
    ["ApplicationManagement", "UserManagement", "RoleManagement",
     "GroupManagement", "DirectoryManagement", "Policy", "Device"],
)
def test_a_category_value_in_loggedbyservice_is_an_error(value):
    """Every value the failing run used. An ERROR rather than a warning, because
    the detection is dead on arrival — a warning ships it."""
    result = validate_kql(_BASE + f'| where LoggedByService == "{value}"', "AuditLogs")
    assert not result.valid
    assert any("matches nothing" in e for e in result.errors)


def test_the_error_names_the_fix_not_just_the_fault():
    """The model has to be able to act on it, and so does a human reading the
    report. Naming the right column is the whole remedy."""
    result = validate_kql(
        _BASE + '| where LoggedByService == "ApplicationManagement"', "AuditLogs"
    )
    msg = " ".join(result.errors)
    assert "Category" in msg
    assert "Core Directory" in msg


def test_filtering_category_is_accepted():
    """The correct query, proven against the live row, must stay valid."""
    result = validate_kql(_BASE + '| where Category == "ApplicationManagement"', "AuditLogs")
    assert result.valid, result.errors


def test_a_real_service_value_is_accepted():
    """LoggedByService is not banned — only Category values in it are."""
    result = validate_kql(_BASE + '| where LoggedByService == "Core Directory"', "AuditLogs")
    assert result.valid, result.errors


def test_the_check_is_scoped_to_auditlogs():
    """Other tables have their own LoggedByService semantics; do not police them."""
    q = 'SigninLogs\n| where TimeGenerated > ago(1h)\n| where LoggedByService == "Policy"'
    assert "matches nothing" not in " ".join(validate_kql(q, "SigninLogs").errors)

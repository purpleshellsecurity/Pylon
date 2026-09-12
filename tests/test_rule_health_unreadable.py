"""A rule the scan could not test is not a rule that failed.

`broken` is a claim about someone's detection. It belongs in a report only when
the service REJECTED the query — a bad table, a bad column, invalid KQL. Every
other failure is the scan admitting it could not look.

The first Windows run got this wrong in the worst possible place: the
`log-analytics` extension was missing, every rule query failed with az's
unrecognised-command exit 2, and the report listed 25 of 26 detections as
broken. A reader would conclude their detection library was defective.
"""

from unittest import mock

import pytest

from pylon import azcli, rulehealth


@pytest.fixture
def rule():
    return {"rule_id": "r1", "name": "Example", "_kind": "Scheduled",
            "enabled": True, "_query": "AzureActivity | take 1",
            "tables_referenced": ["AzureActivity"]}


def health(rule, *, code, err):
    with mock.patch.object(rulehealth, "_run", return_value=(0, err, code)):
        return rulehealth._one(rule, "guid", {})


def test_a_missing_extension_is_unreadable_not_broken(rule):
    """The bug, in the shape it arrived. az exits 2 for an unrecognised
    command, and 2 is not a transport failure — so this used to read as a
    verdict on the customer's detection."""
    out = health(rule, code=2,
                 err="ERROR: 'query' is misspelled or not recognized by the "
                     "system. az monitor log-analytics query")
    assert out["rule_health_status"] == "unreadable"


def test_a_timeout_is_unreadable(rule):
    out = health(rule, code=azcli.TIMED_OUT,
                 err="the call did not finish within 120s and was cancelled")
    assert out["rule_health_status"] == "unreadable"


def test_az_missing_entirely_is_unreadable(rule):
    out = health(rule, code=azcli.COULD_NOT_RUN, err="could not run az")
    assert out["rule_health_status"] == "unreadable"


def test_a_query_the_service_rejected_is_still_broken(rule):
    """The distinction has to hold in both directions. A rule reading a table
    that does not exist IS faulty, and softening that would make the report
    useless in the other way."""
    out = health(rule, code=1,
                 err="BadArgumentError: The query refers to an unknown table "
                     "'NoSuchTable'")
    assert out["rule_health_status"] == "broken"


def test_the_reason_is_carried_through_either_way(rule):
    """A status with no explanation is a status nobody can act on."""
    for code, err in [(2, "'query' is misspelled or not recognized"),
                      (1, "SemanticError: column 'Nope' not found")]:
        assert health(rule, code=code, err=err)["health_detail"] == err

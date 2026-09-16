"""Which connector kinds SentinelHealth reports on, and the three outcomes
that follow: healthy, unhealthy, and health signal unavailable."""

import pytest

from pylon.sentinelhealth import (
    CODELESS_KINDS,
    HEALTH_REPORTS_FOR,
    connector_outcomes,
    reports_health,
)

COVERED = [
    "AmazonWebServicesCloudTrail", "AmazonWebServicesS3", "Dynamics365",
    "Office365", "MicrosoftDefenderAdvancedThreatProtection",
    "ThreatIntelligenceTaxii", "ThreatIntelligence",
]
NOT_COVERED = [
    "MicrosoftCloudAppSecurity", "AzureActiveDirectory", "AzureSecurityCenter",
    "AzureAdvancedThreatProtection", "OfficeATP",
]


@pytest.mark.parametrize("kind", COVERED)
def test_the_documented_seven_are_covered(kind):
    assert reports_health(kind)


@pytest.mark.parametrize("kind", NOT_COVERED)
def test_everything_else_is_not(kind):
    assert not reports_health(kind)


@pytest.mark.parametrize("kind", sorted(CODELESS_KINDS))
def test_codeless_connectors_are_covered_as_a_framework(kind):
    """Codeless Connector Framework kinds count as covered."""
    assert reports_health(kind)


def test_matching_ignores_case():
    assert reports_health("office365")
    assert reports_health("OFFICE365")
    assert reports_health(" Office365 ")


def test_an_unknown_kind_is_not_covered():
    assert not reports_health("SomeConnectorInventedLater")
    assert not reports_health("")
    assert not reports_health(None)


# ── the three outcomes ───────────────────────────────────────────────────────

def test_a_silent_uncovered_connector_is_not_called_broken():
    """A silent connector SentinelHealth does not cover is reported as
    unreported, not unhealthy."""
    out = connector_outcomes({"MicrosoftCloudAppSecurity"}, {})
    assert out["unreported"] == ["MicrosoftCloudAppSecurity"]
    assert out["unhealthy"] == []


def test_a_reporting_connector_is_judged_on_its_rows():
    out = connector_outcomes({"Office365"}, {
        "Office365-Exchange": {"kind": "Office365", "statuses": {"Success": 400}}})
    assert out["healthy"] == ["Office365-Exchange"]
    assert out["unreported"] == []


def test_a_failing_connector_is_called_unhealthy():
    out = connector_outcomes({"Office365"}, {
        "Office365-Exchange": {"kind": "Office365",
                               "statuses": {"Success": 4, "Failure": 9}}})
    assert out["unhealthy"] == ["Office365-Exchange"]


def test_informational_is_not_a_failure():
    out = connector_outcomes({"Office365"}, {
        "O365": {"kind": "Office365",
                 "statuses": {"Success": 4, "Informational": 2}}})
    assert out["healthy"] == ["O365"]


def test_observed_rows_beat_the_documented_list():
    """A connector reporting rows is judged on those rows even if the docs do
    not list it."""
    assert not reports_health("MicrosoftThreatProtection")
    out = connector_outcomes({"MicrosoftThreatProtection"}, {
        "XDR": {"kind": "MicrosoftThreatProtection", "statuses": {"Success": 694}}})
    assert out["healthy"] == ["XDR"]
    assert out["unreported"] == []


def test_the_three_buckets_do_not_overlap():
    kinds = {"Office365", "MicrosoftCloudAppSecurity", "AzureActiveDirectory",
             "MicrosoftDefenderAdvancedThreatProtection"}
    out = connector_outcomes(kinds, {
        "O365": {"kind": "Office365", "statuses": {"Success": 1}},
        "MDE": {"kind": "MicrosoftDefenderAdvancedThreatProtection",
                "statuses": {"Failure": 1}}})
    everything = out["healthy"] + out["unhealthy"] + out["unreported"]
    assert len(everything) == len(set(everything))
    assert out["unreported"] == ["AzureActiveDirectory", "MicrosoftCloudAppSecurity"]


def test_no_connectors_at_all_says_nothing():
    assert connector_outcomes(None, None) == {
        "healthy": [], "unhealthy": [], "unreported": []}


def test_the_list_has_the_seven_microsoft_documents():
    """The supported list holds exactly the seven kinds Microsoft documents."""
    assert len(HEALTH_REPORTS_FOR) == 7, sorted(HEALTH_REPORTS_FOR)

"""Connectors are reported as sources, and only where this tenant already
expects one. There is no recommended list."""

import pytest

from pylon import connectors
from pylon.analysis_model import Connector

SOLUTION = {"display_name": "Office 365", "solution_id": "office365",
            "requires_connectors": ["Office365"], "data_types": ["OfficeActivity"]}


# ── evidence, or nothing ─────────────────────────────────────────────────────

def test_a_solution_declaring_a_connector_is_evidence():
    why = connectors.expected([SOLUTION], [])
    assert "Office365" in why
    assert "the installed Office 365 solution declares it" in why["Office365"]


def test_a_rule_reading_its_table_is_evidence():
    rules = [{"name": "Exchange rule", "tables_referenced": ["OfficeActivity"]}]
    why = connectors.expected([], rules)
    assert "Office365" in why
    assert "1 deployed rule reads a table only it fills" in why["Office365"][0]


def test_a_tenant_that_expects_nothing_gets_no_rows():
    """No solution and no rule means no connector rows at all."""
    assert connectors.expected([], []) == {}
    assert connectors.assess([], [], set()) == []


def test_a_table_several_connectors_could_fill_is_no_evidence():
    """A table several connectors could fill is no evidence for any one of
    them."""
    rules = [{"name": "Alerts", "tables_referenced": ["SecurityAlert"]}]
    assert connectors.expected([], rules) == {}


def test_every_row_carries_its_evidence():
    for row in connectors.assess([SOLUTION], [], {"MicrosoftThreatProtection"}):
        assert row["because"], row


# ── the three states ─────────────────────────────────────────────────────────

def test_a_connector_the_scan_saw_is_present():
    rows = {r["connector"]: r for r in
            connectors.assess([], [], {"MicrosoftThreatProtection"})}
    assert rows["MicrosoftThreatProtection"]["state"] == "present"


def test_an_expected_connector_that_is_absent_says_so():
    rows = {r["connector"]: r for r in
            connectors.assess([SOLUTION], [], {"MicrosoftThreatProtection"})}
    assert rows["Office365"]["state"] == "expected-absent"


def test_nothing_is_called_absent_when_the_leg_did_not_run():
    """With the connector leg unrun, nothing is called absent."""
    rows = connectors.assess([SOLUTION], [], None)
    assert [r["state"] for r in rows] == ["not-established"]
    assert any("could not be read" in w for w in rows[0]["because"])


def test_a_present_connector_is_not_also_reported_missing():
    """Matching is case folded, so a present connector is not also reported
    missing."""
    rows = connectors.assess([SOLUTION], [], {"office365"})
    assert [r["state"] for r in rows] == ["present"]


# ── the document ─────────────────────────────────────────────────────────────

def test_the_model_carries_the_three_states():
    for state in ("present", "expected-absent", "not-established"):
        assert Connector(connector="X", state=state).state == state


def test_an_invented_state_is_refused():
    with pytest.raises(Exception):
        Connector(connector="X", state="probably-fine")


def test_the_section_is_tied_to_a_read():
    """The connectors section is registered in LEGS, so `_legs_agree` checks
    it."""
    from pylon.analysis_model import LEGS

    assert LEGS.get("differential") == "connectors"


def test_the_solution_row_keeps_the_declared_connectors():
    """The solution row keeps the connector ids it declares."""
    from pylon.analysis_model import Solution

    row = Solution(solution_id="s", display_name="S", installed=True,
                   alignment="fed", basis="b", action="none", action_detail="d",
                   requires_connectors=["Office365"])
    assert row.requires_connectors == ["Office365"]

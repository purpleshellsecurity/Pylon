"""A rule the gate enforces and the prompt never states is a trap, not a rule.

The contract gate rejects a query that reads a column the table does not have,
or matches a literal no row carries. Those rules reach the model through
`table_rules` in resource mode -- and reached the dynamic AzureDiagnostics path
through nothing at all. So a run generated against the shared table, the gate
correctly rejected four of eight detections, and the model had never been told
the rules it broke. The one-shot retry could not fix them either, because the
correction prompt does not carry what the original omitted.

This is the second time the same drift has appeared in a week, on two different
paths, which is why it is a test over every path rather than a fix to one.
"""

import pytest

from pylon import contracts, engine
from pylon.prompts import table_rules


def _dataplane_prompt(provider: str, categories: tuple[str, ...]) -> str:
    request = engine.EngineRequest(
        platform="dataplane", service="AzureDiagnostics", max_cost=0.0)
    request.az_diag_provider = provider
    request.az_diag_categories = categories
    return engine._build_prompt(request, "detection")


def test_the_shared_table_path_carries_its_contract():
    text = _dataplane_prompt("Microsoft.Automation",
                             ("AuditEvent", "JobLogs", "JobStreams"))
    assert contracts.render("AzureDiagnostics") in text, (
        "the dynamic AzureDiagnostics path does not carry the contract, so the "
        "gate enforces rules the model was never given")


@pytest.mark.parametrize("column", [
    "targetResources_Resource_s",   # what separates a credential from a runbook
    "clientInfo_ObjectId_g",        # the caller that is NOT redacted
])
def test_the_columns_the_gate_checks_are_named_in_that_prompt(column):
    text = _dataplane_prompt("Microsoft.Automation", ("AuditEvent",))
    assert column in text


def test_the_redaction_is_stated_where_the_query_is_written():
    """Knowing clientInfo_PrincipalName_s exists is worse than useless without
    knowing it always holds "{scrubbed}"."""
    text = _dataplane_prompt("Microsoft.Automation", ("AuditEvent",))
    assert "REDACTED" in text and "clientInfo_PrincipalName_s" in text


@pytest.mark.parametrize("table", sorted(contracts.tables()))
def test_every_contract_reaches_a_prompt_somehow(table):
    """Resource mode goes through `table_rules`. The shared table has its own
    builder. Either way the contract has to arrive somewhere."""
    rendered = contracts.render(table)
    assert rendered, f"{table} renders nothing"
    if table == "AzureDiagnostics":
        assert rendered in _dataplane_prompt("Microsoft.Automation", ("AuditEvent",))
    else:
        assert rendered in table_rules(table)

"""Offline KQL verification (F4) — datatable script + result handling, mocked."""

from pylon.kusto_offline import build_check_script, schema_for_table, verify_query_offline


def test_build_script_declares_typed_datatable():
    script = build_check_script(
        'AzureActivity | where OperationNameValue =~ "X"',
        "AzureActivity",
        {"OperationNameValue": "string", "Caller": "string"},
    )
    assert script.startswith("let AzureActivity = datatable(")
    assert "OperationNameValue:string" in script
    # Sentinel-injected columns are always present so their absence never masks drift
    assert "TimeGenerated:datetime" in script
    assert script.rstrip().endswith('| where OperationNameValue =~ "X"')


def test_offline_ok_when_executor_reports_success():
    res = verify_query_offline(
        "AzureActivity | project Caller", "AzureActivity", {"Caller": "string"},
        executor=lambda script: (True, ""),
    )
    assert res.ran and res.ok and res.error == ""


def test_offline_catches_fabricated_column():
    # The engine rejects an unresolved column — the class static regex can't see.
    def engine(script):
        return (False, "Failed to resolve column reference 'ActorRiskScore'")

    res = verify_query_offline(
        "AzureActivity | where ActorRiskScore > 5", "AzureActivity",
        {"Caller": "string"}, executor=engine,
    )
    assert res.ran and not res.ok and "ActorRiskScore" in res.error


def test_offline_not_run_without_endpoint(monkeypatch):
    monkeypatch.delenv("PYLON_KUSTAINER_URL", raising=False)
    res = verify_query_offline("AzureActivity", "AzureActivity", {"Caller": "string"})
    assert not res.ran and "kustainer" in res.error


def test_executor_exception_is_not_ran():
    def boom(script):
        raise RuntimeError("container down")

    res = verify_query_offline("X", "AzureActivity", {"Caller": "string"}, executor=boom)
    assert not res.ran and "container down" in res.error


def test_schema_for_table_from_hardcoded():
    # AzureActivity has a hardcoded validator schema (names -> string).
    schema = schema_for_table("AzureActivity")
    assert schema.get("Caller") == "string" and "OperationNameValue" in schema


# --- the datatable must carry the REAL types -------------------------------
# A name-only schema types every column `string`, and kusto_offline builds its
# empty datatable from exactly that. Two failures follow, and both make the gate
# worse than useless because it rejects CORRECT queries:
#   * a real column the name list omits fails as unresolved. AzureActivity's
#     reference carries 37 columns; the name list had 16.
#   * a dynamic column declared string breaks the queries that matter. The Entra
#     rules require an mv-expand over TargetResources, which only works on dynamic.

import pytest

from pylon.kusto_offline import schema_for_table


@pytest.mark.parametrize("table,column", [
    ("AuditLogs", "InitiatedBy"),
    ("AuditLogs", "TargetResources"),
    ("AuditLogs", "AdditionalDetails"),
    ("AZKVAuditLogs", "Identity"),
])
def test_a_dynamic_column_is_not_flattened_to_string(table, column):
    assert schema_for_table(table).get(column) == "dynamic", (
        f"{table}.{column} must stay dynamic; as a string every mv-expand and "
        "dot-access over it fails for a reason that is not the detection's fault")


@pytest.mark.parametrize("table,least", [
    ("AzureActivity", 37), ("AuditLogs", 31), ("AZKVAuditLogs", 51),
])
def test_the_schema_is_the_whole_table_not_a_sample(table, least):
    """A short schema rejects real columns, which is the gate firing backwards."""
    assert len(schema_for_table(table)) >= least


def test_azureactivity_knows_the_column_that_warned_on_a_live_run():
    """`EventDataId` is real, and the 16-name list did not carry it."""
    assert "EventDataId" in schema_for_table("AzureActivity")


# --- Sentinel-only functions must not fail the offline gate -----------------
# `_GetWatchlist` is a Sentinel function, not KQL, and the detection prompt marks
# the exclusion scaffolding that uses it REQUIRED. Sent to a bare engine as
# written, the gate failed precisely the queries that followed the house rule and
# passed the ones that ignored it, reporting only "Request is invalid".

from pylon.kusto_offline import build_check_script, substitute_sentinel_functions

_SCAFFOLD = "let AllowedActors = _GetWatchlist('ApprovedAutomation') | project SearchKey;"


def test_the_required_exclusion_scaffolding_becomes_its_own_fallback():
    """The query authors `// let AllowedActors = dynamic([]);` one line down."""
    assert substitute_sentinel_functions(_SCAFFOLD) == "let AllowedActors = dynamic([]);"


def test_a_bare_watchlist_call_is_also_substituted():
    out = substitute_sentinel_functions("let A = _GetWatchlist('Approved');")
    assert "_GetWatchlist" not in out
    assert "dynamic([])" in out


def test_a_query_using_no_sentinel_function_is_untouched():
    kql = "AuditLogs\n| where TimeGenerated > ago(1h)\n| take 1"
    assert substitute_sentinel_functions(kql) == kql


def test_the_check_script_never_ships_a_sentinel_only_call():
    script = build_check_script(
        f"{_SCAFFOLD}\nAuditLogs\n| where TimeGenerated > ago(1h)",
        "AuditLogs", {"OperationName": "string"})
    assert "_GetWatchlist" not in script, (
        "kustainer rejects the whole batch and names no line, so this must be "
        "caught here rather than read out of a 400")

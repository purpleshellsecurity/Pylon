"""A query is not confined to one table, and the column check assumed it was.

The prompt REQUIRES this line, on every plane:

    let AllowedActors = _GetWatchlist('ApprovedAutomation') | project SearchKey;

`SearchKey` is a column of the WATCHLIST. The check walked every identifier in
the query and measured each against the target table's schema, so it read the
scaffolding the prompt mandates as a fabricated column. Harmless as a warning;
once the finding became an error it killed 16 of 19 detections in a live Entra
run, every one with the same message, and the run reported 17% yield.

A `let` binding whose body never names the target table is a foreign scope. A
binding that DOES read the target table stays in scope, because that is where a
real fabrication hides.
"""

import pytest

from pylon.validation.schemas import TABLE_SCHEMAS
from pylon.validation.validate_kql import _foreign_scope_names, validate_kql

_SCAFFOLD = ("let AllowedActors = _GetWatchlist('ApprovedAutomation') "
             "| project SearchKey;\n"
             "// let AllowedActors = dynamic([]);  // fallback: no watchlist\n")


def _docs(table: str) -> frozenset[str]:
    return frozenset(TABLE_SCHEMAS[table])


@pytest.mark.parametrize("table,filter_col", [
    ("AuditLogs", "OperationName"),
    ("AzureActivity", "OperationNameValue"),
    ("AZKVAuditLogs", "OperationName"),
    ("StorageBlobLogs", "OperationName"),
])
def test_the_scaffolding_the_prompt_mandates_validates(table, filter_col):
    kql = (f'{_SCAFFOLD}{table}\n| where TimeGenerated > ago(1h)\n'
           f'| where {filter_col} != ""\n| project TimeGenerated, {filter_col}')
    result = validate_kql(kql, table, documented=_docs(table))
    assert result.valid, result.errors
    assert not any("SearchKey" in f for f in result.errors + result.warnings)


def test_a_fabrication_beside_the_scaffolding_is_still_caught():
    """The scaffolding must not become a blanket amnesty for the whole query."""
    kql = (f'{_SCAFFOLD}AuditLogs\n| where TimeGenerated > ago(1h)\n'
           f'| project TimeGenerated, ThreatLevel')
    result = validate_kql(kql, "AuditLogs", documented=_docs("AuditLogs"))
    assert not result.valid
    assert any("ThreatLevel" in e for e in result.errors)


def test_a_let_that_reads_the_target_table_stays_in_scope():
    """Baseline sub-queries are the most common real place to invent a column, so
    a binding that reads the target table is not foreign."""
    kql = ("let Baseline = AZKVAuditLogs | where ActorRiskScore > 5 | count;\n"
           "AZKVAuditLogs\n| where TimeGenerated > ago(1h)\n"
           '| where OperationName == "SecretGet"')
    result = validate_kql(kql, "AZKVAuditLogs", documented=_docs("AZKVAuditLogs"))
    assert not result.valid
    assert any("ActorRiskScore" in e for e in result.errors)


def test_foreign_scope_reads_only_the_bindings_that_are_foreign():
    kql = ("let Allowed = _GetWatchlist('X') | project SearchKey;\n"
           "let Mine = AuditLogs | project Result;\n"
           "AuditLogs | take 1")
    foreign = _foreign_scope_names(kql, "AuditLogs")
    assert "SearchKey" in foreign
    assert "Result" not in foreign


def test_an_unterminated_let_does_not_swallow_the_query():
    """A missing semicolon must not turn the whole query into a foreign scope and
    silently disable the column check for everything after it."""
    kql = ("let Allowed = _GetWatchlist('X') | project SearchKey\n"
           "AuditLogs\n| project TimeGenerated, ThreatLevel")
    result = validate_kql(kql, "AuditLogs", documented=_docs("AuditLogs"))
    assert not result.valid, "an unterminated let disabled the check"

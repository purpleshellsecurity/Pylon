"""A prompt must not instruct a column the gate rejects.

The generic data-plane NORMALIZE rule said `Operation = OperationName`, and
`validate_kql` errors on `OperationName` for FunctionAppLogs, which has no such
column -- its contract names `Category`. So one prompt carried both

    - filter the operation on `Category` with `=~`          (the contract)
    - | extend ... Operation = OperationName                (the plane rule)

and a detection obeying the second was rejected, costing a corrective retry to
undo what the prompt required. Same shape as the exclusion-scaffolding rule that
was removed for exactly this: the gates refused what the prompt demanded.

The rule defers to the contract's operation column now.
"""
import pytest

from pylon import contracts
from pylon.prompts import table_rules
from pylon.validation.validate_kql import validate_kql

# Tables whose operation column is NOT `OperationName`, which is the case the
# hardcoded rule got wrong.
ODD = [t for t in contracts.tables()
       if ((contracts.for_table(t) or {}).get("operation") or {}).get("column")
       not in (None, "OperationName")]


def test_there_is_a_table_whose_operation_column_is_not_operationname():
    """Guards the premise. If every table used OperationName the rule would be
    harmless and this file could go."""
    assert ODD, "no table disagrees; this rule no longer needs deferring"


@pytest.mark.parametrize("table", ODD)
def test_the_prompt_does_not_hardcode_operationname_for_it(table):
    import re

    rules = table_rules(table)
    # Word-bounded: `Operation = OperationNameValue` is AzureActivity's own
    # correct column and is a prefix of the wrong one.
    assert not re.search(r"Operation = OperationName\b(?!Value)", rules), (
        f"{table}'s prompt mandates OperationName; its contract names "
        f"{((contracts.for_table(table) or {}).get('operation') or {}).get('column')}")


@pytest.mark.parametrize("table", ODD)
def test_a_query_shaped_like_the_prompt_passes_its_own_gate(table):
    """The end-to-end version: build what the prompt asks for and validate it.
    A prompt whose own output fails validation costs a model call every run."""
    column = ((contracts.for_table(table) or {}).get("operation") or {}).get("column")
    query = (f"{table}\n| where TimeGenerated > ago(1h)\n"
             f'| extend ActorUpn = "", ActorId = "", SrcIp = "", '
             f"TargetResource = _ResourceId, Operation = {column}\n"
             f"| project TimeGenerated, ActorUpn, ActorId, SrcIp, "
             f"TargetResource, Operation\n")
    result = validate_kql(query, table)
    assert result.valid, f"{table}: {result.errors}"


def test_the_gate_still_rejects_the_column_that_does_not_exist():
    """Deferring must not disarm the check -- FunctionAppLogs genuinely has no
    OperationName, and a detection naming it is still wrong."""
    bad = ("FunctionAppLogs\n| where TimeGenerated > ago(1h)\n"
           "| extend Operation = OperationName\n")
    result = validate_kql(bad, "FunctionAppLogs")
    assert not result.valid
    assert any("OperationName" in e for e in result.errors), result.errors

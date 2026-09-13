"""A table contract is one object with two consumers, and the point is that it
cannot become two.

Every defect this gate exists to catch was the same shape: a fact that was true,
written down somewhere, and absent from the place that needed it. So these tests
assert the two directions that matter. What the prompt is told must be what the
checker enforces, and what the checker enforces must be reachable from the
command that generates.

The three contracts were measured against a live workspace. The numbers quoted
in the failure messages below are from that measurement, and they are here so
that a future reader who disagrees knows exactly what to re-measure.
"""

import re

import pytest

from pylon import contracts
from pylon.prompts import table_rules

_TABLES = sorted(contracts.tables())


def test_there_are_contracts_at_all():
    """A loader that silently finds nothing renders nothing and checks nothing,
    and every test below would pass on an empty directory."""
    assert _TABLES, "no contracts loaded — is catalog/contracts shipped?"
    assert "AzureActivity" in _TABLES


@pytest.mark.parametrize("table", _TABLES)
def test_every_contract_names_the_operation_column(table):
    op = (contracts.for_table(table) or {}).get("operation") or {}
    assert op.get("column"), f"{table} does not say what to filter the operation on"
    assert op.get("operator") in ("==", "=~"), f"{table} has no usable operator"


@pytest.mark.parametrize("table", _TABLES)
def test_every_contract_renders_into_the_prompt(table):
    """A contract that loads and does not reach the model is decoration."""
    rendered = contracts.render(table)
    assert rendered, f"{table} renders empty"
    assert rendered in table_rules(table), (
        f"{table}'s contract does not reach the prompt through table_rules")


@pytest.mark.parametrize("table", _TABLES)
def test_a_contract_only_claims_recipes_it_can_produce(table):
    """Every recipe must be a formattable template. One with a stray brace
    raises at render time, which would take the whole run with it."""
    for name, body in ((contracts.for_table(table) or {}).get("recipes") or {}).items():
        fields = set(re.findall(r"\{(\w+)\}", body))
        assert fields, f"{table}/{name} has no parameters — it cannot be reused"
        body.format(**{f: "x" for f in fields})   # raises on a malformed template


@pytest.mark.parametrize("table", _TABLES)
def test_a_contracts_own_recipes_pass_its_own_check(table):
    """The clearest way for the two halves to drift is for the advice to violate
    the rule. Instantiate every recipe and run the checker over it."""
    c = contracts.for_table(table)
    for name, body in (c.get("recipes") or {}).items():
        fields = set(re.findall(r"\{(\w+)\}", body))
        filled = body.format(**{f: ("0" if f == "threshold" else
                                    table if f == "table" else
                                    "logs" if f == "array" else "x") for f in fields})
        assert contracts.conforms(filled, table) == [], (
            f"{table}/{name} is offered as a model and fails the check")


def test_a_table_with_no_contract_is_not_a_table_with_no_problems():
    """`conforms` returns [] both for a clean query and for a table nobody has
    contracted. A caller reporting a verdict must be able to tell them apart,
    which is what `tables()` is for."""
    uncontracted = "SigninLogs"      # deliberately outside the current frame
    assert uncontracted not in contracts.tables()
    assert contracts.conforms(f"{uncontracted} | take 1", uncontracted) == []


# --- the three defects that shipped, one test each -------------------------

def test_a_column_that_is_present_and_always_empty_is_caught():
    """OperationName exists on AzureActivity and is populated on 0 of 2000 rows.
    A detection filtering it parses, runs, and matches nothing, which is
    indistinguishable from an attack that did not happen."""
    breaches = contracts.conforms(
        'AzureActivity | where TimeGenerated > ago(1d) | where OperationName =~ "x"',
        "AzureActivity")
    assert any("OperationName" in b for b in breaches)


def test_a_string_column_compared_numerically_is_caught():
    """StorageBlobLogs types StatusCode as string even though it holds "201".
    `StatusCode < 300` is a semantic error and the query does not run at all."""
    assert contracts.conforms(
        "StorageBlobLogs | where TimeGenerated > ago(1d) | where StatusCode < 300",
        "StorageBlobLogs")
    assert contracts.conforms(
        "StorageBlobLogs | where TimeGenerated > ago(1d) | where toint(StatusCode) < 300",
        "StorageBlobLogs") == [], "the documented cast must be accepted"


def test_an_unattributable_principal_is_caught():
    """Measured: 38 of 196 storage rows carry RequesterObjectId, and every one of
    them has AuthenticationType OAuth. Projecting it without that filter yields a
    detection that runs, matches, and names nobody."""
    assert contracts.conforms(
        "StorageBlobLogs | where TimeGenerated > ago(1d) | project RequesterObjectId",
        "StorageBlobLogs")
    assert contracts.conforms(
        'StorageBlobLogs | where TimeGenerated > ago(1d) '
        '| where AuthenticationType == "OAuth" | project RequesterObjectId',
        "StorageBlobLogs") == []


# --- the checker must not fire on things that are not reads ----------------

def test_a_column_named_only_in_a_comment_is_not_a_read():
    assert contracts.conforms(
        'AzureActivity | where TimeGenerated > ago(1d) // OperationName is wrong\n'
        '| where OperationNameValue =~ "x"', "AzureActivity") == []


def test_a_column_named_only_inside_a_string_is_not_a_read():
    assert contracts.conforms(
        'AzureActivity | where TimeGenerated > ago(1d) '
        '| where OperationNameValue =~ "ResourceId"', "AzureActivity") == []


def test_a_longer_column_that_merely_contains_a_banned_name_is_not_a_read():
    """`_ResourceId` is the column to use and `ResourceId` is the one that is
    always empty. A substring match would reject the correct query."""
    assert contracts.conforms(
        "AzureActivity | where TimeGenerated > ago(1d) | project _ResourceId",
        "AzureActivity") == []


# --- the gate must actually fire from the engine ---------------------------
#
# The helper being right is worth nothing if nothing calls it. Every regression
# in this project's history had that shape: a value computed correctly in one
# place and never carried to the next. So this reaches in through the real
# pipeline rather than calling `conforms` again.

def test_the_contract_gate_is_reachable_from_the_engine():
    """`_checked` is defined inside `pylon.run`, so it cannot be imported. What
    CAN be asserted from outside is that the engine module holds the reference
    and the gate text it emits, which is what makes the call site real."""
    import inspect

    from pylon import contracts, engine

    source = inspect.getsource(engine)
    assert "contracts.conforms(" in source, (
        "the engine no longer calls the contract check — the gate is dead code")
    assert '_gate("contract"' in source, (
        "the contract gate no longer records a verdict, so a breach is invisible "
        "in the run log")
    assert "contracts" in dir(engine), "the engine does not import contracts"


def test_a_breach_is_worded_for_the_model_that_has_to_fix_it():
    """The retry loop feeds these strings straight back to the model. A message
    naming the column and what is wrong with it is the difference between a
    corrective retry and a second identical answer."""
    from pylon import contracts

    breaches = contracts.conforms(
        "StorageBlobLogs | where TimeGenerated > ago(1d) | where StatusCode < 300",
        "StorageBlobLogs")
    assert breaches
    text = breaches[0]
    assert "StatusCode" in text, "the message must name the column"
    assert "string" in text, "and say what is actually wrong with it"

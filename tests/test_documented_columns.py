"""Microsoft's column list, on both sides of the run.

The prompt has been grounded on the Azure Monitor table reference all along. The
validator was not -- it judged against `TABLE_SCHEMAS`, which the module's own
docstring says is "extracted from the validated context assets": the columns the
PROMPT teaches, not the columns the TABLE has. AzureActivity lists sixteen there
and Microsoft documents thirty-seven.

That gap is harmless while the finding is a warning and fatal once it is an
error. A live Key Vault run rejected a correct detection filtering on
`OperationId` -- a real column, absent from the sixteen.

These tests need the network. They skip rather than fail when it is unavailable,
because an unreachable reference is an environment fact and not a defect, which
is the same rule the checker itself follows.
"""

import asyncio

import pytest

from pylon.grounding import documented_columns
from pylon.validation.schemas import TABLE_SCHEMAS

_TABLES = ["AzureActivity", "AZKVAuditLogs", "AuditLogs",
           "StorageBlobLogs", "StorageFileLogs", "StorageQueueLogs",
           "StorageTableLogs"]


def _fetch(table: str) -> frozenset[str]:
    cols = asyncio.run(documented_columns(table))
    if not cols:
        pytest.skip(f"Azure Monitor reference unreachable for {table}")
    return cols


@pytest.mark.parametrize("table", _TABLES)
def test_the_documented_list_covers_what_the_prompt_teaches(table):
    """The prompt cannot teach a column Microsoft does not document. Where it
    does, one of the two is wrong and a person should look."""
    missing = set(TABLE_SCHEMAS.get(table, [])) - _fetch(table)
    # `_ResourceId` is a Log Analytics column Microsoft omits from some pages.
    assert missing <= {"_ResourceId"}, (
        f"{table}: the prompt teaches columns the reference does not document: "
        f"{sorted(missing)}"
    )


@pytest.mark.parametrize("table", _TABLES)
def test_every_table_documents_the_column_every_query_uses(table):
    """The guard on the truncation bug. The column block was capped at 3,000
    characters, which cut AzureActivity's table at 30 rows of 38 and dropped
    TimeGenerated, SubscriptionId, Type and ResourceProvider. Judging against
    that list would have rejected every query ever written."""
    assert "TimeGenerated" in _fetch(table)


def test_the_column_the_live_run_was_rejected_for_is_documented():
    assert "OperationId" in _fetch("AzureActivity")
    assert "OperationId" not in TABLE_SCHEMAS["AzureActivity"]


def test_the_list_is_a_superset_worth_having():
    """If the fetch added nothing, the whole mechanism is ceremony."""
    extra = _fetch("AzureActivity") - set(TABLE_SCHEMAS["AzureActivity"])
    assert len(extra) >= 10, f"only {len(extra)} columns beyond the prompt's list"


def test_an_unreachable_reference_returns_empty_not_a_verdict(monkeypatch):
    """Empty means UNREACHABLE. A caller that read it as "this table has no
    columns" would reject every query, which is the failure mode this whole file
    exists to prevent."""
    import pylon.grounding as g

    async def _dead(url):
        return ""

    monkeypatch.setattr(g, "_fetch_cached", _dead)
    assert asyncio.run(g.documented_columns("AzureActivity")) == frozenset()

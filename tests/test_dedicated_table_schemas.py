"""Dedicated tables must not be described with AzureDiagnostics column names.

A service that has migrated from the shared `AzureDiagnostics` table to its own
resource-specific one has TWO documented spellings for the same field, and only
one of them exists in the dedicated table. Key Vault writes `identity_s`, `id_s`,
`httpStatusCode_d` and `CallerIPAddress` into AzureDiagnostics; the dedicated
`AZKVAuditLogs` has `Identity`, `Id`, `HttpStatusCode` and `CallerIpAddress`.

That mix-up shipped. The grounding asset described the dedicated table using the
AzureDiagnostics convention, `TABLE_SCHEMAS` listed the same names, and so
`validate_kql` PASSED a generated query that the live workspace then rejected
with "Failed to resolve scalar expression named 'identity_s'". Static validation
cannot catch a hallucination it was taught.

These tests are the guard rail. Suffixed names are allowed in exactly one place —
the "Fields That DO NOT Exist" section, where naming them is the point.
"""

import re
from pathlib import Path

import pytest

from pylon.validation.schemas import TABLE_SCHEMAS
from pylon.validation.validate_kql import validate_kql

ASSETS = Path(__file__).resolve().parents[1] / "src/pylon/prompts/assets/tables"

# The AzureDiagnostics dynamic-column convention: the property name plus a type
# suffix. Documented at
# https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics
_SUFFIXED = re.compile(r"\b[A-Za-z][A-Za-z0-9_]*_(?:s|d|g|b|t|i)\b")

_DO_NOT_EXIST = "### Fields That DO NOT Exist"


def _asset_files():
    return sorted(ASSETS.glob("*.md"))


def test_the_assets_are_actually_there():
    assert len(_asset_files()) > 5


@pytest.mark.parametrize("path", _asset_files(), ids=lambda p: p.stem)
def test_no_asset_teaches_an_azurediagnostics_column_as_a_real_one(path):
    """Everything above 'Fields That DO NOT Exist' is a claim that the column
    exists. A suffixed name there is the bug this file exists for."""
    text = path.read_text(encoding="utf-8")
    claims = text.split(_DO_NOT_EXIST)[0]
    found = sorted(set(_SUFFIXED.findall(claims)))
    assert not found, f"{path.name} claims AzureDiagnostics columns as real: {found}"


@pytest.mark.parametrize("path", _asset_files(), ids=lambda p: p.stem)
def test_no_asset_shows_a_suffixed_column_in_a_query_it_calls_correct(path):
    # The "Confirmed Rules" block is copied more or less verbatim by the model, so
    # a wrong column there does more damage than one in a bullet list.
    for line in path.read_text(encoding="utf-8").splitlines():
        if "CORRECT" in line and "WRONG" not in line:
            assert not _SUFFIXED.findall(line), f"{path.name}: {line.strip()}"


@pytest.mark.parametrize("table", sorted(TABLE_SCHEMAS), ids=str)
def test_no_vendored_schema_lists_an_azurediagnostics_column(table):
    """`validate_kql` is only as good as this list. A wrong name here is worse
    than a missing one: it converts a hallucination into a pass."""
    bad = [c for c in TABLE_SCHEMAS[table] if _SUFFIXED.fullmatch(c)]
    assert not bad, f"{table}: {bad}"


def test_the_key_vault_schema_is_the_dedicated_tables_and_not_the_shared_ones():
    """Pinned by name because this is the one that was wrong, and because the
    pairs differ only by case in one instance — which KQL cares about."""
    columns = set(TABLE_SCHEMAS["AZKVAuditLogs"])
    assert {"Identity", "Id", "HttpStatusCode", "CallerIpAddress"} <= columns
    assert not columns & {"identity_s", "id_s", "httpStatusCode_d", "CallerIPAddress"}


def test_validate_kql_now_rejects_the_query_the_workspace_rejected():
    """The exact failure from a real run: generated, passed every static check,
    then refused by the tenant. It must not pass now."""
    result = validate_kql(
        'AZKVAuditLogs\n| where OperationName == "Authentication"\n'
        "| extend CallerIdentity = parse_json(identity_s)",
        "AZKVAuditLogs",
    )
    assert not result.valid
    assert any("identity_s" in e for e in result.errors)


def test_validate_kql_accepts_the_query_that_did_run():
    result = validate_kql(
        'AZKVAuditLogs\n| where OperationName == "Authentication"\n'
        '| where ResultType == "Success"\n'
        "| extend CallerUPN = tostring(Identity.claim.upn)\n"
        "| extend SrcIp = tostring(CallerIpAddress)\n"
        "| project TimeGenerated, CallerUPN, SrcIp, HttpStatusCode, _ResourceId",
        "AZKVAuditLogs",
    )
    assert result.valid, result.errors


def test_the_storage_tables_cross_reference_points_at_the_right_table():
    # These four say identity_s is not one of their columns, which is true and
    # worth saying. It used to attribute it to AZKVAuditLogs, which is where the
    # dedicated Key Vault table does NOT have it either.
    for name in ("StorageBlobLogs", "StorageQueueLogs", "StorageFileLogs", "StorageTableLogs"):
        text = (ASSETS / f"{name}.md").read_text(encoding="utf-8")
        line = next(ln for ln in text.splitlines() if "identity_s" in ln)
        assert "AzureDiagnostics field" in line
        assert not line.strip().endswith("AZKVAuditLogs field")

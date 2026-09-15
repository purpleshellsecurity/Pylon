"""A comment must not fail a query.

34 of the 38 regex checks in `validate_kql` scanned the raw query, so a comment
was read as code. A correct AzureActivity detection carrying

    // Caller holds the identity; there is no UserPrincipalName on this table.

was rejected for naming the column it was warning against, and the corrective
retry told the model to fix a query that was already right.

That is the failure this file's own mv-expand check was written to stop, and its
comment claimed "Every other rule in this file already scans the blanked source"
-- which was backwards: four did.

COMMENTS ONLY are removed. String literals are kept, because several checks read
what is inside the quotes -- `OperationName == "..."` needs the value to judge
the casing, and the operation-vocabulary check needs it to judge the name.
"""
import ast
import pathlib

import pytest

from pylon.validation.validate_kql import _blank_comments, validate_kql

SRC = pathlib.Path(__file__).resolve().parents[1] / "src/pylon/validation/validate_kql.py"

# (table, query, what a raw scan would wrongly report)
CORRECT_BUT_COMMENTED = [
    ("AzureActivity",
     'AzureActivity\n'
     '| where OperationNameValue =~ "Microsoft.Storage/storageAccounts/write"\n'
     '// Caller holds the identity; there is no UserPrincipalName on this table.\n'
     '| project TimeGenerated, Caller, CallerIpAddress\n'),
    ("AzureActivity",
     'AzureActivity\n'
     '// TargetResources and InitiatedBy belong to AuditLogs, not here.\n'
     '| where OperationNameValue =~ "Microsoft.Web/sites/write"\n'
     '| project TimeGenerated, Caller\n'),
    ("StorageBlobLogs",
     'StorageBlobLogs\n'
     '| where TimeGenerated > ago(1h)\n'
     '// Note: the column is CallerIpAddress, not CallerIPAddress.\n'
     '| project TimeGenerated, CallerIpAddress\n'),
    ("AuditLogs",
     'AuditLogs\n'
     '| where TimeGenerated > ago(1h)\n'
     '// Do not write OperationName == "Add member to role"; casing varies.\n'
     '| where OperationName =~ "Add member to role"\n'
     '| project TimeGenerated, OperationName, Result\n'),
]


@pytest.mark.parametrize("table,query", CORRECT_BUT_COMMENTED,
                         ids=lambda v: v if isinstance(v, str) and "\n" not in v else "")
def test_an_explanatory_comment_does_not_fail_a_correct_query(table, query):
    result = validate_kql(query, table)
    assert result.valid, (
        f"a comment was read as code: {result.errors}")


# The rules must still fire on the real thing -- a gate that stops firing is
# worse than one that fires wrongly.
STILL_CAUGHT = [
    ("AzureActivity", 'AzureActivity\n| project UserPrincipalName\n', "UserPrincipalName"),
    ("AzureActivity", 'AzureActivity\n| where OperationName == "x"\n', "OperationNameValue"),
    ("AzureActivity", 'AzureActivity\n| extend a = InitiatedBy\n', "InitiatedBy"),
    ("StorageBlobLogs", 'StorageBlobLogs\n| where CallerIPAddress == "1.2.3.4"\n', "lowercase p"),
    ("StorageBlobLogs", 'StorageBlobLogs\n| where StatusCode >= 400\n', "STRING"),
    ("AuditLogs", 'AuditLogs\n| where OperationName == "Add member to role"\n', "CASE-SENSITIVE"),
    ("AuditLogs", 'AuditLogs\n| where ActivityStatusValue == "Success"\n', "does not exist"),
]


@pytest.mark.parametrize("table,query,expected", STILL_CAUGHT,
                         ids=[c[2] for c in STILL_CAUGHT])
def test_the_rule_still_fires_on_real_code(table, query, expected):
    result = validate_kql(query, table)
    assert any(expected in e for e in result.errors), (
        f"the rule stopped firing: {result.errors}")


def test_string_literals_survive_the_blanking():
    """Several checks read inside the quotes. Blanking strings as well as
    comments would silently disable them."""
    out = _blank_comments('| where OperationName == "Add member" // a note here')
    assert '"Add member"' in out, out
    assert "a note here" not in out, out


def test_no_per_table_check_reads_the_raw_query_again():
    """The whole point. Any new `re.<fn>(..., kql)` inside validate_kql is this
    bug returning, so it is counted rather than trusted."""
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "validate_kql")
    offenders = []
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("search", "finditer", "findall", "match")
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "re"
                and len(n.args) > 1 and isinstance(n.args[1], ast.Name)
                and n.args[1].id == "kql"):
            offenders.append(n.lineno)
    assert offenders == [], (
        f"these scan the raw query, so a comment can fail it: lines {offenders}")


def test_a_url_is_not_a_comment():
    """The `//` in `https://` is inside a string literal.

    `_blank_comments` stripped from any `//`, so a URL deleted its own closing
    quote and the rest of its line. Everything after it left the 34 checks that
    read the blanked source -- the direction that SHIPS a defect rather than
    rejecting good work: an `OperationName == "PutBlobb"` sharing a line with a
    blob endpoint validated clean.
    """
    query = (
        'StorageBlobLogs\n'
        '| where AuthenticationType == "OAuth"\n'
        '| where Uri has "https://acct.blob.core.windows.net/" '
        'and OperationName == "PutBlobb"\n'
    )
    assert 'OperationName == "PutBlobb"' in _blank_comments(query)
    assert any("PutBlobb" in e for e in validate_kql(query, "StorageBlobLogs").errors)


def test_a_comment_after_a_url_is_still_a_comment():
    """The fix must not go the other way and keep every `//`."""
    out = _blank_comments('| where Uri has "https://a.example/x" // note here')
    assert '"https://a.example/x"' in out, out
    assert "note here" not in out, out

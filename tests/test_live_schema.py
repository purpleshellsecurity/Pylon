"""Schema-driven validation (docs/DESIGN-any-service.md).

Deterministic (no network): exercises the markdown parser and the schema-aware
validator with literals. The live fetch is proven by running the module's demo
(`python -m pylon.validation.live_schema CDBDataPlaneRequests`).
"""

from pylon.validation.live_schema import (
    merge_results,
    parse_table_schema,
    referenced_columns,
    validate_against_schema,
)
from pylon.validation.validate_kql import ValidationResult

_SAMPLE_DOC = """Intro prose.

## Columns

| Column | Type | Description |
| --- | --- | --- |
| TimeGenerated | datetime | When the event was generated. |
| AccountName | string | The Cosmos account. |
| \\_BilledSize | real | Record size. |
| StatusCode | string | HTTP status code. |
| RequestCharge | real | RU cost. |

## Next section
Not part of the table.
"""

_SCHEMA = {
    "TimeGenerated": "datetime",
    "AccountName": "string",
    "OperationName": "string",
    "StatusCode": "string",
    "RequestCharge": "real",
}


def test_parse_table_schema_reads_columns_and_types():
    schema = parse_table_schema(_SAMPLE_DOC)
    assert schema["TimeGenerated"] == "datetime"
    assert schema["StatusCode"] == "string"
    # The doc escapes leading-underscore names as \\_ — unescape them.
    assert "_BilledSize" in schema
    # Stops at the next section, doesn't swallow prose.
    assert "Not" not in schema


def test_parse_table_schema_missing_table_is_empty():
    assert parse_table_schema("no column table here") == {}


def test_valid_query_passes():
    kql = (
        'CDBDataPlaneRequests\n'
        '| where TimeGenerated > ago(1h)\n'
        '| where OperationName == "Query"\n'
        '| project TimeGenerated, AccountName, StatusCode, RequestCharge'
    )
    res = validate_against_schema(kql, _SCHEMA, "CDBDataPlaneRequests")
    assert res.valid
    assert res.errors == []


def test_fabricated_column_is_flagged():
    kql = (
        'CDBDataPlaneRequests\n'
        '| where TimeGenerated > ago(1h)\n'
        '| project AccountName, ResourceId, ThreatScore'
    )
    res = validate_against_schema(kql, _SCHEMA, "CDBDataPlaneRequests")
    assert not res.valid
    joined = " ".join(res.errors)
    assert "ResourceId" in joined and "ThreatScore" in joined


def test_wrong_case_is_a_warning_not_an_error():
    kql = "CDBDataPlaneRequests\n| where statuscode == \"200\""
    res = validate_against_schema(kql, _SCHEMA, "CDBDataPlaneRequests")
    assert res.valid  # wrong case is advisory, not fatal
    assert any("StatusCode" in w for w in res.warnings)


def test_empty_schema_skips_validation():
    res = validate_against_schema("X | where Foo == 1", {}, "UnknownTable")
    assert res.valid
    assert res.warnings and "skipped" in res.warnings[0].lower()


def test_extractor_ignores_string_literals_and_functions():
    # "InitiatedBy" appears only inside a string literal; tostring() is a function.
    kql = 'T\n| where Note == "InitiatedBy stuff"\n| extend X = tostring(AccountName)'
    refs = referenced_columns(kql, "T")
    assert "InitiatedBy" not in refs   # inside a string literal
    assert "tostring" not in refs      # function call
    assert "X" not in refs             # query-defined alias
    assert "AccountName" in refs       # a real column reference


def test_url_scheme_inside_string_literal_is_not_a_column():
    # Regression: a `//` inside a string literal ("http://") must not be treated
    # as the start of a comment — that would strip the closing quote and leak
    # "http"/"https" as phantom columns (false "fabrication" errors on valid
    # command-line detections).
    schema = {"Timestamp": "datetime", "FileName": "string", "ProcessCommandLine": "string"}
    kql = (
        "DeviceProcessEvents\n"
        "| where Timestamp > ago(1h)\n"
        '| where ProcessCommandLine has "http://" or ProcessCommandLine has "https://"\n'
        '| where ProcessCommandLine has "javascript:"'
    )
    refs = referenced_columns(kql, "DeviceProcessEvents")
    assert "http" not in refs and "https" not in refs and "javascript" not in refs
    res = validate_against_schema(kql, schema, "DeviceProcessEvents")
    assert res.valid
    assert res.errors == []


def test_regex_flag_and_switch_inside_literal_not_columns():
    # "(?i)" regex flag and "/i:" switch live inside string literals; neither the
    # "i" nor the "https" in @"(?i)https?://" may leak as a column.
    schema = {"Timestamp": "datetime", "FileName": "string", "ProcessCommandLine": "string"}
    kql = (
        "DeviceProcessEvents\n"
        '| where FileName =~ "regsvr32.exe"\n'
        '| where ProcessCommandLine contains "scrobj.dll"\n'
        '   or (ProcessCommandLine contains "/i:" and ProcessCommandLine matches regex @"(?i)https?://")'
    )
    refs = referenced_columns(kql, "DeviceProcessEvents")
    assert "i" not in refs and "https" not in refs and "http" not in refs
    assert validate_against_schema(kql, schema, "DeviceProcessEvents").valid


def test_real_comment_still_stripped_and_its_url_ignored():
    # A genuine // comment (and any URL inside it) is still removed, so nothing
    # from the comment is scanned as a column.
    schema = {"Timestamp": "datetime", "FileName": "string"}
    kql = (
        "DeviceProcessEvents\n"
        '| where FileName =~ "x.exe" // ref: http://wiki/NotAColumn\n'
        "| project Timestamp, FileName"
    )
    refs = referenced_columns(kql, "DeviceProcessEvents")
    assert "NotAColumn" not in refs and "http" not in refs
    assert validate_against_schema(kql, schema, "DeviceProcessEvents").valid


def test_always_valid_columns_not_flagged():
    # Defender uses Timestamp, which the LA docs omit; a live schema without it
    # must NOT flag it as fabricated (measured false-positive guard).
    schema = {"DeviceName": "string", "FileName": "string"}
    kql = "DeviceProcessEvents\n| where Timestamp > ago(1h)\n| project DeviceName, FileName, _ResourceId"
    res = validate_against_schema(kql, schema, "DeviceProcessEvents")
    assert res.valid
    assert res.errors == []


def test_merge_results_unions_and_ands():
    a = ValidationResult(valid=True, errors=[], warnings=["w1"])
    b = ValidationResult(valid=False, errors=["e1", "e1"], warnings=["w1", "w2"])
    m = merge_results(a, b)
    assert m.valid is False                 # one invalid -> merged invalid
    assert m.errors == ["e1"]               # deduped
    assert m.warnings == ["w1", "w2"]       # deduped, order preserved

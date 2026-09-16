"""AzureDiagnostics is not a service's table, it is every service's table.

Measured on a workspace with two providers sending: 50 rows, 4 categories, and
231 columns in the table -- a number that is a property of who happens to be
sending, not of any service a detection is about. A query that filters only the
table name returns Automation's runbook output next to SQL's audit statements.

The per-service sections exist for the same reason. The caller is
`clientInfo_PrincipalName_s` on an Automation audit event, `Caller_s` on a job
log, and `server_principal_name_s` on a SQL audit event. One set of column rules
for this table would describe none of them.
"""

import pytest

from pylon import contracts

_T = "AzureDiagnostics"


def _q(body: str) -> str:
    return f"{_T}\n| where TimeGenerated > ago(1h)\n{body}"


def test_the_contract_exists_and_is_per_service():
    c = contracts.for_table(_T)
    assert c, "AzureDiagnostics has no contract"
    services = c.get("services") or {}
    assert len(services) >= 4, "a shared table needs a section per provider/category"
    assert "MICROSOFT.SQL/SQLSecurityAuditEvents" in services
    assert "MICROSOFT.AUTOMATION/JobStreams" in services


def test_reading_the_shared_table_unscoped_is_flagged():
    problems = contracts.conforms(_q("| project Category, Resource"), _T)
    assert problems, "an unscoped read of a shared table must be caught"
    assert "ResourceProvider" in problems[0]


def test_a_provider_filter_alone_is_not_enough():
    """Automation alone still mixes AuditEvent, JobLogs and JobStreams, which
    have different columns and different meanings."""
    problems = contracts.conforms(
        _q('| where ResourceProvider =~ "MICROSOFT.AUTOMATION"\n| project JobId_g'), _T)
    assert problems and "Category" in problems[0]


def test_a_fully_scoped_read_is_accepted():
    assert contracts.conforms(_q(
        '| where ResourceProvider =~ "MICROSOFT.SQL"\n'
        '| where Category =~ "SQLSecurityAuditEvents"\n'
        '| project statement_s, server_principal_name_s'), _T) == []


def test_the_scoping_rule_reaches_the_prompt():
    rendered = contracts.render(_T)
    assert "shared" in rendered.lower()
    assert "ResourceProvider" in rendered and "Category" in rendered
    from pylon.prompts import table_rules
    assert rendered in table_rules(_T)


@pytest.mark.parametrize("service", [
    "MICROSOFT.AUTOMATION/AuditEvent", "MICROSOFT.AUTOMATION/JobLogs",
    "MICROSOFT.AUTOMATION/JobStreams", "MICROSOFT.SQL/SQLSecurityAuditEvents"])
def test_every_service_section_names_its_own_columns_and_roles(service):
    section = (contracts.for_table(_T)["services"])[service]
    assert section.get("columns"), f"{service} lists no columns"
    assert section.get("roles"), f"{service} maps no roles"
    assert section.get("what"), f"{service} does not say what it records"


def test_the_service_sections_do_not_share_a_caller_column():
    """The whole argument for writing this per service. If they agreed, one set
    of rules would do."""
    services = contracts.for_table(_T)["services"]
    callers = {s: (v.get("roles") or {}).get("who") for s, v in services.items()}
    named = [c for c in callers.values() if c and not c.startswith("none")]
    assert len(set(named)) == len(named), (
        f"two services claim the same caller column: {callers}")


def test_the_suffix_typing_is_recorded():
    """`_g` means the VALUE is a guid and the COLUMN is a string, and
    `succeeded_s` holds "true"/"false" as text. Comparing either as its apparent
    type does not compile."""
    typing = contracts.for_table(_T)["typing"]
    assert typing["suffix_g"] == "string"
    assert typing["suffix_s"] == "string"


# --- values, not just column names -----------------------------------------
#
# The contract recorded which columns each service has and not what they hold.
# A generated detection filtered OperationName == "JobStreams" on a table where
# every JobStreams row carries OperationName "Job" -- the model assumed the
# column repeats the Category. It parsed, it ran, and it matched nothing.

def test_a_literal_that_was_never_observed_is_flagged():
    kql = _q('| where ResourceProvider =~ "MICROSOFT.AUTOMATION"\n'
             '| where Category =~ "JobStreams"\n'
             '| where OperationName == "JobStreams"')
    problems = contracts.conforms(kql, _T)
    assert problems, "a literal no row carries must be caught"
    assert "JobStreams" in problems[0] and "Job" in problems[0], (
        "say both what was asked for and what was measured")


def test_the_measured_literal_is_accepted():
    kql = _q('| where ResourceProvider =~ "MICROSOFT.AUTOMATION"\n'
             '| where Category =~ "JobStreams"\n'
             '| where OperationName == "Job"')
    assert contracts.conforms(kql, _T) == []


def test_a_value_that_is_real_but_unexercised_is_not_flagged():
    """Failed, Stopped and Suspended are genuine job outcomes that have not
    happened in the measured tenant. Absence of an event is not a wrong filter,
    and flagging it would reject correct work for a quiet lab."""
    kql = _q('| where ResourceProvider =~ "MICROSOFT.AUTOMATION"\n'
             '| where Category =~ "JobLogs"\n'
             '| where ResultType in ("Failed", "Stopped", "Suspended")')
    assert contracts.conforms(kql, _T) == [], (
        "an `in (...)` list is not an equality match and must not be graded as one")


def test_the_degenerate_column_is_recorded_as_such():
    """All 48 SQL audit rows carry OperationName "AuditEvent", so filtering it
    narrows nothing. The contract has to say so, or a detection will lean on it."""
    sql = contracts.for_table(_T)["services"]["MICROSOFT.SQL/SQLSecurityAuditEvents"]
    assert sql["observed_values"]["OperationName"] == ["AuditEvent"]
    assert "action_name_s" in sql["observed_values"]["OperationName_note"]


def test_a_column_the_scoped_service_does_not_send_is_flagged():
    """A generated detection read `identity_claim_upn_s`. No provider in the
    measured workspace sends that column, so the query ran with the field empty
    on every row and named nobody. On a shared table the type-suffixed columns
    belong to whichever service wrote the row."""
    kql = _q('| where ResourceProvider =~ "MICROSOFT.AUTOMATION"\n'
             '| where Category =~ "AuditEvent"\n'
             '| where identity_claim_upn_s != ""')
    problems = contracts.conforms(kql, _T)
    assert problems and "identity_claim_upn_s" in problems[0]


def test_the_columns_that_service_does_send_are_accepted():
    kql = _q('| where ResourceProvider =~ "MICROSOFT.AUTOMATION"\n'
             '| where Category =~ "AuditEvent"\n'
             '| project clientInfo_ObjectId_g, targetResources_RunbookName_s')
    assert contracts.conforms(kql, _T) == []


def test_another_services_column_is_flagged_not_silently_allowed():
    """SQL's columns are real, and reading one from an Automation-scoped query
    is still wrong."""
    kql = _q('| where ResourceProvider =~ "MICROSOFT.AUTOMATION"\n'
             '| where Category =~ "AuditEvent"\n'
             '| project statement_s')
    assert contracts.conforms(kql, _T)


def test_the_redacted_caller_is_recorded_as_redacted():
    """clientInfo_PrincipalName_s and clientInfo_IpAddress_s hold the literal
    string "{scrubbed}" on every audit event in the measured tenant. A detection
    projecting either names nobody while looking like it names someone."""
    audit = contracts.for_table(_T)["services"]["MICROSOFT.AUTOMATION/AuditEvent"]
    assert audit["roles"]["who"] == "clientInfo_ObjectId_g", (
        "the caller must be the column that actually carries a value")
    assert "clientInfo_PrincipalName_s" in audit["redacted"]
    assert "clientInfo_IpAddress_s" in audit["redacted"]

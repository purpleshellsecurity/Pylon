"""Ports of test/validation/kql.test.ts plus coverage for the added checks."""

import pytest

from pylon.validation import extract_query_table, validate_kql


def test_flags_azurediagnostics_on_resource_specific_table():
    kql = 'AzureDiagnostics\n| where TimeGenerated > ago(1h)\n| where Category == "AuditEvent"'
    result = validate_kql(kql, "AZKVAuditLogs")
    assert not result.valid
    assert any("AzureDiagnostics" in e for e in result.errors)


def test_flags_operationname_filter_on_azureactivity():
    kql = 'AzureActivity\n| where TimeGenerated > ago(1h)\n| where OperationName == "Microsoft.KeyVault/vaults/write"'
    result = validate_kql(kql, "AzureActivity")
    assert not result.valid
    assert any("OperationNameValue" in e for e in result.errors)


def test_flags_mv_expand_on_flat_tables():
    kql = "AzureActivity\n| where TimeGenerated > ago(1h)\n| mv-expand Properties"
    result = validate_kql(kql, "AzureActivity")
    assert not result.valid
    assert any("mv-expand" in e and "flat table" in e for e in result.errors)


def test_flags_tostring_on_plain_string_fields():
    kql = "AzureActivity\n| where TimeGenerated > ago(1h)\n| extend C = tostring(Caller)"
    result = validate_kql(kql, "AzureActivity")
    assert any("tostring(Caller)" in w for w in result.warnings)


@pytest.mark.parametrize(
    "kql,needle",
    [
        ("", "Empty query"),
        ("AzureActivity | where TimeGenerated > ago(1h) | take 0", "never fire"),
        ("AzureActivity | where TimeGenerated > ago(1h) | where false", "never match"),
        ("DROP TABLE users; -- lol", "non-KQL"),
    ],
)
def test_structural_dead_queries_rejected(kql, needle):
    # F2: a column-only validator waved these through. They must be hard errors now.
    result = validate_kql(kql, "AzureActivity")
    assert not result.valid
    assert any(needle in e for e in result.errors)


def test_hallucinated_table_is_error_not_silence():
    # F2 inversion: a nonexistent table used to get total silence (only known-but-
    # wrong tables warned). It must now be an error.
    result = validate_kql("AzureSuperAuditLogzzz | where TimeGenerated > ago(1h)", "AzureActivity")
    assert not result.valid
    assert any("unknown table" in e for e in result.errors)


def test_missing_time_filter_warns():
    result = validate_kql('AzureActivity | where OperationNameValue =~ "X"', "AzureActivity")
    assert any("time filter" in w for w in result.warnings)


def test_correct_kql_passes():
    kql = (
        "AzureActivity\n"
        "| where TimeGenerated > ago(1h)\n"
        '| where OperationNameValue =~ "MICROSOFT.KEYVAULT/VAULTS/WRITE"\n'
        '| where ActivityStatusValue =~ "Success"\n'
        "| project TimeGenerated, Caller, CallerIpAddress, ResourceId"
    )
    result = validate_kql(kql, "AzureActivity")
    assert result.valid
    assert result.errors == []


def test_flags_graph_activity_string_status_code():
    kql = 'MicrosoftGraphActivityLogs\n| where TimeGenerated > ago(1h)\n| where ResponseStatusCode == "200"'
    result = validate_kql(kql, "MicrosoftGraphActivityLogs")
    assert not result.valid
    assert any("ResponseStatusCode" in e and "INT" in e for e in result.errors)


def test_flags_malformed_tostring_split_index():
    # `)` closes tostring() before the [0], so the index hits the stringified
    # array — BasePath is garbage and the regex below silently never matches.
    kql = (
        "MicrosoftGraphActivityLogs\n"
        "| where TimeGenerated > ago(1h)\n"
        '| extend BasePath = tostring(split(RequestUri, "?"))[0]\n'
        '| where BasePath matches regex "^/v1.0/users/[^/]+/mailFolders$"'
    )
    result = validate_kql(kql, "MicrosoftGraphActivityLogs")
    assert not result.valid
    assert any("tostring(split(" in e for e in result.errors)


def test_flags_malformed_tostring_split_with_nested_call():
    # split() arg is itself a call — the [^)]* form missed this; the balanced form catches it.
    kql = (
        "MicrosoftGraphActivityLogs\n"
        "| where TimeGenerated > ago(1h)\n"
        '| extend BasePath = tostring(split(tolower(RequestUri), "?"))[0]'
    )
    result = validate_kql(kql, "MicrosoftGraphActivityLogs")
    assert not result.valid
    assert any("tostring(split(" in e for e in result.errors)


def test_correct_tostring_split_index_passes():
    # Index inside tostring() is correct and must NOT be flagged.
    kql = (
        "MicrosoftGraphActivityLogs\n"
        "| where TimeGenerated > ago(1h)\n"
        '| extend BasePath = tostring(split(RequestUri, "?")[0])\n'
        "| where ResponseStatusCode < 400"
    )
    result = validate_kql(kql, "MicrosoftGraphActivityLogs")
    assert not any("tostring(split(" in e for e in result.errors)


@pytest.mark.parametrize(
    "col", ["OperationName", "CallerIpAddress", "StatusCode", "AuthenticationType"]
)
def test_flags_audit_fields_on_functionapplogs(col):
    # FunctionAppLogs is execution telemetry — it has none of the data-plane
    # audit columns. Regression for the hallucinated OperationName that used to
    # live in the FunctionAppLogs context asset.
    kql = f'FunctionAppLogs\n| where TimeGenerated > ago(1h)\n| where {col} == "x"'
    result = validate_kql(kql, "FunctionAppLogs")
    assert not result.valid
    assert any(col in e and "does not exist" in e for e in result.errors)


def test_functionapplogs_correct_query_passes():
    kql = (
        "FunctionAppLogs\n"
        "| where TimeGenerated > ago(1h)\n"
        '| where Level == "Error"\n'
        "| project TimeGenerated, FunctionName, ExceptionType, Message"
    )
    result = validate_kql(kql, "FunctionAppLogs")
    assert result.valid, result.errors


def test_flags_destinationip_on_azfw_application_rule():
    # Application rules are FQDN/URL based — no DestinationIp column.
    kql = 'AZFWApplicationRule\n| where TimeGenerated > ago(1h)\n| where DestinationIp == "1.2.3.4"'
    result = validate_kql(kql, "AZFWApplicationRule")
    assert not result.valid
    assert any("DestinationIp" in e and "Fqdn" in e for e in result.errors)


@pytest.mark.parametrize("table", ["AZFWNatRule", "AZFWDnsQuery"])
def test_flags_action_on_azfw_tables_without_it(table):
    kql = f'{table}\n| where TimeGenerated > ago(1h)\n| where Action == "Deny"'
    result = validate_kql(kql, table)
    assert not result.valid
    assert any("Action" in e and "no Action column" in e for e in result.errors)


def test_flags_quoted_int_port_on_azfw():
    kql = 'AZFWNetworkRule\n| where TimeGenerated > ago(1h)\n| where DestinationPort == "443"'
    result = validate_kql(kql, "AZFWNetworkRule")
    assert not result.valid
    assert any("INT" in e for e in result.errors)


def test_azfw_correct_queries_pass():
    for kql, table in [
        ('AZFWNetworkRule\n| where TimeGenerated > ago(1h)\n| where Action == "Deny" and DestinationPort == 22', "AZFWNetworkRule"),
        ('AZFWThreatIntel\n| where TimeGenerated > ago(1h)\n| project TimeGenerated, SourceIp, Fqdn, ThreatDescription', "AZFWThreatIntel"),
        ('AZFWIdpsSignature\n| where TimeGenerated > ago(1h)\n| where Severity >= 2', "AZFWIdpsSignature"),
    ]:
        result = validate_kql(kql, table)
        assert result.valid, (table, result.errors)


@pytest.mark.parametrize(
    "table", ["ContainerRegistryLoginEvents", "ContainerRegistryRepositoryEvents"]
)
def test_flags_numeric_durationms_on_acr(table):
    kql = f"{table}\n| where TimeGenerated > ago(1h)\n| where DurationMs > 1000"
    result = validate_kql(kql, table)
    assert not result.valid
    assert any("DurationMs" in e and "STRING" in e for e in result.errors)


def test_acr_repository_push_query_passes():
    kql = (
        "ContainerRegistryRepositoryEvents\n"
        "| where TimeGenerated > ago(1h)\n"
        '| where OperationName == "Push"\n'
        "| project TimeGenerated, Identity, CallerIpAddress, Repository, Tag, Digest"
    )
    result = validate_kql(kql, "ContainerRegistryRepositoryEvents")
    assert result.valid, result.errors


def test_flags_result_on_azureactivity():
    kql = 'AzureActivity\n| where TimeGenerated > ago(1h)\n| where Result == "Success"'
    result = validate_kql(kql, "AzureActivity")
    assert any("ActivityStatusValue" in e for e in result.errors)


def test_flags_initiatedby_on_azureactivity():
    kql = "AzureActivity\n| where TimeGenerated > ago(1h)\n| extend U = InitiatedBy"
    result = validate_kql(kql, "AzureActivity")
    assert not result.valid


def test_flags_wrong_case_kv_caller_ip():
    """The DEDICATED Key Vault table uses CallerIpAddress. This assertion used to
    run the other way — it demanded the capital-IP spelling, which is what Key
    Vault logs are called in the shared AzureDiagnostics table — and so the
    validator passed a generated query that a live workspace then refused."""
    wrong = 'AZKVAuditLogs\n| where TimeGenerated > ago(1h)\n| where CallerIPAddress == "1.2.3.4"'
    result = validate_kql(wrong, "AZKVAuditLogs")
    assert not result.valid
    assert any("CallerIpAddress" in e and "AzureDiagnostics" in e for e in result.errors)

    right = 'AZKVAuditLogs\n| where TimeGenerated > ago(1h)\n| where CallerIpAddress == "1.2.3.4"'
    assert validate_kql(right, "AZKVAuditLogs").valid


def test_flags_storage_numeric_status_code():
    kql = "StorageBlobLogs\n| where TimeGenerated > ago(1h)\n| where StatusCode >= 400"
    result = validate_kql(kql, "StorageBlobLogs")
    assert any("STRING" in e for e in result.errors)


@pytest.mark.parametrize(
    "table", ["StorageBlobLogs", "StorageFileLogs", "StorageQueueLogs", "StorageTableLogs"]
)
def test_all_storage_tables_flag_numeric_status_code(table):
    # All four storage data-plane tables share the StatusCode-is-STRING rule.
    kql = f"{table}\n| where TimeGenerated > ago(1h)\n| where StatusCode >= 400"
    result = validate_kql(kql, table)
    assert not result.valid
    assert any("STRING" in e and table in e for e in result.errors)


@pytest.mark.parametrize(
    "table", ["StorageBlobLogs", "StorageFileLogs", "StorageQueueLogs", "StorageTableLogs"]
)
def test_all_storage_tables_flag_wrong_caller_ip_case(table):
    kql = f'{table}\n| where TimeGenerated > ago(1h)\n| where CallerIPAddress == "1.2.3.4"'
    result = validate_kql(kql, table)
    assert any("CallerIpAddress" in e and table in e for e in result.errors)


@pytest.mark.parametrize(
    "table", ["StorageFileLogs", "StorageQueueLogs", "StorageTableLogs"]
)
def test_new_storage_tables_accept_correct_kql(table):
    kql = (
        f"{table}\n"
        "| where TimeGenerated > ago(1h)\n"
        '| where StatusCode == "200"\n'
        "| project TimeGenerated, OperationName, CallerIpAddress, AccountName"
    )
    result = validate_kql(kql, table)
    assert result.valid, result.errors


def test_flags_auditlogs_uppercase_result_value():
    kql = 'AuditLogs\n| where TimeGenerated > ago(1h)\n| where Result == "Success"'
    result = validate_kql(kql, "AuditLogs")
    assert any("lowercase" in w for w in result.warnings)


def test_unknown_table_skips_validation():
    result = validate_kql("MadeUpTable\n| where TimeGenerated > ago(1h)", "MadeUpTable")
    assert result.valid
    assert any("No known schema" in w for w in result.warnings)


def test_extract_query_table_handles_let_statements():
    kql = 'let lookback = 1h;\nAzureActivity\n| where TimeGenerated > ago(lookback)'
    assert extract_query_table(kql) == "AzureActivity"


def test_extract_query_table_strips_comments():
    kql = "// detection for key vault\nAzureActivity\n| where TimeGenerated > ago(1h)"
    assert extract_query_table(kql) == "AzureActivity"


def test_no_false_positive_on_column_name_inside_string_literal():
    # F5: AUTHORIZATION appears only inside the operation value, not as a column.
    # The case check must not read it as a miscased "Authorization" column.
    kql = (
        "AzureActivity\n"
        "| where TimeGenerated > ago(1h)\n"
        '| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"\n'
        '| where ActivityStatusValue =~ "Succeeded"\n'
        "| project TimeGenerated, Caller, Authorization"
    )
    result = validate_kql(kql, "AzureActivity")
    assert result.valid
    assert not any("wrong case" in w for w in result.warnings), result.warnings


def test_no_false_positive_on_column_name_inside_comment():
    kql = (
        "AzureActivity\n"
        "| where TimeGenerated > ago(1h)  // check AUTHORIZATION scope changes\n"
        "| project TimeGenerated, Caller"
    )
    result = validate_kql(kql, "AzureActivity")
    assert not any("wrong case" in w for w in result.warnings), result.warnings


def test_still_flags_genuine_wrong_case_outside_strings():
    # The fix must not neuter the check: a real miscased column reference (not in
    # a string) is still caught.
    kql = "AzureActivity\n| where TimeGenerated > ago(1h)\n| project ResourceID"
    result = validate_kql(kql, "AzureActivity")
    assert any("wrong case" in w and "ResourceId" in w for w in result.warnings), result.warnings


# --- the unknown column ------------------------------------------------------
#
# Check 10 compared CASE and nothing else. When the identifier was not in the
# schema at all, `schema_lower.get()` returned None and there was no branch for
# it -- so a mis-typed real column was caught and a wholly INVENTED one was not,
# which is the worse of the two. It parses, it deploys, and the workspace
# refuses to resolve it.


@pytest.mark.parametrize("table,column,kql", [
    ("AzureActivity", "ActorRiskScore",
     'AzureActivity\n| where TimeGenerated > ago(1h)\n| project TimeGenerated, ActorRiskScore'),
    ("AuditLogs", "ThreatLevel",
     'AuditLogs\n| where TimeGenerated > ago(1h)\n| where ThreatLevel == "high"'),
    ("StorageBlobLogs", "BlobRiskScore",
     'StorageBlobLogs\n| where TimeGenerated > ago(1h)\n| project BlobRiskScore'),
])
def test_an_invented_column_is_an_error_not_a_silence(table, column, kql):
    """Rejected only when Microsoft's own column list is in hand.

    `TABLE_SCHEMAS` cannot carry the rejection on its own: it is extracted from
    this repo's prompt assets -- the columns the prompt TEACHES -- and lists
    sixteen of AzureActivity's thirty-seven. A live run rejected a correct
    detection filtering on `OperationId` for exactly that reason.
    """
    from pylon.validation.schemas import TABLE_SCHEMAS

    documented = frozenset(TABLE_SCHEMAS[table])       # stands in for the fetch
    result = validate_kql(kql, table, documented=documented)
    assert not result.valid
    assert any(column in e and "not a column" in e for e in result.errors)


@pytest.mark.parametrize("table,column,kql", [
    ("AzureActivity", "ActorRiskScore",
     'AzureActivity\n| where TimeGenerated > ago(1h)\n| project TimeGenerated, ActorRiskScore'),
])
def test_without_the_documented_list_it_warns_and_says_it_could_not_check(
        table, column, kql):
    """Could not look is not looked and found nothing. When the fetch fails the
    question was never asked, and the finding has to say so rather than either
    rejecting the query or passing it silently."""
    result = validate_kql(kql, table)
    assert result.valid
    assert any("NOT checked" in w and column in w for w in result.warnings)


def test_a_real_column_the_prompt_does_not_teach_is_accepted():
    """The regression this whole three-state check exists for. `OperationId` is a
    real AzureActivity column, documented by Microsoft, absent from the sixteen
    the prompt teaches, and used correctly by a detection that was rejected."""
    from pylon.validation.schemas import TABLE_SCHEMAS

    assert "OperationId" not in TABLE_SCHEMAS["AzureActivity"]
    documented = frozenset(TABLE_SCHEMAS["AzureActivity"]) | {"OperationId"}
    kql = ("AzureActivity\n| where TimeGenerated > ago(1h)\n"
           "| project TimeGenerated, OperationId")
    result = validate_kql(kql, "AzureActivity", documented=documented)
    assert result.valid
    assert result.errors == [] and result.warnings == []


@pytest.mark.parametrize("table,kql", [
    # Everything a correct query legitimately creates for itself. Without the
    # _defined_names exclusions, each of these would be reported as a
    # fabrication -- and a check that fails correct queries gets switched off.
    ("AzureActivity",
     'AzureActivity\n| where TimeGenerated > ago(1h)\n'
     '| extend Actor = tostring(Caller)\n'
     '| summarize Hits = count() by Actor, CallerIpAddress'),
    ("AuditLogs",                                    # member access on a dynamic column
     'AuditLogs\n| where TimeGenerated > ago(1h)\n'
     '| mv-expand TargetResources\n'
     '| extend Who = tostring(InitiatedBy.user.userPrincipalName)\n'
     '| project TimeGenerated, Who, Result'),
    ("StorageBlobLogs",                              # a let-bound name
     'let Window = 1h;\nStorageBlobLogs\n| where TimeGenerated > ago(Window)\n'
     '| summarize Downloads = count() by AccountName\n| where Downloads > 100'),
    ("AZKVAuditLogs",                                # indexed split, then a real column
     'AZKVAuditLogs\n| where TimeGenerated > ago(1h)\n'
     '| extend Vault = tostring(split(_ResourceId, "/")[-1])\n'
     '| project TimeGenerated, Vault, CallerIPAddress'),
])
def test_a_name_the_query_defines_is_not_a_fabrication(table, kql):
    result = validate_kql(kql, table)
    invented = [e for e in result.errors if "not a column" in e]
    assert invented == [], f"correct query reported as inventing a column: {invented}"


# --- the operation the query filters on --------------------------------------
#
# The other half of the unknown-column bug, and the one that has actually
# shipped here more than once: a filter on an operation string the log never
# writes. Cosmos DB detections filtered on ReadDocument and QueryDocuments;
# StorageBlobLogs carried LeaseBlob; fifty Entra names carried a backslash. Each
# one parses, validates, deploys, and can never fire.
#
# The DECLARED operation on the attack vector was checked all along. The string
# inside the KQL was not -- so a real operation could be declared and a typo of
# it queried, and nothing looked.


@pytest.mark.parametrize("table,column,bad", [
    ("AZKVAuditLogs", "OperationName", "SecretGett"),
    ("AuditLogs", "OperationName", "Add membr to role"),
    # The real one. This name was in the catalogue and is not a Blob operation:
    # the service logs AcquireBlobLease, RenewBlobLease, ReleaseBlobLease,
    # BreakBlobLease, ChangeBlobLease and GetBlobLeaseInfo, and no LeaseBlob.
    ("StorageBlobLogs", "OperationName", "LeaseBlob"),
    ("AzureActivity", "OperationNameValue", "MICROSOFT.KEYVAULT/VAULTS/EXPLODE"),
])
def test_an_operation_the_log_never_writes_is_reported(table, column, bad):
    """Reported either way. Whether it is an error or a warning depends on the
    table's vocabulary being closed -- see the two tests below -- but it is never
    silent, which is what it was before the query's own filter was checked."""
    kql = f'{table}\n| where TimeGenerated > ago(1h)\n| where {column} =~ "{bad}"'
    result = validate_kql(kql, table)
    assert any("operation filter" in f for f in result.errors + result.warnings), (
        f"{bad!r} on {table} passed unremarked"
    )


@pytest.mark.parametrize("table,clause", [
    ("AZKVAuditLogs", 'OperationName =~ "SecretGet"'),
    # Both spellings of the conditional access activities are real: Microsoft
    # documents one case and a live tenant was measured writing another.
    ("AuditLogs", 'OperationName =~ "Add member to role"'),
    ("AuditLogs", 'OperationName =~ "Add conditional access policy"'),
    ("StorageBlobLogs", 'OperationName in~ ("GetBlob", "PutBlob")'),
    ("AzureActivity", 'OperationNameValue =~ "MICROSOFT.KEYVAULT/VAULTS/DELETE"'),
    # `has` takes a FRAGMENT on purpose. "Secret" is a legitimate prefix filter
    # and is not a claim that an operation of that name exists, so checking the
    # substring forms would fail correct queries.
    ("AZKVAuditLogs", 'OperationName has "Secret"'),
])
def test_a_real_operation_and_a_fragment_filter_are_left_alone(table, clause):
    kql = f'{table}\n| where TimeGenerated > ago(1h)\n| where {clause}'
    result = validate_kql(kql, table)
    flagged = [w for w in result.warnings if "operation filter" in w]
    assert flagged == [], f"correct query flagged: {flagged}"


def test_a_closed_vocabulary_refuses_a_name_it_does_not_hold():
    """This was a warning, and the argument for that was real: `is_known` answers
    "not in this snapshot", never "not real", and Entra adds activities
    continuously, so refusing one could block a correct detection on a stale
    catalogue.

    It is an error now, and the trade is deliberate. A fabricated name ships a
    rule that parses, validates, deploys and never fires -- silent, and the worst
    defect this tool can produce. A real name the catalogue has not caught up
    with fails loudly, names itself in the error, and gets one corrective retry
    before an operator sees exactly which string was rejected. Failing visibly on
    a right answer beats passing silently on a wrong one.

    What makes the refusal defensible is the partition: every name AuditLogs can
    write is mapped to a technique or rejected in writing, so a name in neither
    pile is a claim nobody made. That is a stronger statement than "not in the
    list" and it is why this could not be an error before.
    """
    kql = ('AuditLogs\n| where TimeGenerated > ago(1h)\n'
           '| where OperationName =~ "Some Activity Added Last Tuesday"')
    result = validate_kql(kql, "AuditLogs")
    assert not result.valid
    assert any("operation filter" in e for e in result.errors)


def test_an_open_vocabulary_still_only_warns():
    """AzureActivity carries every provider in Azure, so the table alone cannot
    say whether a name is real -- that is answered per resource type. The rule is
    the same one: refuse only where a complete partition backs the refusal.

    A real provider with an invented action, so the catalogue can judge at all.
    An unknown PROVIDER is the third state and reports nothing: the catalogue
    holds no operations for it, so it cannot say the name is wrong, and treating
    that silence as a verdict is the mistake this file exists to avoid."""
    kql = ('AzureActivity\n| where TimeGenerated > ago(1h)\n'
           '| where OperationNameValue =~ "MICROSOFT.KEYVAULT/VAULTS/EXPLODE"')
    result = validate_kql(kql, "AzureActivity")
    assert result.valid
    assert any("operation filter" in w for w in result.warnings)

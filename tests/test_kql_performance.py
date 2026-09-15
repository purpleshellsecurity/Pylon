"""KQL performance checks — documented anti-patterns, reported as warnings."""

from pylon.validation.validate_kql import _performance_issues, validate_kql

TIME = "| where TimeGenerated > ago(1h)"


def _warns(kql):
    return _performance_issues(kql)


# --- the documented anti-patterns -------------------------------------------


def test_contains_is_flagged_has_is_not():
    # Microsoft: "Use the has operator. Don't use contains ... has works better,
    # since it doesn't look for substrings."
    assert _warns(f'AzureActivity {TIME} | where Caller contains "admin"')
    assert not _warns(f'AzureActivity {TIME} | where Caller has "admin"')


def _errors(kql: str) -> list[str]:
    return validate_kql(kql, "AzureActivity").errors


def test_search_is_an_error_not_a_performance_warning():
    """Reclassified, and the reclassification is the finding.

    `search` was filed here as slow. Microsoft states that a log search alert
    rule using `search` is not supported -- the rule cannot be CREATED. A query
    that will not deploy is not a performance characteristic, and reporting it
    as a warning let it through generation to fail at install time.
    """
    assert any("no-union-in-alert-rule" in e for e in _errors(f'search * {TIME}'))
    assert any("no-union-in-alert-rule" in e for e in _errors('search "compromise"'))
    assert not _errors(f'AzureActivity {TIME} | where Caller has "svc"')


def test_a_union_of_named_tables_is_an_error_too():
    """This test used to assert the opposite, and that assertion WAS the bug.

    `assert not _warns('union AzureActivity, SigninLogs')` encoded the belief
    that only `union *` mattered. A union of two named tables is what a model
    actually writes, it passed with zero errors and zero warnings, and Sentinel
    will not create an alert rule from it.
    """
    assert any("no-union-in-alert-rule" in e for e in _errors(f'union * {TIME}'))
    assert any("no-union-in-alert-rule" in e
               for e in _errors(f'union AzureActivity, SigninLogs {TIME}'))


def test_a_cross_resource_union_is_still_allowed():
    """The one union Microsoft still supports in an alert rule, because it
    scopes to named resources rather than scanning tables."""
    cross = ("union workspace('00000000-0000-0000-0000-000000000003').AzureActivity, "
             "app('00000000-0000-0000-0000-000000000001').requests")
    assert not any("no-union-in-alert-rule" in e for e in _errors(cross))


def test_tolower_comparison_is_flagged():
    # Microsoft: use Col =~ "x", not tolower(Col) == "x".
    assert _warns(f'AzureActivity {TIME} | where tolower(Caller) == "bob"')


def test_parse_json_inside_where_is_flagged():
    # Microsoft's pattern filters with a term match BEFORE paying for parsing.
    assert _warns('AuditLogs | where parse_json(TargetResources)[0].id == "x"')
    assert not _warns(
        'AuditLogs | where TargetResources has "x" | extend d = parse_json(TargetResources)'
    )


# --- what must NOT be flagged ------------------------------------------------


def test_mandated_case_insensitive_operator_is_never_flagged():
    # This repo's ARM prompt REQUIRES =~ on OperationNameValue because Azure
    # operation-name casing varies. Warnings reach the self-correction prompt, so
    # warning here would tell the model to undo what the prompt mandates.
    assert not _warns(
        f'AzureActivity {TIME} | where OperationNameValue =~ "MICROSOFT.KEYVAULT/VAULTS/DELETE"'
    )


def test_anti_patterns_inside_string_literals_are_ignored():
    assert not _warns(f'AzureActivity {TIME} | where Msg == "this contains a word"')


def test_column_names_containing_a_keyword_are_not_flagged():
    assert not _warns(f"AzureActivity {TIME} | project ResearchField")


# --- integration: warnings, never errors -------------------------------------


def test_performance_findings_never_invalidate_a_query():
    # `valid` is computed from errors alone. A perf finding must not trigger the
    # self-correction retry by itself — it rides along only when one is already
    # happening (engine.py folds warnings into the correction prompt).
    result = validate_kql(
        f'AzureActivity {TIME} | where Caller contains "admin"', "AzureActivity"
    )
    assert result.valid is True
    # Asserted on the RULE ID rather than on a "Performance:" prefix. The prefix
    # was a category word typed into four message strings; the id is the rule
    # the model was shown, so a test naming it fails when the rule is renamed
    # rather than when somebody reworded a message.
    assert any("has-not-contains" in w for w in result.warnings)
    assert not any("has-not-contains" in e for e in result.errors)


def test_clean_query_carries_no_performance_warnings():
    result = validate_kql(
        f'AzureActivity {TIME} | where OperationNameValue =~ "MICROSOFT.KEYVAULT/VAULTS/DELETE"',
        "AzureActivity",
    )
    assert not any("Performance" in w for w in result.warnings)


# --- the leading table, through a let binding --------------------------------


def test_a_let_bound_alias_is_not_reported_as_a_hallucinated_table():
    """Found live. A valid Exchange detection opened on a name it had just
    defined -- `let recent = OfficeActivity | ...; recent | ...`, which is
    ordinary KQL -- and was rejected as targeting a hallucinated table called
    "recent". It failed its retry and shipped marked INVALID, the only invalid
    detection across 61 generated."""
    from pylon.validation.validate_kql import extract_query_table

    kql = (
        'let AllowedActors = dynamic([]);\n'
        'let recent = OfficeActivity | where TimeGenerated > ago(1h);\n'
        'recent\n| where Operation =~ "Send"'
    )
    assert extract_query_table(kql) == "OfficeActivity"


def test_a_real_hallucination_is_still_caught_through_an_alias():
    # The fix must not become a way to smuggle a fake table past the check.
    from pylon.validation.validate_kql import extract_query_table

    assert extract_query_table("let r = NotARealTable | where x;\nr | where y") == "NotARealTable"


def test_a_plain_leading_table_is_unchanged():
    from pylon.validation.validate_kql import extract_query_table

    assert extract_query_table("OfficeActivity | where x") == "OfficeActivity"
    assert extract_query_table("let A = dynamic([]);\nOfficeActivity | where x") == "OfficeActivity"


def test_an_unresolvable_alias_reports_nothing_rather_than_a_wrong_answer():
    # A chain of aliases, or one opening on a function call, yields no table
    # claim. Silence is correct here; a guess would be a false accusation.
    from pylon.validation.validate_kql import extract_query_table

    assert extract_query_table("let a = OfficeActivity;\nlet b = a;\nb | where x") is None
    assert extract_query_table("let r = materialize(X);\nr | where y") == "materialize"


def test_the_validator_no_longer_fails_the_live_query():
    from pylon.validation.validate_kql import validate_kql

    kql = (
        'let recent = OfficeActivity | where TimeGenerated > ago(1h);\n'
        'recent\n| where Operation =~ "Send"\n| project TimeGenerated, UserId'
    )
    result = validate_kql(kql, "OfficeActivity")
    assert not [e for e in result.errors if "hallucinated" in e]

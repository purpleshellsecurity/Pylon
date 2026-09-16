"""A GUID extraction that returns the subscription id instead.

An ARM resource id always begins `/subscriptions/<guid>/`, so the FIRST thing
in it matching a GUID is the subscription. A pattern that does not pin where
the GUID sits returns the subscription on every row, in every tenant:

    extract(@"[0-9a-f-]{36}", 0, roleDefinitionId)     -> the subscription
    extract(@"([0-9a-f-]{36})$", 1, roleDefinitionId)  -> the role

Both measured against a live workspace, on the same rows.

The detection then compares that subscription id to a role id and matches
nothing. It is the second half of a pair, and the pair is the point: the
version this replaced had a correctly anchored pattern holding the WRONG GUID.
The same detection was dead twice for opposite reasons and the symptom was
identical each time, which is why the constant and its extraction each need
their own check.
"""

import pytest

from pylon.validation.validate_kql import (_unpinned_guid_extractions as issues,
                                           _without_comments)

LOOSE = 'T | extend g = extract(@"[0-9a-f-]{36}", 0, roleDefinitionId)'


def test_the_extraction_that_shipped_is_caught():
    found = issues(LOOSE)
    assert len(found) == 1
    assert "SUBSCRIPTION id" in found[0]


def test_the_message_shows_the_anchored_form():
    """A finding a reader cannot act on is half a finding."""
    assert 'extract(@"([0-9a-f-]{36})$", 1, roleDefinitionId)' in issues(LOOSE)[0]


# ── the two ways a pattern pins itself ───────────────────────────────────────

@pytest.mark.parametrize("pattern", [
    r"([0-9a-f-]{36})$",
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
])
def test_an_anchor_pins_it(pattern):
    assert issues(f'T | extend g = extract(@"{pattern}", 1, roleDefinitionId)') == []


@pytest.mark.parametrize("pattern", [
    r"/roleDefinitions/([0-9a-f-]{36})",
    r"providers/Microsoft\.Authorization/roleDefinitions/([0-9a-f-]{36})",
])
def test_naming_the_path_segment_pins_it_too(pattern):
    """Literal text outside a character class says where the GUID sits just as
    well as an anchor does, and most of the corpus uses this form."""
    assert issues(f'T | extend g = extract(@"{pattern}", 1, roleDefinitionId)') == []


# ── what must not trip ───────────────────────────────────────────────────────

def test_a_pattern_that_is_not_a_guid_is_left_alone():
    """Nineteen of twenty extracts in the corpus pull a NAME out of a path, and
    an unanchored one of those is normal."""
    assert issues(r'T | extend n = extract(@"([^/]+)$", 1, ResourceId)') == []
    assert issues(r'T | extend v = extract("/secrets/([^/?]+)/", 1, RequestUri)') == []


def test_a_source_that_is_not_an_arm_path_is_left_alone():
    """A column that already holds a GUID has no subscription in front of it."""
    assert issues(r'T | extend g = extract(@"[0-9a-f-]{36}", 0, Caller)') == []


def test_a_wrapped_source_is_still_recognised():
    assert len(issues(
        r'T | extend g = extract(@"[0-9a-f-]{36}", 0, tostring(ResourceId))')) == 1


def test_an_extraction_inside_a_comment_is_not_code():
    assert issues(f"T // {LOOSE}") == []


# ── the comment stripper this needs ──────────────────────────────────────────
# The usual helper blanks strings AND comments, and here the thing being read
# IS a string literal -- the regex handed to extract. Stripping comments naively
# does not work either, because `//` appears inside real KQL strings.

def test_a_url_inside_a_string_is_not_a_comment():
    kql = r'T | extend v = extract("https://([^.]+)\.", 1, Id)'
    assert _without_comments(kql) == kql


def test_a_verbatim_string_survives_intact():
    kql = r'T | where x matches regex @"a//b"'
    assert _without_comments(kql) == kql


def test_a_real_comment_goes():
    assert "secret" not in _without_comments("T | take 1 // secret\n| take 2")


def test_the_line_after_a_comment_survives():
    assert "take 2" in _without_comments("T | take 1 // note\n| take 2")


# ── the AzureDiagnostics-suffix check, judged against the real column list ───
# It flagged `Authorization_d`, `Claims_d` and `Properties_d` as fabrications.
# AzureActivity really has all three, as dynamic columns. The check was reading
# `TABLE_SCHEMAS`, which holds the columns the PROMPT teaches -- sixteen of
# AzureActivity's thirty-seven -- so every real column outside that list looked
# invented.
#
# It cost real work twice: a valid User Access Administrator detection was
# rejected for `Authorization_d`, and a later run lost BOTH of its attempts to
# `Properties_d` and shipped nothing. A missed fabrication is one bad detection;
# a false positive here burns the retry and throws away work that was right.

from pylon.validation.validate_kql import validate_kql


@pytest.mark.parametrize("column", ["Authorization_d", "Claims_d", "Properties_d"])
def test_a_real_azureactivity_dynamic_column_is_not_a_fabrication(column):
    result = validate_kql(
        f"AzureActivity\n| where TimeGenerated > ago(1h)\n"
        f"| extend x = tostring({column})", "AzureActivity")
    assert result.valid, result.errors


def test_an_actual_azurediagnostics_column_is_still_caught():
    """The check still has to work. `identity_s` is the AzureDiagnostics
    spelling and the resource-specific table does not have it."""
    result = validate_kql(
        "AzureActivity\n| where TimeGenerated > ago(1h)\n"
        "| extend x = tostring(identity_s)", "AzureActivity")
    assert not result.valid
    assert "identity_s" in result.errors[0]

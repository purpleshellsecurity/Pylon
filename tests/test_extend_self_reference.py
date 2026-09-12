"""An `extend` that reads a name defined beside it.

KQL evaluates every assignment in one `extend` against the operator's INPUT, so
a sibling assignment is not in scope. The query parses, passes every schema
check, and the workspace refuses it:

    | extend Auth = parse_json(Authorization), Scope = tostring(Auth.scope)
    'extend' operator: Failed to resolve scalar expression named 'Auth'

Two generated detections shipped with it, on different targets and different
tables, and both came back `error` against a workspace holding 144 and 6 real
events. Their siblings in the same directory split the same work across two
`extend`s and ran.

The negative cases matter as much as the positive ones here. A rule written for
this that fires on correct queries is worse than no rule: the last one tried in
this codebase flagged nine of ten correct detections and was deleted. The first
draft of THIS one flagged 56 playbook queries that run fine, because it split
on `|` alone and an `extend` ends at a `;`, not at the next pipe.
"""

import pytest

from pylon.validation.validate_kql import _extend_self_reference as issues


# ── the two that actually shipped ────────────────────────────────────────────

def test_the_arm_query_that_failed_against_the_workspace():
    found = issues("AzureActivity\n"
                   "| extend Auth = parse_json(Authorization), "
                   "grantScope = tostring(Auth.scope)")
    assert len(found) == 1
    assert '"grantScope" reads "Auth"' in found[0]
    assert "Split it into two" in found[0]


def test_the_key_vault_query_that_failed_against_the_workspace():
    found = issues("AZKVAuditLogs\n"
                   "| extend CallerOID = tostring(Identity.claim.oid),\n"
                   "  PrincipalId = iff(isnotempty(CallerOID), CallerOID, CallerUPN)")
    assert len(found) == 1
    assert '"PrincipalId" reads "CallerOID"' in found[0]


def test_the_error_text_the_workspace_returns_is_quoted():
    """So a reader searching the message they got lands on the fix."""
    found = issues("T\n| extend A = 1, B = A")
    assert "Failed to resolve scalar expression named 'A'" in found[0]


# ── the fix, and everything that must not trip ───────────────────────────────

def test_splitting_across_two_extends_is_the_fix_and_is_clean():
    assert issues("AzureActivity\n"
                  "| extend Auth = parse_json(Authorization)\n"
                  "| extend Scope = tostring(Auth.scope)") == []


def test_independent_siblings_are_clean():
    """Three fields off the same dynamic column, none reading another. This is
    what almost every correct query in the corpus looks like."""
    assert issues(
        "AZKVAuditLogs\n| extend CallerUPN = tostring(Identity.claim.upn), "
        "CallerAppId = tostring(Identity.claim.appid), "
        "CallerOID = tostring(Identity.claim.oid)") == []


def test_an_extend_ends_at_a_semicolon_not_at_the_next_pipe():
    """The false positive that 56 working playbook queries caught. The pipes
    inside a following `toscalar(...)` are nested, so splitting on `|` alone ran
    the extend body through every `let` after it and read their contents as its
    own siblings."""
    assert issues(
        "let Events = AZKVAuditLogs;\n"
        "Events\n"
        "| extend ActorUpn = tostring(Identity.claim.upn), "
        "IsFailure = HttpStatusCode >= 300;\n"
        "let BaselineIps = toscalar(\n"
        "    Events\n"
        "    | where ActorUpn == AlertActor\n"
        "    | summarize make_set(CallerIpAddress, 500));\n"
        "Events\n| take 1") == []


def test_reassigning_a_name_that_was_already_in_scope_is_legal():
    """Reading the OLD value of a column an earlier stage created is valid KQL
    and sometimes intended. Only a name this operator introduces is a problem."""
    assert issues("T\n| extend X = 1\n| extend X = X + 1, Y = X") == []


def test_a_let_bound_name_is_in_scope():
    assert issues("let W = 1h;\nT\n| extend A = ago(W), B = ago(W)") == []


def test_a_member_with_the_same_name_as_a_sibling_is_not_a_reference():
    """`Identity.claim.oid` mentions `claim`; a column called `claim` beside it
    is a different thing and the dot is what separates them."""
    assert issues("T\n| extend claim = 1, v = tostring(Identity.claim.oid)") == []


def test_a_comparison_is_not_an_assignment():
    assert issues("T\n| extend A = 1, B = (A2 == 3)") == []


@pytest.mark.parametrize("op", ["project", "summarize", "where", "join"])
def test_only_extend_is_examined(op):
    """The rule is stated for `extend`. Widening it to operators whose scoping
    was not measured is how the last rule in this codebase got deleted."""
    assert issues(f"T\n| {op} A = 1, B = A") == []


def test_a_query_with_no_extend_is_clean():
    assert issues("AzureActivity | where Caller == 'x' | take 5") == []


def test_the_name_in_a_comment_is_not_a_reference():
    assert issues("T\n| extend A = 1, B = 2 // uses A\n") == []


def test_the_name_in_a_string_literal_is_not_a_reference():
    assert issues('T\n| extend A = 1, B = "A"') == []


def test_every_offending_assignment_is_reported_once():
    found = issues("T\n| extend A = 1, B = A, C = A + B")
    assert len(found) == 2
    assert '"B" reads "A"' in found[0] and '"C" reads' in found[1]

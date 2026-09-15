"""The InitiatedBy/mv-expand ordering rule must read code, not comments.

A live Entra detection extracted InitiatedBy before the mv-expand, exactly as the
rule asks, and labelled the block:

    // Extract InitiatedBy BEFORE mv-expand

That comment put the literal text "mv-expand" ahead of the first real
`InitiatedBy.` access, and the rule scanned raw text, so it warned on a query
that had followed it. A gate that fires on correct output gets ignored, and then
it is ignored on the run where it is right.
"""

from pylon.validation.validate_kql import validate_kql

_ORDERING = "InitiatedBy fields are extracted AFTER mv-expand"

CORRECT = """AuditLogs
| where TimeGenerated > ago(1h)
// Extract InitiatedBy BEFORE mv-expand
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
// NOW mv-expand
| mv-expand TargetResources
| extend TargetId = tostring(TargetResources.id)
| project TimeGenerated, ActorUPN, TargetId
"""

WRONG = """AuditLogs
| where TimeGenerated > ago(1h)
| mv-expand TargetResources
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetId = tostring(TargetResources.id)
| project TimeGenerated, ActorUPN, TargetId
"""


def test_a_comment_naming_mv_expand_does_not_trip_the_rule():
    warnings = validate_kql(CORRECT, "AuditLogs").warnings
    assert not any(_ORDERING in w for w in warnings), warnings


def test_the_rule_still_fires_when_the_code_really_is_out_of_order():
    """The fix must not be 'stop checking'."""
    warnings = validate_kql(WRONG, "AuditLogs").warnings
    assert any(_ORDERING in w for w in warnings), warnings

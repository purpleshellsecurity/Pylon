"""Golden-query tests for the Phase-1 pivot generator.

The layer exists to emit the CORRECT per-table fields/casing/parse-paths, so
these assert exactly that — a wrong-field regression should fail here.
"""

from pylon import pivot


def _by_tier(fired):
    return {h["tier"] + ":" + h["table"]: h for h in pivot.pivot_plan(fired)}


def test_keyvault_alert_full_chain():
    hops = pivot.pivot_plan("AZKVAuditLogs")
    tiers = [h["tier"] for h in hops]
    # kill-chain order: identity -> control -> data -> context
    assert tiers.index("identity") < tiers.index("control") < tiers.index("data-same")
    assert tiers.index("data-same") < tiers.index("data-blast")


def test_keyvault_uses_the_dedicated_tables_real_column_names():
    plan = _by_tier("AZKVAuditLogs")
    same = plan["data-same:AZKVAuditLogs"]["kql"]
    assert "tostring(Identity.claim.oid) == ActorId" in same
    assert "_ResourceId == TargetResource" in same      # tier a scopes the resource
    assert "CallerIpAddress" in same                    # lowercase p — the real column
    blast = plan["data-blast:AZKVAuditLogs"]["kql"]
    assert "TargetResource" not in blast                 # tier b is NOT resource-scoped


def test_identity_and_control_hops_use_their_own_fields():
    plan = _by_tier("AZKVAuditLogs")
    assert "SigninLogs | where UserId == ActorId" in plan["identity:SigninLogs"]["kql"]
    # NOT `Caller == ActorId`. That column holds a UPN for a user and an object
    # id for a service principal -- measured over thirty days of one tenant,
    # 15,139 rows carry a UPN and 8,222 an object id. Compared to an object id
    # the pivot found NOTHING whenever a human did the thing, which is the case
    # the detections it ships with fire on. Verified against that tenant: the
    # old form returned 0 rows for a user actor, the new form 15,139, and it
    # still returns 5,150 for a service principal.
    assert ("AzureActivity | where Caller in (ActorId, ActorUpn)"
            in plan["control:AzureActivity"]["kql"])
    assert 'let ActorUpn = "[actor UPN from the alert]";' in plan["control:AzureActivity"]["kql"]
    # AuditLogs actor is buried in InitiatedBy JSON.
    assert "tostring(InitiatedBy.user.id) == ActorId" in plan["identity:AuditLogs"]["kql"]


def test_uncovered_table_yields_nothing():
    assert pivot.pivot_plan("SomeRandomTable") == []
    assert pivot.render_pivot_block("SomeRandomTable") == ""


def test_render_block_is_prompt_ready():
    block = pivot.render_pivot_block("AZKVAuditLogs")
    assert "Grounded pivot queries" in block
    assert "tostring(Identity.claim.oid)" in block


def test_graph_activity_hop_included_for_cloud_alert():
    plan = _by_tier("AZKVAuditLogs")
    mgal = plan["activity:MicrosoftGraphActivityLogs"]["kql"]
    assert "MicrosoftGraphActivityLogs | where UserId == ActorId" in mgal




def test_every_table_a_detection_can_fire_on_gets_a_grounded_plan():
    """The check that would have caught the drift. File, queue and table storage
    were fireable targets with no correlation entry, so `pivot_plan` returned []
    and their playbooks fell back to prose -- no grounded pivot, and nothing said
    so, because the fallback is a legitimate path for an unmapped table."""
    from pylon.services import all_tables

    for table in sorted(all_tables()):
        hops = pivot.pivot_plan(table)
        assert hops, f"{table} can fire and gets no grounded pivot"
        assert pivot.render_pivot_block(table).startswith("Grounded pivot queries")


def test_the_four_storage_services_pivot_the_same_way():
    """They share their identity columns, so a queue detection's playbook reaches
    the same actor across the same hops a blob detection does."""
    shapes = {t: [h["tier"] for h in pivot.pivot_plan(t)]
              for t in ("StorageBlobLogs", "StorageFileLogs",
                        "StorageQueueLogs", "StorageTableLogs")}
    assert len(set(map(tuple, shapes.values()))) == 1, shapes
    for table in shapes:
        same = next(h for h in pivot.pivot_plan(table) if h["tier"] == "data-same")
        assert "RequesterObjectId == ActorId" in same["kql"]
        assert "AccountName == TargetResource" in same["kql"]


def test_no_pivot_wraps_a_dynamic_column_in_parse_json():
    """The generated pivots ARE the model's example. They wrapped Identity and
    InitiatedBy in parse_json, which the Key Vault table asset forbids by name
    ("Identity is DYNAMIC, not a JSON string. Do NOT call parse_json() on it"),
    so a run was told the rule in its schema reference and handed the violation
    in its grounded pivots. It copied the pivots, twice, and I blamed the model
    both times. Three tests asserted the wrong form and locked it in.
    """
    from pylon.correlation import _tables
    from pylon.pivot import render_pivot_block

    checked = 0
    for table in sorted(_tables()):
        block = render_pivot_block(table)
        if not block:
            continue
        checked += 1
        assert "parse_json(" not in block, (
            f"{table}'s pivots wrap a dynamic column in parse_json(), which the "
            "table assets forbid and which the model copies verbatim")
    assert checked, "no table rendered a pivot block -- this check is inert"


def test_a_column_holding_either_shape_is_matched_against_both():
    """AzureActivity.Caller is `upn_or_oid` in the correlation map and means it.

    Comparing it to one shape silently finds nothing for the other. Over thirty
    days of one tenant: 15,139 rows hold a UPN, 8,222 an object id. The pivot
    asked for an object id, so it returned zero every time a user did the thing
    -- the case the detections it ships with fire on. Valid KQL, zero rows,
    forever, which is the same shape as filtering on a field that does not exist.
    """
    from pylon import correlation as co
    from pylon.pivot import _predicate

    assert any(f["kind"] == "upn_or_oid" for f in co.actor_fields("AzureActivity")), (
        "this test is about the upn_or_oid case; the catalogue no longer has one")

    predicate, lets = _predicate("AzureActivity")
    assert "in (ActorId, ActorUpn)" in predicate, predicate
    assert len(lets) == 2, lets


def test_a_column_holding_one_shape_still_compares_to_that_shape():
    """The fix must not widen a table whose actor column is unambiguous."""
    from pylon.pivot import _predicate

    predicate, lets = _predicate("AZKVAuditLogs")
    assert "==" in predicate and " in (" not in predicate, predicate
    assert len(lets) == 1, lets

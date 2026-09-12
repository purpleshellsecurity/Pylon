"""The catalogue is the list, and the gate is what keeps it honest.

This used to run backwards. A hand-written list of seventeen picker labels drove
everything: a resource type could not be reached unless somebody remembered to
add a friendly name for it, so the NAME, which is decoration, gated the DATA,
which is the point. Adding a service meant filling in the stores and then also
remembering the list -- and forgetting the list was silent.

Now three files decide, and each is one somebody had to fill in anyway:

  1. the data plane has an answer -- `RESOURCE_OVERLAY` routes it, or
     `NO_DATA_PLANE` says in writing that there is none;
  2. the ARM operations are judged, under `rejected_by_service`;
  3. a surface survives the per-surface gate.

Every refusal below is here because the thing it refuses has shipped as a target
that looked supported and was not.
"""

import pytest

from pylon.catalog import DISPLAY_NAMES, NO_DATA_PLANE
from pylon.catalog.overlay import RESOURCE_OVERLAY
from pylon.services import (ENTRA_KEY, TableFacts, _arm_partitioned,
                            _redundant_subresource, _table_facts, all_tables,
                            resolve_target, tables_for, targets)

_TARGETS = list(targets().values())
_IDS = [t.key for t in _TARGETS]


def test_the_candidates_are_the_resource_types_the_catalogue_wrote_down():
    """Nothing declares a target. Every key is a resource type that appears in
    the routing overlay or in the written record of having no data plane."""
    declared = {k.lower() for k in RESOURCE_OVERLAY} | {k.lower() for k in NO_DATA_PLANE}
    # Keys are lowercased for lookup; `Target.key` carries the canonical spelling.
    # Every Entra target -- the directory and its eleven category slices -- comes
    # from the audit catalogue rather than the resource overlay.
    arm = {k for k in targets() if not k.startswith(ENTRA_KEY.lower())}
    assert arm <= declared


@pytest.mark.parametrize("target", _TARGETS, ids=_IDS)
def test_every_target_queries_at_least_one_grounded_table(target):
    assert tables_for(target.key)


def test_an_ungroundable_resource_type_is_refused():
    """Data Factory and AKS are real Azure resource types with real operations and
    no verdict on any of them. Accepting either would produce a run that reads
    correct and is grounded in nothing."""
    assert resolve_target("Microsoft.DataFactory/factories") is None
    assert resolve_target("Microsoft.ContainerService/managedClusters") is None
    assert resolve_target("Microsoft.DocumentDB/databaseAccounts") is None
    assert resolve_target("not-a-resource-type") is None
    assert resolve_target("") is None


def test_a_routed_resource_with_no_arm_verdict_still_does_not_appear():
    """AKS, Cosmos, Event Hub and Service Bus all have authored routing. Routing
    is not grounding: the operations behind them were never judged, so having a
    table to query does not make them askable."""
    for rt in ("Microsoft.ContainerService/managedClusters",
               "Microsoft.DocumentDB/databaseAccounts",
               "Microsoft.EventHub/namespaces",
               "Microsoft.ServiceBus/namespaces"):
        assert rt in RESOURCE_OVERLAY
        assert not _arm_partitioned(rt)
        assert resolve_target(rt) is None


def test_the_arm_partition_is_checked_per_resource_type_not_per_table():
    """AzureActivity carries every provider in Azure, so asking whether the TABLE
    has a partition always says yes. Answering it that way opens all 14,850."""
    assert _arm_partitioned("Microsoft.KeyVault/vaults")
    assert _arm_partitioned("Microsoft.Storage/storageAccounts/queueServices")
    assert not _arm_partitioned("Microsoft.DataFactory/factories")


def test_a_subresource_earns_a_target_only_by_bringing_its_own_table():
    """A sub-resource's ARM operations are a SUBSET of its parent's -- measured:
    74 of the 163 on Microsoft.Sql/servers. So Microsoft.Sql/servers/databases,
    whose only data-plane table the gate refuses, would be a second SQL target
    covering strictly less than the first. Storage is the other way: each of
    blob/file/queue/tableServices brings a log of its own."""
    assert resolve_target("Microsoft.Sql/servers/databases") is None
    assert resolve_target("Microsoft.Sql/servers") is not None
    for kind in ("blob", "file", "queue", "table"):
        assert resolve_target(f"Microsoft.Storage/storageAccounts/{kind}Services")

    kept = {"a": ("AzureActivity",), "a/b": ("AzureActivity",),
            "a/c": ("AzureActivity", "OwnLog")}
    assert _redundant_subresource("a/b", kept)
    assert not _redundant_subresource("a/c", kept)


def test_web_sites_runs_control_plane_only_and_names_what_it_dropped():
    target = resolve_target("Microsoft.Web/sites")
    assert target.tables == ("AzureActivity",)
    assert len(target.refused) == 6
    for table in ("AppServiceHTTPLogs", "FunctionAppLogs", "AppServiceAuditLogs"):
        assert any(table in r for r in target.refused)


def test_a_table_with_no_schema_asset_cannot_back_a_surface():
    assert not _table_facts("AppServiceHTTPLogs").has_schema_asset


def test_a_part_examined_vocabulary_is_refused_not_averaged():
    """`unaccounted` is never a judgement. A name in neither the mapped nor the
    rejected pile means nobody looked, and the difference between that and
    "considered and turned down" is the whole point of keeping two piles."""
    facts = TableFacts(table="X", operations=frozenset({"a", "b"}),
                       mapped=frozenset({"a"}), rejected=frozenset(),
                       has_schema_asset=True)
    assert facts.unaccounted == {"b"}
    assert not facts.partitioned


@pytest.mark.parametrize("target", _TARGETS, ids=_IDS)
def test_a_missing_display_name_does_not_cost_a_target(target):
    """This is what "decoration" means. The label is a product name a person
    recognises; a resource type with no entry still resolves, still runs, and
    shows its resource type instead. Under the old list a nameless resource was
    unreachable."""
    if target.resource_type:
        assert target.label == DISPLAY_NAMES.get(target.key, target.key)
    assert resolve_target(target.key) is not None


def test_the_consumers_do_not_keep_their_own_copy_of_the_table_list():
    """Modules used to hold their own list of which tables exist. A copy in a
    validator goes stale silently: the table stops being offered, the row stays,
    and nothing notices."""
    from pylon.prompts import _dataplane_tables

    assert _dataplane_tables() <= all_tables()
    assert "AzureActivity" not in _dataplane_tables()


def test_a_target_removed_from_the_catalogue_disappears_everywhere_at_once():
    import pylon.prompts as prompts
    import pylon.services as services

    caches = (services.targets, services.all_tables)
    for cache in caches:
        cache.cache_clear()
    try:
        original = dict(RESOURCE_OVERLAY)
        RESOURCE_OVERLAY.pop("Microsoft.Storage/storageAccounts/queueServices")
        for cache in caches:
            cache.cache_clear()
        assert resolve_target("Microsoft.Storage/storageAccounts/queueServices") is None
        assert "StorageQueueLogs" not in prompts._dataplane_tables()
    finally:
        RESOURCE_OVERLAY.clear()
        RESOURCE_OVERLAY.update(original)
        for cache in caches:
            cache.cache_clear()


@pytest.mark.parametrize("target", [t for t in _TARGETS if t.resource_type], ids=[
    t.key for t in _TARGETS if t.resource_type])
def test_a_resource_run_is_handed_both_vocabularies_it_must_choose_from(target):
    """The regression that moving the CLI to resource mode introduced.

    `build_resource_prompt` carried the schema and the routing rules and neither
    grounding block, so every ARM and data-plane run lost the curated ATT&CK
    vocabulary it had been getting through the platform prompt: 25.8k of prompt
    became 10.7k, and the model went back to recalling technique IDs instead of
    choosing from a list. Nothing failed, because a recalled ID is a real ID.

    The operation list is the other half, and it is the whole point of the gate: a
    resource type is only a target because every operation behind it has a
    verdict, so the prompt can say "these are the operations and there are no
    others" instead of "do not invent one".
    """
    from pylon.prompts import build_resource_prompt

    threat = build_resource_prompt(target.resource_type, "threat", list(target.surfaces))
    assert "<technique_reference>" in threat
    assert "<operation_reference>" in threat
    for table in target.tables:
        assert table in threat


@pytest.mark.parametrize("phase", ["detection", "playbook"])
def test_the_vocabularies_are_not_paid_for_once_per_detection(phase):
    """Phase 1 chooses the technique and the operation; phase 2 is handed both on
    the attack vector and phase 3 responds to a finished detection. Injecting the
    lists into all three was measured at ~2,600 tokens x 16 calls on a run whose
    entire input was 44,000."""
    from pylon.prompts import build_resource_prompt

    target = resolve_target("Microsoft.KeyVault/vaults")
    built = build_resource_prompt(
        target.resource_type, phase, list(target.surfaces),
        playbook_target="a vector" if phase == "playbook" else None)
    assert "<operation_reference>" not in built
    assert "<technique_reference>" not in built


def test_every_operation_offered_to_the_model_is_one_the_validator_accepts():
    """The prompt hands over a list and the validator checks what comes back. If
    they read different stores, a name could be offered and then rejected."""
    from pylon.services import operation_vocabulary
    from pylon.validation.operation import validate_operation

    for key in ("Microsoft.KeyVault/vaults",
                "Microsoft.Storage/storageAccounts/queueServices"):
        target = resolve_target(key)
        for table in target.tables:
            for name in operation_vocabulary(target.resource_type, table)[:8]:
                assert not validate_operation(name, table), (
                    f"{table} offers {name!r} and the validator warns about it")


def test_entra_is_capitalised_and_still_matches_any_case():
    """It sits in a list beside `Microsoft.KeyVault/vaults`, and a lone lowercase
    entry reads like a different kind of thing. Lookup is unaffected for the same
    reason `MICROSOFT.WEB/SITES` works: keys are lowercased and so is the input."""
    assert ENTRA_KEY == "Entra"
    for typed in ("Entra", "entra", "ENTRA", "  Entra  "):
        target = resolve_target(typed)
        assert target is not None and target.key == "Entra"



# --- the directory, sliced ----------------------------------------------------
#
# A whole-directory run named 33 vectors out of 922 activities -- 3.6% of the
# surface, against Key Vault's 55 of 97. The 33 were the well-known paths, which
# is what makes a 3.6% sample read as a complete answer. It touched 14 of 48
# categories and never looked at 34 holding 461 activities.


def test_the_big_categories_are_targets_and_the_thin_ones_are_not():
    """A size decides, not a list, so the catalogue still owns the answer. The
    smallest that clears is Authentication at 32; the largest that does not is
    Device at 18, and AuthorizationPolicy has one activity."""
    from pylon.services import ENTRA_CATEGORY_MINIMUM
    from pylon import entra_audit_activities as entra

    for category in entra.categories():
        big = len(entra.activities_for(category)) >= ENTRA_CATEGORY_MINIMUM
        assert bool(resolve_target(f"Entra {category}")) is big, category


def test_a_category_too_thin_for_a_threat_analysis_is_refused():
    """Thin targets are what got Microsoft 365 and Defender for Endpoint cut."""
    for refused in ("Entra Device", "Entra AuthorizationPolicy", "Entra Contact",
                    "Entra Nope", "Entra"  " Other"):
        assert resolve_target(refused) is None, refused


def test_the_whole_directory_target_remains():
    """The 26 small categories hold 461 activities between them and are reachable
    only through it, so removing it would make them unreachable."""
    assert resolve_target(ENTRA_KEY) is not None


def test_a_slice_carries_its_category_and_the_whole_does_not():
    assert resolve_target("Entra RoleManagement").entra_category == "RoleManagement"
    assert resolve_target(ENTRA_KEY).entra_category == ""
    assert resolve_target("Microsoft.KeyVault/vaults").entra_category == ""


def test_a_slice_is_grounded_on_its_own_activities_only():
    """Handing the model all 922 is what produced the 3.6% sample."""
    from pylon.services import operation_vocabulary

    scoped = operation_vocabulary("", "AuditLogs", "RoleManagement")
    whole = operation_vocabulary("", "AuditLogs")
    assert 30 <= len(scoped) < len(whole)
    assert set(scoped) <= set(whole)


def test_a_spaced_target_resolves_however_it_is_typed():
    for typed in ("Entra RoleManagement", "entra rolemanagement",
                  "  Entra RoleManagement  "):
        assert resolve_target(typed).key == "Entra RoleManagement"

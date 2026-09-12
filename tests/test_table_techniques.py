"""The curated table -> technique index must be honest about itself.

The index is the one catalog in this repo that is hand-authored rather than
harvested, so the guard rails are here: every technique ID must resolve in the
vendored ATT&CK catalog, every claim must carry a basis, and the operation
literals must be stored in the same slug form the KQL parser produces —
otherwise an operation-resolution match would silently never fire and every rule
would degrade to 'ambiguous' without anyone noticing.
"""

from pylon.catalog import table_techniques as tti
from pylon.catalog.attack import load_catalog
from pylon.library import _slug


def test_index_loads():
    assert len(tti.indexed_tables()) > 5


def test_every_technique_id_exists_in_the_attack_catalog():
    known = {t.id_norm() for t in load_catalog()}
    unknown = [
        (table, claim.technique)
        for table, entry in tti.index().items()
        for claim in entry.techniques
        if claim.technique not in known
    ]
    assert unknown == [], f"technique IDs not in the ATT&CK catalog: {unknown}"


def test_every_claim_carries_a_basis():
    missing = [
        (table, claim.technique)
        for table, entry in tti.index().items()
        for claim in entry.techniques
        if not claim.basis.strip()
    ]
    assert missing == [], f"claims with no stated basis: {missing}"


def test_operations_are_stored_slugified():
    # Operation literals are slugified out of KQL; the index must match
    # that form or operation-resolution lookups can never hit.
    for entry in tti.index().values():
        for claim in entry.techniques:
            for op in claim.operations:
                assert op == _slug(op)


def test_operation_lookup_pins_a_technique():
    assert tti.techniques_for("AZKVAuditLogs", _slug("SecretGet")) == {"T1555.006"}
    assert tti.techniques_for(
        "AzureActivity", _slug("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE")
    ) == {"T1098.003"}


def test_unknown_operation_returns_empty_not_a_guess():
    assert tti.techniques_for("AZKVAuditLogs", "not-a-real-operation") == set()


def test_tables_without_an_operation_vocabulary_are_table_resolution_only():
    # SigninLogs has no OperationName column at all — every claim must be
    # unscoped, so rules on it can only ever be matched at table resolution.
    for claim in tti.candidates("SigninLogs"):
        assert not claim.operation_scoped()
    assert tti.techniques_for("SigninLogs", "anything") == set()


def test_unindexed_table_is_unknown_not_empty():
    # has_table() False is the signal callers use to report the table separately
    # instead of counting it as supporting nothing.
    assert not tti.has_table("SomeTableWeHaveNeverSeen")
    assert tti.candidates("SomeTableWeHaveNeverSeen") == ()


def test_indexed_tables_are_ones_the_tool_actually_grounds():
    # Guards against the index drifting into tables the rest of the tool knows
    # nothing about (which would produce gaps nobody could act on).
    from importlib import resources

    grounded = {
        f.name[:-3]
        for f in (resources.files("pylon.prompts") / "assets" / "tables").iterdir()
        if f.name.endswith(".md")
    }
    assert tti.indexed_tables() <= grounded


# ── The partition ───────────────────────────────────────────────────────────
#
# A table that carries `rejected` claims that every operation it can log was
# looked at. Without that claim, "absent from the file" and "considered and
# turned down" are the same thing on disk, and only one of them is a bug. These
# tests are what make the claim hold: a newly harvested operation that lands in
# neither half fails the suite instead of quietly becoming an unexamined gap.

import pathlib

import pytest
import yaml

from pylon import data_plane_operations as dp

_CATALOG = (
    pathlib.Path(__file__).resolve().parents[1]
    / "src" / "pylon" / "catalog" / "table-techniques.yaml"
)


def _raw() -> dict:
    return yaml.safe_load(_CATALOG.read_text(encoding="utf-8"))["tables"]


def _vocabulary(table: str) -> set[str]:
    """The names the table can log. Data-plane tables carry a curated operation
    file; AuditLogs carries the Entra activity reference."""
    if table == "AuditLogs":
        from pylon import entra_audit_activities as entra

        return {a for c in entra.categories() for a in entra.activities_for(c)}
    return set(dp.operations(table))


def _partitioned() -> list[str]:
    """Tables that claim a complete partition of their operation vocabulary."""
    return sorted(t for t, b in _raw().items() if b.get("rejected"))


def test_at_least_one_table_is_partitioned():
    # Guards the guard: the parametrized tests below would pass vacuously over
    # an empty list, which is the `grep -L` over zero files failure again.
    assert "AZKVAuditLogs" in _partitioned()


@pytest.mark.parametrize("table", _partitioned())
def test_a_partitioned_table_covers_every_operation_it_can_log(table):
    """Was Key Vault only. Parametrized once the four Storage data-plane tables
    made the same claim, so that finishing a table means the same thing on every
    table rather than only on the first one."""
    block = _raw()[table]
    # Case-insensitive, because AuditLogs deliberately carries BOTH spellings of
    # the conditional access activities: the case Microsoft documents and the
    # case a live tenant was measured writing. Comparing exactly would report the
    # measured spellings as names Entra never writes, which is backwards.
    lower = lambda names: {n.lower() for n in names}
    mapped = lower(op for c in block["techniques"] for op in (c.get("operations") or []))
    rejected = lower(block["rejected"])
    harvested = lower(_vocabulary(table))

    assert harvested, "the harvested vocabulary is empty — nothing to partition"
    assert not (mapped & rejected), (
        f"mapped AND rejected: {sorted(mapped & rejected)}. An operation cannot "
        f"be both."
    )
    assert not (mapped | rejected) - harvested, (
        f"named but not a real operation: {sorted((mapped | rejected) - harvested)}. "
        f"A detection grounded on it filters on a value the log never writes."
    )
    assert not harvested - mapped - rejected, (
        f"unaccounted for: {sorted(harvested - mapped - rejected)}. Every operation "
        f"must be mapped to a technique or listed under `rejected` with a reason, "
        f"so that absence stays readable as a harvesting fault."
    )


def test_every_rejection_states_a_reason_or_cites_a_rule():
    """A rejection carries either its own sentence or the name of a rule stated
    once at the top of the table's block.

    AuditLogs is why the second form exists. It rejects 462 activities, and 462
    individual sentences would restate the operation name 462 times and bury the
    judgment that actually matters, which is the RULE. Citing one puts the
    argument in a single place a reviewer can attack.
    """
    thin = []
    for table, block in _raw().items():
        rules = set(block.get("rejection_rules") or {})
        for op, reason in (block.get("rejected") or {}).items():
            text = " ".join(str(reason).split())
            if text in rules:
                continue
            if len(text) < 20:
                thin.append((table, op))
    assert thin == [], (
        f"rejections with a label instead of a reason: {thin}. Give it a sentence, "
        f"or cite a rule declared in this table's `rejection_rules`."
    )


def test_every_declared_rejection_rule_is_actually_cited():
    """A rule nothing cites is a judgment nobody is applying, sitting in the file
    looking like policy."""
    orphans = []
    for table, block in _raw().items():
        cited = set((block.get("rejected") or {}).values())
        for rule in (block.get("rejection_rules") or {}):
            if rule not in cited:
                orphans.append((table, rule))
    assert orphans == [], f"rules declared and never cited: {orphans}"


def test_every_rule_a_rejection_cites_is_declared():
    """The other direction. A citation of a rule that does not exist reads as a
    reason and says nothing."""
    dangling = []
    for table, block in _raw().items():
        rules = set(block.get("rejection_rules") or {})
        for op, reason in (block.get("rejected") or {}).items():
            text = " ".join(str(reason).split())
            if text.startswith("R-") and text not in rules:
                dangling.append((table, op, text))
    assert dangling == [], f"rejections citing an undeclared rule: {dangling}"


def test_a_cloud_table_never_claims_a_host_only_technique():
    """The prompts have always carried this rule in prose -- "map every technique
    to the ATT&CK CLOUD matrix; never use host/endpoint techniques for a cloud
    operation" -- and the catalog had nothing enforcing it.

    So five Key Vault certificate operations shipped mapped to T1553 (Subvert
    Trust Controls), which ATT&CK lists for Linux, Windows and macOS and no cloud
    platform at all. Every existing check passed: the ID is real, it resolves in
    the bundle, and the basis reads plausibly. Nothing asked whether the technique
    can occur where the log is written.

    Endpoint tables are exempt because their `platform` label is not an ATT&CK
    platform string; the claim here is only that a CLOUD table's techniques must
    be reachable from the cloud.
    """
    import json

    cloud = {"IaaS", "Identity Provider", "Office Suite", "SaaS", "Containers"}
    index = json.loads(
        (_CATALOG.parent / "mitre_index.json").read_text(encoding="utf-8")
    )["techniques"]

    offenders = []
    for table, block in _raw().items():
        if block.get("platform") not in cloud:
            continue
        for claim in block.get("techniques") or []:
            platforms = set((index.get(claim["id"]) or {}).get("platforms") or [])
            if platforms and not (platforms & cloud):
                offenders.append((table, claim["id"], sorted(platforms)))

    assert offenders == [], (
        f"host-only techniques claimed for cloud tables: {offenders}. The technique "
        f"cannot occur where this log is written, so the detection is grounded on a "
        f"mapping that is wrong before a single row is read."
    )


# ── AzureActivity, per service ──────────────────────────────────────────────
#
# AzureActivity is ONE table behind every ARM target, so a flat rejection list
# over it would be meaningless: 10,623 operations could appear there and almost
# none is a security event. Completeness is claimed one SERVICE at a time, and
# only for services whose operations someone has actually read.

def _control_plane_ops(scope: str) -> set[str]:
    """Operations under `scope` that could appear in AzureActivity, upper-cased.

    A scope is either a provider ("Microsoft.KeyVault") or a resource type
    ("Microsoft.Network/networkSecurityGroups"), and the slash decides which.
    Both are legitimate. A resource type is what a design target actually names,
    and matters where the provider holds far more: Microsoft.Network has 750
    control-plane writes across 249 types, of which six are security groups.
    A provider scope is the stricter claim, since it is a superset.

    Two filters, and they are not equally solid. `isDataAction` is Azure's own
    field: a data action lands in the resource's own audit log rather than here.
    The read filter rests on this catalog's own note that AzureActivity is
    write-side only, applied by checking for a trailing /read -- a naming
    convention rather than a field. If that note is wrong the denominator is
    larger, and the cost is operations that never get a decision, not wrong ones.
    """
    if "/" in scope:
        from pylon.provider_operations import control_plane_operations

        return {o.upper() for o in control_plane_operations(scope)}

    import gzip
    import json

    raw = (_CATALOG.parent / "provider-operations.json.gz").read_bytes()
    ops = json.loads(gzip.decompress(raw))["operations"]
    return {
        k.upper() for k, v in ops.items()
        if k.lower().startswith(scope.lower() + "/")
        and k.rsplit("/", 1)[-1].lower() != "read"
        and not (isinstance(v, dict) and v.get("isDataAction"))
    }


def _azure_activity():
    return _raw()["AzureActivity"]


def test_a_service_claiming_completeness_accounts_for_every_operation():
    """The same partition Key Vault's data plane holds, on the control-plane
    side. An operation in neither half is a service somebody stopped halfway
    through, and that must read differently from one nobody started."""
    block = _azure_activity()
    by_service = block.get("rejected_by_service") or {}
    assert by_service, "no service claims a complete control-plane partition"

    mapped = {o.upper() for c in block["techniques"] for o in (c.get("operations") or [])}
    for provider, rejected in by_service.items():
        real = _control_plane_ops(provider)
        assert real, f"{provider} has no control-plane operations in the catalog"
        rej = {k.upper() for k in (rejected or {})}
        mine = mapped & real

        assert not (mine & rej), (
            f"{provider}: mapped AND rejected: {sorted(mine & rej)}")
        assert not ((mine | rej) - real), (
            f"{provider}: named but not a real control-plane operation: "
            f"{sorted((mine | rej) - real)}. Either it is a read, a data action, "
            f"or it does not exist.")
        assert not (real - mine - rej), (
            f"{provider}: unaccounted for: {sorted(real - mine - rej)}. Every "
            f"operation must be mapped or rejected with a reason, so that absence "
            f"stays readable as work not yet done.")


def test_the_finished_services_are_named_not_counted():
    """Editing this list is how finishing a service becomes a deliberate act.
    A count would let one drift in; the names make someone type it.

    AzureActivity carries every ARM provider, so it is never "done" and should
    not pretend to be. What it can be is done for the services Pylon offers as
    targets, and this is that list."""
    assert sorted(_azure_activity().get("rejected_by_service") or {}) == [
        "Microsoft.Authorization/roleAssignments",
        "Microsoft.Automation/automationAccounts",
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Insights/diagnosticSettings",
        "Microsoft.KeyVault",
        "Microsoft.Network/networkSecurityGroups",
        "Microsoft.Resources/subscriptions/resourceGroups",
        "Microsoft.Sql/servers",
        "Microsoft.Storage/storageAccounts",
        "Microsoft.Web/sites",
    ]


def test_every_control_plane_rejection_states_a_reason():
    thin = [
        (provider, op)
        for provider, rejected in (_azure_activity().get("rejected_by_service") or {}).items()
        for op, why in (rejected or {}).items()
        if len(" ".join(str(why).split())) < 20
    ]
    assert thin == [], f"rejections with a label instead of a reason: {thin}"


def test_every_arm_target_pylon_offers_has_a_complete_partition():
    """The list above is what has been finished. This is what was PROMISED.

    Pylon offers ten services on the ARM platform. A user picking one is told
    Pylon covers it, and the only thing that makes that true is a complete
    control-plane partition for the resource type behind the label. Without
    this test the two lists drift apart silently: a service can be offered in
    the picker for months with nothing behind it, and the run comes back thin
    rather than wrong, which is the harder failure to notice.

    The map is written out because Azure's resource type is not derivable from
    a display label. Adding an ARM service to the picker fails here until its
    resource type is named and its operations are partitioned.
    """
    from pylon.prompts.constants import PLATFORMS

    resource_type = {
        "Key Vault": "Microsoft.KeyVault",
        "Storage Account": "Microsoft.Storage/storageAccounts",
        "Virtual Machine": "Microsoft.Compute/virtualMachines",
        "Network Security Group": "Microsoft.Network/networkSecurityGroups",
        "SQL Server": "Microsoft.Sql/servers",
        "App Service": "Microsoft.Web/sites",
        # A function app IS a Microsoft.Web/sites resource with kind=functionapp,
        # so both labels share one resource type and one partition. The 33
        # function-specific operations in it -- key writes and key reads, host
        # system keys, runtime invocation, WebJob runs -- are already mapped or
        # rejected there.
        "Azure Functions": "Microsoft.Web/sites",
        "Automation Account": "Microsoft.Automation/automationAccounts",
        "Role Assignment": "Microsoft.Authorization/roleAssignments",
        "Diagnostic Settings": "Microsoft.Insights/diagnosticSettings",
        "Resource Group": "Microsoft.Resources/subscriptions/resourceGroups",
    }
    arm = next(p for p in PLATFORMS if p.id == "arm")
    offered = [s if isinstance(s, str) else s.label for s in arm.services]

    unmapped = [s for s in offered if s not in resource_type]
    assert unmapped == [], (
        f"ARM services offered with no resource type named here: {unmapped}. "
        f"Name the Azure resource type, then partition its operations."
    )

    partitioned = set(_azure_activity().get("rejected_by_service") or {})
    thin = [s for s in offered if resource_type[s] not in partitioned]
    assert thin == [], (
        f"offered to users but never partitioned: {thin}. Every operation of "
        f"the resource type must be mapped to a technique or rejected with a "
        f"reason before the service is offered as a target."
    )


# ATT&CK lists a technique's platforms, and a table is written on exactly one of
# them. Asking only whether a technique is reachable from SOME cloud is a weaker
# question than the one that matters, and it let three claims through: a
# technique ATT&CK places on IaaS and SaaS, claimed on a table Entra writes.
#
# Each exception below is a deliberate, argued decision. Adding a line is how a
# disagreement with ATT&CK's platform list becomes visible instead of silent.
_PLATFORM_EXCEPTIONS: dict[tuple[str, str], str] = {
    ("AuditLogs", "T1531"): (
        "Account Access Removal describes exactly what deleting or disabling an "
        "Entra user does, and ATT&CK lists it for Office Suite and SaaS but not "
        "for Identity Provider -- while Entra is the identity provider BEHIND "
        "both. Kept, because swapping to Account Manipulation would name the act "
        "less accurately in order to satisfy a list."
    ),
}


def test_a_technique_is_reachable_from_the_platform_the_table_is_written_on():
    """The stricter form of the test above.

    The loose version asks whether a technique touches ANY cloud platform, which
    is how T1553 would have been caught and T1531 would not: T1531 lists IaaS,
    Office Suite and SaaS, so it passes the loose check while being absent from
    the platform AuditLogs is actually written on.
    """
    import json

    cloud = {"IaaS", "Identity Provider", "Office Suite", "SaaS", "Containers"}
    index = json.loads(
        (_CATALOG.parent / "mitre_index.json").read_text(encoding="utf-8")
    )["techniques"]

    offenders = []
    for table, block in _raw().items():
        platform = block.get("platform")
        if platform not in cloud:
            continue
        for claim in block.get("techniques") or []:
            platforms = set((index.get(claim["id"]) or {}).get("platforms") or [])
            if not platforms or platform in platforms:
                continue
            if (table, claim["id"]) in _PLATFORM_EXCEPTIONS:
                continue
            offenders.append((table, platform, claim["id"], sorted(platforms)))

    assert offenders == [], (
        f"techniques claimed on a table whose platform ATT&CK does not list: "
        f"{offenders}. Either the technique is wrong for this log, or the "
        f"disagreement with ATT&CK is deliberate -- record it in "
        f"_PLATFORM_EXCEPTIONS with the reason, so a reviewer can argue with it."
    )


def test_every_platform_exception_is_still_needed():
    """An exception that no longer applies is a claim nobody is checking. ATT&CK
    adds platforms between versions, and when it adds one of these the line here
    must go rather than sit as permanent permission."""
    import json

    index = json.loads(
        (_CATALOG.parent / "mitre_index.json").read_text(encoding="utf-8")
    )["techniques"]
    raw = _raw()
    stale = []
    for (table, technique), _why in _PLATFORM_EXCEPTIONS.items():
        block = raw.get(table) or {}
        platforms = set((index.get(technique) or {}).get("platforms") or [])
        claimed = any(c["id"] == technique for c in block.get("techniques") or [])
        if not claimed or block.get("platform") in platforms:
            stale.append((table, technique))
    assert stale == [], (
        f"exceptions that are no longer needed: {stale}. Either the claim is gone "
        f"or ATT&CK now lists the platform; delete the line."
    )

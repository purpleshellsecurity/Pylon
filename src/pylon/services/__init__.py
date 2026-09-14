"""One object per service, assembled from the stores that already hold the facts.

WHY THIS EXISTS

Adding one table to this tool touches about twenty source files. Not because the
logic is hard -- because the SAME FACT is written down twenty times in twenty
formats. That StorageBlobLogs belongs to Storage is stated separately in the
alias map, the routing overlay, the correlation map, the category-to-table map,
the coverage module, the prompt chain list and the
KQL validator. None of them knows about the others, so none of them can be wrong
in a way the others notice.

That is not a modularity problem in the code. It is that the DATA has no home,
so it scattered into whichever file needed it next.

WHAT THIS CHANGES

A Service is the home. It answers every question the twenty places currently
answer separately, and it is assembled from the existing stores rather than
duplicating them -- the harvested catalogues stay the source of truth for names,
and the judged files stay the source of truth for meaning. Nothing is copied.

Consumers stop carrying per-service knowledge and start asking the registry.
Adding a service becomes: fill in the stores, and it appears. Adding a service
INCOMPLETELY becomes impossible, which is the point.

THE GATE IS THE FEATURE

`registry()` refuses a service that is not whole: no resource type, no log
surfaces, a table with no schema asset, or an operation vocabulary that is not
fully partitioned. Every one of those has shipped in this repo as a target that
looked supported and was not. AKS carried seven technique claims and zero
operation names for months, behind a picker that never offered it.

WHAT IS DELIBERATELY NOT HERE

The engine's phases, the prompt assembly and the validators. Those are logic and
they are shared. This is the data seam, and the two should not be mixed again.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from functools import lru_cache

from ..catalog import NO_DATA_PLANE, LogSurface, log_surfaces, resolve_resource
from ..catalog.overlay import RESOURCE_OVERLAY


@dataclass(frozen=True)
class TableFacts:
    """Everything one log table needs, in one place.

    `operations` is HARVESTED -- the names the log can write, from Microsoft.
    `mapped` and `rejected` are JUDGED -- what they mean, decided here. The two
    are kept apart on purpose: every serious bug this codebase has had came from
    one being mistaken for the other.
    """

    table: str
    operations: frozenset[str]          # harvested vocabulary
    mapped: frozenset[str]              # judged: carries a technique
    rejected: frozenset[str]            # judged: considered and turned down
    has_schema_asset: bool

    @property
    def unaccounted(self) -> frozenset[str]:
        """Names in neither pile. Never a judgement -- always unfinished work."""
        return self.operations - self.mapped - self.rejected

    @property
    def partitioned(self) -> bool:
        """Every name the table can log has a verdict."""
        return bool(self.operations) and not self.unaccounted


_ASSETS = pathlib.Path(__file__).resolve().parent.parent / "prompts" / "assets" / "tables"
_TECHNIQUES = (
    pathlib.Path(__file__).resolve().parent.parent / "catalog" / "table-techniques.yaml"
)


@lru_cache(maxsize=1)
def _judged() -> dict:
    import yaml

    return yaml.safe_load(_TECHNIQUES.read_text(encoding="utf-8"))["tables"]


def _table_facts(table: str) -> TableFacts:
    """Assemble one table from the stores that already hold its facts.

    Nothing is copied. `data_plane_operations` and `entra_audit_activities` own
    the harvested names; `table-techniques.yaml` owns the verdicts; the prompt
    assets own the schema. This reads all three and says whether they agree.
    """
    from .. import data_plane_operations as dp

    if table == "AuditLogs":
        from .. import entra_audit_activities as entra
        vocab = {a.lower() for c in entra.categories() for a in entra.activities_for(c)}
    elif table == "AzureActivity":
        # AzureActivity carries every ARM provider, so its vocabulary is not one
        # list -- it is per resource type, and completeness is claimed the same
        # way. Handled by the service, not here.
        vocab = set()
    else:
        vocab = {o.lower() for o in dp.operations(table)}

    # The judged layer is read from the file rather than through
    # `table_techniques.entry`, because that view drops `rejected` -- and the
    # rejected half is exactly what distinguishes "considered and turned down"
    # from "nobody looked". Losing it here would defeat the gate below.
    block = _judged().get(table) or {}
    mapped = {o.lower() for c in (block.get("techniques") or [])
              for o in (c.get("operations") or [])}
    rejected = {o.lower() for o in (block.get("rejected") or {})}
    for by_service in (block.get("rejected_by_service") or {}).values():
        rejected |= {o.lower() for o in (by_service or {})}
    return TableFacts(
        table=table,
        operations=frozenset(vocab),
        mapped=frozenset(mapped & vocab) if vocab else frozenset(mapped),
        rejected=frozenset(rejected),
        has_schema_asset=(_ASSETS / f"{table}.md").is_file(),
    )


# ── The list, and where it comes from ─────────────────────────────────────────
#
# The catalogue IS the list. A resource type is a target when three files agree
# about it, and every one of the three is a file somebody had to fill in anyway:
#
#   1. its data plane has an answer -- either `RESOURCE_OVERLAY` routes it to
#      tables, or `NO_DATA_PLANE` says in writing that it has none;
#   2. its ARM operations are fully judged, under `rejected_by_service` in
#      table-techniques.yaml;
#   3. at least one of its surfaces survives the per-surface gate below.
#
# Nothing else declares it. This used to run the other way: a hand-written list
# of seventeen picker labels drove everything, and a resource type could not be
# reached unless somebody remembered to add a friendly name for it -- so the
# name, which is decoration, gated the data, which is the point.
#
# It matters because of what "add a service" means. It is now: route its data
# plane or write down that it has none, judge its operations, and it appears.
# There is no list to remember, which is the only version of this that stays
# true a year from now.

ENTRA_CATEGORY_MINIMUM = 30
"""Fewest activities a Category needs to be worth a target of its own.

A size rather than a list, so the catalogue still decides. Eleven of the
forty-eight clear it; the smallest that does is Authentication at 32 and the
largest that does not is Device at 18.
"""

ENTRA_KEY = "Entra"
"""The one target that is not an ARM resource. A directory has no resource type.

Capitalised because it sits in a list beside `Microsoft.KeyVault/vaults`, and a
lone lowercase entry reads like a different kind of thing. Lookup is unaffected:
every key in `targets()` is lowercased and `resolve_target` lowercases its input,
which is the same reason `Microsoft.Web/sites` matches whatever case Azure used.
"""


@dataclass(frozen=True)
class Target:
    """One thing a user can ask for, and every surface it can be seen on."""

    key: str                            # exactly what the user types
    label: str                          # for output, never for lookup
    resource_type: str                  # "" for Entra
    surfaces: tuple[LogSurface, ...]    # the ones that survived the gate
    refused: tuple[str, ...] = ()       # surfaces left out, each with its reason

    @property
    def tables(self) -> tuple[str, ...]:
        return tuple(s.table for s in self.surfaces)

    @property
    def entra_category(self) -> str:
        """The AuditLogs Category this target is scoped to, or "" for the whole
        directory. It is a real column, so scoping the prompt and scoping the
        query are the same act."""
        head, _, rest = self.key.partition(" ")
        return rest if head == ENTRA_KEY else ""


def _arm_partitioned(resource_type: str) -> bool:
    """Is this resource type's ARM vocabulary fully judged?

    AzureActivity carries every provider in Azure, so "does this table have a
    partition" is the wrong question -- it is answered per resource type, under
    `rejected_by_service`. Without this check the front door would accept all
    14,850 resource-type paths in the harvest and ground detections for ten.

    The judged keys are PREFIXES ("Microsoft.KeyVault" covers `/vaults`) and
    Azure's own casing is inconsistent between the two files, so the match is
    case-insensitive on the prefix.
    """
    judged = (_judged().get("AzureActivity") or {}).get("rejected_by_service") or {}
    rt = resource_type.lower()
    return any(rt == k.lower() or rt.startswith(k.lower() + "/") for k in judged)


def _surface_refusal(surface: LogSurface, resource_type: str) -> str:
    """Why this surface cannot back a detection, or "" if it can."""
    if surface.table == "AzureActivity":
        if not _arm_partitioned(resource_type):
            return f"AzureActivity: no operation partition for {resource_type}"
        return ""
    facts = _table_facts(surface.table)
    # A CONTRACT is grounding, and stronger grounding than a schema asset. The
    # asset lists columns; a contract carries which column holds the caller,
    # which columns exist and are always empty, the typing that cannot be
    # guessed from the values, and query shapes that have been executed against
    # a real workspace. This gate predates contracts, so it refused four App
    # Service tables for lacking the weaker of the two after the stronger had
    # been written and verified.
    from .. import contracts as _contracts

    if not facts.has_schema_asset and surface.table not in _contracts.tables():
        return f"{surface.table}: no schema asset, so its KQL cannot be grounded"
    if not facts.operations:
        # A contract's MEASURED values are a vocabulary. Not the harvested kind
        # -- those come from a published reference and are closed by
        # construction -- but counted in a real workspace, which is what the
        # check downstream actually needs: something to compare a generated
        # literal against. It caught `OperationName == "JobStreams"` on a table
        # where every row says "Job".
        #
        # Whether the set is CLOSED is a separate and stronger claim, recorded
        # per column in `vocabulary_complete`. An access-restriction outcome is
        # closed; a publishing protocol nobody exercised is not.
        from .. import contracts as _contracts

        measured, _complete = _contracts.vocabulary(surface.table)
        if not measured:
            return f"{surface.table}: no operation vocabulary"
    if facts.unaccounted:
        n = len(facts.unaccounted)
        return (f"{surface.table}: {n} operation{'s' if n != 1 else ''} with no "
                f"verdict, so its coverage is part-finished")
    return ""


def _label_for(resource_type: str) -> str:
    """The product name, or the resource type when nobody wrote one down.

    Decoration. `DISPLAY_NAMES` gates nothing -- a resource type with no entry is
    still a target, and still runs. That is the whole difference from the picker
    list this replaced, where the friendly name WAS the list and a resource with
    no name could not be reached.
    """
    from ..catalog import DISPLAY_NAMES

    return DISPLAY_NAMES.get(resource_type, resource_type)


def _redundant_subresource(resource_type: str, kept: dict[str, tuple]) -> bool:
    """True when a parent resource type already covers everything this one has.

    A sub-resource's ARM operations are always a SUBSET of its parent's -- the 74
    on Microsoft.Sql/servers/databases are 74 of the 163 on Microsoft.Sql/servers,
    measured, and the same holds for storage. So a sub-resource earns a target of
    its own only by bringing a data-plane table the parent does not have.

    Storage does: each of blob/file/queue/tableServices has its own log. SQL
    databases does not -- SQLSecurityAuditEvents is refused by the gate, leaving
    it with AzureActivity, which its parent already offers. Without this it would
    appear as a second SQL target covering a strict subset of the first.
    """
    parts = resource_type.split("/")
    for n in range(len(parts) - 1, 0, -1):
        parent = "/".join(parts[:n])
        if parent in kept and set(kept[resource_type]) <= set(kept[parent]):
            return True
    return False


@lru_cache(maxsize=1)
def targets() -> dict[str, Target]:
    """Every target, keyed by the lowercased string a user types.

    Read the section comment above for where the list comes from. The gate runs
    twice, and both refusals have shipped as a target that looked supported:
    per resource type (its ARM vocabulary must be judged) and per surface (a
    table must have a schema asset and a fully partitioned vocabulary).

    Microsoft.Web/sites is why the per-surface half exists. Its six data-plane
    tables have no operation vocabulary and no schema asset between them, so a
    run including them would put six tables in the prompt and be able to check an
    operation name on none of them. It runs control plane only.
    """
    from ..catalog import NO_DATA_PLANE
    from ..catalog.overlay import RESOURCE_OVERLAY

    kept: dict[str, tuple] = {}
    refused: dict[str, tuple] = {}
    for rt in sorted(set(RESOURCE_OVERLAY) | set(NO_DATA_PLANE)):
        if not _arm_partitioned(rt):
            continue
        keep, drop = [], []
        for surface in log_surfaces(rt):
            why = _surface_refusal(surface, rt)
            (drop.append(why) if why else keep.append(surface))
        if not keep:
            continue
        kept[rt] = tuple(s.table for s in keep)
        refused[rt] = (tuple(keep), tuple(drop))

    out: dict[str, Target] = {}
    for rt, (surfaces, dropped) in refused.items():
        if _redundant_subresource(rt, kept):
            continue
        out[rt.lower()] = Target(
            key=rt,
            label=_label_for(rt),
            resource_type=rt,
            surfaces=surfaces,
            refused=dropped,
        )

    # One target per Entra audit category big enough to carry a threat analysis.
    #
    # Measured: a whole-directory run named 33 vectors out of 922 activities --
    # 3.6% of the surface, against Key Vault's 55 of 97. The 33 were the
    # well-known paths (credential addition, conditional access, federation,
    # consent), which is what makes a 3.6% sample read as a complete answer. It
    # touched 14 of 48 categories and never looked at 34 holding 461 activities,
    # among them ResourceManagement's 171 and EntitlementManagement's 57.
    #
    # The threshold is a size, not a list. Below thirty activities a category
    # cannot carry a threat analysis -- AuthorizationPolicy has one -- and thin
    # targets are what got Microsoft 365 and Defender for Endpoint cut. The 26
    # small ones stay reachable through the whole-directory `Entra` target, which
    # is why that one remains.
    from .. import entra_audit_activities as _entra

    for category in _entra.categories():
        if len(_entra.activities_for(category)) < ENTRA_CATEGORY_MINIMUM:
            continue
        key = f"{ENTRA_KEY} {category}"
        out[key.lower()] = Target(
            key=key,
            label=f"Entra ID directory changes: {category}",
            resource_type="",
            surfaces=(),
        )

    out[ENTRA_KEY.lower()] = Target(
        key=ENTRA_KEY,
        label="Entra ID directory changes",
        resource_type="",
        surfaces=(),                    # not an ARM resource; AuditLogs is fixed
    )
    return out


def resolve_target(typed: str) -> Target | None:
    """A typed target, or None. Case-insensitive: Azure's own casing varies."""
    return targets().get(typed.strip().lower())


def tables_for(key: str) -> tuple[str, ...]:
    """The tables a target queries. Entra's is fixed and has no surface list."""
    target = resolve_target(key)
    if target is None:
        return ()
    return target.tables or ("AuditLogs",)


@lru_cache(maxsize=1)
def all_tables() -> frozenset[str]:
    """Every table any target can query. What the consumers used to each keep
    their own copy of."""
    return frozenset(t for key in targets() for t in tables_for(key))


def vocabulary_is_closed(table: str) -> bool:
    """Does this table's operation list account for every name it can write?

    The difference between a warning and an error. When every operation has a
    verdict -- mapped to a technique, or rejected in writing -- a name that is in
    neither pile is not "unrecognised", it is wrong, and shipping a detection
    that filters on it ships a rule that cannot fire.

    False for AzureActivity, and correctly: its vocabulary is per resource type,
    not per table, so the table alone cannot answer whether a name is real.
    """
    return _table_facts(table).partitioned


def operation_column(table: str) -> str:
    """The column a query must filter on to name an operation in `table`.

    AzureActivity is the trap. `OperationName` exists there and holds a DISPLAY
    name ("Create or Update Key Vault"); the string Azure documents and the
    catalogue harvests lives in `OperationNameValue`. A filter on the wrong one
    parses, runs, and matches nothing.

    One home for the fact: the validator reads the operation out of a query with
    it, and `design list` shows it to whoever is writing the query by hand.
    """
    if table == "AzureActivity":
        return "OperationNameValue"
    from .. import data_plane_operations as dp

    return dp.field_for(table) or "OperationName"


def operation_match(table: str) -> tuple[str, str]:
    """The comparison operator a filter on `table` must use, and why.

    AuditLogs is the one that bites. The catalogue holds the names Microsoft
    DOCUMENTS, and a tenant writes them in a different case -- the reference says
    "Delete Conditional Access policy" and the tenant logged "Delete conditional
    access policy". `==` is case-sensitive in KQL, so it matches nothing and the
    rule looks healthy. `entra_audit_activities.render_for_prompt` says this at
    length to the model; this is the same fact in the one line a listing has room
    for, so the two cannot disagree about the operator.

    AzureActivity is the second, and it was found by a reader comparing this
    function against the ARM prompt rules: those say "filter on OperationNameValue
    using =~ for case-insensitive matching" and this returned `==`. Both reach the
    model in the SAME prompt, so it was being told two different things about one
    operation string. The rule is the considered statement -- `==` was the
    unconsidered fallthrough -- so this agrees with it now, and
    `test_the_operator_is_one_fact` fails if they part again.
    """
    if table == "AuditLogs":
        return "=~", "case-insensitive: a tenant spells these differently than the docs"
    if table == "AzureActivity":
        return "=~", "case-insensitive: the ARM rules require it on OperationNameValue"
    return "==", ""


def operation_vocabulary(resource_type: str, table: str,
                         category: str = "") -> tuple[str, ...]:
    """Every operation `table` can carry for `resource_type`, sorted.

    Three stores answer this, one per table shape, and the caller should not have
    to know which: ARM control-plane operations are per RESOURCE TYPE (which is
    why this takes one), Entra activities are per category, and a data-plane
    table owns a flat list.
    """
    if table == "AzureActivity":
        from .. import provider_operations as po

        return tuple(sorted(po.control_plane_operations(resource_type)))
    if table == "AuditLogs":
        from .. import entra_audit_activities as entra

        # One category when the target is a slice of the directory. Reporting the
        # whole 922 for `Entra RoleManagement` would describe a run that is not
        # the one about to happen.
        if category:
            return entra.activities_for(category)
        # An activity can sit under more than one category, so the union is a
        # multiset. 1,171 category rows are 922 distinct activity names.
        return tuple(sorted(
            {a for c in entra.categories() for a in entra.activities_for(c)}))
    from .. import data_plane_operations as dp

    return tuple(sorted(dp.operations(table)))

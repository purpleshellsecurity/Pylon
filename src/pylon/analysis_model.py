"""The analysis contract, declared rather than implied.

`analysis.py` shapes a `GapReport` into a dict. That makes the data model
implicit in a shaping function: the only way to know what a field may hold is to
read the code that fills it, and the only way to know a run produced a valid
document is to look at it. This declares the same document as types, so the
shape can be validated and the rules it is supposed to follow can FAIL rather
than be remembered.

Two rules are enforced here instead of being conventions.

**Unknown is not zero, and not an empty list.** Every optional leg of the scan
is represented three ways and they are kept apart: a list is `None` when the leg
did not run, `[]` when it ran and found nothing, and populated otherwise. Same
for counts. `_legs_agree` checks this against `reads` and raises when a document
claims a measurement it never took — which is the failure the cost meter, the
table-plan interlock and the dark-resource count each taught separately.

**Provenance travels with the value.** A tier read from the owner's tag and one
guessed from an ARM type are different kinds of fact. Any field that can be
guessed carries the route that produced it, and the routes are an enum so a
consumer can filter rather than trust.

Pydantic rather than dataclasses because the repo already depends on it, it
serialises `datetime` without a custom encoder, and `model_json_schema()` emits
the contract as JSON Schema for consumers that are not Python.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = 1


class Strict(BaseModel):
    """Every model here forbids unknown fields.

    Pydantic ignores them by default, which means a renamed field validates
    clean and silently arrives as its default: `is_gap` -> `is_index_gap` passed
    every check while the value was dropped on the floor. A contract that
    accepts a field it does not understand is not validating the document, it is
    agreeing with it.
    """

    model_config = ConfigDict(extra="forbid")

# Every optional leg of the scan, and the part of the document it fills. The
# validator walks this, so adding a leg here is what makes it checked.
LEGS: dict[str, str] = {
    "inventory": "resources",
    "table_activity": "tables",
    "rules": "rules",
    "gaps": "gaps",
    "resource_activity": "coverage_gaps",
    "provisioned_tables": "provisioned_tables",
}


class ReadState(Strict):
    """Whether one read happened, and what it returned.

    `ran=False` with a `detail` is a permissions failure, a missing dependency
    or a deliberate skip — all of which must read differently from a leg that
    ran and found nothing.
    """

    ran: bool
    detail: str | None = None


class Reads(Strict):
    """One entry per leg. Absent legs default to not-run, which is the safe
    direction: a document that forgot to declare a read claims nothing."""

    inventory: ReadState = ReadState(ran=False)
    table_activity: ReadState = ReadState(ran=False)
    # The control-plane list of tables that EXIST here, which is a different
    # call and a different failure from the data-plane activity read above. One
    # can answer while the other does not.
    provisioned_tables: ReadState = ReadState(ran=False)
    resource_activity: ReadState = ReadState(ran=False)
    rules: ReadState = ReadState(ran=False)
    rule_audit: ReadState = ReadState(ran=False)
    differential: ReadState = ReadState(ran=False)
    # Was `table_plans`, and it never held one: `inventory` populated it from
    # `sentinelhealth.probe`, and `Reads` had no field for Sentinel health at
    # all. Nothing read it, so the misfiling was invisible. The module it was
    # named for went with the gap-scan removal; the leg it actually carries is
    # live, so the name follows the data.
    sentinel_health: ReadState = ReadState(ran=False)
    diagnostic_settings: ReadState = ReadState(ran=False)
    endpoint_census: ReadState = ReadState(ran=False)
    defender_plans: ReadState = ReadState(ran=False)
    role_assignments: ReadState = ReadState(ran=False)
    platforms: ReadState = ReadState(ran=False)
    gaps: ReadState = ReadState(ran=False)
    library: ReadState = ReadState(ran=False)
    generation: ReadState = ReadState(ran=False)


# ── Layer 1: what the tenant runs ─────────────────────────────────────────────

CriticalitySource = Literal["tag", "type_default", "name_heuristic", "unrated"]

# Which input placed `exposure_rank`. Named after the STRONGEST signal that
# decided the tier, so a reader can tell a rank that came from a measured
# privileged assignment from one that came from finding nothing:
#   role_assignment       a privileged role decided it (tiers 0, 2, 3)
#   public_network_access reachability decided it, no privileged role (tier 1)
#   scope                 both checks ran and found nothing (tier 4). NOT the
#                         resource's `scope` field -- it means "placed by being
#                         an ordinary resource with no exposure signal on it"
#   unrated               a check needed to place it did not run. Distinct from
#                         tier 4 in exactly the way `not_assessed` is distinct
#                         from `not-enabled`: unmeasured, not clean
ExposureSource = Literal["public_network_access", "role_assignment", "scope",
                         "unrated"]

# Where a telemetry source sits in Azure's containment hierarchy. Telemetry
# reaches a SIEM by mechanisms that differ by SCOPE, not by resource type: an
# identity sign-in, a control-plane write, a resource's own diagnostic log and
# a read of the data INSIDE that resource are four different questions with
# four different remediations, and only the third is a diagnostic setting on
# the resource itself. Rows carry the scope they were measured at so a
# consumer can ask one question at a time instead of reading a merged status
# that answers none of them cleanly.
#   data_plane  who touched the DATA in a resource -- a blob read, a secret
#               fetched. Structurally separate in Azure (storage keeps these
#               on child services), and separate here for the same reason.
#   sentinel    not "is the log produced" but "can the SIEM receive it":
#               connectors and Defender plans. Kept in the same three states
#               because an unconnected connector is a gap like any other.
Scope = Literal["tenant", "subscription", "resource", "data_plane", "sentinel"]


class Resource(Strict):
    """One resource, its importance, and how far this run got with it.

    `assessment_status` and `logging_status` are separate on purpose. "Did this
    run assess the resource" and "is the resource logging" are different
    questions, and one field answering both means a resource the scan never
    reached is indistinguishable from one it reached and found dark.
    """

    resource_id: str
    resource_type: str
    # Defaults to `resource` so a document written before scopes existed still
    # validates and still means what it said.
    scope: Scope = "resource"
    subscription: str | None = None
    region: str | None = None

    # The owner's own word, verbatim — "Tier 0", "P1", "business-critical". Never
    # rewritten into this file's vocabulary, because it is the one authoritative
    # signal available and normalising it would substitute an opinion for it.
    criticality_tier: str
    # The same judgement as a sortable integer, 0 highest. None where the tier is
    # a string nothing here can rank — which is most tag values, and is why the
    # verbatim field exists. A consumer ordering a queue reads this and can tell
    # an unrankable tier from a low one.
    criticality_rank: int | None = None
    criticality_source: CriticalitySource

    # STRUCTURAL exposure, deliberately not a second criticality. Criticality is
    # the owner's opinion, read from a tag; this is measured from the resource's
    # own configuration and from RBAC, and no part of it is inferred from tags
    # or from names.
    #
    # Reachability as Azure reports it. `None` means the type has no such
    # concept -- a disk, a resource group -- while "unknown" means the type DOES
    # expose one and this run did not get a value. Collapsing the two would read
    # as "not reachable" for a resource nobody checked.
    public_network_access: Literal["enabled", "disabled", "unknown"] | None = None
    # The property and value that decided it, verbatim -- e.g.
    # "networkAcls.defaultAction=Allow". Every other claim in this document
    # carries its basis; a reachability verdict with none is a bare assertion,
    # and the reader cannot check whether it means an open firewall or
    # anonymous access, which are very different findings.
    public_network_access_basis: str | None = None
    # Role names (Owner, Contributor, User Access Administrator) held at or
    # above this resource. Empty means the read ran and found none; a resource
    # whose read did not run carries exposure_source="unrated" instead, because
    # an empty list here would otherwise claim a clean result.
    privileged_role_assignments: list[str] = Field(default_factory=list)
    # 0 = most exposed. Explicit tiers, never a weighted sum: a summed score
    # reads as precise while its weights are invented, and this file's whole
    # discipline is that a number can be traced to something measured.
    exposure_rank: int | None = None
    exposure_source: ExposureSource = "unrated"

    # Did THIS RUN reach the resource. A workflow state, about the scan.
    #   out_of_scope  the type has no log categories at all — a disk, a NIC, a
    #                 serverfarm, a managed identity. Nothing to switch on, so
    #                 it can never be dark, and counting it made the headline
    #                 73 of 77 where the finding was 32 of 36.
    #   not_assessed  the run could not determine it: the catalog has no opinion
    #                 on the type, or the inventory returned counts and no ids.
    assessment_status: Literal["assessed", "not_assessed", "out_of_scope"]

    # What was FOUND. An outcome, about the tenant. None where there is no
    # outcome to state — never a string standing in for one.
    #   partial-enabled  observable, but not across every surface it has.
    #                 Folding this into `not-enabled` either overstates the
    #                 outage or buries it, which `PartialCoverage` already
    #                 decided at type level.
    logging_status: Literal["fully-enabled", "partial-enabled", "not-enabled"] | None = None

    @model_validator(mode="after")
    def _unrated_has_no_rank(self):
        if self.criticality_source == "unrated" and self.criticality_rank is not None:
            raise ValueError("an unrated resource cannot carry a rank")
        return self

    @model_validator(mode="after")
    def _exposure_rank_and_source_agree(self):
        """Tier 4 means checked and clean; `unrated` means never checked.

        Letting the two blur is the failure this whole field is exposed to: a
        role read that silently returned nothing would otherwise present every
        resource in the tenant as measured and unexposed.
        """
        if self.exposure_source == "unrated" and self.exposure_rank is not None:
            raise ValueError("an unrated resource cannot carry an exposure_rank")
        if self.exposure_source != "unrated" and self.exposure_rank is None:
            raise ValueError(
                f"exposure_source={self.exposure_source} with no rank: a check "
                "that ran and placed nothing is unrated")
        return self

    @model_validator(mode="after")
    def _status_and_outcome_agree(self):
        """Only four of the nine combinations mean anything.

        `not_assessed` with an outcome is an accusation about a resource nobody
        measured — the shape this whole report exists to prevent. `assessed`
        with no outcome is `not_assessed` wearing a different label.
        """
        if self.assessment_status == "assessed" and self.logging_status is None:
            raise ValueError(
                "assessed with no logging_status: a run that looked and has no "
                "answer is not_assessed"
            )
        if self.assessment_status != "assessed" and self.logging_status is not None:
            raise ValueError(
                f"{self.assessment_status} carries logging_status="
                f"{self.logging_status!r}: an outcome for a resource this run "
                "did not measure"
            )
        return self


# ── Layer 2: what is arriving ─────────────────────────────────────────────────

# The vocabulary diagnostic_settings.classify already uses. Reused verbatim
# rather than restated: two sets of words for one question is how a report ends
# up needing a decoder ring.
DarkReason = Literal[
    # These two were one value, "never configured", and the report had to key on
    # (reason, has_setting) to tell them apart -- a decoder ring for a
    # distinction the document could have carried itself. They are different
    # states with different fixes: create a setting, or tick a box on the one
    # that is already there.
    "no diagnostic setting",
    "category not enabled",
    "metrics only, no log categories",
    "ships elsewhere",
    "configured here — idle in the window",
    "settings unreadable",
]


class CoverageGap(Strict):
    """A resource that should be logging to a table and is not.

    `dark_reason` is what makes the row actionable, and one of its values —
    `configured here — idle in the window` — is not a gap at all. Counting an
    idle-but-correct resource with the misconfigured ones is how a report
    inflates its own findings, so the reason is required rather than optional.
    """

    resource_id: str
    expected_table: str
    is_logging: bool
    days_since_last_log: float | None = None
    dark_reason: DarkReason
    categories_to_enable: list[str] = Field(default_factory=list)
    # Derived from criticality_rank; None until the resource carries a rankable
    # tier. Never defaulted to a middle value — a severity invented from a
    # missing tier looks exactly like a measured one.
    gap_severity: Literal["high", "medium", "low"] | None = None
    # How `expected_table` was arrived at. Which table a category fills depends
    # on `logAnalyticsDestinationType` on the diagnostic setting — so a resource
    # with NO setting has nothing to read the mode from, and the name is the
    # documented default rather than a reading. That is exactly the resource
    # every remediation line is about, which is why this is recorded instead of
    # left implicit. Defaults to `assumed`: a gap that does not say it measured
    # the mode did not measure it.
    mode_basis: Literal["measured", "assumed"] = "assumed"


# ── Layer 3: health ───────────────────────────────────────────────────────────


class TableHealth(Strict):
    """One table the Usage meter saw inside the window.

    `table_tier` is `None` where the plans could not be read, which refuses every
    query rather than assuming Analytics — an unknown plan is not a free one.
    `is_gap` is a gap in PYLON's technique index, NOT in the tenant: the table
    has data and nothing here can say what it could detect. The name is
    ambiguous — it reads as "this table is a gap" — and is kept anyway, because
    renaming a shipped field to fix a docstring's job is churn. It is a worklist
    for extending table-techniques.yaml, and it is not the input to
    `no_data_no_rule`; see docs/no-data-no-rule.md for why those are near
    inverses.
    """

    table_name: str
    table_tier: Literal["Analytics", "Basic", "Auxiliary"] | None = None
    last_ingest: datetime | None = None
    megabytes: float | None = None
    # The part of `megabytes` the workspace is actually charged for, from the
    # Usage meter's own IsBillable column. `None` means the meter did not price
    # the table; `0.0` means it priced it and charges nothing, which is a real
    # answer for SecurityAlert, SecurityIncident, AzureActivity, SentinelHealth
    # and the Office 365 connectors. The two must not read alike.
    billable_megabytes: float | None = None
    # Whether anything at all is charged for, independent of the rounded
    # figure above. A table billed for a few kilobytes rounds to 0.0 MB, and
    # printing that as "free" is the one direction a cost claim must not fail
    # in. None means the meter did not price the table.
    billable: bool | None = None
    is_gap: bool = False


# All six verdicts the live check produces. `inconclusive` (ran clean but over
# the rule's own window, so the lookback was never reached) and `not_assessed`
# (the billing interlock refused the query) are not `never_fires`: a tier
# limitation stated as a dead rule is an accusation that was never measured.
RuleHealth_ = Literal[
    "broken", "fires", "never-fires", "inconclusive", "unreadable", "not-assessed",
]

# How a rule's technique was established. `same-table` is the ambiguous case — a
# rule reads a table that could carry the technique and nothing here can tell
# whether it covers it. It is not "none": folding it up overstates coverage,
# folding it down manufactures a gap.
MappingBasis = Literal["labelled", "rule-metadata", "kql-operation", "same-table", "none"]


class RuleHealth(Strict):
    """One deployed, enabled scheduled rule.

    `rule_id` is the ARM GUID. It is `None` today because `_to_existing_rule`
    keeps `display_name` and discards it — and a display name is not an id: not
    unique, not stable across a rename. Anything joining these rows must join on
    `rule_id`, which is why it is declared and nullable rather than omitted.
    """

    rule_id: str | None = None
    name: str
    # ALERT severity — how bad if it fires. Not `criticality_tier`, which is
    # business impact of an asset: a different scale, and conflating them puts
    # "High" and "Tier 0" in one column. Values are Sentinel's own, verified
    # against azure-mgmt-securityinsight 1.0.0 `AlertSeverity`. To weight rule
    # health by what it protects, join tables_referenced -> the resources those
    # tables carry -> criticality_tier; that is a join, not a field on a rule.
    rule_severity: Literal["Informational", "Low", "Medium", "High"] | None = None
    rule_health_status: RuleHealth_ | None = None
    health_detail: str | None = None
    technique_mapping_confidence: MappingBasis = "none"
    # WHICH techniques, not only how the mapping was established. Without
    # these, joining a rule to a technique needs a second source and the
    # confidence field describes a claim the document does not carry.
    techniques: list[str] = Field(default_factory=list)
    tables_referenced: list[str] = Field(default_factory=list)


# ── Layer 4: gaps and what to do about them ───────────────────────────────────

# Seven values, each earning its slot by naming a distinct action. See
# docs/detection-suggestion-surfaces.md for the precedence order.
GapType = Literal[
    "covered",
    "covered_by_product",
    "needs_confirmation",
    "available_not_deployed",
    "plan_available_not_enabled",
    "data_no_rule",
    "no_data_no_rule",
    # Nothing in the installed Content Hub even mentions this technique, so
    # there is no template to deploy and no logging change that would reach it.
    # It exists because the candidate set is now ATT&CK narrowed by measured
    # platforms rather than the template list: under the old denominator this
    # row was unrepresentable, and the coverage figure silently excluded every
    # gap Microsoft has no content for.
    "no_content",
]


class Gap(Strict):
    """One candidate technique and what should be done about it.

    Every candidate is carried, `covered` included: the partition over the
    candidate set is what makes the headline counts checkable, and emitting only
    the non-covered rows removes the check that catches a technique counted
    twice or dropped.
    """

    technique_id: str
    technique_name: str = ""
    gap_type: GapType
    # The evidence that decided the verdict. Required, because a gap_type with
    # nothing behind it is a claim the reader cannot argue with.
    basis: str
    supporting_tables: list[str] = Field(default_factory=list)
    # ATT&CK tactics, from the grounding step. Carried because the largest
    # bucket -- techniques nothing here addresses -- is unreadable as a flat
    # list of 82 rows and legible when grouped by what the adversary is trying
    # to do.
    tactics: list[str] = Field(default_factory=list)


class Backtest(Strict):
    """What a suggested detection would have alerted on. Measurements, no verdict.

    `window_days_covered` is never omitted: the retrohunt discovers queryable
    history from the table, so a four-day read and a quiet detection return the
    same zero and only this tells them apart. There is deliberately no
    false-positive estimate — a count on a new detection is ambiguous in both
    directions — and no actor list, which would put principal names in a file
    that gets handed to clients.
    """

    hit_count: int
    window_days_asked: int
    window_days_covered: int
    distinct_principals: int | None = None
    busiest_day: int | None = None
    p95_hourly: int | None = None


class SuggestedDetection(Strict):
    """A proposal. `status` and `reviewed_by` are joined in from the detection
    library at write time, not state this document owns — which is what keeps the
    document regenerable."""

    suggestion_id: str
    gap_technique_id: str
    tier: Literal["deploy", "adapt", "draft"]
    source_template_id: str | None = None
    # The template's own name and severity, copied rather than referenced.
    # A pointer cannot go stale and a copy can -- but this document is a
    # dated snapshot by construction (`generated_at`, and a separate cadence
    # from the analysis for exactly that reason), so a label inside it is no
    # staler than the document around it. A suggestion nobody can read
    # without a second lookup is not a deliverable.
    source_template_name: str | None = None
    source_template_severity: Literal[
        "Informational", "Low", "Medium", "High"] | None = None
    # Microsoft's own sentence about what the detection does, carried verbatim.
    #
    # It is here because it answers a question no structured field in this
    # document can. Whether a detection applies is not just "do I have the
    # tables" -- it is whether the thing it watches exists here, and that turns
    # on a distinction the schema cannot make: a rule that watches activity ON
    # a resource is useless without the resource, while a rule that watches the
    # CREATION of one is most useful when you have none. "Modified domain
    # federation trust settings" is the case in point: this tenant has zero
    # federated domains, and the description says it fires on "Update domain
    # authentication from Managed to Federated" -- so the absence is the reason
    # to keep it, not to drop it.
    #
    # Modelling that was tried and abandoned. One sentence a reader can scan
    # settles in a second what a filter got wrong in both directions.
    source_template_description: str | None = None
    # Tables this template reads that hold NO data in the target workspace.
    # Empty means every table it needs is fed. A suggestion that would deploy
    # a rule onto an empty table is how a recommendation manufactures the
    # never-fires rule the analysis just finished reporting, so the shortfall
    # travels with the suggestion rather than being left for a reader to
    # rediscover. None where it was not checked, which is not the same as
    # nothing missing.
    tables_missing: list[str] | None = None
    draft_kql: str | None = None
    backtest: Backtest | None = None
    status: Literal["proposed", "approved", "deployed"] = "proposed"
    reviewed_by: str | None = None


# ── The summary, and the document ─────────────────────────────────────────────


class Summary(Strict):
    """Headline counts, computed once here so no renderer computes them again.

    Counts whose leg is optional are `int | None`; the always-measured core stays
    `int`. There is deliberately no `needs_attention` total: it would sum an
    optional leg (dark resources) with a mandatory one (uncovered techniques),
    and one headline combining halves of different provenance is the bug the
    73-of-77 dark count already taught.
    """

    # Always measured — the core computation runs or there is no scan.
    fresh_tables: int = 0
    unindexed_tables: int = 0
    techniques_covered: int = 0
    techniques_ambiguous: int = 0
    techniques_uncovered: int = 0
    # The index knows these and this tenant produces none of their telemetry.
    # Counted here and kept OUT of the three above, which partition the
    # candidate set — a technique with no telemetry is not a candidate.
    techniques_no_telemetry: int = 0
    rules_total: int = 0

    # Optional legs. None means the leg did not run.
    rules_executed: int | None = None
    fires: int | None = None
    never_fires: int | None = None
    inconclusive: int | None = None
    unreadable: int | None = None
    broken_rules: int | None = None
    downstream_defects: int | None = None
    # The subset of never-fires the static check cannot see: the rule's table
    # HAS data, so only running the rule reveals it.
    never_fires_on_live_tables: int | None = None
    # Refused by the billing interlock. Never `broken` and never `never_fires`:
    # a tier limitation is not a judgement about a detection.
    not_run_billable: int | None = None
    resources: int | None = None
    resource_types: int | None = None
    dark_resources: int | None = None
    loggable_resources: int | None = None
    tables_checked: int | None = None
    tables_billable: int | None = None

    heaviest_gap: str | None = None
    heaviest_gap_name: str | None = None


SolutionAction = Literal[
    # Microsoft retired it. Installed content nobody maintains looks like
    # coverage and is not.
    "remove",
    # Installed, and its data connector delivers nothing. Its rule templates
    # sit in the library and cannot fire. Named for the CONNECTOR rather than
    # the solution: "enable" on a row whose Installed column reads 3.0.7 asks
    # the reader to install what they already have.
    "connect",
    # Installed and delivering, but a newer version is published.
    "update",
    # Installed, current, delivering -- and its detections are switched off.
    # Distinct from "none" because "nothing to do" measured the SOLUTION and
    # ignored whether it detects anything: one tenant was told nine things
    # needed attention while the same report's second table said 212 rule
    # templates had never been turned into an analytics rule.
    #
    # Only issued when the presence test PASSED. A test that could not run is
    # not a tenant that needs the content, and without that gate a tenant with
    # no OT devices gets told to switch on fifteen IoT detections.
    "enable",
    # Not installed, and every table its connector delivers already holds data.
    "install",
    # Installed, and it declares no data connector, so whether it applies here
    # was NOT measured. Distinct from "none": unjudged, not judged fine.
    "review",
    "none",
]


class Solution(Strict):
    """One Content Hub solution, and what to do about it.

    The unit is the solution rather than the rule template because that is what
    Content Hub installs and what an operator switches on. The template-level
    version of this document emitted one row per Microsoft rule whose tables
    held data, which produced 119 rows that shared table names -- `Event` from
    one Windows host passed every domain-controller template -- and filtering
    it to 72 made it shorter without making it a decision.
    """

    solution_id: str
    display_name: str
    publisher: str | None = None
    installed: bool
    version_installed: str | None = None
    version_available: str | None = None
    deprecated: bool = False
    # How the tenant was matched to the solution, and the evidence. Never the
    # solution's name: `Azure Kubernetes Service (AKS)` is installed in a
    # tenant with no cluster, and only a measurement catches that.
    # fed         something it needs holds data
    # unfed       a resource here would emit it and the log is not switched on
    # repoint     a resource produces it and ships it somewhere else
    # no_source   RESERVED. Nothing in this tenant emits what it needs. Not
    #             currently assignable: coverage_gaps only measures resources
    #             with a diagnostic setting, so an unmeasured table cannot be
    #             distinguished from an unemitted one.
    # no_rules    it ships no analytics rules, so no detection can be dark
    # unseen      the tables it needs received nothing in the window, and
    #             whether a source could be configured was not assessed
    # unmeasured  nothing here measures those tables at all, so whether the
    #             tenant produces them was never established
    # unmatched   its rule templates could not be matched by name to the
    #             alert-rule templates that carry the queries
    # unknown     RETIRED, and kept in the union only so an analysis.json
    #             written before the split still loads. Nothing emits it.
    alignment: Literal["fed", "unfed", "repoint", "no_source", "no_rules",
                       "unseen", "unmeasured", "unmatched", "unknown"]
    basis: str
    data_types: list[str] = Field(default_factory=list)
    analytics_rules: int = 0
    # Active rules created from this solution's templates. Installing a
    # solution does NOT switch its rules on: each is created by hand from
    # Analytics > Rule templates. 306 templates are installed in this tenant
    # and one rule has been created from them, which no other field says.
    rules_enabled: int = 0
    # What the solution collects from, and whether this tenant has it. The
    # link Microsoft publishes nowhere, resolved in solutions.py against a
    # vendored service catalogue plus a presence test for the products that
    # are not ARM resources.
    collects_from: str | None = None
    # Every diagnostic category the resource type offers, when the row's advice
    # is to switch logging on. The prose cannot carry 53 of them, and an
    # operator following the advice needs the whole list rather than the three
    # that happen to sort first.
    categories_to_enable: list[str] = Field(default_factory=list)
    action: SolutionAction
    action_detail: str


class Recommendations(Strict):
    """The suggested detections — a SEPARATE document from the analysis.

    Everything in `Analysis` is measured and free, so it can be regenerated as
    often as anyone likes. This costs money and model calls. One file would force
    both to the same cadence: either every refresh of the measured half spends,
    or the document carries a generated section older than the document
    containing it — which is the same "serving verdicts the run did not measure"
    this repo already refused once.

    `analysis_generated_at` is the join back to the measurements these were
    produced against, and it is what lets a reader see that the recommendations
    are older than the analysis beside them. Without it, two files at different
    ages look like one consistent set.
    """

    schema_version: int = SCHEMA_VERSION
    generated_at: datetime
    workspace: str | None = None
    # Which analysis these were derived from. None only where they were produced
    # without one, which should not happen and is visible rather than assumed.
    analysis_generated_at: datetime | None = None
    # What to turn on, enable, update or remove in Content Hub. Replaces the
    # per-template `suggestions` list, which ranked Microsoft's catalogue
    # instead of naming a decision.
    solutions: list[Solution] = Field(default_factory=list)

    # What it cost. `cost_is_partial` makes every figure a stated FLOOR: the
    # provider does not always return usage, and an unreported call is not a
    # free one. Same answer the usage meter arrived at.
    cost_usd: float | None = None
    model_calls: int | None = None
    unreported_calls: int = 0
    cost_is_partial: bool = False

    @model_validator(mode="after")
    def _partial_cost_is_declared(self):
        if self.unreported_calls and not self.cost_is_partial:
            raise ValueError(
                f"{self.unreported_calls} call(s) reported no usage but "
                "cost_is_partial is false: the figure would read as exact"
            )
        return self


class Analysis(Strict):
    """One scan, as a document a consumer can validate before trusting.

    `scope` is structural rather than a disclaimer: a targeted run measures what
    it needed for one technique and nothing else, and a JSON file gets read by
    things that never saw the caveat.
    """

    schema_version: int = SCHEMA_VERSION
    generated_at: datetime
    workspace: str | None = None
    scope: Literal["full", "targeted"] = "full"
    window_days: int = 30
    fresh_days: int = 3

    reads: Reads = Reads()
    summary: Summary = Summary()

    # None everywhere means "this leg did not run". [] means it ran and found
    # nothing. The validator below is what makes that difference real.
    resources: list[Resource] | None = None
    coverage_gaps: list[CoverageGap] | None = None
    tables: list[TableHealth] | None = None
    rules: list[RuleHealth] | None = None
    gaps: list[Gap] | None = None
    # {OSPlatform: device count}. None where the census did not run — distinct
    # from {}, which is a fleet with no devices in it.
    endpoint_os: dict[str, int] | None = None
    # Every table SCHEMA provisioned in the workspace, which is not the same as
    # a table anything writes to. Installing a Content Hub solution provisions
    # its schemas, so this counts solutions as much as it counts telemetry: a
    # real tenant returned 844 here against 34 holding data, with AKSAudit and
    # CDBDataPlaneRequests present while running neither service.
    #
    # It was called `deployed_tables` and was used as proof that a tenant used
    # the resource-specific logging mode. It is not proof of that, and the name
    # is what made it look like proof. Confirmation comes from `tables` — data
    # arrived, so that mode is in use — and this stays as the record of what the
    # installed solutions provisioned, which is a different and still useful
    # fact.
    provisioned_tables: list[str] | None = None

    # What SentinelHealth said, beyond whether the read ran. The read state
    # carries a one-line summary; this carries the parts a report needs to
    # render: which rules Sentinel auto-disabled, and why runs failed.
    #
    # `None` means the read did not run. An `enabled: False` dict means it ran
    # and found the feature switched off, which is a different and reportable
    # fact — health monitoring collects only from the moment it is turned on,
    # so an empty result is not "nothing failed".
    sentinel_health: dict | None = None

    # What this workspace pays under: sku, any daily commitment, retention.
    # Not a leg of its own — it rides along with the table read, and `None`
    # means that read did not answer. A report pricing volume states the plan
    # it priced against, because a per-GB figure without one is a number the
    # customer cannot check.
    workspace_plan: dict | None = None

    @model_validator(mode="after")
    def _legs_agree(self):
        """A section is present exactly when its read ran.

        This is the rule the whole codebase already follows by hand — an empty
        plan map means "could not find out", never "nothing is billable" — made
        into something that fails. Both directions are errors: a populated
        section whose read did not run is a measurement nobody took, and a null
        section whose read DID run silently drops what was measured.
        """
        problems = []
        for leg, section in LEGS.items():
            ran = getattr(self.reads, leg).ran
            value = getattr(self, section)
            if ran and value is None:
                problems.append(f"reads.{leg} ran but {section} is null")
            if not ran and value is not None:
                problems.append(f"reads.{leg} did not run but {section} is populated")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    @model_validator(mode="after")
    def _targeted_scope_is_partial(self):
        """A targeted run cannot present itself as a full assessment."""
        if self.scope == "targeted" and self.reads.inventory.ran:
            raise ValueError(
                "scope=targeted with an inventory read: a targeted run measures "
                "one technique, and a document carrying both reads as an assessment"
            )
        return self

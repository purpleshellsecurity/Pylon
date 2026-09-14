"""Typed phase outputs.

The original app emits one markdown blob per phase; structuring the
*metadata* (attack vectors, detection records) lets the workflow fan out per
vector, validate per query, and score coverage programmatically. The prose
(KQL, playbook steps) stays as text fields.
"""

from typing import Literal

from pydantic import Field, model_validator

from .analysis_model import Strict
from .provenance import Provenance
from .attack_paths import Tag


def _nothing_learned(model, *fields: str) -> None:
    """Raise when `ran` is False and any of `fields` claims a finding.

    The rule the analyze half enforces in `_legs_agree` and this half only wrote
    down: a check that did not run learned nothing, so a result beside `ran=False`
    is a measurement nobody took. Reported together rather than one at a time --
    a caller fixing a contradictory construction wants the whole list.
    """
    if getattr(model, "ran", True):
        return
    # A field is CLAIMED when it differs from its own declared default.
    #
    # This read `not in (None, False, 0, "", [])`, which let every falsy value
    # through -- so `LiveCheck(ran=False, row_count=0)` was accepted. Zero is the
    # dangerous number, not a harmless one: `row_count=0` beside `ran=False`
    # reads as "the query ran and matched nothing", which is the never-fires
    # verdict, asserted by a query that never reached the service. The same hole
    # let `TuneResult(ran=False, p95_hourly=0)` through -- a threshold of zero,
    # from a calibration that did not happen, which is the number most likely to
    # be deployed.
    #
    # Comparing to the declared default rather than to a fixed falsy set is also
    # what keeps this safe across a JSON round-trip: a serialised document
    # carries every field including the ones sitting at their defaults, and
    # `model_fields_set` would call those explicit and refuse a document it had
    # just written.
    claimed = [f for f in fields
               if getattr(model, f, None) != type(model).model_fields[f].default]
    if claimed:
        raise ValueError(
            f"ran=False, so nothing was learned, but {', '.join(sorted(claimed))} "
            f"{'is' if len(claimed) == 1 else 'are'} set"
        )


class AttackVector(Strict):
    """One row of the original Phase 1 'Quick Reference Matrix' — as data."""

    name: str = Field(description="Short attack vector name")
    priority: Literal["critical", "high", "medium", "low"]
    mitre_technique: str = Field(
        description="Verified MITRE ATT&CK technique ID with sub-technique "
        "where applicable, e.g. T1078.004. Never fabricate."
    )
    operation: str = Field(
        description="Exact operation name as it appears in the platform logs "
        "(e.g. MICROSOFT.KEYVAULT/VAULTS/WRITE for ARM)."
    )
    log_table: str = Field(description="Sentinel table the detection queries")
    alert_condition: str = Field(description="One-line alert condition")
    # Prose cannot be checked. A run enumerated five vectors for a surface with
    # two operations, subdividing one of them four ways by request-body fields,
    # and one of the four asked for a state the API does not produce. Reading
    # the field names back out of the prose condition was tried and is not
    # possible -- "remains", "configured" and "sink" are indistinguishable from
    # field names to anything but a reader. So the plan states them.
    distinguishing_fields: list[str] = Field(
        default_factory=list,
        description="ONLY when another vector in this plan uses the same "
        "operation: the exact request-body field names that tell this vector "
        "apart from those, e.g. [\"logs\", \"retentionPolicy\"]. Field names "
        "as they appear in the log, not prose. Leave empty when this vector is "
        "the only one using its operation.",
    )
    rationale: str = Field(
        description="Two sentences: what the operation does and why it is "
        "security-relevant. Facts only — no statistics, no APT attribution."
    )
    requires: list[Tag] = Field(
        default_factory=list,
        description="Attacker footholds that must ALREADY be held before this "
        "action is possible (preconditions). Empty = an entry point that needs "
        "nothing. Choose only from the provided token list; never invent tokens.",
    )
    enables: list[Tag] = Field(
        default_factory=list,
        description="Attacker footholds gained once this action succeeds "
        "(effects). Empty = a terminal objective. Choose only from the token "
        "list; never invent tokens.",
    )


class ThreatAnalysis(Strict):
    """Phase 1 output."""

    service: str
    platform: str
    # What the run was ASKED for, as `design list` spells it. Written by Pylon
    # after Phase 1, never by the model: the model echoed the table into
    # `service` and a saved Entra plan could not be re-opened. Defaulted so a
    # plan written before this field still loads.
    target: str = ""
    # Which build, model and run wrote this. Written by Pylon, never the model,
    # and defaulted so a plan saved before the field still loads. The run id is
    # what joins a plan to the detections and playbooks built from it -- the
    # vector name cannot, because the detection phase rewrites it.
    provenance: Provenance | None = None
    executive_summary: str
    attack_vectors: list[AttackVector]
    # What the plan gate said about this plan. Written by Pylon after Phase 1,
    # never by the model, and defaulted so a plan saved before the field still
    # loads. Warnings rather than deletions: the gate measures one tenant, so a
    # field nobody has triggered is unmeasured, not unreal.
    plan_warnings: list[str] = Field(default_factory=list)
    # "verified" once the MITRE CTI bundle has screened the technique IDs;
    # "unavailable" when the bundle couldn't be fetched (verification did not run —
    # fabricated IDs may have slipped through). Recorded so it's never silent.
    mitre_verification: str = "verified"


class Detection(Strict):
    """Phase 2 output — one per attack vector."""

    vector_name: str
    mitre_technique: str
    kql: str = Field(description="Production-ready KQL query, copy-paste ready")
    tuning_guidance: str = Field(
        description="At most 2 bullet lines, each starting '- ' and at most 20 "
        "words. First: the threshold or scope to start with. Second (only if "
        "there is one): the field to allowlist. Imperative, no preamble, no "
        "restating what the query does.",
    )
    false_positive_notes: str = Field(
        description="The single most likely benign trigger, in one sentence of "
        "at most 25 words. Name it; do not explain the detection.",
    )


class LiveCheck(Strict):
    """Result of executing a detection query against a real workspace (F3, opt-in).

    ``ran`` = the query reached the service (vs. a credential/network failure).
    ``ok`` = it executed without a query error — the difference between
    'syntactically plausible' and 'actually runs against the live schema'.
    ``row_count`` is the count over the lookback (0 is a valid match-nothing run)."""

    ran: bool
    ok: bool = False
    row_count: int | None = None
    error: str = ""


    @model_validator(mode="after")
    def _a_query_that_did_not_run_has_no_result(self):
        """`ran` is whether the query REACHED the service. Without that, `ok` and
        `row_count` are not small numbers, they are absent ones -- and `ok=True`
        beside `ran=False` reads as a detection that runs against the live schema
        when nothing was executed."""
        _nothing_learned(self, "ok", "row_count")
        return self

class OfflineCheck(Strict):
    """Result of running a detection query through the offline KQL engine
    (kustainer) with the table declared as an empty typed datatable (F4). ``ran`` =
    the engine evaluated it; ``ok`` = it parsed and every column/type resolved — a
    fabricated column (`ActorRiskScore`) that the regex validator can't see fails
    here with the engine's own error. No tenant, no data, CI-able."""

    ran: bool
    ok: bool = False
    error: str = ""
    # The engine was CONFIGURED and could not be talked to -- a dead container,
    # a refused connection -- as opposed to never configured. Both leave the
    # gate unrun; only one means the run is broken and should stop. Kept off
    # `ok` deliberately: an unreachable engine has no opinion about the query.
    unreachable: bool = False


    @model_validator(mode="after")
    def _an_engine_that_did_not_evaluate_has_no_verdict(self):
        _nothing_learned(self, "ok")
        return self

class OperationCheck(Strict):
    """What the provider-operations catalog could say about the model-asserted
    operation — which is three answers, not two.

    ``status`` is "known", "unknown" or "provider-absent". The last is the one
    that needed a name: the catalog holds no operations at all for that provider,
    so it cannot judge, and reporting that as a suspect operation is the same
    mistake as reading an unread table plan as free. Absence of evidence.

    A wrong operation is the worst kind of defect this tool can ship — the KQL
    parses, the schema validates, and the rule silently never fires — so how
    thoroughly each one was checked is recorded per detection rather than
    summarised away.
    """

    status: Literal["known", "unknown", "provider-absent"]
    operation: str = ""              # what was checked
    checked: bool = True             # False when nothing could be concluded
    warnings: list[str] = []


class TuneResult(Strict):
    """Workspace-calibrated tuning for a detection (--tune, opt-in). Turns model
    guesses into numbers from THIS tenant: ``hit_count`` = how many times the query
    would have fired over the lookback (a real false-positive proxy, vs the model
    speculating); ``p95_hourly`` = 95th-percentile hourly volume, a data-driven
    threshold; ``top_actors`` = the busiest ActorUpn values, a suggested AllowedActors
    allowlist. ``ran`` is False when the calibration queries could not execute."""

    ran: bool
    hit_count: int | None = None
    p95_hourly: int | None = None
    top_actors: list[str] = []
    error: str = ""


    @model_validator(mode="after")
    def _calibration_that_did_not_run_has_no_numbers(self):
        """A threshold nobody measured is worse than no threshold: it is a number
        someone will deploy."""
        _nothing_learned(self, "hit_count", "p95_hourly", "top_actors")
        return self

class RetrohuntResult(Strict):
    """What a detection WOULD have alerted on, run over historical telemetry.

    The point is the question a detection engineer asks before deploying: would
    this have paged us, how often, and on whom? Aggregates only — the Logs query
    API caps a result at 500,000 rows and ~104 MB, and none of those answers need
    rows returned.

    ``covered_days`` is discovered from the data, never assumed, and it measures
    QUERYABLE HISTORY rather than configured retention — the two are not the same:

    - Retention is per TABLE, not per workspace. Tables inherit the workspace
      default (30 days) but can be set anywhere from 4 to 730.
    - `AzureActivity` and `Usage` keep at least 90 days at no charge, so the table
      behind every ARM detection holds three times what the workspace default
      suggests.
    - Long-term retention is not queryable at all. Data past the analytics period
      is reachable only through a search job, so a table configured for 730 days
      can still answer a normal query with 30.
    - A table that only started collecting ten days ago is indistinguishable from
      one trimmed to ten days. Same consequence here, so this does not claim to
      know which.

    Reading the earliest row present answers the only question that matters — how
    far back can this detection actually be run — without needing any of the
    above. ``truncated`` says the answer came back shorter than asked for.
    """

    ran: bool = False
    requested_days: int = 0
    covered_days: int = 0          # history the workspace actually held
    truncated: bool = False        # covered < requested: the window was cut short
    hits: int | None = None            # rows the detection would have alerted on
    distinct_actors: int | None = None  # how many principals triggered it
    busiest_day: int | None = None      # worst single day, for alert-fatigue sizing
    error: str = ""

    def evidence_record(self) -> dict:
        """This result as a library evidence record (see library.with_evidence).

        A run that could not execute records nothing: an empty record earns no
        status, which is correct — a failed query is not evidence of quiet.
        """
        if not self.ran:
            return {}
        return {
            "covered_days": self.covered_days,
            "requested_days": self.requested_days,
            "truncated": self.truncated,
            "hits": self.hits,
            "distinct_actors": self.distinct_actors,
            "busiest_day": self.busiest_day,
        }


    @model_validator(mode="after")
    def _the_history_covered_agrees_with_what_was_asked(self):
        """`truncated` is not an opinion -- it is whether the queryable history
        fell short of the window requested. Carried as a separate bool, it could
        disagree with the two numbers beside it, and a retrohunt that covered 5
        of 90 days while reporting truncated=False reads as 85 quiet days."""
        _nothing_learned(self, "hits", "distinct_actors", "busiest_day")
        if self.covered_days > self.requested_days:
            raise ValueError(
                f"covered_days ({self.covered_days}) exceeds requested_days "
                f"({self.requested_days}); history cannot be longer than the window"
            )
        if self.truncated != (self.covered_days < self.requested_days):
            raise ValueError(
                f"truncated={self.truncated} contradicts covered_days="
                f"{self.covered_days} of requested_days={self.requested_days}"
            )
        return self

class ProveResult(Strict):
    """A detection observed against a real emulated attack in a lab tenant.

    Two halves, and both are required — a detection that fires on everything is
    not proven, it is broken:

    - ``fired``: the query returned the attack after it was performed.
    - ``benign_quiet``: the same query returned nothing in the window BEFORE it.

    ``timed_out`` is kept separate from ``fired`` on purpose. Azure Monitor
    documents 3-20 minutes of end-to-end latency for Activity logs and 3-10 for
    resource logs, so giving up early says nothing about the detection: the row
    may land after the deadline. A timeout records what was waited, and earns no
    promotion rather than a failure.

    ``detected_after_seconds`` is the ingestion latency actually observed, which
    is worth keeping — it is the number to set the next deadline from.
    """

    ran: bool = False
    fired: bool | None = None
    benign_quiet: bool | None = None
    baseline_hits: int | None = None       # matches in the window before the attack
    detected_after_seconds: int | None = None  # observed ingestion latency
    waited_seconds: int = 0
    deadline_seconds: int = 0
    timed_out: bool = False
    error: str = ""

    def evidence_record(self) -> dict:
        """This result as a library evidence record (see library.with_evidence).

        A run that could not execute records nothing. Note the ladder promotes to
        `stable` only on fired AND benign_quiet, so a timeout or a noisy baseline
        lands at `test` without any special-casing here.
        """
        if not self.ran:
            return {}
        return {
            "fired": self.fired,
            "benign_quiet": self.benign_quiet,
            "baseline_hits": self.baseline_hits,
            "detected_after_seconds": self.detected_after_seconds,
            "waited_seconds": self.waited_seconds,
            "timed_out": self.timed_out,
        }


    @model_validator(mode="after")
    def _a_run_that_could_not_execute_records_nothing(self):
        """`evidence_record` already returns {} when `ran` is False, so a proof
        carrying `fired=True` beside `ran=False` was silently dropped rather than
        rejected -- the maturity ladder never saw it and nothing said why."""
        _nothing_learned(self, "fired", "benign_quiet", "baseline_hits",
                         "detected_after_seconds")
        return self

class ValidatedDetection(Strict):
    """A detection plus its validator verdict (attached by code, not the model)."""

    detection: Detection
    log_table: str
    valid: bool
    errors: list[str]
    warnings: list[str]
    retried: bool
    live_check: LiveCheck | None = None  # F3: populated only when --verify-live runs
    offline_check: OfflineCheck | None = None  # F4: populated only when --verify-offline runs
    tune: TuneResult | None = None  # #5: populated only when --tune runs
    # How the operation string fared against the catalog. Populated on every ARM
    # detection; None where no catalog applies (data-plane vocabularies).
    operation_check: OperationCheck | None = None
    # How much `log_table` is worth. "deployed" = the scanned workspace has this
    # table, so the tenant's legacy/resource-specific choice is confirmed.
    # "catalogue" = we had the list and it is not on it, so this is an
    # assumption. "unchecked" = no scan document, so nothing was compared.
    #
    # Defaults to unchecked, the safe direction: a detection built by a caller
    # that never looked claims nothing. Without this field a guessed table and a
    # confirmed one render identically, and a detection that can never fire
    # produces no complaint -- it produces silence, which reads as a quiet tenant.
    table_basis: Literal["deployed", "catalogue", "unchecked"] = "unchecked"
    prerequisite: str = ""  # diagnostic-setting requirement (resource mode)
    operation: str = ""     # the vector's operation — anchor for saved-list matching
    # How this detection fared against REAL events, when a workspace was
    # configured at generation. None means it was not graded, which is not the
    # same as graded clean -- the distinction every other field here keeps.
    verification: "DetectionVerification | None" = None
    rationale: str = ""     # why this threat matters — surfaced as a KQL comment
    priority: str = ""      # critical|high|medium|low — maps to Sentinel severity
    retrohunt: "RetrohuntResult | None" = None  # what it WOULD have alerted on
    prove: "ProveResult | None" = None  # observed against a real emulated attack
    requires: list[Tag] = Field(default_factory=list)  # attack-path preconditions (from the vector)
    enables: list[Tag] = Field(default_factory=list)   # attack-path effects (from the vector)


    @model_validator(mode="after")
    def _valid_means_no_errors(self):
        """The gate's whole contract. A detection carrying `valid=True` and a
        populated `errors` is one that failed validation and shipped anyway, and
        every consumer reads the flag rather than the list."""
        if self.valid and self.errors:
            raise ValueError(
                f"valid=True with {len(self.errors)} error(s): "
                f"{self.errors[0][:80]}"
            )
        return self

class Playbook(Strict):
    """One IR playbook — for one chosen detection. A run can produce several."""

    target: str  # the detection's vector_name
    text: str    # the playbook markdown


class NarrowingStep(Strict):
    """One line of the peel: a filter, and the rows that survived it.

    `rows` is None when that prefix did not run, which is worth carrying rather
    than dropping -- a prefix that fails to run is itself a finding about the
    query.
    """

    filter: str
    rows: int | None = None


class DetectionVerification(Strict):
    """One detection measured against the events it claims to detect.

    `expected` counts the operation in the raw table; `observed` counts what the
    detection returned over the same window. Two numbers from two independent
    sources -- the detection cannot influence the first one.
    """

    vector_name: str
    operation: str
    expected: int | None = None   # events of this operation in the window
    observed: int | None = None   # rows the detection returned
    verdict: str                  # exact | under | over | dead | aggregates | no-ground-truth | error
    detail: str = ""
    widened: bool = False         # the detection's own time bound was replaced
    # The run that MEASURED this, which is not the run that generated it. A
    # verdict is only as current as the moment it was taken: the detection may
    # have been regenerated since, and the workspace certainly has moved on.
    verified_by: Provenance | None = None
    workspace: str = ""
    # Why it matched nothing, when it matched nothing. Each filter goes back on
    # one at a time and the rows are counted, so the line that reaches zero
    # names the cause instead of leaving the reader to open the KQL. Empty when
    # the query matched rows, when it has fewer than two filters, or when it
    # joins -- see `verification.peel`.
    narrowing: list[NarrowingStep] = []
    killed_by: str = ""


class EngineReport(Strict):
    """Structured result of a full pipeline run.

    The workflow returns data, not prose — rendering (markdown report, .kql
    files, terminal summary) is the CLI's job (report.py).
    """

    service: str
    platform: str
    # The same run id the plan carries, so a report can be traced to the plan
    # that asked for it and to the playbooks written from it.
    provenance: Provenance | None = None
    analysis: ThreatAnalysis
    detections: list[ValidatedDetection]
    playbooks: list[Playbook] = []          # one per picked detection
    playbooks_skipped: list[str] = []       # targets requested but budget-skipped
    # What `design verify` measured, empty until it has run. A detection with no
    # entry here has never been checked against real events -- which is not the
    # same as passing, and is the distinction the whole module exists for.
    verification: list[DetectionVerification] = []
    # Two distinct numbers (see scoring.ProgramScore), never conflated:
    # generation_yield = weighted share of ENUMERATED vectors that got a valid
    # detection (did generation do its job — NOT coverage); catalog_coverage =
    # weighted share of the platform's external ATT&CK catalog covered (the honest
    # coverage number, None when no catalog maps to this platform).
    generation_yield: int
    # How many vectors the PLAN held, when a --pick narrowed what was built.
    # `generation_yield` is scored against what was ATTEMPTED, so a run that
    # picked eight of fifty-five and got eight scores 100%, not 10% -- the
    # forty-seven were never tried and counting them as failures reads a
    # deliberate choice as a broken run.
    vectors_planned: int = 0
    catalog_coverage: int | None = None
    catalog_covered: int = 0
    catalog_total: int = 0
    critical_gaps: list[str]
    # "verified" | "unavailable" — whether MITRE ID screening actually ran (see
    # ThreatAnalysis.mitre_verification). Surfaced so an unreachable bundle is visible.
    mitre_verification: str = "verified"
    # Cost accounting for this run (0 on checkpoint-resume, which re-bills nothing).
    input_tokens: int = 0
    output_tokens: int = 0
    model_calls: int = 0
    # How many of those calls came back with no token counts. Every cost figure
    # on this report is a FLOOR when this is non-zero — the calls happened and
    # their tokens are unknown, which is not the same as free.
    unreported_calls: int = 0
    estimated_cost_usd: float = 0.0

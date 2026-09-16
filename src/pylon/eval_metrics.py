"""Eval metrics — turn a batch of runs into numbers that answer "is it tight?".

The engine is deterministic *code* wrapping a stochastic *model*. These metrics
measure the two things that determine whether the wrapper is doing its job:

  1. Do the gates catch the model's mistakes?  (validator catch-rate, final
     invalid-rate, operation-warning-rate)
  2. Is the output stable enough to trust?      (run-to-run drift / core coverage)

Pure functions over a list of EngineReport — no model, no I/O — so the harness's
own logic is deterministically testable even though a live eval needs a model.
`scripts/eval.py` runs the model N times and feeds the reports here.
"""

from dataclasses import dataclass, field
from itertools import combinations

from .library import detection_key

# Distinctive phrases emitted only by validate_operation (validation/operation.py),
# used to separate operation warnings from KQL-schema warnings in the mixed
# `warnings` list. Heuristic — kept in sync with that module's messages.
_OP_WARNING_MARKERS = (
    "ARM operation",
    "belongs to the resource",
    "provider-operations catalog",  # catalog-miss (control-plane)
    "is not a known",               # data-plane vocabulary miss
)


def is_operation_warning(text: str) -> bool:
    """True if `text` reads as an operation warning (vs a KQL-schema warning), by its
    distinctive validate_operation phrases."""
    return any(m in text for m in _OP_WARNING_MARKERS)


@dataclass
class TargetMetrics:
    """Aggregate over N runs of a single target."""

    target: str
    runs: int
    # Detection counts, summed across runs.
    detections: int = 0
    generated: int = 0          # produced KQL (not budget-skipped)
    valid: int = 0
    invalid: int = 0            # generated but failed validation (leaked through)
    skipped: int = 0            # budget-skipped
    first_pass_failed: int = 0  # validator fired -> a self-correction retry ran
    retry_fixed: int = 0        # retried AND ended valid
    op_warned: int = 0          # detections carrying an operation warning
    refusals: int = 0           # runs that produced zero attack vectors / errored
    # Stability across the N runs (None when runs < 2).
    stability: float | None = None
    core_coverage: float | None = None
    # The detection keys each run produced, in run order. Already computed for
    # `stability` and previously thrown away, which made an A/B of two prompts
    # impossible to analyse: the aggregate says how much a variant drifts, never
    # WHICH vectors it found. Kept per run rather than merged into a union
    # because a union cannot distinguish a vector a variant finds every time
    # from one it found once — and at 41.7% core coverage on this target, most
    # of a union is run-dependent.
    key_sets: list[list[str]] = field(default_factory=list)
    # Cost.
    cost_usd: float = 0.0

    @property
    def invalid_rate(self) -> float:
        """Share of generated detections that failed validation — what leaked."""
        return self.invalid / self.generated if self.generated else 0.0

    @property
    def catch_rate(self) -> float:
        """Of the detections whose first KQL failed, how many the retry fixed.
        A gate that never fires (first_pass_failed == 0) reports 1.0 — nothing to
        catch — so read it alongside first_pass_failed."""
        return self.retry_fixed / self.first_pass_failed if self.first_pass_failed else 1.0

    @property
    def first_pass_fail_rate(self) -> float:
        """How often the model's first KQL was wrong (the gate's workload)."""
        return self.first_pass_failed / self.generated if self.generated else 0.0


@dataclass
class EvalResult:
    """Per-target eval metrics for a batch, plus batch-wide aggregates."""

    per_target: list[TargetMetrics] = field(default_factory=list)

    @property
    def total_cost(self) -> float:
        """Summed estimated USD cost across every target."""
        return sum(t.cost_usd for t in self.per_target)


def detection_keys(report) -> set[str]:
    """Stable identity set for a run's valid detections (mitre|table|operation)."""
    return {
        detection_key(
            d.detection.mitre_technique, d.log_table, d.operation, d.detection.vector_name
        )
        for d in report.detections
        if d.valid and d.detection.kql
    }


def _jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity of two sets; 1.0 when both are empty."""
    union = a | b
    return len(a & b) / len(union) if union else 1.0


def stability(key_sets: list[set[str]]) -> tuple[float | None, float | None]:
    """(mean pairwise Jaccard, core coverage) across runs.

    - pairwise Jaccard = 1.0 means every run produced the identical detection set.
    - core coverage = |detections in EVERY run| / |detections in ANY run|: the
      fraction of the union that is rock-solid across all runs.
    None for both when there are fewer than two runs (nothing to compare)."""
    if len(key_sets) < 2:
        return None, None
    pairs = list(combinations(key_sets, 2))
    mean_jaccard = sum(_jaccard(a, b) for a, b in pairs) / len(pairs)
    union: set[str] = set().union(*key_sets)
    intersection: set[str] = set(key_sets[0]).intersection(*key_sets[1:])
    core = len(intersection) / len(union) if union else 1.0
    return mean_jaccard, core


def metrics_for_target(target: str, reports: list) -> TargetMetrics:
    """Fold N EngineReports for one target into a TargetMetrics."""
    m = TargetMetrics(target=target, runs=len(reports))
    for r in reports:
        # A None report is a run that refused or errored; count it and move on
        # (it contributes no detections and no key set, so drift ignores it).
        if r is None or not r.analysis.attack_vectors:
            m.refusals += 1
            if r is None:
                continue
        m.cost_usd += getattr(r, "estimated_cost_usd", 0.0) or 0.0
        for d in r.detections:
            m.detections += 1
            if not d.detection.kql:
                m.skipped += 1
                continue
            m.generated += 1
            if d.valid:
                m.valid += 1
            else:
                m.invalid += 1
            if d.retried:
                m.first_pass_failed += 1
                if d.valid:
                    m.retry_fixed += 1
            if any(is_operation_warning(w) for w in d.warnings):
                m.op_warned += 1
    per_run = [detection_keys(r) for r in reports if r is not None]
    m.stability, m.core_coverage = stability(per_run)
    # Sorted for a stable diff; the run ORDER is preserved, the within-run order
    # is not meaningful.
    m.key_sets = [sorted(keys) for keys in per_run]
    return m


def _pct(x: float | None) -> str:
    """Format a 0-1 ratio as a right-aligned percentage, or '  n/a' for None."""
    return "  n/a" if x is None else f"{x * 100:5.1f}%"


def format_result(result: EvalResult) -> str:
    """Human-readable report. The four numbers that matter are marked."""
    lines = ["", "=" * 72, "EVAL — is the wrapper doing its job?", "=" * 72]
    for t in result.per_target:
        lines += [
            "",
            f"■ {t.target}   ({t.runs} run{'s' if t.runs != 1 else ''})",
            (
                f"    detections/run ....... {t.detections / t.runs:.1f}  "
                f"({t.valid} valid, {t.invalid} invalid, {t.skipped} skipped, total)"
            ),
            (
                f"    final invalid-rate ... {_pct(t.invalid_rate)}   "
                + ("← nothing leaked past the gate" if not t.invalid
                   else "← LEAKED PAST THE GATE (want 0)")
            ),
            (
                f"    first-pass fail-rate . {_pct(t.first_pass_fail_rate)}   "
                f"({t.first_pass_failed} KQL failed validation on first try)"
            ),
            # Reported as n/a, never as 100%, when nothing failed. catch_rate is
            # retry_fixed/first_pass_failed and returns 1.0 on a zero denominator;
            # printing that as a perfect score reads as "the validator did great
            # work" when it did none, which is the more dangerous misreading of
            # the two — a validator that is asleep looks identical to one that is
            # unnecessary, and only this line distinguishes them.
            (
                f"    validator catch-rate . {_pct(t.catch_rate)}   "
                "← of those, fixed on retry (want high)"
                if t.first_pass_failed else
                "    validator catch-rate .    n/a   ← nothing failed first pass, "
                "so nothing to catch"
            ),
            f"    operation warnings ... {t.op_warned}   ← model-asserted ops flagged as suspect",
            f"    drift (stability) .... {_pct(t.stability)}   ← identical set across runs = 100%",
            f"    core coverage ........ {_pct(t.core_coverage)}   ← share of union present in EVERY run",
            f"    refusals ............. {t.refusals}/{t.runs}",
            f"    cost ................. ${t.cost_usd:.2f}  (${t.cost_usd / t.runs:.2f}/run)",
        ]
    lines += ["", "-" * 72, f"TOTAL COST: ${result.total_cost:.2f}", "=" * 72, ""]
    return "\n".join(lines)

#!/usr/bin/env python
"""Eval harness — run targets N times against a real model and print the numbers
that tell you whether the wrapper is doing its job.

This is the "is it tight?" measurement: it exercises the FULL pipeline (grounding
→ threat analysis → detection + validation + self-correction) against a live
model, several times per target, and reports:

  • final invalid-rate ...  detections that failed validation and shipped anyway
  • validator catch-rate ..  first-pass failures the self-correction retry fixed
  • operation warnings ....  model-asserted operations flagged as structurally off
  • drift / core coverage .  how stable the detection set is run-to-run
  • cost .................   total + per run

Unlike the unit tests, this NEEDS a model — set the same env the CLI uses
(PYLON_PROVIDER, OPENAI_API_KEY / AZURE_OPENAI_*, OPENAI_CHAT_MODEL).
It costs real tokens; keep --runs small (3 is enough to see drift). Metric logic
lives in pylon.eval_metrics (unit-tested); this file is just the
live driver.

Examples:
    python scripts/eval.py                                  # default targets, 3 runs
    python scripts/eval.py --runs 5 --targets "resource:Key Vault"
    python scripts/eval.py --targets "arm:Storage Account" "entra:Entra" --json eval.json
    python scripts/eval.py --targets "dynamic:Microsoft.CognitiveServices/accounts"

The "dynamic:<resource type or name>" target is the go/no-go for the generic
AzureDiagnostics path: it resolves the resource through the logs-index exactly as
the CLI's --dynamic-routing does, so an uncurated resource routes to AzureDiagnostics
with its ResourceProvider + categories threaded into the prompt and validator.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Allow running from the repo root without an install.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pylon import config
from pylon.engine import (
    EngineRequest,
    ModelRefusalError,
    runnable,
)
from pylon.eval_metrics import (
    EvalResult,
    format_result,
    metrics_for_target,
)
from pylon.usage import reset_meter

# One target on both planes and one on the directory. Both are fully grounded --
# every operation behind them has a verdict -- so a leaked invalid detection is a
# genuine signal rather than a gap in the catalogue.
#
# The old defaults were "resource:Key Vault" and "resource:AKS". AKS resolves to
# Microsoft.ContainerService/managedClusters, which the CLI refuses: its
# vocabulary is eight bare Kubernetes verbs and no operation behind it has a
# verdict. The harness resolved it anyway, because it built its own request
# instead of asking the gate, so `scripts/eval.py` with no arguments spent money
# generating ungrounded Kubernetes detections that no `pylon` command can produce.
_DEFAULT_TARGETS = ["Microsoft.KeyVault/vaults", "entra"]


def _request_for(target: str, max_cost: float) -> tuple[str, EngineRequest]:
    """Turn a target into an EngineRequest the same way the command line does.

    Through `resolve_target`, deliberately. This used to parse its own
    "resource:NAME" and "platform:service" forms and assemble the request itself,
    which meant the harness could reach targets the CLI refuses -- and its own
    default did: AKS has no operation partition, so an unattended eval run
    generated detections nothing could check and reported metrics on them.

    A harness that can reach what the product cannot is measuring a different
    product.

    `dynamic:` is kept: it exercises the generic AzureDiagnostics route, which is
    a real code path with no target of its own.
    """
    kind, _, rest = target.partition(":")
    if kind.strip().lower() == "dynamic" and rest:
        # The generic AzureDiagnostics go/no-go: resolve through the logs-index
        # like the CLI's --dynamic-routing, threading provider + categories so the
        # prompt scopes the shared table and the validator enforces it.
        from pylon.catalog.resolver import resolve_dataplane_route

        decision = resolve_dataplane_route(rest.strip())
        if decision is None:
            raise SystemExit(
                f'Unknown dynamic target "{rest.strip()}" — not in the logs-index. '
                'Try a resource type like "Microsoft.CognitiveServices/accounts".'
            )
        request = EngineRequest(
            platform="dataplane", service=decision.table, max_cost=max_cost
        )
        if not decision.resource_specific:
            request.az_diag_provider = decision.provider
            request.az_diag_categories = tuple(decision.categories)
            request.az_diag_samples = decision.samples
        return f"dynamic:{rest.strip()} -> {decision.table}", request

    from pylon.services import ENTRA_KEY, resolve_target

    resolved = resolve_target(target)
    if resolved is None:
        from pylon.services import targets

        raise SystemExit(
            f'"{target}" is not a target this tool can ground. Supported: '
            + ", ".join(targets()) + "."
        )
    if resolved.key == ENTRA_KEY:
        return resolved.key, EngineRequest(
            platform="entra", service="AuditLogs", max_cost=max_cost
        )
    return resolved.key, EngineRequest(
        resource=resolved.resource_type, surfaces=resolved.surfaces, max_cost=max_cost
    )


async def _run_once(request: EngineRequest):
    """Run the workflow once (no checkpoint, no HITL). Returns the EngineReport,
    or None if the model refused or the run produced no output.

    The meter is process-global and the workflow does not reset it (a reset there
    re-zeroes a checkpoint resume — see engine.pylon). The CLI resets once because
    one invocation is one run; this harness runs `runs x targets` in ONE process,
    so without a reset here run 2's report carried run 1's tokens as well, and
    metrics_for_target summed the lot: a 3-run target reported ~6x one run's cost
    instead of 3x. `over_budget` reads the same meter, so the cap bound early too
    and later runs were skipped before they started.
    """
    reset_meter()
    try:
        stream = runnable().run(stream=True, message=request)
        async for _ in stream:
            pass
        result = await stream.get_final_response()
    except ModelRefusalError:
        return None
    outputs = result.get_outputs()
    return outputs[0] if outputs else None


async def _eval(
    resolved: list[tuple[str, EngineRequest]],
    runs: int,
    json_path: Path | None = None,
    result: EvalResult | None = None,
) -> EvalResult:
    """Run every target `runs` times, persisting after each target completes.

    A full release eval is a dozen live-model runs over tens of minutes. Holding
    every result in memory until the last one finishes means a crash — or a
    Ctrl-C, or a rate limit on the final target — throws away everything already
    paid for. So each target's metrics are written as soon as that target is
    done, and the file is valid JSON at every point in between.
    """
    # The caller may pass the accumulator in so it still holds the completed
    # targets if this coroutine is interrupted partway through.
    result = result if result is not None else EvalResult()
    for label, request in resolved:
        reports = []
        for i in range(runs):
            print(f"  {label}: run {i + 1}/{runs} ...", flush=True)
            reports.append(await _run_once(request))
        result.per_target.append(metrics_for_target(label, reports))
        if json_path:
            _write_json(json_path, result, complete=False)
    return result


def _write_json(path: Path, result: EvalResult, *, complete: bool) -> None:
    """Write the metrics file. `complete` records whether every target ran, so a
    partial file is never mistaken for a finished eval when it is read back."""
    payload = _to_json(result)
    payload["complete"] = complete
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _to_json(result: EvalResult) -> dict:
    return {
        "targets": [
            {
                "target": t.target,
                "runs": t.runs,
                "detections": t.detections,
                "valid": t.valid,
                "invalid": t.invalid,
                "skipped": t.skipped,
                "invalid_rate": round(t.invalid_rate, 4),
                "first_pass_fail_rate": round(t.first_pass_fail_rate, 4),
                "catch_rate": round(t.catch_rate, 4),
                "operation_warnings": t.op_warned,
                "stability": None if t.stability is None else round(t.stability, 4),
                "core_coverage": None if t.core_coverage is None else round(t.core_coverage, 4),
                "refusals": t.refusals,
                "cost_usd": round(t.cost_usd, 4),
                # Per RUN, not merged. Comparing two prompt variants needs to
                # tell a vector found every time from one found once, and a
                # union cannot: on this target ~58% of the union is
                # run-dependent, so a key present in one variant's union and
                # absent from the other's is indistinguishable from drift.
                "key_sets": t.key_sets,
            }
            for t in result.per_target
        ],
        "total_cost_usd": round(result.total_cost, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="eval",
        description="Run targets N times against a real model and report gate/drift metrics.",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        default=_DEFAULT_TARGETS,
        help='Targets as "resource:NAME" or "platform:service" '
        '(default: %(default)s).',
    )
    parser.add_argument(
        "--runs", type=int, default=3, help="Runs per target (default: 3)."
    )
    parser.add_argument(
        "--max-cost",
        type=float,
        default=0.0,
        help="Per-run USD cap passed to the engine (0 = no cap).",
    )
    parser.add_argument(
        "--json", type=Path, default=None, help="Also write metrics as JSON here."
    )
    args = parser.parse_args()

    if args.runs < 1:
        raise SystemExit("--runs must be >= 1.")

    # Before anything resolves a target or builds a model client. Without it this
    # harness ignores ~/.config/pylon/config.env entirely and only runs when the
    # variables happen to be exported — and the failure it produces points at the
    # model client ("Exactly one of 'base_url', 'endpoint' must be provided"),
    # saying nothing about the config file that exists and was not read.
    config.apply()

    # Resolve targets to requests BEFORE entering the event loop. A "dynamic:"
    # target runs the logs-index resolver, which calls asyncio.run() internally;
    # doing that from inside _eval (already in a running loop) raises
    # "asyncio.run() cannot be called from a running event loop".
    resolved = [_request_for(t, args.max_cost) for t in args.targets]

    print(f"Evaluating {len(resolved)} target(s), {args.runs} run(s) each — live model.")
    if args.json:
        print(f"  (partial metrics written to {args.json} after each target)")

    # Interrupting is a legitimate way to stop a long eval, and what already ran
    # is still worth reading. Report on the targets that finished rather than
    # dumping a traceback over the numbers they paid for.
    result = EvalResult()
    try:
        asyncio.run(_eval(resolved, args.runs, args.json, result))
        complete = True
    except KeyboardInterrupt:
        print("\nInterrupted — reporting the targets that completed.", flush=True)
        complete = False

    print(format_result(result))
    if not complete:
        done = len(result.per_target)
        print(f"\nPARTIAL: {done} of {len(resolved)} targets ran. Not a go/no-go result.")

    if args.json:
        _write_json(args.json, result, complete=complete)
        print(f"Wrote {args.json}")


if __name__ == "__main__":
    main()

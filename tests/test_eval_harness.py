"""Eval harness (scripts/eval.py) — target resolution, offline.

Guards the "dynamic:" go/no-go target: it must resolve through the logs-index
resolver in a SYNC context (before the event loop), because that resolver calls
asyncio.run() internally — resolving inside _eval's running loop raises
"asyncio.run() cannot be called from a running event loop".
"""

import asyncio
import importlib.util
from pathlib import Path

_EVAL_PATH = Path(__file__).resolve().parent.parent / "scripts" / "eval.py"

_FIXTURE_AZ_DIAG = """|Category|Costs to export|Log table|[b](/x)|[t](/y)|Example queries|
|---|---|---|---|---|---|
|Audit Events|No|[AzureDiagnostics](/azure/azure-monitor/reference/tables/azurediagnostics)<p>Logs.|No|No|[Q](/q)|
"""


def _load_eval():
    spec = importlib.util.spec_from_file_location("eval_harness_under_test", _EVAL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _patch_fetch(monkeypatch):
    from pylon.catalog import resolver

    async def _fetch(url):
        return _FIXTURE_AZ_DIAG

    monkeypatch.setattr(resolver, "_fetch_cached", _fetch)


def test_dynamic_target_resolves_to_azure_diagnostics(monkeypatch):
    _patch_fetch(monkeypatch)
    ev = _load_eval()
    label, request = ev._request_for("dynamic:Microsoft.CognitiveServices/accounts", 0.0)
    assert request.platform == "dataplane"
    assert request.service == "AzureDiagnostics"
    assert request.az_diag_provider == "Microsoft.CognitiveServices"
    assert request.az_diag_categories != ()
    assert "AzureDiagnostics" in label


def test_eval_composes_without_nesting_event_loops(monkeypatch):
    # Resolution happens before the loop (as main() does); _eval only consumes
    # pre-resolved requests, so the resolver's inner asyncio.run() never fires
    # inside the running loop.
    _patch_fetch(monkeypatch)
    ev = _load_eval()

    async def _no_model(request):
        return None

    monkeypatch.setattr(ev, "_run_once", _no_model)
    resolved = [ev._request_for("dynamic:Microsoft.CognitiveServices/accounts", 0.0)]
    result = asyncio.run(ev._eval(resolved, 1))
    assert len(result.per_target) == 1


def test_unknown_dynamic_target_errors(monkeypatch):
    _patch_fetch(monkeypatch)
    ev = _load_eval()
    import pytest

    with pytest.raises(SystemExit):
        ev._request_for("dynamic:banana vault", 0.0)


def test_each_run_starts_from_a_zero_meter(monkeypatch):
    """`runs x targets` workflows share one process, so a run must not inherit the
    previous run's tokens.

    It did. The meter is process-global; the workflow deliberately does not reset
    it (a reset there re-zeroes a checkpoint resume), and the CLI resets once
    because one invocation is one run. This harness is the only caller that runs
    the workflow more than once, so run 2's EngineReport carried run 1's tokens
    too and `metrics_for_target` summed them: a 3-run target reported ~6x one
    run's cost instead of 3x. `over_budget` reads the same meter, so the cap bound
    early and later runs were skipped before they started.
    """
    from pylon import usage

    mod = _load_eval()
    seen_at_entry = []

    class _Stream:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

        async def get_final_response(self):
            return self

        def get_outputs(self):
            return [object()]

    def _fake_run(*, stream, message):
        # What the meter holds when the workflow starts. Must be a fresh run.
        seen_at_entry.append(usage.current_meter().input_tokens)
        # Spend, as a real run would, so the next run inherits it if unreset.
        usage.record({"input_token_count": 1000, "output_token_count": 100})
        return _Stream()

    monkeypatch.setattr(mod, "pylon", type("W", (), {"run": staticmethod(_fake_run)}))

    async def _three():
        for _ in range(3):
            await mod._run_once(object())

    asyncio.run(_three())
    assert seen_at_entry == [0, 0, 0], (
        f"each run must start from a zero meter, saw {seen_at_entry}"
    )

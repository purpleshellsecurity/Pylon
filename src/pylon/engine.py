"""The detection engine as an Agent Framework functional workflow.

Pipeline (the original app's three phases, restructured around typed data):

  grounding fetch                      @step, cached
      |
  Phase 1 — threat analysis agent      @step, structured output (ThreatAnalysis)
      |       [service-gate middleware; MITRE ID verification]
      v
  Phase 2 — one detection agent call   asyncio.gather fan-out, per-vector
      |       PER attack vector        validate_kql + one self-correction retry
      v
  HITL — human picks playbook target   ctx.request_info (suspends the run)
      |
  Phase 3 — IR playbook agent          @step
      v
  markdown report + MITRE coverage score

The functional API's resume model matches the original's phase-dependency
contract: on HITL resume or checkpoint restore, completed @step results come
from cache — Phases 1-2 never re-run or re-bill.

Agent instructions come verbatim from the ported prompt chains
(prompts/assets/**), assembled by build_system_prompt — the same
role/platform_rules/schema_reference/task structure the original app sent.
"""

import asyncio
import dataclasses
import functools
import hashlib
import os
import re
import sys
import time
from dataclasses import dataclass

from agent_framework import Agent, RunContext, step, workflow

from . import column_values, contracts, mitre, operation_grounding, pivot, progress
from . import knowledge as contracts_knowledge
from . import verification
from .attack_paths import normalize_tags, tag_seed_context
from . import deployed
from .catalog import log_surfaces
from .clients import cacheable, make_chat_client
from .grounding import (MitreBundleUnavailable, documented_columns,
                        mitre_technique_names, table_schema_context)
from . import watchdog
from .logs import get_logger, in_phase
from .middleware import make_service_gate
from .provenance import stamp
from .kusto_offline import schema_for_table, verify_query_offline
from .models import (
    Detection,
    EngineReport,
    OfflineCheck,
    OperationCheck,
    Playbook,
    ThreatAnalysis,
    ValidatedDetection,
)
from .prompts import (
    build_resource_prompt,
    build_system_prompt,
)
from .prompts.constants import table_for_target
from .provider_operations import PROVIDER_ABSENT
from .prompts import UNMAPPED
from .scoring import normalize_technique_id, score_program
from .usage import current_meter, estimate_cost, over_budget, record
from .validation import (
    ValidationResult,
    check_playbook,
    fence_bare_kql,
    operation_status,
    sanitize_service,
    validate_kql,
)
from .validation.live_schema import (
    fetch_table_schema,
    merge_results,
    validate_against_schema,
)


@dataclass
class EngineRequest:
    """Typed input for one pylon run — target, budget caps, and mode flags."""

    platform: str = "arm"       # "arm" | "dataplane" | "entra" (ignored if resource set)
    service: str = ""           # table name / resource type / "Entra"
    resource: str = ""          # canonical resource type -> resource-centric mode
    max_cost: float = 0.0       # hard USD cap for the run (0 = unlimited)
    max_tokens: int = 0         # hard token cap for the run (0 = unlimited)
    seed_context: str = ""      # saved-list anchor injected into Phase 1
    # IR playbooks (Phase 3), opt-in: "" = none (just threat analysis + detections);
    # PLAYBOOK_PROMPT = interactive menu (HITL); "1,3" / "all" = non-interactive picks.
    playbook_selection: str = ""
    dynamic_schema: bool = False  # also validate KQL against the LIVE fetched schema
    # The third gate: grade each detection against real events while generating
    # it. Explicit here rather than read straight from the environment, so a
    # caller can pass one and a test can leave it empty; the env var remains the
    # fallback because a sweep sets it once for every target it drives.
    verify_workspace: str = ""
    verify_window: str = ""
    # Dynamic-routing generic path (service == "AzureDiagnostics"): the resolver's
    # ResourceProvider + log categories, so the prompt can scope the shared table
    # and the validator can enforce that scoping. Empty for every curated path.
    az_diag_provider: str = ""
    az_diag_categories: tuple[str, ...] = ()
    az_diag_samples: tuple[str, ...] = ()  # provider-scoped AzureDiagnostics KQL grounding
    # One AuditLogs Category, when the target is a slice of the directory rather
    # than all of it. Empty means the whole thing.
    entra_category: str = ""
    # A plan from a previous `design plan` run, so `design detections --from` does
    # not pay for Phase 1 twice. None -> enumerate it.
    analysis: object | None = None
    # Which of the plan's vectors to build. "" means all (the default, and what
    # every run did before the plan existed); "none" stops after Phase 1.
    vector_selection: str = ""
    # Resource-mode surfaces resolved once (logs-index data-plane + control plane),
    # optionally narrowed by --tables. Empty -> engine falls back to the curated
    # overlay (e.g. the eval harness, which does not pre-resolve).
    surfaces: tuple = ()
    # What the USER asked for, as `design list` spells it. `service` is what the
    # run resolved that to -- a table, for Entra -- and the two are not the same
    # fact. A saved plan needs the first so `--from` can resolve it again; the
    # playbook phase needs the second. One field served both and the Entra plan
    # recorded "AuditLogs", which `design detections --from` then refused,
    # because AuditLogs is not a target anyone can ask for.
    target_key: str = ""
    # Tables the scanned workspace HOLDS DATA IN, from `deployed.from_analysis()`,
    # which reads `Analysis.tables`. The field name is historical and misleading:
    # it is NOT `Analysis.provisioned_tables`, and must not be rewired to it.
    # `deployed.py`'s module docstring has the measurement -- 844 tables existed
    # in the first real tenant and 34 held data, so provisioning proves only that
    # a Content Hub solution was installed. Feeding this the provisioned list
    # would report "confirmed" for nearly every table it was asked about.
    # None means nobody looked -- distinct from an empty set, which would mean a
    # workspace with no tables at all. Used to prefer a table this tenant has
    # over one the catalogue merely offers, and to label the difference.
    provisioned_tables: frozenset[str] | None = None


# Sentinel value for playbook_selection: suspend and ask the human to pick.
PLAYBOOK_PROMPT = "__prompt__"


# Checkpoint state is guarded by a restricted unpickler (a trust boundary):
# only built-ins, agent_framework types, and explicitly allowlisted types can
# be restored. These are the custom types that cross checkpoint boundaries.
CHECKPOINT_ALLOWED_TYPES = [
    "pylon.engine:EngineRequest",
    "pylon.catalog.overlay:LogSurface",
    "pylon.models:ThreatAnalysis",
    "pylon.models:AttackVector",
    "pylon.models:Detection",
    "pylon.models:ValidatedDetection",
    # Every model nested inside a checkpointed one belongs here. The list gates
    # DESERIALIZATION: an unregistered type makes the checkpoint unreadable, and
    # the run then silently re-executes the phase it should have replayed —
    # paying again for exactly the calls --resume exists to skip. It warns on
    # stderr and stops nothing, which is the shape of every scar in CLAUDE.md:
    # a failure that reports something other than what it is.
    #
    # Three hang off ValidatedDetection and are PAID features — --verify-live,
    # --verify-offline, --tune — so a resume after any of them was
    # re-billing the detection phase.
    "pylon.models:LiveCheck",
    "pylon.models:OfflineCheck",
    "pylon.models:TuneResult",
    # These two were in nobody's count — a derived guard in the tests found
    # them, which is the argument for deriving it: a hand-written list of nested
    # models is exactly as complete as the last person to remember to update it.
    "pylon.models:ProveResult",
    "pylon.models:RetrohuntResult",
    # And the seventh, from the three-state operation check.
    "pylon.models:OperationCheck",
    "pylon.models:Playbook",
    # `design verify` records what it measured on the report, so a checkpoint
    # carrying a report carries these too. Found by the derived guard again.
    "pylon.models:DetectionVerification",
    # Nested inside it: the rows-surviving-each-filter table a verdict carries
    # when the detection matched nothing. Found by the derived guard a third
    # time, which is the point of that guard.
    "pylon.models:NarrowingStep",
    # Stamped onto the plan, the report and every verdict, so a checkpoint
    # carrying any of those carries this.
    "pylon.provenance:Provenance",
    "pylon.models:EngineReport",
]


def _force_utf8_checkpoints() -> bool:
    """Make agent_framework's checkpoint file I/O UTF-8. True when patched.

    UPSTREAM BUG, AND IT BREAKS WINDOWS OUTRIGHT. agent_framework's own
    `_checkpoint.py` -- a third-party file, not one of ours -- opens its
    files four times with no encoding and then writes
    `json.dump(..., ensure_ascii=False)`, so the non-ASCII in a checkpoint --
    the box drawing from the attack diagram, the status emoji -- goes through
    the locale codec. On Linux and macOS that is UTF-8 and nothing is noticed.
    On Windows it is cp1252:

        UnicodeEncodeError: 'charmap' codec can't encode character '\u2502'

    Saving raises and resuming would mis-decode, so `--resume` is unusable there.

    `open` is shadowed in that module's namespace rather than the four methods
    being reimplemented here: their bodies are upstream's to change, and a copy
    would drift silently. Shadowing a module global affects only that module --
    builtins are untouched everywhere else.

    A no-op once upstream names its encoding, and reports that rather than
    asserting, so the day it is fixed is visible instead of silent.
    """
    import builtins
    import importlib

    mod = importlib.import_module("agent_framework._workflows._checkpoint")
    if getattr(mod, "_pylon_utf8", False):
        return True

    def _utf8_open(file, mode="r", *args, **kwargs):
        if "b" not in mode:
            kwargs.setdefault("encoding", "utf-8")
        return builtins.open(file, mode, *args, **kwargs)

    mod.open = _utf8_open
    mod._pylon_utf8 = True
    return True


def make_checkpoint_storage(path):
    """FileCheckpointStorage with our types allowlisted for restore."""
    from agent_framework import FileCheckpointStorage

    _force_utf8_checkpoints()
    return FileCheckpointStorage(str(path), allowed_checkpoint_types=CHECKPOINT_ALLOWED_TYPES)


def operation_vocabulary_for(request: "EngineRequest", table: str) -> tuple[str, ...]:
    """Every operation this table records for the target, or () when unknown.

    Empty is not "none exist" -- it is "nobody has catalogued this surface" --
    and `plan_problems` treats it that way, checking nothing rather than
    rejecting everything.
    """
    from .services import operation_vocabulary

    resource = request.resource if _is_resource_mode(request) else ""
    if not resource:
        return ()
    try:
        return tuple(operation_vocabulary(resource, table))
    except Exception:          # an uncatalogued surface is not a run failure
        return ()


def _is_resource_mode(request: "EngineRequest") -> bool:
    """True when the request targets a canonical resource type (resource-centric mode)."""
    return bool(request.resource)


def _clamp_choice(choice: str, n: int) -> int:
    """Parse a menu selection into a valid index. Backstop for a bad/empty
    HITL response so a stray keystroke can't crash a completed run (the CLI
    re-prompts before it reaches here; this guards other resume paths)."""
    try:
        idx = int(str(choice).strip())
    except (ValueError, TypeError):
        return 0
    return min(max(idx, 0), n - 1)


def _parse_choices(choice: str, n: int) -> list[int]:
    """Parse a menu selection into an ordered, de-duplicated list of valid
    indices. Accepts 'all', a single number, or comma-separated numbers
    ('1,3,5'). Falls back to [0] for empty/garbage so a completed run always
    yields at least one playbook (mirrors _clamp_choice's backstop)."""
    raw = str(choice).strip().lower()
    if raw == "all":
        return list(range(n))
    picks: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        try:
            idx = int(part)
        except (ValueError, TypeError):
            continue
        if 0 <= idx < n and idx not in picks:
            picks.append(idx)
    return picks or [0]


# The engine used to answer this itself, with the half of the rule it needed:
# arm means AzureActivity, and everything else is already a table. That last
# assumption is the one that broke -- a display label reaching here is "already
# a table" by that rule, and stays a label.
#
# `table_for_target` is now the only place this is worked out. Six call sites answered
# it before; this was one of them.


def _resource_surfaces(request: "EngineRequest") -> list:
    """Resource-mode log surfaces for this run: the ones resolved up front (the
    logs-index data-plane tables + control plane, optionally --tables-narrowed),
    else the curated overlay as a fallback for callers that don't pre-resolve
    (e.g. the eval harness)."""
    return list(request.surfaces) if request.surfaces else log_surfaces(request.resource)


def _expected_for_vector(request: "EngineRequest", vector) -> str:
    """The table a detection must query and validate against. In resource mode
    and combined Graph mode this is per-vector (the model's Phase 1 routing
    choice, clamped to a real table for the resource); otherwise it's the
    single pinned table."""
    if _is_resource_mode(request):
        tables = [s.table for s in _resource_surfaces(request)]
        chosen = vector.log_table if vector.log_table in tables else tables[0]
        # If the routing pick is not a table this workspace has but a sibling
        # surface is, take the sibling. A detection naming a table the tenant
        # does not have cannot fire, and the catalogue cannot know which of the
        # legacy/resource-specific pair was configured here.
        return deployed.prefer(chosen, tables, request.provisioned_tables)
    return table_for_target(request.platform, request.service)


def _prerequisite_for(request: "EngineRequest", table: str) -> str:
    """The diagnostic-setting prerequisite for `table` in resource mode, or '' when
    not in resource mode or no resolved surface matches the table."""
    if not _is_resource_mode(request):
        return ""
    for s in _resource_surfaces(request):
        if s.table == table:
            return s.prerequisite()
    return ""


def _build_prompt(request: "EngineRequest", phase_id: str, playbook_target: str | None = None) -> str:
    """Assemble the agent instructions for one phase — the resource-mode prompt in
    resource mode, else the platform/service system prompt (with any AzureDiagnostics
    provider/category routing context)."""
    if _is_resource_mode(request):
        return build_resource_prompt(
            request.resource, phase_id, _resource_surfaces(request), playbook_target
        )
    return build_system_prompt(
        request.platform,
        request.service,
        phase_id,
        playbook_target,
        entra_category=request.entra_category,
        az_provider=request.az_diag_provider,
        az_categories=request.az_diag_categories,
        az_samples=request.az_diag_samples,
    )


# ── Rate-limit hygiene ────────────────────────────────────────────────────────
# Azure OpenAI deployments carry per-minute token/request quotas; an unbounded
# fan-out over 10+ attack vectors can exhaust a small deployment's quota in one
# burst. Cap concurrency and retry 429s with exponential backoff. Tune both to
# your deployment's TPM via env.

log = get_logger(__name__)

class EngineGone(RuntimeError):
    """The offline KQL engine was configured and stopped answering mid-run.

    Raised rather than folded into the detection's result, because it is not a
    fact about the detection. See the gate in `_checked`.
    """


MAX_CONCURRENCY = int(os.environ.get("PYLON_MAX_CONCURRENCY", "2"))
MAX_RETRIES = int(os.environ.get("PYLON_MAX_RETRIES", "5"))
# A model call that never returns blocked an entire run for 103 minutes with no
# error, no retry and nothing to notice — the retry path only fires on
# EXCEPTIONS, so a hang was invisible to it. Measured on this deployment: normal
# calls finish in 38-145s, the slowest that ever COMPLETED took 680s. The ceiling
# is set well above that, because killing a call that would have succeeded pays
# for the same work twice; it exists to break a hang, not to trim a slow call.
MODEL_CALL_TIMEOUT = float(os.environ.get("PYLON_CALL_TIMEOUT", "900"))
# The backstop for when MODEL_CALL_TIMEOUT cannot fire at all. `asyncio.wait_for`
# schedules its cancellation on the event loop, so a synchronous call inside the
# client -- or a coroutine that swallows CancelledError -- leaves it unable to
# act, both measured. A run sat eighteen hours on a call with a fifteen-minute
# limit and logged nothing after "model call started".
#
# Deliberately well clear of the soft limit: this is not a second retry trigger,
# it is the line past which the process has provably stopped making progress.
MODEL_CALL_DEADLINE = float(
    os.environ.get("PYLON_CALL_DEADLINE", str(MODEL_CALL_TIMEOUT * 2)))


class ModelRefusalError(RuntimeError):
    """The model returned a refusal/prose instead of the required structured
    output, and kept doing so across retries. Raised with a human-readable
    message so the CLI can present it cleanly instead of a parse traceback."""


class RateLimitExhausted(RuntimeError):
    """The deployment throttled us and kept throttling across every retry.

    Raised so the CLI can say what was hit and how to fix it. The default reached
    the operator as 7,500 bytes of stack trace ending in `rate_limit_exceeded` —
    which does not tell someone that the cause is a capacity number on their own
    Azure deployment, usually set far below what their subscription already
    allows. This repo already names the exact RBAC permission when a table read
    fails; a throttle deserves the same treatment."""


class ServiceGateError(RuntimeError):
    """The service gate blocked the run because the requested service did not
    look valid for the platform. Raised with the gate's message so the CLI can
    present a clean refusal instead of an AttributeError traceback."""


def _unwrap_threat_response(response) -> "ThreatAnalysis":
    """Return the structured ThreatAnalysis from an agent response.

    The service gate short-circuits by setting a plain-string result, so the
    response may be a bare ``str`` (or an object whose structured ``.value`` is
    None). Surface that as a clean ServiceGateError instead of letting
    ``response.value`` raise ``AttributeError`` on a str.
    """
    value = getattr(response, "value", None)
    if value is None:
        message = response if isinstance(response, str) else getattr(response, "text", None)
        raise ServiceGateError(str(message) if message else "The service could not be validated.")
    return value


def _unwrap_fill(response):
    """The structured PlaybookFill from an agent response.

    Separate from `_unwrap_threat_response` because the failure means something
    different: there is no service gate here, so a missing `.value` is the model
    answering with prose where the four fields were asked for. Said plainly rather
    than raising AttributeError on a str.
    """
    from .playbook import PlaybookFill

    value = getattr(response, "value", None)
    if isinstance(value, PlaybookFill):
        return value
    if isinstance(value, dict):
        return PlaybookFill.model_validate(value)
    text = response if isinstance(response, str) else getattr(response, "text", "")
    raise ValueError(
        "the playbook phase asked for four fields and got free text instead: "
        + (str(text)[:200] or "an empty response")
    )


def _is_rate_limit(ex: Exception) -> bool:
    """True if the exception (or its cause) looks like a 429 / rate-limit error."""
    # BOTH, because they are not the same class before 3.11. asyncio.TimeoutError
    # only became an alias of the builtin in Python 3.11, and this package supports
    # >=3.10 — so on 3.10 `isinstance(ex, TimeoutError)` is False for the very
    # exception asyncio.wait_for raises, and a hung call would escape the retry
    # path and kill the run. Caught by the CI matrix; a 3.13-only local suite
    # cannot see it.
    if isinstance(ex, (asyncio.TimeoutError, TimeoutError)):
        # A hung call and a throttled one want the same treatment — back off and
        # try again — even though they are different faults. Matched by TYPE, not
        # by message text, so the classification cannot drift with the wording.
        return True
    text = f"{ex} {ex.__cause__ or ''}".lower()
    return "429" in text or "rate limit" in text or "rate_limit" in text


# A refusal reads as a leading assistant-decline construction. Anchored to a
# decline VERB (assist/help/comply/continue/fulfill) so a legitimate error that
# merely contains the word "sorry" somewhere doesn't get misread as a refusal and
# burn the retry budget.
_REFUSAL_PHRASE = re.compile(
    r"\b(?:i'?m sorry|i am sorry|i cannot|i can'?t|i won'?t|unable to)\b[^.]{0,40}"
    r"\b(?:assist|help|comply|continue|fulfil|fulfill|provide|create|generate)\b"
)


def _is_refusal(ex: Exception) -> bool:
    """A structured-output call whose JSON parse failed because the model
    answered with prose — almost always a (often spurious) safety refusal from
    a reasoning model. Reasoning outputs are stochastic, so a retry usually
    gets a compliant response. Detected by the JSON-parse-failure signal, or a
    genuine leading refusal construction (not a bare 'sorry' substring)."""
    text = f"{ex} {ex.__cause__ or ''}".lower()
    if "json_invalid" in text or "invalid json" in text or "json_decode" in text:
        return True
    return bool(_REFUSAL_PHRASE.search(text))


async def _arun(agent: Agent, prompt: str, *, options: dict | None = None):
    """Run an agent, time it, and record its token usage for the cost meter.

    The timing is the point. A model call is the only thing in this program that
    takes minutes, and until now it produced no trace at all — so a run sitting
    silent for fifteen minutes was indistinguishable from a run doing nothing.
    """
    started = time.monotonic()
    log.debug("model call started", extra={"event": "model_call_started"})
    try:
        # Two guards, on purpose. `wait_for` handles the ordinary hang: it
        # unwinds cleanly and the failure takes the normal retry path. The
        # deadline handles the hang `wait_for` cannot see, and only ends the
        # run -- by then the process has provably stopped making progress.
        with watchdog.deadline(MODEL_CALL_DEADLINE, "model call"):
            response = await asyncio.wait_for(
                agent.run(prompt, options=options) if options else agent.run(prompt),
                timeout=MODEL_CALL_TIMEOUT,
            )
    except (asyncio.TimeoutError, TimeoutError) as exc:
        # Raised as a rate-limit-shaped failure so it takes the SAME backoff and
        # retry path: a hung endpoint and a throttled one both want another go.
        log.warning(
            "model call TIMED OUT after %.0fs (limit %.0fs) — abandoning and retrying",
            time.monotonic() - started, MODEL_CALL_TIMEOUT,
            extra={"event": "model_call_timeout",
                   "elapsed_s": round(time.monotonic() - started, 1),
                   "limit_s": MODEL_CALL_TIMEOUT},
        )
        # Deliberately does NOT say "rate limit": a hang is not a throttle, and a
        # message that happens to contain the phrase would be classified by TEXT,
        # leaving the isinstance check below as dead code that no test can pin.
        raise TimeoutError(
            f"model call exceeded {MODEL_CALL_TIMEOUT:.0f}s with no response"
        ) from exc
    except Exception as exc:
        log.warning(
            "model call FAILED after %.1fs: %s: %s",
            time.monotonic() - started, type(exc).__name__, str(exc)[:200],
            extra={"event": "model_call_failed", "elapsed_s": round(time.monotonic() - started, 1),
                   "error_type": type(exc).__name__},
        )
        raise
    usage = getattr(response, "usage_details", None)
    record(usage)
    elapsed = time.monotonic() - started
    tokens = 0
    if isinstance(usage, dict):
        tokens = int(usage.get("input_token_count", 0) or 0) + int(
            usage.get("output_token_count", 0) or 0
        )
    log.debug(
        "model call ok in %.1fs (%s tokens)", elapsed, f"{tokens:,}" if tokens else "unreported",
        extra={"event": "model_call", "elapsed_s": round(elapsed, 1), "tokens": tokens},
    )
    return response


async def _saying_it_is_alive(awaitable, what: str, every: float = 30.0):
    """Await `awaitable`, reporting elapsed time while it is still in flight.

    Phases 1 and 3 are each ONE model call with nothing to count inside them, so
    the run printed a line and then nothing at all for the length of a paid
    request. A stalled run and a working one looked identical from outside, and
    the honest reading of a blank screen is that the tool has hung.

    Deliberately a log line and not a terminal spinner. The live meter this
    replaces was gated on `isatty()`, so a redirected or CI run emitted nothing
    -- and a run that stalls at 03:00 in CI is the one with no terminal to
    scroll back through. tests/test_logs.py pins that property; this keeps it.
    """
    task = asyncio.ensure_future(awaitable)
    started = time.monotonic()
    while True:
        done, _ = await asyncio.wait({task}, timeout=every)
        if done:
            return task.result()
        waited = time.monotonic() - started
        log.info(
            "still %s after %.0fs", what, waited,
            extra={"event": "heartbeat", "doing": what, "elapsed_s": round(waited, 1)},
        )


async def _run_with_retry(agent: Agent, prompt: str, *, options: dict):
    """Retry a call on transient rate limits (backoff) and on stochastic model
    refusals of a structured-output request (quick retry). Persistent refusal
    surfaces as ModelRefusalError; other errors propagate immediately."""
    delay = 5.0
    last: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            return await _arun(agent, prompt, options=options)
        except Exception as ex:
            last = ex
            if attempt == MAX_RETRIES - 1:
                if _is_refusal(ex):
                    raise ModelRefusalError(str(ex)) from ex
                if _is_rate_limit(ex):
                    # Every retry was throttled. A traceback here tells the
                    # operator nothing they can act on.
                    raise RateLimitExhausted(str(ex)) from ex
                raise
            if _is_rate_limit(ex):
                # Silent backoff is what made a throttled run and a working run
                # look identical from outside. Say which, and for how long.
                log.warning(
                    "rate limited — retry %d/%d, backing off %.0fs",
                    attempt + 1, MAX_RETRIES, delay,
                    extra={"event": "retry", "reason": "rate_limit",
                           "attempt": attempt + 1, "max": MAX_RETRIES, "backoff_s": delay},
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)
            elif _is_refusal(ex):
                log.warning(
                    "model refused — retry %d/%d, retrying promptly",
                    attempt + 1, MAX_RETRIES,
                    extra={"event": "retry", "reason": "refusal",
                           "attempt": attempt + 1, "max": MAX_RETRIES, "backoff_s": 1.0},
                )
                await asyncio.sleep(1.0)  # stochastic — retry promptly
            else:
                raise
    raise ModelRefusalError(str(last)) if last and _is_refusal(last) else RuntimeError("unreachable")


# ── Steps ─────────────────────────────────────────────────────────────────────
def _guidance_result(detection, table: str = "") -> "ValidationResult":
    """What is wrong with a detection's TUNING NOTES, as a ValidationResult.

    `tuning_guidance` is free text the model writes, and until now nothing
    checked it -- so the advice a SOC acts on was the least verified thing in
    the output. Measured: a detection for a permanent Global Administrator
    grant outside PIM (T1098.003) advised "Allowlist ActorUPN for break-glass
    or approved automation accounts". Break-glass accounts are the highest-value
    identities in a tenant; an attacker who reaches one becomes invisible to
    that rule, and nothing decided that advice or checked it.

    Folded into the same ValidationResult the retry loop already reads, so a bad
    note drives the same one-shot correction a fabricated column does.
    """
    from .validation.kql_rules import guidance_problems, technique_problems
    from .validation.validate_kql import ValidationResult

    notes = getattr(detection, "tuning_guidance", "") or ""
    technique = getattr(detection, "mitre_technique", "") or ""
    problems = guidance_problems(notes, technique)
    # The technique itself, as a WARNING. A host-platform technique on a cloud
    # operation is usually wrong and occasionally right, and the catalogue says
    # which by carrying a `platform_exception`. A warning rather than an error
    # because blocking it would force the wrong mapping: T1648 Serverless
    # Execution is the cloud-tagged alternative to T1505.003 Web Shell and its
    # tactic is EXECUTION where a planted backdoor is PERSISTENCE, so a gate
    # insisting on the platform tag would make the alert say the wrong thing
    # about what is happening.
    warnings = technique_problems(technique, table)
    return ValidationResult(valid=not problems, errors=list(problems),
                            warnings=list(warnings))


def _shared_section(request: "EngineRequest", target) -> str:
    """"PROVIDER/Category" for a detection on the shared table, else "".

    AzureDiagnostics is every service's table and each service answers "which
    column holds the caller" differently, so a playbook on it needs to know
    WHICH service before it can say anything true. The provider is on the
    request in generic mode and on the resource type in resource mode; the
    category comes from the operation, because one AzureDiagnostics surface
    spans every category a provider writes.
    """
    if target.log_table != "AzureDiagnostics":
        return ""
    provider = request.az_diag_provider or (request.resource or "").split("/")[0]
    if not provider:
        return ""
    from . import contracts as _c
    return _c.section_for("AzureDiagnostics", provider, target.operation or "")


# @step = cached across HITL resumes / checkpoint restores, emits
# executor lifecycle events, and checkpoints after completion.


@step
async def fetch_grounding(log_table: str) -> str:
    """Live doc excerpts appended to the schema_reference (grounding.ts port)."""
    context = await table_schema_context(log_table)
    return f"\n\n<live_documentation>\n{context}\n</live_documentation>" if context else ""


def _surface_size(request: "EngineRequest") -> str:
    """The operations this target actually records, named for Phase 1.

    The prompt tells Phase 1 to cover the surface and not sample it, which is
    right for a vault with 78 operations and is an instruction to invent on a
    surface with two. It was never shown which it was dealing with: the
    vocabulary is consulted in Phase 2, per vector, long after the count is
    decided. A run against Microsoft.Insights/diagnosticSettings enumerated five
    vectors for Write and Delete.

    So the list goes in, and "cover the surface" becomes bounded by a list
    rather than by how thorough the model feels.
    """
    tables = tuple(request.surfaces or ()) or ((request.service,) if request.service else ())
    lines: list[str] = []
    for table in tables:
        vocabulary = operation_vocabulary_for(request, table)
        if not vocabulary:
            continue
        lines.append(f"{table} records exactly these {len(vocabulary)} operations "
                     f"for this target:")
        lines += [f"  {op}" for op in sorted(vocabulary)]
    if not lines:
        return ""
    return ("\n".join(lines) + "\n\nThat list is the whole surface. Do not "
            "enumerate a vector for anything absent from it, and do not split one "
            "operation into several vectors unless you can name the request-body "
            "fields that tell them apart -- put those in distinguishing_fields.\n\n")


@step
@in_phase("run_threat_phase")
async def run_threat_phase(request: EngineRequest, grounding: str) -> ThreatAnalysis:
    """Phase 1 — run the threat-analysis agent and return structured ThreatAnalysis.

    Builds the threat-phase agent (guarded by the service-gate middleware outside
    resource mode), runs it with retry, and unwraps the structured result — raising
    ServiceGateError when the gate short-circuited the run.
    """
    _t0 = time.monotonic()
    log.info("reading the attack surface and enumerating attack vectors",
             extra={"event": "phase_start", "phase": "run_threat_phase"})
    client = make_chat_client()
    middleware = []
    subject = request.resource or request.service
    if not _is_resource_mode(request):
        verifier = client.as_agent(instructions="Answer with only YES or NO.")
        middleware = [make_service_gate(request.platform, request.service, verifier)]
    agent = Agent(
        client=client,
        instructions=cacheable(
            _build_prompt(request, "threat")
            + grounding
            + request.seed_context
            + tag_seed_context()
        ),
        middleware=middleware,
    )
    response = await _saying_it_is_alive(
        _run_with_retry(
            agent,
            f"Target: {subject}\n"
            + _surface_size(request)
            + "Execute the task completely. Be thorough and production-ready.",
            options={"response_format": ThreatAnalysis},
        ),
        "enumerating attack vectors",
    )
    analysis = _unwrap_threat_response(response)
    # Stamped, not asked for. Phase 1 returns `service` as the model writes it,
    # and on the Entra path the model writes the TABLE — so a saved plan said
    # "AuditLogs" and `design detections --from` refused it. Pylon knows what it
    # was asked for; it should not read that back out of a model's answer.
    analysis.target = request.target_key or subject
    # Cleared for the same reason `target` is stamped: this field is Pylon's
    # answer about the plan, not the model's. Left writable, the model filled it
    # with its own KQL advice -- true advice, in the field where the plan gate's
    # findings go, which would have read as Pylon having measured something it
    # had not yet looked at.
    analysis.plan_warnings = []
    # Stamped here, beside the target, for the same reason: both are facts about
    # the RUN that the model has no business supplying or rewriting.
    analysis.provenance = stamp("design plan")
    return analysis


@step
async def verify_mitre_ids(analysis: ThreatAnalysis) -> ThreatAnalysis:
    """Drop vectors whose technique ID is not in the MITRE CTI bundle.

    The prompts forbid fabricated mappings; this makes the rule enforcement,
    not a request. When the bundle is unreachable, verification cannot run — the
    run fails open (keeps vectors) but records mitre_verification="unavailable" and
    logs loudly, so a network hiccup can never masquerade as a clean verification.
    """
    ids = {v.mitre_technique for v in analysis.attack_vectors}
    ids |= {v.mitre_technique.split(".")[0] for v in analysis.attack_vectors}
    try:
        verified = await mitre_technique_names(ids)
    except MitreBundleUnavailable as exc:
        analysis.mitre_verification = "unavailable"
        print(
            f"WARNING: {exc} Attack vectors were NOT screened for fabricated MITRE "
            "IDs this run (mitre_verification=unavailable in run.json).",
            file=sys.stderr,
        )
        return analysis
    analysis.mitre_verification = "verified"
    if not verified:
        return analysis
    analysis.attack_vectors = [
        v
        for v in analysis.attack_vectors
        if v.mitre_technique in verified or v.mitre_technique.split(".")[0] in verified
    ]

    # Existing is not the same as current, and the bundle check above only
    # answers the first. MITRE revokes technique ids and the revoked ones stay
    # in the bundle forever, so every anti-forensics vector this tool wrote was
    # labelled T1562.007 or T1562.008 -- ids MITRE retired in favour of
    # T1686.001 and T1685.002 -- and shipped screened and wrong. Seventeen
    # vectors across seven targets carried one.
    #
    # RELABELLED, NOT DROPPED. Dropping is what a pure validity check leads to
    # and it is the wrong answer: it deletes the detection rather than fixing
    # its label, and the detection was fine. The replacement is stated in the
    # index, so this follows it.
    #
    # Only revocations are followed. A deprecated id, or one from another
    # matrix, has nothing to move to; those are left alone and `mitre.ground`
    # remains the thing that reports them.
    moved = []
    for v in analysis.attack_vectors:
        now, why = mitre.current(v.mitre_technique)
        if now != v.mitre_technique:
            moved.append(why)
            v.mitre_technique = now
    if moved:
        # Loud, because a silently relabelled vector is a change to what the
        # document claims it detects. `version_note` says which ATT&CK release
        # decided it.
        print(f"  relabelled {len(moved)} vector(s) onto current ATT&CK ids "
              f"({mitre.version_note()}):", file=sys.stderr)
        for why in sorted(set(moved)):
            print(f"    {why}", file=sys.stderr)
    return analysis


@step
async def normalize_vector_tags(analysis: ThreatAnalysis) -> ThreatAnalysis:
    """Canonicalize each vector's requires/enables against the shared token list.

    The list[Tag] schema already constrains generation to the closed list; this
    dedupes and drops anything off-list that slips through a backend that doesn't
    strictly enforce enums — a warning, never a failed run (mirrors
    verify_mitre_ids).
    """
    for v in analysis.attack_vectors:
        v.requires, _ = normalize_tags(v.requires)
        v.enables, _ = normalize_tags(v.enables)
    return analysis


@step
@in_phase("run_detection_phase")
async def run_detection_phase(
    request: EngineRequest, grounding: str, analysis: ThreatAnalysis
) -> list[ValidatedDetection]:
    """Fan out one detection-writer call per attack vector, concurrently.

    Each vector gets: generate -> validate_kql -> (on errors) one corrective
    re-run with the error list in the prompt. The original app generated all
    detections in a single document and only *warned* about hallucinated
    fields client-side.
    """
    # Nothing selected is a `design plan` run, not an empty analysis. Announcing
    # "writing detections / 0 attack vectors enumerated" made a successful plan
    # read like a failed design.
    if not analysis.attack_vectors:
        return []

    # THE PLAN GATE. Phase 1 is told to cover the surface and shown how big it
    # is -- without the size, the only way to be exhaustive on a two-operation
    # surface is to invent, and it did: five vectors for Write and Delete, one
    # asking for a write with every destination empty, which cannot happen.
    #
    # A WARNING, not a refusal. This samples one tenant, so a field nobody has
    # triggered is unmeasured rather than unreal. It names the count behind the
    # claim and reaches report.json.
    #
    # Priority has a FLOOR set by where ATT&CK puts the technique, not by the
    # model's judgement: `assessPatches` is discovery because MITRE places
    # T1518 there. A floor only -- the model may rank lower, and a late-chain
    # technique is never demoted.
    for vector in analysis.attack_vectors:
        table = _expected_for_vector(request, vector)
        known = contracts_knowledge.about(table, vector.operation,
                                          request.resource or "")
        if known.tier_exception and vector.priority in ("critical", "high"):
            log.info("plan: %s is early-chain but exempt; keeping %s (%s)",
                     vector.name, vector.priority,
                     known.tier_exception.detail[:120],
                     extra={"event": "plan_gate", "vector": vector.name,
                            "operation": vector.operation, "table": table})
        elif known.tier_floor_applies and vector.priority in ("critical", "high"):
            log.info("plan: %s is %s in ATT&CK; lowering %s to medium",
                     vector.name, known.tier, vector.priority,
                     extra={"event": "plan_gate", "vector": vector.name,
                            "operation": vector.operation, "table": table})
            vector.priority = "medium"

    for table in {_expected_for_vector(request, v) for v in analysis.attack_vectors}:
        here = [(i, v) for i, v in enumerate(analysis.attack_vectors)
                if _expected_for_vector(request, v) == table]
        found = contracts.plan_problems(
            [v for _i, v in here], table,
            vocabulary=operation_vocabulary_for(request, table))
        for position, (index, vector) in enumerate(here):
            for problem in found.get(position, []):
                log.warning("plan: %s — %s", vector.name, problem,
                            extra={"event": "plan_gate", "vector": vector.name,
                                   "operation": vector.operation, "table": table})
                analysis.plan_warnings.append(f"{vector.name}: {problem}")

    _t0 = time.monotonic()
    log.info("writing detections", extra={"event": "phase_start", "phase": "run_detection_phase"})
    agent = Agent(
        client=make_chat_client(),
        instructions=cacheable(_build_prompt(request, "detection") + grounding),
    )
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

    # --dynamic-schema: fetch each target table's LIVE column schema once (the
    # 24h cache dedups), then validate generated KQL against it in addition to
    # the hardcoded validate_kql. Off by default; pure-additive when on.
    live_schemas: dict[str, dict[str, str]] = {}
    if request.dynamic_schema:
        for tbl in {_expected_for_vector(request, v) for v in analysis.attack_vectors}:
            live_schemas[tbl] = await fetch_table_schema(tbl)

    # Microsoft's own column list, per table this run can produce. The prompt has
    # been grounded on this page all along; the validator was not, and judged
    # against `TABLE_SCHEMAS` instead -- the columns the PROMPT teaches, sixteen
    # of AzureActivity's thirty-seven. A live run rejected a correct detection
    # filtering on `OperationId` because of the gap. Same fetch, already cached
    # from the grounding step, so this costs nothing on the wire.
    doc_columns: dict[str, frozenset[str]] = {}
    for tbl in {_expected_for_vector(request, v) for v in analysis.attack_vectors}:
        doc_columns[tbl] = await documented_columns(tbl)

    # The workspace to grade against, if one is configured. Third gate, after
    # the regexes and the KQL engine, and the only one that can ask whether a
    # query matches anything that actually happened.
    #
    # Env-gated like the engine above, and for the same reason: generation must
    # work offline. What it fixes when it IS set is a claim this command makes
    # and cannot support -- "100% of the picked vectors produced a valid
    # detection", printed while shipping a query that matched none of 144 real
    # events. `valid` meant "passed the regexes" and was read as "works".
    verify_workspace = (request.verify_workspace
                        or os.environ.get("PYLON_VERIFY_WORKSPACE", "")).strip()
    verify_window = (request.verify_window
                     or os.environ.get("PYLON_VERIFY_WINDOW", "")).strip() or "30d"
    workspace_guid = ""
    if verify_workspace:
        try:
            from . import validate as _validate_mod
            _t, _a, workspace_guid = _validate_mod.resolve(verify_workspace)
        except Exception as exc:  # noqa: BLE001 - a bad name must not kill a run
            print(f"  PYLON_VERIFY_WORKSPACE={verify_workspace!r} could not be "
                  f"resolved, so detections are not graded against real events: "
                  f"{exc}", file=sys.stderr)
            workspace_guid = ""

    def _count(kql: str) -> int | None:
        """Row count for `kql`, or None when it did not run."""
        from . import validate as _validate_mod

        rows = _validate_mod._run_kql(f"{kql}\n| count", workspace_guid,
                                      _validate_mod.parse_window(verify_window))
        if rows is None:
            return None
        return int(rows[0].get("Count") or 0) if rows else 0

    async def _ground_truth(kql: str, table: str, operation: str):
        """Grade one detection against the workspace, off the event loop.

        Two queries per detection, both synchronous under the hood, so the same
        `to_thread` rule applies as for the KQL engine: a blocking call inside a
        coroutine stalls every other detection being generated beside it.
        """
        return await asyncio.to_thread(
            verification.measure, kql, table, operation, verify_window, _count)

    # Whether the offline KQL engine is reachable. Read once: it decides
    # whether every detection this run pays for a round trip, and a mid-run
    # change of mind would make half the run checked and half not, with nothing
    # saying which.
    offline_on = bool(os.environ.get("PYLON_KUSTAINER_URL", "").strip())
    # Said once per run, before the money, because the consequence is not
    # obvious from the gate lines. The static checks are regexes: they know a
    # banned column and a dead literal, and they cannot tell you a query is well
    # formed. The only real KQL PARSER in this tool is the offline engine. With
    # neither it nor a workspace, nothing in the run will notice a syntax error,
    # and a detection that cannot be parsed ships looking exactly like one that
    # can. That happened.
    if not offline_on and not workspace_guid:
        log.warning(
            "syntax will NOT be checked this run: no PYLON_KUSTAINER_URL and no "
            "--workspace, so nothing here parses KQL. A detection that does not "
            "run will still be written.",
            extra={"event": "gate", "gate": "engine", "passed": False,
                   "vector": "", "kql_sha": "", "skipped": True,
                   "error": "no parser and no workspace"})

    async def _offline(kql: str, table: str) -> OfflineCheck:
        """Run the query through the real KQL engine against an empty typed
        datatable.

        This gate was built, tested, and never connected to anything -- the
        function had no caller outside its own module and `offline_check` was
        never populated on a detection. Three failures reached a live workspace
        in one session that it would have refused at generation, all of them
        things a regex cannot see: an `extend` reading a name defined beside it,
        `Auth.scope` off an unparsed column, and `startswith(x, y)` written as a
        function when KQL has it as a binary operator.

        Static checks are a list of mistakes someone already made. The engine
        is the actual grammar and the actual schema, so it catches the next one
        too.

        IT REPORTS NO REASON. kustainer answers a bad query with
        `General_BadRequest` and a request id, and nothing else -- measured, and
        identical for a syntax error and an unresolved column. So this is a
        pass/fail gate, not a source of guidance, and the retry prompt says so
        rather than implying the model was told what was wrong. The value is
        still large: a query the engine refuses is definitely broken, and
        refusing to ship it does not depend on knowing why.

        Run in a thread. `httpx.post` here is SYNCHRONOUS, and a sync call
        inside a coroutine blocks the whole event loop -- which in this codebase
        is not a theoretical cost: it is what defeats `asyncio.wait_for` and how
        a model call once hung for eighteen hours without the timeout firing.
        """
        schema = schema_for_table(table)
        if not schema:
            # A table the catalogue cannot type would be declared all-string,
            # and an all-string datatable rejects exactly the dynamic-column
            # queries that matter. Not running is the honest answer.
            return OfflineCheck(ran=False,
                                error=f"no typed schema for {table}")
        return await asyncio.to_thread(verify_query_offline, kql, table, schema)

    def _gate(name: str, vector: str, kql: str, passed: bool, **detail) -> None:
        """Record one gate's verdict on one attempt, structured.

        The run log used to show two model calls and two workspace queries and
        nothing about WHICH gate rejected the first attempt or what it produced.
        You could see that a detection was retried; you could not see why, and
        the query that failed existed nowhere at all.

        `kql_sha` is the join. It is what separates a loop that is converging
        from one that is cycling -- three attempts in a row that differ in text
        and land on the same verdict is the signal that the fix belongs in the
        prompt, and the only way to see it is to have both halves recorded
        against each attempt.
        """
        # "pass" and "skipped" are different answers and were rendered the
        # same. A reader scanning a run log for three passes and finding four
        # lines has no way to tell the gate ran from the gate being absent.
        verdict = "skipped" if detail.get("skipped") else ("pass" if passed else "FAIL")
        log.info("gate %s: %s", name, verdict,
                 extra={"event": "gate", "gate": name, "passed": passed,
                        "vector": vector,
                        "kql_sha": hashlib.sha256(kql.encode()).hexdigest()[:12],
                        **detail})

    async def _checked(kql: str, table: str, operation: str = "",
                       vector: str = ""):
        """Static validation, then the engine on whatever survived it.

        Ordered, not parallel. There is no point paying a round trip for a
        query the regexes already rejected, and the engine stops at its FIRST
        error -- so on a query with a fabricated column and a syntax error it
        reports one of them, and the static errors would be lost behind it.

        An engine refusal is folded into the same ValidationResult the retry
        loop already reads, so a refusal drives the same one-shot correction a
        static error does -- and, if the second attempt is refused too, the
        detection ships marked invalid rather than silently.
        """
        result = _validate(kql, table)
        _gate("static", vector, kql, result.valid,
              errors=result.errors[:3], table=table)

        # The contract gate. It runs beside the static one and before anything
        # is paid for, because what it catches is cheap to find and expensive to
        # miss: a column that is present and always empty, a string column
        # compared numerically, a principal projected from rows that do not
        # carry one. All three shipped past the other three gates, because a
        # well-formed query the engine accepts can still read the table wrong.
        breaches = contracts.conforms(kql, table)
        _gate("contract", vector, kql, not breaches,
              breaches=breaches[:3], table=table,
              had_contract=table in contracts.tables())
        if breaches:
            result = merge_results(result, ValidationResult(
                valid=False,
                errors=[f"this contradicts what {table} actually contains: {b}"
                        for b in breaches]))
        offline = OfflineCheck(
            ran=False,
            error="" if offline_on else "no kustainer endpoint configured")
        # Each gate is skipped on its own terms. This used to return early when
        # the KQL engine was not configured, which made the WORKSPACE gate
        # unreachable unless a container happened to be running -- so
        # `--workspace` parsed, cost a round trip of nothing, and recorded no
        # verdict. The gates are independent and the control flow now says so.
        if offline_on and result.valid:
            offline = await _offline(kql, table)
            if offline.unreachable:
                # CONFIGURED AND NOT ANSWERING. Not a verdict on this query, and
                # not a gate the caller chose to skip -- they asked for the
                # parser and are not getting it. Continuing means every
                # remaining detection ships unparsed while the run keeps paying
                # for model calls, which is what round ten did: five correct
                # detections condemned, each re-prompted, $0.45 for nothing.
                raise EngineGone(
                    f"the KQL engine at PYLON_KUSTAINER_URL stopped answering: "
                    f"{offline.error}. Nothing is wrong with the detections -- "
                    f"the parser gate cannot run, so the run is stopping rather "
                    f"than billing for queries nothing can check. Restart the "
                    f"container and re-run; on Apple silicon it dies under "
                    f"Rosetta with exit 133.")
            _gate("engine", vector, kql, offline.ok, ran=offline.ran,
                  error=offline.error[:120])
        else:
            # A gate that does not run must say so. This one was simply absent
            # from the log when no endpoint was configured, so a run showed
            # static, contract and workspace passing and nothing to suggest the
            # only real KQL PARSER had been skipped. The static checks are
            # regexes and cannot tell you a query is well formed, so without an
            # endpoint the sole thing catching a syntax error is the live
            # workspace query -- which means a run without --workspace ships an
            # unparseable detection clean, and one did.
            _gate("engine", vector, kql, True, ran=False, skipped=True,
                  error=offline.error[:120] or "skipped")
        if offline.ran and not offline.ok:
            # WHAT THE ENGINE SAID COMES FIRST, when it said anything. This text
            # asserted "It reports no reason" unconditionally and then printed
            # the reason underneath, so round nine read:
            #
            #   It reports no reason, so re-read the whole query [...]
            #   Engine response: 'extend' operator: Failed to resolve scalar
            #   expression named 'OperationName'
            #
            # Written when the offline engine returned a bare failure, and never
            # revisited once it started naming the fault. The advice is still
            # right for the silent case, so it is kept for that case only --
            # leading with a guess when the engine has named the column wastes
            # the retry this error exists to drive.
            reason = (offline.error or "").strip()
            hints = ("Common causes: an `extend` assignment reading a name "
                     "defined beside it, a column referenced after a "
                     "`summarize` that did not carry it through, an operator "
                     "written as a function (`startswith(a, b)` is not valid "
                     "KQL -- it is `a startswith b`), or a column this table "
                     "does not have.")
            message = (
                f"the real KQL engine refused this query: {reason[:200]} "
                f"Fix exactly what it names. {hints}"
                if reason else
                f"the real KQL engine refused this query and reports no "
                f"reason, so re-read the whole query for a syntax error or a "
                f"column that does not resolve. {hints}")
            result = merge_results(result, ValidationResult(
                valid=False, errors=[message]))
        if not (workspace_guid and operation and result.valid):
            return result, offline, None

        graded = await _ground_truth(kql, table, operation)
        _gate("workspace", vector, kql,
              graded.verdict not in verification.DEFECTS,
              verdict=graded.verdict, expected=graded.expected,
              observed=graded.observed, operation=operation)
        # ONLY a defect invalidates. `no-ground-truth` and `aggregates` mean the
        # question was not answered, and failing on those would reject most
        # correct work: 65% of the detections on this tenant have no matching
        # events at all, because a lab does not read secrets or rotate keys.
        # Treating "we could not check" as "wrong" is the failure this whole
        # command exists to avoid.
        if graded.verdict in verification.DEFECTS:
            result = merge_results(result, ValidationResult(
                valid=False,
                errors=[
                    f"against real events in the workspace this is "
                    f"{graded.verdict}: {graded.detail}. The query is valid KQL "
                    f"and the engine accepted it, so if something is wrong it "
                    f"is in what the query MATCHES rather than how it is "
                    f"written -- a filter comparing the wrong shape (a full ARM "
                    f"path against a bare GUID), a value that never appears in "
                    f"this column, or a join key that is empty on every row. "
                    f"Check those before changing anything: a query that "
                    f"filters on nothing beyond the operation and still matches "
                    f"none of them is the case this can be sure about."],
            ))
        return result, offline, graded

    def _validate(kql: str, table: str) -> ValidationResult:
        """Validate KQL against `table`, adding live-schema checks under
        --dynamic-schema and enforcing the resolved provider on the AzureDiagnostics
        path."""
        # On the generic AzureDiagnostics path, hand the validator the resolved
        # ResourceProvider so it can enforce that every query scopes to it.
        provider = request.az_diag_provider if table == "AzureDiagnostics" else ""
        result = validate_kql(kql, table, expected_provider=provider,
                              documented=doc_columns.get(table))
        if request.dynamic_schema:
            result = merge_results(
                result, validate_against_schema(kql, live_schemas.get(table, {}), table)
            )
        return result

    async def generate_one(vector) -> ValidatedDetection:
        """Build, validate, and self-correct one detection for `vector`.

        Generates KQL, validates it, and on failure re-runs once with the errors in
        the prompt. Returns a budget-skipped placeholder ValidatedDetection when
        the run's cost/token cap is reached.
        """
        expected = _expected_for_vector(request, vector)
        # Ground the operation from the vendored catalog when we have it: what the
        # operation really does + its exact string. Empty for tables/ops we don't
        # cover, so the model falls back to the table's prose asset.
        _og = operation_grounding.grounding_block(expected, vector.operation)
        op_block = f"\n\nVerified operation reference (use these exact facts):\n{_og}" if _og else ""
        # The values a column takes, where the reference page documents them. A
        # wrong VALUE parses and matches nothing, so this is the same class of
        # grounding as the operation literals above — and the model cannot get
        # `notApplied` or `confirmedCompromised` right by reasoning about it.
        # grounding_lines() labels an illustrative set as illustrative; telling
        # the model a partial list is closed is how it learns to write a filter
        # that excludes a real value.
        _vals = column_values.grounding_lines(expected)
        val_block = (
            "\n\nDocumented values for this table's columns (use these exact "
            "spellings):\n" + "\n".join(f"- {line}" for line in _vals)
        ) if _vals else ""
        prompt = (
            "Build ONE production-ready detection for this attack vector "
            "from the Phase 1 threat analysis:\n\n"
            f"Attack vector: {vector.name}\n"
            f"MITRE: {vector.mitre_technique}\n"
            f"Operation: {vector.operation}\n"
            f"Log table: {expected}\n"
            f"Alert condition: {vector.alert_condition}\n"
            f"Rationale: {vector.rationale}"
            + op_block
            + val_block
        )
        async with semaphore:
            # Hard budget stop, enforced in code before spending on another call.
            if over_budget(request.max_cost, request.max_tokens):
                progress.mark_done()
                return ValidatedDetection(
                    detection=Detection(
                        vector_name=vector.name,
                        mitre_technique=vector.mitre_technique,
                        kql="",
                        tuning_guidance="",
                        false_positive_notes="",
                    ),
                    log_table=expected,
                    table_basis=deployed.basis(expected, request.provisioned_tables),
                    valid=False,
                    errors=["skipped: run budget reached before this detection"],
                    warnings=[],
                    retried=False,
                    prerequisite=_prerequisite_for(request, expected),
                    operation=vector.operation,
                    rationale=vector.rationale,
                    priority=vector.priority,
                    requires=vector.requires,
                    enables=vector.enables,
                )
            response = await _run_with_retry(
                agent, prompt, options={"response_format": Detection}
            )
            detection: Detection = response.value
            # Stamped, not asked for. `vector_name` is the join key the report
            # uses to put a detection back beside the vector it was built for,
            # and the model sometimes renames the vector -- narrowing "sink
            # redirected to a non-approved destination" to "redirected
            # cross-subscription" after being told the allowlist half was dead.
            # That rename is a good answer and a broken key: the lookup missed,
            # and three detections rendered with no query and no verdict at all
            # while report.json held both. Pylon knows which vector it asked
            # for; it must not read that back out of the answer.
            detection.vector_name = vector.name
            result, offline, graded = await _checked(
                detection.kql, expected, vector.operation, vector.name)
            result = merge_results(result, _guidance_result(detection, expected))
            retried = False

            if not result.valid:
                retried = True
                # Errors and warnings, kept apart. They were one list under
                # "Fix every listed error", and only the errors are things the
                # query got wrong. A warning is often the validator saying a
                # CHECK could not run -- "Microsoft's column list could not be
                # fetched, so this was NOT checked against it" fires on
                # `CategoryValue`, a real AzureActivity column -- and the model
                # obliges by deleting a correct filter. The run gets one retry;
                # spending it undoing right answers is worse than not retrying.
                must_fix = "\n".join(f"- {m}" for m in result.errors)
                advisory = "\n".join(f"- {m}" for m in result.warnings)
                instruction = (
                    f"{prompt}\n\nYour previous query failed validation.\n\n"
                    f"These are errors. Fix every one:\n{must_fix}\n"
                )
                if advisory:
                    instruction += (
                        "\nThese did NOT fail the query and several of them say a "
                        "check could not be RUN rather than that the query is "
                        "wrong. Act on one only where the change cannot alter what "
                        f"the query matches:\n{advisory}\n")
                instruction += "\nReturn the corrected detection."
                response = await _run_with_retry(
                    agent, instruction,
                    options={"response_format": Detection},
                )
                detection = response.value
                detection.vector_name = vector.name
                result, offline, graded = await _checked(
                    detection.kql, expected, vector.operation, vector.name)
                result = merge_results(result, _guidance_result(detection, expected))

        # Warning-only sanity check on the model-asserted operation string. A
        # wrong operation produces KQL that passes schema validation but filters
        # on a value that never appears — a silently-dead detection. Warnings
        # never invalidate the detection; `cli._kql_header` is what puts them
        # in front of the person pasting the query into Sentinel.
        resource_provider = request.resource if _is_resource_mode(request) else None
        op_status, op_warnings = operation_status(
            vector.operation, expected, resource_provider
        )
        operation_check = OperationCheck(
            status=op_status,
            operation=vector.operation,
            # provider-absent means the catalog could not judge — recorded as
            # unchecked so a gap in the catalog never reads as a clean bill.
            checked=op_status != PROVIDER_ABSENT,
            warnings=list(op_warnings),
        )

        # Models sometimes embellish the technique ID they return
        # ("T1003.001 - OS Credential Dumping: LSASS Memory (Enterprise)").
        # Sentinel's relevantTechniques and our coverage scoring both need the
        # bare ID, so normalize once here — every downstream artifact (report,
        # run.json, rule YAML) then carries the canonical form.
        if graded is not None:
            graded.vector_name = vector.name
        detection.mitre_technique = normalize_technique_id(detection.mitre_technique)
        progress.mark_done()
        return ValidatedDetection(
            detection=detection,
            log_table=expected,
            table_basis=deployed.basis(expected, request.provisioned_tables),
            valid=result.valid,
            errors=result.errors,
            warnings=result.warnings + op_warnings,
            retried=retried,
            prerequisite=_prerequisite_for(request, expected),
            operation=vector.operation,
            operation_check=operation_check,
            offline_check=offline,
            verification=graded,
            rationale=vector.rationale,
            priority=vector.priority,
            requires=vector.requires,
            enables=vector.enables,
        )

    label = "generated"
    progress.set_total(len(analysis.attack_vectors), label=label)
    log.info(
        "%d attack vectors enumerated; writing a detection for each, %d at a time",
        len(analysis.attack_vectors), MAX_CONCURRENCY,
        extra={"event": "fanout", "total": len(analysis.attack_vectors),
               "concurrency": MAX_CONCURRENCY},
    )
    detections = list(await asyncio.gather(
        *[generate_one(v) for v in analysis.attack_vectors]))
    return await _screen_detection_techniques(detections, analysis)


async def _screen_detection_techniques(
    detections: list[ValidatedDetection], analysis: ThreatAnalysis
) -> list[ValidatedDetection]:
    """Check the technique ID phase 2 returned, not just the one phase 1 chose.

    Phase 1's IDs are screened against the MITRE bundle and a fabricated one
    deletes the vector. Phase 2 returns its OWN `mitre_technique`, and that field
    was only reshaped by `normalize_technique_id` -- never checked. It is also the
    field `threats_covered` is built from, so an ID invented in phase 2 inflated
    the coverage number, and nothing said so: a recalled ID is a real ID, and
    reshaping a string is not verification.

    One bundle lookup for the whole batch. The fetch is cached from phase 1, so
    this costs nothing on the wire.

    It falls back rather than dropping the detection. The vector's ID has already
    passed the bundle and the KQL is usually sound when only the label drifted;
    discarding validated work over a wrong label would cost more than it saves.
    The substitution is recorded on the detection, never silent.
    """
    if analysis.mitre_verification != "verified":
        return detections            # nothing was screened; do not imply otherwise

    by_name = {v.name: v for v in analysis.attack_vectors}
    # "unmapped" is a REFUSAL, not a fabrication. MITRE_RULE asks for it by name:
    # "Use only ids given in this prompt; if none of them fits the vector, write
    # unmapped". Screening it as a bad ID and substituting the vector's technique
    # overrides the model at exactly the moment it declined to guess -- and
    # asserts a mapping nobody made. Downstream already treats it as a value
    # (report_design excludes it from the coverage count) rather than an error.
    claimed = {d.detection.mitre_technique for d in detections
               if d.detection.mitre_technique
               and d.detection.mitre_technique != UNMAPPED}
    if not claimed:
        return detections
    try:
        verified = await mitre_technique_names(claimed)
    except MitreBundleUnavailable:
        return detections            # same rule as phase 1: fail open, stay quiet

    for d in detections:
        got = d.detection.mitre_technique
        if not got or got == UNMAPPED or got in verified:
            continue
        vector = by_name.get(d.detection.vector_name)
        fallback = vector.mitre_technique if vector else ""
        note = (f'technique: phase 2 returned "{got}", which is not in the MITRE '
                f"bundle")
        if fallback and fallback != got and fallback != UNMAPPED:
            d.detection.mitre_technique = fallback
            note += f' — using the attack vector\'s verified "{fallback}" instead.'
        else:
            note += " — no verified technique from phase 1 to fall back to."
        d.warnings = list(d.warnings) + [note]
    return detections


@step
@in_phase("run_playbook_phase")
async def run_playbook_phase(request: EngineRequest, target: ValidatedDetection) -> str:
    """Phase 3 — generate one IR playbook (markdown) for the chosen detection.

    Runs the playbook agent grounded in the detection's operation reference (with its
    containment reverse) and cross-log pivots, returning the rendered playbook text.
    """
    _t0 = time.monotonic()
    log.info("writing the incident-response playbook",
             extra={"event": "phase_start", "phase": "run_playbook_phase"})
    # The document is ASSEMBLED, not requested. Three runs of one vector produced
    # three structurally different playbooks because the whole document was a
    # request; a model handed a template to reproduce rewrites it. Pylon renders
    # the fourteen sections and asks only for the four fields it cannot derive.
    from .playbook import PlaybookFill, document_template, fill_prompt, render, unfilled

    agent = Agent(
        client=make_chat_client(),
        instructions=cacheable(fill_prompt(
            _build_prompt(request, "playbook",
                          playbook_target=target.detection.vector_name))),
    )
    # Ground the playbook's operation context (and its containment reverse) in the
    # vendored catalog. Empty for uncovered tables/ops -> falls back to prose.
    _og = operation_grounding.grounding_block(target.log_table, target.operation)
    op_block = f"\n\nVerified operation reference (ground triage/containment in this):\n{_og}" if _og else ""
    # Grounded cross-log pivots for the Investigation section — actor-correlated
    # queries with each table's real fields. Empty for uncovered tables.
    # The pivot key is the table for every ordinary detection and the composite
    # provider/category key on the shared table, where the actor column differs
    # per service and a table-level pivot would name the wrong one. Computed
    # once and used by the pivots, the prompt, the template and the render, so
    # all four are looking at the same service.
    _section = _shared_section(request, target)
    _pv = pivot.render_pivot_block(
        f"{target.log_table}/{_section}" if _section else target.log_table)
    pivot_block = f"\n\n{_pv}" if _pv else ""
    prompt = (
        "Use the Phase 2 output below for context and exact field names.\n\n"
        f"Detection: {target.detection.vector_name} "
        f"({target.detection.mitre_technique})\n\n"
        f"KQL:\n{target.detection.kql}\n\n"
        f"Tuning guidance: {target.detection.tuning_guidance}"
        + op_block
        + pivot_block
    )
    # A rejected FIELD used to discard the whole playbook. The document check
    # below has had a corrective retry all along; this call had none, so one
    # four-sentence attack_context threw away an otherwise complete document and
    # the command wrote nothing. Same treatment, for the same reason: the model
    # supplies four fields, and a field it can correct is not a run it should lose.
    try:
        response = await _arun(agent, prompt,
                               options={"response_format": PlaybookFill})
        fill = _unwrap_fill(response)
    except Exception as exc:
        log.info("playbook fields rejected; asking once more",
                 extra={"event": "playbook_fill_retry", "error": str(exc)[:200]})
        response = await _arun(
            agent,
            f"{prompt}\n\nYour previous answer was rejected: {exc}\nReturn the "
            "same fields again, corrected, and keep every field inside the "
            "length its description states.",
            options={"response_format": PlaybookFill},
        )
        fill = _unwrap_fill(response)
    template = document_template(
        request.platform, target.log_table, target.detection.vector_name,
        operation=target.operation or "",
        technique=target.detection.mitre_technique or "",
        # The provider is already resolved on the generic AzureDiagnostics path
        # and was never handed to the playbook, so a shared-table playbook read
        # the table-level contract and got no per-service roles at all.
        az_provider=_section,
    )
    text = render(template, target, target.log_table, fill, _section)
    # A blank nobody filled is a blank the RESPONDER cannot fill either, because
    # the document never says where its value comes from. Named, not shipped.
    left = unfilled(text)
    if left:
        print(f"WARNING: playbook for '{target.detection.vector_name}' has "
              f"{len(left)} blank(s) with no stated source: {', '.join(left[:3])}",
              file=sys.stderr)

    # Phase 3 output is gated like Phase 2. A playbook carries 6-10 KQL queries
    # and 3 PowerShell blocks a responder pastes at 3am; unchecked, a `let` that
    # shadows its own comparison column and a Graph cmdlet on an Azure
    # connection both reached the assets.
    #
    # FENCE BARE QUERIES FIRST. Asking does not work -- two runs came back with
    # fourteen unfenced queries each, through a header rule and a retry. Fencing
    # here makes it a property of the output, and the checks then see queries
    # that were invisible to every validator.
    text = fence_bare_kql(text)
    check = await asyncio.to_thread(check_playbook, text, target.log_table)
    if check.failed:
        issues = "\n".join(f"- {e}" for e in check.errors)
        # Re-ASK and re-RENDER. Taking `response.text` here would throw away the
        # assembled document and ship whatever prose came back, which is how a
        # retry turned a 323-line playbook into an empty string in the tests.
        # The model only ever supplies four fields, so a retry can only correct
        # those three.
        response = await _arun(
            agent,
            f"{prompt}\n\nThe playbook assembled from your previous three "
            f"fields had these faults:\n{issues}\nReturn the four fields "
            "again, corrected. Still four fields — Pylon writes the document.",
            options={"response_format": PlaybookFill},
        )
        text = render(template, target, target.log_table, _unwrap_fill(response), _section)
        recheck = await asyncio.to_thread(check_playbook, text, target.log_table)
        if recheck.failed:
            # Surfaced, not swallowed. A playbook that still has a broken
            # containment block after a retry is worse than one that says so.
            print(
                f"WARNING: playbook for '{target.detection.vector_name}' still has "
                f"{len(recheck.errors)} code-block fault(s) after one retry: "
                + "; ".join(recheck.errors[:2]),
                file=sys.stderr,
            )
    if check.unchecked:
        print(
            "NOTE: playbook PowerShell not fully checked — " + "; ".join(check.unchecked),
            file=sys.stderr,
        )
    return text


# ── The workflow ──────────────────────────────────────────────────────────────


def _selected_vectors(selection: str, vectors: list) -> list:
    """The vectors a `--pick` string keeps. "none" keeps nothing.

    Matching lives in the CLI (`_resolve_picks`), which already accepts a number,
    a technique id, or a substring of the name. This is the one place the engine
    needs to know the answer, so it asks rather than growing a second rule that
    could disagree about what `--pick federation` means.
    """
    if selection.strip().lower() == "none":
        return []
    from .cli import _resolve_picks

    picks = _resolve_picks(selection, vectors, noun="vector")
    return [vectors[i] for i in (picks or [])]


@workflow(name="pylon")
async def pylon(request: EngineRequest, ctx: RunContext) -> EngineReport:
    """The pylon workflow: grounding -> Phase 1 threat analysis ->
    per-vector detections -> optional HITL playbook selection -> EngineReport.

    Normalizes the request, resets the cost/progress meters, fetches grounding per
    target table, runs the phases, scores MITRE coverage, and returns the report with
    token and cost totals. Phase 3 (playbooks) is opt-in and may suspend for human
    input via ctx.request_info.
    """
    # `replace`, naming ONLY what changes. This was a field-by-field rebuild, and
    # every field it forgot was silently dropped on the way into the workflow --
    # `target_key` was added, not listed here, and arrived as "". The symptom was
    # a saved Entra plan that could not be reopened, three commits after the
    # apparent fix. A copy that enumerates every field is a copy that goes stale
    # the next time someone adds one.
    request = dataclasses.replace(request, service=sanitize_service(request.service))
    # NO reset_meter() here. This body RE-EXECUTES when the workflow resumes from
    # the --playbook pick, and the earlier steps then replay from cache without
    # making model calls — so a reset here zeroed the calls Phase 1 and Phase 2 had
    # already made, and the run reported only the 2 Phase 3 calls that
    # came after it. `--max-cost` was compared against that same wiped meter, so the
    # cap never bound on any run that paused for a pick. The CLI resets once, before
    # the workflow starts. (The intent of the old comment was right — "count only
    # tokens spent this invocation" — the placement made a resume re-ZERO instead.)
    progress.reset()  # Phase 2 detection counter for the CLI spinner

    if _is_resource_mode(request):
        # One grounding fetch per surface table.
        grounding = ""
        for tbl in [s.table for s in _resource_surfaces(request)]:
            grounding += await fetch_grounding(tbl)
        subject = request.resource
    else:
        grounding = await fetch_grounding(table_for_target(request.platform, request.service))
        subject = request.service

    # A plan handed in is a plan already paid for. `design plan` writes one and
    # `design detections --from` passes it back, so choosing what to build costs a
    # look rather than a second Phase 1.
    if request.analysis is not None:
        analysis = request.analysis
    else:
        analysis = await run_threat_phase(request, grounding)
        analysis = await verify_mitre_ids(analysis)
        analysis = await normalize_vector_tags(analysis)

    # Phase 2 is where the money is: one Key Vault run measured 102 model calls,
    # 101 of them here. Narrowing the plan first is the difference between $5.83
    # and a dollar, so the selection is applied BEFORE the fan-out, never after.
    planned = list(analysis.attack_vectors)
    if request.vector_selection:
        keep = _selected_vectors(request.vector_selection, planned)
        analysis.attack_vectors = keep

    attempted = list(analysis.attack_vectors)
    detections = await run_detection_phase(request, grounding, analysis)
    # The plan is what was enumerated, not what was built. Restoring it keeps the
    # report honest about the surface the analysis covered; `attempted` keeps the
    # score honest about what was actually asked for.
    analysis.attack_vectors = planned

    # Phase 3 (IR playbooks) is opt-in. Empty selection -> stop after detections
    # (the base command furnishes threat analysis + detections only, no HITL
    # pause). PLAYBOOK_PROMPT -> suspend and ask the human to pick (the original
    # app's target dropdown); a literal "1,3"/"all" -> non-interactive picks.
    playbooks: list[Playbook] = []
    playbooks_skipped: list[str] = []
    selection = request.playbook_selection
    if selection:
        if selection == PLAYBOOK_PROMPT:
            # HITL: pending requests survive checkpoints; on resume everything
            # above returns from @step cache.
            menu = "\n".join(
                f"{i}: {d.detection.vector_name} ({d.detection.mitre_technique}) [{d.log_table}]"
                f"{'' if d.valid else '  [FAILED VALIDATION]'}"
                for i, d in enumerate(detections)
            )
            selection = await ctx.request_info(
                request_data=(
                    "Pick playbook targets by number (comma-separated, or 'all'):\n" + menu
                ),
                response_type=str,
            )
        # One IR playbook per pick. If the run budget is spent, remaining picks
        # are recorded as skipped but NOT generated — run_playbook_phase is never
        # called for them, so no "skipped" placeholder is cached. A later
        # `--resume` (higher cap) replays Phases 1-2 from cache, resets the meter,
        # and generates exactly the ones that were skipped.
        picks = _parse_choices(selection, len(detections))
        progress.set_total(len(picks), label="playbooks built")  # drives the CLI bar
        for idx in picks:
            target = detections[idx]
            if over_budget(request.max_cost, request.max_tokens):
                playbooks_skipped.append(target.detection.vector_name)
                progress.mark_done()
                continue
            text = await run_playbook_phase(request, target)
            playbooks.append(Playbook(target=target.detection.vector_name, text=text))
            progress.mark_done()

    # External denominator for honest coverage: the platform's ATT&CK cloud
    # catalog (offline, vendored). Falls back to yield-only when unmapped/absent.
    from .catalog.attack import attack_platform_for, load_catalog

    report_platform = "resource" if _is_resource_mode(request) else request.platform
    catalog = load_catalog(attack_platform_for(report_platform))
    score = score_program(
        # What was ATTEMPTED, not what was enumerated. Scoring eight picked
        # detections against a fifty-five vector plan reported 10% for a run
        # that succeeded on every one of its picks.
        threats_in_scope=[v.mitre_technique for v in attempted],
        threats_covered=[d.detection.mitre_technique for d in detections if d.valid],
        catalog_ids=[t.id_norm() for t in catalog] or None,
    )

    meter = current_meter()
    return EngineReport(
        service=subject,
        platform=report_platform,
        # The same run id the plan carries: one invocation, one key, every
        # artefact it wrote.
        provenance=stamp("design detections"),
        analysis=analysis,
        detections=detections,
        # Populated when a workspace was configured at generation, so a report
        # answers "does this fire" without a second command. `design verify`
        # overwrites this list with a fresh measurement.
        verification=[d.verification for d in detections if d.verification],
        playbooks=playbooks,
        playbooks_skipped=playbooks_skipped,
        generation_yield=score.generation_yield,
        vectors_planned=len(planned),
        catalog_coverage=score.catalog_coverage,
        catalog_covered=score.catalog_covered,
        catalog_total=score.catalog_total,
        critical_gaps=[g["mitre_id"] for g in score.critical_gaps],
        mitre_verification=analysis.mitre_verification,
        input_tokens=meter.input_tokens,
        output_tokens=meter.output_tokens,
        model_calls=meter.calls,
        unreported_calls=meter.unreported,
        estimated_cost_usd=estimate_cost(meter.input_tokens, meter.output_tokens),
    )


@functools.lru_cache(maxsize=1)
def runnable():
    """The workflow object that has `.run`, whichever agent_framework is installed.

    `@workflow` changed shape between the versions this project has pinned. In
    1.13 it returned a `FunctionalWorkflow` and you called `.run` on it; from
    1.18 it returns a `FunctionalWorkflowDefinition`, `.run` is gone, and the
    runnable comes from `.build()`. The `.run` signature either side is
    identical, so the build hop is the whole difference.

    That hop lives here rather than at each call site because there are six --
    the CLI, the eval harness and four test files -- and functional workflows
    are still flagged EXPERIMENTAL upstream ("may change or be removed in future
    versions without notice"). The next time this moves it should be one edit.

    Built once and cached, which is what 1.13 did implicitly: `pylon` was itself
    the workflow, module-level, reused across runs. `build()` returns a fresh
    object per call, so building per run would quietly change that -- and
    checkpoint resume runs `.run` twice against what must be one workflow.
    """
    return pylon.build() if hasattr(pylon, "build") else pylon

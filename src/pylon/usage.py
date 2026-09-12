"""Per-run token accounting and cost estimation.

Every model call reports token usage; this accumulates it and turns it into a
dollar estimate so each run tells you what it cost. Prices are USD per 1,000,000
tokens, overridable per deployment via env:

  PYLON_PRICE_INPUT   (default 1.25)
  PYLON_PRICE_OUTPUT  (default 10.00)

The workspace-side rate lives here too, so every price the tool prints is
overridden in one place:

  PYLON_PRICE_GB      (default 4.30, USD per GB ingested)

Defaults assume gpt-5 list pricing (early 2026). Azure OpenAI rates vary by
region and commitment — set the env vars to your actual rates for a real number.
Note: reasoning/"thinking" tokens are billed as output tokens.

Single-run scoped: one CLI invocation = one run, so a module-level meter is
fine. Not safe for concurrent workflow runs in one process.
"""

import os
from dataclasses import dataclass


@dataclass
class UsageMeter:
    """Running token and call totals for a single run.

    `calls` counts every call that was MADE. `unreported` counts how many of
    those came back without usable token counts, and therefore contribute
    nothing to the cost.

    That split is the whole point. This used to drop a call with no usage
    details on the floor — no tokens, no count, no warning — so a run that made
    24 calls reported 1, and there was no way to tell an unreported call from a
    call that never happened. Three real runs came back at a fraction of their
    true cost that way. `--max-cost` is enforced from this meter, so an
    undercount is not a cosmetic problem: it is a cap that does not cap, on a
    tool whose own documentation argues at length that the person typing the
    flag is not the person paying.

    Same shape as the table-plan interlock, and answered the same way: unknown
    is not zero. The tokens genuinely are not known, so they cannot be invented
    — but the CALL is known, and saying so is what turns a silent undercount
    into a visible one.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0
    unreported: int = 0  # calls made whose token counts never arrived

    def add(self, usage_details) -> None:
        """Record one call. Tokens are added when they arrive; the call is
        counted either way."""
        self.calls += 1
        # UsageDetails is a dict subclass; anything else carries no counts.
        if not isinstance(usage_details, dict):
            self.unreported += 1
            return
        got_in = int(usage_details.get("input_token_count", 0) or 0)
        got_out = int(usage_details.get("output_token_count", 0) or 0)
        if not got_in and not got_out:
            # Present but empty is the same answer as absent: nothing measured.
            self.unreported += 1
        self.input_tokens += got_in
        self.output_tokens += got_out

    @property
    def cost_is_partial(self) -> bool:
        """True when some call's tokens never arrived, so every figure derived
        from this meter is a FLOOR rather than a total."""
        return self.unreported > 0


_meter = UsageMeter()


def reset_meter() -> UsageMeter:
    """Replace the module-level meter with a fresh one and return it."""
    global _meter
    _meter = UsageMeter()
    return _meter


def current_meter() -> UsageMeter:
    """The current module-level usage meter."""
    return _meter


def record(usage_details) -> None:
    """Add one call's usage details to the current meter."""
    _meter.add(usage_details)


def _price(env: str, default: float) -> float:
    """Read a float price from env var `env`, falling back to `default` if unset
    or unparseable."""
    try:
        return float(os.environ[env])
    except (KeyError, ValueError):
        return default


def prices() -> tuple[float, float]:
    """(input, output) USD per 1,000,000 tokens."""
    return _price("PYLON_PRICE_INPUT", 1.25), _price(
        "PYLON_PRICE_OUTPUT", 10.0
    )


# USD per GB ingested on the Analytics tier at pay-as-you-go list price, which
# is the only rate that can be a default: a commitment tier, an enterprise
# agreement or a regional difference all move it, and none of them is readable
# from the workspace. The report states the plan it priced against and says
# "list price" so the number is checkable rather than authoritative.
INGEST_PRICE_GB = 4.30


def ingest_price() -> float:
    """USD per GB of billable ingestion, at the configured rate."""
    return _price("PYLON_PRICE_GB", INGEST_PRICE_GB)


def ingest_cost(megabytes: float) -> float:
    """USD for `megabytes` of BILLABLE volume. The caller decides what is
    billable -- this does no arithmetic on which data is free, because that
    depends on what the tenant bought and only the Usage meter knows it."""
    return megabytes / 1024 * ingest_price()


def estimate_cost(input_tokens: int, output_tokens: int) -> float:
    """USD cost estimate for the given token counts at the configured prices."""
    p_in, p_out = prices()
    return input_tokens / 1_000_000 * p_in + output_tokens / 1_000_000 * p_out


def over_budget(max_cost: float = 0.0, max_tokens: int = 0) -> bool:
    """True once the run has spent its cap. Enforced in code, not by the model:
    checked between calls, so a cap is approximate (an in-flight call can push
    slightly over). 0 = no limit.

    A cap read off a meter with `unreported` calls is a floor being compared to
    a limit, so it stops LATER than it should — never earlier. Nothing here can
    fix that, because the missing tokens are missing; `budget_warning` exists so
    the run says it rather than the cap quietly meaning less than it says.
    """
    m = current_meter()
    if max_tokens and (m.input_tokens + m.output_tokens) >= max_tokens:
        return True
    return bool(max_cost and estimate_cost(m.input_tokens, m.output_tokens) >= max_cost)


def budget_warning(max_cost: float = 0.0, max_tokens: int = 0) -> str:
    """What to tell the operator when a cap is being enforced on partial data.

    Empty when there is no cap, or when every call reported its tokens. A cap
    that silently means less than it says is the failure this whole meter is
    guarding against, so it is said out loud rather than left in a field nobody
    reads.
    """
    m = current_meter()
    if not (max_cost or max_tokens) or not m.cost_is_partial:
        return ""
    return (
        f"{m.unreported} of {m.calls} model call(s) returned no token counts, so "
        "the spend measured here is a FLOOR, not a total — the cap you set is "
        "being compared against an undercount and will stop the run later than "
        "you asked, if at all."
    )

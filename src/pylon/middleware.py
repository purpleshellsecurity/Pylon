"""Guardrail middleware — the port of the /api/generate route's guards.

The original route did input sanitization and a cheap LLM yes/no service
check inline before every Phase 1 call. As agent middleware the guard is
configured once at agent creation and cannot be forgotten per call.

Short-circuit rule: middleware that does NOT await call_next() stops the
run — the framework's documented guardrail pattern.
"""

from agent_framework import AgentContext, agent_middleware

from .prompts import is_known_service
from .usage import record


def _did_you_mean(service: str) -> str:
    """Resource types the index holds that look like what was asked for.

    A refusal that names nothing leaves the reader where they started. "Azure
    Bastion" is a product name no catalog can hold, and the index knows
    `Microsoft.Network/bastionHosts` — saying so is the difference between
    ending the conversation and finishing the job.
    """
    try:
        from .catalog import suggest_resource_types
    except ImportError:  # pragma: no cover - catalog ships with the package
        return ""
    hits = suggest_resource_types(service)
    if not hits:
        return ""
    named = ", ".join(hits)
    return f" Closest in the Azure Monitor logs-index: {named}."


def make_service_gate(platform: str, service: str, verifier_agent=None):
    """Agent middleware that blocks Phase 1 for unknown services.

    Known services pass locally with no model call. Free-text input falls
    back to a 10-token LLM yes/no check (the original validateService) via a
    cheap verifier agent — a guard against nonsense input, not a security
    boundary. Fails closed if the verifier errors.
    """

    @agent_middleware
    async def service_gate(context: AgentContext, call_next):
        """Pass known services through; otherwise ask the verifier agent and
        short-circuit the run with a refusal message unless it replies YES."""
        if is_known_service(platform, service):
            await call_next()
            return

        verdict = "NO"
        if verifier_agent is not None:
            try:
                # Metered like any other call: it is a real model call, and a
                # gate that spends money invisibly is the same undercount this
                # meter exists to stop.
                response = await verifier_agent.run(
                    f'Is "{service}" a real cloud service, resource type, or '
                    f"Log Analytics table on the {platform} platform? "
                    f"Reply with only YES or NO."
                )
                record(getattr(response, "usage_details", None))
                verdict = response.text.strip().upper()
            except Exception:  # noqa: BLE001 — verifier failure must fail closed
                verdict = "NO"

        if not verdict.startswith("YES"):
            # Not calling call_next() short-circuits the run.
            context.result = (
                f'"{service}" does not appear to be a valid service for '
                f"{platform}. Check the service name and try again."
                + _did_you_mean(service)
            )
            return

        await call_next()

    return service_gate

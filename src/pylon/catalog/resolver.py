"""Layer 2 of the logs-index chain: resource type -> log categories + routing.

The vendored ``supported_logs_index.md`` (Layer 1, parsed in ``__init__``) maps
each Azure resource type to its supported-logs doc page. This module fetches that
page (Layer 2, same docs source as ``grounding``) and turns it into routing
surfaces so a user can point the tool at *any* indexed Azure resource — not just
the handful hardcoded in ``cli.py`` / ``overlay.py``.

The discovery that shapes this module: the azure-monitor-docs supported-logs
pages publish, for every category, the **AzureDiagnostics** (legacy) table — they
do **not** publish the resource-specific table name (``AKSAudit``,
``AZKVAuditLogs``, ...). Even "Kubernetes Audit" lists ``AzureDiagnostics``. So
Layer 2 reliably yields:

  * the log **categories** a resource emits, and
  * the **AzureDiagnostics** routing (provider + categories) usable for ANY
    resource,

but *not* resource-specific table names. Those stay in the hand-curated
``overlay.py``, which this resolver never overrides — curated resources keep
their high-fidelity resource-specific tables; everything else gets honest,
lower-fidelity AzureDiagnostics coverage instead of a hard "unknown service"
error.

Runnable:
    python -m pylon.catalog.resolver Microsoft.CognitiveServices/accounts
    python -m pylon.catalog.resolver "api management"
"""
from __future__ import annotations

import asyncio
import re
import sys
from dataclasses import dataclass

from ..grounding import DOCS_BASE, _fetch_cached
from .overlay import RESOURCE_OVERLAY, LogSurface

# ── Layer 2: parse the supported-logs page ────────────────────────────────────


@dataclass(frozen=True)
class LogCategory:
    """One log category a resource emits, as parsed from its supported-logs page:
    the category name, the table the docs name for it, and its export-cost flag."""

    name: str          # e.g. "Kubernetes Audit"
    table: str         # table the docs name for it (usually "AzureDiagnostics")
    costs_to_export: bool


def _slug_from_url(url: str) -> str | None:
    """Last path segment of a supported-logs doc URL:
    .../reference/supported-logs/microsoft-keyvault-vaults-logs -> that slug."""
    m = re.search(r"/supported-logs/([a-z0-9-]+)", url)
    return m.group(1) if m else None


def supported_logs_doc_url(resource_type: str) -> str | None:
    """Raw-markdown DOCS_BASE URL for a resource's supported-logs page, or None
    if the resource isn't in the vendored index."""
    from . import supported_logs_url  # local import: avoids an import cycle

    url = supported_logs_url(resource_type)
    slug = _slug_from_url(url) if url else None
    return f"{DOCS_BASE}/supported-logs/{slug}.md" if slug else None


def parse_categories(md: str) -> list[LogCategory]:
    """Parse the ``|Category|Costs to export|Log table|...|`` table into
    LogCategory rows. The Log-table cell is a markdown link
    ``[TableName](/azure/.../tables/<slug>)`` we pull the name out of."""
    cats: list[LogCategory] = []
    header = re.search(r"\|\s*Category\s*\|", md)
    if not header:
        return cats
    # Skip the header row and the |---| separator; read rows until the table ends.
    for line in md[header.start():].splitlines()[2:]:
        line = line.strip()
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        name = cells[0]
        if not name or set(name) <= {"-"}:
            continue
        costs = cells[1].lower().startswith("y")
        link = re.search(r"\[([A-Za-z0-9_]+)\]", cells[2])
        table = link.group(1) if link else cells[2].split("<")[0].strip()
        cats.append(LogCategory(name=name, table=table, costs_to_export=costs))
    return cats


async def fetch_categories(resource_type: str) -> list[LogCategory]:
    """Live log categories for a resource, from the supported-logs doc page.
    Empty list on any miss (not indexed / fetch failed) so callers degrade."""
    url = supported_logs_doc_url(resource_type)
    if not url:
        return []
    md = await _fetch_cached(url)
    return parse_categories(md) if md else []


async def azure_diagnostics_samples(provider: str, limit: int = 4) -> list[str]:
    """Documented AzureDiagnostics KQL scoped to a specific ResourceProvider,
    pulled from the azurediagnostics queries doc. This is the real OperationName
    vocabulary for the generic path — but only for the providers that doc covers
    (Key Vault, Network, SQL, CDN, Automation, Firewall, Event Hub, ...). Returns
    [] for providers it doesn't cover (e.g. Microsoft.CognitiveServices), so the
    prompt falls back to category anchoring."""
    from ..grounding import extract_kql_blocks

    md = await _fetch_cached(f"{DOCS_BASE}/queries/azurediagnostics.md")
    if not md:
        return []
    scoped = re.compile(
        r'ResourceProvider\s*[=~!]+\s*"' + re.escape(provider.upper()) + '"', re.IGNORECASE
    )
    return [b for b in extract_kql_blocks(md) if scoped.search(b)][:limit]


# ── Derive routing surfaces from parsed categories ────────────────────────────


def _provider(resource_type: str) -> str:
    """The provider segment of a resource type (part before the first '/')."""
    return resource_type.split("/")[0]


def derived_surfaces(resource_type: str, categories: list[LogCategory]) -> list[LogSurface]:
    """Routing surfaces for a resource that has NO curated overlay, built from
    its parsed categories. AzureDiagnostics categories collapse into one generic
    surface; any doc-named resource-specific tables (rare) become their own.

    Facts only, and that is a change: these used to assert `covers=("read",
    "write")` and a volume, neither of which the logs-index states. Both strings
    go straight into the generation prompt, so for every uncurated resource — 206
    of the 212 indexed — the model was being told a table covered reads on no
    authority at all. A derived surface now carries `covers=()`,
    `volume="unknown"` and `reviewed=False`, which is what "the page did not say"
    looks like. The curated overlay still asserts both, because there it is
    somebody's judgement rather than a gap being papered over.
    """
    if not categories:
        return []
    provider = _provider(resource_type)
    ad_categories = [c.name for c in categories if c.table.lower() == "azurediagnostics"]
    surfaces: list[LogSurface] = []
    if ad_categories:
        shown = ", ".join(ad_categories[:6]) + ("…" if len(ad_categories) > 6 else "")
        surfaces.append(
            LogSurface(
                table="AzureDiagnostics",
                diagnostic_category=shown,
                mode="azure-diagnostics",
                covers=(),
                volume="unknown",
                note=(
                    f"Generic Azure Diagnostics path for {provider}. No resource-specific "
                    f'table is published for this service; scope with ResourceProvider == '
                    f'"{provider.upper()}" and Category. Lower fidelity than a curated table. '
                    "NOT REVIEWED: whether this covers reads as well as writes, and how "
                    "much of it there is, are not stated in the logs-index."
                ),
                reviewed=False,
            )
        )
    for c in categories:
        if c.table.lower() not in ("azurediagnostics", ""):
            surfaces.append(
                LogSurface(
                    table=c.table,
                    diagnostic_category=c.name,
                    mode="resource-specific",
                    covers=(),
                    volume="unknown",
                    note=(
                        f"Resource-specific table for category '{c.name}' (from the "
                        "logs-index). NOT REVIEWED: whether it covers reads as well as "
                        "writes, and how much of it there is, are not stated there."
                    ),
                    reviewed=False,
                )
            )
    return surfaces


async def resolve_surfaces(resource_type: str) -> list[LogSurface]:
    """Data-plane surfaces for a resource: the hand-curated overlay if one
    exists (high fidelity), else surfaces derived live from the logs-index.
    Empty if the resource isn't indexed and has no overlay."""
    overlay = RESOURCE_OVERLAY.get(resource_type) or RESOURCE_OVERLAY.get(resource_type.lower())
    if overlay:
        return list(overlay)
    return derived_surfaces(resource_type, await fetch_categories(resource_type))


async def resolve_full_surfaces(resource_type: str) -> list[LogSurface]:
    """Every routing surface for a resource — control plane (AzureActivity) plus
    the resolved data-plane surfaces (overlay or logs-index derived). This is the
    resolver-backed version of catalog.log_surfaces, so resource-centric mode can
    route across ANY indexed resource's tables, not just the two with overlays."""
    from . import control_plane_surface  # local import: avoids an import cycle

    return [control_plane_surface(_provider(resource_type))] + await resolve_surfaces(resource_type)


# ── Sync entry point for the CLI selector ─────────────────────────────────────


@dataclass(frozen=True)
class RouteDecision:
    """The resolved routing for a --service pick: the chosen primary surface plus
    the provider, categories, and every table and sample for the multi-table hint."""

    resource_type: str
    surface: LogSurface        # the primary surface chosen for --service
    provider: str
    categories: list[str]
    tables: tuple[str, ...] = ()   # every surface table (for the multi-table hint)
    samples: tuple[str, ...] = ()  # provider-scoped AzureDiagnostics KQL (generic path)

    @property
    def table(self) -> str:
        """The primary surface's table."""
        return self.surface.table

    @property
    def resource_specific(self) -> bool:
        """True when routed to a dedicated table; False for the generic
        AzureDiagnostics path (lower fidelity)."""
        return self.surface.mode != "azure-diagnostics"


# Security-relevance ranking for the single-table --service pick. A resource
# with several resource-specific tables (e.g. API Management publishes a gateway
# log, a dev-portal audit log, a WebSocket log, an LLM-gateway log ...) should
# route --service to the table that actually carries the security-relevant
# request/audit traffic, not whichever the docs happen to list first. (--resource
# mode still routes across ALL of them; this only picks the single primary.)
_SURFACE_BOOST = (
    "audit", "security", "gateway", "signin", "sign-in", "auth",
    "access", "admin", "activity", "diagnostic", "request", "operation",
)
_SURFACE_PENALTY = (
    "usage", "developer portal", "devportal", "trace", "websocket", "metric",
    "llm", "genai", "generative ai", "mcp", "runtime", "health",
)


def _surface_rank(s: LogSurface) -> int:
    """Security-relevance score for a surface: +2 per boost keyword, -2 per
    penalty keyword in its table/category, used to pick the primary --service table."""
    text = f"{s.table} {s.diagnostic_category}".lower()
    return (
        sum(2 for kw in _SURFACE_BOOST if kw in text)
        - sum(2 for kw in _SURFACE_PENALTY if kw in text)
    )


def resolve_dataplane_route(name: str) -> RouteDecision | None:
    """CLI helper: a friendly name or resource-type string -> a routing decision
    derived from the logs-index, or None if it can't be resolved. Runs the async
    fetch to completion; safe to call from sync CLI code before the engine loop."""
    from . import resolve_resource  # local import: avoids an import cycle

    resource_type = resolve_resource(name)
    if not resource_type:
        return None
    surfaces = asyncio.run(resolve_surfaces(resource_type))
    if not surfaces:
        return None
    # Prefer the most security-relevant resource-specific surface; fall back to
    # the generic AzureDiagnostics one. max() keeps doc order on ties (returns
    # the first surface reaching the top score).
    specific = [s for s in surfaces if s.mode != "azure-diagnostics"]
    primary = max(specific, key=_surface_rank) if specific else surfaces[0]
    categories = [s.diagnostic_category for s in surfaces]
    provider = _provider(resource_type)
    # Only the generic AzureDiagnostics path needs the provider-scoped sample
    # grounding; a resource-specific table already grounds on its own doc.
    samples = (
        tuple(asyncio.run(azure_diagnostics_samples(provider)))
        if primary.mode == "azure-diagnostics"
        else ()
    )
    return RouteDecision(
        resource_type=resource_type,
        surface=primary,
        provider=provider,
        categories=categories,
        tables=tuple(s.table for s in surfaces),
        samples=samples,
    )


# ── Runnable demo ─────────────────────────────────────────────────────────────


def _demo(name: str) -> None:
    """Resolve `name` and print its routing decision — the runnable CLI demo."""
    decision = resolve_dataplane_route(name)
    if not decision:
        print(f'"{name}" is not in the vendored logs-index and has no curated overlay.')
        return
    print(f"{name!r} -> {decision.resource_type}")
    print(f"  primary table : {decision.table}  ({decision.surface.mode})")
    print(f"  provider      : {decision.provider}")
    print(f"  resource-spec : {decision.resource_specific}")
    print(f"  note          : {decision.surface.note}")


if __name__ == "__main__":
    _demo(sys.argv[1] if len(sys.argv) > 1 else "Microsoft.CognitiveServices/accounts")

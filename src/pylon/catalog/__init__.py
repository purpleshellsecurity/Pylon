"""Resource → log-surface catalog.

Two layers:

1. STRUCTURAL — parsed from the vendored supported-logs index
   (supported_logs_index.md): resource type -> its supported-logs doc page.
   Broad, low-effort, inherited from Microsoft's own index.

2. SEMANTIC OVERLAY — hand-authored (overlay.py) only where a resource has
   overlapping tables that force a routing decision the index can't express:
   read-vs-write coverage, resource-specific vs legacy AzureDiagnostics mode,
   and the diagnostic-setting prerequisite. Most resources need no overlay.

This is the backbone for resource-centric mode: you name a resource and each
attack vector is routed to the correct table — the generalization of combined
Graph mode. It IS wired into the generation workflow (the resource-mode branch
of engine.pylon calls allowed_tables / log_surfaces).
"""

import json
import re
from functools import lru_cache
from importlib import resources

from .overlay import NO_DATA_PLANE, RESOURCE_OVERLAY, LogSurface

__all__ = [
    "NO_DATA_PLANE",
    "RESOURCE_OVERLAY",
    "LogSurface",
    "allowed_tables",
    "control_plane_surface",
    "DISPLAY_NAMES",
    "data_plane_state",
    "log_surfaces",
    "resolve_resource",
    "resource_candidates",
    "resource_types",
    "service_files",
    "service_logging_docs",
    "service_manifest",
    "suggest_resource_types",
    "supported_logs_url",
]

# Resource type -> the product name a person would recognise. Decoration, and
# deliberately so: a target works with no entry here and falls back to showing
# its resource type, which is what the user types anyway. Azure's product name
# is often not its type name (Microsoft.Web/sites is App Service), so it cannot
# be derived -- but nothing is gated on it, which is the difference between this
# and the picker list it replaced.
DISPLAY_NAMES = {
    "Microsoft.Authorization/roleAssignments": "Role Assignment",
    "Microsoft.Automation/automationAccounts": "Automation Account",
    "Microsoft.Compute/virtualMachines": "Virtual Machine",
    "Microsoft.Insights/diagnosticSettings": "Diagnostic Settings",
    "Microsoft.KeyVault/vaults": "Key Vault",
    "Microsoft.Network/networksecuritygroups": "Network Security Group",
    "Microsoft.Resources/subscriptions/resourceGroups": "Resource Group",
    "Microsoft.Sql/servers": "SQL Server",
    "Microsoft.Storage/storageAccounts/blobServices": "Blob Storage",
    "Microsoft.Storage/storageAccounts/fileServices": "File Storage",
    "Microsoft.Storage/storageAccounts/queueServices": "Queue Storage",
    "Microsoft.Storage/storageAccounts/tableServices": "Table Storage",
    "Microsoft.Web/sites": "App Service and Azure Functions",
}

# Friendly names -> resource type, for the piloted resources. Extend as
# resources are brought into resource-centric mode. These win over the
# auto-derived aliases below (they point at the higher-fidelity overlay).
_ALIASES = {
    "key vault": "Microsoft.KeyVault/vaults",
    "keyvault": "Microsoft.KeyVault/vaults",
    "aks": "Microsoft.ContainerService/managedClusters",
    "managed cluster": "Microsoft.ContainerService/managedClusters",
    "kubernetes": "Microsoft.ContainerService/managedClusters",
    "azure firewall": "Microsoft.Network/azureFirewalls",
    "firewall": "Microsoft.Network/azureFirewalls",
    "container registry": "Microsoft.ContainerRegistry/registries",
    "acr": "Microsoft.ContainerRegistry/registries",
    "azure backup": "Microsoft.RecoveryServices/Vaults",
    "backup": "Microsoft.RecoveryServices/Vaults",
    "recovery services vault": "Microsoft.RecoveryServices/Vaults",
    # A storage account has blob/file/queue/table sub-services; the bare word
    # "storage" stays ambiguous (declines + lists candidates), but these specific
    # friendly phrases default to blob — StorageBlobLogs is the exfil/recon surface
    # that matters for detection. Name a specific sub-service type
    # (e.g. Microsoft.Storage/storageAccounts/fileServices) to target the others.
    # Names that cannot be DERIVED from the type string, so they live here —
    # which is what this map is for. Three reasons a derivation fails: the index
    # holds only a type's sub-services and not the parent (storage accounts), the
    # docs filename is all-lowercase so there is no camel case left to split
    # (networksecuritygroups), or Azure's product name is simply not its type
    # name (Microsoft.Web/sites is App Service).
    "app service": "Microsoft.Web/sites",
    "web app": "Microsoft.Web/sites",
    "function app": "Microsoft.Web/sites",
    "network security group": "Microsoft.Network/networksecuritygroups",
    "nsg": "Microsoft.Network/networksecuritygroups",
    "virtual machine": "Microsoft.Compute/virtualMachines",
    "vm": "Microsoft.Compute/virtualMachines",
    "log analytics workspace": "Microsoft.OperationalInsights/workspaces",
    "storage account": "Microsoft.Storage/storageAccounts/blobServices",
    "blob storage": "Microsoft.Storage/storageAccounts/blobServices",
    "blob": "Microsoft.Storage/storageAccounts/blobServices",
    # Every label the picker offers must resolve here, or a resource-centric run
    # cannot be asked for by the name the tool itself printed. "Azure Functions"
    # and "SQL Server" were both offered and neither resolved.
    "azure functions": "Microsoft.Web/sites",
    "functions": "Microsoft.Web/sites",
    "sql server": "Microsoft.Sql/servers",
    "azure sql": "Microsoft.Sql/servers",
    "sql database": "Microsoft.Sql/servers/databases",
    "azure sql database": "Microsoft.Sql/servers/databases",
    "automation account": "Microsoft.Automation/automationAccounts",
    "automation": "Microsoft.Automation/automationAccounts",
    "cosmos db": "Microsoft.DocumentDB/databaseAccounts",
    "cosmosdb": "Microsoft.DocumentDB/databaseAccounts",
    "event hub": "Microsoft.EventHub/namespaces",
    "service bus": "Microsoft.ServiceBus/namespaces",
    "file storage": "Microsoft.Storage/storageAccounts/fileServices",
    "queue storage": "Microsoft.Storage/storageAccounts/queueServices",
    "table storage": "Microsoft.Storage/storageAccounts/tableServices",
    "key vault secrets": "Microsoft.KeyVault/vaults",
    # ARM operation families rather than resources with a data plane of their
    # own. They resolve so a resource-centric run can be asked for by name, and
    # log_surfaces correctly returns AzureActivity alone for each: there is no
    # data plane to miss, which is different from one nobody has written down.
    "role assignment": "Microsoft.Authorization/roleAssignments",
    "diagnostic settings": "Microsoft.Insights/diagnosticSettings",
    "resource group": "Microsoft.Resources/subscriptions/resourceGroups",
}


def _decamel(s: str) -> str:
    """`CognitiveServices` -> `cognitive services`; `Sql` -> `sql`."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s).strip().lower()


_INDEX = resources.files(__name__) / "supported_logs_index.md"
_LINK_RE = re.compile(r"\* \[([^\]]+)\]\((https?://[^)]+)\)")


def _normalize_url(url: str) -> str:
    """China mirror (docs.azure.cn/...) -> canonical learn.microsoft.com/azure."""
    return url.replace(
        "https://docs.azure.cn/en-us/azure-monitor/",
        "https://learn.microsoft.com/en-us/azure/azure-monitor/",
    )


def _load_index() -> dict[str, str]:
    """Parse the vendored supported-logs index into resource type -> doc URL."""
    text = _INDEX.read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for m in _LINK_RE.finditer(text):
        resource_type, url = m.group(1), _normalize_url(m.group(2))
        out[resource_type] = url
    return out


_INDEX_MAP = _load_index()


def _build_auto_aliases() -> dict[str, list[str]]:
    """Friendly service name (decameled provider) -> resource type(s) from the
    index, so `--service "cognitive services"` resolves without the exact
    `Microsoft.CognitiveServices/accounts` string. A name that maps to more than
    one resource type (e.g. `storage`, `sql`, `network`, `web`) is ambiguous —
    kept as a list so resolve_resource declines it and the caller can list the
    candidates instead of silently guessing."""
    out: dict[str, list[str]] = {}
    for rt in _INDEX_MAP:
        suffix = rt.split("/")[0].split(".", 1)[-1]  # Microsoft.CognitiveServices -> CognitiveServices
        key = _decamel(suffix)
        if not key:
            continue
        out.setdefault(key, [])
        if rt not in out[key]:
            out[key].append(rt)
    return out


_AUTO_ALIASES = _build_auto_aliases()


def resource_types() -> list[str]:
    """All resource types in the vendored index (structural layer)."""
    return sorted(_INDEX_MAP)


def supported_logs_url(resource_type: str) -> str | None:
    """The supported-logs doc page for a resource type (case-insensitive)."""
    if resource_type in _INDEX_MAP:
        return _INDEX_MAP[resource_type]
    lower = resource_type.lower()
    for rt, url in _INDEX_MAP.items():
        if rt.lower() == lower:
            return url
    return None


# Universal control-plane surface: every ARM resource's create/modify/delete
# lands in AzureActivity, regardless of the index (which lists resource logs
# only). This is the "change" side of access-vs-change for all of ARM.
def control_plane_surface(provider: str) -> LogSurface:
    """The universal AzureActivity control-plane surface for a provider — the
    write-only 'change' side every ARM resource shares. Does not record reads."""
    return LogSurface(
        table="AzureActivity",
        diagnostic_category="(Activity Log — always on, no diagnostic setting)",
        mode="control-plane",
        covers=("write",),
        volume="low",
        note=f"Control-plane create/update/delete for {provider}. Does not record reads.",
    )


def resolve_resource(name: str) -> str | None:
    """Friendly name or resource-type string -> canonical resource type.

    Resolution order: exact type -> curated alias -> case-insensitive type ->
    auto-derived friendly name (decameled provider), the last only when it maps
    to a single resource type. An ambiguous friendly name returns None — call
    resource_candidates() to list what it could have meant."""
    # NO_DATA_PLANE is a declaration too: "this resource type exists and has no
    # data plane" is exactly as much of an answer as a routing entry, and four
    # target types (role assignments, diagnostic settings, resource groups, SQL
    # servers) are declared ONLY there. Leaving it out made the resolver reject
    # resource types the tool itself offers.
    _DECLARED = (_INDEX_MAP, RESOURCE_OVERLAY, NO_DATA_PLANE)
    if any(name in d for d in _DECLARED):
        return name
    low = name.strip().lower()
    if low in _ALIASES:
        return _ALIASES[low]
    for d in _DECLARED:
        for rt in d:
            if rt.lower() == low:
                return rt
    auto = _AUTO_ALIASES.get(low)
    if auto:
        narrowed = _prefer_parent(auto)
        if len(narrowed) == 1:
            return narrowed[0]
    return None


def _prefer_parent(candidates: list[str]) -> list[str]:
    """Drop sub-resource types when their PARENT is also a candidate.

    Completing the index took it from 47 resource types to 212, which brought in
    sub-resources — `Microsoft.CognitiveServices/accounts/projects` beside
    `.../accounts`, `Microsoft.ApiManagement/service/workspaces` beside
    `.../service`. Without this, more complete data made `--service "cognitive
    services"` STOP resolving: a name that used to work became ambiguous because
    a child of the thing it meant had appeared.

    A parent and its own children are not a genuine ambiguity — the parent is
    what a friendly name means. Real ambiguity (`storage` over
    `Microsoft.Storage/storageAccounts/blobServices` and its siblings) is
    untouched, because none of those is a prefix of another.
    """
    parents = [
        c for c in candidates
        if not any(other != c and c.startswith(other + "/") for other in candidates)
    ]
    return parents or candidates


@lru_cache(maxsize=1)
def service_logging_docs() -> dict[str, list[dict]]:
    """Resource type -> its service-owned logging docs (Monitor article, dedicated
    logging how-to, monitoring-data reference), from the vendored
    service_logging_docs.json. These are the pages INSIDE a service's own doc set —
    where the real per-table schemas live — as opposed to the auto-generated
    Azure Monitor supported-logs reference. A resource type maps to a LIST because
    one type can back multiple products (e.g. Microsoft.Web/sites = App Service +
    Functions). Keyed case-insensitively. Empty dict if the index is unavailable."""
    try:
        text = (resources.files(__name__) / "service_logging_docs.json").read_text(
            encoding="utf-8"
        )
    except (FileNotFoundError, OSError):
        return {}
    out: dict[str, list[dict]] = {}
    for entry in json.loads(text).get("services", []):
        rt = entry.get("resource_type", "")
        out.setdefault(rt.lower(), []).append(entry)
    return out


@lru_cache(maxsize=1)
def service_manifest() -> dict[str, dict]:
    """The master grounding contract: resource type -> {service_name, tables:
    {table: {columns: {name: type}, curated: bool}}, sources, ...}. Harvested from
    the per-resource-type Azure Monitor tables pages by
    scripts/harvest_service_manifest.py. This is the allowlist a model is bound to
    when building detections for a service — the exact tables and columns that
    exist. Keyed by the exact resource_type string. Empty dict if unavailable."""
    try:
        text = (resources.files(__name__) / "service_manifest.json").read_text(
            encoding="utf-8"
        )
    except (FileNotFoundError, OSError):
        return {}
    return json.loads(text).get("services", {})


@lru_cache(maxsize=1)
def service_files() -> dict[str, dict]:
    """Per-service grounding contracts in the reviewed format: resource type ->
    {logging_docs, api_references, tables: {table: {columns, operations|
    operations_status}}}. logging_docs + columns are doc-verified for all 47
    services; operations are present only where doc-verified (operations_status=
    'pending' otherwise, never invented). Built by scripts/build_service_files.py
    into the per-service files under service_files/ (one JSON per service, keyed by
    its resource_type). Empty dict if the directory is unavailable."""
    out: dict[str, dict] = {}
    try:
        d = resources.files(__name__) / "service_files"
        for f in d.iterdir():
            if f.name.endswith(".json") and not f.name.startswith("_"):
                svc = json.loads(f.read_text(encoding="utf-8"))
                rt = svc.get("resource_type")
                if rt:
                    out[rt] = svc
    except (FileNotFoundError, OSError, NotADirectoryError):
        return {}
    return out


def suggest_resource_types(name: str, limit: int = 5) -> list[str]:
    """Indexed resource types whose TYPE segment contains a word from `name`.

    For the names a catalog cannot hold. "Azure Bastion" is a product name; the
    index knows `Microsoft.Network/bastionHosts`, and no amount of aliasing
    derives one from the other. What it can do is notice that "bastion" appears
    in exactly one type and say so — the difference between a refusal that ends
    the conversation and one that finishes the job.

    Matched on the provider segment as well as the type: a product's name lives
    in one or the other and there is no telling which — "bastion" is the type in
    `Microsoft.Network/bastionHosts`, "postgres" is the provider in
    `Microsoft.DBforPostgreSQL/servers`. "azure" and "microsoft" are dropped
    because they are in almost every entry and would drag in the world.
    """
    words = [w for w in re.split(r"[^a-z0-9]+", name.lower()) if len(w) > 3]
    words = [w for w in words if w not in {"azure", "microsoft", "service", "services"}]
    if not words:
        return []
    hits = []
    for rt in _INDEX_MAP:
        provider, _, tail = rt.partition("/")
        segment = f"{provider.split('.', 1)[-1]} {tail}".lower()
        if any(w in segment for w in words):
            hits.append(rt)
    return sorted(hits)[:limit]


def resource_candidates(name: str) -> list[str]:
    """Resource types an ambiguous friendly name could mean (e.g. `storage` ->
    the four Microsoft.Storage/* types). Empty if the name is unknown or already
    unambiguous. For building a helpful 'did you mean' error."""
    auto = _prefer_parent(_AUTO_ALIASES.get(name.strip().lower(), []))
    return sorted(auto) if len(auto) > 1 else []


def allowed_tables(resource_type: str) -> list[str]:
    """The tables an attack vector may be routed to for this resource."""
    return [s.table for s in log_surfaces(resource_type)]


def data_plane_state(resource_type: str) -> str:
    """Why this resource has no data-plane surfaces: "none" if it has some,
    "by-nature" if NO_DATA_PLANE explains why it never will, "unwritten" if
    nobody has authored its routing yet.

    Callers need the last two apart. Both return AzureActivity alone from
    log_surfaces, and only one of them is a gap.
    """
    rt = resource_type
    if RESOURCE_OVERLAY.get(rt) or RESOURCE_OVERLAY.get(rt.lower()):
        return "none"
    if rt in NO_DATA_PLANE or rt.lower() in {k.lower() for k in NO_DATA_PLANE}:
        return "by-nature"
    return "unwritten"


def log_surfaces(resource_type: str) -> list[LogSurface]:
    """All routing-relevant log surfaces for a resource: its control-plane
    surface (AzureActivity) plus any curated data-plane surfaces from the
    overlay.

    Returns the control-plane surface alone when the resource has no data plane.
    That answer is ambiguous on its own -- see data_plane_state for whether it
    means "nothing else exists" or "nobody has written it down"."""
    provider = resource_type.split("/")[0]
    surfaces = [control_plane_surface(provider)]
    overlay = RESOURCE_OVERLAY.get(resource_type) or RESOURCE_OVERLAY.get(resource_type.lower())
    if overlay:
        surfaces.extend(overlay)
    return surfaces

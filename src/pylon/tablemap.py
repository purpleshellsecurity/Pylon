"""Which table a log category lands in.

The scan measures CATEGORIES -- what a diagnostic setting switches on. Rules
query TABLES. They are not the same names and they are not one to one, so
without this map the two halves of a coverage question cannot be joined:
nothing connects "storage is dark" to "StorageBlobLogs is empty" to "the rule
reading StorageBlobLogs cannot fire".

The table is a function of the category AND the setting's destination mode,
not the category alone. Microsoft's generated reference documents the legacy
answer only -- it lists Key Vault's AuditEvent as AzureDiagnostics and never
mentions AZKVAuditLogs -- so a map built from the docs alone is wrong for any
tenant using resource-specific mode. Three cases exist and all three are in
this tenant:

    dedicated only   storage        always StorageBlobLogs, no legacy form
    dual mode        key vault      AzureDiagnostics or AZKVAuditLogs
    legacy only      cognitive svc  always AzureDiagnostics

`provenance` records where each row came from, because a docs-sourced
dedicated name that no tenant has confirmed is a weaker claim than one read
back out of a workspace.
"""

from __future__ import annotations

LEGACY = "AzureDiagnostics"

# {resource type: {category: (legacy table | None, dedicated table | None, provenance)}}
# A None means that mode does not exist for the category, NOT that it is
# unknown -- unknown is the absence of the row entirely.
TABLE_MAP: dict[str, dict[str, tuple[str | None, str | None, str]]] = {
    "microsoft.keyvault/vaults": {
        # Dedicated names confirmed in a live workspace, not from the docs,
        # which document only the legacy destination for this type.
        "AuditEvent": (LEGACY, "AZKVAuditLogs", "docs+tenant"),
        "AzurePolicyEvaluationDetails": (LEGACY, "AZKVPolicyEvaluationDetailsLogs", "docs+tenant"),
    },
    "microsoft.storage/storageaccounts/blobservices": {
        "StorageRead": (None, "StorageBlobLogs", "docs"),
        "StorageWrite": (None, "StorageBlobLogs", "docs"),
        "StorageDelete": (None, "StorageBlobLogs", "docs"),
    },
    "microsoft.storage/storageaccounts/fileservices": {
        "StorageRead": (None, "StorageFileLogs", "docs"),
        "StorageWrite": (None, "StorageFileLogs", "docs"),
        "StorageDelete": (None, "StorageFileLogs", "docs"),
    },
    # Both are documented the same way blob and file are: the monitoring-data
    # reference for each service carries a "Supported resource logs" table
    # mapping every category to its Log Analytics table.
    "microsoft.storage/storageaccounts/queueservices": {
        "StorageRead": (None, "StorageQueueLogs", "docs"),
        "StorageWrite": (None, "StorageQueueLogs", "docs"),
        "StorageDelete": (None, "StorageQueueLogs", "docs"),
    },
    "microsoft.storage/storageaccounts/tableservices": {
        "StorageRead": (None, "StorageTableLogs", "docs"),
        "StorageWrite": (None, "StorageTableLogs", "docs"),
        "StorageDelete": (None, "StorageTableLogs", "docs"),
    },
    "microsoft.network/networksecuritygroups": {
        "NetworkSecurityGroupEvent": (LEGACY, None, "docs"),
        "NetworkSecurityGroupFlowEvent": (LEGACY, None, "docs"),
        "NetworkSecurityGroupRuleCounter": (LEGACY, None, "docs"),
    },
    "microsoft.network/publicipaddresses": {
        "DDoSMitigationFlowLogs": (LEGACY, None, "docs"),
        "DDoSMitigationReports": (LEGACY, None, "docs"),
        "DDoSProtectionNotifications": (LEGACY, None, "docs"),
    },
    "microsoft.cognitiveservices/accounts": {
        "Audit": (LEGACY, None, "docs"),
        "AzureOpenAIRequestUsage": (LEGACY, None, "docs"),
        "ManagedNetworkEvent": (LEGACY, None, "docs"),
        "RequestResponse": (LEGACY, None, "docs"),
        "Trace": (LEGACY, None, "docs"),
    },
    "microsoft.automation/automationaccounts": {
        "AuditEvent": (LEGACY, None, "docs"),
        "DscNodeStatus": (LEGACY, None, "docs"),
        "JobLogs": (LEGACY, None, "docs"),
        "JobStreams": (LEGACY, None, "docs"),
    },
    "microsoft.operationalinsights/workspaces": {
        "Audit": (None, "LAQueryLogs", "docs"),
        "Jobs": (None, "LAJobLogs", "docs"),
        "SummaryLogs": (None, "LASummaryLogs", "docs"),
    },
    "microsoft.web/sites": {
        "AppServiceAntivirusScanAuditLogs": (None, "AppServiceAntivirusScanAuditLogs", "docs"),
        "AppServiceAppLogs": (None, "AppServiceAppLogs", "docs"),
        "AppServiceAuditLogs": (None, "AppServiceAuditLogs", "docs"),
        "AppServiceAuthenticationLogs": (None, "AppServiceAuthenticationLogs", "docs"),
        "AppServiceConsoleLogs": (None, "AppServiceConsoleLogs", "docs"),
        "AppServiceFileAuditLogs": (None, "AppServiceFileAuditLogs", "docs"),
        "AppServiceHTTPLogs": (None, "AppServiceHTTPLogs", "docs"),
        "AppServiceIPSecAuditLogs": (None, "AppServiceIPSecAuditLogs", "docs"),
        "AppServicePlatformLogs": (None, "AppServicePlatformLogs", "docs"),
        "FunctionAppLogs": (None, "FunctionAppLogs", "docs"),
        "WorkflowRuntime": (None, "LogicAppWorkflowRuntime", "docs"),
    },
}

# Scopes that are not ARM resources still land somewhere.
SCOPE_TABLES: dict[str, str] = {
    "subscription": "AzureActivity",
}

# Paths outside diagnostic settings entirely.
PSEUDO_CATEGORY_TABLES: dict[str, str] = {
    # Traffic Analytics processes flow records into these; without it the
    # records exist only as blobs and reach no table at all.
    "FlowLogs": "NTANetAnalytics",
    # A fallback only. The real answer is the data collection rule's streams,
    # and `AGENT_STREAM_TABLES` below is how they are read. This value is what
    # a VM WOULD fill if an agent were collecting, and `Event` is Windows-only
    # -- so `agent_table` picks by OS rather than using this blindly, which is
    # what shipped and told an Ubuntu VM to feed the Windows event log.
    "AgentCollection": "Event",
}

# What a data collection rule's stream lands in. Read from the DCR's dataFlows,
# which is the authoritative answer for a VM that HAS an agent configured:
# Microsoft's own words are that Windows event data "can only be sent to a Log
# Analytics workspace where it's stored in the Event table", and the same for
# Syslog.
AGENT_STREAM_TABLES: dict[str, str] = {
    "Microsoft-Event": "Event",
    "Microsoft-WindowsEvent": "Event",
    "Microsoft-SecurityEvent": "SecurityEvent",
    "Microsoft-Syslog": "Syslog",
    "Microsoft-Perf": "Perf",
    "Microsoft-InsightsMetrics": "InsightsMetrics",
}

# What a VM with NO agent configured would fill, by operating system. Used only
# when there are no streams to read: it answers "which table is this VM dark
# for", and getting it wrong sends someone to enable collection into a table
# their machine can never write to.
AGENT_TABLE_BY_OS: dict[str, str] = {
    "linux": "Syslog",
    "windows": "Event",
}


def agent_table(streams: list[str] | None, os_type: str | None) -> list[str]:
    """Which tables a VM's agent collection fills, best evidence first.

    Configured streams win: they are what the rule actually routes. Absent any,
    the operating system decides what it WOULD fill -- a Linux machine writes
    Syslog and never Event, so a coverage gap naming Event for an Ubuntu VM is
    advice that cannot be followed.

    An unknown OS with no streams returns nothing rather than guessing. "We do
    not know which table" is a different answer from "Event", and only one of
    them is true.
    """
    if streams:
        known = {AGENT_STREAM_TABLES[s] for s in streams if s in AGENT_STREAM_TABLES}
        if known:
            return sorted(known)
    guess = AGENT_TABLE_BY_OS.get((os_type or "").strip().lower())
    return [guess] if guess else []


def table_for(resource_type: str, category: str,
              dedicated: bool) -> tuple[str | None, str]:
    """(table, provenance) for one category, given the setting's mode.

    Returns (None, "unmapped") where nothing here knows -- never a guess. An
    unmapped category is a hole in this file, and it must read differently
    from a category that genuinely produces no table.
    """
    if category in PSEUDO_CATEGORY_TABLES:
        return PSEUDO_CATEGORY_TABLES[category], "mechanism"
    row = TABLE_MAP.get(resource_type, {}).get(category)
    if row is None:
        return None, "unmapped"
    legacy, ded, provenance = row
    if dedicated and ded:
        return ded, provenance
    if not dedicated and legacy:
        return legacy, provenance
    # The mode asked for does not exist; the type only offers the other one.
    return (ded or legacy), provenance


def tables_for(resource_type: str, categories: list[str],
               dedicated: bool) -> tuple[list[str], list[str]]:
    """(tables these categories fill, categories nothing here can map)."""
    tables, unmapped = set(), []
    for category in categories:
        table, provenance = table_for(resource_type, category, dedicated)
        if table is None:
            unmapped.append(category)
        else:
            tables.add(table)
    return sorted(tables), sorted(unmapped)

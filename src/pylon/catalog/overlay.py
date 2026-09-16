"""Semantic overlay — the routing-relevant metadata the index can't express.

For each data-plane log surface: which table, what it covers (read/write),
whether it needs resource-specific vs legacy AzureDiagnostics mode, and the
diagnostic-setting prerequisite a generated detection must state.

Authored only for resources where the choice actually matters. Piloted on the
two hard cases: Key Vault (control + data plane) and AKS (dual audit tables,
one write-only). Add resources as they're brought into resource-centric mode.
"""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class LogSurface:
    """One log surface for a resource: its table, coverage, mode, and the
    diagnostic-setting prerequisite a generated detection must state."""

    table: str
    diagnostic_category: str
    # resource-specific = dedicated table; azure-diagnostics = legacy blob;
    # control-plane = AzureActivity (always on).
    mode: Literal["resource-specific", "azure-diagnostics", "control-plane"]
    covers: tuple[str, ...]     # subset of {"read", "write"}; () = not established
    volume: Literal["low", "medium", "high", "unknown"]
    note: str
    # False for a surface read off a docs page rather than authored here. The
    # page states categories and table names; it does not state what a table
    # covers or how much of it there is, and both go into the generation prompt.
    # A fetched surface is usable for ROUTING and must not be quoted as judgement.
    reviewed: bool = True

    def prerequisite(self) -> str:
        """Human-readable setup this surface needs: the always-on Activity Log for
        control-plane, else the diagnostic-setting category and mode to enable."""
        if self.mode == "control-plane":
            return "Azure Activity Log (always on)"
        return f'diagnostic setting: category "{self.diagnostic_category}", {self.mode} mode'


# Resources whose data plane is absent BY NATURE, not by omission. Without this,
# log_surfaces returning AzureActivity alone means two different things -- "there
# is nothing else to see" and "nobody has written it down yet" -- and those look
# identical to a caller. Same failure the operation catalogue exists to prevent,
# one level up.
NO_DATA_PLANE: dict[str, str] = {
    "Microsoft.Authorization/roleAssignments":
        "A role assignment is an ARM object. Granting, changing and removing one "
        "are control-plane writes; there is nothing inside it to read.",
    "Microsoft.Insights/diagnosticSettings":
        "A diagnostic setting is the thing that CREATES data planes. It has none "
        "of its own -- writing one is a control-plane operation and that is all "
        "there is.",
    "Microsoft.Resources/subscriptions/resourceGroups":
        "A resource group is a container. Everything that happens to it is a "
        "control-plane write, and everything that happens INSIDE it belongs to "
        "the resources it holds.",
    "Microsoft.Network/networksecuritygroups":
        "Rule changes are control-plane writes. NSG flow logs exist and are a "
        "different product: they are written to a storage account by Network "
        "Watcher rather than to a Log Analytics table by a diagnostic setting, "
        "so they are not a surface this tool can route a detection to.",
    "Microsoft.Compute/virtualMachines":
        "A virtual machine's data plane is its guest operating system, and the "
        "agent-collected tables that carry it -- SecurityEvent, Syslog, Event -- "
        "are endpoint telemetry rather than an Azure resource log. Out of scope "
        "for the same reason Defender for Endpoint is.",
    "Microsoft.Sql/servers":
        "The logical server has no resource logs of its own -- Azure publishes a "
        "supported-logs page for Microsoft.Sql/servers/databases and none for the "
        "server. Auditing configured AT the server flows into each database's "
        "SQLSecurityAuditEvents, so the server's data plane is its databases. Its "
        "control plane is a different matter and is fully partitioned: 163 "
        "operations covering firewall rules, auditing settings and keys.",
    "Microsoft.Automation/automationAccounts":
        "Runbook execution is recorded in JobLogs and JobStreams, which hold job "
        "status and whatever the script printed. Neither is an audit trail with "
        "an operation vocabulary, so the account's real security surface is its "
        "control plane, which is fully partitioned.",
}


# resource type -> its data-plane surfaces (control-plane AzureActivity is added
# universally by catalog.log_surfaces, not repeated here).
RESOURCE_OVERLAY: dict[str, list[LogSurface]] = {
    "Microsoft.KeyVault/vaults": [
        LogSurface(
            table="AZKVAuditLogs",
            diagnostic_category="AuditEvent",
            mode="resource-specific",
            covers=("read", "write"),
            volume="medium",
            note="Data-plane access to secrets/keys/certs, incl. reads (secret Get). "
            "This is where exfil/recon of vault contents shows up — AzureActivity does not.",
        ),
    ],
    # The worst case: two audit tables that overlap, one deliberately narrower.
    "Microsoft.ContainerService/managedClusters": [
        LogSurface(
            table="AKSAudit",
            diagnostic_category="kube-audit",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="Every Kubernetes API call incl. get/list. Use for recon/enumeration "
            "(list secrets, enumerate pods) — the only table with reads. High volume/cost.",
        ),
        LogSurface(
            table="AKSAuditAdmin",
            diagnostic_category="kube-audit-admin",
            mode="resource-specific",
            covers=("write",),
            volume="medium",
            note="Same stream with get/list stripped — write/modify only. Prefer for "
            "change detections (exec, create clusterrolebinding): cleaner and cheaper. "
            "Will NOT contain read/enumeration events.",
        ),
        LogSurface(
            table="AKSControlPlane",
            diagnostic_category="kube-apiserver / kube-controller-manager",
            mode="resource-specific",
            covers=("write",),
            volume="medium",
            note="Control-plane component logs (apiserver, controller-manager). "
            "Supplementary; most detections use the audit tables.",
        ),
    ],
}


# Storage: four sub-services, one shared category set. The diagnostic setting
# attaches to the SUB-RESOURCE, not the account -- the log's own resourceId is
# ".../storageAccounts/testaccount1/blobServices/default" -- so enabling this on
# the account does nothing and reads as configured. Categories verified against
# each service's supported-logs reference:
# https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference
# https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-storage-storageaccounts-fileservices-logs
# (queueServices and tableServices carry the identical three categories).
#
# Present because gap-scan could report ten dark storage accounts and not say
# what to switch on: the harvested service file knows the TABLE, only the
# overlay knows the CATEGORY, and without it the finding ends at "dark".
RESOURCE_OVERLAY.update({
    # SQL, Cosmos, Event Hub and Service Bus. Read off Microsoft's generated
    # supported-logs pages, which for all four list AzureDiagnostics and never
    # the dedicated table -- the exact trap tablemap.py was written for. The
    # dedicated names below come from this repo's own table assets, which were
    # confirmed against a workspace; the CATEGORY that switches each on is the
    # docs' contribution.
    "Microsoft.Sql/servers/databases": [
        LogSurface(
            table="SQLSecurityAuditEvents",
            diagnostic_category="SQLSecurityAuditEvents",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="SQL auditing: the statements that ran against the database, so the "
            "only surface that sees a SELECT. Off by default and it must be switched "
            "on at the server or the database -- every mapping here assumes it is. "
            "The docs list this category as landing in AzureDiagnostics; that is the "
            "legacy mode, and a tenant using resource-specific mode gets this table.",
        ),
    ],
    "Microsoft.DocumentDB/databaseAccounts": [
        LogSurface(
            table="CDBDataPlaneRequests",
            diagnostic_category="DataPlaneRequests",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="Every data-plane operation on the account: creating, updating, "
            "deleting or retrieving data. The read side, so this is where "
            "enumeration and bulk retrieval of documents appear.",
        ),
        LogSurface(
            table="CDBControlPlaneRequests",
            diagnostic_category="ControlPlaneRequests",
            mode="resource-specific",
            covers=("write",),
            volume="low",
            note="Cosmos keeps its OWN control-plane log, and it is not a duplicate of "
            "AzureActivity. Microsoft's description names what it holds: failover "
            "policy, indexing policy, IAM role assignments, backup and restore "
            "policies, virtual network and firewall rules, private links, and account "
            "updates and deletes. Role assignments and firewall rules on one quiet, "
            "low-volume table.",
        ),
        LogSurface(
            table="CDBQueryRuntimeStatistics",
            diagnostic_category="QueryRuntimeStatistics",
            mode="resource-specific",
            covers=("read",),
            volume="high",
            note="The queries run against a SQL API account. Query TEXT and parameters "
            "are obfuscated by default and full text logging is available on request, "
            "so what a detection can read here depends on a setting the tenant chose.",
        ),
    ],
    "Microsoft.EventHub/namespaces": [
        LogSurface(
            table="AZMSRunTimeAuditLogs",
            diagnostic_category="RuntimeAuditLogs",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="Runtime audit: who connected to the namespace and what they did with "
            "messages. The surface for a client reading events it should not. Costs to "
            "export, per the docs, so a tenant may well have left it off.",
        ),
    ],
    "Microsoft.ServiceBus/namespaces": [
        LogSurface(
            table="AZMSRunTimeAuditLogs",
            diagnostic_category="RuntimeAuditLogs",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="The same runtime audit surface Event Hub uses -- both are Azure "
            "Messaging and both write AZMS tables. A rule on this table sees traffic "
            "from either service, so it must scope by resource.",
        ),
        LogSurface(
            table="AZMSVNetConnectionEvents",
            diagnostic_category="VNetAndIPFilteringLogs",
            mode="resource-specific",
            covers=(),
            volume="low",
            note="Which connections the namespace's virtual network and IP filter rules "
            "allowed or blocked. Service Bus publishes this category and Event Hub's "
            "page does not list it, which is why the two are written out separately "
            "rather than aliased to each other.",
        ),
    ],
    # App Service and Functions. The case that showed why this file has to be
    # filled in rather than piloted: a function app writes ELEVEN resource log
    # tables, the picker offered one of them, and the one it offered records
    # publishing logons -- so a stolen function key being USED was invisible.
    #
    # Ordered by what a detection asks. Categories and their descriptions are
    # Microsoft's, from the Functions and App Service monitoring references.
    "Microsoft.Web/sites": [
        LogSurface(
            table="AppServiceHTTPLogs",
            diagnostic_category="AppServiceHTTPLogs",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="Every incoming HTTP request to the app. The only table that sees a "
            "function access key being USED -- an invocation carries the key in the "
            "?code= query string or the x-functions-key header, and a call to the "
            "/admin runtime routes carries the master key. AzureActivity records the "
            "key being READ and never the request that follows. High volume: this is "
            "the app's whole traffic, so a rule needs a path, a status or a rate.",
        ),
        LogSurface(
            table="AppServiceFileAuditLogs",
            diagnostic_category="AppServiceFileAuditLogs",
            mode="resource-specific",
            covers=("write",),
            volume="low",
            note="App content was modified. This is the code changing, whatever route "
            "it arrived by -- a deployment, the Kudu console, or a master key against "
            "the runtime APIs. Quiet in a tenant that deploys through a pipeline, "
            "which is what makes it worth watching.",
        ),
        LogSurface(
            table="AppServiceAuditLogs",
            diagnostic_category="AppServiceAuditLogs",
            mode="resource-specific",
            covers=("write",),
            volume="low",
            note="A SUCCESSFUL publishing logon over FTP, FTPS, Kudu or WebDeploy. "
            "Successes only -- there is no result column, so failed attempts are not "
            "here and a brute-force detection cannot be built on it. Identity is User "
            "and the source IP is UserAddress; the protocol says which door was used.",
        ),
        LogSurface(
            table="AppServiceAuthenticationLogs",
            diagnostic_category="AppServiceAuthenticationLogs",
            mode="resource-specific",
            covers=(),
            volume="medium",
            note="App Service Authentication, the built-in identity layer in front of "
            "the app. Records what it decided about a caller, so it is the surface for "
            "an app whose auth is the platform's rather than its own. Absent entirely "
            "when the feature is off, which is the common case.",
        ),
        LogSurface(
            table="AppServiceIPSecAuditLogs",
            diagnostic_category="AppServiceIPSecAuditLogs",
            mode="resource-specific",
            covers=(),
            volume="low",
            note="Access-restriction decisions: which requests the app's IP rules let "
            "through or turned away. Pairs with the ARM operation that edits those "
            "rules -- the rule change is in AzureActivity, the traffic it newly "
            "permits is here.",
        ),
        LogSurface(
            table="FunctionAppLogs",
            diagnostic_category="FunctionAppLogs",
            mode="resource-specific",
            covers=(),
            volume="high",
            note="Output from the Functions host and from customer code. An "
            "application log, NOT an audit trail: there is no operation column and its "
            "contents are whatever the code chose to write. Useful for an execution "
            "failing or a host restarting; not a surface a detection should filter on "
            "by operation, because there is nothing to filter.",
        ),
    ],
    "Microsoft.Storage/storageAccounts/blobServices": [
        LogSurface(
            table="StorageBlobLogs",
            diagnostic_category="StorageRead, StorageWrite, StorageDelete",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="Data-plane blob requests incl. anonymous and SAS reads. Where exfil (mass GetBlob), public-container access and SAS abuse show up -- AzureActivity records none of it. StorageRead alone is the high-volume category.",
        ),
    ],
    "Microsoft.Storage/storageAccounts/fileServices": [
        LogSurface(
            table="StorageFileLogs",
            diagnostic_category="StorageRead, StorageWrite, StorageDelete",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="Data-plane file share requests over SMB and REST. Carries the SMB identity fields, so it is the only view of share access by a compromised host.",
        ),
    ],
    "Microsoft.Storage/storageAccounts/queueServices": [
        LogSurface(
            table="StorageQueueLogs",
            diagnostic_category="StorageRead, StorageWrite, StorageDelete",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="Data-plane queue requests. Lower volume than blob; useful where a queue drives an automation path an attacker could inject into.",
        ),
    ],
    "Microsoft.Storage/storageAccounts/tableServices": [
        LogSurface(
            table="StorageTableLogs",
            diagnostic_category="StorageRead, StorageWrite, StorageDelete",
            mode="resource-specific",
            covers=("read", "write"),
            volume="high",
            note="Data-plane table requests. Lower volume than blob; relevant where table storage holds configuration or state a detection depends on.",
        ),
    ],
})

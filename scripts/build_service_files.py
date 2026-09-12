"""Emit per-service manifest files in the reviewed format, for all 47 services.

Fills the VERIFIED parts everywhere:
  - logging_docs   : from catalog/service_logging_docs.json (the doc index)
  - tables/columns : from catalog/service_manifest.json (harvested from the real
                     per-resource-type Azure Monitor tables pages)

Fills OPERATIONS only where they've been doc-verified (Key Vault + the four
Storage services). Every other table gets "operations_status": "pending" instead
of an invented list — columns are the allowlist until its ops doc is read.

Writes catalog/service_files/<slug>.json (one per service, the runtime source of
truth) + catalog/service_files/_index.json (counts + resource_type list, no data
duplication). Re-run after verifying more services' operations.
"""
from __future__ import annotations

import json
from pathlib import Path

CATALOG = Path(__file__).resolve().parent.parent / "src" / "pylon" / "catalog"
OUT_DIR = CATALOG / "service_files"

manifest = json.loads((CATALOG / "service_manifest.json").read_text())["services"]
docs_raw = json.loads((CATALOG / "service_logging_docs.json").read_text())["services"]
# Doc-verified operations from the verification workflow (resource_type -> table ->
# {status, operations, source_url, notes}). status="verified" means the ops literally
# appear in the cited doc; "not_enumerated" means the doc was read but lists no
# OperationName values. Never invented — see service_operations_verified.json header.
_wf_path = CATALOG / "service_operations_verified.json"
WF_VERIFIED = json.loads(_wf_path.read_text())["services"] if _wf_path.exists() else {}
# resource_type -> its service-docs entry (first product wins for shared types)
docs: dict[str, dict] = {}
for e in docs_raw:
    docs.setdefault(e["resource_type"], e)

STORAGE_REST = "https://learn.microsoft.com/en-us/rest/api/storageservices/storage-analytics-logged-operations-and-status-messages"

# --- The five doc-verified operation sets (verbatim from Microsoft docs) ---
VERIFIED = {
    "Microsoft.KeyVault/vaults": {
        "AZKVAuditLogs": {
            "rest_api": "https://learn.microsoft.com/en-us/rest/api/keyvault/",
            "operations_source": "https://learn.microsoft.com/en-us/azure/key-vault/general/logging",
            "operations": {
                "vault": ["Authentication", "VaultGet", "VaultPut", "VaultPatch", "VaultDelete", "VaultRecover", "VaultAccessPolicyChangedEventGridNotification"],
                "keys": ["KeyGet", "KeyList", "KeyCreate", "KeyImport", "KeyDelete", "KeyPurge", "KeyRecover", "KeyBackup", "KeyRestore", "KeySign", "KeyVerify", "KeyEncrypt", "KeyDecrypt", "KeyWrap", "KeyUnwrap", "KeyUpdate", "KeyListVersions", "KeyGetDeleted", "KeyListDeleted", "KeyRotate", "KeyRotateIfDue", "KeyRotationPolicyGet", "KeyRotationPolicySet", "KeyNearExpiryEventGridNotification", "KeyExpiredEventGridNotification"],
                "secrets": ["SecretGet", "SecretList", "SecretSet", "SecretDelete", "SecretPurge", "SecretRecover", "SecretBackup", "SecretRestore", "SecretUpdate", "SecretListVersions", "SecretGetDeleted", "SecretListDeleted", "SecretNearExpiryEventGridNotification", "SecretExpiredEventGridNotification"],
                "certificates": ["CertificateGet", "CertificateList", "CertificateCreate", "CertificateImport", "CertificateDelete", "CertificateUpdate", "CertificateListVersions", "CertificatePurge", "CertificateBackup", "CertificateRestore", "CertificateRecover", "CertificateGetDeleted", "CertificateListDeleted", "CertificatePolicyGet", "CertificatePolicyUpdate", "CertificatePolicySet", "CertificateContactsGet", "CertificateContactsSet", "CertificateContactsDelete", "CertificateIssuerGet", "CertificateIssuerSet", "CertificateIssuerUpdate", "CertificateIssuerDelete", "CertificateIssuersList", "CertificateEnroll", "CertificateRenew", "CertificatePendingGet", "CertificatePendingMerge", "CertificatePendingUpdate", "CertificatePendingDelete", "CertificateNearExpiryEventGridNotification", "CertificateExpiredEventGridNotification"],
            },
        },
    },
    "Microsoft.Storage/storageAccounts/blobServices": {
        "StorageBlobLogs": {
            "rest_api": "https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api",
            "operations_source": STORAGE_REST,
            "operations": {
                "blob": ["GetBlob", "PutBlob", "DeleteBlob", "UndeleteBlob", "CopyBlob", "CopyBlobSource", "CopyBlobDestination", "IncrementalCopyBlob", "SnapshotBlob", "AppendBlock", "PutBlock", "PutBlockFromURL", "PutBlockList", "GetBlockList", "PutPage", "ClearPage", "GetPageRanges", "QueryBlobContents", "FindBlobsByTags", "ListBlobs", "GetBlobProperties", "SetBlobProperties", "GetBlobMetadata", "SetBlobMetadata", "GetBlobTags", "SetBlobTags", "SetBlobTier", "SetBlobExpiry"],
                "container": ["CreateContainer", "DeleteContainer", "ListContainers", "GetContainerProperties", "GetContainerMetadata", "SetContainerMetadata", "GetContainerACL", "SetContainerACL"],
                "lease": ["AcquireBlobLease", "RenewBlobLease", "ReleaseBlobLease", "BreakBlobLease", "ChangeBlobLease", "GetBlobLeaseInfo", "AcquireContainerLease", "RenewContainerLease", "ReleaseContainerLease", "BreakContainerLease", "ChangeContainerLease"],
                "account": ["GetAccountInformation", "GetUserDelegationKey", "GetBlobServiceStats", "GetBlobServiceProperties", "SetBlobServiceProperties", "AbortCopyBlob", "BlobPreflightRequest"],
            },
        },
    },
    "Microsoft.Storage/storageAccounts/fileServices": {
        "StorageFileLogs": {
            "rest_api": "https://learn.microsoft.com/en-us/rest/api/storageservices/file-service-rest-api",
            "operations_source": STORAGE_REST,
            "operations": {
                "file": ["GetFile", "PutRange", "PutRangeFromURL", "CreateFile", "DeleteFile", "ClearRange", "ListFileRanges", "GetFileProperties", "SetFileProperties", "GetFileMetadata", "SetFileMetadata", "GetFilePermission", "PutFilePermission", "CreateFileSnapshot", "ListFileSnapshots", "GetFileCopyInformation", "GetPostMigrationFileInfo", "CopyFile", "CopyFileSource", "CopyFileDestination", "AbortCopyFile", "GetEncryptionKey"],
                "directory": ["CreateDirectory", "DeleteDirectory", "GetDirectoryMetadata", "SetDirectoryMetadata", "GetDirectoryProperties", "ListFilesystemDir", "ListFiles"],
                "share": ["CreateShare", "DeleteShare", "GetShareProperties", "SetShareProperties", "GetShareMetadata", "SetShareMetadata", "GetShareAcl", "SetShareAcl", "GetShareStats", "GetFileShareUniqueId", "SnapshotShare", "ListShares"],
                "lease": ["AcquireFileLease", "BreakFileLease", "ChangeFileLease", "ReleaseFileLease"],
                "handles": ["ListHandles"],
                "service": ["GetFileServiceProperties", "SetFileServiceProperties", "FilePreflightRequest", "FileSessionConnect"],
                "smb": ["Cancel", "ChangeNotify", "Close", "Create", "Echo", "Flush", "Ioctl", "Lock", "Logoff", "Negotiate", "OplockBreak", "QueryDirectory", "QueryInfo", "Read", "SessionSetup", "SetInfo", "TreeConnect", "TreeDisconnect", "Write"],
            },
        },
    },
    "Microsoft.Storage/storageAccounts/queueServices": {
        "StorageQueueLogs": {
            "rest_api": "https://learn.microsoft.com/en-us/rest/api/storageservices/queue-service-rest-api",
            "operations_source": STORAGE_REST,
            "operations": {
                "message": ["PutMessage", "GetMessage", "GetMessages", "GetMessageRead", "GetMessageWrite", "PeekMessage", "PeekMessages", "UpdateMessage", "DeleteMessage", "ClearMessages"],
                "queue": ["CreateQueue", "DeleteQueue", "GetQueue", "ListQueues", "GetQueueMetadata", "SetQueueMetadata"],
                "service": ["GetQueueServiceProperties", "SetQueueServiceProperties", "QueuePreflightRequest"],
            },
        },
    },
    "Microsoft.Storage/storageAccounts/tableServices": {
        "StorageTableLogs": {
            "rest_api": "https://learn.microsoft.com/en-us/rest/api/storageservices/table-service-rest-api",
            "operations_source": STORAGE_REST,
            "operations": {
                "entity": ["InsertEntity", "QueryEntity", "QueryEntities", "UpdateEntity", "MergeEntity", "DeleteEntity", "InsertOrMergeEntity", "InsertOrReplaceEntity", "EntityGroupTransaction"],
                "table": ["CreateTable", "DeleteTable", "QueryTable", "QueryTables"],
                "service": ["GetTableServiceProperties", "SetTableServiceProperties", "TablePreflightRequest"],
            },
        },
    },
}


# Action-like fields a table may carry INSTEAD of OperationName. If a table has
# none of OperationName/OperationNameValue, it can't be filtered on OperationName;
# we say so honestly and point at whatever action field it does have (several are
# grounded elsewhere: AZFW Action, SQL ActionName).
_ALT_ACTION_FIELDS = ["ActionName", "DeviceAction", "Action", "Operation", "Category"]


def _pending_status(cols: dict) -> str:
    """Honest operations_status for a table whose operations aren't doc-verified."""
    lower = {c.lower(): c for c in cols}
    if "operationname" in lower or "operationnamevalue" in lower:
        return "pending doc verification (columns below are the verified allowlist)"
    alt = next((lower[f.lower()] for f in _ALT_ACTION_FIELDS if f.lower() in lower), None)
    if alt:
        return (
            f"n/a — no OperationName column in this table's schema; its action field "
            f"is '{alt}' (columns below are the verified allowlist)"
        )
    return (
        "n/a — no OperationName column in this table's schema; it carries no action "
        "field (metrics/telemetry table; columns below are the verified allowlist)"
    )


def build_one(rt: str, svc: dict) -> dict:
    d = docs.get(rt, {})
    out: dict = {
        "resource_type": rt,
        "service_name": svc.get("service_name") or d.get("service_name"),
        "logging_docs": {
            "monitor_page": d.get("monitor_page"),
            "dedicated_logging_page": d.get("dedicated_logging_page"),
            "monitoring_data_reference": d.get("monitoring_data_reference"),
            "supported_logs_reference": d.get("supported_logs_reference"),
        },
        "tables": {},
    }
    if svc.get("routing") == "AzureDiagnostics":
        out["routing"] = "AzureDiagnostics"
    # Categories a service emits into the shared AzureDiagnostics table (for
    # services with no resource-specific table, or in addition to their dedicated
    # ones). Query AzureDiagnostics and scope `| where Category == "<cat>"`.
    if svc.get("azure_diagnostics_categories"):
        out["azure_diagnostics_categories"] = svc["azure_diagnostics_categories"]

    verified = VERIFIED.get(rt, {})
    wf = WF_VERIFIED.get(rt, {})
    rest_apis = set()
    op_sources = set()
    for tname, tinfo in svc.get("tables", {}).items():
        entry: dict = {"schema_mode": "resource-specific"}
        v = verified.get(tname)
        w = wf.get(tname)
        if v:
            # Hand-verified (Key Vault + the four Storage services): grouped ops.
            entry["operation_field"] = "OperationName"
            entry["operations"] = v["operations"]
            rest_apis.add(v["rest_api"])
            op_sources.add(v["operations_source"])
        elif w and w.get("status") == "verified" and w.get("operations"):
            # Workflow-verified: flat list, ops literally present in the cited doc.
            # The target column varies: audit-style tables (e.g. Databricks) put the
            # value in ActionName, not OperationName. Honor the doc-reported field.
            entry["operation_field"] = w.get("field") or "OperationName"
            entry["operations"] = w["operations"]
            if w.get("source_url"):
                op_sources.add(w["source_url"])
        elif w and w.get("status") == "not_enumerated":
            src = w.get("source_url") or "the service doc"
            entry["operations_status"] = (
                f"not enumerated in Azure docs (checked {src}); "
                "columns below are the verified allowlist"
            )
            if w.get("notes"):
                entry["operations_note"] = w["notes"]
        else:
            cols = tinfo.get("columns", {})
            entry["operations_status"] = _pending_status(cols)
        entry["columns"] = tinfo.get("columns", {})
        out["tables"][tname] = entry

    api: dict = {}
    if rest_apis:
        api["data_plane_rest_api"] = min(rest_apis) if len(rest_apis) == 1 else sorted(rest_apis)
    if op_sources:
        api["operations_source"] = min(op_sources)
    if api:
        out["api_references"] = api
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    combined: dict[str, dict] = {}
    verified_n = 0
    for rt, svc in sorted(manifest.items()):
        f = build_one(rt, svc)
        combined[rt] = f
        slug = rt.lower().replace(".", "-").replace("/", "-")
        (OUT_DIR / f"{slug}.json").write_text(json.dumps(f, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if rt in VERIFIED:
            verified_n += 1

    n_tables = sum(len(s["tables"]) for s in combined.values())
    ops_tables = sum(1 for s in combined.values() for t in s["tables"].values() if "operations" in t)
    not_enum = sum(
        1
        for s in combined.values()
        for t in s["tables"].values()
        if str(t.get("operations_status", "")).startswith("not enumerated")
    )
    pending = sum(
        1
        for s in combined.values()
        for t in s["tables"].values()
        if str(t.get("operations_status", "")).startswith("pending")
    )
    svcs_with_ops = sum(
        1 for s in combined.values() if any("operations" in t for t in s["tables"].values())
    )
    meta = {
        "purpose": "Per-service grounding contracts, one JSON per service under this directory (keyed by resource_type). logging_docs + table columns are doc-verified for all services; operations are doc-verified only where present. A table is one of: operations (verified against source_url), operations_status='not enumerated' (doc read, lists no OperationName values), operations_status='n/a' (table has no OperationName column — metrics/telemetry or uses a different action field), or operations_status='pending' (has an OperationName column, not yet checked). Never invented.",
        "services": len(combined),
        "tables": n_tables,
        "tables_with_verified_operations": ops_tables,
        "tables_operations_not_enumerated_in_docs": not_enum,
        "tables_pending_verification": pending,
        "services_with_any_verified_operations": svcs_with_ops,
        "services_hand_verified": verified_n,
    }
    # A small index only — the data lives in the per-service files, not duplicated here.
    (OUT_DIR / "_index.json").write_text(
        json.dumps({"metadata": meta, "resource_types": sorted(combined)}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(combined)} per-service files + service_files/_index.json")
    print(f"  tables: {n_tables}  | tables with verified operations: {ops_tables}  | services verified: {verified_n}")


if __name__ == "__main__":
    main()

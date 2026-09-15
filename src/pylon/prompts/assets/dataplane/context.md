

## Azure Data Plane — Diagnostic Log Schema Reference

You are building detections for Azure data plane operations using service-specific diagnostic log tables in Microsoft Sentinel.

### The Data Plane Difference
Unlike Azure ARM (single AzureActivity table) or Entra ID directory changes (single AuditLogs table), Azure Data Plane logging uses DIFFERENT tables per service. The exact table and field names depend on the service being analyzed. The table you must use is explicitly provided in the task — do not substitute a different table under any circumstances.

### Service-to-Table Mapping

| Service | Log Table | Notes |
|---------|-----------|-------|
| Key Vault Secrets | AZKVAuditLogs | Resource-specific table — preferred over AzureDiagnostics |
| Blob Storage | StorageBlobLogs | Resource-specific table — preferred over AzureDiagnostics |
| File Storage | StorageFileLogs | Resource-specific table — preferred over AzureDiagnostics |
| Queue Storage | StorageQueueLogs | Resource-specific table — preferred over AzureDiagnostics |
| Table Storage | StorageTableLogs | Resource-specific table — preferred over AzureDiagnostics |

These five are the data plane tables this tool covers. Every one of them has a
complete operation vocabulary behind it, so a name that is not in the task's
operation list is not a name the table writes.

### CRITICAL: Always use the resource-specific table
Never use AzureDiagnostics when a resource-specific table exists.
The table is explicitly stated in every task — use it exactly as written.

### Per-table columns
The task carries the schema reference for the table you were given. Read the
column names, and especially the TYPES, from there — this page deliberately
does not repeat them, because a second copy is a second thing to go stale.

### Fields that DO NOT EXIST across data plane tables (never use these)
- identity_s / httpStatusCode_d / id_s / statusCode_s / callerIpAddress_s /
  userAgent_s → AzureDiagnostics spellings. The resource-specific tables use
  plain names and different TYPES. A suffixed column name on a dedicated table
  is always wrong here.
- ResourceId → the column is _ResourceId, with the leading underscore
- InitiatedBy → use service-specific identity fields
- ActivityStatusValue → use ResultType (AZKVAuditLogs) or StatusCode (the
  Storage tables)
- OperationNameValue → use OperationName (data plane uses mixed case, not
  all-caps; OperationNameValue is an AzureActivity column)
- TargetResources → data plane tables are flat
- Category / LoggedByService → AuditLogs columns, not data plane ones

### The one type trap that spans these tables
- AZKVAuditLogs.HttpStatusCode is an INT — compare numerically (>= 300).
- The four Storage tables spell status as StatusCode and it is a STRING —
  compare to "200" / "403", never numerically.
Getting this backwards produces valid KQL that never matches.

### Anti-Fabrication Rules
- Only include attack vectors based on REAL, DOCUMENTED operations for the specified table
- Every OperationName must be the exact string that appears in that table
- Do NOT use AzureDiagnostics — always use the resource-specific table provided in the task
- Do NOT include statistics, percentages, or frequency claims
- Do NOT write multi-step attack chains



## Microsoft Graph — AuditLogs Schema Reference

You are building detections for Microsoft Entra ID using the AuditLogs table in Microsoft Sentinel.

### Fields that EXIST in AuditLogs
- TimeGenerated
- OperationName — exact operation string (e.g. "Add service principal credentials")
- Category — UserManagement, ApplicationManagement, RoleManagement
- Result — "success" or "failure"
- Identity — may contain UPN
- InitiatedBy — DYNAMIC type, must parse with tostring()
- TargetResources — ARRAY type, must use mv-expand
- CorrelationId

### Fields that DO NOT EXIST in AuditLogs (never use these)
- UserPrincipalName → use tostring(InitiatedBy.user.userPrincipalName)
- SourceIP → use tostring(InitiatedBy.user.ipAddress)
- AppName → use tostring(InitiatedBy.app.displayName)
- AppId → use tostring(InitiatedBy.app.appId)
- StatusCode → use Result

### KQL Parse Order Rule
Always extract InitiatedBy fields BEFORE mv-expand on TargetResources.

CORRECT:
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)  // BEFORE
| extend ActorAppId = tostring(InitiatedBy.app.appId)             // BEFORE
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)           // BEFORE
| mv-expand TargetResources                                        // THEN expand
| extend TargetName = tostring(TargetResources.displayName)        // AFTER

WRONG — ActorUPN will be empty:
| mv-expand TargetResources
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)  // TOO LATE

### modifiedProperties Parsing
Values come as JSON arrays: "[false]" not "false". Always clean them:
| mv-expand ModifiedProps = TargetResources.modifiedProperties
| extend PropertyName = tostring(ModifiedProps.displayName)
| extend NewValue = tostring(ModifiedProps.newValue)
| extend NewValueClean = trim(@'[\[\]"\s]', NewValue)
| where NewValueClean =~ "false"

### Detection Philosophy: AuditLogs Only
- AuditLogs is the only table for this target, in every phase.
- Do not reach for a second Entra table. A query against one this tool does
  not cover is neither grounded nor validated here.

### Known Microsoft App IDs (use for exclusions in Phase 2)
let KnownMicrosoftApps = dynamic([
    "cb1056e2-e479-49de-ae31-7812af012ed8",  // Azure AD Connect Sync
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",  // Microsoft Graph PowerShell
    "1950a258-227b-4e31-a9cf-717495945fc2",  // Microsoft Azure PowerShell
    "797f4846-ba00-4fd7-ba43-dac1f8f63013",  // Azure Resource Manager
    "00000002-0000-0000-c000-000000000000",  // Azure AD Graph (legacy)
    "00000003-0000-0000-c000-000000000000",  // Microsoft Graph
    "0000000c-0000-0000-c000-000000000000",  // Microsoft App Access Panel
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",  // Azure Portal
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   // Azure CLI
]);

### Anti-Fabrication Rules
- Only include attack vectors based on REAL, DOCUMENTED Microsoft Graph API operations
- Every OperationName must be the exact string that appears in AuditLogs
- Do NOT invent attack vectors that sound plausible but are not documented
- Do NOT include statistics, percentages, or frequency claims
- Do NOT write multi-step attack chains
- Do NOT attribute to APT groups without a specific cited source

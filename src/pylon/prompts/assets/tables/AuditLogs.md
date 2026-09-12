
## AuditLogs — Schema Reference & Parsing Guide

### Purpose
Records Entra ID directory changes. Captures user/group/app/role/credential/permission
changes. Does NOT capture reads — use MicrosoftGraphActivityLogs for data plane activity.

### Detection Philosophy: AuditLogs First
- Always available — no additional configuration required
- Captures all control plane operations (CREATE/UPDATE/DELETE on directory objects)
- Lower cost and simpler queries than MicrosoftGraphActivityLogs
- Better signal-to-noise for security-relevant operations
- MicrosoftGraphActivityLogs is for Phase 3 enrichment only — not primary Phase 2 detections

### Key Fields
- TimeGenerated
- OperationName — "Add user", "Update application", etc. MATCH IT WITH `=~`,
  NEVER `==`. Microsoft's documented activity names and what a tenant actually
  writes differ in CASE. Measured: the reference says "Delete Conditional Access
  policy" and the tenant logged "Delete conditional access policy". `==` is
  case-sensitive in KQL, so a detection using it parses, validates, executes and
  matches nothing for ever. AzureActivity has carried this rule for
  OperationNameValue all along; AuditLogs needs it just as much.
- Category — UserManagement, ApplicationManagement, RoleManagement, GroupManagement,
  DirectoryManagement, DeviceManagement, Policy. This is the field those words
  belong to.
- LoggedByService — the Entra SERVICE that wrote the row, NOT the category. Real
  values are prose with spaces: "Core Directory", "Self-service Group Management",
  "Account Provisioning", "Conditional Access", "Authentication Methods", "PIM".
  Never a Category value.
- Result — "success" or "failure" (lowercase)
- InitiatedBy — WHO — DYNAMIC type, must parse with tostring()
- TargetResources — WHAT — ARRAY type, must use mv-expand
- CorrelationId — links related operations
- Identity — UPN if available

### LoggedByService vs Category — MEASURED, and the mistake is silent
Both columns exist, so a query mixing them up parses, validates, deploys, executes
and returns clean — for ever. It was measured against a live tenant by performing
the attack and reading the row it wrote:

    Operation        "Add service principal credentials"
    Category         "ApplicationManagement"     <- the category
    LoggedByService  "Core Directory"            <- the service

`| where LoggedByService == "ApplicationManagement"` therefore matches NOTHING.
In one run, 25 of 25 generated detections carried exactly that filter and not one
of them could ever fire.

If you want to scope by the kind of object, filter **Category**. If you do not
need to scope by service, omit LoggedByService entirely — OperationName is already
specific. Do not guess a LoggedByService value.

### Fields That DO NOT Exist in AuditLogs
- UserPrincipalName → use Identity or parse InitiatedBy
- SourceIP → use tostring(InitiatedBy.user.ipAddress)
- AppName → use tostring(InitiatedBy.app.displayName)
- StatusCode → use Result
- ActivityStatusValue → AzureActivity field, does not exist here

### InitiatedBy Parsing (REQUIRED)
Always extract InitiatedBy fields with tostring():

| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorAppId = tostring(InitiatedBy.app.appId)
| extend ActorAppName = tostring(InitiatedBy.app.displayName)
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)

### TargetResources Parsing (REQUIRED)
| mv-expand TargetResources
| extend TargetId = tostring(TargetResources.id)
| extend TargetType = tostring(TargetResources.type)
| extend TargetName = tostring(TargetResources.displayName)

---

## CRITICAL KQL Gotchas

### Gotcha 1 — KQL Parsing Order Rule
ALWAYS extract parent-level fields BEFORE mv-expand on child arrays.
Fields from InitiatedBy return empty/wrong values after mv-expand.

CORRECT:
AuditLogs
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)  // BEFORE
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)           // BEFORE
| mv-expand TargetResources                                        // THEN expand
| extend TargetName = tostring(TargetResources.displayName)       // AFTER

WRONG — ActorUPN will be empty:
AuditLogs
| mv-expand TargetResources
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)  // TOO LATE

### Gotcha 2 — Nested mv-expand
Extract ALL parent fields before ANY mv-expand:

CORRECT:
AuditLogs
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)  // First
| mv-expand TargetResources                                        // First expand
| extend ModifiedProps = TargetResources.modifiedProperties
| mv-expand ModifiedProps                                          // Second expand
| where tostring(ModifiedProps.displayName) == "SomeProperty"

WRONG:
AuditLogs
| mv-expand TargetResources
| mv-expand ModifiedProps
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)  // Returns garbage

### Gotcha 3 — Always Use tostring() for Dynamic Fields
CORRECT:   | extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
WRONG:     | extend ActorUPN = InitiatedBy.user.userPrincipalName

### Gotcha 4 — modifiedProperties Values Are JSON-Encoded Arrays
Values come as "[false]" not "false". Always clean them:

CORRECT:
| mv-expand ModifiedProps = TargetResources.modifiedProperties
| extend PropertyName = tostring(ModifiedProps.displayName)
| extend NewValue = tostring(ModifiedProps.newValue)
| extend OldValue = tostring(ModifiedProps.oldValue)
| extend NewValueClean = trim(@'[\[\]"\s]', NewValue)
| extend OldValueClean = trim(@'[\[\]"\s]', OldValue)
| where NewValueClean =~ "false"

WRONG — misses "[false]":
| where NewValue == "false"

Common properties affected: AccountEnabled, AppRoleAssignmentRequired,
BlockCredential, ShowInMyApps, any boolean or array property.

### Gotcha 5 — Result Field is Lowercase
CORRECT: | where Result == "success"
WRONG:   | where Result == "Success"
WRONG:   | where ActivityStatusValue =~ "Success"  // AzureActivity field, not AuditLogs

---

## Known Microsoft App IDs (for exclusions)
let KnownMicrosoftApps = dynamic([
    "cb1056e2-e479-49de-ae31-7812af012ed8",  // Azure AD Connect Sync
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",  // Microsoft Graph PowerShell
    "1950a258-227b-4e31-a9cf-717495945fc2",  // Microsoft Azure PowerShell
    "797f4846-ba00-4fd7-ba43-dac1f8f63013",  // Azure Resource Manager
    "00000002-0000-0000-c000-000000000000",  // Azure AD Graph (legacy)
    "00000003-0000-0000-c000-000000000000",  // Microsoft Graph
    "0000000c-0000-0000-c000-000000000000",  // Microsoft App Access Panel
    "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7",  // Office365 Shell WCSS-Client
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",  // Azure Portal
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   // Azure CLI
]);

---

## PowerShell Gotchas

### Gotcha 1 — -ApplicationId expects Object ID not display name
CORRECT:
$App = Get-MgApplication -Filter "displayName eq 'MyAppName'"
$App = Get-MgApplication -ApplicationId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
WRONG:
$App = Get-MgApplication -ApplicationId "MyAppName"

### Gotcha 2 — Credential removal requires individual KeyId iteration
CORRECT:
foreach ($Secret in $App.PasswordCredentials) {
    Remove-MgApplicationPassword -ApplicationId $App.Id -KeyId $Secret.KeyId
}
WRONG: Update-MgApplication -ApplicationId $App.Id -PasswordCredentials @()

### Gotcha 3 — Always include Connect-MgGraph in every script block
Connect-MgGraph -Scopes "Application.ReadWrite.All" -NoWelcome

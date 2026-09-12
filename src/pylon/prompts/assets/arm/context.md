

## Azure ARM — AzureActivity Schema Reference

You are building detections for Azure Resource Manager using the AzureActivity table in Microsoft Sentinel.

### Fields that EXIST in AzureActivity
- TimeGenerated
- OperationNameValue — resource provider format, uppercase: e.g. "MICROSOFT.KEYVAULT/VAULTS/WRITE" — use this for filtering with =~
- OperationName — human-readable display name — less reliable, do not use for filtering
- ActivityStatusValue — "Success", "Failure", "Start" — use =~ for case-insensitive matching
- ActivitySubstatusValue — additional status detail e.g. "Created", "Deleted", "OK"
- Caller — plain string: UPN for users (user@domain.com), object ID for service principals, "Microsoft Azure" for platform operations
- CallerIpAddress — plain string IP address
- ResourceId — full ARM resource ID path e.g. /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{resource}
- ResourceGroup — resource group name
- SubscriptionId
- ResourceProviderValue — e.g. "MICROSOFT.KEYVAULT"
- Properties — JSON blob with additional operation detail — extract with parse_json(Properties)
- Authorization — JSON blob with RBAC action, scope, evidence — extract with parse_json(Authorization)
- Claims — JSON blob with identity claims including appid, oid, upn — extract with parse_json(Claims)
- CorrelationId
- Category — "Administrative", "Policy", "Security", "ServiceHealth"
- Level — "Informational", "Warning", "Error", "Critical"

### Fields that DO NOT EXIST in AzureActivity (never use these)
- InitiatedBy → use Caller and CallerIpAddress (plain strings, no parsing needed)
- Result → use ActivityStatusValue
- TargetResources → AzureActivity is flat — use ResourceId, ResourceGroup, SubscriptionId
- UserPrincipalName → use Caller directly
- SourceIP → use CallerIpAddress directly

### Operation Name Format Rule
OperationNameValue is always in PROVIDER/RESOURCETYPE/ACTION format, uppercase.
Always filter with =~ for case-insensitive matching.

CORRECT:
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"

WRONG:
| where OperationName == "Microsoft.Authorization/roleAssignments/write"
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"

### parse_json Patterns
Properties blob:
| extend Props = parse_json(Properties)
| extend StatusCode = tostring(Props.statusCode)
| extend StatusMessage = tostring(Props.statusMessage)

Authorization blob:
| extend Auth = parse_json(Authorization)
| extend AuthAction = tostring(Auth.action)
| extend AuthScope = tostring(Auth.scope)

Claims blob:
| extend Clms = parse_json(Claims)
| extend CallerAppId = tostring(Clms.appid)
| extend CallerOID = tostring(Clms.oid)

### Detection Philosophy: AzureActivity Only
- Use AzureActivity for ALL Phase 2 ARM detections.
- AzureActivity does NOT capture read operations (GET).
- AzureActivity is always available and lower cost than resource-specific diagnostic logs.

### Anti-Fabrication Rules
- Only include attack vectors based on REAL, DOCUMENTED Azure Resource Manager operations
- Every OperationNameValue must be in exact PROVIDER/RESOURCETYPE/ACTION format
- Do NOT invent operations. If uncertain whether an operation is logged — omit it
- Do NOT include statistics, percentages, or frequency claims
- Do NOT write multi-step attack chains
- Do NOT attribute to APT groups without a specific cited source

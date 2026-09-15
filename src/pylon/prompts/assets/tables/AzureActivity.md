
## AzureActivity — Schema Reference & Parsing Guide

### Purpose
Records every Azure Resource Manager (ARM) operation — creates, updates, deletes
across all Azure resources. The management plane log.

### Key Fields
- TimeGenerated
- OperationNameValue — PROVIDER/RESOURCETYPE/ACTION format, uppercase
- OperationName — human-readable display name, unreliable for filtering
- ActivityStatusValue — "Success", "Failure", "Start"
- Caller — plain string: UPN for users, object ID for service principals
- CallerIpAddress — plain string IP
- ResourceId — full ARM resource ID
- ResourceGroup
- SubscriptionId
- Properties — JSON blob, extract with parse_json()
- Authorization — JSON blob with RBAC action and scope
- Claims — JSON blob with identity claims

### Fields That DO NOT Exist in AzureActivity
- InitiatedBy → use Caller and CallerIpAddress directly
- Result → use ActivityStatusValue
- TargetResources → use ResourceId, ResourceGroup, SubscriptionId
- UserPrincipalName → use Caller directly

### Known Gotchas
// Add gotchas here as you discover them during testing.
// Examples of what belongs here:
// - Field name mistakes the model consistently makes
// - Operator mistakes (== vs =~ etc.)
// - Parsing patterns that look right but break at runtime

### Confirmed Rules
- Filter on OperationNameValue not OperationName — OperationName is unreliable
- OperationNameValue must use =~ not == for case-insensitive matching
- ActivityStatusValue must use =~ not == 
- Caller and CallerIpAddress are plain strings — no tostring() needed
- No COLUMN here holds an array, so never mv-expand a column. A value parsed
  out of Properties can be an array and must be expanded: `mv-expand entry = Body.properties.logs`
- Time filter must be first operator after table name
- Let-statement queries must end with semicolon

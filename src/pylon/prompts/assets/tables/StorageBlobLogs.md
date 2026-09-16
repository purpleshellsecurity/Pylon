
## StorageBlobLogs — Schema Reference & Parsing Guide

### Purpose
Records blob-level read/write/delete operations on Azure Blob Storage.
Resource-specific table — preferred over AzureDiagnostics.

### Key Fields
- TimeGenerated
- OperationName — "GetBlob", "PutBlob", "DeleteBlob", "ListBlobs"
- StatusCode — STRING (not integer) — HTTP status code
- StatusText — "Success", "AnonymousSuccess", etc.
- AuthenticationType — "SAS", "OAuth", "AccountKey", "Anonymous"
- CallerIpAddress — source IP (lowercase p — not CallerIPAddress)
- Uri — full URI of the blob accessed
- ObjectKey — storage account/container/blob path
- UserAgentHeader — client user agent
- AccountName — storage account name
- ResponseBodySize — bytes returned
- RequesterObjectId — OAuth object ID of requester
- RequesterUpn — UPN of requester (OAuth only)
- RequesterAppId — OAuth application ID

### Fields That DO NOT Exist in StorageBlobLogs
- ResultType → use StatusCode or StatusText
- ActivityStatusValue → AzureActivity field
- OperationNameValue → AzureActivity field
- identity_s → AzureDiagnostics field. NOT an AZKVAuditLogs field either:
               the dedicated Key Vault table has a dynamic Identity column
- CallerIPAddress → that spelling is AzureDiagnostics — this table uses CallerIpAddress

### Known Gotchas
- `OperationCount` is NOT a count to sum. The docs define it as an INDEX starting
  at 0 for the operations within one request — a blob copy spans several — so
  `sum(OperationCount)` is a number with no meaning that nobody would question.
  `count()` over rows is the operation count.

### Confirmed Rules
- StatusCode is a STRING field — do not use numeric comparison
- CORRECT: | where StatusCode == "200"
- WRONG:   | where StatusCode >= 200
- Success filter: | where StatusCode == "200" or StatusText contains "Success"
- CallerIpAddress is lowercase p — not CallerIPAddress


## StorageQueueLogs — Schema Reference & Parsing Guide

### Purpose
Records message- and queue-level operations on Azure Queue Storage
(GetMessages/PeekMessages/PutMessage/ClearMessages, queue create/delete).
Resource-specific table — preferred over AzureDiagnostics.

### Key Fields
- TimeGenerated
- OperationName — "GetMessages", "PeekMessages", "PutMessage", "ClearMessages", "ListQueues"
- StatusCode — STRING (not integer) — HTTP status code
- StatusText — "Success", "SASSuccess", etc.
- AuthenticationType — "SAS", "OAuth", "AccountKey", "Anonymous"
- CallerIpAddress — source IP (lowercase p — not CallerIPAddress)
- Uri — full URI of the queue accessed
- ObjectKey — storage account/queue path
- UserAgentHeader — client user agent
- AccountName — storage account name
- ResponseBodySize — bytes returned
- RequesterObjectId — OAuth object ID of requester
- RequesterUpn — UPN of requester (OAuth only)
- RequesterAppId — OAuth application ID

### Fields That DO NOT Exist in StorageQueueLogs
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

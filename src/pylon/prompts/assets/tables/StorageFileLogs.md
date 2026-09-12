
## StorageFileLogs — Schema Reference & Parsing Guide

### Purpose
Records file-level read/write/delete operations on Azure Files (SMB and REST
file shares). Resource-specific table — preferred over AzureDiagnostics.

### Key Fields
- TimeGenerated
- OperationName — "GetFile", "PutRange", "CreateFile", "DeleteFile", "ListFiles", "ListShares"
- StatusCode — STRING (not integer) — HTTP status code
- StatusText — "Success", "SASSuccess", etc.
- AuthenticationType — "SAS", "OAuth", "AccountKey", "Anonymous"
- CallerIpAddress — source IP (lowercase p — not CallerIPAddress)
- Uri — full URI of the file/share accessed
- ObjectKey — storage account/share/directory/file path
- UserAgentHeader — client user agent
- AccountName — storage account name
- ResponseBodySize — bytes returned
- RequesterObjectId — OAuth object ID of requester
- RequesterUpn — UPN of requester (OAuth only)
- RequesterAppId — OAuth application ID

### Fields That DO NOT Exist in StorageFileLogs
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

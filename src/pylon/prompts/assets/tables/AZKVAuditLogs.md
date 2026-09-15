
## AZKVAuditLogs — Schema Reference & Parsing Guide

### Purpose
Records Key Vault data plane operations — authentication, and secret/key/certificate
access, creation and deletion. This is the DEDICATED (resource-specific) table,
selected by `logAnalyticsDestinationType: Dedicated` on the vault's diagnostic
setting. Its columns are NOT the ones Key Vault logs get in the shared
AzureDiagnostics table; see the section below.

### Key Fields
- TimeGenerated — datetime
- OperationName — string. Documented values include "Authentication", "VaultGet",
                  "VaultPut", "VaultPatch", "VaultDelete", "SecretGet", "SecretSet",
                  "SecretDelete", "SecretList", "SecretBackup", "SecretRestore",
                  "SecretPurge", "KeyGet", "KeyCreate", "KeySign", "KeyDecrypt",
                  "KeyEncrypt", "CertificateGet", "CertificateCreate"
- ResultType — string. Result of the REST API request
- ResultSignature — string. HTTP status of the request/response
- ResultDescription — string. Additional description, when available
- HttpStatusCode — INT. HTTP status code of the request
- CallerIpAddress — string. IP of the client that made the request (lowercase p)
- Identity — DYNAMIC. Identity from the token presented in the request: usually a
             user, a service principal, or user+appId
- Id — string. Resource identifier (key ID or secret ID)
- RequestUri — string. URI of the request
- ClientInfo — string. User agent information
- CorrelationId — string
- DurationMs — int. Time to service the request, in milliseconds
- IsRbacAuthorized / IsAccessPolicyMatch / IsAddressAuthorized — BOOL
- AppliedAssignmentId — string. Assignment that granted or denied access
- TrustedService — string. Null when the principal is not a trusted service
- SubnetId — string. Set when the request comes from a known subnet
- Tlsversion — string
- KeyProperties / SecretProperties / CertificateProperties / VaultProperties /
  NetworkAcls / Sku / Properties / Nsp — DYNAMIC property bags
- _ResourceId — string. ARM resource ID of the vault

### Fields That DO NOT Exist in AZKVAuditLogs
Everything in this list is the AzureDiagnostics spelling of the same data. Key
Vault logs routed to the SHARED AzureDiagnostics table get flattened, suffixed
columns; the dedicated table does not have them, and a query using them fails with
"Failed to resolve scalar expression". A model trained on AzureDiagnostics-era
examples will reach for these — do not.

- identity_s → use Identity (already dynamic; see Confirmed Rules)
- identity_claim_appid_g → use tostring(Identity.claim.appid)
- identity_claim_ipaddr_s → use tostring(Identity.claim.ipaddr), or CallerIpAddress
- id_s → use Id
- httpStatusCode_d → use HttpStatusCode (an int, not a real)
- clientInfo_s → use ClientInfo
- requestUri_s → use RequestUri
- CallerIPAddress → that spelling (capital IP) is AzureDiagnostics — this table
                    uses CallerIpAddress. KQL column names are case-sensitive
- InitiatedBy → use Identity
- ActivityStatusValue → AzureActivity field
- OperationNameValue → AzureActivity field; this table uses OperationName

### Known Gotchas
- Identity is DYNAMIC, not a JSON string. Do NOT call parse_json() on it — index
  it directly. Wrapping a dynamic value in parse_json() is not an error, but the
  extra call is noise and signals the AzureDiagnostics shape.
- ClientInfo is the USER AGENT. The name does not say so, so a query that wants
  the user agent for this table reaches for a column that does not exist, or
  concludes Key Vault has none and drops the field. It has one.
- HttpStatusCode is an INT. Compare numerically (>= 300), not as a string.
- "Authentication" with HttpStatusCode 401 is routine challenge/response, not a
  failure — Microsoft's own sample query excludes exactly that pair when counting
  failures.

### Confirmed Rules
- CORRECT:
  | extend CallerUPN   = tostring(Identity.claim.upn)
  | extend CallerAppId = tostring(Identity.claim.appid)
  | extend CallerOID   = tostring(Identity.claim.oid)
- WRONG: | extend CallerIdentity = parse_json(identity_s)     // AzureDiagnostics
- WRONG: | where CallerIPAddress == "1.2.3.4"                 // wrong case
- Failure filter: | where HttpStatusCode >= 300
- Use ResultType for the request outcome, not ActivityStatusValue

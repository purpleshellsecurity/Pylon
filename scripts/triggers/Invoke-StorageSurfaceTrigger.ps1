#Requires -Modules Az.Accounts, Az.Storage

<#
.SYNOPSIS
    Exercise the Storage data plane so the four Storage*Logs tables have rows.

.DESCRIPTION
    A lab storage account logs reads and nothing else, because browsing the
    portal is a read and nobody writes to it. Measured on this tenant: 106 rows
    in StorageBlobLogs over 30 days, every one of them StorageRead, and zero
    rows in the file, queue and table logs. A detection over StorageWrite or
    StorageDelete cannot be graded against that, so it ships unproven.

    This performs the write and delete half once, on all four services, so
    `pylon design record` can capture them and grade offline afterwards.

    Everything it touches, it creates. Every name carries a run stamp and
    nothing that existed before the run is read, modified or deleted.

    Per service, the operations it emits:
      blob    CreateContainer PutBlob GetBlob ListBlobs DeleteBlob DeleteContainer
      file    CreateShare CreateFile PutRange GetFile DeleteFile DeleteShare
      queue   CreateQueue PutMessage GetMessages DeleteMessage DeleteQueue
      table   CreateTable InsertEntity QueryEntities DeleteEntity DeleteTable

    NOT covered, and why:
      file services        the SMB data roles do not cover REST; see -Services
      SetContainerACL      changes public access; not something to script
      SAS operations       issuing a SAS is a control-plane listAccountSas
      Lifecycle / restore  needs policy and soft delete configured first

.PARAMETER AccountName
    A LAB storage account. Diagnostic settings must send StorageWrite and
    StorageDelete to the workspace, or the operations happen and nothing is
    logged. The `audit` category group covers all three; check with
    `az monitor diagnostic-settings list --resource <account>/blobServices/default`.

.PARAMETER Services
    Which services to exercise. Defaults to all four.

.PARAMETER Execute
    Required. Without it the script prints what it would do and exits.

.PARAMETER KeepObjects
    Leave the created objects behind instead of deleting them. Off by default,
    and leaving them on means the delete operations are never emitted.

.EXAMPLE
    ./Invoke-StorageSurfaceTrigger.ps1 -AccountName mylabstorage -Execute
    # wait ~5 minutes for ingestion, then:
    pylon design record --from ./blob --workspace my-workspace --out fixtures/
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AccountName,
    # `file` is NOT in the default. The only file data-plane roles most tenants
    # are offered are the three SMB ones, and SMB roles do not authorize the
    # REST calls these cmdlets make -- so the operations 403 and no row is
    # written. Emitting file rows over REST needs Storage File Data Privileged
    # Contributor, which is a different and less commonly granted role.
    [ValidateSet('blob', 'file', 'queue', 'table')]
    [string[]]$Services = @('blob', 'queue', 'table'),
    [switch]$Execute,
    [switch]$KeepObjects
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
# Storage names are lowercase alphanumeric with a 3-63 length; a stamp with
# 'T' and 'Z' in it is rejected by container and share names, so strip to digits.
$suffix   = ($stamp -replace '[^0-9]', '')
$container = "pylon-trigger-$suffix"
$share     = "pylon-trigger-$suffix"
$queue     = "pylon-trigger-$suffix"
$tableName = "pylontrigger$suffix"

Write-Host "TRIGGER  Storage data plane / $($Services -join ', ')"
Write-Host "  account   $AccountName"
Write-Host "  objects   $container (blob/file/queue), $tableName (table)"

if (-not $Execute) {
    Write-Host "`nDRY RUN. Re-run with -Execute to emit the events." -ForegroundColor Yellow
    return
}

# OAuth, not account keys. Measured on this tenant: of 61 storage rows, the 5
# written with AuthenticationType "OAuth" carry RequesterObjectId and the other
# 56 -- TrustedAccess, SAS, AnonymousPreflight -- carry nothing. So the auth
# type is what decides whether a row can answer "who", and a key-based context
# produces rows no detection can attribute.
# -EnableFileBackupRequestIntent is required for the FILE service specifically.
# Azure Files rejects an OAuth request without the x-ms-file-request-intent
# header with 400 MissingRequiredHeader, so without this the share is created
# and every operation inside it fails. It is harmless for blob, queue and table.
$ctx = New-AzStorageContext -StorageAccountName $AccountName -UseConnectedAccount `
    -EnableFileBackupRequestIntent

$created = [System.Collections.ArrayList]::new()
function Note($what, $name) { [void]$created.Add(@{ What = $what; Name = $name }) }

try {
    if ($Services -contains 'blob') {
        Write-Host "`n  BLOB"
        New-AzStorageContainer -Name $container -Context $ctx | Out-Null
        Note 'container' $container; Write-Host "    CreateContainer  $container"

        $tmp = New-TemporaryFile
        "pylon trigger $stamp" | Set-Content -Path $tmp -Encoding utf8
        Set-AzStorageBlobContent -File $tmp -Container $container -Blob 'probe.txt' `
            -Context $ctx -Force | Out-Null
        Write-Host "    PutBlob          probe.txt"
        Get-AzStorageBlobContent -Container $container -Blob 'probe.txt' `
            -Destination "$tmp.out" -Context $ctx -Force | Out-Null
        Write-Host "    GetBlob"
        Get-AzStorageBlob -Container $container -Context $ctx | Out-Null
        Write-Host "    ListBlobs"
        # Deleting the container deletes the blob with it and emits only
        # DeleteContainer. DeleteBlob is the far more common event, so remove
        # the blob explicitly first.
        Remove-AzStorageBlob -Container $container -Blob 'probe.txt' -Context $ctx -Force
        Write-Host "    DeleteBlob"
        Remove-Item $tmp, "$tmp.out" -Force -ErrorAction SilentlyContinue
    }

    if ($Services -contains 'file') {
        Write-Host "`n  FILE"
        New-AzStorageShare -Name $share -Context $ctx | Out-Null
        Note 'share' $share; Write-Host "    CreateShare      $share"

        $tmp = New-TemporaryFile
        "pylon trigger $stamp" | Set-Content -Path $tmp -Encoding utf8
        Set-AzStorageFileContent -ShareName $share -Source $tmp -Path 'probe.txt' `
            -Context $ctx -Force | Out-Null
        Write-Host "    CreateFile/PutRange  probe.txt"
        Get-AzStorageFile -ShareName $share -Context $ctx | Out-Null
        Write-Host "    ListFiles"
        # Same reason as DeleteBlob: removing the share would emit DeleteShare
        # only, and DeleteFile is the event a detection actually looks for.
        Remove-AzStorageFile -ShareName $share -Path 'probe.txt' -Context $ctx
        Write-Host "    DeleteFile"
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }

    if ($Services -contains 'queue') {
        Write-Host "`n  QUEUE"
        $q = New-AzStorageQueue -Name $queue -Context $ctx
        Note 'queue' $queue; Write-Host "    CreateQueue      $queue"

        # The Az module returns the v12 SDK client; PutMessage and GetMessages
        # go through it rather than through a cmdlet, which does not exist.
        $q.QueueClient.SendMessage("pylon trigger $stamp") | Out-Null
        Write-Host "    PutMessage"
        $msgs = $q.QueueClient.ReceiveMessages(1)
        Write-Host "    GetMessages"
        foreach ($m in $msgs.Value) {
            $q.QueueClient.DeleteMessage($m.MessageId, $m.PopReceipt) | Out-Null
            Write-Host "    DeleteMessage"
        }
    }

    if ($Services -contains 'table') {
        Write-Host "`n  TABLE"
        $t = New-AzStorageTable -Name $tableName -Context $ctx
        Note 'table' $tableName; Write-Host "    CreateTable      $tableName"

        # TableClient hangs off the returned object itself, NOT off .Context.
        $client = $t.TableClient
        $entity = [Azure.Data.Tables.TableEntity]::new('pylon', $suffix)
        $entity['Note'] = 'trigger'
        # AddEntity is generic, so PowerShell needs the type argument spelled out.
        $client.AddEntity[Azure.Data.Tables.TableEntity]($entity) | Out-Null
        Write-Host "    InsertEntity"
        # Query returns a lazy Pageable: nothing is sent until it is enumerated,
        # so without the @() this emits no QueryEntities event at all.
        $found = @($client.Query[Azure.Data.Tables.TableEntity]("PartitionKey eq 'pylon'"))
        Write-Host "    QueryEntities    ($(@($found).Count) entity/entities)"
        $client.DeleteEntity('pylon', $suffix) | Out-Null
        Write-Host "    DeleteEntity"
    }
}
finally {
    if ($KeepObjects) {
        Write-Warning "-KeepObjects set: no delete operations were emitted, and these remain:"
        foreach ($c in $created) { Write-Warning "  $($c.What) $($c.Name)" }
    }
    else {
        Write-Host "`n  CLEANUP  (these are the StorageDelete events)"
        foreach ($c in $created) {
            try {
                switch ($c.What) {
                    'container' { Remove-AzStorageContainer -Name $c.Name -Context $ctx -Force }
                    'share'     { Remove-AzStorageShare -Name $c.Name -Context $ctx -Force }
                    'queue'     { Remove-AzStorageQueue -Name $c.Name -Context $ctx -Force }
                    'table'     { Remove-AzStorageTable -Name $c.Name -Context $ctx -Force }
                }
                Write-Host "    deleted $($c.What) $($c.Name)"
            }
            catch {
                # Say what is left behind and how to remove it. A cleanup that
                # fails silently leaves litter nobody knows to look for.
                Write-Warning "could not delete $($c.What) '$($c.Name)': $($_.Exception.Message)"
            }
        }
    }
    Write-Host "`n  ingestion lag is about 5 minutes before these rows are queryable"
}

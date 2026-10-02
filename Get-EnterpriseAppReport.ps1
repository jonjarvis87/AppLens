<#
.SYNOPSIS
    AppLens by CloudEndpoint.ai — Enterprise App Insight for Microsoft 365.
    CloudEndpoint.ai branded edition.
    Generates an HTML report of all Enterprise Applications in a Microsoft 365 tenant
    with staleness, credential health, SSO configuration, SAML cert health, provisioning
    status, ownership, assignments, permissions, and a combined risk score.

.DESCRIPTION
    Pulls for each enterprise app:
      - Sign-in activity (delegated + app-only, client + resource)
      - SSO mode (SAML / Password / OIDC / None)
      - SAML signing certificate expiry (separate from API credentials)
      - Provisioning (SCIM) health for apps like Salesforce, Workday, ServiceNow
      - Notification email presence (for SAML cert expiry alerts)
      - API credential status (secrets & non-SAML certs; rotation-aware)
      - Owner count, assigned users/groups count, app-only permission count
      - Legacy API exposure: EWS (being switched off) and retired Azure AD Graph
      - Entra Agent ID identities (accountable via sponsors, not owners)
    Combines all signals into a 0-100 risk score and writes a styled HTML report.

.PARAMETER OutputPath
    File path for the generated HTML report.

.PARAMETER IncludeMicrosoftApps
    Include first-party Microsoft applications. Off by default.

.PARAMETER TenantId
    Optional tenant ID. If omitted, Connect-MgGraph will prompt.

.PARAMETER SkipDetailedAnalysis
    Skip the per-SP batched calls (owners, assignments, permissions, provisioning).

.NOTES
    Permissions: Application.Read.All, AuditLog.Read.All, Directory.Read.All,
                 Synchronization.Read.All (for provisioning jobs)
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$IncludeMicrosoftApps,
    [string]$TenantId,
    [switch]$SkipDetailedAnalysis,
    # How many days back to query the live sign-in log (auditLogs/signIns) to
    # supplement the activity report. Max 30 (Entra ID retention limit on free
    # SKUs; P1/P2 retain longer but 30 is the safe default).
    [ValidateRange(1, 30)]
    [int]$SignInLogDays = 30,

    # ---- Azure Automation / scheduled-run params ----
    # Send the report as an email attachment via Graph SendMail. Set -SenderUpn
    # to the mailbox that sends (Mail.Send permission required on that mailbox)
    # and -RecipientUpns to the admin distribution list.
    [switch]$SendEmail,
    [string]$SenderUpn,
    [string[]]$RecipientUpns,

    # Where the month-over-month snapshot JSON lives for interactive runs.
    # In Azure Automation the snapshot is stored in an Automation Variable
    # ('AppLens-Snapshot') instead, so this is ignored there.
    [string]$SnapshotPath
)

$ErrorActionPreference = 'Stop'

# Detect Azure Automation runtime so we can switch auth + skip interactive bits.
$inAutomation = [bool]($PSPrivateMetadata.JobId.Guid)

# Resolve OutputPath default based on environment.
if (-not $OutputPath) {
    $rootDir  = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
    $filename = if ($inAutomation) { "AppLens-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html" } else { 'AppLens-Report.html' }
    $OutputPath = Join-Path $rootDir $filename
}

# ---------------------------------------------------------------------------
# Brand banner
# ---------------------------------------------------------------------------
$brandName     = 'AppLens by CloudEndpoint.ai'
$brandTagline  = 'Enterprise App Insight for Microsoft 365'
$brandPunchline = 'cloudendpoint.ai'
$brandVersion  = '1.3'

if ($inAutomation) {
    Write-Output "==> $brandName v$brandVersion — $brandTagline"
} else {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║  " -NoNewline -ForegroundColor DarkCyan
    Write-Host ("{0,-46}" -f $brandName) -NoNewline -ForegroundColor White
    Write-Host "  ║" -ForegroundColor DarkCyan
    Write-Host "  ║  " -NoNewline -ForegroundColor DarkCyan
    Write-Host ("{0,-46}" -f $brandTagline) -NoNewline -ForegroundColor Gray
    Write-Host "  ║" -ForegroundColor DarkCyan
    Write-Host "  ║  " -NoNewline -ForegroundColor DarkCyan
    Write-Host ("{0,-46}" -f $brandPunchline) -NoNewline -ForegroundColor DarkGray
    Write-Host "  ║" -ForegroundColor DarkCyan
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    Write-Host ""
}

# ---------------------------------------------------------------------------
# 0. Run telemetry, resilient Graph helpers, and failure alerting
#    Every Graph call goes through Invoke-GraphWithRetry (429/5xx retry with
#    Retry-After honouring). $batch inner item failures are retried separately
#    — the SDK only retries at the HTTP level, not per batch item.
# ---------------------------------------------------------------------------
$swTotal = [System.Diagnostics.Stopwatch]::StartNew()
$telemetry = [ordered]@{
    Throttles       = 0
    Retries         = 0
    ActivityReport  = @{ Status = 'NotRun'; Records = 0 }
    SignInLogs      = [ordered]@{}   # label -> @{ Events; Pages; Truncated; Status }
    AuditLog        = @{ Status = 'NotRun'; Events = 0; Pages = 0; Truncated = $false }
    DetailBatches   = @{ Total = 0; InnerFailures = 0; Recovered = 0 }
    AppRegs         = @{ Status = 'NotRun'; Count = 0 }
    DelegatedGrants = @{ Status = 'NotRun'; Count = 0 }
}

function Invoke-GraphWithRetry {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        $Body = $null,
        [string]$ContentType = 'application/json',
        [int]$MaxAttempts = 5
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            if ($null -ne $Body) {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -ContentType $ContentType
            }
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri
        } catch {
            $status = 0
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            if ($status -notin 429, 500, 502, 503, 504 -or $attempt -ge $MaxAttempts) { throw }
            $delay = [Math]::Min(60, [Math]::Pow(2, $attempt))
            try {
                $ra = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                if ($ra -gt 0) { $delay = [Math]::Min(120, [Math]::Max($ra, 1)) }
            } catch { }
            if ($status -eq 429) { $telemetry.Throttles++ } else { $telemetry.Retries++ }
            Start-Sleep -Seconds $delay
        }
    }
}

# Runs a set of $batch requests, retrying inner 429/5xx items up to MaxRounds.
# Returns hashtable: request id -> final response (success OR permanent failure
# — callers check .status so 'lookup failed' can be told apart from 'empty').
function Invoke-GraphBatchWithRetry {
    param([Parameter(Mandatory)][array]$Requests, [int]$MaxRounds = 3)
    $final = @{}
    $pending = $Requests
    for ($round = 1; $round -le $MaxRounds -and $pending.Count -gt 0; $round++) {
        if ($round -gt 1) { Start-Sleep -Seconds ([Math]::Pow(2, $round)) }
        $body = @{ requests = @($pending) } | ConvertTo-Json -Depth 5 -Compress
        $resp = Invoke-GraphWithRetry -Method POST -Uri 'https://graph.microsoft.com/v1.0/$batch' -Body $body
        $retry = @()
        foreach ($r in $resp.responses) {
            $rid = [string]$r.id
            $final[$rid] = $r
            if ($r.status -in 429, 500, 502, 503, 504) {
                if ($round -lt $MaxRounds) { $retry += @($pending | Where-Object { [string]$_.id -eq $rid }) }
                if ($r.status -eq 429) { $telemetry.Throttles++ }
            } elseif ($r.status -ge 200 -and $r.status -lt 300 -and $round -gt 1) {
                $telemetry.DetailBatches.Recovered++
            }
        }
        $pending = $retry
    }
    $telemetry.DetailBatches.InnerFailures += @($final.Values | Where-Object { $_.status -in 429, 500, 502, 503, 504 }).Count
    return $final
}

# If the run dies anywhere past this point, best-effort email the admins so a
# broken month doesn't go unnoticed, then rethrow so the job shows Failed.
function Send-RunFailureAlert {
    param($ErrorRecord)
    try {
        if (-not $SendEmail -or -not $SenderUpn -or -not $RecipientUpns) { return }
        if (-not (Get-MgContext)) { return }
        $jobId = if ($inAutomation) { $PSPrivateMetadata.JobId.Guid } else { 'interactive run' }
        $alertText = "The scheduled report run failed.`n`nError: $($ErrorRecord.Exception.Message)`n`nAt: $($ErrorRecord.InvocationInfo.PositionMessage)`n`nJob: $jobId`n`nCheck the Automation job output for details."
        $alertBody = @{
            message = @{
                subject      = "$brandName — RUN FAILED $((Get-Date).ToString('yyyy-MM-dd HH:mm'))"
                body         = @{ contentType = 'Text'; content = $alertText }
                toRecipients = @($RecipientUpns | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
            }
            saveToSentItems = $true
        } | ConvertTo-Json -Depth 10
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$SenderUpn/sendMail" `
            -Body $alertBody -ContentType 'application/json'
        Write-Output "Failure alert email sent to $($RecipientUpns -join ', ')."
    } catch {
        Write-Warning "Could not send failure alert: $($_.Exception.Message)"
    }
}

trap {
    Write-Output "FATAL: $($_.Exception.Message)"
    Write-Output "AT: $($_.InvocationInfo.PositionMessage)"
    Send-RunFailureAlert -ErrorRecord $_
    break
}

# ---------------------------------------------------------------------------
# 1. Module management
# ---------------------------------------------------------------------------
$requiredModules = @('Microsoft.Graph.Authentication','Microsoft.Graph.Applications','Microsoft.Graph.Reports')

function Get-HighestInstalledVersion {
    param([string]$Name)
    Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1 -ExpandProperty Version
}

if ($inAutomation) {
    # In Azure Automation modules are pre-installed via the portal. Just import.
    Write-Output "Importing Microsoft Graph modules (Azure Automation runtime)..."
    foreach ($name in $requiredModules) {
        Import-Module $name -ErrorAction Stop
    }
} else {
    Write-Host "Checking Microsoft Graph modules..." -ForegroundColor Cyan

    $loadedGraph = Get-Module | Where-Object { $_.Name -like 'Microsoft.Graph*' }
    foreach ($lm in $loadedGraph) {
        $highest = Get-HighestInstalledVersion -Name $lm.Name
        if ($highest -and $lm.Version -lt $highest) {
            Write-Host ""
            Write-Host "ERROR: $($lm.Name) v$($lm.Version) is loaded but v$highest is installed." -ForegroundColor Red
            Write-Host "Fix: Close this PowerShell window completely, open a fresh one, and re-run." -ForegroundColor Yellow
            exit 1
        }
    }

    $authVersion = Get-HighestInstalledVersion -Name 'Microsoft.Graph.Authentication'
    foreach ($name in $requiredModules) {
        $installed = Get-HighestInstalledVersion -Name $name
        if (-not $installed) {
            Write-Host "Installing $name..." -ForegroundColor Yellow
            if ($authVersion) {
                Install-Module -Name $name -RequiredVersion $authVersion -Scope CurrentUser -Force -AllowClobber
            } else {
                Install-Module -Name $name -Scope CurrentUser -Force -AllowClobber
                $authVersion = Get-HighestInstalledVersion -Name $name
            }
        } elseif ($authVersion -and $installed -ne $authVersion) {
            Write-Host "Aligning $name from v$installed to v$authVersion..." -ForegroundColor Yellow
            Install-Module -Name $name -RequiredVersion $authVersion -Scope CurrentUser -Force -AllowClobber
        }
    }
    foreach ($name in $requiredModules) {
        Import-Module $name -RequiredVersion (Get-HighestInstalledVersion -Name $name) -ErrorAction Stop
    }
}

# ---------------------------------------------------------------------------
# 2. Connect
# ---------------------------------------------------------------------------
$scopes = @('Application.Read.All','AuditLog.Read.All','Directory.Read.All','Synchronization.Read.All')
if ($SendEmail) { $scopes += 'Mail.Send' }

if ($inAutomation) {
    Write-Output "Connecting to Microsoft Graph (Managed Identity)..."
    Connect-MgGraph -Identity -NoWelcome | Out-Null
} else {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    if ($TenantId) {
        Connect-MgGraph -Scopes $scopes -TenantId $TenantId -NoWelcome | Out-Null
    } else {
        Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
    }
}
$context = Get-MgContext
$connectedMsg = "Connected to tenant: $($context.TenantId) ($($context.Account))"
if ($inAutomation) { Write-Output $connectedMsg } else { Write-Host $connectedMsg -ForegroundColor Green }

# Friendly tenant name for the report header (falls back to the GUID).
$tenantName = $context.TenantId
try {
    $org = Invoke-GraphWithRetry -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName'
    if ($org.value -and $org.value[0].displayName) { $tenantName = $org.value[0].displayName }
} catch { }

# ---------------------------------------------------------------------------
# 3. Fetch service principals (incl. SSO + notification email props)
# ---------------------------------------------------------------------------
Write-Host "Fetching service principals (enterprise apps)..." -ForegroundColor Cyan
$spParams = @{
    All      = $true
    Property = 'id,appId,displayName,accountEnabled,createdDateTime,publisherName,verifiedPublisher,appOwnerOrganizationId,servicePrincipalType,signInAudience,tags,homepage,passwordCredentials,keyCredentials,preferredSingleSignOnMode,preferredTokenSigningKeyThumbprint,notificationEmailAddresses,appRoleAssignmentRequired'
}
$servicePrincipals = Get-MgServicePrincipal @spParams

# Resource SPs behind legacy APIs, captured before the Microsoft filter below
# drops them: permissions granted against these are flagged in the report.
$legacyResourceAppIds = @{
    '00000002-0000-0ff1-ce00-000000000000' = 'Exchange'   # Office 365 Exchange Online (EWS)
    '00000002-0000-0000-c000-000000000000' = 'AADGraph'   # Windows Azure Active Directory (retired Aug 2025)
}
$legacyResourceMap = @{}   # resource SP object id -> 'Exchange' | 'AADGraph'
foreach ($s in $servicePrincipals) {
    $kind = $legacyResourceAppIds[[string]$s.AppId]
    if ($kind) { $legacyResourceMap[[string]$s.Id] = $kind }
}

if (-not $IncludeMicrosoftApps) {
    # First-party apps are owned by either the Microsoft Services tenant or the
    # Microsoft corporate tenant (Graph Explorer, Graph PowerShell, Intune
    # PowerShell and friends live in the latter).
    $msftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
    $servicePrincipals = $servicePrincipals | Where-Object {
        [string]$_.AppOwnerOrganizationId -notin $msftTenants -and
        $_.ServicePrincipalType -ne 'ManagedIdentity'
    }
}
Write-Host ("  {0} apps to report on" -f $servicePrincipals.Count) -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Sign-in activity report
# ---------------------------------------------------------------------------
Write-Host "Fetching service principal sign-in activity..." -ForegroundColor Cyan
$activityMap = @{}
try {
    $uri = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=999'
    do {
        $resp = Invoke-GraphWithRetry -Uri $uri
        foreach ($entry in $resp.value) {
            if ($entry.appId) { $activityMap[$entry.appId] = $entry }
        }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    $telemetry.ActivityReport = @{ Status = 'OK'; Records = $activityMap.Count }
    Write-Host ("  {0} activity records retrieved" -f $activityMap.Count) -ForegroundColor Green
} catch {
    $telemetry.ActivityReport = @{ Status = 'Failed'; Records = 0 }
    Write-Warning "Could not fetch sign-in activity (requires Entra ID P1/P2)."
    Write-Warning $_.Exception.Message
}

# ---------------------------------------------------------------------------
# 4b. Cross-reference with auditLogs/signIns — the activity report can lag by
#     up to 48h and occasionally misses sign-in types. We pull FOUR event
#     streams: interactive (v1.0 default), non-interactive (token refreshes —
#     how most SSO usage actually appears), service principal credential
#     sign-ins, and managed identity (only when -IncludeMicrosoftApps).
#     All queries are ordered newest-first so page-cap truncation only ever
#     drops the OLDEST events.
# ---------------------------------------------------------------------------
$signInData = @{}   # appId -> @{ LastSignIn; UserIds (HashSet); UserSample (first 10 UPNs) }
$cutoff = (Get-Date).ToUniversalTime().AddDays(-$SignInLogDays).ToString('yyyy-MM-ddTHH:mm:ssZ')

# No explicit $orderby — signIns returns newest-first by default, and Graph's
# own nextLink generation 400s ('Unsupported Query') when $orderby is combined
# with signInEventTypes filters past page 1.
$siSelect = '$select=appId,appDisplayName,createdDateTime,userId,userPrincipalName'

function Get-SignInUri {
    param([string]$Version, [string]$EventFilter, [string]$Before)
    $f = "createdDateTime ge $cutoff"
    if ($Before)      { $f += " and createdDateTime lt $Before" }
    if ($EventFilter) { $f += " and $EventFilter" }
    "https://graph.microsoft.com/$Version/auditLogs/signIns?`$filter=$f&$siSelect&`$top=999"
}

function Add-SignInEvents {
    param([string]$Label, [string]$Version = 'beta', [string]$EventFilter, [int]$MaxPages)
    $stat = @{ Events = 0; Pages = 0; Truncated = $false; Resumed = 0; Status = 'OK' }
    $oldest = $null   # oldest createdDateTime seen so far (UTC, filter format)
    try {
        $next = Get-SignInUri -Version $Version -EventFilter $EventFilter
        while ($next) {
            try {
                $resp = Invoke-GraphWithRetry -Uri $next
            } catch {
                # Graph beta sometimes generates broken nextLinks for event-type
                # filters. Results are newest-first, so resume with a fresh query
                # bounded by the oldest event already seen (keyset paging)
                # rather than losing the rest of the window.
                if (-not $oldest -or $stat.Resumed -ge 10) { throw }
                $stat.Resumed++
                $resp = Invoke-GraphWithRetry -Uri (Get-SignInUri -Version $Version -EventFilter $EventFilter -Before $oldest)
            }
            $stat.Pages++
            $pageOldest = $null
            foreach ($e in $resp.value) {
                if (-not $e.appId) { continue }
                $stat.Events++
                if (-not $signInData.ContainsKey($e.appId)) {
                    $signInData[$e.appId] = @{
                        LastSignIn = $null
                        UserIds    = [System.Collections.Generic.HashSet[string]]::new()
                        UserSample = New-Object System.Collections.Generic.List[string]
                    }
                }
                $entry = $signInData[$e.appId]
                $when  = [datetime]$e.createdDateTime
                if (-not $entry.LastSignIn -or $when -gt $entry.LastSignIn) { $entry.LastSignIn = $when }
                if (-not $pageOldest -or $when -lt $pageOldest) { $pageOldest = $when }
                if ($e.userId) {
                    $isNew = $entry.UserIds.Add($e.userId)
                    if ($isNew -and $entry.UserSample.Count -lt 10 -and $e.userPrincipalName) {
                        [void]$entry.UserSample.Add($e.userPrincipalName)
                    }
                }
            }
            if ($pageOldest) {
                $u = if ($pageOldest.Kind -eq 'Unspecified') { [datetime]::SpecifyKind($pageOldest, 'Utc') } else { $pageOldest.ToUniversalTime() }
                $oldest = $u.ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            $next = $resp.'@odata.nextLink'
            if ($stat.Pages -ge $MaxPages -and $next) {
                $stat.Truncated = $true
                Write-Warning "$Label sign-ins truncated at $MaxPages pages (newest events kept — query is ordered desc)."
                break
            }
        }
    } catch {
        if ($stat.Events -gt 0) {
            # Resume attempts exhausted mid-window. Events collected so far are
            # the NEWEST ones — keep them and report the stream as partial.
            $stat.Truncated = $true
            Write-Warning "$Label sign-ins: pagination stopped after $($stat.Events) events (newest kept) — $($_.Exception.Message)"
        } else {
            $stat.Status = 'Failed'
            Write-Warning "$Label sign-in query failed: $($_.Exception.Message)"
        }
    }
    $telemetry.SignInLogs[$Label] = $stat
}

Write-Host ("Fetching sign-in logs (last {0} days; interactive, non-interactive, service principal)..." -f $SignInLogDays) -ForegroundColor Cyan
Add-SignInEvents -Label 'Interactive' -Version 'v1.0' -MaxPages 60
Add-SignInEvents -Label 'Non-interactive' -MaxPages 60 -EventFilter "signInEventTypes/any(t: t eq 'nonInteractiveUser')"
Add-SignInEvents -Label 'Service principal' -MaxPages 40 -EventFilter "signInEventTypes/any(t: t eq 'servicePrincipal')"
if ($IncludeMicrosoftApps) {
    Add-SignInEvents -Label 'Managed identity' -MaxPages 20 -EventFilter "signInEventTypes/any(t: t eq 'managedIdentity')"
}
Write-Host ("  {0} unique apps had sign-ins in the last {1} days" -f $signInData.Count, $SignInLogDays) -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Per-SP detail via Graph $batch
#    Each SP gets 4 requests: owners, appRoleAssignedTo, appRoleAssignments,
#    synchronization/jobs. 5 SPs × 4 requests = 20 (Graph batch limit).
# ---------------------------------------------------------------------------
$detailMap = @{}
foreach ($sp in $servicePrincipals) {
    $detailMap[$sp.Id] = [pscustomobject]@{
        Owners        = @();  OwnersKnown   = $false
        AssignedCount = 0;    AssignedKnown = $false
        AppPerms      = @();  PermsKnown    = $false
        ProvJobs      = @();  ProvKnown     = $false
    }
}

if (-not $SkipDetailedAnalysis) {
    Write-Host "Fetching per-app details (owners, assignments, permissions, provisioning)..." -ForegroundColor Cyan
    $batchSize = 5
    $batches = [Math]::Ceiling($servicePrincipals.Count / $batchSize)
    $batchIdx = 0
    for ($i = 0; $i -lt $servicePrincipals.Count; $i += $batchSize) {
        $batchIdx++
        $chunk = $servicePrincipals[$i..([Math]::Min($i + $batchSize - 1, $servicePrincipals.Count - 1))]
        $requests = @()
        for ($j = 0; $j -lt $chunk.Count; $j++) {
            $spId = $chunk[$j].Id
            $requests += @{ id = "$j-o"; method = 'GET'; url = "/servicePrincipals/$spId/owners?`$select=id,displayName,userPrincipalName&`$top=20" }
            $requests += @{ id = "$j-a"; method = 'GET'; url = "/servicePrincipals/$spId/appRoleAssignedTo?`$select=id&`$top=999" }
            $requests += @{ id = "$j-p"; method = 'GET'; url = "/servicePrincipals/$spId/appRoleAssignments?`$select=appRoleId,resourceId,resourceDisplayName&`$top=100" }
            $requests += @{ id = "$j-s"; method = 'GET'; url = "/servicePrincipals/$spId/synchronization/jobs" }
        }
        $telemetry.DetailBatches.Total++
        try {
            $results = Invoke-GraphBatchWithRetry -Requests $requests
            foreach ($key in $results.Keys) {
                $r = $results[$key]
                $parts = $key -split '-'
                $idx = [int]$parts[0]; $type = $parts[1]
                $spId = $chunk[$idx].Id
                if ($r.status -ge 200 -and $r.status -lt 300) {
                    $val = $r.body.value
                    switch ($type) {
                        'o' { $detailMap[$spId].Owners        = @($val | ForEach-Object { if ($_.displayName) { $_.displayName } else { $_.userPrincipalName } }); $detailMap[$spId].OwnersKnown = $true }
                        'a' { $detailMap[$spId].AssignedCount = @($val).Count; $detailMap[$spId].AssignedKnown = $true }
                        'p' { $detailMap[$spId].AppPerms      = @($val); $detailMap[$spId].PermsKnown = $true }
                        's' { $detailMap[$spId].ProvJobs      = @($val); $detailMap[$spId].ProvKnown = $true }
                    }
                } elseif ($type -eq 's' -and $r.status -ge 400 -and $r.status -lt 500 -and $r.status -ne 429) {
                    # 4xx on /synchronization/jobs = provisioning not applicable for
                    # this SP type — that's a known-empty, not a data gap.
                    $detailMap[$spId].ProvKnown = $true
                }
                # All other non-2xx outcomes stay flagged unknown — the report
                # shows '?' and risk scoring skips them rather than treating a
                # failed lookup as 'zero owners'.
            }
        } catch {
            Write-Warning "Batch $batchIdx failed after retries: $($_.Exception.Message)"
        }
        Write-Progress -Activity "Per-app details" -Status "Batch $batchIdx of $batches" -PercentComplete (($batchIdx / $batches) * 100)
    }
    Write-Progress -Activity "Per-app details" -Completed
    Write-Host "  done" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5b. Resolve appRoleId GUIDs to permission names (e.g. Mail.ReadWrite).
#     We fetch the appRoles definitions of each distinct resource SP that
#     permissions were granted against (Microsoft Graph, SharePoint, etc.).
# ---------------------------------------------------------------------------
$roleNameMap = @{}   # resourceId -> @{ appRoleId -> permission value }
$resourceIds = @($detailMap.Values | ForEach-Object { $_.AppPerms } |
    ForEach-Object { $_.resourceId } | Where-Object { $_ } | Select-Object -Unique)
if ($resourceIds.Count -gt 0) {
    Write-Host "Resolving permission names ($($resourceIds.Count) resource apps)..." -ForegroundColor Cyan
    for ($i = 0; $i -lt $resourceIds.Count; $i += 20) {
        $chunk = @($resourceIds[$i..([Math]::Min($i + 19, $resourceIds.Count - 1))])
        $requests = @()
        for ($j = 0; $j -lt $chunk.Count; $j++) {
            $requests += @{ id = "$j"; method = 'GET'; url = "/servicePrincipals/$($chunk[$j])?`$select=id,appRoles" }
        }
        try {
            $results = Invoke-GraphBatchWithRetry -Requests $requests
            foreach ($key in $results.Keys) {
                $r = $results[$key]
                if ($r.status -ge 200 -and $r.status -lt 300 -and $r.body.id) {
                    $m = @{}
                    foreach ($role in @($r.body.appRoles)) { $m[[string]$role.id] = [string]$role.value }
                    $roleNameMap[[string]$r.body.id] = $m
                }
            }
        } catch {
            Write-Warning "Permission name resolution batch failed: $($_.Exception.Message)"
        }
    }
}

# App-only permissions that warrant a red flag when held by a stale/unmanaged app.
# The same list doubles for delegated scopes — the names largely overlap.
$dangerousPermList = @(
    'Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory','AppRoleAssignment.ReadWrite.All',
    'Application.ReadWrite.All','Mail.ReadWrite','Mail.Send','Files.ReadWrite.All','Sites.FullControl.All',
    'Sites.ReadWrite.All','User.ReadWrite.All','Group.ReadWrite.All','GroupMember.ReadWrite.All',
    'Exchange.ManageAsApp','full_access_as_app','MailboxSettings.ReadWrite',
    'Policy.ReadWrite.ConditionalAccess','UserAuthenticationMethod.ReadWrite.All'
)

# Exchange Web Services permissions (app-only and delegated). Exchange Online
# starts switching EWS off in October 2026 and removes it in April 2027.
$ewsPermList = @('full_access_as_app', 'EWS.AccessAsApp', 'EWS.AccessAsUser.All')

# ---------------------------------------------------------------------------
# 5c. Delegated permission grants (oauth2PermissionGrants) — the other half of
#     the permission picture: consented scopes used on behalf of signed-in
#     users. AllPrincipals = admin-consented for everyone in the tenant.
# ---------------------------------------------------------------------------
$grantMap = @{}   # SP object id (clientId) -> list of grants
try {
    Write-Host "Fetching delegated permission grants..." -ForegroundColor Cyan
    $uri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
    $grantCount = 0
    do {
        $resp = Invoke-GraphWithRetry -Uri $uri
        foreach ($g in $resp.value) {
            if (-not $g.clientId) { continue }
            $cid = [string]$g.clientId
            if (-not $grantMap.ContainsKey($cid)) { $grantMap[$cid] = New-Object System.Collections.Generic.List[object] }
            $grantMap[$cid].Add([pscustomobject]@{
                Scopes      = @(([string]$g.scope).Trim() -split '\s+' | Where-Object { $_ })
                ConsentType = [string]$g.consentType
                ResourceId  = [string]$g.resourceId
            })
            $grantCount++
        }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    $telemetry.DelegatedGrants = @{ Status = 'OK'; Count = $grantCount }
    Write-Host ("  {0} grants retrieved" -f $grantCount) -ForegroundColor Green
} catch {
    $telemetry.DelegatedGrants = @{ Status = 'Failed'; Count = 0 }
    Write-Warning "Could not fetch delegated grants: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# 5d. App registration credentials — secrets/certs usually live on the
#     application object, not the service principal. Merging both prevents
#     owned apps falsely reporting 'no credentials' (which corrupts the risk
#     score and hides expiries from the renewal timeline).
# ---------------------------------------------------------------------------
$appRegCredMap = @{}   # appId -> @{ Pw = creds[]; Key = creds[] }
$appObjToAppId = @{}   # application object id -> appId (audit events target the object id)
try {
    Write-Host "Fetching app registration credentials..." -ForegroundColor Cyan
    $uri = 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,passwordCredentials,keyCredentials&$top=999'
    $appRegCount = 0
    do {
        $resp = Invoke-GraphWithRetry -Uri $uri
        foreach ($app in $resp.value) {
            if (-not $app.appId) { continue }
            $appRegCredMap[[string]$app.appId] = @{ Pw = @($app.passwordCredentials); Key = @($app.keyCredentials) }
            if ($app.id) { $appObjToAppId[[string]$app.id] = [string]$app.appId }
            $appRegCount++
        }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    $telemetry.AppRegs = @{ Status = 'OK'; Count = $appRegCount }
    Write-Host ("  {0} app registrations merged" -f $appRegCount) -ForegroundColor Green
} catch {
    $telemetry.AppRegs = @{ Status = 'Failed'; Count = 0 }
    Write-Warning "Could not fetch app registrations: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# 5e. Directory audit log — when was each SP last modified by an admin?
#     Recent config changes on a sign-in-stale app mean someone is still
#     working on it, so the removal recommendation is softened.
# ---------------------------------------------------------------------------
$lastModifiedMap = @{}   # SP object id -> [datetime] of most recent change
$lastModifiedByAppId = @{}   # appId -> [datetime] (app registration changes)
try {
    Write-Host ("Fetching directory audit events (last {0} days)..." -f $SignInLogDays) -ForegroundColor Cyan
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $cutoff&`$orderby=activityDateTime desc&`$top=999"
    $auditPages = 0; $auditEvents = 0; $auditTrunc = $false
    do {
        $auditPages++
        $resp = Invoke-GraphWithRetry -Uri $uri
        foreach ($a in $resp.value) {
            $when = [datetime]$a.activityDateTime
            foreach ($t in @($a.targetResources)) {
                if (-not $t.id) { continue }
                $tid = [string]$t.id
                if ([string]$t.type -eq 'ServicePrincipal') {
                    $auditEvents++
                    $existing = $lastModifiedMap[$tid]
                    if (-not $existing -or $when -gt $existing) { $lastModifiedMap[$tid] = $when }
                } elseif ([string]$t.type -eq 'Application' -and $appObjToAppId.ContainsKey($tid)) {
                    # Application targets carry the app registration's object id,
                    # which never matches an SP id — key these by appId instead.
                    $auditEvents++
                    $aid = $appObjToAppId[$tid]
                    $existing = $lastModifiedByAppId[$aid]
                    if (-not $existing -or $when -gt $existing) { $lastModifiedByAppId[$aid] = $when }
                }
            }
        }
        $uri = $resp.'@odata.nextLink'
        if ($auditPages -ge 50 -and $uri) { $auditTrunc = $true; break }
    } while ($uri)
    $telemetry.AuditLog = @{ Status = 'OK'; Events = $auditEvents; Pages = $auditPages; Truncated = $auditTrunc }
    Write-Host ("  {0} app-related audit events" -f $auditEvents) -ForegroundColor Green
} catch {
    $telemetry.AuditLog = @{ Status = 'Failed'; Events = 0; Pages = 0; Truncated = $false }
    Write-Warning "Could not fetch directory audits: $($_.Exception.Message)"
}

# Credential objects arrive as SDK objects (PascalCase) from Get-MgServicePrincipal
# and as hashtables (camelCase) from raw REST — normalise both shapes.
function ConvertTo-CredObject {
    param($c)
    $keyId = $null; $end = $null; $usage = $null; $key = $null
    if ($c -is [hashtable]) {
        foreach ($k in $c.Keys) {
            switch -Regex ([string]$k) {
                '^(k|K)eyId$'       { $keyId = $c[$k] }
                '^(e|E)ndDateTime$' { $end   = $c[$k] }
                '^(u|U)sage$'       { $usage = $c[$k] }
                '^(k|K)ey$'         { $key   = $c[$k] }
            }
        }
    } else {
        if ($c.PSObject.Properties['KeyId'])       { $keyId = $c.KeyId }       elseif ($c.PSObject.Properties['keyId'])       { $keyId = $c.keyId }
        if ($c.PSObject.Properties['EndDateTime']) { $end   = $c.EndDateTime } elseif ($c.PSObject.Properties['endDateTime']) { $end   = $c.endDateTime }
        if ($c.PSObject.Properties['Usage'])       { $usage = $c.Usage }       elseif ($c.PSObject.Properties['usage'])       { $usage = $c.usage }
        if ($c.PSObject.Properties['Key'])         { $key   = $c.Key }         elseif ($c.PSObject.Properties['key'])         { $key   = $c.key }
    }
    # Thumbprint of the public cert (SAML 'Verify' creds carry it), used to
    # find the active signing cert. Raw REST gives base64; the SDK gives bytes.
    $thumb = $null
    if ($key) {
        try {
            # Typed so the if-expression's output isn't unrolled into object[].
            [byte[]]$bytes = if ($key -is [string]) { [Convert]::FromBase64String($key) } else { $key }
            $thumb = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes).Thumbprint
        } catch { }
    }
    [pscustomobject]@{ KeyId = [string]$keyId; EndDateTime = $end; Usage = [string]$usage; Thumbprint = $thumb }
}

# ---------------------------------------------------------------------------
# 6. Helpers
# ---------------------------------------------------------------------------
function Get-LastSignIn {
    param($activity)
    if (-not $activity) { return $null }
    $candidates = @(
        $activity.lastSignInActivity.lastSignInDateTime,
        $activity.delegatedClientSignInActivity.lastSignInDateTime,
        $activity.delegatedResourceSignInActivity.lastSignInDateTime,
        $activity.applicationAuthenticationClientSignInActivity.lastSignInDateTime,
        $activity.applicationAuthenticationResourceSignInActivity.lastSignInDateTime
    ) | Where-Object { $_ } | ForEach-Object { [datetime]$_ }
    if ($candidates.Count -eq 0) { return $null }
    return ($candidates | Sort-Object -Descending | Select-Object -First 1)
}

function Get-Bucket {
    param([Nullable[datetime]]$LastSignIn, $Days)
    if (-not $LastSignIn) { return 'Never' }
    if ($Days -le 30)  { return 'Active' }
    if ($Days -le 60)  { return 'Stale30' }
    if ($Days -le 90)  { return 'Stale60' }
    return 'Stale90'
}

# Splits keyCredentials into SAML signing certs (usage='Verify') and other API
# certs. 'Sign' certs are dropped — they're the private half of the SAML pair
# and would double-count the same certificate.
function Split-KeyCredentials {
    param($KeyCreds)
    $saml  = @($KeyCreds | Where-Object { $_.Usage -eq 'Verify' })
    $other = @($KeyCreds | Where-Object { $_.Usage -notin @('Verify', 'Sign') })
    return @{ Saml = $saml; Other = $other }
}

# -UseLatest judges health by the LAST valid expiry rather than the first: an
# app whose old secret expires next week but already has a replacement that
# runs for years has been rotated, not about to break.
function Get-CertHealth {
    param($Creds, $Now, [switch]$UseLatest)
    if (-not $Creds -or $Creds.Count -eq 0) {
        return [pscustomobject]@{ Status = 'None'; Detail = 'None'; DaysUntilExpiry = $null; LatestExpiry = $null }
    }
    $valid   = @($Creds | Where-Object { $_.EndDateTime -and ([datetime]$_.EndDateTime) -ge $Now })
    $expired = @($Creds | Where-Object { $_.EndDateTime -and ([datetime]$_.EndDateTime) -lt $Now })
    if ($valid.Count -eq 0) {
        return [pscustomobject]@{ Status = 'Expired'; Detail = "$($expired.Count) expired"; DaysUntilExpiry = $null; LatestExpiry = $null }
    }
    $sorted  = @($valid | Sort-Object { [datetime]$_.EndDateTime })
    $soonest = [datetime]$sorted[0].EndDateTime
    $latest  = [datetime]$sorted[$sorted.Count - 1].EndDateTime
    $target  = if ($UseLatest) { $latest } else { $soonest }
    $daysUntil = [int]($target - $Now).TotalDays
    if     ($daysUntil -lt 30) { $status = 'Expiring30' }
    elseif ($daysUntil -lt 60) { $status = 'Expiring60' }
    else                       { $status = 'Valid' }
    $detail = "$($valid.Count) valid, expires in $daysUntil d"
    if ($UseLatest -and $valid.Count -gt 1) {
        $detail = "$($valid.Count) valid, latest expires in $daysUntil d"
        $soonDays = [int]($soonest - $Now).TotalDays
        if (($latest - $soonest).TotalDays -ge 30) { $detail += " (older one in $soonDays d — remove once cut over)" }
    }
    return [pscustomobject]@{ Status = $status; Detail = $detail; DaysUntilExpiry = $daysUntil; LatestExpiry = $latest }
}

# Combined cert + secret health for non-SSO API credentials.
function Get-CredentialHealth {
    param($PasswordCreds, $OtherKeyCreds, $Now)
    $all = @()
    if ($PasswordCreds)  { $all += @($PasswordCreds  | ForEach-Object { @{ EndDateTime = $_.EndDateTime } }) }
    if ($OtherKeyCreds)  { $all += @($OtherKeyCreds  | ForEach-Object { @{ EndDateTime = $_.EndDateTime } }) }
    return Get-CertHealth -Creds $all -Now $Now -UseLatest
}

# Entra Agent ID objects. Agent identities have no credentials of their own
# and must have a sponsor, so 'no owners' isn't an accountability gap for them.
# (Reading sponsors needs AgentIdentity.ReadWrite.All — too much for a read-only
# report — so the report relies on Entra enforcing them instead.)
function Get-AgentKind {
    param($Sp)
    $odataType = ''
    try { if ($Sp.AdditionalProperties) { $odataType = [string]$Sp.AdditionalProperties['@odata.type'] } } catch { }
    $spType = [string]$Sp.ServicePrincipalType
    if ($odataType -eq '#microsoft.graph.agentIdentity' -or $spType -eq 'ServiceIdentity') { return 'Identity' }
    if ($odataType -eq '#microsoft.graph.agentIdentityBlueprintPrincipal' -or $spType -eq 'AgentIdentityBlueprintPrincipal') { return 'Blueprint' }
    return ''
}

function Get-SsoMode {
    param($Sp)
    $mode = $Sp.PreferredSingleSignOnMode
    if ([string]::IsNullOrWhiteSpace($mode)) { return 'None' }
    switch ($mode.ToLower()) {
        'saml'         { 'SAML' }
        'password'     { 'Password' }
        'oidc'         { 'OIDC' }
        'notsupported' { 'None' }
        'external'     { 'External' }
        default        { $mode }
    }
}

function Get-AppSource {
    param($Sp)
    switch (Get-AgentKind $Sp) {
        'Identity'  { return 'Agent identity' }
        'Blueprint' { return 'Agent blueprint' }
    }
    $tags = @($Sp.Tags)
    if ($tags -contains 'WindowsAzureActiveDirectoryGalleryApplicationNonPrimaryV1') { return 'Gallery' }
    if ($tags -contains 'WindowsAzureActiveDirectoryCustomSingleSignOnApplication') { return 'Custom SSO' }
    if ($tags -contains 'WindowsAzureActiveDirectoryIntegratedApp') { return 'Integrated' }
    return 'Other'
}

function Get-ProvisioningStatus {
    param($Jobs)
    $jobs = @($Jobs)
    if ($jobs.Count -eq 0) { return [pscustomobject]@{ Status = 'None'; Detail = 'Not configured'; LastSync = $null } }
    # Pick the most relevant job — first one in the response is usually canonical.
    $job = $jobs[0]
    $code = if ($job.status.code) { [string]$job.status.code } else { 'Unknown' }
    $lastSuccess = $job.status.lastSuccessfulExecution.timeBegan
    $lastSync = if ($lastSuccess) { [datetime]$lastSuccess } else { $null }
    $detail = "State: $code"
    if ($lastSync) { $detail += " | Last success: $($lastSync.ToString('yyyy-MM-dd'))" }
    $status = switch ($code.ToLower()) {
        'active'      { 'Healthy' }
        'paused'      { 'Paused' }
        'quarantine'  { 'Quarantine' }
        'disabled'    { 'Disabled' }
        default       { 'Other' }
    }
    return [pscustomobject]@{ Status = $status; Detail = $detail; LastSync = $lastSync }
}

function Get-RiskScore {
    param($Row)
    $s = 0
    switch ($Row.Bucket) {
        'Active'  { $s += 0 }
        'Stale30' { $s += 10 }
        'Stale60' { $s += 25 }
        'Stale90' { $s += 45 }
        'Never'   { $s += 50 }
    }
    # SAML cert expiry is heavy — expired = users locked out
    switch ($Row.SamlCertStatus) {
        'Expired'    { $s += 25 }
        'Expiring30' { $s += 15 }
        'Expiring60' { $s += 8 }
    }
    # API credential expiry
    switch ($Row.CredStatus) {
        'Expired'    { $s += 15 }
        'Expiring30' { $s += 10 }
        'Expiring60' { $s += 5 }
    }
    # Provisioning health
    switch ($Row.ProvStatus) {
        'Quarantine' { $s += 15 }
        'Disabled'   { $s += 8 }
        'Paused'     { $s += 5 }
    }
    # SSO configured but no notification email — no one gets cert expiry alerts
    if ($Row.SsoMode -in @('SAML','Password','OIDC') -and -not $Row.HasNotificationEmail) { $s += 8 }
    # Legacy APIs: EWS is being switched off in Exchange Online (the app will
    # break); retired Azure AD Graph grants mark an old, likely unmaintained app.
    if (@($Row.EwsPerms).Count -gt 0)      { $s += 10 }
    if (@($Row.AadGraphPerms).Count -gt 0) { $s += 5 }
    # Other signals. Null counts mean the lookup failed — a data gap must not
    # masquerade as 'zero owners', so nulls are excluded from scoring.
    if (-not $Row.Enabled)         { $s += 5 }
    if ($Row.Unowned)              { $s += 10 }
    if ($null -ne $Row.AppPermCount -and $Row.AppPermCount -gt 0) { $s += 5 }
    if ($Row.HasGraphAppPerms)     { $s += 10 }
    if ($Row.DangerousPermCount -gt 0) { $s += 10 }
    if ($Row.DangerousDelegatedCount -gt 0 -and $Row.HasAllPrincipalsGrant) { $s += 8 }
    if ($null -ne $Row.AssignedCount -and $Row.AssignedCount -eq 0 -and $Row.Bucket -ne 'Active') { $s += 5 }
    return [Math]::Min($s, 100)
}

function Get-RiskBand {
    param([int]$Score)
    if ($Score -ge 70) { return 'Critical' }
    if ($Score -ge 45) { return 'High' }
    if ($Score -ge 20) { return 'Medium' }
    return 'Low'
}

# One concrete next step per app, in priority order. Empty string = nothing needed.
function Get-RecommendedAction {
    param($Row)
    $recentlyModified = $Row.LastModified -and ((Get-Date) - $Row.LastModified).TotalDays -le 30
    $accountable = if ($Row.AgentKind -eq 'Identity') { 'sponsor' } else { 'owner' }
    if ($Row.SamlCertStatus -eq 'Expired')    { return 'Renew SAML signing cert NOW — SSO is broken' }
    if ($Row.SamlCertStatus -eq 'Expiring30') { return "Renew SAML cert within $($Row.SamlDays) days" }
    if ($Row.Bucket -in @('Stale90','Never') -and $Row.DangerousPermCount -gt 0) { return 'Stale with high-privilege perms — review urgently' }
    if ($Row.Bucket -in @('Stale90','Never') -and $null -ne $Row.AssignedCount -and $Row.AssignedCount -eq 0 -and $Row.CredStatus -in @('None','Expired')) {
        if ($recentlyModified) { return "Stale but recently modified — verify with $accountable before removal" }
        return 'Unused — candidate for removal'
    }
    if (@($Row.EwsPerms).Count -gt 0)         { return 'Migrate off EWS now — Exchange Online is switching it off' }
    if ($Row.CredStatus -eq 'Expired')        { return 'Remove or rotate expired credentials' }
    if ($Row.CredStatus -eq 'Expiring30')     { return "Rotate credential within $($Row.CredDays) days" }
    if ($Row.ProvStatus -eq 'Quarantine')     { return 'Fix provisioning — quarantined' }
    if ($Row.Bucket -in @('Stale90','Never')) {
        if ($recentlyModified) { return 'Stale sign-ins but recently modified — verify status' }
        return 'Review usage — stale'
    }
    if ($Row.Unowned) { return 'Assign an owner' }
    if ($Row.SsoMode -in @('SAML','Password','OIDC') -and -not $Row.HasNotificationEmail) { return 'Set notification email' }
    if (@($Row.AadGraphPerms).Count -gt 0)    { return 'Remove retired Azure AD Graph permissions' }
    if ($Row.SamlCertStatus -eq 'Expiring60') { return 'Plan SAML cert renewal' }
    if ($Row.CredStatus -eq 'Expiring60')     { return 'Plan credential rotation' }
    return ''
}

# Plain-English risk factors, used by the executive summary.
function Get-RiskFactors {
    param($Row)
    $f = @()
    switch ($Row.Bucket) {
        'Never'   { $f += 'never signed in' }
        'Stale90' { $f += 'inactive 90+ days' }
        'Stale60' { $f += 'inactive 60-90 days' }
        'Stale30' { $f += 'inactive 30-60 days' }
    }
    if ($Row.SamlCertStatus -eq 'Expired') { $f += 'SAML cert expired' }
    elseif ($Row.SamlCertStatus -in @('Expiring30','Expiring60')) { $f += 'SAML cert expiring' }
    if ($Row.CredStatus -eq 'Expired') { $f += 'expired credentials' }
    elseif ($Row.CredStatus -in @('Expiring30','Expiring60')) { $f += 'credentials expiring' }
    if ($Row.ProvStatus -in @('Quarantine','Disabled','Paused')) { $f += "provisioning $(([string]$Row.ProvStatus).ToLower())" }
    if ($Row.Unowned) { $f += 'no owners' }
    if (@($Row.EwsPerms).Count -gt 0) { $f += 'EWS permissions (being switched off)' }
    if (@($Row.AadGraphPerms).Count -gt 0) { $f += 'retired Azure AD Graph permissions' }
    if ($Row.DangerousPermCount -gt 0) { $f += "$($Row.DangerousPermCount) high-privilege permission$(if ($Row.DangerousPermCount -gt 1) {'s'})" }
    elseif ($null -ne $Row.AppPermCount -and $Row.AppPermCount -gt 0) { $f += 'app-only permissions' }
    if ($Row.DangerousDelegatedCount -gt 0) { $f += "$($Row.DangerousDelegatedCount) high-privilege delegated scope$(if ($Row.DangerousDelegatedCount -gt 1) {'s'})$(if ($Row.HasAllPrincipalsGrant) {' (tenant-wide consent)'})" }
    if (-not $Row.Enabled) { $f += 'disabled' }
    if ($null -ne $Row.AssignedCount -and $Row.AssignedCount -eq 0) { $f += 'no user assignments' }
    if ($Row.LastModified -and ((Get-Date) - $Row.LastModified).TotalDays -le 30) { $f += 'recently modified' }
    if ($null -eq $Row.OwnerCount -or $null -eq $Row.AssignedCount -or $null -eq $Row.AppPermCount) { $f += 'some lookups incomplete' }
    return @($f)
}

# ---------------------------------------------------------------------------
# 7. Build rows
# ---------------------------------------------------------------------------
Write-Host "Processing apps..." -ForegroundColor Cyan
$now = Get-Date
$credTimelineAcc = New-Object System.Collections.Generic.List[object]
$rows = foreach ($sp in $servicePrincipals) {
    $activity      = $activityMap[$sp.AppId]
    $reportSignIn  = Get-LastSignIn $activity
    $signInEntry   = $signInData[$sp.AppId]
    $logSignIn     = if ($signInEntry) { $signInEntry.LastSignIn } else { $null }
    $userCount     = if ($signInEntry) { $signInEntry.UserIds.Count } else { 0 }
    $userSample    = if ($signInEntry) { ($signInEntry.UserSample -join '; ') } else { '' }

    # Take the most recent of (activity report, live sign-in log) and remember source.
    $lastSignIn = $reportSignIn
    $signInSource = if ($reportSignIn) { 'Activity report' } else { $null }
    if ($logSignIn -and (-not $lastSignIn -or $logSignIn -gt $lastSignIn)) {
        $lastSignIn   = $logSignIn
        $signInSource = 'Sign-in log'
    }
    $daysSince  = if ($lastSignIn) { [int]($now - $lastSignIn).TotalDays } else { $null }
    $bucket     = Get-Bucket -LastSignIn $lastSignIn -Days $daysSince

    # Merge SP credentials with the underlying app registration's (dedupe on
    # KeyId — gallery apps sync the same cert to both objects).
    $regCred    = $appRegCredMap[[string]$sp.AppId]
    $spKeyObjs  = @(@($sp.KeyCredentials) | ForEach-Object { ConvertTo-CredObject $_ })
    $keySplit   = Split-KeyCredentials -KeyCreds $spKeyObjs

    $seenCred = @{}
    $pwCreds = @()
    foreach ($c in @(@($sp.PasswordCredentials) | ForEach-Object { ConvertTo-CredObject $_ })) {
        $k = 'p' + $c.KeyId
        if (-not $c.KeyId -or -not $seenCred.ContainsKey($k)) { $seenCred[$k] = 1; $pwCreds += $c }
    }
    $otherKeys = @($keySplit.Other)
    foreach ($c in @($keySplit.Other)) { if ($c.KeyId) { $seenCred['k' + $c.KeyId] = 1 } }
    foreach ($c in @($keySplit.Saml))  { if ($c.KeyId) { $seenCred['k' + $c.KeyId] = 1 } }
    if ($regCred) {
        foreach ($c in @(@($regCred.Pw) | ForEach-Object { ConvertTo-CredObject $_ })) {
            $k = 'p' + $c.KeyId
            if (-not $c.KeyId -or -not $seenCred.ContainsKey($k)) { $seenCred[$k] = 1; $pwCreds += $c }
        }
        foreach ($c in @(@($regCred.Key) | ForEach-Object { ConvertTo-CredObject $_ })) {
            $k = 'k' + $c.KeyId
            if (-not $c.KeyId -or -not $seenCred.ContainsKey($k)) { $seenCred[$k] = 1; $otherKeys += $c }
        }
    }

    # Only the ACTIVE SAML signing cert decides whether SSO works. A renewed-
    # but-not-activated cert, or an old inactive one left behind, must not
    # mask (or fake) an expiry. Falls back to all Verify certs if unmatched.
    $samlCreds = @($keySplit.Saml)
    $activeThumb = [string]$sp.PreferredTokenSigningKeyThumbprint
    if ($activeThumb) {
        $activeSaml = @($samlCreds | Where-Object { $_.Thumbprint -and $_.Thumbprint -eq $activeThumb })
        if ($activeSaml.Count -gt 0) { $samlCreds = $activeSaml }
    }

    $samlHealth = Get-CertHealth       -Creds $samlCreds -Now $now
    $credHealth = Get-CredentialHealth -PasswordCreds $pwCreds -OtherKeyCreds $otherKeys -Now $now

    # Feed the credential renewal timeline (next 90 days) from the merged set.
    # Credentials already outlived by a newer one are labelled as rotated.
    $credLatest = $credHealth.LatestExpiry
    foreach ($c in $pwCreds) {
        if (-not $c.EndDateTime) { continue }
        $d = [int](([datetime]$c.EndDateTime) - $now).TotalDays
        $type = if ($credLatest -and ([datetime]$c.EndDateTime) -lt $credLatest.AddDays(-30)) { 'Secret (rotated)' } else { 'Secret' }
        if ($d -ge 0 -and $d -le 90) { $credTimelineAcc.Add([pscustomobject]@{ App = $sp.DisplayName; Type = $type; Expiry = [datetime]$c.EndDateTime; Days = $d }) }
    }
    foreach ($c in $samlCreds) {
        if (-not $c.EndDateTime) { continue }
        $d = [int](([datetime]$c.EndDateTime) - $now).TotalDays
        if ($d -ge 0 -and $d -le 90) { $credTimelineAcc.Add([pscustomobject]@{ App = $sp.DisplayName; Type = 'SAML cert'; Expiry = [datetime]$c.EndDateTime; Days = $d }) }
    }
    foreach ($c in $otherKeys) {
        if (-not $c.EndDateTime) { continue }
        $d = [int](([datetime]$c.EndDateTime) - $now).TotalDays
        $type = if ($credLatest -and ([datetime]$c.EndDateTime) -lt $credLatest.AddDays(-30)) { 'Certificate (rotated)' } else { 'Certificate' }
        if ($d -ge 0 -and $d -le 90) { $credTimelineAcc.Add([pscustomobject]@{ App = $sp.DisplayName; Type = $type; Expiry = [datetime]$c.EndDateTime; Days = $d }) }
    }

    $ssoMode    = Get-SsoMode -Sp $sp
    $appSource  = Get-AppSource -Sp $sp
    $agentKind  = Get-AgentKind -Sp $sp
    $hasEmail   = @($sp.NotificationEmailAddresses).Count -gt 0

    $detail     = $detailMap[$sp.Id]
    $appPerms   = @($detail.AppPerms)
    $hasGraph   = [bool]($appPerms | Where-Object { $_.resourceDisplayName -eq 'Microsoft Graph' })
    $prov       = Get-ProvisioningStatus -Jobs $detail.ProvJobs

    # Resolve permission GUIDs to names and flag the dangerous ones.
    $permObjects = @(foreach ($p in $appPerms) {
        $value = $null
        $resId = [string]$p.resourceId
        if ($resId -and $roleNameMap.ContainsKey($resId)) { $value = $roleNameMap[$resId][[string]$p.appRoleId] }
        if (-not $value) { $value = 'unknown-role' }
        $resName = [string]$p.resourceDisplayName
        $display = if ($resName -and $resName -ne 'Microsoft Graph') { "$resName`: $value" } else { $value }
        $legacy  = if ($legacyResourceMap[$resId] -eq 'AADGraph' -or $resName -eq 'Windows Azure Active Directory') { 'AADGraph' }
                   elseif ($ewsPermList -contains $value) { 'EWS' } else { '' }
        [pscustomobject]@{ Value = $value; Display = $display; Dangerous = ($dangerousPermList -contains $value); Legacy = $legacy }
    })
    $dangerousCount = @($permObjects | Where-Object Dangerous).Count

    # Delegated (on-behalf-of-user) permission grants. Azure AD Graph scopes
    # share names with Microsoft Graph ones (User.Read...), so they're kept
    # apart and prefixed rather than merged.
    $grants = $grantMap[[string]$sp.Id]
    $delegScopes = @()
    $aadGraphDeleg = @()
    $hasAllPrincipals = $false
    if ($grants) {
        foreach ($g in $grants) {
            if ($g.ConsentType -eq 'AllPrincipals') { $hasAllPrincipals = $true }
            if ($legacyResourceMap[$g.ResourceId] -eq 'AADGraph') {
                $aadGraphDeleg += @($g.Scopes | ForEach-Object { "Azure AD Graph: $_" })
            } else {
                $delegScopes += $g.Scopes
            }
        }
    }
    $delegScopes = @(@($delegScopes | Select-Object -Unique) + @($aadGraphDeleg | Select-Object -Unique))
    $dangerousDeleg = @($delegScopes | Where-Object { $dangerousPermList -contains $_ })

    # Legacy API exposure across both permission types.
    $ewsPerms      = @(@($permObjects | Where-Object { $_.Legacy -eq 'EWS' } | ForEach-Object { $_.Value }) +
                       @($delegScopes | Where-Object { $ewsPermList -contains $_ }) | Select-Object -Unique)
    $aadGraphPerms = @(@($permObjects | Where-Object { $_.Legacy -eq 'AADGraph' } | ForEach-Object { $_.Display }) + $aadGraphDeleg | Select-Object -Unique)
    $legacyApi     = if ($ewsPerms.Count -gt 0) { 'EWS' } elseif ($aadGraphPerms.Count -gt 0) { 'AADGraph' } else { '' }

    # When was this SP (or its app registration) last touched by an admin?
    $lastModified = $lastModifiedMap[[string]$sp.Id]
    $regModified  = $lastModifiedByAppId[[string]$sp.AppId]
    if ($regModified -and (-not $lastModified -or $regModified -gt $lastModified)) { $lastModified = $regModified }

    # SAML cert is only meaningful for SAML-configured apps
    $samlStatus = if ($ssoMode -eq 'SAML') { $samlHealth.Status } else { 'NA' }

    # Failed lookups become $null (= 'unknown'), never zero.
    $ownerCountVal    = if ($detail.OwnersKnown)   { @($detail.Owners).Count } else { $null }
    $assignedCountVal = if ($detail.AssignedKnown) { [int]$detail.AssignedCount } else { $null }
    $appPermCountVal  = if ($detail.PermsKnown)    { $appPerms.Count } else { $null }
    $provStatusVal    = if ($detail.ProvKnown)     { $prov.Status } else { 'Unknown' }
    $provDetailVal    = if ($detail.ProvKnown)     { $prov.Detail } else { 'Lookup failed — provisioning state unknown' }

    $row = [pscustomobject]@{
        DisplayName         = $sp.DisplayName
        AppId               = $sp.AppId
        ObjectId            = $sp.Id
        Publisher           = $sp.PublisherName
        AppSource           = $appSource
        Enabled             = $sp.AccountEnabled
        AssignmentRequired  = $sp.AppRoleAssignmentRequired
        Created             = $sp.CreatedDateTime
        LastSignIn          = $lastSignIn
        SignInSource        = $signInSource
        DaysSince           = $daysSince
        Bucket              = $bucket
        UserCount           = $userCount
        UserSample          = $userSample
        SsoMode             = $ssoMode
        SamlCertStatus      = $samlStatus
        SamlCertDetail      = $samlHealth.Detail
        SamlDays            = $samlHealth.DaysUntilExpiry
        CredStatus          = $credHealth.Status
        CredDetail          = $credHealth.Detail
        CredDays            = $credHealth.DaysUntilExpiry
        ProvStatus          = $provStatusVal
        ProvDetail          = $provDetailVal
        HasNotificationEmail= $hasEmail
        NotificationEmails  = (@($sp.NotificationEmailAddresses) -join '; ')
        OwnerCount          = $ownerCountVal
        OwnerNames          = (@($detail.Owners) -join '; ')
        AssignedCount       = $assignedCountVal
        AppPermCount        = $appPermCountVal
        HasGraphAppPerms    = $hasGraph
        PermObjects         = $permObjects
        DangerousPermCount  = $dangerousCount
        DelegatedPermCount  = $delegScopes.Count
        DelegatedScopes     = $delegScopes
        HasAllPrincipalsGrant = $hasAllPrincipals
        DangerousDelegatedCount = $dangerousDeleg.Count
        LastModified        = $lastModified
        Homepage            = $sp.Homepage
        AgentKind           = $agentKind
        # Agent identities are accountable via mandatory sponsors, not owners.
        Unowned             = ($null -ne $ownerCountVal -and $ownerCountVal -eq 0 -and $agentKind -ne 'Identity')
        EwsPerms            = $ewsPerms
        AadGraphPerms       = $aadGraphPerms
        LegacyApi           = $legacyApi
    }
    $row | Add-Member -NotePropertyName RiskScore -NotePropertyValue (Get-RiskScore $row)
    $row | Add-Member -NotePropertyName RiskBand  -NotePropertyValue (Get-RiskBand $row.RiskScore)
    $row | Add-Member -NotePropertyName Action    -NotePropertyValue (Get-RecommendedAction $row)
    $row
}

$rows = $rows | Sort-Object @{ Expression = { if ($_.LastSignIn) { $_.LastSignIn } else { [datetime]'1900-01-01' } } }

$counts = @{
    Total      = $rows.Count
    Active     = ($rows | Where-Object Bucket   -eq 'Active').Count
    Stale30    = ($rows | Where-Object Bucket   -eq 'Stale30').Count
    Stale60    = ($rows | Where-Object Bucket   -eq 'Stale60').Count
    Stale90    = ($rows | Where-Object Bucket   -eq 'Stale90').Count
    Never      = ($rows | Where-Object Bucket   -eq 'Never').Count
    Critical   = ($rows | Where-Object RiskBand -eq 'Critical').Count
    High       = ($rows | Where-Object RiskBand -eq 'High').Count
    SamlApps   = ($rows | Where-Object SsoMode  -eq 'SAML').Count
    SamlExpiry = ($rows | Where-Object { $_.SamlCertStatus -in @('Expired','Expiring30') }).Count
    ProvIssues = ($rows | Where-Object ProvStatus -in @('Quarantine','Disabled','Paused')).Count
    DataGaps   = @($rows | Where-Object { $null -eq $_.OwnerCount -or $null -eq $_.AssignedCount -or $null -eq $_.AppPermCount }).Count
    Ews        = @($rows | Where-Object { @($_.EwsPerms).Count -gt 0 }).Count
    AadGraph   = @($rows | Where-Object { @($_.AadGraphPerms).Count -gt 0 }).Count
    Legacy     = @($rows | Where-Object { $_.LegacyApi }).Count
    Agents     = @($rows | Where-Object { $_.AgentKind }).Count
}

# ---------------------------------------------------------------------------
# 7b. Month-over-month change tracking.
#     Interactive: snapshot JSON saved next to the report.
#     Automation:  snapshot stored in the 'AppLens-Snapshot' Automation
#     Variable (created by the setup script; change tracking is skipped with a
#     warning if the variable doesn't exist).
# ---------------------------------------------------------------------------
$snapshotVariableName = 'AppLens-Snapshot'
if (-not $SnapshotPath) { $SnapshotPath = Join-Path (Split-Path $OutputPath -Parent) 'AppLens-Snapshot.json' }

$prevSnapshot = $null
try {
    if ($inAutomation) {
        $rawSnap = Get-AutomationVariable -Name $snapshotVariableName -ErrorAction Stop
        if ($rawSnap) { $prevSnapshot = $rawSnap | ConvertFrom-Json }
    } elseif (Test-Path $SnapshotPath) {
        $prevSnapshot = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    }
} catch {
    Write-Warning "Could not load previous snapshot — change tracking starts fresh. ($($_.Exception.Message))"
}

$changes = $null
if ($prevSnapshot -and $prevSnapshot.apps) {
    $bucketOrder = @{ 'Active' = 0; 'Stale30' = 1; 'Stale60' = 2; 'Stale90' = 3; 'Never' = 4 }
    $prevMap = @{}
    foreach ($p in $prevSnapshot.apps) { $prevMap[[string]$p.id] = $p }
    $curIds  = [System.Collections.Generic.HashSet[string]]::new()
    $added   = New-Object System.Collections.Generic.List[object]
    $staler  = New-Object System.Collections.Generic.List[object]
    $riskUp  = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        [void]$curIds.Add([string]$r.AppId)
        $p = $prevMap[[string]$r.AppId]
        if (-not $p) { $added.Add($r); continue }
        if ($bucketOrder[$r.Bucket] -gt $bucketOrder[[string]$p.b] -and $r.Bucket -in @('Stale60','Stale90','Never')) {
            $staler.Add([pscustomobject]@{ Row = $r; PrevBucket = [string]$p.b })
        }
        if (($r.RiskScore - [int]$p.r) -ge 15) {
            $riskUp.Add([pscustomobject]@{ Row = $r; PrevScore = [int]$p.r })
        }
    }
    $removed = @($prevSnapshot.apps | Where-Object { -not $curIds.Contains([string]$_.id) })
    # NB: .ToArray() not @(...) — PS 5.1 throws 'Argument types do not match'
    # when @() wraps a Generic.List inside some expression contexts.
    $changes = [pscustomobject]@{
        Added    = $added.ToArray()
        Removed  = $removed
        Staler   = $staler.ToArray()
        RiskUp   = $riskUp.ToArray()
        PrevDate = [string]$prevSnapshot.date
    }
}

# Save the new snapshot (lean: id, name, risk, bucket per app) plus a rolling
# 12-run KPI history for the trend chart.
$kpiNow = @{ d = $now.ToString('yyyy-MM-dd'); t = $counts.Total; c = $counts.Critical; h = $counts.High; s = $counts.Stale90; n = $counts.Never }
$kpiHistory = @()
if ($prevSnapshot -and $prevSnapshot.PSObject.Properties['history'] -and $prevSnapshot.history) {
    $kpiHistory = @($prevSnapshot.history)
}
$kpiHistory = @($kpiHistory + $kpiNow | Select-Object -Last 12)

$newSnapshot = @{
    date    = $now.ToString('yyyy-MM-dd HH:mm')
    apps    = @($rows | ForEach-Object { @{ id = $_.AppId; n = $_.DisplayName; r = $_.RiskScore; b = $_.Bucket } })
    history = $kpiHistory
} | ConvertTo-Json -Compress -Depth 5
try {
    if ($inAutomation) {
        Set-AutomationVariable -Name $snapshotVariableName -Value $newSnapshot
        Write-Output "Snapshot saved to Automation Variable '$snapshotVariableName'."
    } else {
        $newSnapshot | Out-File -FilePath $SnapshotPath -Encoding UTF8
    }
} catch {
    Write-Warning "Could not save snapshot — change tracking will restart next run. ($($_.Exception.Message))"
}

# ---------------------------------------------------------------------------
# 7c. Credential renewal timeline — accumulated during row processing from the
#     merged SP + app registration credential set, sorted soonest-first.
# ---------------------------------------------------------------------------
$credTimeline = @($credTimelineAcc.ToArray() | Sort-Object Expiry)

# ---------------------------------------------------------------------------
# 7d. Executive summary — top 5 riskiest apps with factors + action.
# ---------------------------------------------------------------------------
$topRisk = @($rows | Where-Object { $_.RiskScore -ge 20 } | Sort-Object RiskScore -Descending | Select-Object -First 5)

# ---------------------------------------------------------------------------
# 8. HTML generation
# ---------------------------------------------------------------------------
Write-Host "Generating HTML..." -ForegroundColor Cyan

$bucketMeta = @{
    'Active'  = @{ Label = 'Active < 30 d'; Class = 'b-active' }
    'Stale30' = @{ Label = '30-60 d';        Class = 'b-stale30' }
    'Stale60' = @{ Label = '60-90 d';        Class = 'b-stale60' }
    'Stale90' = @{ Label = '90+ d';          Class = 'b-stale90' }
    'Never'   = @{ Label = 'Never';          Class = 'b-never' }
}
$certMeta = @{
    'None'       = @{ Label = 'None';          Class = 'c-none' }
    'NA'         = @{ Label = 'N/A';           Class = 'c-na' }
    'Valid'      = @{ Label = 'Valid';         Class = 'c-valid' }
    'Expiring60' = @{ Label = 'Expires <60d';  Class = 'c-expiring60' }
    'Expiring30' = @{ Label = 'Expires <30d';  Class = 'c-expiring30' }
    'Expired'    = @{ Label = 'Expired';       Class = 'c-expired' }
}
$ssoMeta = @{
    'SAML'     = @{ Class = 's-saml' }
    'OIDC'     = @{ Class = 's-oidc' }
    'Password' = @{ Class = 's-password' }
    'External' = @{ Class = 's-external' }
    'None'     = @{ Class = 's-none' }
}
$provMeta = @{
    'None'       = @{ Label = 'None';       Class = 'p-none' }
    'Healthy'    = @{ Label = 'Healthy';    Class = 'p-healthy' }
    'Paused'     = @{ Label = 'Paused';     Class = 'p-paused' }
    'Quarantine' = @{ Label = 'Quarantine'; Class = 'p-quarantine' }
    'Disabled'   = @{ Label = 'Disabled';   Class = 'p-disabled' }
    'Other'      = @{ Label = 'Other';      Class = 'p-other' }
    'Unknown'    = @{ Label = '?';          Class = 'p-none' }
}
$riskMeta = @{
    'Low'      = @{ Class = 'r-low' };       'Medium'   = @{ Class = 'r-medium' }
    'High'     = @{ Class = 'r-high' };      'Critical' = @{ Class = 'r-critical' }
}

function HtmlEncode { param($s); if ($null -eq $s) { return '' }; return [System.Net.WebUtility]::HtmlEncode([string]$s) }

$rowIdx = 0
$tbody = foreach ($r in $rows) {
    $rowIdx++
    $bm = $bucketMeta[$r.Bucket]
    $cm = $certMeta[$r.CredStatus]
    $sm = $ssoMeta[$r.SsoMode]; if (-not $sm) { $sm = @{ Class = 's-none' } }
    $scm = $certMeta[$r.SamlCertStatus]
    $pm = $provMeta[$r.ProvStatus]
    $rm = $riskMeta[$r.RiskBand]

    $lastSignInDisplay = if ($r.LastSignIn) {
        $title = if ($r.SignInSource) { " title=""Source: $($r.SignInSource)""" } else { '' }
        "<span$title>$($r.LastSignIn.ToString('yyyy-MM-dd'))</span>"
    } else { '—' }
    $daysDisplay       = if ($null -ne $r.DaysSince) { $r.DaysSince } else { '—' }
    $createdDisplay    = if ($r.Created) { ([datetime]$r.Created).ToString('yyyy-MM-dd') } else { '—' }
    $enabledDisplay    = if ($r.Enabled) { 'Yes' } else { 'No' }
    $daysSortKey       = if ($null -ne $r.DaysSince) { $r.DaysSince } else { 99999 }

    $entraUrl = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$($r.ObjectId)/appId/$($r.AppId)"

    $emailIcon = if ($r.SsoMode -in @('SAML','Password','OIDC')) {
        if ($r.HasNotificationEmail) {
            " <span title=""Notification email set: $(HtmlEncode $r.NotificationEmails)"">✉</span>"
        } else {
            " <span class=""warn"" title=""No notification email — no one will be warned of SAML cert expiry"">⚠</span>"
        }
    } else { '' }

    $ownerCell = if ($null -eq $r.OwnerCount) {
        '<span class="dim" title="Lookup failed — excluded from risk scoring">?</span>'
    } elseif ($r.OwnerCount -gt 0) {
        "<span title=""$(HtmlEncode $r.OwnerNames)"">$($r.OwnerCount)</span>"
    } elseif ($r.AgentKind -eq 'Identity') {
        '<span class="dim" title="Agent identity — accountable via its sponsors">0</span>'
    } else { '<span class="warn">0</span>' }

    $assignedCell = if ($null -eq $r.AssignedCount) {
        '<span class="dim" title="Lookup failed — excluded from risk scoring">?</span>'
    } else { "$($r.AssignedCount)" }

    $userCell = if ($r.UserCount -gt 0) {
        $tip = if ($r.UserCount -gt 10) { "$(HtmlEncode $r.UserSample) (+$($r.UserCount - 10) more)" } else { HtmlEncode $r.UserSample }
        "<span title=""$tip"">$($r.UserCount)</span>"
    } else { '<span class="dim">0</span>' }

    $permCell = if ($null -eq $r.AppPermCount) {
        '<span class="dim" title="Lookup failed — excluded from risk scoring">?</span>'
    } elseif ($r.AppPermCount -gt 0) {
        $cls = if ($r.DangerousPermCount -gt 0) { 'warn' } elseif ($r.HasGraphAppPerms) { 'warn' } else { '' }
        "<span class=""$cls"">$($r.AppPermCount)</span>"
    } else { '0' }

    $actionCell = if ($r.Action) {
        $aCls = if ($r.Action -match 'NOW|urgent') { 'action urgent' } else { 'action' }
        "<span class=""$aCls"">$(HtmlEncode $r.Action)</span>"
    } else { '<span class="dim">—</span>' }

    $permBadges = if (@($r.PermObjects).Count -gt 0) {
        (@($r.PermObjects | ForEach-Object {
            $po   = $_
            $pCls = if ($po.Dangerous) { 'perm dangerous' } elseif ($po.Legacy) { 'perm legacy' } else { 'perm' }
            $pTip = if ($po.Legacy -eq 'EWS') { ' title="Exchange Web Services — being switched off in Exchange Online"' }
                    elseif ($po.Legacy -eq 'AADGraph') { ' title="Azure AD Graph — retired, this permission does nothing"' }
                    else { '' }
            "<span class=""$pCls""$pTip>$(HtmlEncode $po.Display)</span>"
        }) -join ' ')
    } else { '<span class="dim">None</span>' }

    # Homepage is publisher-controlled on multi-tenant apps — only link http(s),
    # so a 'javascript:' URL can't run script from inside the report.
    $homepageHtml = if ($r.Homepage -match '^https?://') { "<a href=""$(HtmlEncode $r.Homepage)"" target=""_blank"" rel=""noopener"">$(HtmlEncode $r.Homepage)</a>" }
                    elseif ($r.Homepage) { HtmlEncode $r.Homepage }
                    else { '<span class="dim">—</span>' }
    $ownersHtml   = if ($null -eq $r.OwnerCount) { '<span class="dim">Lookup failed</span>' }
                    elseif ($r.OwnerNames) { HtmlEncode $r.OwnerNames }
                    elseif ($r.AgentKind -eq 'Identity') { '<span class="dim">None — agent identities are accountable via their sponsors (Entra → Agents)</span>' }
                    else { '<span class="warn">None — orphaned app</span>' }
    $legacyHtml   = if ($r.LegacyApi) {
        $parts = @()
        if (@($r.EwsPerms).Count -gt 0) { $parts += '<span class="warn">EWS</span> (' + (HtmlEncode (@($r.EwsPerms) -join ', ')) + ') — Exchange Online is switching EWS off; migrate to Microsoft Graph' }
        if (@($r.AadGraphPerms).Count -gt 0) { $parts += 'Azure AD Graph (' + (HtmlEncode (@($r.AadGraphPerms) -join ', ')) + ') — API retired Aug 2025; permissions can be removed' }
        $parts -join '<br>'
    } else { '<span class="dim">None</span>' }
    $lastModHtml  = if ($r.LastModified) { $r.LastModified.ToString('yyyy-MM-dd') } else { '<span class="dim">No changes in window</span>' }
    $delegBadges  = if (@($r.DelegatedScopes).Count -gt 0) {
        $shownScopes = @($r.DelegatedScopes | Select-Object -First 20)
        $badgeList = @($shownScopes | ForEach-Object {
            $dCls = if ($dangerousPermList -contains $_) { 'perm dangerous' }
                    elseif ($ewsPermList -contains $_ -or $_ -like 'Azure AD Graph: *') { 'perm legacy' }
                    else { 'perm' }
            "<span class=""$dCls"">$(HtmlEncode $_)</span>"
        }) -join ' '
        $moreScopes = if (@($r.DelegatedScopes).Count -gt 20) { " <span class='dim'>(+$(@($r.DelegatedScopes).Count - 20) more)</span>" } else { '' }
        $consentNote = if ($r.HasAllPrincipalsGrant) { ' <span class="warn" title="Admin-consented for all users in the tenant">tenant-wide</span>' } else { '' }
        $badgeList + $moreScopes + $consentNote
    } else { '<span class="dim">None</span>' }
    $moreUsers    = if ($r.UserCount -gt 10) { " <span class='dim'>(+$($r.UserCount - 10) more)</span>" } else { '' }
    $usersHtml    = if ($r.UserSample) { (HtmlEncode $r.UserSample) + $moreUsers } else { '<span class="dim">No sign-ins in window</span>' }
    $notifHtml    = if ($r.NotificationEmails) { HtmlEncode $r.NotificationEmails } else { '<span class="dim">Not set</span>' }
    $actionHtml   = if ($r.Action) { HtmlEncode $r.Action } else { '<span class="dim">Nothing needed</span>' }

    @"
<tr class="main" data-idx="$rowIdx" data-bucket="$($r.Bucket)" data-risk="$($r.RiskBand)" data-sso="$($r.SsoMode)" data-days="$daysSortKey" data-score="$($r.RiskScore)" data-legacy="$($r.LegacyApi)" data-agent="$(if ($r.AgentKind) { 'yes' })">
  <td><span class="caret">&#9656;</span> <a class="applink" href="$entraUrl" target="_blank" rel="noopener" title="Open in Entra admin centre">$(HtmlEncode $r.DisplayName)</a></td>
  <td>$actionCell</td>
  <td>$(HtmlEncode $r.AppSource)</td>
  <td><span class="badge $($sm.Class)">$(HtmlEncode $r.SsoMode)</span>$emailIcon</td>
  <td><span class="badge $($scm.Class)" title="$(HtmlEncode $r.SamlCertDetail)">$(HtmlEncode $scm.Label)</span></td>
  <td><span class="badge $($pm.Class)" title="$(HtmlEncode $r.ProvDetail)">$(HtmlEncode $pm.Label)</span></td>
  <td>$enabledDisplay</td>
  <td>$createdDisplay</td>
  <td>$lastSignInDisplay</td>
  <td class="num">$daysDisplay</td>
  <td class="num">$userCell</td>
  <td><span class="badge $($bm.Class)">$(HtmlEncode $bm.Label)</span></td>
  <td><span class="badge $($cm.Class)" title="$(HtmlEncode $r.CredDetail)">$(HtmlEncode $cm.Label)</span></td>
  <td class="num">$ownerCell</td>
  <td class="num">$assignedCell</td>
  <td class="num">$permCell</td>
  <td><span class="badge $($rm.Class)">$($r.RiskBand) ($($r.RiskScore))</span></td>
</tr>
<tr class="detail" data-detail-for="$rowIdx" style="display:none;">
  <td colspan="17">
    <div class="detail-grid">
      <div><span class="dl">Recommended action</span><span class="dv">$actionHtml</span></div>
      <div><span class="dl">Publisher</span><span class="dv">$(HtmlEncode $r.Publisher)</span></div>
      <div><span class="dl">App ID</span><span class="dv mono">$(HtmlEncode $r.AppId)</span></div>
      <div><span class="dl">Object ID</span><span class="dv mono">$(HtmlEncode $r.ObjectId)</span></div>
      <div><span class="dl">Homepage</span><span class="dv">$homepageHtml</span></div>
      <div><span class="dl">Owners</span><span class="dv">$ownersHtml</span></div>
      <div><span class="dl">Notification emails</span><span class="dv">$notifHtml</span></div>
      <div><span class="dl">Recent users</span><span class="dv">$usersHtml</span></div>
      <div><span class="dl">API credentials</span><span class="dv">$(HtmlEncode $r.CredDetail)</span></div>
      <div><span class="dl">SAML cert</span><span class="dv">$(HtmlEncode $r.SamlCertDetail)</span></div>
      <div><span class="dl">Provisioning</span><span class="dv">$(HtmlEncode $r.ProvDetail)</span></div>
      <div><span class="dl">Last admin change</span><span class="dv">$lastModHtml</span></div>
      <div class="wide"><span class="dl">Legacy APIs</span><span class="dv">$legacyHtml</span></div>
      <div class="wide"><span class="dl">App-only permissions ($($r.AppPermCount))</span><span class="dv">$permBadges</span></div>
      <div class="wide"><span class="dl">Delegated permissions ($($r.DelegatedPermCount))</span><span class="dv">$delegBadges</span></div>
    </div>
  </td>
</tr>
"@
}

$reportDate = $now.ToString('yyyy-MM-dd HH:mm')
$tenantDisplay = HtmlEncode $tenantName

# --- Executive summary fragment -------------------------------------------
$execHtml = if ($topRisk.Count -gt 0) {
    $items = for ($i = 0; $i -lt $topRisk.Count; $i++) {
        $t = $topRisk[$i]
        $rm = $riskMeta[$t.RiskBand]
        $factors = (Get-RiskFactors $t) -join ', '
        $entraUrl = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$($t.ObjectId)/appId/$($t.AppId)"
        $act = if ($t.Action) { HtmlEncode $t.Action } else { 'Review' }
        @"
    <div class="exec-row">
      <div class="exec-rank">$($i + 1)</div>
      <div class="exec-body">
        <div class="exec-name"><a class="applink" href="$entraUrl" target="_blank" rel="noopener">$(HtmlEncode $t.DisplayName)</a>
          <span class="badge $($rm.Class)">$($t.RiskBand) ($($t.RiskScore))</span></div>
        <div class="exec-why">$(HtmlEncode $factors)</div>
      </div>
      <div class="exec-action">$act</div>
    </div>
"@
    }
    @"
<div class="section-title">Executive summary — top risks</div>
<div class="panel exec">
$($items -join "`n")
</div>
"@
} else {
    @"
<div class="section-title">Executive summary</div>
<div class="panel exec"><div class="allclear">No apps scored Medium risk or above — the estate looks healthy.</div></div>
"@
}

# --- What-changed fragment --------------------------------------------------
$changesHtml = if ($changes) {
    $blocks = @()
    if ($changes.Added.Count -gt 0) {
        $names = (@($changes.Added | Select-Object -First 8 | ForEach-Object { HtmlEncode $_.DisplayName }) -join ', ')
        if ($changes.Added.Count -gt 8) { $names += " <span class=""dim"">(+$($changes.Added.Count - 8) more)</span>" }
        $blocks += "<div class=""chg""><span class=""chg-badge chg-new"">+$($changes.Added.Count) new</span> $names</div>"
    }
    if (@($changes.Removed).Count -gt 0) {
        $names = (@($changes.Removed | Select-Object -First 8 | ForEach-Object { HtmlEncode $_.n }) -join ', ')
        if (@($changes.Removed).Count -gt 8) { $names += " <span class=""dim"">(+$(@($changes.Removed).Count - 8) more)</span>" }
        $blocks += "<div class=""chg""><span class=""chg-badge chg-gone"">&minus;$(@($changes.Removed).Count) removed</span> $names</div>"
    }
    if ($changes.Staler.Count -gt 0) {
        $names = (@($changes.Staler | Select-Object -First 8 | ForEach-Object { "$(HtmlEncode $_.Row.DisplayName) <span class=""dim"">($($_.PrevBucket) &rarr; $($_.Row.Bucket))</span>" }) -join ', ')
        $blocks += "<div class=""chg""><span class=""chg-badge chg-stale"">$($changes.Staler.Count) went stale</span> $names</div>"
    }
    if ($changes.RiskUp.Count -gt 0) {
        $names = (@($changes.RiskUp | Select-Object -First 8 | ForEach-Object { "$(HtmlEncode $_.Row.DisplayName) <span class=""dim"">($($_.PrevScore) &rarr; $($_.Row.RiskScore))</span>" }) -join ', ')
        $blocks += "<div class=""chg""><span class=""chg-badge chg-risk"">$($changes.RiskUp.Count) risk jumped</span> $names</div>"
    }
    if ($blocks.Count -eq 0) { $blocks += '<div class="allclear">No notable changes since the last run.</div>' }
    @"
<div class="section-title">What changed since $(HtmlEncode $changes.PrevDate)</div>
<div class="panel">
$($blocks -join "`n")
</div>
"@
} else {
    @"
<div class="section-title">What changed</div>
<div class="panel"><div class="dim" style="font-size:12px;">First run — baseline snapshot created. Change tracking starts with the next report.</div></div>
"@
}

# --- Charts fragments (pure CSS, no external libraries) ---------------------
function New-ConicGradient {
    param($Items)   # array of @{ Count; Color }
    $total = 0; foreach ($i in $Items) { $total += $i.Count }
    if ($total -eq 0) { return 'conic-gradient(#dde9e9 0deg 360deg)' }
    $deg = 0.0; $parts = @()
    foreach ($i in $Items) {
        if ($i.Count -le 0) { continue }
        $end = $deg + (360.0 * $i.Count / $total)
        $parts += ('{0} {1}deg {2}deg' -f $i.Color, [Math]::Round($deg, 1), [Math]::Round($end, 1))
        $deg = $end
    }
    return 'conic-gradient(' + ($parts -join ', ') + ')'
}

$activityDonut = New-ConicGradient @(
    @{ Count = $counts.Active;  Color = '#16a34a' }
    @{ Count = $counts.Stale30; Color = '#d97706' }
    @{ Count = $counts.Stale60; Color = '#ea580c' }
    @{ Count = $counts.Stale90; Color = '#dc2626' }
    @{ Count = $counts.Never;   Color = '#5d7273' }
)

$riskCounts = @{
    Low      = @($rows | Where-Object RiskBand -eq 'Low').Count
    Medium   = @($rows | Where-Object RiskBand -eq 'Medium').Count
    High     = $counts.High
    Critical = $counts.Critical
}
$riskBarSegs = @()
foreach ($band in @(@('Critical','#dc2626'), @('High','#ea580c'), @('Medium','#d97706'), @('Low','#16a34a'))) {
    $c = $riskCounts[$band[0]]
    if ($c -gt 0 -and $counts.Total -gt 0) {
        $pct = [Math]::Round(100.0 * $c / $counts.Total, 1)
        $riskBarSegs += "<div class=""seg"" style=""width:$pct%;background:$($band[1]);"" title=""$($band[0]): $c""></div>"
    }
}
$riskBarHtml = if ($riskBarSegs.Count -gt 0) { $riskBarSegs -join '' } else { '<div class="seg" style="width:100%;background:#dde9e9;"></div>' }

$timelineHtml = if (@($credTimeline).Count -gt 0) {
    $shown = @($credTimeline | Select-Object -First 15)
    $items = foreach ($t in $shown) {
        $urg = if ($t.Days -lt 14) { 'tl-urgent' } elseif ($t.Days -lt 30) { 'tl-soon' } else { 'tl-ok' }
        "<div class=""tl-row""><span class=""tl-days $urg"">$($t.Days)d</span><span class=""tl-app"">$(HtmlEncode $t.App)</span><span class=""tl-type"">$(HtmlEncode $t.Type)</span><span class=""tl-date"">$($t.Expiry.ToString('yyyy-MM-dd'))</span></div>"
    }
    $more = if (@($credTimeline).Count -gt 15) { "<div class=""dim"" style=""font-size:11px;margin-top:6px;"">+$(@($credTimeline).Count - 15) more within 90 days — see CSV export</div>" } else { '' }
    ($items -join "`n") + $more
} else {
    '<div class="allclear">No credentials expire in the next 90 days.</div>'
}

# --- Risk trend fragment (needs 2+ runs of history) --------------------------
$trendHtml = ''
if (@($kpiHistory).Count -ge 2) {
    $maxRisk = 1
    foreach ($h in $kpiHistory) { $v = [int]$h.c + [int]$h.h; if ($v -gt $maxRisk) { $maxRisk = $v } }
    $trendBars = foreach ($h in $kpiHistory) {
        $v = [int]$h.c + [int]$h.h
        $hPct = [Math]::Max(6, [Math]::Round(100.0 * $v / $maxRisk))
        $lbl = ([datetime][string]$h.d).ToString('dd MMM')
        "<div class=""trend-col"" title=""$($h.d): $v critical+high of $($h.t) apps""><div class=""trend-bar"" style=""height:$hPct%""></div><div class=""trend-lbl"">$lbl</div></div>"
    }
    $trendHtml = @"
  <div class="panel">
    <h3>Critical + High risk — trend</h3>
    <div class="trend">$($trendBars -join '')</div>
  </div>
"@
}

# --- Data quality / telemetry fragment ---------------------------------------
function New-HealthRow {
    param($Name, $Status, $Detail)
    $cls = switch ($Status) { 'OK' { 'h-ok' } 'Partial' { 'h-warn' } 'Failed' { 'h-fail' } default { 'h-na' } }
    "<div class=""h-row""><span class=""h-status $cls"">$Status</span><span class=""h-name"">$(HtmlEncode $Name)</span><span class=""h-detail"">$(HtmlEncode $Detail)</span></div>"
}
$healthRows = @()
$healthRows += New-HealthRow 'Activity report' $telemetry.ActivityReport.Status "$($telemetry.ActivityReport.Records) records"
foreach ($k in $telemetry.SignInLogs.Keys) {
    $s = $telemetry.SignInLogs[$k]
    $st = if ($s.Status -ne 'OK') { 'Failed' } elseif ($s.Truncated) { 'Partial' } else { 'OK' }
    $det = "$($s.Events) events, $($s.Pages) page$(if ($s.Pages -ne 1) {'s'})"
    if ($s.Resumed) { $det += ", $($s.Resumed) resumed" }
    if ($s.Truncated) { $det += ' — truncated (newest kept)' }
    $healthRows += New-HealthRow "Sign-ins: $k" $st $det
}
$alSt = if ($telemetry.AuditLog.Status -ne 'OK') { 'Failed' } elseif ($telemetry.AuditLog.Truncated) { 'Partial' } else { 'OK' }
$healthRows += New-HealthRow 'Directory audits' $alSt "$($telemetry.AuditLog.Events) app events"
$dbSt = if ($telemetry.DetailBatches.InnerFailures -gt 0) { 'Partial' } else { 'OK' }
$healthRows += New-HealthRow 'Per-app detail' $dbSt "$($telemetry.DetailBatches.Total) batches, $($telemetry.DetailBatches.InnerFailures) failed lookups, $($telemetry.DetailBatches.Recovered) recovered on retry"
$healthRows += New-HealthRow 'App registrations' $telemetry.AppRegs.Status "$($telemetry.AppRegs.Count) credential sets merged"
$healthRows += New-HealthRow 'Delegated grants' $telemetry.DelegatedGrants.Status "$($telemetry.DelegatedGrants.Count) grants"
$gapNote = if ($counts.DataGaps -gt 0) { " · $($counts.DataGaps) apps have incomplete data (shown as ?)" } else { '' }
$throttleNote = "$($telemetry.Throttles) throttle retries · run time $([Math]::Round($swTotal.Elapsed.TotalMinutes, 1)) min$gapNote"
$healthHtml = @"
  <div class="panel">
    <h3>Data quality</h3>
$($healthRows -join "`n")
    <div class="dim" style="font-size:11px;margin-top:8px;">$throttleNote</div>
  </div>
"@

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AppLens by CloudEndpoint.ai — $reportDate</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%232e7d82'/><rect x='6' y='6' width='9' height='9' rx='2' fill='white' opacity='0.45'/><rect x='17' y='6' width='9' height='9' rx='2' fill='white' opacity='0.75'/><rect x='6' y='17' width='9' height='9' rx='2' fill='white' opacity='0.75'/><rect x='17' y='17' width='9' height='9' rx='2' fill='white'/></svg>">
<style>
  :root {
    /* CloudEndpoint.ai brand palette — teal with grid heritage */
    --bg:#f4f9f9; --card:#ffffff; --text:#152527; --muted:#5d7273; --border:#dde9e9;
    --brand:#2e7d82; --brand-2:#3a9da3; --brand-3:#225053; --brand-soft:#e6f2f2;
    --green:#16a34a; --amber:#d97706; --orange:#ea580c; --red:#dc2626; --grey:#5d7273;
    --blue:#2563eb; --purple:#3a9da3; --teal:#0d9488;
    --warn:#dc2626;
    --shadow-sm: 0 1px 2px rgba(21,37,39,.05), 0 1px 3px rgba(21,37,39,.07);
    --shadow-md: 0 4px 6px -1px rgba(21,37,39,.07), 0 2px 4px -2px rgba(21,37,39,.05);
  }
  * { box-sizing: border-box; }
  html, body { margin:0; padding:0; }
  body { font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:var(--bg); color:var(--text); -webkit-font-smoothing:antialiased; }

  /* Branded header bar — CloudEndpoint.ai teal gradient with grid motif overlay */
  .topbar { background:linear-gradient(135deg, #1e2a2b 0%, #225053 50%, #2e7d82 100%);
            color:white; padding:24px 32px; box-shadow:var(--shadow-md);
            position:relative; overflow:hidden; }
  .topbar::before {
    content:''; position:absolute; right:-40px; top:-30px; width:280px; height:280px;
    background-image:
      url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect x='6' y='6' width='40' height='40' rx='9' fill='none' stroke='white' stroke-width='2.5' opacity='0.18'/><rect x='54' y='6' width='40' height='40' rx='9' fill='none' stroke='white' stroke-width='2.5' opacity='0.10'/><rect x='6' y='54' width='40' height='40' rx='9' fill='none' stroke='white' stroke-width='2.5' opacity='0.10'/><rect x='54' y='54' width='40' height='40' rx='9' fill='none' stroke='white' stroke-width='2.5' opacity='0.18'/></svg>"),
      url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect x='10' y='10' width='80' height='80' rx='16' fill='none' stroke='white' stroke-width='2' opacity='0.08'/></svg>");
    background-size:150px 150px, 90px 90px;
    background-position:0 0, 100px 80px;
    background-repeat:no-repeat;
    pointer-events:none;
  }
  .topbar-inner { max-width:1600px; margin:0 auto; display:flex; align-items:center;
                  justify-content:space-between; gap:24px; flex-wrap:wrap;
                  position:relative; z-index:1; }
  .brand { display:flex; align-items:center; gap:14px; }
  .brand-logo { width:42px; height:42px; border-radius:10px;
                background:rgba(255,255,255,.16); display:flex; align-items:center;
                justify-content:center; backdrop-filter:blur(6px); }
  .brand-text h1 { margin:0; font-size:22px; font-weight:700; letter-spacing:-.01em; }
  .brand-text .tag { font-size:12px; opacity:.85; letter-spacing:.02em; }
  .topbar-meta { font-size:12px; opacity:.95; text-align:right; line-height:1.6; }
  .topbar-meta b { font-weight:600; }
  .topbar-meta .pill { display:inline-block; padding:3px 10px; background:rgba(255,255,255,.18);
                       border-radius:999px; margin-left:6px; font-weight:500; }

  /* Main content */
  main { max-width:1600px; margin:0 auto; padding:24px 32px 40px; }

  .section-title { font-size:11px; font-weight:600; color:var(--muted);
                   text-transform:uppercase; letter-spacing:.08em; margin:18px 0 10px; }

  .summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(135px,1fr));
             gap:12px; margin-bottom:8px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:10px;
          padding:14px 16px; cursor:pointer; transition:all .15s; box-shadow:var(--shadow-sm); }
  .card:hover { transform:translateY(-2px); box-shadow:var(--shadow-md); border-color:#cbd5e1; }
  .card.selected { border-color:var(--brand); box-shadow:0 0 0 2px rgba(46,125,130,.18); }
  .card .label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em;
                 font-weight:600; }
  .card .value { font-size:26px; font-weight:700; margin-top:4px; letter-spacing:-.02em; }
  .card.total .value    { color:var(--text); }
  .card.active .value   { color:var(--green); }
  .card.stale30 .value  { color:var(--amber); }
  .card.stale60 .value  { color:var(--orange); }
  .card.stale90 .value  { color:var(--red); }
  .card.never .value    { color:var(--grey); }
  .card.critical .value { color:var(--red); }
  .card.high .value     { color:var(--orange); }
  .card.saml .value     { color:var(--brand); }
  .card.cert .value     { color:var(--red); }
  .card.prov .value     { color:var(--orange); }
  .card.legacy .value   { color:var(--amber); }
  .card.agent .value    { color:var(--brand); }

  .controls { display:flex; gap:10px; align-items:center; margin:18px 0 12px; flex-wrap:wrap; }
  .controls input { padding:9px 13px; border:1px solid var(--border); border-radius:8px;
                    font-size:13px; min-width:280px; background:var(--card); box-shadow:var(--shadow-sm); }
  .controls input:focus { outline:none; border-color:var(--brand); box-shadow:0 0 0 3px rgba(46,125,130,.15); }
  .controls button { padding:9px 14px; border:1px solid var(--border); background:var(--card);
                     border-radius:8px; cursor:pointer; font-size:13px; font-weight:500;
                     box-shadow:var(--shadow-sm); transition:all .12s; color:var(--text); }
  .controls button:hover { border-color:var(--brand); color:var(--brand); }
  .controls button.primary { background:var(--brand); color:white; border-color:var(--brand); }
  .controls button.primary:hover { background:#1f5c60; }

  .table-wrap { overflow-x:auto; background:var(--card); border:1px solid var(--border);
                border-radius:10px; box-shadow:var(--shadow-sm); }
  table { width:100%; border-collapse:collapse; }
  th, td { padding:9px 12px; text-align:left; border-bottom:1px solid var(--border);
           font-size:12px; vertical-align:middle; white-space:nowrap; }
  th { background:#f8fafc; font-weight:600; cursor:pointer; user-select:none; position:sticky; top:0;
       color:var(--muted); text-transform:uppercase; font-size:10px; letter-spacing:.05em;
       border-bottom:2px solid var(--border); }
  th:hover { background:#eef2ff; color:var(--brand); }
  tr:last-child td { border-bottom:none; }
  tbody tr:hover { background:#fafbff; }
  .num { text-align:right; font-variant-numeric:tabular-nums; }
  .mono { font-family:ui-monospace,"SF Mono","Cascadia Mono",Menlo,monospace; font-size:11px;
          color:var(--muted); }
  .warn { color:var(--warn); font-weight:600; }
  .dim { color:#cbd5e1; }
  .badge { display:inline-block; padding:3px 9px; border-radius:999px; font-size:11px; font-weight:500;
           color:white; white-space:nowrap; letter-spacing:.01em; }
  .b-active{background:var(--green)} .b-stale30{background:var(--amber)} .b-stale60{background:var(--orange)}
  .b-stale90{background:var(--red)}  .b-never{background:var(--grey)}
  .c-none{background:var(--grey)} .c-na{background:#e2e8f0; color:#475569}
  .c-valid{background:var(--green)} .c-expiring60{background:var(--amber)}
  .c-expiring30{background:var(--orange)} .c-expired{background:var(--red)}
  .s-saml{background:var(--brand)} .s-oidc{background:var(--purple)} .s-password{background:var(--teal)}
  .s-external{background:#475569} .s-none{background:#e2e8f0; color:#475569}
  .p-none{background:#e2e8f0; color:#475569} .p-healthy{background:var(--green)}
  .p-paused{background:var(--amber)} .p-quarantine{background:var(--red)}
  .p-disabled{background:var(--grey)} .p-other{background:#475569}
  .r-low{background:var(--green)} .r-medium{background:var(--amber)}
  .r-high{background:var(--orange)} .r-critical{background:var(--red)}

  /* Panels (exec summary, changes, charts) */
  .panel { background:var(--card); border:1px solid var(--border); border-radius:10px;
           padding:16px 18px; box-shadow:var(--shadow-sm); margin-bottom:8px; }
  .panel h3 { margin:0 0 12px; font-size:13px; font-weight:600; color:var(--text); }
  .allclear { color:var(--green); font-size:13px; font-weight:500; }

  /* Executive summary */
  .exec-row { display:flex; align-items:center; gap:14px; padding:10px 0;
              border-bottom:1px solid var(--border); }
  .exec-row:last-child { border-bottom:none; }
  .exec-rank { width:28px; height:28px; border-radius:8px; background:var(--brand-soft);
               color:var(--brand); font-weight:700; font-size:13px; display:flex;
               align-items:center; justify-content:center; flex-shrink:0; }
  .exec-body { flex:1; min-width:0; }
  .exec-name { font-size:13px; font-weight:600; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .exec-why { font-size:12px; color:var(--muted); margin-top:2px; }
  .exec-action { font-size:12px; font-weight:600; color:var(--brand); text-align:right;
                 max-width:240px; flex-shrink:0; }

  /* What changed */
  .chg { font-size:12px; padding:7px 0; border-bottom:1px solid var(--border); line-height:1.8; }
  .chg:last-child { border-bottom:none; }
  .chg-badge { display:inline-block; padding:2px 9px; border-radius:999px; font-size:11px;
               font-weight:600; color:white; margin-right:8px; white-space:nowrap; }
  .chg-new   { background:var(--brand); }
  .chg-gone  { background:var(--grey); }
  .chg-stale { background:var(--orange); }
  .chg-risk  { background:var(--red); }

  /* At-a-glance charts */
  .glance { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:12px;
            margin-bottom:8px; }
  .donut-wrap { display:flex; align-items:center; gap:18px; }
  .donut { width:120px; height:120px; border-radius:50%; position:relative; flex-shrink:0; }
  .donut-hole { position:absolute; inset:22px; background:var(--card); border-radius:50%;
                display:flex; flex-direction:column; align-items:center; justify-content:center;
                font-size:22px; font-weight:700; }
  .donut-hole span { font-size:10px; font-weight:500; color:var(--muted); text-transform:uppercase; }
  .legend { font-size:12px; line-height:2; }
  .legend .swatch { display:inline-block; width:10px; height:10px; border-radius:3px;
                    margin-right:7px; vertical-align:middle; }
  .riskbar { display:flex; height:22px; border-radius:6px; overflow:hidden; margin-bottom:12px; }
  .riskbar .seg { min-width:3px; }

  /* Risk trend */
  .trend { display:flex; gap:6px; align-items:flex-end; height:100px; padding-top:6px; }
  .trend-col { flex:1; display:flex; flex-direction:column; justify-content:flex-end;
               align-items:center; height:100%; min-width:0; }
  .trend-bar { width:70%; background:var(--orange); border-radius:4px 4px 0 0; min-height:4px; }
  .trend-lbl { font-size:9px; color:var(--muted); margin-top:4px; white-space:nowrap; }

  /* Data quality */
  .h-row { display:flex; gap:10px; font-size:12px; padding:4px 0; align-items:center; }
  .h-status { width:52px; text-align:center; border-radius:6px; color:white; font-size:10px;
              font-weight:700; padding:2px 0; flex-shrink:0; }
  .h-ok { background:var(--green); } .h-warn { background:var(--amber); }
  .h-fail { background:var(--red); } .h-na { background:var(--grey); }
  .h-name { font-weight:600; min-width:130px; flex-shrink:0; }
  .h-detail { color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }

  /* Credential timeline */
  .tl-row { display:flex; align-items:center; gap:10px; font-size:12px; padding:5px 0;
            border-bottom:1px solid var(--border); }
  .tl-row:last-child { border-bottom:none; }
  .tl-days { width:44px; text-align:center; border-radius:6px; font-weight:700; font-size:11px;
             padding:3px 0; color:white; flex-shrink:0; }
  .tl-urgent { background:var(--red); } .tl-soon { background:var(--orange); } .tl-ok { background:var(--green); }
  .tl-app { flex:1; font-weight:500; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .tl-type { color:var(--muted); flex-shrink:0; }
  .tl-date { color:var(--muted); font-variant-numeric:tabular-nums; flex-shrink:0; }

  /* Table extras: links, action, expandable detail rows */
  .applink { color:var(--text); text-decoration:none; border-bottom:1px dotted #a9cdd0; }
  .applink:hover { color:var(--brand); border-bottom-color:var(--brand); }
  .caret { display:inline-block; color:var(--muted); font-size:10px; transition:transform .15s;
           cursor:pointer; }
  tr.main.expanded .caret { transform:rotate(90deg); }
  tr.main { cursor:pointer; }
  .action { font-size:11px; font-weight:600; color:var(--brand); white-space:normal; max-width:200px;
            display:inline-block; line-height:1.4; }
  .action.urgent { color:var(--red); }
  tr.detail td { background:var(--brand-soft); border-bottom:2px solid var(--brand);
                 padding:14px 18px; white-space:normal; }
  .detail-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:10px 24px; }
  .detail-grid .wide { grid-column:1 / -1; }
  .dl { display:block; font-size:10px; font-weight:600; color:var(--muted); text-transform:uppercase;
        letter-spacing:.05em; margin-bottom:2px; }
  .dv { font-size:12px; line-height:1.6; }
  .perm { display:inline-block; padding:2px 8px; border-radius:5px; background:#ddeeee;
          color:var(--brand); font-size:11px; font-weight:500; margin:2px 2px 2px 0;
          font-family:ui-monospace,"Cascadia Mono",Menlo,monospace; }
  .perm.dangerous { background:#fde8e8; color:var(--red); font-weight:700; }
  .perm.legacy { background:#fff4e0; color:#b45309; }

  footer { margin:32px auto 24px; max-width:1600px; padding:0 32px;
           color:var(--muted); font-size:11px; text-align:center; line-height:1.7; }
  footer .brand-mini { color:var(--brand); font-weight:600; }
  @media print {
    .controls, .topbar { display:none; }
    body { padding:0; }
    .card { break-inside:avoid; }
  }
</style>
</head>
<body>
<div class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <div class="brand-logo">
        <!-- CloudEndpoint.ai grid with magnifier lens -->
        <svg width="30" height="30" viewBox="0 0 32 32" fill="none">
          <rect x="4" y="4" width="11" height="11" rx="3" fill="rgba(255,255,255,0.40)"/>
          <rect x="17" y="4" width="11" height="11" rx="3" fill="rgba(255,255,255,0.70)"/>
          <rect x="4" y="17" width="11" height="11" rx="3" fill="rgba(255,255,255,0.70)"/>
          <rect x="17" y="17" width="11" height="11" rx="3" fill="rgba(255,255,255,0.95)"/>
          <circle cx="15" cy="15" r="6.5" fill="none" stroke="white" stroke-width="2"/>
          <line x1="20" y1="20" x2="27" y2="27" stroke="white" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </div>
      <div class="brand-text">
        <h1>CloudEndpoint.ai <span style="font-weight:400;opacity:.85;">· AppLens</span></h1>
        <div class="tag">Enterprise App Insight for Microsoft 365 · cloudendpoint.ai</div>
      </div>
    </div>
    <div class="topbar-meta">
      <div><b>Tenant</b> <span class="pill">$tenantDisplay</span></div>
      <div><b>Generated</b> <span class="pill">$reportDate</span> <span class="pill">$($counts.Total) apps</span></div>
    </div>
  </div>
</div>

<main>
$execHtml

$changesHtml

<div class="section-title">At a glance</div>
<div class="glance">
  <div class="panel">
    <h3>Activity distribution</h3>
    <div class="donut-wrap">
      <div class="donut" style="background:$activityDonut;">
        <div class="donut-hole">$($counts.Total)<span>apps</span></div>
      </div>
      <div class="legend">
        <div><span class="swatch" style="background:#16a34a;"></span>Active &lt;30d — $($counts.Active)</div>
        <div><span class="swatch" style="background:#d97706;"></span>30-60d — $($counts.Stale30)</div>
        <div><span class="swatch" style="background:#ea580c;"></span>60-90d — $($counts.Stale60)</div>
        <div><span class="swatch" style="background:#dc2626;"></span>90+d — $($counts.Stale90)</div>
        <div><span class="swatch" style="background:#5d7273;"></span>Never — $($counts.Never)</div>
      </div>
    </div>
  </div>
  <div class="panel">
    <h3>Risk distribution</h3>
    <div class="riskbar">$riskBarHtml</div>
    <div class="legend">
      <div><span class="swatch" style="background:#dc2626;"></span>Critical — $($riskCounts.Critical)</div>
      <div><span class="swatch" style="background:#ea580c;"></span>High — $($riskCounts.High)</div>
      <div><span class="swatch" style="background:#d97706;"></span>Medium — $($riskCounts.Medium)</div>
      <div><span class="swatch" style="background:#16a34a;"></span>Low — $($riskCounts.Low)</div>
    </div>
  </div>
  <div class="panel">
    <h3>Credential expiries — next 90 days</h3>
$timelineHtml
  </div>
$trendHtml
$healthHtml
</div>

<div class="section-title">Overview</div>

<div class="summary">
  <div class="card total"    data-filter-type="bucket" data-filter="all">     <div class="label">Total</div>          <div class="value">$($counts.Total)</div></div>
  <div class="card active"   data-filter-type="bucket" data-filter="Active">  <div class="label">Active &lt; 30 d</div><div class="value">$($counts.Active)</div></div>
  <div class="card stale30"  data-filter-type="bucket" data-filter="Stale30"> <div class="label">30-60 d</div>        <div class="value">$($counts.Stale30)</div></div>
  <div class="card stale60"  data-filter-type="bucket" data-filter="Stale60"> <div class="label">60-90 d</div>        <div class="value">$($counts.Stale60)</div></div>
  <div class="card stale90"  data-filter-type="bucket" data-filter="Stale90"> <div class="label">90+ d</div>          <div class="value">$($counts.Stale90)</div></div>
  <div class="card never"    data-filter-type="bucket" data-filter="Never">   <div class="label">Never</div>          <div class="value">$($counts.Never)</div></div>
  <div class="card saml"     data-filter-type="sso"    data-filter="SAML">    <div class="label">SAML SSO apps</div>  <div class="value">$($counts.SamlApps)</div></div>
  <div class="card cert"     data-filter-type="cert"   data-filter="expiring"><div class="label">SAML cert &lt; 30 d</div><div class="value">$($counts.SamlExpiry)</div></div>
  <div class="card prov"     data-filter-type="prov"   data-filter="issues">  <div class="label">Provisioning issues</div><div class="value">$($counts.ProvIssues)</div></div>
  <div class="card legacy"   data-filter-type="legacy" data-filter="any" title="EWS: $($counts.Ews) · Azure AD Graph: $($counts.AadGraph)"><div class="label">Legacy API perms</div><div class="value">$($counts.Legacy)</div></div>
  <div class="card agent"    data-filter-type="agent"  data-filter="yes">   <div class="label">AI agents</div>      <div class="value">$($counts.Agents)</div></div>
  <div class="card critical" data-filter-type="risk"   data-filter="Critical"><div class="label">Critical risk</div>  <div class="value">$($counts.Critical)</div></div>
  <div class="card high"     data-filter-type="risk"   data-filter="High">    <div class="label">High risk</div>      <div class="value">$($counts.High)</div></div>
</div>

<div class="section-title">Applications</div>
<div class="controls">
  <input id="search" type="text" placeholder="Search by name, app ID, publisher...">
  <button id="reset">Clear filters</button>
  <button id="csv">Export visible as CSV</button>
  <button id="sortRisk" class="primary">Sort by risk &darr;</button>
</div>

<div class="table-wrap">
<table id="apps">
  <thead>
    <tr>
      <th data-sort="text">Display name</th>
      <th data-sort="text">Recommended action</th>
      <th data-sort="text">Source</th>
      <th data-sort="text">SSO mode</th>
      <th data-sort="text">SAML cert</th>
      <th data-sort="text">Provisioning</th>
      <th data-sort="text">Enabled</th>
      <th data-sort="text">Created</th>
      <th data-sort="text">Last sign-in</th>
      <th data-sort="num">Days inactive</th>
      <th data-sort="num">Users (${SignInLogDays}d)</th>
      <th data-sort="text">Activity</th>
      <th data-sort="text">API creds</th>
      <th data-sort="num">Owners</th>
      <th data-sort="num">Assigned</th>
      <th data-sort="num">App perms</th>
      <th data-sort="risk">Risk</th>
    </tr>
  </thead>
  <tbody>
$($tbody -join "`n")
  </tbody>
</table>
</div>

</main>

<footer>
  <div><span class="brand-mini">AppLens by CloudEndpoint.ai</span> · v$brandVersion</div>
  <div>Risk model: staleness · SAML cert expiry (heaviest) · API cred expiry · provisioning quarantine ·
  zero owners (agent identities excepted) · missing SSO notification email · high-privilege app permissions ·
  EWS / retired Azure AD Graph permissions · disabled · zero assignments</div>
  <div style="margin-top:4px;">Click any row to expand details · click an app name to open it in the Entra admin centre</div>
  <div style="margin-top:8px;opacity:.7;">© CloudEndpoint.ai · cloudendpoint.ai</div>
</footer>

<script>
  const tbody = document.querySelector('#apps tbody');
  const rows = Array.from(tbody.querySelectorAll('tr.main'));
  const search = document.getElementById('search');
  const noFilters = () => ({ bucket:'all', risk:'all', sso:'all', cert:'all', prov:'all', legacy:'all', agent:'all' });
  let filters = noFilters();

  function detailFor(r) {
    return tbody.querySelector('tr.detail[data-detail-for="' + r.dataset.idx + '"]');
  }

  function syncDetail(r) {
    const d = detailFor(r);
    if (!d) return;
    const visible = r.style.display !== 'none' && r.classList.contains('expanded');
    d.style.display = visible ? '' : 'none';
  }

  function applyFilters() {
    const q = search.value.toLowerCase();
    rows.forEach(r => {
      const d = detailFor(r);
      const okB = filters.bucket === 'all' || r.dataset.bucket === filters.bucket;
      const okR = filters.risk === 'all' || r.dataset.risk === filters.risk;
      const okS = filters.sso === 'all' || r.dataset.sso === filters.sso;
      const okC = filters.cert === 'all' ||
                  (filters.cert === 'expiring' && /Expired|<30d/i.test(r.children[4].textContent));
      const okP = filters.prov === 'all' ||
                  (filters.prov === 'issues' && /Quarantine|Disabled|Paused/i.test(r.children[5].textContent));
      const okL = filters.legacy === 'all' || (filters.legacy === 'any' && r.dataset.legacy !== '');
      const okA = filters.agent === 'all' || r.dataset.agent === filters.agent;
      const hay = (r.textContent + ' ' + (d ? d.textContent : '')).toLowerCase();
      const okT = !q || hay.includes(q);
      r.style.display = (okB && okR && okS && okC && okP && okL && okA && okT) ? '' : 'none';
      syncDetail(r);
    });
  }

  // Row click toggles the detail panel (links and badges keep working).
  rows.forEach(r => {
    r.addEventListener('click', e => {
      if (e.target.closest('a')) return;
      r.classList.toggle('expanded');
      syncDetail(r);
    });
  });

  document.querySelectorAll('.card').forEach(card => {
    card.addEventListener('click', () => {
      document.querySelectorAll('.card').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      const t = card.dataset.filterType, v = card.dataset.filter;
      filters = noFilters();
      if (v !== 'all') filters[t] = v;
      applyFilters();
    });
  });

  search.addEventListener('input', applyFilters);
  document.getElementById('reset').addEventListener('click', () => {
    search.value = '';
    filters = noFilters();
    document.querySelectorAll('.card').forEach(c => c.classList.remove('selected'));
    applyFilters();
  });

  function reorder(sorted) {
    sorted.forEach(r => {
      tbody.appendChild(r);
      const d = detailFor(r);
      if (d) tbody.appendChild(d);
    });
  }

  document.getElementById('sortRisk').addEventListener('click', () => {
    reorder(rows.slice().sort((a,b) => parseInt(b.dataset.score) - parseInt(a.dataset.score)));
  });

  document.querySelectorAll('th').forEach((th, idx) => {
    let asc = true;
    th.addEventListener('click', () => {
      const type = th.dataset.sort;
      const sorted = rows.slice().sort((a, b) => {
        if (type === 'risk') {
          const av = parseInt(a.dataset.score), bv = parseInt(b.dataset.score);
          return asc ? av - bv : bv - av;
        }
        let av = a.children[idx].textContent.trim();
        let bv = b.children[idx].textContent.trim();
        if (type === 'num') {
          av = parseFloat(av) || (asc ? Infinity : -Infinity);
          bv = parseFloat(bv) || (asc ? Infinity : -Infinity);
          return asc ? av - bv : bv - av;
        }
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      reorder(sorted);
      asc = !asc;
    });
  });

  // App names are publisher-controlled: drop the expand caret and prefix
  // anything Excel would evaluate as a formula (=, +, -, @, tab, CR).
  function csvCell(text) {
    let s = text.replace(/^▸\s*/, '').trim();
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }

  document.getElementById('csv').addEventListener('click', () => {
    const headers = Array.from(document.querySelectorAll('#apps thead th')).map(h => csvCell(h.textContent));
    const visible = rows.filter(r => r.style.display !== 'none');
    const lines = [headers.join(',')].concat(visible.map(r =>
      Array.from(r.children).map(td => csvCell(td.textContent)).join(',')
    ));
    const blob = new Blob([lines.join('\n')], { type:'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'applens-export.csv';
    a.click();
  });
</script>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkCyan
Write-Host "   AppLens by CloudEndpoint.ai — report ready" -ForegroundColor White
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkCyan
Write-Host ("   File: {0}" -f $OutputPath) -ForegroundColor Green
$sourceReport = ($rows | Where-Object SignInSource -eq 'Activity report').Count
$sourceLog    = ($rows | Where-Object SignInSource -eq 'Sign-in log').Count
Write-Host ""
Write-Host ("   Sources    Activity report {0} · Sign-in log {1} · No data {2}" -f `
    $sourceReport, $sourceLog, ($counts.Total - $sourceReport - $sourceLog)) -ForegroundColor DarkGray
Write-Host ("   Activity   Active {0} · 30-60d {1} · 60-90d {2} · 90d+ {3} · Never {4}" -f `
    $counts.Active, $counts.Stale30, $counts.Stale60, $counts.Stale90, $counts.Never) -ForegroundColor Cyan
Write-Host ("   SSO/SAML   SAML apps {0} · SAML cert <30d {1} · Provisioning issues {2}" -f `
    $counts.SamlApps, $counts.SamlExpiry, $counts.ProvIssues) -ForegroundColor Cyan
Write-Host ("   Risk       Critical {0} · High {1}" -f $counts.Critical, $counts.High) -ForegroundColor Cyan
Write-Host ("   Legacy     EWS {0} · Azure AD Graph {1} · AI agents {2}" -f $counts.Ews, $counts.AadGraph, $counts.Agents) -ForegroundColor Cyan
if ($changes) {
    Write-Host ("   Changes    +{0} new · -{1} removed · {2} went stale · {3} risk jumped (vs {4})" -f `
        $changes.Added.Count, @($changes.Removed).Count, $changes.Staler.Count, $changes.RiskUp.Count, $changes.PrevDate) -ForegroundColor Yellow
} else {
    Write-Host "   Changes    baseline created — tracking starts next run" -ForegroundColor DarkGray
}
Write-Host ("   Telemetry  Throttle retries {0} · Failed lookups {1} · Data gaps {2} apps · Runtime {3} min" -f `
    $telemetry.Throttles, $telemetry.DetailBatches.InnerFailures, $counts.DataGaps, [Math]::Round($swTotal.Elapsed.TotalMinutes, 1)) -ForegroundColor DarkGray
Write-Host ""

# ---------------------------------------------------------------------------
# Email delivery (Azure Automation or any scheduled run)
# ---------------------------------------------------------------------------
if ($SendEmail) {
    if (-not $SenderUpn -or -not $RecipientUpns -or $RecipientUpns.Count -eq 0) {
        throw "-SendEmail requires both -SenderUpn and -RecipientUpns to be set."
    }

    $htmlBytes = [System.IO.File]::ReadAllBytes($OutputPath)
    $sizeMB    = [Math]::Round($htmlBytes.Length / 1MB, 2)
    Write-Output "Report size: $sizeMB MB"

    $monthYear   = $now.ToString('MMMM yyyy')
    $attachName  = "AppLens-$($now.ToString('yyyy-MM')).html"
    $attachContentType = 'text/html'
    $attachBytes = $htmlBytes

    # Graph SendMail caps the whole request at 4 MB and base64 inflates the
    # attachment by a third — zip well before that (HTML compresses ~10x).
    if ($htmlBytes.Length -gt 2MB) {
        try {
            $zipPath = [System.IO.Path]::ChangeExtension($OutputPath, '.zip')
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
            Compress-Archive -Path $OutputPath -DestinationPath $zipPath -Force
            $attachBytes = [System.IO.File]::ReadAllBytes($zipPath)
            $attachName  = [System.IO.Path]::ChangeExtension($attachName, '.zip')
            $attachContentType = 'application/zip'
            Write-Output ("Report compressed for email: {0} MB zip" -f [Math]::Round($attachBytes.Length / 1MB, 2))
        } catch {
            Write-Warning "Compression failed — attaching raw HTML: $($_.Exception.Message)"
        }
    }
    if ($attachBytes.Length -gt 2.8MB) {
        Write-Warning "Attachment still exceeds 2.8 MB (~3.7 MB encoded) — send may fail."
    }
    $base64 = [Convert]::ToBase64String($attachBytes)

    # One-line data quality verdict for the email footer.
    $dqIssues = @()
    if ($telemetry.ActivityReport.Status -ne 'OK') { $dqIssues += 'activity report' }
    foreach ($k in $telemetry.SignInLogs.Keys) {
        $s = $telemetry.SignInLogs[$k]
        if ($s.Status -ne 'OK' -or $s.Truncated) { $dqIssues += "sign-ins ($k)" }
    }
    if ($telemetry.AuditLog.Status -ne 'OK') { $dqIssues += 'directory audits' }
    if ($telemetry.DetailBatches.InnerFailures -gt 0) { $dqIssues += "$($telemetry.DetailBatches.InnerFailures) detail lookups" }
    if ($telemetry.AppRegs.Status -ne 'OK') { $dqIssues += 'app registrations' }
    if ($telemetry.DelegatedGrants.Status -ne 'OK') { $dqIssues += 'delegated grants' }
    $dqLine = if ($dqIssues.Count -eq 0) { 'Data quality: all sources OK' } else { 'Data quality: check report — issues with ' + ($dqIssues -join ', ') }
    $changesEmailRow = if ($changes) {
        $chgText = "+$($changes.Added.Count) new &middot; &minus;$(@($changes.Removed).Count) removed &middot; $($changes.Staler.Count) went stale"
        "<tr><td style=""padding:7px 10px;border-bottom:1px solid #e3efef;"">Changes since last run</td><td style=""padding:7px 10px;border-bottom:1px solid #e3efef;text-align:right;font-weight:600;"">$chgText</td></tr>"
    } else { '' }
    $emailBody = @"
<!doctype html>
<html><body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#152527;max-width:620px;margin:0 auto;background:#f4f9f9;padding:20px;">
  <div style="background:linear-gradient(135deg,#1e2a2b,#225053,#2e7d82);color:white;padding:22px 26px;border-radius:10px 10px 0 0;position:relative;overflow:hidden;">
    <table style="width:100%;border-collapse:collapse;">
      <tr>
        <td style="vertical-align:middle;width:48px;">
          <div style="width:42px;height:42px;border-radius:10px;background:rgba(255,255,255,.16);text-align:center;line-height:42px;">
            <svg width="26" height="26" viewBox="0 0 32 32" fill="none" style="vertical-align:middle;">
              <rect x="4" y="4" width="11" height="11" rx="3" fill="rgba(255,255,255,0.40)"/>
              <rect x="17" y="4" width="11" height="11" rx="3" fill="rgba(255,255,255,0.70)"/>
              <rect x="4" y="17" width="11" height="11" rx="3" fill="rgba(255,255,255,0.70)"/>
              <rect x="17" y="17" width="11" height="11" rx="3" fill="rgba(255,255,255,0.95)"/>
              <circle cx="15" cy="15" r="6.5" fill="none" stroke="white" stroke-width="2"/>
              <line x1="20" y1="20" x2="27" y2="27" stroke="white" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </div>
        </td>
        <td style="vertical-align:middle;padding-left:14px;">
          <h2 style="margin:0;font-size:20px;font-weight:700;letter-spacing:-.01em;">CloudEndpoint.ai · AppLens</h2>
          <div style="font-size:12px;opacity:.9;margin-top:3px;">Monthly report — $monthYear</div>
        </td>
      </tr>
    </table>
  </div>
  <div style="border:1px solid #dde9e9;border-top:none;padding:22px 26px;border-radius:0 0 10px 10px;background:white;">
    <p style="margin-top:0;">Your monthly enterprise application audit is attached. Headline figures for <code style="background:#e6f2f2;padding:2px 6px;border-radius:4px;color:#2e7d82;">$(HtmlEncode $tenantName)</code>:</p>
    <table style="border-collapse:collapse;width:100%;margin:14px 0;font-size:13px;">
      <tr><td style="padding:7px 10px;border-bottom:1px solid #e3efef;">Total apps</td><td style="padding:7px 10px;border-bottom:1px solid #e3efef;text-align:right;font-weight:600;">$($counts.Total)</td></tr>
      <tr><td style="padding:7px 10px;border-bottom:1px solid #e3efef;">Critical risk</td><td style="padding:7px 10px;border-bottom:1px solid #e3efef;text-align:right;font-weight:700;color:#dc2626;">$($counts.Critical)</td></tr>
      <tr><td style="padding:7px 10px;border-bottom:1px solid #e3efef;">High risk</td><td style="padding:7px 10px;border-bottom:1px solid #e3efef;text-align:right;font-weight:700;color:#ea580c;">$($counts.High)</td></tr>
      <tr><td style="padding:7px 10px;border-bottom:1px solid #e3efef;">SAML cert &lt; 30d</td><td style="padding:7px 10px;border-bottom:1px solid #e3efef;text-align:right;font-weight:700;color:#dc2626;">$($counts.SamlExpiry)</td></tr>
      <tr><td style="padding:7px 10px;border-bottom:1px solid #e3efef;">Provisioning issues</td><td style="padding:7px 10px;border-bottom:1px solid #e3efef;text-align:right;font-weight:600;">$($counts.ProvIssues)</td></tr>
      <tr><td style="padding:7px 10px;border-bottom:1px solid #e3efef;">Apps with EWS permissions (being switched off)</td><td style="padding:7px 10px;border-bottom:1px solid #e3efef;text-align:right;font-weight:700;color:#d97706;">$($counts.Ews)</td></tr>
      <tr><td style="padding:7px 10px;border-bottom:1px solid #e3efef;">Active &lt; 30d</td><td style="padding:7px 10px;border-bottom:1px solid #e3efef;text-align:right;font-weight:600;color:#16a34a;">$($counts.Active)</td></tr>
      <tr><td style="padding:7px 10px;border-bottom:1px solid #e3efef;">Stale 90+ d / Never</td><td style="padding:7px 10px;border-bottom:1px solid #e3efef;text-align:right;font-weight:600;color:#5d7273;">$($counts.Stale90 + $counts.Never)</td></tr>
      $changesEmailRow
    </table>
    <p>Open the attached <code style="background:#e6f2f2;padding:2px 6px;border-radius:4px;color:#2e7d82;">$attachName</code> in any browser for the full interactive report — filter, sort, click cards to drill in, export to CSV.</p>
    <hr style="border:none;border-top:1px solid #dde9e9;margin:22px 0 14px;">
    <div style="font-size:11px;color:#5d7273;line-height:1.7;">
      <b style="color:#2e7d82;">AppLens by CloudEndpoint.ai v$brandVersion</b><br>
      cloudendpoint.ai · Sent by Azure Automation<br>
      $dqLine<br>
      Next scheduled run: first Monday of $($now.AddMonths(1).ToString('MMMM yyyy'))
    </div>
  </div>
</body></html>
"@

    $recipients = @($RecipientUpns | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    $messageBody = @{
        message = @{
            subject      = "AppLens by CloudEndpoint.ai — $monthYear Report"
            body         = @{ contentType = 'HTML'; content = $emailBody }
            toRecipients = $recipients
            attachments  = @(
                @{
                    '@odata.type' = '#microsoft.graph.fileAttachment'
                    name          = $attachName
                    contentType   = $attachContentType
                    contentBytes  = $base64
                }
            )
        }
        saveToSentItems = $true
    }
    $jsonBody = $messageBody | ConvertTo-Json -Depth 10

    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/users/$SenderUpn/sendMail" `
            -Body $jsonBody -ContentType 'application/json'
        Write-Output ("Email sent from {0} to: {1}" -f $SenderUpn, ($RecipientUpns -join ', '))
    } catch {
        Write-Error "Failed to send email: $($_.Exception.Message)"
        throw
    }
}

# Auto-open the report when running interactively (skip in Automation).
if (-not $inAutomation) {
    try { Start-Process $OutputPath } catch { Write-Host "  (Open the file manually)" -ForegroundColor Yellow }
}

# Graph SDK 2.40 warns that it can't clear its token cache on disconnect even
# when the disconnect worked — keep that noise out of the run output.
Disconnect-MgGraph -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

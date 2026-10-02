<#
.SYNOPSIS
    Bootstraps the Azure infrastructure needed to run AppLens by CloudEndpoint.ai
    monthly from Azure Automation. Creates the resource group, automation account,
    imports the required modules, uploads the runbook, and schedules it.

.DESCRIPTION
    Run this ONCE to provision everything. It does not grant Graph permissions
    to the Managed Identity — that step requires a Global Admin and is covered
    in APPLENS-AUTOMATION-SETUP.md (a PowerShell snippet is printed at the end).

    Idempotent: safe to re-run; existing resources are reused.

.PARAMETER SubscriptionId
    Azure subscription that will host the Automation Account.

.PARAMETER ResourceGroupName
    Resource group to create or reuse.

.PARAMETER Location
    Azure region (e.g. uksouth, westeurope, eastus).

.PARAMETER AutomationAccountName
    Name for the Automation Account.

.PARAMETER RunbookName
    Name of the runbook inside the account.

.PARAMETER ScheduleName
    Name of the monthly schedule.

.PARAMETER SenderUpn
    The mailbox that sends the report (must exist and have Mail.Send permission).

.PARAMETER RecipientUpns
    Array of admin email addresses to receive the report.

.PARAMETER ScriptPath
    Path to Get-EnterpriseAppReport.ps1 (defaults to next to this script).

.PARAMETER GraphModuleVersion
    Microsoft Graph module version to import (all three modules use the same
    one). Defaults to the latest on the PowerShell Gallery at setup time.
    Re-running with a different version upgrades or rolls back the account.

.NOTES
    Requires the Az PowerShell module: Install-Module Az -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SubscriptionId,
    [string]$TenantId,
    [string]$ResourceGroupName     = 'rg-applens',
    [string]$Location              = 'uksouth',
    # Automation Account names are reserved in the region for ~30 days after
    # deletion, which causes "Conflict" errors on re-runs. Default to a short
    # hex suffix to dodge that.
    [string]$AutomationAccountName = "aa-applens-$([guid]::NewGuid().ToString('N').Substring(0,4))",
    [string]$RunbookName           = 'AppLens-MonthlyReport',
    [string]$ScheduleName          = 'AppLens-Monthly',
    [Parameter(Mandatory)] [string]$SenderUpn,
    [Parameter(Mandatory)] [string[]]$RecipientUpns,
    [string]$ScriptPath,           # default: Get-EnterpriseAppReport.ps1 next to this script
    [string]$GraphModuleVersion    # default: latest on PSGallery, pinned for all three modules
)

$ErrorActionPreference = 'Stop'

# Resolved here, not in param(): Windows PowerShell 5.1 leaves $PSScriptRoot
# empty inside parameter defaults.
if (-not $ScriptPath) {
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $ScriptPath = Join-Path $here 'Get-EnterpriseAppReport.ps1'
}

function Ensure-AzModule {
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host "Installing Az PowerShell module (this may take a few minutes)..." -ForegroundColor Yellow
        Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module Az.Accounts, Az.Resources, Az.Automation -ErrorAction Stop
}

function Write-Step { param([string]$msg) Write-Host "==> $msg" -ForegroundColor Cyan }

# ---------------------------------------------------------------------------
Write-Step "Checking prerequisites"
Ensure-AzModule
if (-not (Test-Path $ScriptPath)) {
    throw "Cannot find runbook source script at: $ScriptPath"
}

# ---------------------------------------------------------------------------
Write-Step "Signing in to Azure"
# Suppress the noisy cross-tenant token warnings — we only care about ours.
$prevWarn = $WarningPreference
$WarningPreference = 'SilentlyContinue'
try {
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    $needConnect = -not $ctx -or $ctx.Subscription.Id -ne $SubscriptionId
    if ($needConnect) {
        if ($TenantId) {
            Connect-AzAccount -SubscriptionId $SubscriptionId -TenantId $TenantId | Out-Null
        } else {
            Connect-AzAccount -SubscriptionId $SubscriptionId | Out-Null
        }
    }
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
} finally {
    $WarningPreference = $prevWarn
}
Write-Host "  Subscription: $((Get-AzContext).Subscription.Name)"
Write-Host "  Tenant:       $((Get-AzContext).Tenant.Id)"
Write-Host "  Account:      $((Get-AzContext).Account.Id)"

# ---------------------------------------------------------------------------
Write-Step "Resource group: $ResourceGroupName"
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
    Write-Host "  Created."
} else { Write-Host "  Exists." }

# ---------------------------------------------------------------------------
# Reuse any Automation Account already in the RG so re-runs (with a different
# random suffix) don't create duplicates.
$existingAAs = @(Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
if ($existingAAs.Count -gt 0) {
    $aa = $existingAAs[0]
    $AutomationAccountName = $aa.AutomationAccountName
    Write-Step "Automation account: $AutomationAccountName (reusing existing)"
} else {
    Write-Step "Automation account: $AutomationAccountName"
}

if (-not $aa) {
    try {
        $aa = New-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName `
            -Location $Location -AssignSystemIdentity
        Write-Host "  Created with System Managed Identity."
    } catch {
        if ($_.Exception.Message -match 'Conflict|already exists|reserved') {
            Write-Host ""
            Write-Host "  Conflict: the name '$AutomationAccountName' is in use OR reserved" -ForegroundColor Red
            Write-Host "  by Azure (Automation Account names are held for ~30 days after deletion)." -ForegroundColor Red
            Write-Host ""
            Write-Host "  Re-run with a unique name, e.g.:" -ForegroundColor Yellow
            Write-Host "    -AutomationAccountName 'aa-applens-$([guid]::NewGuid().ToString('N').Substring(0,6))'" -ForegroundColor White
            Write-Host ""
            throw
        }
        throw
    }
} else {
    Write-Host "  Exists."
    if (-not $aa.Identity -or -not $aa.Identity.PrincipalId) {
        Write-Host "  Enabling System Managed Identity..."
        $aa = Set-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -AssignSystemIdentity
    }
}
$miObjectId = $aa.Identity.PrincipalId
Write-Host "  Managed Identity Object ID: $miObjectId"

# ---------------------------------------------------------------------------
Write-Step "Importing required PowerShell modules into the Automation Account"
# All three modules must be the SAME version (Applications and Reports require
# the exact Authentication version), so resolve one version and pin it.
if (-not $GraphModuleVersion) {
    try {
        $GraphModuleVersion = [string](Find-Module -Name 'Microsoft.Graph.Authentication' -Repository PSGallery -ErrorAction Stop).Version
    } catch {
        throw "Could not look up the latest Microsoft Graph module on the PowerShell Gallery — re-run with -GraphModuleVersion (e.g. 2.40.0). $($_.Exception.Message)"
    }
}
Write-Host "  Microsoft Graph modules pinned to v$GraphModuleVersion"

function Import-GraphModuleWave {
    param([string[]]$Names)
    $started = @()
    foreach ($m in $Names) {
        $existing = Get-AzAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $m -ErrorAction SilentlyContinue
        if ($existing -and $existing.ProvisioningState -eq 'Succeeded' -and [string]$existing.Version -eq $GraphModuleVersion) {
            Write-Host "  $m v$GraphModuleVersion — already imported"
            continue
        }
        $from = if ($existing -and $existing.Version) { " (replacing v$($existing.Version))" } else { '' }
        Write-Host "  Importing $m v$GraphModuleVersion$from (5-10 minutes)..." -ForegroundColor Yellow
        # New-AzAutomationModule downloads + provisions straight from the Gallery
        $contentLink = "https://www.powershellgallery.com/api/v2/package/$m/$GraphModuleVersion"
        New-AzAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
            -Name $m -ContentLinkUri $contentLink | Out-Null
        $started += $m
    }
    if ($started.Count -eq 0) { return }

    Write-Host "  Waiting for module imports to complete..." -ForegroundColor Yellow
    $timeout = (Get-Date).AddMinutes(30)
    do {
        Start-Sleep -Seconds 20
        $states = @($started | ForEach-Object {
            (Get-AzAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $_).ProvisioningState
        })
        Write-Host ("    States: {0}" -f ($states -join ', '))
        $allDone = -not ($states | Where-Object { $_ -notin 'Succeeded','Failed' })
    } until ($allDone -or (Get-Date) -gt $timeout)

    $failed = @($started | Where-Object {
        (Get-AzAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $_).ProvisioningState -ne 'Succeeded'
    })
    if ($failed.Count -gt 0) { throw "Module import failed or timed out for: $($failed -join ', ')" }
}

# Authentication first — the other two declare it as a dependency.
Import-GraphModuleWave -Names @('Microsoft.Graph.Authentication')
Import-GraphModuleWave -Names @('Microsoft.Graph.Applications', 'Microsoft.Graph.Reports')

# ---------------------------------------------------------------------------
Write-Step "Uploading runbook: $RunbookName"
$existingRb = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -ErrorAction SilentlyContinue
if (-not $existingRb) {
    Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
        -Name $RunbookName -Type PowerShell -Path $ScriptPath | Out-Null
    Write-Host "  Imported."
} else {
    Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
        -Name $RunbookName -Type PowerShell -Path $ScriptPath -Force | Out-Null
    Write-Host "  Updated."
}
Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName | Out-Null
Write-Host "  Published."

# ---------------------------------------------------------------------------
Write-Step "Snapshot variable for month-over-month change tracking"
$snapVarName = 'AppLens-Snapshot'
$existingVar = Get-AzAutomationVariable -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $snapVarName -ErrorAction SilentlyContinue
if (-not $existingVar) {
    New-AzAutomationVariable -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
        -Name $snapVarName -Value '' -Encrypted $false | Out-Null
    Write-Host "  Created '$snapVarName'."
} else { Write-Host "  Exists." }

# ---------------------------------------------------------------------------
Write-Step "Monthly schedule: $ScheduleName"
$existingSched = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ScheduleName -ErrorAction SilentlyContinue
if (-not $existingSched) {
    # First Monday of next month at 09:00 local UK time
    $startTime = (Get-Date -Hour 9 -Minute 0 -Second 0).AddDays(1)
    while ($startTime.DayOfWeek -ne 'Monday' -or $startTime.Day -gt 7) {
        $startTime = $startTime.AddDays(1)
    }
    New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
        -Name $ScheduleName -StartTime $startTime -MonthInterval 1 -DayOfWeek Monday -DayOfWeekOccurrence First `
        -TimeZone 'Europe/London' | Out-Null
    Write-Host "  Created (first Monday of each month at 09:00 UK time, next run: $startTime)."
} else {
    Write-Host "  Exists."
}

# ---------------------------------------------------------------------------
Write-Step "Linking schedule to runbook with default parameters"
$params = @{
    SendEmail       = $true
    SenderUpn       = $SenderUpn
    RecipientUpns   = $RecipientUpns
}
$existingJob = Get-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName -ScheduleName $ScheduleName -ErrorAction SilentlyContinue
if ($existingJob) {
    Unregister-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -JobScheduleId $existingJob.JobScheduleId -Force
}
Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
    -RunbookName $RunbookName -ScheduleName $ScheduleName -Parameters $params | Out-Null
Write-Host "  Linked."

# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkCyan
Write-Host "   AppLens by CloudEndpoint.ai — Azure ready" -ForegroundColor White
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Next step: grant the Managed Identity its permissions." -ForegroundColor Yellow
Write-Host "  This needs a Global Admin (Graph) and an Exchange Admin (Mail.Send). Either:" -ForegroundColor Yellow
Write-Host "    1. Follow APPLENS-AUTOMATION-SETUP.md, OR" -ForegroundColor Yellow
Write-Host "    2. Run the two PowerShell snippets below." -ForegroundColor Yellow
Write-Host ""
Write-Host "  ────────── GRAPH PERMISSIONS (Global Admin) ──────────" -ForegroundColor Cyan
$snippet = @"
# Run this as a Global Admin to grant Graph permissions to the
# AppLens (CloudEndpoint.ai) Managed Identity.
Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All'

`$miObjectId = '$miObjectId'
`$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
# Mail.Send is deliberately NOT granted here — it's granted scoped to the
# sender mailbox via Exchange RBAC for Applications (next snippet).
`$perms = @('Application.Read.All','AuditLog.Read.All','Directory.Read.All','Synchronization.Read.All')

foreach (`$p in `$perms) {
    `$role = `$graphSp.AppRoles | Where-Object { `$_.Value -eq `$p -and `$_.AllowedMemberTypes -contains 'Application' }
    if (-not `$role) { Write-Warning "Permission '`$p' not found"; continue }
    `$existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId `$miObjectId | Where-Object { `$_.AppRoleId -eq `$role.Id }
    if (`$existing) { Write-Host "  `$p — already granted"; continue }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId `$miObjectId -PrincipalId `$miObjectId -ResourceId `$graphSp.Id -AppRoleId `$role.Id | Out-Null
    Write-Host "  Granted: `$p" -ForegroundColor Green
}
"@
Write-Host $snippet -ForegroundColor White
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""

# Mail.Send via RBAC for Applications, scoped to the sender mailbox only.
# (Application Access Policies are legacy — Microsoft says not to create new ones.)
$miAppId = '<managed-identity-application-id>'
try { $miAppId = (Get-AzADServicePrincipal -ObjectId $miObjectId -ErrorAction Stop).AppId } catch { }
Write-Host "  ────────── MAIL.SEND SCOPING (Exchange Administrator) ──────────" -ForegroundColor Cyan
$exoSnippet = @"
# Run this as an Exchange Administrator. Grants Mail.Send on the sender
# mailbox ONLY, using Exchange RBAC for Applications.
Connect-ExchangeOnline

New-ServicePrincipal -AppId '$miAppId' -ObjectId '$miObjectId' -DisplayName '$AutomationAccountName'
New-ManagementScope -Name '$RunbookName sender' -RecipientRestrictionFilter "UserPrincipalName -eq '$SenderUpn'"
New-ManagementRoleAssignment -App '$miObjectId' -Role 'Application Mail.Send' -CustomResourceScope '$RunbookName sender'

# Verify: InScope should be True for the sender, False for anyone else.
Test-ServicePrincipalAuthorization -Identity '$miObjectId' -Resource '$SenderUpn'
"@
Write-Host $exoSnippet -ForegroundColor White
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Once permissions are granted (Exchange can take up to 2 hours to apply), test with:" -ForegroundColor Yellow
Write-Host "    Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName ``" -ForegroundColor White
Write-Host "      -AutomationAccountName $AutomationAccountName -Name $RunbookName ``" -ForegroundColor White
Write-Host "      -Parameters @{ SendEmail=`$true; SenderUpn='$SenderUpn'; RecipientUpns=@('$($RecipientUpns -join "','")') }" -ForegroundColor White
Write-Host ""

# AppLens — Azure Automation Setup Guide

This guide walks through setting up **AppLens** to run automatically every month from Azure Automation and email the report to your admin team.

---

## What you'll end up with

- An **Azure Automation Account** running the AppLens runbook on a monthly schedule (first Monday of each month, 09:00 UK time)
- A **System-Assigned Managed Identity** that authenticates to Microsoft Graph with no stored credentials
- A **branded HTML report** delivered as an email attachment to your admin distribution list
- **Mail.Send scoped to one mailbox** (via Exchange RBAC for Applications) so the Managed Identity can only send from `applens@yourdomain.com` (or whichever sender you choose)

---

## Prerequisites

| Item | Why |
|---|---|
| **Azure subscription** | Hosts the Automation Account |
| **Global Administrator** access | Required to grant Graph application permissions to the Managed Identity |
| **Exchange Administrator** access | Required to grant `Mail.Send` scoped to one mailbox |
| **A dedicated sending mailbox** | e.g. `applens@yourdomain.com` — must be a real licensed mailbox or a shared mailbox |
| **PowerShell 7+** with the `Az` module | For running the bootstrap script |
| **Entra ID P1 or P2** licence | The sign-in activity report requires it |

---

## Step 1 — Run the bootstrap script

From a PowerShell 7+ session on your workstation:

```powershell
cd "C:\path\to\EnterpriseAppReport"

.\Setup-AppLensAutomation.ps1 `
    -SubscriptionId    '<your-subscription-guid>' `
    -SenderUpn         'applens@yourdomain.com' `
    -RecipientUpns     @('admin1@yourdomain.com','admin2@yourdomain.com') `
    -Location          'uksouth'      # optional, default uksouth
```

What it does:
1. Creates a resource group `rg-applens`
2. Creates an Automation Account `aa-applens-XXXX` (random suffix to dodge name reservations) with a System Managed Identity
3. Imports the three Microsoft Graph modules, all pinned to the same version — Authentication first, as the other two depend on it (10-15 minutes — modules are large). Defaults to the latest on the PowerShell Gallery; pass `-GraphModuleVersion '2.40.0'` to pin a specific one. Re-running with a newer version upgrades the account.
4. Uploads `Get-EnterpriseAppReport.ps1` as a runbook called `AppLens-MonthlyReport`
5. Creates the `AppLens-Snapshot` Automation Variable used for month-over-month change tracking
6. Creates a monthly schedule (first Monday at 09:00 UK time)
7. Links the schedule to the runbook with your sender/recipient parameters
8. Prints out the **permission scripts** for Steps 2 and 3, pre-filled with your Managed Identity's IDs

> Idempotent — safe to re-run. Existing resources are reused.

---

## Step 2 — Grant Graph permissions to the Managed Identity

The bootstrap script prints a ready-to-run snippet. **Run it as a Global Admin** in a separate PowerShell session. It grants the following Graph application permissions:

| Permission | Why |
|---|---|
| `Application.Read.All` | List enterprise apps, owners, app role assignments |
| `AuditLog.Read.All` | Read sign-in activity report + live sign-in logs |
| `Directory.Read.All` | Read service principal details |
| `Synchronization.Read.All` | Read provisioning (SCIM) job status |

`Mail.Send` is deliberately **not** granted here — an Entra grant of `Mail.Send` lets the identity send as *any* mailbox in the tenant. Step 3 grants it for the sender mailbox only.

The snippet looks like this (your specific Object ID will be substituted):

```powershell
Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All'

$miObjectId = '<printed by bootstrap script>'
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$perms = @('Application.Read.All','AuditLog.Read.All','Directory.Read.All','Synchronization.Read.All')

foreach ($p in $perms) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $p -and $_.AllowedMemberTypes -contains 'Application' }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miObjectId `
        -PrincipalId $miObjectId -ResourceId $graphSp.Id -AppRoleId $role.Id | Out-Null
    Write-Host "  Granted: $p" -ForegroundColor Green
}
```

---

## Step 3 — Grant Mail.Send for the sender mailbox only

Use Exchange **RBAC for Applications** to give the Managed Identity `Mail.Send` on the sender mailbox and nothing else. This replaces the older `New-ApplicationAccessPolicy` approach, which Microsoft now classes as legacy (don't create new ones). The bootstrap script prints this snippet with your IDs filled in:

```powershell
# Run as Exchange Administrator
Connect-ExchangeOnline

# Pointer to the Managed Identity's service principal. Both IDs are on the
# Enterprise applications page for the identity (not App registrations).
$miAppId    = '<managed-identity-application-id>'
$miObjectId = '<managed-identity-object-id>'
New-ServicePrincipal -AppId $miAppId -ObjectId $miObjectId -DisplayName 'AppLens'

# Scope containing just the sender mailbox, and the scoped role assignment
New-ManagementScope -Name 'AppLens-MonthlyReport sender' `
    -RecipientRestrictionFilter "UserPrincipalName -eq 'applens@yourdomain.com'"
New-ManagementRoleAssignment -App $miObjectId -Role 'Application Mail.Send' `
    -CustomResourceScope 'AppLens-MonthlyReport sender'

# Verify — InScope should be True for the sender and False for anyone else
Test-ServicePrincipalAuthorization -Identity $miObjectId -Resource 'applens@yourdomain.com'
Test-ServicePrincipalAuthorization -Identity $miObjectId -Resource 'someotheruser@yourdomain.com'
```

> Exchange caches app permissions for between 30 minutes and 2 hours, so a send straight after this step can still fail. Give it time before testing.

**Already deployed with an Application Access Policy?** It keeps working. To migrate with no interruption: run the snippet above, then remove the Entra `Mail.Send` grant from the Managed Identity, then `Remove-ApplicationAccessPolicy`. Don't leave the Entra grant in place — Entra and Exchange grants are additive, so an unscoped Entra `Mail.Send` would cancel out the scoping.

---

## Step 4 — Test the runbook manually

```powershell
Start-AzAutomationRunbook `
    -ResourceGroupName     'rg-applens' `
    -AutomationAccountName 'aa-applens-XXXX' `
    -Name                  'AppLens-MonthlyReport' `
    -Parameters @{
        SendEmail     = $true
        SenderUpn     = 'applens@yourdomain.com'
        RecipientUpns = @('admin1@yourdomain.com')
    }
```

Watch the job in the Azure portal: **Automation Account → Jobs**. A run typically takes 10-30 minutes — paging through 30 days of sign-in logs dominates, so busy tenants take longer.

You should receive the email within a minute of the job completing.

---

## Adjusting the schedule

```powershell
# Remove the existing schedule
Remove-AzAutomationSchedule -ResourceGroupName 'rg-applens' `
    -AutomationAccountName 'aa-applens-XXXX' -Name 'AppLens-Monthly' -Force

# Re-create with different timing (example: first day of month at 06:00 UTC)
New-AzAutomationSchedule -ResourceGroupName 'rg-applens' `
    -AutomationAccountName 'aa-applens-XXXX' -Name 'AppLens-Monthly' `
    -StartTime (Get-Date '2026-11-01 06:00:00Z') `
    -MonthInterval 1 -DaysOfMonth One
```

Then re-link with `Register-AzAutomationScheduledRunbook` (see bootstrap script for syntax).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Could not fetch sign-in activity` | Tenant lacks Entra ID P1/P2 | Upgrade licence, or the report runs without staleness data |
| `Forbidden` / `ErrorAccessDenied` calling `/users/.../sendMail` | Step 3 not done, still propagating, or scope doesn't match the sender | Wait up to 2 hours, then `Test-ServicePrincipalAuthorization -Identity <miObjectId> -Resource <sender>` |
| `Authentication failed` | Managed Identity disabled | Automation Account → Identity → re-enable System Assigned |
| `Module not found` / `Could not load file or assembly` | Module import failed, or the three Graph modules are on different versions | Re-run the bootstrap script — it re-imports any module that isn't on the pinned version |
| Email never arrives | Sender mailbox doesn't exist, or scope in Step 3 misconfigured | Check Exchange admin centre for sent items in the sender mailbox |
| Empty report attachment | First run before any sign-in data available | Wait for next scheduled run, or trigger manually |
| Hundreds of parse errors running the script locally | File saved without its UTF-8 BOM (Windows PowerShell 5.1 then misreads the em dashes) | Re-save as "UTF-8 with BOM", or run it in PowerShell 7 |

---

## Cost

- **Automation Account**: first 500 job minutes/month are free; this runbook uses roughly 10-30 min/month → **free**
- **Graph API calls**: free
- **Email**: free (uses your existing Exchange Online licence)

Effectively zero ongoing cost.

---

## Removing everything

```powershell
Remove-AzResourceGroup -Name 'rg-applens' -Force
```

Plus, in Entra ID, remove the app role assignments from the Managed Identity's enterprise app entry (it will be tombstoned but can be deleted via `Remove-MgServicePrincipal`), and in Exchange Online remove the role assignment, management scope and service principal pointer from Step 3.

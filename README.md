# AppLens by CloudEndpoint.ai

Enterprise App Insight for Microsoft 365 — a branded auditing tool that generates
an interactive HTML report of every enterprise application in a tenant, with
staleness analysis, SAML cert health, SCIM provisioning status, ownership,
assignments, app-only permissions, and a combined risk score for cleanup
prioritisation.

---

## Contents

| File | Purpose |
|---|---|
| `Get-EnterpriseAppReport.ps1` | Main script. Dual-mode: runs interactively on your workstation or as an Azure Automation runbook. |
| `Setup-AppLensAutomation.ps1` | One-shot Azure bootstrap — creates RG, Automation Account, Managed Identity, imports modules, schedules the runbook. |
| `APPLENS-AUTOMATION-SETUP.md` | Step-by-step Azure Automation setup guide (Graph permissions, Mail.Send scoping, troubleshooting). |

---

## Quick start (interactive)

```powershell
.\Get-EnterpriseAppReport.ps1
```

First run will prompt for browser auth, install the Microsoft.Graph modules
if missing, generate the HTML report next to the script, and open it in your
default browser. Works in Windows PowerShell 5.1 and PowerShell 7+.

### Common options

```powershell
# Include first-party Microsoft apps (off by default)
.\Get-EnterpriseAppReport.ps1 -IncludeMicrosoftApps

# Faster: skip per-app detail batches (no owners, assignments, perms, provisioning)
.\Get-EnterpriseAppReport.ps1 -SkipDetailedAnalysis

# Adjust the live sign-in log lookback window
.\Get-EnterpriseAppReport.ps1 -SignInLogDays 14
```

---

## Monthly automated reports (Azure Automation)

See **`APPLENS-AUTOMATION-SETUP.md`** for the full guide. Headline steps:

1. Run `Setup-AppLensAutomation.ps1` to provision the Azure side
2. As a Global Admin, run the printed snippet to grant Graph permissions to the Managed Identity
3. As an Exchange Admin, run the printed snippet to grant `Mail.Send` on the sender mailbox only (Exchange RBAC for Applications)
4. Test with `Start-AzAutomationRunbook`

Effectively zero ongoing cost (first 500 Automation job minutes/month are free; this uses roughly 10-30).

---

## What's in the report

- **Activity buckets**: Active <30d / 30-60d / 60-90d / 90+d / Never
- **SAML cert expiry** (separate from API credentials — expired = users locked out)
- **SCIM provisioning health** for apps like Salesforce, Workday, ServiceNow
- **Owners, assigned users/groups, app-only and delegated permissions**
- **Credential expiry, rotation-aware** — an old secret that's already been replaced isn't flagged
- **Legacy API exposure** — apps still holding EWS permissions (Exchange Online is switching EWS off) or retired Azure AD Graph permissions
- **AI agents** — Entra Agent ID identities are labelled and judged by their sponsors, not owners
- **Combined 0-100 risk score** weighting all of the above
- **Filterable, sortable, exportable** — click cards to drill in, export visible rows to CSV

---

## Permissions required

Microsoft Graph application permissions for the Managed Identity (or delegated for
interactive use):

- `Application.Read.All`
- `AuditLog.Read.All`
- `Directory.Read.All`
- `Synchronization.Read.All` (provisioning jobs)
- `Mail.Send` (only if `-SendEmail` is used — in Automation, grant it scoped to the sender mailbox via Exchange RBAC for Applications rather than in Entra)

Plus **Entra ID P1 or P2** for sign-in activity reporting.

---

## Branding

This is the **CloudEndpoint.ai branded edition**. All visual identity
(gradient header, grid logo, teal palette `#2e7d82`/`#225053`/`#3a9da3`)
follows CloudEndpoint.ai's brand.

---

© CloudEndpoint.ai · [cloudendpoint.ai](https://cloudendpoint.ai)

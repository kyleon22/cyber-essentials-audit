# Cyber Essentials Readiness Audit

A read-only PowerShell module that audits a Microsoft 365 / Intune tenant — and, optionally, an on-premises Active Directory environment — against **all five Cyber Essentials technical controls** (IASME/NCSC **Danzell v3.3** question set), then exports the findings to a multi-tab Excel workbook and/or JSON.

Every CE sub-requirement gets an automated verdict on the **Summary** tab:

| Verdict | Meaning |
|---|---|
| **Pass** | Tenant data shows the control is in place |
| **Fail** | Tenant data shows the control is **not** in place |
| **Manual check** | Cannot be automated — the assessor must evidence it (the tab says exactly what to check) |
| **Unknown** | A required API call failed (permissions/transient). **Never an implicit pass** — see the Run info tab |

---

## Quick start

```powershell
# Interactive (TUI) - recommended for first use
.\Start-CyberEssentialsAudit.ps1

# Or drive the module directly
Import-Module .\CyberEssentialsAudit
$audit = Invoke-CeAudit -Mode CloudOnly
Export-CeReport -Audit $audit -Path "$HOME\Documents\CyberEssentialsAudit_demo.xlsx" -Format Both
```

Unattended / scheduled (app-only certificate auth):

```powershell
Invoke-CeAudit -AuthMode App -TenantId $tenantId -ClientId $appId -CertificateThumbprint $thumb |
    Export-CeReport -Path C:\Reports\CyberEssentialsAudit_weekly.xlsx -Format Both -ForceOverwrite
```

Exit codes (`-NoMenu` launcher mode): `0` success, `1` failure — usable from schedulers and pipelines.

---

## What gets checked

| CE control | Automated checks |
|---|---|
| **Scope** | Tenant/domain/device/user facts pre-filled on the Scope tab (declaration itself is Manual) |
| **Firewalls** | Windows software firewall (Endpoint Protection profiles, settings catalog **per-setting values**, endpoint-security intents/baselines, hybrid GPO); macOS firewall; boundary firewall (Manual, with a checklist) |
| **Secure configuration** | AutoPlay/AutoRun disabled; device locking (compliance policies); mobile devices managed (MAM / CA / compliance); default credentials (Manual) |
| **User access control** | MFA enforced (security defaults **or** enabled CA policies — report-only/disabled policies are *not* counted); MFA registration coverage; shared-account heuristics; stale/leaver accounts (last sign-in); guest review; password protections (length / deny list / smart lockout / on-prem domain policy); **admin/standard account separation** (Entra roles incl. role-assignable groups + PIM-eligible; on-prem privileged groups resolved via LDAP in-chain matching — handles >5,000-member groups) |
| **Malware protection** | Defender AV policies (real-time protection, cloud protection, PUA, signature cadence) across intents, settings catalog, classic profiles, compliance policies and hybrid GPO; application allow-listing as the alternative route; macOS AV (Manual) |
| **Security update management** | Windows Update rings vs the **14-day requirement** (deferral + deadline + grace, pause detection); feature/driver/expedite profiles; macOS update policies; **unsupported/EOL operating systems** per device (Windows client/server + macOS lifecycle tables); third-party patching (Manual) |

In **hybrid** mode, GPO findings come from a **structured parse** of each GPO report (account policy nodes, per-profile firewall enablement, AppLocker rule collections, configured admin-template policies) — not text matching — and are folded into the matching tabs tagged `On-prem GPO`.

## The report

Tabs: **Summary** (RAG, one row per sub-requirement) · **Scope** · Device list (with per-device **Support status / Support end**) · MFA · Software firewall · **Malware protection** · **Security updates** · Mobile devices · Status of autoplay-autorun · Shared accounts (+ stale + guests) · Application whitelisting · Password · Privileged users · **Run info** (who/when/scopes/version + every API error).

`-Format Json` (or `Both`) writes a machine-readable document alongside the workbook for pipelines/SIEM ingestion. A transcript log is written next to the report.

---

## Requirements

* Windows PowerShell 5.1 or PowerShell 7+ (runs on servers/DCs; no Office install needed)
* Modules (version-pinned, auto-installed by the launcher): `Microsoft.Graph.Authentication 2.25.0`, `ImportExcel 7.8.10`
* Hybrid mode: RSAT `ActiveDirectory` + `GroupPolicy` modules (ship with the AD DS/GPMC role on a DC)

### Graph permissions

Delegated (interactive sign-in consents these read-only scopes):

```
DeviceManagementManagedDevices.Read.All   DeviceManagementConfiguration.Read.All
DeviceManagementApps.Read.All             Policy.Read.All
Directory.Read.All                        User.Read.All
RoleManagement.Read.Directory             AuditLog.Read.All
```

App-only (`-AuthMode App`): create an app registration with the **application-permission equivalents** of the same scopes, a certificate credential, and grant admin consent. `AuditLog.Read.All` powers MFA-registration and stale-account checks; without it those checks report **Unknown** (never a silent pass).

---

## Module layout

```
CyberEssentialsAudit/
  CyberEssentialsAudit.psd1      # manifest (pinned RequiredModules, v2.0.0)
  Public/    Invoke-CeAudit, Export-CeReport
  Private/
    Core/    pure evaluators (OS lifecycle, MFA, update rings, GPO XML parser,
             formula-injection guard, privilege classifier) - all Pester-tested
    Graph/   central URI table, paged+cached requests, error journal, auth
    Checks/  one file per CE area; every check returns the same typed result
    Excel/   rendering only - fully decoupled from collection
Tests/       Pester 5 suite + JSON/XML fixtures
.github/workflows/ci.yml         # PSScriptAnalyzer + Pester (PS 5.1 & 7) + release zip
```

Design rule: every check returns `{Control; CheckId; Title; Status; Reason; Evidence; DetailSheet}` — the Excel/JSON layers only render. `Get-IntuneEndpointReport.ps1` remains as a deprecated wrapper that forwards to the module.

## Development

```powershell
Invoke-Pester -Path .\Tests
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

**Annual data maintenance:** the OS lifecycle tables in `Private/Core/Get-CeOsInfo.ps1` (new Windows builds, macOS supported majors after each September release) are dated facts — review them at least yearly and when Microsoft/Apple ship new releases. CE question-set wording should be verified against the published Danzell documents before relying on verdict text.

## Security

The tool is **read-only** (GET requests and read-only AD/GPO cmdlets only — enforced by a unit test), pins its dependencies, restores PSGallery trust state after installs, guards against output-file clobbering and CSV formula injection, and warns when the report is written to a shared location. See [SECURITY.md](SECURITY.md).

## Limitations

* Most Intune configuration still requires the Graph **beta** endpoint; all URIs live in one table (`Private/Graph/Invoke-CeGraph.ps1`) so endpoint churn is a one-line fix.
* Third-party agents (AV, allow-listing, patching) are not visible in Intune policy — those items are flagged Manual rather than guessed.
* Heuristic findings (shared accounts, admin naming) are labelled as such and always require human confirmation.

# Cyber Essentials Readiness Audit

A PowerShell tool that audits a Microsoft 365 / Intune tenant — and, optionally, an on-premises Active Directory environment — against several **Cyber Essentials** control areas, then exports the findings to a multi-tab Excel workbook (`.xlsx`).

It is built for both technical and non-technical users: run it directly from PowerShell, or drive it through a menu-based **text user interface (TUI)**.

---

## Contents

- [What it does](#what-it-does)
- [The report tabs](#the-report-tabs)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Using the TUI launcher](#using-the-tui-launcher)
- [Running the script directly](#running-the-script-directly)
- [Parameters](#parameters)
- [Cloud-only vs hybrid](#cloud-only-vs-hybrid)
- [Permissions and scopes](#permissions-and-scopes)
- [Output](#output)
- [Troubleshooting](#troubleshooting)
- [How findings are determined](#how-findings-are-determined)
- [Limitations and caveats](#limitations-and-caveats)
- [Files in this package](#files-in-this-package)
- [Security notes](#security-notes)

---

## What it does

The tool connects to Microsoft Graph using **delegated (interactive) authentication** and reads configuration and inventory data from your tenant. In **hybrid** mode it additionally connects to on-premises Active Directory and Group Policy. It never makes changes — all operations are **read-only**.

The result is a single Excel workbook with one tab per control area, suitable for evidencing a Cyber Essentials self-assessment or for an auditor's review.

---

## The report tabs

| Tab | What it covers |
|-----|----------------|
| **Device list** | Windows workstations, servers (listed separately), and macOS devices. Includes per-make/OS/SKU summaries (e.g. `20x HP Windows 11 24H2 Pro`, `10x HP Windows Server 2019 Standard`). In hybrid mode this is a **unified, de-duplicated** list across cloud + on-premises, with a source-of-truth banner. |
| **MFA** | Conditional Access policies that enforce multi-factor authentication, whether they apply to all cloud apps and all users, and any excluded users / groups / roles. |
| **Software firewall** | Intune policies that enable/enforce the Windows firewall — Endpoint Protection profiles, Settings Catalog, and Endpoint Security / Security Baseline intents — with their assignments. |
| **Mobile devices** | Android/iOS devices with a make + OS summary, app protection (MAM) policies and their settings, Conditional Access app-protection enforcement, and compliance-policy fallback. |
| **Status of autoplay-autorun** | Policies/settings that disable AutoPlay / AutoRun across Settings Catalog, Administrative Templates, custom OMA-URI, and Security Baselines. |
| **Shared accounts** | Accounts flagged **heuristically** as possible shared accounts (by naming pattern / missing name), with their licences and a clear manual-verification caveat. |
| **Application whitelisting** | AppLocker, App Control for Business / WDAC, and Smart App Control policies and assignments. If none are found, a caveat prompts the auditor to confirm ThreatLocker or another third-party solution. |
| **Password** | Security defaults status plus the custom banned-password list (Entra Password Protection), with a Cyber Essentials verdict. |
| **Privileged users** | Every identity holding administrative privilege, flagging **standard (day-to-day) accounts that also have admin**. Covers Entra ID directory roles (including users who inherit a role via a **role-assignable group**), **PIM-eligible** assignments, and service principals/apps holding roles. In hybrid mode it also enumerates well-known **on-premises AD privileged groups** (Domain/Enterprise/Schema Admins, Administrators, Account/Server/Backup/Print Operators, Group Policy Creator Owners, DnsAdmins, etc.) resolved **recursively**, recording **direct vs nested** membership and the intermediate group a user inherits through. |

In **hybrid** mode, relevant on-premises **GPO findings** are folded into the matching tabs (firewall, AutoPlay/AutoRun, application whitelisting, password) tagged as `On-prem GPO`, so the tab set stays identical to a cloud-only run.

---

## How it works

```
              ┌─────────────────────────────┐
              │ Start-CyberEssentialsAudit  │  ← optional TUI launcher
              │            .ps1             │
              └──────────────┬──────────────┘
                             │  (forwards parameters)
                             ▼
              ┌─────────────────────────────┐
              │  Get-IntuneEndpointReport   │  ← the audit engine
              │            .ps1             │
              └──────┬───────────────┬──────┘
                     │               │
        Microsoft Graph        On-prem AD + GPO
        (cloud, always)        (hybrid only, RSAT)
                     │               │
                     ▼               ▼
              ┌─────────────────────────────┐
              │   Excel workbook (.xlsx)    │  ← native, via ImportExcel/EPPlus
              └─────────────────────────────┘
```

The workbook is written with the **ImportExcel** module (EPPlus engine), so **Microsoft Excel/Office is *not* required** — it runs on servers and domain controllers.

---

## Requirements

| Component | Cloud only | Hybrid |
|-----------|:---------:|:------:|
| Windows PowerShell 5.1 or PowerShell 7+ | ✓ | ✓ |
| `Microsoft.Graph.Authentication` module | ✓ | ✓ |
| `ImportExcel` module | ✓ | ✓ |
| `ActiveDirectory` RSAT module | — | ✓ |
| `GroupPolicy` RSAT module | — | ✓ |
| Internet access (Graph + PSGallery for first install) | ✓ | ✓ |
| Run from a **domain controller** (or domain-joined host with RSAT) | — | ✓ |
| Elevated (Administrator) session | only to install RSAT | recommended |

The script includes a **dependency preflight** at launch: it lists what's missing for the chosen mode and offers to install it (PSGallery modules via `Install-Module`; RSAT via `Add-WindowsCapability` / `Install-WindowsFeature`).

> **Note:** Microsoft Excel is **not** a requirement. Earlier versions used Excel COM automation; the tool now writes `.xlsx` natively so it works on Server Core and domain controllers.

---

## Installation

1. Copy both scripts into the **same folder**:
   - `Get-IntuneEndpointReport.ps1` (the audit engine)
   - `Start-CyberEssentialsAudit.ps1` (the TUI launcher)
2. Allow script execution for your session if needed:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
3. (Optional) Pre-install dependencies — otherwise the script offers to do it on first run:
   ```powershell
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
   Install-Module ImportExcel -Scope CurrentUser
   ```
   For hybrid audits on a server/DC, the AD and GroupPolicy modules usually come with the AD DS / GPMC role; otherwise add RSAT.

### Offline / isolated servers

If the machine cannot reach the PowerShell Gallery, stage the modules on an internet-connected machine and copy them across:

```powershell
Save-Module Microsoft.Graph.Authentication -Path C:\Temp\Modules
Save-Module ImportExcel -Path C:\Temp\Modules
# then copy C:\Temp\Modules\* to a path in $env:PSModulePath on the target
```

---

## Quick start

**Interactive (recommended for most users):**
```powershell
.\Start-CyberEssentialsAudit.ps1
```

**Direct, cloud-only:**
```powershell
.\Get-IntuneEndpointReport.ps1 -Mode CloudOnly
```

**Direct, hybrid (run on a domain controller):**
```powershell
.\Get-IntuneEndpointReport.ps1 -Mode Hybrid
```

A browser window opens for Microsoft 365 sign-in. When it finishes, the workbook path is printed to the console.

---

## Using the TUI launcher

Running `Start-CyberEssentialsAudit.ps1` with no parameters opens a menu:

```
1. Run audit  -  Cloud only
2. Run audit  -  Hybrid (on-prem + cloud)
3. Configure options
4. Check / install dependencies
5. Show the equivalent PowerShell command
6. Open the output folder
7. Help / about
Q. Quit
```

- **Configure options** lets you set the output path, check-in window (weeks), tenant ID, domain controller FQDN, and toggle baseline diagnostics — without typing parameters.
- **Show the equivalent PowerShell command** prints the exact command line your choices map to, so nothing is hidden and you can copy it for automation.
- **Check / install dependencies** runs a pre-flight and can install the PSGallery modules on the spot.

To skip the menu and run directly through the launcher (parameters are forwarded):
```powershell
.\Start-CyberEssentialsAudit.ps1 -NoMenu -Mode Hybrid -CheckInWindowWeeks 6
```

> The TUI needs an interactive console. For scheduled/automated runs, call `Get-IntuneEndpointReport.ps1` directly or use `-NoMenu`.

---

## Running the script directly

`Get-IntuneEndpointReport.ps1` can be run on its own with any combination of the parameters below. If `-Mode` is omitted it prompts (cloud-only vs hybrid) at launch.

---

## Parameters

These apply to `Get-IntuneEndpointReport.ps1` (and are forwarded by the launcher):

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputPath` | string | Timestamped `.xlsx` in your **private Documents** folder | Full path for the output workbook. Must end in `.xlsx`. |
| `-CheckInWindowWeeks` | int | `6` | Devices not seen within this many weeks are excluded. |
| `-TenantId` | string | (interactive) | Specific tenant to sign into. |
| `-Mode` | `CloudOnly` / `Hybrid` | (prompts) | Audit scope. |
| `-DomainController` | string | (integrated / current DC) | FQDN of a DC/AD server to target. Override for running off-box. |
| `-ADCredential` | PSCredential | (integrated) | Explicit domain credentials. Override for running off-box. |
| `-DiagnoseBaselines` | switch | off | Writes `baseline-diagnostics.txt` dumping every Security Baseline intent's settings (troubleshooting). |
| `-ForceOverwrite` | switch | off | Allow overwriting an existing output file that is **not** named like a previous report. Without it, the script refuses to delete a non-report file. |
| `-GraphModuleVersion` | string | `2.25.0` | Pinned version of `Microsoft.Graph.Authentication` the preflight installs/imports. |
| `-ImportExcelVersion` | string | `7.8.10` | Pinned version of `ImportExcel` the preflight installs/imports. |

The launcher (`Start-CyberEssentialsAudit.ps1`) additionally accepts `-NoMenu` to bypass the TUI.

---

## Cloud-only vs hybrid

**Cloud only** audits the Microsoft 365 / Intune tenant via Microsoft Graph. The Device list contains Intune-enrolled devices; Intune is treated as the source of truth.

**Hybrid** does everything cloud-only does **and**:

- Inventories **on-premises AD computers** across **every container and OU** (including the default `Computers` container and the `Domain Controllers` OU). "Active" is judged from a combined signal (`lastLogonTimestamp`, computer-account password age, and `whenChanged`) so devices aren't dropped just because one stale attribute lags.
- Pulls hardware (manufacturer/model) and OS edition per device via **CIM/WMI** where the machine is reachable.
- Produces a **unified, de-duplicated** asset list — a device present in both Intune and AD is listed once and tagged `Both (Intune + AD)`.
- Lists **servers separately** from workstations, each with its own summary.
- Reviews **Group Policy** for the relevant controls and folds those findings into the matching tabs.
- Compares cloud vs on-prem device counts to recommend whether **GPO or Intune** should be the source of truth.

Hybrid mode is intended to be run **from a domain controller**, using the logged-on (integrated) credentials. Use `-DomainController` / `-ADCredential` only when running from a different management host.

---

## Permissions and scopes

Sign-in is **delegated** — the signed-in user needs read access to the relevant areas. The following Microsoft Graph scopes are requested (consent on first run):

| Scope | Used for |
|-------|----------|
| `DeviceManagementManagedDevices.Read.All` | Intune device inventory |
| `DeviceManagementConfiguration.Read.All` | Firewall / AutoPlay / baseline / GPO-equivalent config policies |
| `DeviceManagementApps.Read.All` | Mobile app protection (MAM) policies |
| `Policy.Read.All` | Conditional Access policies |
| `Directory.Read.All` | Resolving users / groups / roles |
| `User.Read.All` | Account & shared-account review |
| `RoleManagement.Read.Directory` | Directory roles, role-assignable groups & PIM eligibility (Privileged users tab) |

A role such as **Global Reader** (plus **Intune** read access) typically covers these. For the on-premises portion, the account needs read access to AD and the ability to run `Get-GPOReport`; CIM hardware queries require network reach (WinRM/RPC) to each endpoint.

---

## Output

- A single `.xlsx` workbook (default: `IntuneEndpointReport_<timestamp>.xlsx` in the working folder).
- One worksheet per control area (see [The report tabs](#the-report-tabs)).
- Colour-coded banners highlight verdicts (e.g. green/red on the Password tab) and caveats (red) where manual verification is required.
- With `-DiagnoseBaselines`, an extra `baseline-diagnostics.txt` is written alongside the workbook.

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `Class not registered (0x80040154)` on `Excel.Application` | An old COM-based copy of the script. Use the current version, which needs **no Excel** (uses ImportExcel). |
| `The property 'Value' cannot be found on this object` | An older EPPlus build of the script. The current version addresses cells by string (`"A1"`) to avoid PowerShell's array-slicing of `ExcelRange`. Use the latest file. |
| `The hash literal was incomplete` / brace errors | You're running a truncated/temporary file (e.g. `*.cleaned.ps1`). Run **`Get-IntuneEndpointReport.ps1`** and delete any stray copies. |
| `Parsing OData Select and Expand failed … 'skuFamily'` | Old version using the v1.0 endpoint. The current script queries the beta endpoint where these properties exist. |
| On-prem server missing from the report | Fixed in the current version — AD search now covers all containers/OUs and uses a combined activity signal instead of just `lastLogonTimestamp`. Check the per-container counts printed during a hybrid run. |
| RSAT install fails | Run PowerShell **as Administrator**; ensure internet or a configured feature source; reboot if Windows requests it, then re-run. |
| Module install fails on an old host | The script forces **TLS 1.2** for PSGallery; for fully offline servers use the [offline install](#offline--isolated-servers) steps. |
| AutoPlay/firewall settings in a Security Baseline not detected | Fixed — baseline settings are matched by category/display name (resolved via the template), not just raw definition IDs. |
| Columns not auto-sized on Server Core | Expected — Server Core lacks the GDI+ layer `AutoFitColumns` needs. The report still generates; widths just aren't auto-fitted. |

For deeper baseline diagnosis, run with `-DiagnoseBaselines` and inspect `baseline-diagnostics.txt`.

---

## How findings are determined

- **MFA** — a CA policy counts as MFA-enforcing if it grants the built-in `mfa` control or requires an authentication strength.
- **Firewall** — checked across Endpoint Protection profiles (`firewallProfile*` states), Settings Catalog (`enableFirewall`), and firewall/baseline intents.
- **AutoPlay/AutoRun** — matched across Settings Catalog, Administrative Templates, custom OMA-URI, and Security Baselines (by setting/category display name).
- **Application whitelisting** — AppLocker (`appLockerApplicationControl`), App Control for Business / WDAC, and Smart App Control across profiles, Settings Catalog, intents, and OMA-URI.
- **Password** — combines security-defaults state with the presence of a non-empty custom banned-password list (Entra Password Protection).
- **Shared accounts** — flagged heuristically (generic name keywords, missing first/last name, single-word display name). **Always requires manual confirmation.**
- **Hybrid source-of-truth** — based on the relative count of cloud vs on-prem workstations.

---

## Limitations and caveats

- **Shared accounts are heuristic**, not authoritative — every flagged account must be manually verified.
- **Application whitelisting** covers Intune/GPO-managed mechanisms. Third-party tools such as **ThreatLocker** are not auto-detected; the tab includes a reminder to confirm these manually.
- **On-prem hardware/SKU depends on CIM reachability.** AD only stores OS name/version and DNS name; unreachable machines fall back to AD attributes with `Unknown` hardware.
- **MAM-only (unenrolled) mobile devices** won't appear in the device list, though their protection policies are still reported.
- **Delegated permissions** mean results reflect what the signed-in user can read.
- The tool is **read-only** and makes no changes to the tenant or directory.

---

## Files in this package

**Shipped files** — these three make up the app and should always be present in the folder:

| File | Purpose |
|------|---------|
| `Get-IntuneEndpointReport.ps1` | The audit engine — collects data and writes the workbook. |
| `Start-CyberEssentialsAudit.ps1` | TUI launcher / front-end (optional). |
| `README.md` | This document. |

**Generated at runtime** — these are *created when you run the tool*; they do not ship with it, so don't worry if they aren't there before the first run:

| File | When it appears |
|------|-----------------|
| `IntuneEndpointReport_<timestamp>.xlsx` | The report — written on every run (unless you set `-OutputPath`). |
| `baseline-diagnostics.txt` | Only when you run with `-DiagnoseBaselines`. |

> If you see a `Get-IntuneEndpointReport.cleaned.ps1` (or any other `*.cleaned.ps1`) in the folder, it is a leftover temporary file from an earlier edit and is **safe to delete** — run only `Get-IntuneEndpointReport.ps1`.

---

## Security notes

- Authentication is interactive and delegated; **no credentials or secrets are stored** by the tool.
- All tenant and directory operations are **read-only**.
- The output workbook contains device names, user principal names, and licence/account details — treat it as **sensitive** and store/share it accordingly.
- Run from a trusted, managed host. For hybrid audits, that host should be a domain controller or a secured domain-joined management server.

### Supply-chain and output safeguards

- **Pinned modules.** The required PSGallery modules are installed and imported at **fixed versions** (`-GraphModuleVersion`, `-ImportExcelVersion`) rather than "latest", to avoid silently pulling an unvetted update onto a privileged host. Override only after validating a version.
- **No persistent trust change.** When the script installs modules it reads PSGallery's current trust state and **restores it afterwards**, so the repository is not left permanently `Trusted`.
- **Private output by default.** The report is written to your **private Documents** folder, not the working directory. If the destination resolves to a **UNC / network / mapped drive**, the script prints a warning — the workbook is sensitive and the location should be access-controlled.
- **Safe overwrite.** `-OutputPath` must end in `.xlsx`. An existing file is only deleted if it looks like a previous report (`IntuneEndpointReport_*.xlsx`) or you pass `-ForceOverwrite`, so a mistyped path cannot destroy an unrelated file.
- **Formula-injection neutralised.** Tenant/AD-controlled strings that begin with `=`, `+`, `-`, `@`, tab, or carriage return are prefixed with `'` before being written, so the data is safe even if later re-exported to CSV or opened by a client that auto-interprets formulas.

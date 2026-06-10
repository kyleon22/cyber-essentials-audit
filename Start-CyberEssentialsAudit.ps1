<#
.SYNOPSIS
    Text-based UI (TUI) launcher for the Cyber Essentials readiness audit.

.DESCRIPTION
    A thin, menu-driven console front-end over the CyberEssentialsAudit module
    (Invoke-CeAudit + Export-CeReport). It lets a non-technical operator
    configure and run the audit without typing parameters, handles the
    dependency preflight (pinned PSGallery modules, RSAT for hybrid), and
    writes a transcript log next to the report.

    Menu:
      1. Run audit - Cloud only
      2. Run audit - Hybrid (on-premises AD + cloud)
      3. Configure options
      4. Check / install dependencies
      5. Show the equivalent PowerShell command
      6. Open the output folder
      7. Help / about
      Q. Quit

.EXAMPLE
    .\Start-CyberEssentialsAudit.ps1
        Launches the interactive TUI.

.EXAMPLE
    .\Start-CyberEssentialsAudit.ps1 -NoMenu -Mode Hybrid -CheckInWindowWeeks 6
        Skips the menu and runs the audit directly. Exit code 0 on success,
        1 on failure (for scripts/schedulers).
#>
[CmdletBinding()]
param(
    # Skip the TUI and run the audit directly with the parameters below.
    [switch]$NoMenu,

    # Forwarded to Invoke-CeAudit / Export-CeReport (all of them - B17).
    [string]$OutputPath,
    [ValidateRange(1, 52)][int]$CheckInWindowWeeks = 6,
    [string]$TenantId,
    [ValidateSet('CloudOnly', 'Hybrid')][string]$Mode,
    [string]$DomainController,
    [System.Management.Automation.PSCredential]$ADCredential,
    [switch]$SkipHardwareInventory,
    [switch]$ForceOverwrite,
    [ValidateSet('Excel', 'Json', 'Both')][string]$OutputFormat = 'Excel',
    [ValidateSet('Delegated', 'App')][string]$AuthMode = 'Delegated',
    [string]$ClientId,
    [string]$CertificateThumbprint,

    # Pinned PSGallery versions for the preflight installer. Override only if
    # you have validated a different version.
    [string]$GraphModuleVersion = '2.25.0',
    [string]$ImportExcelVersion = '7.8.10'
)

$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------- #
#  Locate and import the module (same folder as this launcher).               #
# --------------------------------------------------------------------------- #
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptDir 'CyberEssentialsAudit'
if (-not (Test-Path (Join-Path $modulePath 'CyberEssentialsAudit.psd1'))) {
    Write-Host "ERROR: the CyberEssentialsAudit module folder was not found next to this launcher ($scriptDir)." -ForegroundColor Red
    if ($NoMenu) { exit 1 } else { return }
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Install-RsatFeature {
    param([string]$Module)
    $capability = switch ($Module) {
        'ActiveDirectory' { 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' }
        'GroupPolicy'     { 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0' }
        default           { $null }
    }
    $feature = switch ($Module) {
        'ActiveDirectory' { 'RSAT-AD-PowerShell' }
        'GroupPolicy'     { 'RSAT-GPMC' }
        default           { $null }
    }
    try {
        if (Get-Command Add-WindowsCapability -ErrorAction SilentlyContinue) {
            $cap = Get-WindowsCapability -Online -Name $capability -ErrorAction Stop
            if ($cap.State -ne 'Installed') {
                Add-WindowsCapability -Online -Name $capability -ErrorAction Stop | Out-Null
            }
            return $true
        }
    } catch { }
    try {
        if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
            Install-WindowsFeature -Name $feature -IncludeManagementTools -ErrorAction Stop | Out-Null
            return $true
        }
    } catch { }
    return $false
}

# Dependency preflight. PSGallery modules are version-PINNED (supply-chain
# hygiene: never silently pull "latest" onto a privileged audit host / DC).
function Invoke-CePreflight {
    param([bool]$Hybrid, [bool]$Interactive = $true)
    $required = @(
        @{ Name = 'Microsoft.Graph.Authentication'; Kind = 'PSGallery'; Version = $GraphModuleVersion; Why = 'Microsoft Graph sign-in & API calls' }
        @{ Name = 'ImportExcel';                    Kind = 'PSGallery'; Version = $ImportExcelVersion; Why = 'native .xlsx output (no Office needed)' }
    )
    if ($Hybrid) {
        $required += @{ Name = 'ActiveDirectory'; Kind = 'RSAT'; Why = 'on-premises AD inventory' }
        $required += @{ Name = 'GroupPolicy';     Kind = 'RSAT'; Why = 'on-premises GPO review' }
    }

    Write-Host ''
    Write-Host 'Checking dependencies...' -ForegroundColor Cyan
    $missing = @()
    foreach ($dep in $required) {
        if (Get-Module -ListAvailable -Name $dep.Name) {
            Write-Host ("  [OK]      {0}" -f $dep.Name) -ForegroundColor Green
        } else {
            Write-Host ("  [MISSING] {0}  - {1}" -f $dep.Name, $dep.Why) -ForegroundColor Yellow
            $missing += $dep
        }
    }
    if ($missing.Count -eq 0) { return $true }

    if ($Interactive) {
        $ans = Read-Host ("Install the {0} missing dependency/dependencies now? [Y/N]" -f $missing.Count)
        if ($ans -notmatch '^(y|yes)$') {
            $instr = $missing | ForEach-Object {
                if ($_.Kind -eq 'PSGallery') { "  Install-Module $($_.Name) -RequiredVersion $($_.Version) -Repository PSGallery -Scope CurrentUser" }
                else { "  Add the RSAT feature for $($_.Name) (Install-WindowsFeature / Add-WindowsCapability)" }
            }
            Write-Host ("Install them and re-run:`n{0}" -f ($instr -join "`n")) -ForegroundColor Yellow
            return $false
        }
    }

    if (($missing | Where-Object { $_.Kind -eq 'RSAT' }).Count -gt 0 -and -not (Test-IsAdmin)) {
        Write-Host 'Installing RSAT features requires an elevated session. Re-run PowerShell as Administrator.' -ForegroundColor Red
        return $false
    }

    # Capture PSGallery trust so it can be RESTORED (never left Trusted).
    $prevPolicy = $null
    try { $prevPolicy = (Get-PSRepository -Name PSGallery -ErrorAction Stop).InstallationPolicy } catch { }
    try {
        foreach ($dep in $missing) {
            Write-Host ("Installing {0}{1}..." -f $dep.Name, $(if ($dep.Version) { " v$($dep.Version)" } else { '' })) -ForegroundColor Cyan
            if ($dep.Kind -eq 'PSGallery') {
                try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
                # Pinned version, explicit repository; -Force only bypasses the
                # untrusted-repo prompt, it does NOT pull "latest".
                Install-Module $dep.Name -RequiredVersion $dep.Version -Repository PSGallery `
                    -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            } else {
                if (-not (Install-RsatFeature -Module $dep.Name)) {
                    Write-Host ("  Automatic RSAT install not available for {0} on this OS - install it manually." -f $dep.Name) -ForegroundColor Red
                    return $false
                }
            }
            Write-Host ("  Installed {0}." -f $dep.Name) -ForegroundColor Green
        }
    } finally {
        if ($prevPolicy -and $prevPolicy -ne 'Trusted') {
            try { Set-PSRepository -Name PSGallery -InstallationPolicy $prevPolicy -ErrorAction Stop } catch { }
        }
    }
    return $true
}

# --------------------------------------------------------------------------- #
#  Session configuration (mutable via the Configure menu).                    #
# --------------------------------------------------------------------------- #
$script:cfg = [ordered]@{
    OutputPath            = $OutputPath
    CheckInWindowWeeks    = $CheckInWindowWeeks
    TenantId              = $TenantId
    DomainController      = $DomainController
    ADCredential          = $ADCredential
    SkipHardwareInventory = [bool]$SkipHardwareInventory
    ForceOverwrite        = [bool]$ForceOverwrite
    OutputFormat          = $OutputFormat
    AuthMode              = $AuthMode
    ClientId              = $ClientId
    CertificateThumbprint = $CertificateThumbprint
}

# Default output: timestamped file in the user's private Documents folder (not
# the current/working folder, which may be shared).
function Get-CeDefaultOutputPath {
    Join-Path ([Environment]::GetFolderPath('MyDocuments')) ("CyberEssentialsAudit_{0:yyyyMMdd_HHmmss}.xlsx" -f (Get-Date))
}

function Write-Rule { param([string]$Char = '=') Write-Host ($Char * 72) -ForegroundColor DarkCyan }
function Show-Header {
    Clear-Host
    Write-Rule
    Write-Host '            CYBER ESSENTIALS READINESS AUDIT  -  Launcher' -ForegroundColor Cyan
    Write-Rule
    Write-Host ''
}

function Get-CommandPreview {
    param([ValidateSet('CloudOnly', 'Hybrid')][string]$RunMode)
    $parts = @('Invoke-CeAudit', "-Mode $RunMode")
    if ($script:cfg.CheckInWindowWeeks -ne 6) { $parts += "-CheckInWindowWeeks $($script:cfg.CheckInWindowWeeks)" }
    if ($script:cfg.TenantId)              { $parts += "-TenantId $($script:cfg.TenantId)" }
    if ($RunMode -eq 'Hybrid' -and $script:cfg.DomainController) { $parts += "-DomainController $($script:cfg.DomainController)" }
    if ($RunMode -eq 'Hybrid' -and $script:cfg.ADCredential)     { $parts += '-ADCredential $cred' }
    if ($script:cfg.SkipHardwareInventory) { $parts += '-SkipHardwareInventory' }
    if ($script:cfg.AuthMode -eq 'App')    { $parts += "-AuthMode App -ClientId $($script:cfg.ClientId) -CertificateThumbprint $($script:cfg.CertificateThumbprint)" }
    $out = if ($script:cfg.OutputPath) { $script:cfg.OutputPath } else { '<Documents>\CyberEssentialsAudit_<timestamp>.xlsx' }
    $exp = @('Export-CeReport', "-Path `"$out`"", "-Format $($script:cfg.OutputFormat)")
    if ($script:cfg.ForceOverwrite) { $exp += '-ForceOverwrite' }
    return ("{0} | {1}" -f ($parts -join ' '), ($exp -join ' '))
}

function Invoke-AuditRun {
    param([ValidateSet('CloudOnly', 'Hybrid')][string]$RunMode, [bool]$Interactive = $true)
    if ($Interactive) { Show-Header }
    Write-Host ("Running audit in {0} mode..." -f $RunMode) -ForegroundColor Cyan
    Write-Host ("Command: {0}" -f (Get-CommandPreview -RunMode $RunMode)) -ForegroundColor DarkGray
    Write-Host ''

    if (-not (Invoke-CePreflight -Hybrid ($RunMode -eq 'Hybrid') -Interactive $Interactive)) {
        if (-not $Interactive) { exit 1 }
        [void](Read-Host 'Press Enter to return to the menu')
        return
    }
    Import-Module (Join-Path $modulePath 'CyberEssentialsAudit.psd1') -Force

    $outPath = if ($script:cfg.OutputPath) { $script:cfg.OutputPath } else { Get-CeDefaultOutputPath }
    $logPath = [System.IO.Path]::ChangeExtension($outPath, '.log')

    $auditParams = @{
        Mode               = $RunMode
        CheckInWindowWeeks = $script:cfg.CheckInWindowWeeks
        TranscriptPath     = $logPath
    }
    if ($script:cfg.TenantId)         { $auditParams['TenantId'] = $script:cfg.TenantId }
    if ($RunMode -eq 'Hybrid') {
        if ($script:cfg.DomainController) { $auditParams['DomainController'] = $script:cfg.DomainController }
        if ($script:cfg.ADCredential)     { $auditParams['ADCredential']     = $script:cfg.ADCredential }
    }
    if ($script:cfg.SkipHardwareInventory) { $auditParams['SkipHardwareInventory'] = $true }
    if ($script:cfg.AuthMode -eq 'App') {
        $auditParams['AuthMode'] = 'App'
        $auditParams['ClientId'] = $script:cfg.ClientId
        $auditParams['CertificateThumbprint'] = $script:cfg.CertificateThumbprint
    }

    try {
        $audit = Invoke-CeAudit @auditParams
        $exportParams = @{ Audit = $audit; Path = $outPath; Format = $script:cfg.OutputFormat }
        if ($script:cfg.ForceOverwrite) { $exportParams['ForceOverwrite'] = $true }
        [void](Export-CeReport @exportParams)
        Write-Host ''
        Write-Host ("Audit completed. Overall: {0}. Run log: {1}" -f $audit.Overall, $logPath) -ForegroundColor Green
        if (-not $Interactive) { exit 0 }
    } catch {
        Write-Host ''
        Write-Host ("Audit failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
        if (-not $Interactive) { exit 1 }
    }
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
}

function Edit-Configuration {
    while ($true) {
        Show-Header
        Write-Host 'CONFIGURE OPTIONS  (press Enter to keep the current value)' -ForegroundColor Cyan
        Write-Host ''
        Write-Host ("  1. Output path .............. {0}" -f $(if ($script:cfg.OutputPath) { $script:cfg.OutputPath } else { '(auto: timestamped .xlsx in your Documents folder)' }))
        Write-Host ("  2. Check-in window (weeks) .. {0}" -f $script:cfg.CheckInWindowWeeks)
        Write-Host ("  3. Tenant ID ................ {0}" -f $(if ($script:cfg.TenantId) { $script:cfg.TenantId } else { '(interactive default)' }))
        Write-Host ("  4. Domain controller (FQDN) . {0}" -f $(if ($script:cfg.DomainController) { $script:cfg.DomainController } else { '(integrated / current DC)' }))
        Write-Host ("  5. AD credential ............ {0}" -f $(if ($script:cfg.ADCredential) { $script:cfg.ADCredential.UserName } else { '(integrated)' }))
        Write-Host ("  6. Skip hardware inventory .. {0}" -f $(if ($script:cfg.SkipHardwareInventory) { 'Yes (faster on big estates)' } else { 'No' }))
        Write-Host ("  7. Output format ............ {0}" -f $script:cfg.OutputFormat)
        Write-Host ("  8. Force overwrite .......... {0}" -f $(if ($script:cfg.ForceOverwrite) { 'On' } else { 'Off' }))
        Write-Host ("  9. Auth mode ................ {0}" -f $(if ($script:cfg.AuthMode -eq 'App') { "App (ClientId: $($script:cfg.ClientId))" } else { 'Delegated (interactive sign-in)' }))
        Write-Host '  B. Back to main menu'
        Write-Host ''
        $sel = Read-Host 'Select an option to change'
        switch ($sel) {
            '1' { $v = Read-Host 'Output path (full .xlsx path)'; if ($v) { $script:cfg.OutputPath = $v } }
            '2' {
                $v = Read-Host 'Check-in window in weeks (1-52)'
                if ($v -match '^\d+$' -and [int]$v -ge 1 -and [int]$v -le 52) { $script:cfg.CheckInWindowWeeks = [int]$v }
                elseif ($v) { Write-Host 'Must be a number between 1 and 52 - unchanged.' -ForegroundColor Yellow; Start-Sleep 1 }
            }
            '3' { $v = Read-Host 'Tenant ID (GUID or domain)'; if ($v) { $script:cfg.TenantId = $v } }
            '4' { $v = Read-Host 'Domain controller FQDN'; if ($v) { $script:cfg.DomainController = $v } }
            '5' {
                $v = Read-Host 'Capture a domain credential now? [Y/N]'
                if ($v -match '^(y|yes)$') { try { $script:cfg.ADCredential = Get-Credential -Message 'Domain credential for AD/GPO reads' } catch { } }
                else { $script:cfg.ADCredential = $null }
            }
            '6' { $script:cfg.SkipHardwareInventory = -not $script:cfg.SkipHardwareInventory }
            '7' {
                $v = Read-Host 'Output format: Excel, Json or Both'
                if ($v -in @('Excel', 'Json', 'Both')) { $script:cfg.OutputFormat = $v }
            }
            '8' { $script:cfg.ForceOverwrite = -not $script:cfg.ForceOverwrite }
            '9' {
                $v = Read-Host 'Auth mode: Delegated or App'
                if ($v -eq 'App') {
                    $script:cfg.AuthMode = 'App'
                    $script:cfg.ClientId = Read-Host 'App (client) id'
                    $script:cfg.CertificateThumbprint = Read-Host 'Certificate thumbprint'
                    if (-not $script:cfg.TenantId) { $script:cfg.TenantId = Read-Host 'Tenant id (required for app auth)' }
                } elseif ($v -eq 'Delegated') { $script:cfg.AuthMode = 'Delegated' }
            }
            'b' { return }
            'B' { return }
            default { }
        }
    }
}

function Show-Command {
    Show-Header
    Write-Host 'EQUIVALENT POWERSHELL COMMANDS' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Cloud only:' -ForegroundColor White
    Write-Host ("  {0}" -f (Get-CommandPreview -RunMode 'CloudOnly')) -ForegroundColor Gray
    Write-Host ''
    Write-Host 'Hybrid:' -ForegroundColor White
    Write-Host ("  {0}" -f (Get-CommandPreview -RunMode 'Hybrid')) -ForegroundColor Gray
    Write-Host ''
    Write-Host '(Import-Module .\CyberEssentialsAudit first when running these directly.)' -ForegroundColor DarkGray
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
}

function Open-OutputFolder {
    # Default matches the engine default: the user's Documents folder (B17).
    $folder = if ($script:cfg.OutputPath) { Split-Path -Parent $script:cfg.OutputPath } else { [Environment]::GetFolderPath('MyDocuments') }
    if ([string]::IsNullOrWhiteSpace($folder)) { $folder = [Environment]::GetFolderPath('MyDocuments') }
    Show-Header
    if (Test-Path $folder) {
        Write-Host ("Opening: {0}" -f $folder) -ForegroundColor Cyan
        try { Start-Process explorer.exe $folder } catch { Write-Host 'Could not open Explorer (headless server?). Path shown above.' -ForegroundColor Yellow }
    } else {
        Write-Host ("Folder does not exist yet: {0}" -f $folder) -ForegroundColor Yellow
    }
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
}

function Show-Help {
    Show-Header
    Write-Host 'HELP / ABOUT' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'This launcher drives the CyberEssentialsAudit module, which produces a'
    Write-Host 'Cyber Essentials readiness workbook (.xlsx) and optional JSON covering'
    Write-Host 'all five CE controls with a Pass / Fail / Manual / Unknown verdict per'
    Write-Host 'sub-requirement on the Summary tab:'
    Write-Host '  Firewalls | Secure configuration | User access control |'
    Write-Host '  Malware protection | Security update management'
    Write-Host ''
    Write-Host 'Cloud only : audits the Microsoft 365 / Intune tenant via Microsoft Graph.'
    Write-Host 'Hybrid     : ALSO audits on-premises Active Directory + Group Policy.'
    Write-Host '             Run this from a domain controller (uses integrated creds).'
    Write-Host ''
    Write-Host 'The audit is READ-ONLY. Output is native .xlsx (no Excel install needed).'
    Write-Host 'A transcript log is written next to the report.'
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
}

# --------------------------------------------------------------------------- #
#  -NoMenu: run directly and exit with a meaningful exit code.                #
# --------------------------------------------------------------------------- #
if ($NoMenu) {
    $runMode = if ($Mode) { $Mode } else { 'CloudOnly' }
    Invoke-AuditRun -RunMode $runMode -Interactive $false
    return
}

# --------------------------------------------------------------------------- #
#  Main menu loop (labelled so the quit option exits the WHILE, not the       #
#  switch).                                                                   #
# --------------------------------------------------------------------------- #
:menu while ($true) {
    Show-Header
    Write-Host ("Current options: window={0}wk; format={1}; output={2}" -f `
        $script:cfg.CheckInWindowWeeks, $script:cfg.OutputFormat,
        $(if ($script:cfg.OutputPath) { Split-Path -Leaf $script:cfg.OutputPath } else { 'auto-named (Documents)' })) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  1. Run audit  -  Cloud only'               -ForegroundColor White
    Write-Host '  2. Run audit  -  Hybrid (on-prem + cloud)' -ForegroundColor White
    Write-Host '  3. Configure options'                      -ForegroundColor White
    Write-Host '  4. Check / install dependencies'           -ForegroundColor White
    Write-Host '  5. Show the equivalent PowerShell command' -ForegroundColor White
    Write-Host '  6. Open the output folder'                 -ForegroundColor White
    Write-Host '  7. Help / about'                           -ForegroundColor White
    Write-Host '  Q. Quit'                                   -ForegroundColor White
    Write-Host ''
    $choice = Read-Host 'Select an option'
    switch ($choice) {
        '1' { Invoke-AuditRun -RunMode 'CloudOnly' }
        '2' { Invoke-AuditRun -RunMode 'Hybrid' }
        '3' { Edit-Configuration }
        '4' { Show-Header; [void](Invoke-CePreflight -Hybrid $true -Interactive $true); Write-Host ''; [void](Read-Host 'Press Enter to return to the menu') }
        '5' { Show-Command }
        '6' { Open-OutputFolder }
        '7' { Show-Help }
        'q' { break menu }
        'Q' { break menu }
        default { }
    }
}

Show-Header
Write-Host 'Goodbye.' -ForegroundColor Cyan

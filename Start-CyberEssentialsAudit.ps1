<#
.SYNOPSIS
    Text-based UI (TUI) launcher for the Cyber Essentials readiness audit.

.DESCRIPTION
    A menu-driven console front-end for Get-IntuneEndpointReport.ps1. It lets a
    non-technical user configure and run the audit without typing parameters,
    while still allowing the underlying script to be run directly.

    Menu:
      1. Run audit - Cloud only
      2. Run audit - Hybrid (on-premises AD + cloud)
      3. Configure options (output path, check-in window, tenant, DC, diagnostics)
      4. Check / install dependencies
      5. Show the equivalent PowerShell command
      6. Open the output folder
      7. Help / about
      Q. Quit

    Run with -NoMenu to bypass the TUI and run the audit directly with whatever
    parameters you pass (these are forwarded to Get-IntuneEndpointReport.ps1).

.EXAMPLE
    .\Start-CyberEssentialsAudit.ps1
        Launches the interactive TUI.

.EXAMPLE
    .\Start-CyberEssentialsAudit.ps1 -NoMenu -Mode Hybrid -CheckInWindowWeeks 6
        Skips the menu and runs the audit directly (parameters forwarded).
#>

[CmdletBinding()]
param(
    # Skip the TUI and run the audit script directly with the parameters below.
    [switch]$NoMenu,

    # Forwarded to Get-IntuneEndpointReport.ps1 when -NoMenu is used.
    [string]$OutputPath,
    [int]$CheckInWindowWeeks = 6,
    [string]$TenantId,
    [ValidateSet('CloudOnly','Hybrid')] [string]$Mode,
    [string]$DomainController,
    [switch]$DiagnoseBaselines
)

# --------------------------------------------------------------------------- #
#  Locate the underlying audit script (same folder as this launcher).         #
# --------------------------------------------------------------------------- #
$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$auditScript = Join-Path $scriptDir 'Get-IntuneEndpointReport.ps1'
if (-not (Test-Path $auditScript)) {
    Write-Host "ERROR: Get-IntuneEndpointReport.ps1 was not found next to this launcher ($scriptDir)." -ForegroundColor Red
    Write-Host 'Place both scripts in the same folder and try again.' -ForegroundColor Red
    return
}

# --------------------------------------------------------------------------- #
#  Session configuration (mutable via the Configure menu).                    #
# --------------------------------------------------------------------------- #
$script:cfg = [ordered]@{
    OutputPath         = $OutputPath
    CheckInWindowWeeks = $CheckInWindowWeeks
    TenantId           = $TenantId
    DomainController   = $DomainController
    DiagnoseBaselines  = [bool]$DiagnoseBaselines
}

# --------------------------------------------------------------------------- #
#  Helpers                                                                     #
# --------------------------------------------------------------------------- #
function Write-Rule { param([string]$Char = '=') Write-Host ($Char * 72) -ForegroundColor DarkCyan }

function Show-Header {
    Clear-Host
    Write-Rule
    Write-Host '            CYBER ESSENTIALS READINESS AUDIT  -  Launcher' -ForegroundColor Cyan
    Write-Rule
    Write-Host ''
}

# Build the parameter splat for the audit script from current config + a mode.
function Get-AuditParams {
    param([ValidateSet('CloudOnly','Hybrid')][string]$RunMode)
    $p = @{ Mode = $RunMode }
    if ($script:cfg.OutputPath)        { $p['OutputPath']        = $script:cfg.OutputPath }
    if ($script:cfg.CheckInWindowWeeks){ $p['CheckInWindowWeeks']= $script:cfg.CheckInWindowWeeks }
    if ($script:cfg.TenantId)          { $p['TenantId']          = $script:cfg.TenantId }
    if ($RunMode -eq 'Hybrid' -and $script:cfg.DomainController) { $p['DomainController'] = $script:cfg.DomainController }
    if ($script:cfg.DiagnoseBaselines) { $p['DiagnoseBaselines'] = $true }
    return $p
}

# Render the equivalent command line (for transparency / copy-paste).
function Get-CommandPreview {
    param([ValidateSet('CloudOnly','Hybrid')][string]$RunMode)
    $parts = @(".\Get-IntuneEndpointReport.ps1", "-Mode $RunMode")
    if ($script:cfg.OutputPath)         { $parts += "-OutputPath `"$($script:cfg.OutputPath)`"" }
    if ($script:cfg.CheckInWindowWeeks) { $parts += "-CheckInWindowWeeks $($script:cfg.CheckInWindowWeeks)" }
    if ($script:cfg.TenantId)           { $parts += "-TenantId $($script:cfg.TenantId)" }
    if ($RunMode -eq 'Hybrid' -and $script:cfg.DomainController) { $parts += "-DomainController $($script:cfg.DomainController)" }
    if ($script:cfg.DiagnoseBaselines)  { $parts += "-DiagnoseBaselines" }
    return ($parts -join ' ')
}

function Invoke-Audit {
    param([ValidateSet('CloudOnly','Hybrid')][string]$RunMode)
    Show-Header
    Write-Host ("Running audit in {0} mode..." -f $RunMode) -ForegroundColor Cyan
    Write-Host ("Command: {0}" -f (Get-CommandPreview -RunMode $RunMode)) -ForegroundColor DarkGray
    Write-Host ''
    $params = Get-AuditParams -RunMode $RunMode
    try {
        & $auditScript @params
        Write-Host ''
        Write-Host 'Audit completed.' -ForegroundColor Green
    } catch {
        Write-Host ''
        Write-Host ("Audit failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
}

function Edit-Configuration {
    while ($true) {
        Show-Header
        Write-Host 'CONFIGURE OPTIONS  (press Enter to keep the current value)' -ForegroundColor Cyan
        Write-Host ''
        Write-Host ("  1. Output path .............. {0}" -f $(if ($script:cfg.OutputPath) { $script:cfg.OutputPath } else { '(auto: timestamped .xlsx in current folder)' }))
        Write-Host ("  2. Check-in window (weeks) .. {0}" -f $script:cfg.CheckInWindowWeeks)
        Write-Host ("  3. Tenant ID ................ {0}" -f $(if ($script:cfg.TenantId) { $script:cfg.TenantId } else { '(interactive default)' }))
        Write-Host ("  4. Domain controller (FQDN) . {0}" -f $(if ($script:cfg.DomainController) { $script:cfg.DomainController } else { '(integrated / current DC)' }))
        Write-Host ("  5. Baseline diagnostics ..... {0}" -f $(if ($script:cfg.DiagnoseBaselines) { 'On' } else { 'Off' }))
        Write-Host '  B. Back to main menu'
        Write-Host ''
        $sel = Read-Host 'Select an option to change'
        switch ($sel) {
            '1' { $v = Read-Host 'Output path (full .xlsx path)';        if ($v) { $script:cfg.OutputPath = $v } }
            '2' {
                $v = Read-Host 'Check-in window in weeks (number)'
                if ($v -match '^\d+$') { $script:cfg.CheckInWindowWeeks = [int]$v }
                elseif ($v) { Write-Host 'Not a number - unchanged.' -ForegroundColor Yellow; Start-Sleep 1 }
            }
            '3' { $v = Read-Host 'Tenant ID (GUID or domain)';            if ($v) { $script:cfg.TenantId = $v } }
            '4' { $v = Read-Host 'Domain controller FQDN';                if ($v) { $script:cfg.DomainController = $v } }
            '5' { $script:cfg.DiagnoseBaselines = -not $script:cfg.DiagnoseBaselines }
            'b' { return }
            'B' { return }
            default { }
        }
    }
}

function Invoke-DependencyCheck {
    Show-Header
    Write-Host 'DEPENDENCY CHECK' -ForegroundColor Cyan
    Write-Host ''
    $deps = @(
        @{ Name = 'Microsoft.Graph.Authentication'; Kind = 'PSGallery'; Version = '2.25.0' }
        @{ Name = 'ImportExcel';                    Kind = 'PSGallery'; Version = '7.8.10' }
        @{ Name = 'ActiveDirectory'; Kind = 'RSAT (hybrid only)' }
        @{ Name = 'GroupPolicy';     Kind = 'RSAT (hybrid only)' }
    )
    $missing = @()
    foreach ($d in $deps) {
        if (Get-Module -ListAvailable -Name $d.Name) {
            Write-Host ("  [OK]      {0}  ({1})" -f $d.Name, $d.Kind) -ForegroundColor Green
        } else {
            Write-Host ("  [MISSING] {0}  ({1})" -f $d.Name, $d.Kind) -ForegroundColor Yellow
            $missing += $d
        }
    }
    Write-Host ''
    if ($missing.Count -eq 0) {
        Write-Host 'All dependencies are present.' -ForegroundColor Green
    } else {
        Write-Host 'Note: the audit script also checks and offers to install dependencies at launch.' -ForegroundColor DarkGray
        $a = Read-Host 'Install the missing PSGallery modules now? [Y/N]'
        if ($a -match '^(y|yes)$') {
            # Capture PSGallery trust so we can restore it (don't leave it Trusted).
            $prevPolicy = $null
            try { $prevPolicy = (Get-PSRepository -Name PSGallery -ErrorAction Stop).InstallationPolicy } catch { }
            try {
                foreach ($d in ($missing | Where-Object { $_.Kind -eq 'PSGallery' })) {
                    Write-Host ("Installing {0} v{1}..." -f $d.Name, $d.Version) -ForegroundColor Cyan
                    try {
                        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
                        Install-Module $d.Name -RequiredVersion $d.Version -Repository PSGallery `
                            -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                        Write-Host ("  Installed {0}." -f $d.Name) -ForegroundColor Green
                    } catch {
                        Write-Host ("  Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                    }
                }
            } finally {
                if ($prevPolicy -and $prevPolicy -ne 'Trusted') {
                    try { Set-PSRepository -Name PSGallery -InstallationPolicy $prevPolicy -ErrorAction Stop } catch { }
                }
            }
            if ($missing | Where-Object { $_.Kind -like 'RSAT*' }) {
                Write-Host 'RSAT features (ActiveDirectory / GroupPolicy) are installed by the audit script when you run a Hybrid audit (requires an elevated session).' -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
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
    Write-Host 'You can run either of these directly instead of using this launcher.' -ForegroundColor DarkGray
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
}

function Open-OutputFolder {
    $folder = if ($script:cfg.OutputPath) { Split-Path -Parent $script:cfg.OutputPath } else { (Get-Location).Path }
    if ([string]::IsNullOrWhiteSpace($folder)) { $folder = (Get-Location).Path }
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
    Write-Host 'This launcher runs Get-IntuneEndpointReport.ps1, which produces a Cyber'
    Write-Host 'Essentials readiness workbook (.xlsx) covering: device list, MFA,'
    Write-Host 'software firewall, mobile devices, AutoPlay/AutoRun, shared accounts,'
    Write-Host 'application whitelisting, and password protection.'
    Write-Host ''
    Write-Host 'Cloud only : audits the Microsoft 365 / Intune tenant via Microsoft Graph.'
    Write-Host 'Hybrid     : ALSO audits on-premises Active Directory + Group Policy.'
    Write-Host '             Run this from a domain controller (uses integrated creds).'
    Write-Host ''
    Write-Host 'Output is a native .xlsx (no Microsoft Excel install required).'
    Write-Host 'You can also run the audit script directly - see "Show command".'
    Write-Host ''
    [void](Read-Host 'Press Enter to return to the menu')
}

# --------------------------------------------------------------------------- #
#  -NoMenu: run directly and exit (parameters forwarded).                     #
# --------------------------------------------------------------------------- #
if ($NoMenu) {
    $runMode = if ($Mode) { $Mode } else { 'CloudOnly' }
    Invoke-Audit -RunMode $runMode
    return
}

# --------------------------------------------------------------------------- #
#  Main menu loop                                                              #
# --------------------------------------------------------------------------- #
while ($true) {
    Show-Header
    Write-Host ("Mode-on-run is chosen below. Current options: window={0}wk; output={1}" -f `
        $script:cfg.CheckInWindowWeeks,
        $(if ($script:cfg.OutputPath) { Split-Path -Leaf $script:cfg.OutputPath } else { 'auto-named' })) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  1. Run audit  -  Cloud only'              -ForegroundColor White
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
        '1' { Invoke-Audit -RunMode 'CloudOnly' }
        '2' { Invoke-Audit -RunMode 'Hybrid' }
        '3' { Edit-Configuration }
        '4' { Invoke-DependencyCheck }
        '5' { Show-Command }
        '6' { Open-OutputFolder }
        '7' { Show-Help }
        'q' { break }
        'Q' { break }
        default { }
    }
}

Show-Header
Write-Host 'Goodbye.' -ForegroundColor Cyan

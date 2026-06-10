<#
.SYNOPSIS
    DEPRECATED compatibility wrapper - use the CyberEssentialsAudit module.

.DESCRIPTION
    The audit engine has been restructured into the CyberEssentialsAudit
    module (Invoke-CeAudit + Export-CeReport). This wrapper keeps the old
    entry point and parameter names working; it forwards to the module and
    will be removed in a future release.

    New equivalents:
        Import-Module .\CyberEssentialsAudit
        $audit = Invoke-CeAudit -Mode CloudOnly
        Export-CeReport -Audit $audit -Path .\report.xlsx

.NOTES
    -DiagnoseBaselines is no longer supported (intent diagnostics moved to
    -Verbose output) and is accepted but ignored.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath ("IntuneEndpointReport_{0:yyyyMMdd_HHmmss}.xlsx" -f (Get-Date))),
    [ValidateRange(1, 52)][int]$CheckInWindowWeeks = 6,
    [string]$TenantId,
    [ValidateSet('CloudOnly', 'Hybrid')][string]$Mode,
    [string]$DomainController,
    [System.Management.Automation.PSCredential]$ADCredential,
    [switch]$DiagnoseBaselines,
    [switch]$ForceOverwrite,
    [string]$GraphModuleVersion = '2.25.0',
    [string]$ImportExcelVersion = '7.8.10'
)

$ErrorActionPreference = 'Stop'

Write-Warning 'Get-IntuneEndpointReport.ps1 is deprecated. Use the CyberEssentialsAudit module (Invoke-CeAudit | Export-CeReport) or Start-CyberEssentialsAudit.ps1. This wrapper forwards to the module.'
if ($DiagnoseBaselines) {
    Write-Warning '-DiagnoseBaselines is no longer supported and will be ignored (run with -Verbose for intent diagnostics).'
}

# Interactive mode prompt, as before, when -Mode is not supplied.
if (-not $Mode) {
    Write-Host ''
    Write-Host 'Is this audit for a CLOUD-ONLY environment or a HYBRID environment' -ForegroundColor Cyan
    Write-Host '(on-premises Active Directory / domain controllers + Microsoft 365)?' -ForegroundColor Cyan
    Write-Host '  [1] Cloud only' -ForegroundColor White
    Write-Host '  [2] Hybrid'     -ForegroundColor White
    do { $choice = Read-Host 'Enter 1 or 2' } until ($choice -in @('1', '2'))
    $Mode = if ($choice -eq '2') { 'Hybrid' } else { 'CloudOnly' }
}

$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptDir 'CyberEssentialsAudit\CyberEssentialsAudit.psd1'
if (-not (Test-Path $modulePath)) {
    throw "The CyberEssentialsAudit module was not found at '$modulePath'. Keep the module folder next to this script."
}
Import-Module $modulePath -Force

$auditParams = @{
    Mode               = $Mode
    CheckInWindowWeeks = $CheckInWindowWeeks
    TranscriptPath     = [System.IO.Path]::ChangeExtension($OutputPath, '.log')
}
if ($TenantId)         { $auditParams['TenantId']         = $TenantId }
if ($DomainController) { $auditParams['DomainController'] = $DomainController }
if ($ADCredential)     { $auditParams['ADCredential']     = $ADCredential }

$audit = Invoke-CeAudit @auditParams
Export-CeReport -Audit $audit -Path $OutputPath -ForceOverwrite:$ForceOverwrite | Out-Null
Write-Host 'Done.' -ForegroundColor Green

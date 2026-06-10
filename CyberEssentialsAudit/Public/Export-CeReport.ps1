<#
.SYNOPSIS
    Renders an audit result (from Invoke-CeAudit) to Excel and/or JSON.

.DESCRIPTION
    Excel: a multi-tab workbook with a RAG Summary tab (one row per CE
    sub-requirement), Scope, per-control detail tabs and a Run info manifest.
    JSON: a machine-readable document (run manifest + every check verdict +
    key findings) for pipelines / SIEM ingestion.

    Output safety: the path must end in .xlsx; an existing file is only
    overwritten if it looks like a previous report or -ForceOverwrite is set;
    shared/network destinations trigger a data-sensitivity warning.

.EXAMPLE
    Export-CeReport -Audit $audit -Path C:\Reports\contoso.xlsx -Format Both
#>
function Export-CeReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Audit,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Excel', 'Json', 'Both')][string]$Format = 'Excel',
        [switch]$ForceOverwrite
    )

    process {
        $fullPath = [System.IO.Path]::GetFullPath($Path)

        if ([System.IO.Path]::GetExtension($fullPath) -ne '.xlsx') {
            throw "Path must end in .xlsx (got '$fullPath'). The JSON output (if requested) is written alongside it."
        }
        $outDir = Split-Path -Parent $fullPath
        if (-not (Test-Path -LiteralPath $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }

        # Warn when the destination is a shared/network location - the workbook
        # contains device names, UPNs, licence and AD data.
        $isUnc = ([uri]$fullPath).IsUnc
        $driveType = $null
        try { $driveType = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$((Split-Path -Qualifier $fullPath))'" -ErrorAction SilentlyContinue).DriveType } catch { }
        if ($isUnc -or $driveType -eq 4) {
            Write-Warning ("The report destination looks like a shared/network location:`n  {0}`nThis workbook contains device names, UPNs, licence and AD data - ensure the location is access-controlled." -f $fullPath)
        }

        # Never silently clobber a file that is not a previous report.
        if (Test-Path -LiteralPath $fullPath) {
            $leaf = Split-Path -Leaf $fullPath
            $looksLikeReport = ($leaf -like 'CyberEssentialsAudit_*.xlsx') -or ($leaf -like 'IntuneEndpointReport_*.xlsx')
            if (-not $looksLikeReport -and -not $ForceOverwrite) {
                throw "A file already exists at '$fullPath' and does not look like a previous report. Re-run with -ForceOverwrite to replace it, or choose a different -Path."
            }
            Remove-Item -LiteralPath $fullPath -Force -ErrorAction Stop
        }

        if ($Format -in @('Excel', 'Both')) {
            Write-Host 'Writing Excel workbook (ImportExcel / EPPlus - no Office needed)...' -ForegroundColor Cyan
            Export-CeWorkbook -Audit $Audit -Path $fullPath
            Write-Host ("Report saved to: {0}" -f $fullPath) -ForegroundColor Green
        }

        if ($Format -in @('Json', 'Both')) {
            $jsonPath = [System.IO.Path]::ChangeExtension($fullPath, '.json')
            if ((Test-Path -LiteralPath $jsonPath) -and -not $ForceOverwrite) {
                $jleaf = Split-Path -Leaf $jsonPath
                if ($jleaf -notlike 'CyberEssentialsAudit_*.json' -and $jleaf -notlike 'IntuneEndpointReport_*.json') {
                    throw "A file already exists at '$jsonPath'. Re-run with -ForceOverwrite to replace it."
                }
            }
            # JSON document: manifest + verdicts + key findings. Bulk raw user
            # objects are excluded deliberately (data minimisation).
            $doc = [ordered]@{
                runInfo = $Audit.RunInfo
                overall = $Audit.Overall
                checks  = $Audit.Checks
                scope   = $Audit.Scope.Details
                inventory = [ordered]@{
                    windows       = $Audit.Inventory.Windows
                    servers       = $Audit.Inventory.Servers
                    macOS         = $Audit.Inventory.MacOS
                    mobile        = $Audit.Inventory.Mobile
                    eolDevices    = $Audit.Inventory.EolDevices
                    sourceOfTruth = $Audit.Inventory.SourceOfTruth
                }
                findings = [ordered]@{
                    firewall        = $Audit.Sections.Firewall.Findings
                    malware         = $Audit.Sections.Malware.Findings
                    updateRings     = $Audit.Sections.Updates.RingRows
                    autoplay        = $Audit.Sections.Autoplay.Findings
                    appControl      = $Audit.Sections.AppControl.Findings
                    privilegedUsers = $Audit.Sections.Privileged.Findings
                    sharedAccounts  = $Audit.Sections.Accounts.SharedAccounts
                    staleAccounts   = $Audit.Sections.Accounts.StaleAccounts
                    mfaPolicies     = $Audit.Sections.Mfa.PolicyRows
                }
            }
            $doc | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            Write-Host ("JSON results saved to: {0}" -f $jsonPath) -ForegroundColor Green
        }

        return $fullPath
    }
}

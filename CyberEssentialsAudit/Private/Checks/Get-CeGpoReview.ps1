# Hybrid: enumerate all GPOs and run the STRUCTURED report parser over each
# (ConvertFrom-CeGpoReportXml - fixes B6). Findings are folded into the
# matching control checks by the orchestrator.
function Get-CeGpoReview {
    [CmdletBinding()]
    param([hashtable]$AdParams = @{})

    Write-Host 'Reviewing Group Policy Objects (structured setting parse)...' -ForegroundColor Cyan
    $findings = @()
    $reviewed = 0
    $failed   = 0

    $allGpos = @()
    try {
        $allGpos = @(Get-GPO @AdParams -All -ErrorAction Stop)
    } catch {
        Write-Warning "Could not enumerate GPOs: $($_.Exception.Message)"
        return [pscustomobject]@{ Findings = @(); Reviewed = 0; Failed = 0; EnumerationFailed = $true }
    }

    foreach ($g in $allGpos) {
        $reviewed++
        $xml = $null
        try {
            [xml]$xml = Get-GPOReport @AdParams -Guid $g.Id -ReportType Xml -ErrorAction Stop
        } catch {
            Write-Verbose "GPO report failed for $($g.DisplayName): $($_.Exception.Message)"
            $failed++
            continue
        }
        $findings += @(ConvertFrom-CeGpoReportXml -Xml $xml -GpoName $g.DisplayName -GpoStatus ([string]$g.GpoStatus))
    }

    Write-Host ("Reviewed {0} GPO(s); {1} structured finding(s); {2} report failure(s)." -f $reviewed, @($findings).Count, $failed) -ForegroundColor Green
    [pscustomobject]@{
        Findings          = @($findings)
        Reviewed          = $reviewed
        Failed            = $failed
        EnumerationFailed = $false
    }
}

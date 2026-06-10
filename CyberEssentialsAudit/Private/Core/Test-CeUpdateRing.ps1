# Evaluate a Windows Update for Business ring (windowsUpdateForBusinessConfiguration)
# against the Cyber Essentials 14-day patching requirement (Danzell: high/critical
# updates applied within 14 days - AUTO-FAIL territory).
#
# Worst-case days for a quality update to land =
#   deferral + deadline + grace. Anything over 14, or paused updates, fails.
function Test-CeUpdateRing {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Ring)

    $deferral = 0
    $deadline = $null
    $grace    = 0
    if ($null -ne $Ring.qualityUpdatesDeferralPeriodInDays) { $deferral = [int]$Ring.qualityUpdatesDeferralPeriodInDays }
    if ($null -ne $Ring.deadlineForQualityUpdatesInDays)    { $deadline = [int]$Ring.deadlineForQualityUpdatesInDays }
    if ($null -ne $Ring.deadlineGracePeriodInDays)          { $grace    = [int]$Ring.deadlineGracePeriodInDays }

    $paused = $false
    if ("$($Ring.qualityUpdatesPaused)" -match '(?i)true') { $paused = $true }
    if ("$($Ring.qualityUpdatesPauseExpiryDateTime)" -and $Ring.qualityUpdatesPaused) { $paused = $true }

    $verdict = 'Manual'
    $maxDays = $null
    $reason  = ''

    if ($paused) {
        $verdict = 'Fail'
        $reason  = 'Quality updates are PAUSED on this ring'
    } elseif ($null -eq $deadline) {
        $verdict = 'Manual'
        $maxDays = $deferral
        $reason  = "No enforced deadline configured (deferral $deferral d). Default/compliance deadlines may apply - verify devices actually install within 14 days"
    } else {
        $maxDays = $deferral + $deadline + $grace
        if ($maxDays -le 14) {
            $verdict = 'Pass'
            $reason  = "Worst case $maxDays day(s): deferral $deferral + deadline $deadline + grace $grace"
        } else {
            $verdict = 'Fail'
            $reason  = "Worst case $maxDays day(s) exceeds the 14-day CE requirement: deferral $deferral + deadline $deadline + grace $grace"
        }
    }

    [pscustomobject]@{
        RingName        = [string]$Ring.displayName
        Verdict         = $verdict
        MaxDays         = $maxDays
        QualityDeferral = $deferral
        Deadline        = $deadline
        Grace           = $grace
        Paused          = $paused
        FeatureDeferral = $(if ($null -ne $Ring.featureUpdatesDeferralPeriodInDays) { [int]$Ring.featureUpdatesDeferralPeriodInDays } else { 0 })
        AutomaticMode   = [string]$Ring.automaticUpdateMode
        Reason          = $reason
    }
}

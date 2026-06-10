# Pure MFA evaluation over Conditional Access policies + security defaults.
# Fixes B2 (disabled / report-only policies no longer counted as enforcing) and
# feeds B7 (security defaults surfaced as a valid MFA route).
function Get-CeMfaEvaluation {
    [CmdletBinding()]
    param(
        [object[]]$CaPolicies = @(),
        [bool]$SecurityDefaultsOn = $false,
        # $true when the CA policy read FAILED (so "no policies" is Unknown, not Fail).
        [bool]$CaReadFailed = $false
    )

    # A policy "requires MFA" if its grant controls include the mfa built-in
    # control or an authentication strength.
    $requiresMfa = {
        param($p)
        $builtIn = @()
        if ($p.grantControls -and $p.grantControls.builtInControls) { $builtIn = @($p.grantControls.builtInControls) }
        ($builtIn -contains 'mfa') -or ($p.grantControls -and $p.grantControls.authenticationStrength)
    }

    $mfaAll      = @($CaPolicies | Where-Object { & $requiresMfa $_ })
    $enforced    = @($mfaAll | Where-Object { [string]$_.state -eq 'enabled' })
    $reportOnly  = @($mfaAll | Where-Object { [string]$_.state -eq 'enabledForReportingButNotEnforced' })
    $disabled    = @($mfaAll | Where-Object { [string]$_.state -eq 'disabled' })

    # Does any ENFORCED policy cover all users AND all cloud apps?
    $fullCoverage = @($enforced | Where-Object {
        $apps  = $_.conditions.applications
        $users = $_.conditions.users
        (@($apps.includeApplications) -contains 'All') -and (@($users.includeUsers) -contains 'All')
    })

    $status = 'Unknown'; $reason = ''
    if ($SecurityDefaultsOn) {
        $status = 'Pass'
        $reason = 'Security defaults are enabled - Microsoft enforces MFA for all users (Conditional Access cannot coexist with security defaults)'
    } elseif ($fullCoverage.Count -gt 0) {
        $status = 'Pass'
        $reason = ("{0} enabled Conditional Access policy(ies) require MFA for All users / All cloud apps: {1}. Review the exclusions listed on the MFA tab." -f `
            $fullCoverage.Count, (($fullCoverage | ForEach-Object { $_.displayName }) -join '; '))
    } elseif ($enforced.Count -gt 0) {
        $status = 'Manual'
        $reason = ("{0} enabled policy(ies) require MFA but none covers All users AND All cloud apps. Verify combined coverage reaches every user and cloud service (CE auto-fail if not)." -f $enforced.Count)
    } elseif ($CaReadFailed) {
        $status = 'Unknown'
        $reason = 'Conditional Access policies could not be read (permissions/API error) and security defaults are off - MFA enforcement cannot be verified'
    } else {
        $status = 'Fail'
        $reason = 'Security defaults are OFF and no enabled Conditional Access policy requires MFA. MFA on cloud services is an AUTO-FAIL item under the Danzell question set.'
    }
    if (($reportOnly.Count + $disabled.Count) -gt 0 -and $status -ne 'Pass') {
        $reason += (" Note: {0} report-only and {1} disabled MFA policy(ies) exist but DO NOT enforce anything." -f $reportOnly.Count, $disabled.Count)
    }

    [pscustomobject]@{
        Status       = $status
        Reason       = $reason
        Enforced     = $enforced
        ReportOnly   = $reportOnly
        Disabled     = $disabled
        FullCoverage = $fullCoverage
    }
}

# Mobile management: app protection (MAM) policies, Conditional Access
# app-protection enforcement, and mobile compliance policies as fallback
# evidence. Mobile device rows come from the shared inventory (B10 applied
# there).
function Get-CeMobileCheck {
    [CmdletBinding()]
    param($Inventory)

    Write-Host 'Reviewing mobile app protection (MAM) policies...' -ForegroundColor Cyan

    # Extract scalar settings from an app protection policy, skipping metadata.
    function Get-CeAppPolicySettings {
        param($Policy)
        $skip = @('id','displayName','description','createdDateTime','lastModifiedDateTime',
                  'version','roleScopeTagIds','isAssigned','deployedAppCount','assignments',
                  'apps','@odata.type','@odata.context')
        $d = [ordered]@{}
        foreach ($pr in $Policy.PSObject.Properties) {
            $n = $pr.Name
            if ($skip -contains $n) { continue }
            $v = $pr.Value
            if ($null -eq $v) { continue }
            if ($v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double]) { $d[$n] = "$v"; continue }
            if ($v -is [string]) { if (-not [string]::IsNullOrWhiteSpace($v)) { $d[$n] = $v }; continue }
            if ($v -is [System.Collections.IEnumerable]) {
                $parts = @()
                foreach ($i in $v) { if ($i -is [string] -or $i -is [valuetype]) { $parts += "$i" } }
                if ($parts.Count) { $d[$n] = ($parts -join ', ') }
                continue
            }
        }
        return $d
    }

    $appPolicies = @()
    foreach ($plat in @(
        @{ Name = 'iOS';     Uri = $script:CeUri.IosAppProtections }
        @{ Name = 'Android'; Uri = $script:CeUri.AndroidAppProtections }
    )) {
        try {
            foreach ($p in @(Get-CeGraphPaged -Uri $plat.Uri -Area 'AppProtection')) {
                $asg = Get-CeAssignmentSummary $p.assignments
                $appPolicies += [pscustomobject]@{
                    Platform = $plat.Name; Name = $p.displayName
                    Included = $asg.Included; Excluded = $asg.Excluded
                    Settings = (Get-CeAppPolicySettings $p)
                }
            }
        } catch { }
    }
    $appPolicies = @($appPolicies)

    # CA policies that require an approved app / app protection policy.
    $caAppEnforce = @()
    $caPolicies = @()
    try { $caPolicies = Get-CeCollection -Key 'caPolicies' -Uri $script:CeUri.CaPolicies -Area 'ConditionalAccess' } catch { }
    foreach ($p in @($caPolicies)) {
        $bic = @()
        if ($p.grantControls -and $p.grantControls.builtInControls) { $bic = @($p.grantControls.builtInControls) }
        if (($bic -contains 'compliantApplication') -or ($bic -contains 'approvedApplication')) {
            $caAppEnforce += [pscustomobject]@{ Name = $p.displayName; State = $p.state }
        }
    }
    $caAppEnforce = @($caAppEnforce)

    # Mobile compliance policies (fallback evidence).
    $fallback = @()
    try {
        foreach ($p in @(Get-CeCompliancePolicies)) {
            $t = [string]$p.'@odata.type'
            if ($t -match '(?i)android' -or $t -match '(?i)ios') {
                $asg  = Get-CeAssignmentSummary $p.assignments
                $plat = if ($t -match '(?i)android') { 'Android' } elseif ($t -match '(?i)ios') { 'iOS' } else { 'Mobile' }
                $fallback += [pscustomobject]@{
                    Name = $p.displayName; Platform = $plat; Type = 'Compliance policy'
                    Included = $asg.Included; Excluded = $asg.Excluded
                }
            }
        }
    } catch { }
    $fallback = @($fallback)

    $mobileCount = 0
    if ($Inventory) { $mobileCount = @($Inventory.Mobile).Count }
    $areaFailed = Test-CeAreaFailed -Area @('AppProtection', 'CompliancePolicies')

    if ($mobileCount -eq 0) {
        $status = 'Manual'
        $reason = 'No mobile devices within the check-in window. If personal (BYOD) phones access organisational data (email, Teams), they ARE in CE scope - confirm none do, or bring them under management.'
    } elseif ($appPolicies.Count -gt 0) {
        $status = 'Pass'
        $reason = ("{0} mobile device(s) in scope with {1} app protection (MAM) policy/policies{2}" -f `
            $mobileCount, $appPolicies.Count,
            $(if ($caAppEnforce.Count) { (" and {0} Conditional Access policy(ies) enforcing app protection" -f $caAppEnforce.Count) } else { ' - consider a Conditional Access policy to enforce app protection at sign-in' }))
    } elseif ($fallback.Count -gt 0) {
        $status = 'Manual'
        $reason = ("{0} mobile device(s) in scope; no app protection (MAM) policies but {1} mobile compliance policy/policies exist. Verify mobiles meet CE: PIN/biometric lock, supported OS, and protected access to organisational data." -f $mobileCount, $fallback.Count)
    } elseif ($areaFailed) {
        $status = 'Unknown'
        $reason = 'App protection / compliance policies could not be read'
    } else {
        $status = 'Fail'
        $reason = ("{0} mobile device(s) access organisational data with no app protection or compliance policy in place" -f $mobileCount)
    }

    [pscustomobject]@{
        Results = @(
            New-CeCheckResult -Control 'Secure configuration' -CheckId 'CE-SC-04' `
                -Title 'Mobile devices managed and protected' `
                -Status $status -Reason $reason `
                -Evidence ("{0} mobile device(s); {1} MAM policies; {2} CA app-protection policies; {3} compliance policies" -f $mobileCount, $appPolicies.Count, $caAppEnforce.Count, $fallback.Count) `
                -DetailSheet 'Mobile devices'
        )
        AppPolicies  = $appPolicies
        CaAppEnforce = $caAppEnforce
        Fallback     = $fallback
    }
}

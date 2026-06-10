# Application allow-listing (AppLocker / App Control for Business / WDAC) -
# an alternative/additional route to the malware-protection control. Consumes
# the shared cached inventories plus structured hybrid GPO findings.
function Get-CeAppControlCheck {
    [CmdletBinding()]
    param([object[]]$GpoFindings = @())

    Write-Host 'Reviewing application allow-listing policies...' -ForegroundColor Cyan
    $awPattern = '(?i)applocker|appcontrol|app control|wdac|windowsdefenderapplicationcontrol|application control|codeintegrity|smartappcontrol|applicationcontrol'
    $findings = @()

    # 1) Classic Endpoint Protection profiles (appLockerApplicationControl).
    try {
        foreach ($p in @(Get-CeDeviceConfigurations)) {
            if ($p.'@odata.type' -ne '#microsoft.graph.windows10EndpointProtectionConfiguration') { continue }
            $alc = [string]$p.appLockerApplicationControl
            if ([string]::IsNullOrWhiteSpace($alc) -or $alc -eq 'notConfigured') { continue }
            $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.DeviceConfigurations -Id $p.id -Area 'DeviceConfigurations')
            $findings += [pscustomobject]@{
                Source = 'Endpoint Protection profile'; PolicyName = $p.displayName
                Mechanism = 'AppLocker'; Setting = "appLockerApplicationControl = $alc"
                Included = $asg.Included; Excluded = $asg.Excluded
            }
        }
    } catch { }

    # 2) Settings catalog (per-setting ids, not raw-JSON regex).
    try {
        foreach ($cp in @(Get-CeCatalogPolicies)) {
            $hits = @($cp.Pairs | Where-Object { $_.Id -match $awPattern })
            $nameHit = ("$($cp.Policy.name)" -match $awPattern)
            if ($hits.Count -eq 0 -and -not $nameHit) { continue }
            $hay = (@($hits | ForEach-Object { $_.Id }) + @($cp.Policy.name)) -join ' '
            $mech = if     ($hay -match '(?i)applocker') { 'AppLocker' }
                    elseif ($hay -match '(?i)smartappcontrol') { 'Smart App Control' }
                    elseif ($hay -match '(?i)appcontrol|app control|wdac|applicationcontrol|codeintegrity') { 'App Control for Business / WDAC' }
                    else   { 'Application control' }
            $setting = if ($hits.Count) {
                (@($hits | Select-Object -First 5 | ForEach-Object { "{0} = {1}" -f (($_.Id -split '_')[-1]), (($_.Value -split '_')[-1]) }) -join '; ')
            } else { 'Policy name indicates application control (review policy)' }
            $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.ConfigurationPolicies -Id $cp.Policy.id -Area 'ConfigurationPolicies')
            $findings += [pscustomobject]@{
                Source = 'Settings catalog policy'; PolicyName = $cp.Policy.name
                Mechanism = $mech; Setting = $setting
                Included = $asg.Included; Excluded = $asg.Excluded
            }
        }
    } catch { }

    # 3) Endpoint-security intents & baselines.
    try {
        foreach ($ii in @(Get-CeIntentInventory)) {
            $matched = $false; $label = $null
            if ("$($ii.TemplateName) $($ii.Intent.displayName)" -match $awPattern) { $matched = $true; $label = $ii.TemplateName }
            foreach ($cs in @($ii.CategorySettings)) {
                $did  = [string]$cs.Setting.definitionId
                $name = [string]$ii.DefMap[$did]
                if ("$($cs.Category) $did $name" -match $awPattern) {
                    $matched = $true
                    if (-not $label) { $label = if ($name) { $name } else { $cs.Category } }
                }
            }
            if (-not $matched) { continue }
            $mech = if     ("$($ii.TemplateName) $label" -match '(?i)applocker') { 'AppLocker' }
                    elseif ("$($ii.TemplateName) $label" -match '(?i)appcontrol|app control|wdac|applicationcontrol|codeintegrity') { 'App Control for Business / WDAC' }
                    else   { 'Application control' }
            $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.Intents -Id $ii.Intent.id -Area 'Intents')
            $findings += [pscustomobject]@{
                Source = $(if ($ii.TemplateName -match '(?i)baseline') { 'Security baseline (intent)' } else { 'Endpoint security (intent)' })
                PolicyName = $ii.Intent.displayName; Mechanism = $mech
                Setting = $(if ($label) { "Template/setting: $label" } else { 'Application-control template' })
                Included = $asg.Included; Excluded = $asg.Excluded
            }
        }
    } catch { }

    # 4) Custom OMA-URI profiles referencing AppLocker / WDAC CSPs.
    try {
        foreach ($p in @(Get-CeDeviceConfigurations)) {
            if ([string]$p.'@odata.type' -notmatch '(?i)customConfiguration') { continue }
            $dcAsg = $null
            foreach ($oma in @($p.omaSettings)) {
                $omaUri = [string]$oma.omaUri
                if ($omaUri -notmatch $awPattern) { continue }
                if ($null -eq $dcAsg) {
                    $dcAsg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.DeviceConfigurations -Id $p.id -Area 'DeviceConfigurations')
                }
                $mech = if ($omaUri -match '(?i)applocker') { 'AppLocker' } else { 'App Control for Business / WDAC' }
                $findings += [pscustomobject]@{
                    Source = 'Custom OMA-URI'; PolicyName = $p.displayName; Mechanism = $mech
                    Setting = $omaUri; Included = $dcAsg.Included; Excluded = $dcAsg.Excluded
                }
            }
        }
    } catch { }

    # 5) Hybrid GPO (AppLocker rule collections / SRP - structured parse).
    foreach ($gf in @($GpoFindings | Where-Object { $_.Control -eq 'Application whitelisting' })) {
        $findings += [pscustomobject]@{
            Source = 'On-prem GPO'; PolicyName = $gf.GPO
            Mechanism = 'AppLocker / SRP (GPO)'; Setting = ("{0} = {1}" -f $gf.Setting, $gf.Value)
            Included = $gf.LinkedOUs; Excluded = 'N/A (GPO link scope)'
        }
    }

    $findings = @($findings)
    $areaFailed = Test-CeAreaFailed -Area @('DeviceConfigurations', 'ConfigurationPolicies', 'Intents')

    if ($findings.Count -gt 0) {
        $status = 'Manual'
        $reason = ("{0} application-control finding(s). Allow-listing can satisfy the CE malware-protection control - verify enforcement mode (not audit-only) and coverage." -f $findings.Count)
    } elseif ($areaFailed) {
        $status = 'Unknown'
        $reason = 'Policy reads failed - application-control configuration cannot be verified'
    } else {
        $status = 'Manual'
        $reason = 'No Intune application allow-listing policy found. Check whether ThreatLocker or another third-party allow-listing product is enforced on endpoints; if malware protection relies on Defender AV instead, no action is needed here.'
    }

    [pscustomobject]@{
        Results = @(
            New-CeCheckResult -Control 'Malware protection' -CheckId 'CE-MP-05' `
                -Title 'Application allow-listing (alternative malware-protection route)' `
                -Status $status -Reason $reason `
                -Evidence ("{0} application-control finding(s)" -f $findings.Count) `
                -DetailSheet 'Application whitelisting'
        )
        Findings = $findings
    }
}

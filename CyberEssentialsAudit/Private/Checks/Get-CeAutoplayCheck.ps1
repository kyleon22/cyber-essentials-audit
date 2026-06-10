# Secure configuration: AutoPlay / AutoRun disabled. Consumes the shared
# cached inventories (settings catalog, admin templates, OMA-URI profiles,
# intents) plus structured hybrid GPO findings.
function Get-CeAutoplayCheck {
    [CmdletBinding()]
    param([object[]]$GpoFindings = @())

    Write-Host 'Reviewing AutoPlay / AutoRun policies...' -ForegroundColor Cyan
    $findings = @()

    # 1) Settings catalog.
    try {
        foreach ($cp in @(Get-CeCatalogPolicies)) {
            $hits = @($cp.Pairs | Where-Object { $_.Id -match '(?i)autoplay|autorun' })
            if ($hits.Count -eq 0) { continue }
            $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.ConfigurationPolicies -Id $cp.Policy.id -Area 'ConfigurationPolicies')
            foreach ($h in $hits) {
                $set   = ("$($h.Id)" -split '_config_')[-1]
                $state = if     ("$($h.Value)" -match '(?i)_1$|_true$|donotexecute|donotplay|enabled') { 'Enabled (disables AutoPlay/AutoRun)' }
                         elseif ("$($h.Value)" -match '(?i)_0$|_false$') { 'Not enforced' }
                         else   { "$($h.Value)" }
                $findings += [pscustomobject]@{
                    Source = 'Settings catalog'; PolicyName = $cp.Policy.name; Setting = $set
                    State = $state; Included = $asg.Included; Excluded = $asg.Excluded
                    Enforces = ($state -like 'Enabled*' -and $asg.IsAssigned)
                }
            }
        }
    } catch { }

    # 2) Administrative templates (group policy configurations).
    try {
        $gpConfigs = Get-CeCollection -Key 'groupPolicyConfigs' -Uri $script:CeUri.GroupPolicyConfigs -Area 'AdminTemplates'
        foreach ($cfg in @($gpConfigs)) {
            $dv = $null
            try { $dv = Get-CeGraphJson -Uri ("{0}/{1}/definitionValues?`$expand=definition" -f $script:CeUri.GroupPolicyConfigs, $cfg.id) -Area 'AdminTemplates' } catch { }
            $cfgAsg = $null
            foreach ($d in @($dv.value)) {
                $name = [string]$d.definition.displayName
                if ($name -notmatch '(?i)autoplay|autorun') { continue }
                if ($null -eq $cfgAsg) {
                    $cfgAsg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.GroupPolicyConfigs -Id $cfg.id -Area 'AdminTemplates')
                }
                $findings += [pscustomobject]@{
                    Source = 'Administrative template'; PolicyName = $cfg.displayName; Setting = $name
                    State = $(if ($d.enabled) { 'Enabled' } else { 'Disabled / Not configured' })
                    Included = $cfgAsg.Included; Excluded = $cfgAsg.Excluded
                    Enforces = ([bool]$d.enabled -and $cfgAsg.IsAssigned)
                }
            }
        }
    } catch { }

    # 3) Custom OMA-URI profiles.
    try {
        foreach ($p in @(Get-CeDeviceConfigurations)) {
            if ([string]$p.'@odata.type' -notmatch '(?i)customConfiguration') { continue }
            $dcAsg = $null
            foreach ($oma in @($p.omaSettings)) {
                $omaUri = [string]$oma.omaUri
                if ($omaUri -notmatch '(?i)autoplay|autorun') { continue }
                if ($null -eq $dcAsg) {
                    $dcAsg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.DeviceConfigurations -Id $p.id -Area 'DeviceConfigurations')
                }
                $findings += [pscustomobject]@{
                    Source = 'Custom OMA-URI'; PolicyName = $p.displayName
                    Setting = ("{0} [{1}]" -f $oma.displayName, $omaUri)
                    State = "$($oma.value)"; Included = $dcAsg.Included; Excluded = $dcAsg.Excluded
                    Enforces = $dcAsg.IsAssigned
                }
            }
        }
    } catch { }

    # 4) Security baselines / endpoint-security intents.
    try {
        foreach ($ii in @(Get-CeIntentInventory)) {
            $iAsg = $null
            foreach ($cs in @($ii.CategorySettings)) {
                $did  = [string]$cs.Setting.definitionId
                $name = [string]$ii.DefMap[$did]
                $hay  = "$($cs.Category) $did $name"
                if ($hay -notmatch '(?i)autoplay|autorun') { continue }
                if ($null -eq $iAsg) {
                    $iAsg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.Intents -Id $ii.Intent.id -Area 'Intents')
                }
                $label = if ($name) { $name } elseif ($cs.Category) { "$($cs.Category) / $(($did -split '_') | Select-Object -Last 1)" } else { ($did -split '_') | Select-Object -Last 1 }
                $valStr = Get-CeIntentSettingValue $cs.Setting
                $findings += [pscustomobject]@{
                    Source = 'Security baseline (intent)'; PolicyName = $ii.Intent.displayName; Setting = $label
                    State = $valStr; Included = $iAsg.Included; Excluded = $iAsg.Excluded
                    Enforces = ($valStr -match '(?i)enabled|true|blocked|disallow' -and $iAsg.IsAssigned)
                }
            }
        }
    } catch { }

    # 5) Hybrid GPO (structured).
    foreach ($gf in @($GpoFindings | Where-Object { $_.Control -eq 'AutoPlay/AutoRun' })) {
        $findings += [pscustomobject]@{
            Source = 'On-prem GPO'; PolicyName = $gf.GPO; Setting = $gf.Setting
            State = $gf.Value; Included = $gf.LinkedOUs; Excluded = 'N/A (GPO link scope)'
            Enforces = ($gf.Value -match '(?i)enabled' -and $gf.LinkedOUs -ne 'Not linked')
        }
    }

    $findings = @($findings)
    $enforcing = @($findings | Where-Object { $_.Enforces })
    $areaFailed = Test-CeAreaFailed -Area @('ConfigurationPolicies', 'AdminTemplates', 'DeviceConfigurations', 'Intents')

    if ($enforcing.Count -gt 0) {
        $status = 'Pass'
        $reason = ("{0} assigned setting(s) disable AutoPlay/AutoRun: {1}" -f $enforcing.Count, (($enforcing | Select-Object -First 5 | ForEach-Object { $_.PolicyName } | Sort-Object -Unique) -join '; '))
    } elseif ($findings.Count -gt 0) {
        $status = 'Manual'
        $reason = 'AutoPlay/AutoRun settings exist but none was confirmed as enforced on assigned devices - review the tab'
    } elseif ($areaFailed) {
        $status = 'Unknown'
        $reason = 'Policy reads failed - AutoPlay status cannot be verified (see Run info tab)'
    } else {
        $status = 'Fail'
        $reason = 'No policy disabling AutoPlay/AutoRun was found'
    }

    [pscustomobject]@{
        Results = @(
            New-CeCheckResult -Control 'Secure configuration' -CheckId 'CE-SC-01' `
                -Title 'AutoPlay / AutoRun disabled' `
                -Status $status -Reason $reason `
                -Evidence ("{0} finding(s); {1} enforcing" -f $findings.Count, $enforcing.Count) `
                -DetailSheet 'Status of autoplay-autorun'
        )
        Findings = $findings
    }
}

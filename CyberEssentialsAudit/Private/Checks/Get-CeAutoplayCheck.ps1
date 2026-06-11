# Secure configuration: AutoPlay / AutoRun disabled.
#
# Robustness rules (an enabled security baseline must NEVER be reported as
# "no setting found"):
#   * Matching uses the separator-tolerant $script:CeAutoplayPattern - the
#     legacy MDM security baselines surface these settings as "Auto Play" /
#     "Auto play default auto run behavior" (with spaces), which a plain
#     'autoplay|autorun' regex misses entirely.
#   * Five sources are scanned: settings catalog (INCLUDING modern security
#     baselines, which are settings-catalog policies with a templateReference),
#     administrative templates, custom OMA-URI profiles, legacy endpoint
#     security / baseline intents, and hybrid GPO findings.
#   * Every source records how many objects it scanned and whether any read
#     failed; a failed read can only ever produce Unknown, never Fail.
function Get-CeAutoplayCheck {
    [CmdletBinding()]
    param([object[]]$GpoFindings = @())

    Write-Host 'Reviewing AutoPlay / AutoRun policies...' -ForegroundColor Cyan
    $pattern  = $script:CeAutoplayPattern
    $findings = @()
    $scan = [ordered]@{
        CatalogPoliciesScanned   = 0
        CatalogSettingsUnreadable = 0
        AdminTemplatesScanned    = 0
        OmaProfilesScanned       = 0
        IntentsScanned           = 0
        GpoFindingsSupplied      = @($GpoFindings).Count
    }

    # 1) Settings catalog - includes modern security baselines (templateReference).
    try {
        foreach ($cp in @(Get-CeCatalogPolicies)) {
            $scan.CatalogPoliciesScanned++
            if (-not $cp.SettingsRead) { $scan.CatalogSettingsUnreadable++ }
            $source = if ($cp.TemplateFamily -match '(?i)baseline') { 'Security baseline (settings catalog)' }
                      elseif ($cp.TemplateFamily) { "Endpoint security (settings catalog)" }
                      else { 'Settings catalog' }
            $asg = $null
            foreach ($pair in @($cp.Pairs)) {
                $ap = ConvertTo-CeAutoplaySetting -Pair $pair
                if ($null -eq $ap) { continue }
                if ($null -eq $asg) {
                    $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.ConfigurationPolicies -Id $cp.Policy.id -Area 'ConfigurationPolicies')
                }
                $findings += [pscustomobject]@{
                    Source = $source; PolicyName = $cp.Policy.name; Setting = $ap.Setting
                    State = $ap.State; Included = $asg.Included; Excluded = $asg.Excluded
                    Enforces = ($ap.Disables -and $asg.IsAssigned)
                    Configured = $ap.Disables
                }
            }
            # Defence in depth: a policy NAMED for AutoPlay whose settings did
            # not yield a match (or could not be read) still gets surfaced.
            if ("$($cp.Policy.name)" -match $pattern -and -not @($findings | Where-Object { $_.PolicyName -eq $cp.Policy.name }).Count) {
                if ($null -eq $asg) {
                    $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.ConfigurationPolicies -Id $cp.Policy.id -Area 'ConfigurationPolicies')
                }
                $findings += [pscustomobject]@{
                    Source = $source; PolicyName = $cp.Policy.name
                    Setting = $(if ($cp.SettingsRead) { 'Policy name indicates AutoPlay/AutoRun - review the policy' } else { 'Policy settings could not be read - review manually' })
                    State = 'Review required'; Included = $asg.Included; Excluded = $asg.Excluded
                    Enforces = $false; Configured = $false
                }
            }
        }
    } catch { }

    # 2) Administrative templates (group policy configurations).
    try {
        $gpConfigs = Get-CeCollection -Key 'groupPolicyConfigs' -Uri $script:CeUri.GroupPolicyConfigs -Area 'AdminTemplates'
        foreach ($cfg in @($gpConfigs)) {
            $scan.AdminTemplatesScanned++
            $dv = $null
            try { $dv = Get-CeGraphJson -Uri ("{0}/{1}/definitionValues?`$expand=definition" -f $script:CeUri.GroupPolicyConfigs, $cfg.id) -Area 'AdminTemplates' } catch { }
            $cfgAsg = $null
            foreach ($d in @($dv.value)) {
                $name = [string]$d.definition.displayName
                if ($name -notmatch $pattern) { continue }
                if ($null -eq $cfgAsg) {
                    $cfgAsg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.GroupPolicyConfigs -Id $cfg.id -Area 'AdminTemplates')
                }
                $enabled = [bool]$d.enabled
                $findings += [pscustomobject]@{
                    Source = 'Administrative template'; PolicyName = $cfg.displayName; Setting = $name
                    State = $(if ($enabled) { 'Enabled' } else { 'Disabled / Not configured' })
                    Included = $cfgAsg.Included; Excluded = $cfgAsg.Excluded
                    Enforces = ($enabled -and $cfgAsg.IsAssigned)
                    Configured = $enabled
                }
            }
        }
    } catch { }

    # 3) Custom OMA-URI profiles.
    try {
        foreach ($p in @(Get-CeDeviceConfigurations)) {
            if ([string]$p.'@odata.type' -notmatch '(?i)customConfiguration') { continue }
            $scan.OmaProfilesScanned++
            $dcAsg = $null
            foreach ($oma in @($p.omaSettings)) {
                $omaUri = [string]$oma.omaUri
                if ("$omaUri $($oma.displayName)" -notmatch $pattern) { continue }
                if ($null -eq $dcAsg) {
                    $dcAsg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.DeviceConfigurations -Id $p.id -Area 'DeviceConfigurations')
                }
                $findings += [pscustomobject]@{
                    Source = 'Custom OMA-URI'; PolicyName = $p.displayName
                    Setting = ("{0} [{1}]" -f $oma.displayName, $omaUri)
                    State = "$($oma.value)"; Included = $dcAsg.Included; Excluded = $dcAsg.Excluded
                    Enforces = $dcAsg.IsAssigned
                    Configured = $true
                }
            }
        }
    } catch { }

    # 4) Legacy endpoint-security / security-baseline intents. Match on the
    #    category name ("Auto Play"), the resolved setting display name
    #    ("Block auto play for non-volume devices") AND the definitionId.
    try {
        foreach ($ii in @(Get-CeIntentInventory)) {
            $scan.IntentsScanned++
            $iAsg = $null
            foreach ($cs in @($ii.CategorySettings)) {
                $did  = [string]$cs.Setting.definitionId
                $name = [string]$ii.DefMap[$did]
                $hay  = "$($cs.Category) $did $name"
                if ($hay -notmatch $pattern) { continue }
                if ($null -eq $iAsg) {
                    $iAsg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.Intents -Id $ii.Intent.id -Area 'Intents')
                }
                $label = if ($name) { $name } elseif ($cs.Category) { "$($cs.Category) / $(($did -split '_') | Select-Object -Last 1)" } else { ($did -split '_') | Select-Object -Last 1 }
                $valStr = Get-CeIntentSettingValue $cs.Setting
                # Legacy-baseline values are readable strings ("blocked",
                # "doNotExecute", "disabled" = AutoPlay off) or booleans.
                $disables = ($valStr -match '(?i)enabled|true|blocked|disallow|donotexecute|doNotExecute|notAllowed|disabled')
                $findings += [pscustomobject]@{
                    Source = $(if ($ii.TemplateName -match '(?i)baseline') { 'Security baseline (intent)' } else { 'Endpoint security (intent)' })
                    PolicyName = $ii.Intent.displayName; Setting = $label
                    State = $valStr; Included = $iAsg.Included; Excluded = $iAsg.Excluded
                    Enforces = ($disables -and $iAsg.IsAssigned)
                    Configured = $disables
                }
            }
        }
    } catch { }

    # 5) Hybrid GPO (structured parse).
    foreach ($gf in @($GpoFindings | Where-Object { $_.Control -eq 'AutoPlay/AutoRun' })) {
        $enabled = ($gf.Value -match '(?i)enabled|true')
        $findings += [pscustomobject]@{
            Source = 'On-prem GPO'; PolicyName = $gf.GPO; Setting = $gf.Setting
            State = $gf.Value; Included = $gf.LinkedOUs; Excluded = 'N/A (GPO link scope)'
            Enforces = ($enabled -and $gf.LinkedOUs -ne 'Not linked')
            Configured = $enabled
        }
    }

    $findings   = @($findings)
    $enforcing  = @($findings | Where-Object { $_.Enforces })
    $configured = @($findings | Where-Object { $_.Configured })
    $areaFailed = (Test-CeAreaFailed -Area @('ConfigurationPolicies', 'AdminTemplates', 'DeviceConfigurations', 'Intents')) -or
                  ($scan.CatalogSettingsUnreadable -gt 0)

    $coverage = ("Scanned: {0} settings-catalog policies (incl. baselines{1}), {2} administrative templates, {3} OMA-URI profiles, {4} endpoint-security/baseline intents{5}." -f `
        $scan.CatalogPoliciesScanned,
        $(if ($scan.CatalogSettingsUnreadable) { "; {0} unreadable" -f $scan.CatalogSettingsUnreadable } else { '' }),
        $scan.AdminTemplatesScanned, $scan.OmaProfilesScanned, $scan.IntentsScanned,
        $(if ($scan.GpoFindingsSupplied) { ", {0} GPO finding(s)" -f $scan.GpoFindingsSupplied } else { '' }))

    if ($enforcing.Count -gt 0) {
        $status = 'Pass'
        $reason = ("{0} assigned setting(s) disable AutoPlay/AutoRun: {1}. {2}" -f `
            $enforcing.Count,
            (($enforcing | Select-Object -First 5 | ForEach-Object { $_.PolicyName } | Sort-Object -Unique) -join '; '),
            $coverage)
    } elseif ($configured.Count -gt 0) {
        $status = 'Manual'
        $reason = ("AutoPlay/AutoRun is disabled in {0} policy/policies but NONE is assigned to any device/group - assign the policy or confirm devices are covered another way: {1}. {2}" -f `
            $configured.Count,
            (($configured | Select-Object -First 5 | ForEach-Object { $_.PolicyName } | Sort-Object -Unique) -join '; '),
            $coverage)
    } elseif ($findings.Count -gt 0) {
        $status = 'Manual'
        $reason = ("AutoPlay/AutoRun-related settings were found but none clearly disables it - review the tab. {0}" -f $coverage)
    } elseif ($areaFailed) {
        $status = 'Unknown'
        $reason = ("One or more policy sources could not be read, so AutoPlay status CANNOT be verified (see Run info tab). {0}" -f $coverage)
    } else {
        $status = 'Fail'
        $reason = ("No policy disabling AutoPlay/AutoRun was found in any source. {0}" -f $coverage)
    }

    [pscustomobject]@{
        Results = @(
            New-CeCheckResult -Control 'Secure configuration' -CheckId 'CE-SC-01' `
                -Title 'AutoPlay / AutoRun disabled' `
                -Status $status -Reason $reason `
                -Evidence ("{0} finding(s); {1} enforcing; {2} configured-but-unassigned" -f $findings.Count, $enforcing.Count, ($configured.Count - $enforcing.Count)) `
                -DetailSheet 'Status of autoplay-autorun'
        )
        Findings = $findings
        Scan     = $scan
        Coverage = $coverage
    }
}

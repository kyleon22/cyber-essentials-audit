# Firewalls: Windows software firewall (Intune profiles, settings catalog,
# endpoint-security intents/baselines, hybrid GPO), macOS firewall, and the
# inherently-manual boundary firewall question.
function Get-CeFirewallCheck {
    [CmdletBinding()]
    param([object[]]$GpoFindings = @())

    Write-Host 'Reviewing software firewall policies...' -ForegroundColor Cyan
    $findings = @()
    $macFindings = @()
    $convert = {
        param($v)
        $s = [string]$v
        if ([string]::IsNullOrWhiteSpace($s)) { return 'Not configured' }
        switch ($s) {
            'allowed'       { return 'Enabled' }
            'blocked'       { return 'Disabled' }
            'notConfigured' { return 'Not configured' }
            default         { return $s }
        }
    }

    # 1) Classic device-configuration profiles.
    try {
        foreach ($p in @(Get-CeDeviceConfigurations)) {
            $type = [string]$p.'@odata.type'
            if ($type -eq '#microsoft.graph.windows10EndpointProtectionConfiguration') {
                $dom = & $convert $p.firewallProfileDomain.firewallEnabled
                $prv = & $convert $p.firewallProfilePrivate.firewallEnabled
                $pub = & $convert $p.firewallProfilePublic.firewallEnabled
                if ($dom -eq 'Not configured' -and $prv -eq 'Not configured' -and $pub -eq 'Not configured') { continue }
                $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.DeviceConfigurations -Id $p.id -Area 'DeviceConfigurations')
                $enabled = (@($dom, $prv, $pub) -contains 'Enabled')
                $findings += [pscustomobject]@{
                    Source = 'Endpoint Protection profile'; PolicyName = $p.displayName; Platform = 'Windows'
                    FirewallSetting = "Domain: $dom; Private: $prv; Public: $pub"
                    Included = $asg.Included; Excluded = $asg.Excluded
                    Enforces = ($enabled -and $asg.IsAssigned)
                }
            }
            elseif ($type -eq '#microsoft.graph.macOSEndpointProtectionConfiguration') {
                $fw = [string]$p.firewallEnabled
                if ([string]::IsNullOrWhiteSpace($fw)) { continue }
                $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.DeviceConfigurations -Id $p.id -Area 'DeviceConfigurations')
                $state = & $convert $fw
                $row = [pscustomobject]@{
                    Source = 'macOS Endpoint Protection profile'; PolicyName = $p.displayName; Platform = 'macOS'
                    FirewallSetting = "Firewall: $state"
                    Included = $asg.Included; Excluded = $asg.Excluded
                    Enforces = (($state -eq 'Enabled' -or $fw -match '(?i)true') -and $asg.IsAssigned)
                }
                $findings += $row
                $macFindings += $row
            }
        }
    } catch { }

    # 2) Settings-catalog policies - per-setting values, not raw-JSON regex (B11).
    try {
        foreach ($cp in @(Get-CeCatalogPolicies)) {
            $fwPairs = @($cp.Pairs | Where-Object { $_.Id -match '(?i)firewall' })
            if ($fwPairs.Count -eq 0) { continue }
            $parts = @(); $anyEnabled = $false; $anyDisabled = $false
            foreach ($pair in $fwPairs) {
                $fs = ConvertTo-CeFirewallSetting -Pair $pair
                if ($null -eq $fs) { continue }
                if ($fs.IsEnableFirewall) {
                    $parts += ("{0}: {1}" -f $fs.Profile, $fs.State)
                    if ($fs.State -eq 'Enabled')  { $anyEnabled = $true }
                    if ($fs.State -eq 'Disabled') { $anyDisabled = $true }
                }
            }
            if ($parts.Count -eq 0) { $parts = @("Firewall settings present ($($fwPairs.Count) setting(s) - review policy)") }
            $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.ConfigurationPolicies -Id $cp.Policy.id -Area 'ConfigurationPolicies')
            $platform = "$($cp.Policy.platforms)"
            $row = [pscustomobject]@{
                Source = 'Settings catalog policy'; PolicyName = $cp.Policy.name; Platform = $platform
                FirewallSetting = ($parts -join '; ')
                Included = $asg.Included; Excluded = $asg.Excluded
                Enforces = ($anyEnabled -and -not $anyDisabled -and $asg.IsAssigned)
            }
            $findings += $row
            if ($platform -match '(?i)mac') { $macFindings += $row }
        }
    } catch { }

    # 3) Endpoint-security firewall intents & security baselines.
    try {
        foreach ($ii in @(Get-CeIntentInventory)) {
            $bits = @(); $sawFw = $false; $anyEnabled = $false
            foreach ($cs in @($ii.CategorySettings)) {
                $s    = $cs.Setting
                $did  = [string]$s.definitionId
                $name = [string]$ii.DefMap[$did]
                $hay  = "$($cs.Category) $did $name"
                if ($hay -notmatch '(?i)firewall') { continue }
                $sawFw = $true
                $valStr = Get-CeIntentSettingValue $s
                if (($hay -match '(?i)enable') -or ($valStr -match '(?i)allowed|true|enabled')) {
                    $label = if ($name) { $name } elseif ($cs.Category) { "$($cs.Category) / $(($did -split '_') | Select-Object -Last 1)" } else { ($did -split '_') | Select-Object -Last 1 }
                    $bits += ("{0} = {1}" -f $label, $valStr)
                    if ($valStr -match '(?i)allowed|true|enabled') { $anyEnabled = $true }
                }
            }
            if (-not $sawFw) { continue }
            $src = if ($ii.TemplateName -match '(?i)firewall') { 'Endpoint security firewall (intent)' } else { 'Security baseline (intent)' }
            $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.Intents -Id $ii.Intent.id -Area 'Intents')
            $findings += [pscustomobject]@{
                Source = $src; PolicyName = $ii.Intent.displayName; Platform = 'Windows'
                FirewallSetting = $(if ($bits.Count) { $bits -join '; ' } else { 'Firewall settings present (review policy)' })
                Included = $asg.Included; Excluded = $asg.Excluded
                Enforces = ($anyEnabled -and $asg.IsAssigned)
            }
        }
    } catch { }

    # 4) Hybrid: structured GPO firewall findings.
    foreach ($gf in @($GpoFindings | Where-Object { $_.Control -eq 'Firewall' })) {
        $findings += [pscustomobject]@{
            Source = 'On-prem GPO'; PolicyName = $gf.GPO; Platform = 'Windows (domain)'
            FirewallSetting = ("{0} = {1}" -f $gf.Setting, $gf.Value)
            Included = $gf.LinkedOUs; Excluded = 'N/A (GPO link scope)'
            Enforces = ($gf.Value -match '(?i)true|enabled' -and $gf.LinkedOUs -ne 'Not linked')
        }
    }

    $findings = @($findings)
    $enforcing = @($findings | Where-Object { $_.Enforces })
    $areaFailed = Test-CeAreaFailed -Area @('DeviceConfigurations', 'ConfigurationPolicies', 'Intents')

    # Windows verdict.
    $winEnforcing = @($enforcing | Where-Object { $_.Platform -notmatch '(?i)mac' })
    if ($winEnforcing.Count -gt 0) {
        $winStatus = 'Pass'
        $winReason = ("{0} assigned policy/policies enable the Windows firewall: {1}" -f $winEnforcing.Count, (($winEnforcing | Select-Object -First 5 | ForEach-Object { $_.PolicyName }) -join '; '))
    } elseif (@($findings | Where-Object { $_.Platform -notmatch '(?i)mac' }).Count -gt 0) {
        $winStatus = 'Manual'
        $winReason = 'Firewall-related policies exist but none clearly enables the firewall on assigned devices - review the Software firewall tab'
    } elseif ($areaFailed) {
        $winStatus = 'Unknown'
        $winReason = 'One or more Intune policy reads failed - firewall enforcement cannot be verified (see Run info tab)'
    } else {
        $winStatus = 'Fail'
        $winReason = 'No Intune policy (or hybrid GPO) enabling the Windows software firewall was found. Devices may still have the OS default enabled, but CE requires it to be ENFORCED.'
    }

    # macOS verdict (only when Macs exist is this surfaced as Fail - the
    # orchestrator passes HasMacs and downgrades to Manual otherwise).
    $macEnforcing = @($macFindings | Where-Object { $_.Enforces })
    if ($macEnforcing.Count -gt 0) {
        $macStatus = 'Pass'; $macReason = ("{0} assigned policy/policies enable the macOS firewall" -f $macEnforcing.Count)
    } elseif ($areaFailed) {
        $macStatus = 'Unknown'; $macReason = 'Policy reads failed - macOS firewall enforcement cannot be verified'
    } else {
        $macStatus = 'Fail'; $macReason = 'No Intune policy enabling the macOS application firewall was found'
    }

    $results = @(
        New-CeCheckResult -Control 'Firewalls' -CheckId 'CE-FW-01' `
            -Title 'Software firewall enabled on Windows devices' `
            -Status $winStatus -Reason $winReason `
            -Evidence ("{0} firewall-related finding(s); {1} enforcing" -f $findings.Count, $enforcing.Count) `
            -DetailSheet 'Software firewall'
        New-CeCheckResult -Control 'Firewalls' -CheckId 'CE-FW-02' `
            -Title 'Software firewall enabled on macOS devices' `
            -Status $macStatus -Reason $macReason `
            -Evidence ("{0} macOS firewall finding(s)" -f @($macFindings).Count) `
            -DetailSheet 'Software firewall'
        New-CeCheckResult -Control 'Firewalls' -CheckId 'CE-FW-03' `
            -Title 'Boundary firewall / router configuration' `
            -Status 'Manual' `
            -Reason 'Internet boundary devices (routers/firewalls) cannot be audited via Microsoft Graph. Confirm: default admin passwords changed, WAN management disabled or MFA-protected, and inbound services blocked by default.' `
            -DetailSheet 'Software firewall'
    )

    [pscustomobject]@{
        Results  = $results
        Findings = $findings
    }
}

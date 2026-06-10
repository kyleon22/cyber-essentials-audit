# Walk a settings-catalog settings collection and return EVERY
# (settingDefinitionId, value) pair found in the instance tree (fixes B11:
# checks evaluate per-setting values instead of regex over the raw JSON blob).
function Get-CeCatalogSettingPairs {
    [CmdletBinding()]
    param($SettingsArray)
    $found = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Stack
    foreach ($s in @($SettingsArray)) { if ($null -ne $s) { $stack.Push($s) } }
    while ($stack.Count -gt 0) {
        $n = $stack.Pop()
        if ($null -eq $n) { continue }
        $defId = $null
        try { $defId = $n.settingDefinitionId } catch { $defId = $null }
        if ($defId) {
            $val = $null
            if ($n.choiceSettingValue) { $val = $n.choiceSettingValue.value }
            elseif ($n.simpleSettingValue) { $val = $n.simpleSettingValue.value }
            $found.Add([pscustomobject]@{ Id = "$defId"; Value = "$val" })
        }
        foreach ($prop in @('settingInstance', 'choiceSettingValue', 'simpleSettingValue')) {
            try { if ($n.$prop) { $stack.Push($n.$prop) } } catch { }
        }
        foreach ($prop in @('children', 'value', 'groupSettingCollectionValue', 'simpleSettingCollectionValue')) {
            try {
                $c = $n.$prop
                if (($c -is [System.Collections.IEnumerable]) -and -not ($c -is [string])) {
                    foreach ($i in $c) { $stack.Push($i) }
                }
            } catch { }
        }
    }
    # Plain (enumerated) return on purpose: every consumer wraps with @(...).
    return $found.ToArray()
}

# Convenience: parse a Windows Firewall settings-catalog definitionId into its
# profile + setting, e.g. vendor_msft_firewall_mdmstore_domainprofile_enablefirewall.
function ConvertTo-CeFirewallSetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Pair)
    if ($Pair.Id -notmatch '(?i)firewall') { return $null }
    $profileName = 'General'
    if ($Pair.Id -match '(?i)(domain|private|public)profile') {
        $profileName = (Get-Culture).TextInfo.ToTitleCase($Matches[1].ToLower())
    }
    $settingName = ($Pair.Id -split '_')[-1]
    $state = 'Configured'
    if ($Pair.Id -match '(?i)enablefirewall') {
        if ($Pair.Value -match '(?i)true|_1$') { $state = 'Enabled' }
        elseif ($Pair.Value -match '(?i)false|_0$') { $state = 'Disabled' }
    } else {
        $state = $Pair.Value
    }
    [pscustomobject]@{
        Profile = $profileName
        Setting = $settingName
        State   = $state
        IsEnableFirewall = [bool]($Pair.Id -match '(?i)enablefirewall')
    }
}

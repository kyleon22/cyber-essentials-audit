# Shared, cached Intune configuration inventories. Each is fetched ONCE per
# run and consumed by multiple checks (firewall, AutoPlay, app control,
# malware, updates) - previously every check re-fetched everything.

# Classic device-configuration profiles (Endpoint Protection, custom OMA-URI,
# update rings, macOS profiles...).
function Get-CeDeviceConfigurations {
    [CmdletBinding()]
    param()
    return Get-CeCollection -Key 'deviceConfigurations' -Uri $script:CeUri.DeviceConfigurations -Area 'DeviceConfigurations'
}

# Settings-catalog policies WITH their parsed (definitionId, value) pairs.
# Includes endpoint-security and SECURITY BASELINE policies - since ~2023
# new baselines are settings-catalog policies distinguished only by their
# templateReference. Returns objects:
#   @{ Policy; Pairs; SettingsRead; TemplateFamily }
# SettingsRead = $false means the per-policy settings call failed (also
# journaled, so dependent checks report Unknown instead of a silent miss).
function Get-CeCatalogPolicies {
    [CmdletBinding()]
    param()
    if ($script:Ce.Collections.ContainsKey('catalogPolicies')) { return $script:Ce.Collections['catalogPolicies'] }
    $out = New-Object System.Collections.Generic.List[object]
    $policies = Get-CeCollection -Key 'configurationPolicies' -Uri $script:CeUri.ConfigurationPolicies -Area 'ConfigurationPolicies'
    foreach ($p in @($policies)) {
        $pairs = @()
        $settingsRead = $true
        try {
            $settings = Get-CeGraphPaged -Uri ("{0}/{1}/settings" -f $script:CeUri.ConfigurationPolicies, $p.id) -Area 'ConfigurationPolicies'
            $pairs = @(Get-CeCatalogSettingPairs $settings)
        } catch { $settingsRead = $false }
        $family = ''
        try { $family = [string]$p.templateReference.templateFamily } catch { }
        $out.Add([pscustomobject]@{
            Policy         = $p
            Pairs          = $pairs
            SettingsRead   = $settingsRead
            TemplateFamily = $family
        })
    }
    $result = $out.ToArray()
    $script:Ce.Collections['catalogPolicies'] = $result
    return $result
}

# Endpoint-security intents (incl. security baselines) with template name,
# definition-name map and per-category settings. Paged (fixes B5) and fetched
# once (the old code walked all intents four separate times).
# Returns objects: @{ Intent; TemplateName; DefMap; CategorySettings }.
function Get-CeIntentInventory {
    [CmdletBinding()]
    param()
    if ($script:Ce.Collections.ContainsKey('intentInventory')) { return $script:Ce.Collections['intentInventory'] }
    $out = New-Object System.Collections.Generic.List[object]
    $intents = Get-CeCollection -Key 'intents' -Uri $script:CeUri.Intents -Area 'Intents'
    foreach ($intent in @($intents)) {
        $tid = [string]$intent.templateId
        $templateName = $null
        $defMap = @{}
        if ($tid) {
            if (-not $script:Ce.TemplateNames.ContainsKey($tid)) {
                try {
                    $tpl = Get-CeGraphJson -Uri ("{0}/{1}" -f $script:CeUri.Templates, $tid) -Area 'Intents'
                    $script:Ce.TemplateNames[$tid] = [string]$tpl.displayName
                } catch { $script:Ce.TemplateNames[$tid] = $null }
            }
            $templateName = $script:Ce.TemplateNames[$tid]

            if (-not $script:Ce.TemplateDefs.ContainsKey($tid)) {
                $map = @{}
                try {
                    $cats = Get-CeGraphJson -Uri ("{0}/{1}/categories?`$expand=settingDefinitions" -f $script:CeUri.Templates, $tid) -Area 'Intents'
                    foreach ($c in @($cats.value)) {
                        foreach ($sd in @($c.settingDefinitions)) {
                            if ($sd.id) { $map[[string]$sd.id] = [string]$sd.displayName }
                        }
                    }
                } catch { }
                $script:Ce.TemplateDefs[$tid] = $map
            }
            $defMap = $script:Ce.TemplateDefs[$tid]
        }

        # Category + settings walk (category names like "AutoPlay Policies"
        # are reliable even when definitionIds are opaque).
        $catSettings = @()
        try {
            $cats = Get-CeGraphJson -Uri ("{0}/{1}/categories" -f $script:CeUri.Intents, $intent.id) -Area 'Intents'
            foreach ($cat in @($cats.value)) {
                $cs = $null
                try { $cs = Get-CeGraphJson -Uri ("{0}/{1}/categories/{2}/settings" -f $script:CeUri.Intents, $intent.id, $cat.id) -Area 'Intents' } catch { }
                foreach ($s in @($cs.value)) {
                    $catSettings += [pscustomobject]@{ Category = [string]$cat.displayName; Setting = $s }
                }
            }
        } catch { }

        $out.Add([pscustomobject]@{
            Intent           = $intent
            TemplateName     = $templateName
            DefMap           = $defMap
            CategorySettings = @($catSettings)
        })
    }
    $result = $out.ToArray()
    $script:Ce.Collections['intentInventory'] = $result
    return $result
}

# Compliance policies (assignments expanded), shared by mobile / device-lock /
# malware checks.
function Get-CeCompliancePolicies {
    [CmdletBinding()]
    param()
    return Get-CeCollection -Key 'compliancePolicies' -Uri $script:CeUri.CompliancePolicies -Area 'CompliancePolicies'
}

# Extract a readable value from an intent setting (scalar, else valueJson).
function Get-CeIntentSettingValue {
    [CmdletBinding()]
    param($Setting)
    $v = $Setting.value
    if ($null -ne $v -and ($v -is [string] -or $v -is [valuetype])) { return "$v" }
    $vj = $Setting.valueJson
    if ($null -ne $vj) { return ("$vj").Trim('"') }
    return "$v"
}

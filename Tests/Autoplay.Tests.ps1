# Regression tests for AutoPlay/AutoRun detection - in particular the
# security-baseline cases: legacy baselines surface settings with SPACES
# ("Auto Play", "Block auto play for non-volume devices") and modern baselines
# are settings-catalog policies whose AutoPlay definition ids must be
# classified per value, not just spotted.
BeforeAll {
    $core = Join-Path $PSScriptRoot '..\CyberEssentialsAudit\Private\Core'
    . (Join-Path $core 'Get-CeCatalogSettingPairs.ps1')
    . (Join-Path $core 'ConvertTo-CeAutoplaySetting.ps1')
    $script:FixtureDir = Join-Path $PSScriptRoot 'Fixtures'
}

Describe 'CeAutoplayPattern (separator tolerance)' {
    It 'matches <_label_>' -ForEach @(
        @{ label = 'settings-catalog id';            text = 'device_vendor_msft_policy_config_autoplay_turnoffautoplay' }
        @{ label = 'legacy baseline category';       text = 'Auto Play' }
        @{ label = 'legacy baseline setting name';   text = 'Auto play default auto run behavior' }
        @{ label = 'legacy baseline non-volume name'; text = 'Block auto play for non-volume devices' }
        @{ label = 'GPO admin-template name';        text = 'Turn off AutoPlay' }
        @{ label = 'GPO AutoRun name';               text = 'Set the default behavior for AutoRun' }
        @{ label = 'registry value name';            text = 'NoDriveTypeAutoRun' }
        @{ label = 'hyphenated form';                text = 'disable auto-run on removable media' }
    ) {
        $text | Should -Match $script:CeAutoplayPattern
    }
    It 'does not match unrelated text: <_text_>' -ForEach @(
        @{ text = 'Automatic Updates' }
        @{ text = 'AutoPilot enrollment' }
        @{ text = 'playbook automation runner' }
        @{ text = 'firewall settings' }
    ) {
        $text | Should -Not -Match $script:CeAutoplayPattern
    }
}

Describe 'ConvertTo-CeAutoplaySetting (value-aware classification)' {
    It 'classifies an enabled "Turn off AutoPlay" as disabling' {
        $r = ConvertTo-CeAutoplaySetting -Pair ([pscustomobject]@{
            Id = 'device_vendor_msft_policy_config_autoplay_turnoffautoplay'
            Value = 'device_vendor_msft_policy_config_autoplay_turnoffautoplay_1' })
        $r.Disables | Should -BeTrue
        $r.Setting  | Should -Be 'Turn off AutoPlay'
    }
    It 'classifies a DISABLED "Turn off AutoPlay" as NOT disabling (AutoPlay allowed)' {
        $r = ConvertTo-CeAutoplaySetting -Pair ([pscustomobject]@{
            Id = 'device_vendor_msft_policy_config_autoplay_turnoffautoplay'
            Value = 'device_vendor_msft_policy_config_autoplay_turnoffautoplay_0' })
        $r.Disables | Should -BeFalse
    }
    It 'classifies "do not execute" AutoRun behaviour as disabling' {
        $r = ConvertTo-CeAutoplaySetting -Pair ([pscustomobject]@{
            Id = 'device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior'
            Value = 'device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior_1' })
        $r.Disables | Should -BeTrue
    }
    It 'classifies "automatically execute" AutoRun behaviour as NOT disabling' {
        $r = ConvertTo-CeAutoplaySetting -Pair ([pscustomobject]@{
            Id = 'device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior_noautorun_dropdownlist'
            Value = 'device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior_noautorun_dropdownlist_2' })
        $r.Disables | Should -BeFalse
        $r.State    | Should -Match 'does NOT disable'
    }
    It 'returns null for non-AutoPlay settings' {
        ConvertTo-CeAutoplaySetting -Pair ([pscustomobject]@{
            Id = 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring'
            Value = 'x_1' }) | Should -BeNullOrEmpty
    }
}

Describe 'Modern security baseline (settings catalog) end-to-end pair extraction' {
    BeforeAll {
        $settings = Get-Content (Join-Path $FixtureDir 'baseline-autoplay-settings.json') -Raw | ConvertFrom-Json
        $script:pairs = @(Get-CeCatalogSettingPairs $settings)
    }
    It 'extracts every instance including template-referenced children' {
        $pairs.Count | Should -Be 6   # 3 autoplay parents + 2 children + 1 defender
    }
    It 'classifies all three baseline AutoPlay settings as disabling' {
        $auto = @($pairs | ForEach-Object { ConvertTo-CeAutoplaySetting -Pair $_ } | Where-Object { $_ })
        @($auto).Count | Should -Be 5   # 3 parents + 2 children
        @($auto | Where-Object { $_.Disables }).Count | Should -BeGreaterOrEqual 3
        ($auto | ForEach-Object { $_.Setting } | Sort-Object -Unique) | Should -Contain 'Turn off AutoPlay'
        ($auto | ForEach-Object { $_.Setting } | Sort-Object -Unique) | Should -Contain 'Disallow AutoPlay for non-volume devices'
        ($auto | ForEach-Object { $_.Setting } | Sort-Object -Unique) | Should -Contain 'Default AutoRun behaviour'
    }
}

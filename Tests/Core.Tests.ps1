# Pester 5 tests for the pure core functions. These would have caught B1
# (formula neutraliser never firing), B3 (server misclassification) and B8
# (surname false-positives) before release.
BeforeAll {
    $core = Join-Path $PSScriptRoot '..\CyberEssentialsAudit\Private\Core'
    . (Join-Path $core 'Protect-CeCellText.ps1')
    . (Join-Path $core 'Get-CeOsInfo.ps1')
    . (Join-Path $core 'Get-CePrivClass.ps1')
    . (Join-Path $core 'Get-CeCatalogSettingPairs.ps1')
    . (Join-Path $core 'Test-CeUpdateRing.ps1')
    $script:FixtureDir = Join-Path $PSScriptRoot 'Fixtures'
}

Describe 'Protect-CeCellText (B1: formula injection)' {
    It 'prefixes a leading <_char_> with a quote' -ForEach @(
        @{ char = '=' }, @{ char = '+' }, @{ char = '-' }, @{ char = '@' }
    ) {
        Protect-CeCellText ("{0}cmd|calc" -f $char) | Should -Be ("'{0}cmd|calc" -f $char)
    }
    It 'prefixes a leading tab' {
        Protect-CeCellText "`tdata" | Should -Be "'`tdata"
    }
    It 'prefixes a leading carriage return' {
        Protect-CeCellText "`rdata" | Should -Be "'`rdata"
    }
    It 'leaves ordinary strings unchanged' {
        Protect-CeCellText 'Contoso Laptop 01' | Should -Be 'Contoso Laptop 01'
    }
    It 'leaves a string with = in the middle unchanged' {
        Protect-CeCellText 'a=b' | Should -Be 'a=b'
    }
    It 'passes non-strings through untouched' {
        Protect-CeCellText 42 | Should -Be 42
        Protect-CeCellText $null | Should -BeNullOrEmpty
    }
    It 'handles the empty string' {
        Protect-CeCellText '' | Should -Be ''
    }
}

Describe 'Get-CeOsInfo (B3 server classification + B4 EOL detection)' {
    BeforeAll { $asOf = [datetime]'2026-06-10' }

    It 'identifies Windows 11 24H2 Pro as a supported workstation' {
        $r = Get-CeOsInfo -OsVersion '10.0.26100.3915' -SkuFamily 'Pro' -AsOf $asOf
        $r.FriendlyName  | Should -Be 'Windows 11 24H2'
        $r.IsServer      | Should -BeFalse
        $r.SupportStatus | Should -Be 'Supported'
    }
    It 'knows Windows 11 25H2 (build 26200 was missing from the old map)' {
        (Get-CeOsInfo -OsVersion '10.0.26200.100' -SkuFamily 'Pro' -AsOf $asOf).FriendlyName | Should -Be 'Windows 11 25H2'
    }
    It 'flags Windows 10 22H2 as EOL after October 2025' {
        $r = Get-CeOsInfo -OsVersion '10.0.19045.5011' -SkuFamily 'Pro' -AsOf $asOf
        $r.FriendlyName  | Should -Be 'Windows 10 22H2'
        $r.SupportStatus | Should -Be 'EOL'
    }
    It 'classifies build 20348 as Windows Server 2022, not a Windows 10 workstation (B3)' {
        $r = Get-CeOsInfo -OsVersion '10.0.20348.2700' -AsOf $asOf
        $r.IsServer      | Should -BeTrue
        $r.FriendlyName  | Should -Be 'Windows Server 2022'
        $r.SupportStatus | Should -Be 'Supported'
    }
    It 'classifies build 17763 with a server SKU as Server 2019, not Windows 10 1809 (B3)' {
        $r = Get-CeOsInfo -OsVersion '10.0.17763.6414' -SkuFamily 'ServerStandard' -AsOf $asOf
        $r.IsServer      | Should -BeTrue
        $r.FriendlyName  | Should -Be 'Windows Server 2019'
        $r.SupportStatus | Should -Be 'Supported'
    }
    It 'still treats build 17763 with a client SKU as Windows 10 1809 (EOL)' {
        $r = Get-CeOsInfo -OsVersion '10.0.17763.6414' -SkuFamily 'Enterprise' -AsOf $asOf
        $r.IsServer      | Should -BeFalse
        $r.FriendlyName  | Should -Be 'Windows 10 1809'
        $r.SupportStatus | Should -Be 'EOL'
    }
    It 'uses the Enterprise lifecycle date for Enterprise SKUs (23H2 still in support)' {
        $r = Get-CeOsInfo -OsVersion '10.0.22631.4460' -SkuFamily 'Enterprise' -AsOf $asOf
        $r.SupportStatus | Should -Be 'Supported'
        (Get-CeOsInfo -OsVersion '10.0.22631.4460' -SkuFamily 'Pro' -AsOf $asOf).SupportStatus | Should -Be 'EOL'
    }
    It 'resolves AD server name strings without a build number' {
        $r = Get-CeOsInfo -OsName 'Windows Server 2012 R2 Standard' -AsOf $asOf
        $r.IsServer      | Should -BeTrue
        $r.SupportStatus | Should -Be 'EOL'
    }
    It 'treats supported macOS majors as supported (current + two prior)' {
        (Get-CeOsInfo -OperatingSystem 'macOS' -OsVersion '14.7.1' -AsOf $asOf).SupportStatus | Should -Be 'Supported'
        (Get-CeOsInfo -OperatingSystem 'macOS' -OsVersion '26.0'   -AsOf $asOf).SupportStatus | Should -Be 'Supported'
    }
    It 'flags old macOS majors as EOL' {
        $r = Get-CeOsInfo -OperatingSystem 'macOS' -OsVersion '13.6.9' -AsOf $asOf
        $r.SupportStatus | Should -Be 'EOL'
        $r.FriendlyName  | Should -Match 'Ventura'
    }
    It 'returns Unknown for an unparseable version, never a silent pass' {
        (Get-CeOsInfo -OperatingSystem 'macOS' -OsVersion '' -AsOf $asOf).SupportStatus | Should -Be 'Unknown'
    }
}

Describe 'Get-CePrivClass (B8: anchored admin tokens)' {
    It 'does not classify the surname <_account_> as admin-named' -ForEach @(
        @{ account = 'adams@contoso.com';   name = 'Bob Adams' }
        @{ account = 'ahmadi@contoso.com';  name = 'Sara Ahmadi' }
        @{ account = 'privett@contoso.com'; name = 'Joe Privett' }
        @{ account = 'amanda.jones@contoso.com'; name = 'Amanda Jones' }
    ) {
        Get-CePrivClass -Account $account -Name $name -Licensed $true -IsBuiltinAdmin $false |
            Should -Be 'Standard user (licensed day-to-day account)'
    }
    It 'classifies <_account_> as admin-named' -ForEach @(
        @{ account = 'admin.jones@contoso.com' }
        @{ account = 'jones.admin@contoso.com' }
        @{ account = 'adm-jsmith@contoso.com' }
        @{ account = 'svc_backup@contoso.com' }
        @{ account = 'jsmith-a@contoso.com' }
        @{ account = 'da.wilson@contoso.com' }
    ) {
        Get-CePrivClass -Account $account -Name 'x' -Licensed $false -IsBuiltinAdmin $false |
            Should -Be 'Dedicated admin account'
    }
    It 'flags a licensed account even when admin-named' {
        Get-CePrivClass -Account 'admin.jones@contoso.com' -Name 'Admin Jones' -Licensed $true -IsBuiltinAdmin $false |
            Should -Be 'Admin-named but LICENSED account'
    }
    It 'recognises the built-in Administrator' {
        Get-CePrivClass -Account 'Administrator' -Name 'Administrator' -Licensed $false -IsBuiltinAdmin $true |
            Should -Match 'Built-in Administrator'
    }
    It 'matches an explicit admin display name' {
        Get-CePrivClass -Account 'jbloggs@contoso.com' -Name 'Joe Bloggs (Admin)' -Licensed $false -IsBuiltinAdmin $false |
            Should -Be 'Dedicated admin account'
    }
}

Describe 'Get-CeCatalogSettingPairs + ConvertTo-CeFirewallSetting (B11)' {
    BeforeAll {
        $settings = Get-Content (Join-Path $FixtureDir 'catalog-settings.json') -Raw | ConvertFrom-Json
        $script:pairs = @(Get-CeCatalogSettingPairs $settings)
    }
    It 'extracts every definitionId/value pair, including nested children' {
        $pairs.Count | Should -Be 4
        ($pairs | Where-Object { $_.Id -match 'defaultinboundaction' }).Count | Should -Be 1
    }
    It 'distinguishes the domain profile (enabled) from the public profile (disabled)' {
        $dom = ConvertTo-CeFirewallSetting -Pair ($pairs | Where-Object { $_.Id -match 'domainprofile_enablefirewall' })
        $pub = ConvertTo-CeFirewallSetting -Pair ($pairs | Where-Object { $_.Id -match 'publicprofile_enablefirewall' })
        $dom.Profile | Should -Be 'Domain'
        $dom.State   | Should -Be 'Enabled'
        $pub.Profile | Should -Be 'Public'
        $pub.State   | Should -Be 'Disabled'
    }
    It 'returns null for non-firewall settings' {
        ConvertTo-CeFirewallSetting -Pair ($pairs | Where-Object { $_.Id -match 'autoplay' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-CeUpdateRing (CE 14-day requirement)' {
    BeforeAll {
        $script:rings = Get-Content (Join-Path $FixtureDir 'update-rings.json') -Raw | ConvertFrom-Json
    }
    It 'passes a ring with deferral+deadline+grace <= 14 days' {
        $r = Test-CeUpdateRing -Ring $rings[0]
        $r.Verdict | Should -Be 'Pass'
        $r.MaxDays | Should -Be 9
    }
    It 'fails a ring whose worst case exceeds 14 days' {
        $r = Test-CeUpdateRing -Ring $rings[1]
        $r.Verdict | Should -Be 'Fail'
        $r.MaxDays | Should -Be 22
    }
    It 'fails a paused ring regardless of deadlines' {
        (Test-CeUpdateRing -Ring $rings[2]).Verdict | Should -Be 'Fail'
    }
    It 'returns Manual when no deadline is enforced (never an implicit pass)' {
        (Test-CeUpdateRing -Ring $rings[3]).Verdict | Should -Be 'Manual'
    }
}

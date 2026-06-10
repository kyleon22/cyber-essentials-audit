# Pester 5 tests for the pure evaluation functions that drive Summary-tab
# verdicts: MFA (B2/B7) and the structured GPO parser (B6).
BeforeAll {
    $core = Join-Path $PSScriptRoot '..\CyberEssentialsAudit\Private\Core'
    . (Join-Path $core 'Get-CeMfaEvaluation.ps1')
    . (Join-Path $core 'ConvertFrom-CeGpoReportXml.ps1')
    $script:FixtureDir = Join-Path $PSScriptRoot 'Fixtures'
    $script:caPolicies = Get-Content (Join-Path $FixtureDir 'ca-policies.json') -Raw | ConvertFrom-Json
}

Describe 'Get-CeMfaEvaluation (B2: state-aware counting; B7: security defaults)' {
    It 'counts only ENABLED policies as enforcing' {
        $e = Get-CeMfaEvaluation -CaPolicies $caPolicies
        @($e.Enforced).Count   | Should -Be 2    # all-users + finance-only
        @($e.ReportOnly).Count | Should -Be 1
        @($e.Disabled).Count   | Should -Be 1
    }
    It 'passes when an enabled policy covers All users and All apps' {
        (Get-CeMfaEvaluation -CaPolicies $caPolicies).Status | Should -Be 'Pass'
    }
    It 'fails when only report-only/disabled MFA policies exist (the old code passed this)' {
        $weak = @($caPolicies | Where-Object { $_.state -ne 'enabled' })
        $e = Get-CeMfaEvaluation -CaPolicies $weak
        $e.Status | Should -Be 'Fail'
        $e.Reason | Should -Match 'report-only'
    }
    It 'returns Manual when MFA is enforced only for a subset of users' {
        $partial = @($caPolicies | Where-Object { $_.displayName -eq 'MFA for finance group only' })
        (Get-CeMfaEvaluation -CaPolicies $partial).Status | Should -Be 'Manual'
    }
    It 'passes on security defaults alone (B7: previously reported as a false fail)' {
        (Get-CeMfaEvaluation -CaPolicies @() -SecurityDefaultsOn $true).Status | Should -Be 'Pass'
    }
    It 'returns Unknown (not Fail) when the CA read failed' {
        (Get-CeMfaEvaluation -CaPolicies @() -CaReadFailed $true).Status | Should -Be 'Unknown'
    }
    It 'fails when nothing enforces MFA' {
        (Get-CeMfaEvaluation -CaPolicies @()).Status | Should -Be 'Fail'
    }
}

Describe 'ConvertFrom-CeGpoReportXml (B6: structured parsing, no schema noise)' {
    BeforeAll {
        [xml]$xml = Get-Content (Join-Path $FixtureDir 'gpo-report.xml') -Raw
        $script:findings = @(ConvertFrom-CeGpoReportXml -Xml $xml -GpoName 'Workstation hardening' -GpoStatus 'AllSettingsEnabled')
    }
    It 'extracts the account-policy password/lockout settings with their values' {
        $pw = @($findings | Where-Object { $_.Control -eq 'Password / lockout' })
        $pw.Count | Should -Be 2
        ($pw | Where-Object { $_.Setting -eq 'MinimumPasswordLength' }).Value | Should -Be '12'
        ($pw | Where-Object { $_.Setting -eq 'LockoutBadCount' }).Value | Should -Be '5'
    }
    It 'extracts per-profile firewall enablement' {
        $fw = @($findings | Where-Object { $_.Control -eq 'Firewall' })
        ($fw | Where-Object { $_.Setting -eq 'DomainProfile/EnableFirewall' }).Value | Should -Be 'true'
        ($fw | Where-Object { $_.Setting -eq 'PublicProfile/EnableFirewall' }).Value | Should -Be 'false'
    }
    It 'extracts AppLocker rule collections with enforcement mode' {
        $aw = @($findings | Where-Object { $_.Control -eq 'Application whitelisting' })
        $aw.Count | Should -Be 1
        $aw[0].Setting | Should -Match 'Exe'
        $aw[0].Value   | Should -Be 'Enabled'
    }
    It 'extracts configured AutoPlay and Windows Update admin-template policies' {
        @($findings | Where-Object { $_.Control -eq 'AutoPlay/AutoRun' }).Count   | Should -Be 1
        @($findings | Where-Object { $_.Control -eq 'Security updates' }).Count | Should -Be 1
    }
    It 'does NOT flag unrelated policies that merely contain the word password (the old regex did)' {
        @($findings | Where-Object { $_.Setting -match 'password manager' }).Count | Should -Be 0
    }
    It 'carries the linked OU scope on every finding' {
        $findings[0].LinkedOUs | Should -Be 'contoso.com/Workstations'
    }
    It 'parses an empty GPO without errors' {
        [xml]$empty = '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"><Name>Empty</Name></GPO>'
        @(ConvertFrom-CeGpoReportXml -Xml $empty -GpoName 'Empty') | Should -BeNullOrEmpty
    }
}

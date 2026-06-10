# End-to-end smoke test for the Excel rendering layer: builds a synthetic
# audit result covering every tab/table/status and renders a real workbook.
BeforeDiscovery {
    $script:HaveDeps = [bool](Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication') -and
                       [bool](Get-Module -ListAvailable -Name 'ImportExcel')
}

Describe 'Export-CeWorkbook (synthetic audit)' -Skip:(-not $script:HaveDeps) {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot '..\CyberEssentialsAudit\CyberEssentialsAudit.psd1'
        $script:Module = Import-Module $manifest -Force -PassThru
    }
    AfterAll {
        Remove-Module CyberEssentialsAudit -Force -ErrorAction SilentlyContinue
    }

    It 'renders a complete workbook with all 14 tabs from a synthetic audit result' {
        $path = Join-Path $TestDrive 'CyberEssentialsAudit_smoke.xlsx'

        & $script:Module {
            param($Path)

            $winRow = [pscustomobject]@{
                DeviceName = 'WS-001'; Manufacturer = 'Dell'; Model = 'Latitude'; OS = 'Windows 11 24H2'
                OperatingSys = 'Windows'; SkuFamily = 'Pro'; Ownership = 'company'; JoinType = 'azureADJoined'
                PrimaryUser = 'alice@contoso.com'; LastCheckIn = (Get-Date); Source = 'Cloud (Intune)'
                IsServer = $false; SupportStatus = 'Supported'; SupportEnd = '2026-10-13'; SupportNote = ''
            }
            $eolRow = [pscustomobject]@{
                DeviceName = '=WS-EOL()'; Manufacturer = 'HP'; Model = 'EliteBook'; OS = 'Windows 10 22H2'
                OperatingSys = 'Windows'; SkuFamily = 'Pro'; Ownership = 'company'; JoinType = 'hybridAzureADJoined'
                PrimaryUser = 'bob@contoso.com'; LastCheckIn = (Get-Date); Source = 'Both (Intune + AD)'
                IsServer = $false; SupportStatus = 'EOL'; SupportEnd = '2025-10-14'; SupportNote = 'Home/Pro servicing end'
            }
            $srvRow = [pscustomobject]@{
                DeviceName = 'DC-01'; Manufacturer = 'HPE'; Model = 'DL380'; OS = 'Windows Server 2022'
                OperatingSys = 'Windows'; SkuFamily = 'Standard'; Ownership = 'On-premises (domain-joined)'
                JoinType = 'On-prem AD'; PrimaryUser = ''; LastCheckIn = (Get-Date); Source = 'On-premises (AD)'
                IsServer = $true; SupportStatus = 'Supported'; SupportEnd = '2031-10-14'; SupportNote = ''
            }
            $inventory = [pscustomobject]@{
                Unified = @($winRow, $eolRow, $srvRow); Windows = @($winRow, $eolRow); Servers = @($srvRow); MacOS = @()
                Summary = @([pscustomobject]@{ Count = 2; Manufacturer = 'Dell'; OS = 'Windows 11 24H2'; SkuFamily = 'Pro'; Description = '2x Dell Windows 11 24H2 Pro' })
                ServerSummary = @([pscustomobject]@{ Count = 1; Manufacturer = 'HPE'; OS = 'Windows Server 2022'; SkuFamily = 'Standard'; Description = '1x HPE Windows Server 2022 Standard' })
                Mobile = @([pscustomobject]@{ DeviceName = 'iPhone-1'; Make = 'Apple'; Model = 'iPhone 15'; OS = 'iOS 18'; Ownership = 'personal'; PrimaryUser = 'alice@contoso.com'; LastCheckIn = (Get-Date) })
                MobileSummary = @([pscustomobject]@{ Count = 1; Make = 'Apple'; OS = 'iOS 18'; Description = '1x Apple iOS 18' })
                EolDevices = @($eolRow)
                CloudWorkstations = 1; OnPremWorkstations = 1; DuplicatesMerged = 1; SkippedStale = 3
                SourceOfTruth = 'Mixed (GPO + Intune)'; DistributionVerdict = 'Evenly split.'
                CheckInWindowWeeks = 6; CutoffUtc = '2026-04-29T00:00:00Z'
            }

            $checks = @(
                New-CeCheckResult -Control 'Scope' -CheckId 'CE-SCOPE-01' -Title 'Scope declared' -Status 'Manual' -Reason 'Declare it' -DetailSheet 'Scope'
                New-CeCheckResult -Control 'Firewalls' -CheckId 'CE-FW-01' -Title 'Windows firewall' -Status 'Pass' -Reason 'Enforced' -Evidence '2 policies' -DetailSheet 'Software firewall'
                New-CeCheckResult -Control 'User access control' -CheckId 'CE-UA-01' -Title 'MFA enforced' -Status 'Fail' -Reason 'Nothing enforces MFA' -DetailSheet 'MFA'
                New-CeCheckResult -Control 'User access control' -CheckId 'CE-UA-06' -Title 'Password protections' -Status 'Pass' -Reason 'Smart lockout + banned list' -DetailSheet 'Password'
                New-CeCheckResult -Control 'Malware protection' -CheckId 'CE-MP-01' -Title 'AV managed' -Status 'Unknown' -Reason 'Policy read failed' -DetailSheet 'Malware protection'
                New-CeCheckResult -Control 'Security update management' -CheckId 'CE-SU-01' -Title '14-day patching' -Status 'Fail' -Reason 'Ring allows 22 days' -DetailSheet 'Security updates'
            )

            $audit = [pscustomobject]@{
                RunInfo = [pscustomobject]@{
                    ToolVersion = '2.0.0'; StartedUtc = [datetime]::UtcNow.AddMinutes(-5); FinishedUtc = [datetime]::UtcNow
                    Account = 'auditor@contoso.com'; AuthMode = 'Delegated'; TenantId = '00000000-0000-0000-0000-000000000000'
                    Mode = 'Hybrid'; CheckInWindowWeeks = 6
                    Scopes = @('Directory.Read.All'); AdAvailable = 'True'
                    GraphErrors = @([pscustomobject]@{ Area = 'Intents'; Uri = 'https://graph...'; Message = '403 Forbidden'; TimeUtc = [datetime]::UtcNow })
                    GpoReviewed = 4
                }
                Overall = 'Fail'
                Checks  = $checks
                Inventory = $inventory
                Scope = [pscustomobject]@{ Details = [ordered]@{ 'Organisation' = 'Contoso'; 'Tenant id' = '0000'; 'Windows workstations' = 2 } }
                Sections = [pscustomobject]@{
                    Mfa = [pscustomobject]@{
                        Evaluation = [pscustomobject]@{ Enforced = @(); ReportOnly = @(1); Disabled = @(); FullCoverage = @() }
                        PolicyRows = @([ordered]@{ 'Policy name' = 'MFA pilot'; 'Enforcement' = 'REPORT-ONLY (not enforcing)'; 'State' = 'enabledForReportingButNotEnforced' })
                        CaPolicyCount = 2; SecurityDefaultsOn = $false
                        RegistrationTotal = 10; RegistrationMfa = 7
                        Unregistered = @([pscustomobject]@{ User = 'carol@contoso.com'; Name = 'Carol'; MfaCapable = 'No'; Methods = '' })
                    }
                    Firewall = [pscustomobject]@{ Findings = @([pscustomobject]@{ Source = 'Settings catalog policy'; PolicyName = 'FW baseline'; Platform = 'Windows'; FirewallSetting = 'Domain: Enabled; Private: Enabled; Public: Enabled'; Included = 'All devices'; Excluded = 'None'; Enforces = $true }) }
                    Malware = [pscustomobject]@{
                        Findings = @([pscustomobject]@{ Source = 'Endpoint security antivirus (intent)'; PolicyName = 'AV policy'; Platform = 'Windows'; Setting = 'RealTime = true'; Included = 'All devices'; Excluded = 'None' })
                        Signals = @{ RealTime = $true; Cloud = $false; Pua = $false; SigCad = 8 }
                    }
                    Updates = [pscustomobject]@{
                        RingRows = @([pscustomobject]@{ RingName = 'Slow ring'; Verdict = 'Fail'; WorstCase = '22 day(s)'; Deferral = 10; Deadline = 7; Grace = 5; Paused = 'No'; FeatureDefer = 60; AutoMode = 'autoInstall'; Reason = 'Exceeds 14 days'; Included = 'All devices'; Excluded = 'None'; IsAssigned = $true })
                        ProfileRows = @([pscustomobject]@{ Type = 'Feature update profile'; Name = '24H2 rollout'; Detail = 'Target version: Windows 11 24H2' })
                        MacRows = @(); GpoRows = @([pscustomobject]@{ Type = 'On-prem GPO'; Name = 'WSUS policy'; Detail = 'Configure Automatic Updates = Enabled' })
                        EolDevices = $inventory.EolDevices
                    }
                    Autoplay = [pscustomobject]@{ Findings = @([pscustomobject]@{ Source = 'Settings catalog'; PolicyName = 'Hardening'; Setting = 'autoplay_off'; State = 'Enabled (disables AutoPlay/AutoRun)'; Included = 'All devices'; Excluded = 'None'; Enforces = $true }) }
                    Accounts = [pscustomobject]@{
                        SharedAccounts = @([pscustomobject]@{ DisplayName = 'Reception'; UPN = 'reception@contoso.com'; Enabled = 'Yes'; UserType = 'Member'; Licenses = 'O365_E3'; Reasons = "name contains 'reception'" })
                        StaleAccounts = @([pscustomobject]@{ DisplayName = 'Old Bob'; UPN = 'oldbob@contoso.com'; LastSignIn = '2025-09-01'; Created = '2020-01-01' })
                        Guests = @([pscustomobject]@{ DisplayName = 'Ext Guest'; UPN = 'guest_x#EXT#@contoso.com'; Enabled = 'Yes'; Created = '2024-05-01' })
                        TotalUsers = 42; StaleDays = 90; AllUsers = @()
                    }
                    SecureConfig = [pscustomobject]@{ LockRows = @([pscustomobject]@{ Platform = 'Windows'; PolicyName = 'Win compliance'; Settings = 'passwordRequired = true'; Included = 'All devices'; Excluded = 'None'; IsAssigned = $true }) }
                    AppControl = [pscustomobject]@{ Findings = @([pscustomobject]@{ Source = 'On-prem GPO'; PolicyName = 'AppLocker GPO'; Mechanism = 'AppLocker / SRP (GPO)'; Setting = 'AppLocker rule collection: Exe = Enabled'; Included = 'contoso.com/Workstations'; Excluded = 'N/A (GPO link scope)' }) }
                    Password = [pscustomobject]@{ Details = [ordered]@{ 'Microsoft security defaults enabled' = 'No'; 'Custom banned password list enabled' = 'Yes'; 'Custom banned words configured' = '25' } }
                    Privileged = [pscustomobject]@{
                        Findings = @([pscustomobject]@{ Scope = 'Cloud (Entra ID)'; DisplayName = 'Alice Adams'; Account = 'alice@contoso.com'; Privilege = 'Global Administrator'; Assignment = 'Direct'; Enabled = 'Yes'; AccountClass = 'Standard user (licensed day-to-day account)'; Risk = 'HIGH - standard user holds a HIGH-privilege admin role'; Notes = 'Type=Member; O365_E3' })
                        StandardUsers = @(1); Nested = @(); High = @(1)
                    }
                    Mobile = [pscustomobject]@{
                        AppPolicies = @([pscustomobject]@{ Platform = 'iOS'; Name = 'iOS MAM'; Included = 'All users'; Excluded = 'None'; Settings = [ordered]@{ pinRequired = 'True' } })
                        CaAppEnforce = @([pscustomobject]@{ Name = 'Require approved apps'; State = 'enabled' })
                        Fallback = @()
                    }
                    Gpo = $null
                }
            }
            Export-CeWorkbook -Audit $audit -Path $Path
        } $path

        Test-Path $path | Should -BeTrue
        $sheets = @(Get-ExcelSheetInfo -Path $path)
        $sheets.Count | Should -Be 14
        ($sheets | ForEach-Object { $_.Name }) | Should -Contain 'Summary'
        ($sheets | ForEach-Object { $_.Name }) | Should -Contain 'Malware protection'
        ($sheets | ForEach-Object { $_.Name }) | Should -Contain 'Security updates'
        ($sheets | ForEach-Object { $_.Name }) | Should -Contain 'Run info'

        # B1 regression at the rendering layer: a device name starting with '='
        # must have been neutralised in the workbook.
        $deviceRows = Import-Excel -Path $path -WorksheetName 'Device list' -NoHeader
        $flat = @($deviceRows | ForEach-Object { $_.PSObject.Properties.Value }) -join "`n"
        $flat | Should -Match "'=WS-EOL"
    }
}

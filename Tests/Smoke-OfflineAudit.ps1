# Offline end-to-end smoke: runs the FULL Invoke-CeAudit -> Export-CeReport
# pipeline with every Graph call stubbed inside module scope. No tenant, no
# sign-in. Catches runtime/orchestration bugs the unit tests cannot.
#   .\Tests\Smoke-OfflineAudit.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$m = Import-Module (Join-Path $root 'CyberEssentialsAudit\CyberEssentialsAudit.psd1') -Force -PassThru

& $m {
    param($OutPath)

    # ---- Graph stubs (module scope overrides) -----------------------------
    function script:Connect-CeGraph {
        param([string]$AuthMode, [string]$TenantId, [string]$ClientId, [string]$CertificateThumbprint)
        $script:Ce.ConnectedByUs = $false
        [pscustomobject]@{ TenantId = '00000000-0000-0000-0000-000000000000'; Account = 'smoke@contoso.com'; Scopes = @('Directory.Read.All') }
    }
    function script:Get-MgContext {
        [pscustomobject]@{ TenantId = '00000000-0000-0000-0000-000000000000'; Account = 'smoke@contoso.com'; Scopes = @('Directory.Read.All') }
    }
    function script:Get-CeGraphJson {
        param([string]$Uri, [string]$Area)
        switch -Regex ($Uri) {
            'identitySecurityDefaultsEnforcementPolicy' { return [pscustomobject]@{ isEnabled = $false } }
            # Legacy MDM security baseline (intent): the AutoPlay category is
            # named "Auto Play" WITH A SPACE - the regression this smoke guards.
            'intents/int1/categories/c1/settings' {
                return [pscustomobject]@{ value = @(
                    [pscustomobject]@{ definitionId = 'deviceConfiguration--windows10GeneralConfiguration_autoPlayMode'; value = 'blocked' }
                ) }
            }
            'intents/int1/categories' {
                return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'c1'; displayName = 'Auto Play' }) }
            }
            'templates/tmpl1/categories' { return [pscustomobject]@{ value = @() } }
            'templates/tmpl1'            { return [pscustomobject]@{ displayName = 'MDM Security Baseline for Windows 10 and later for December 2020' } }
            '/settings$'                                { return [pscustomobject]@{ value = @() } }
            'configurationPolicies/.+/settings'         { return [pscustomobject]@{ value = @() } }
            'users/.+\?'                                { return [pscustomobject]@{ id = 'u1'; displayName = 'Alice Adams'; userPrincipalName = 'alice@contoso.com'; accountEnabled = $true; userType = 'Member'; assignedLicenses = @(@{ skuId = 'sku1' }); onPremisesSyncEnabled = $false } }
            default                                     { return $null }
        }
    }
    function script:Get-CeGraphPaged {
        param([string]$Uri, [string]$Area)
        # NOTE: patterns are evaluated top-down - keep the most specific first
        # (entity assignment URIs end in /assignments with no query string).
        switch -Regex ($Uri) {
            '/[^/?]+/assignments$' {
                return @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
            }
            'configurationPolicies/cp2/settings' {
                # Modern security baseline (settings catalog): AutoPlay settings.
                return @(
                    [pscustomobject]@{
                        id = '0'
                        settingInstance = [pscustomobject]@{
                            settingDefinitionId = 'device_vendor_msft_policy_config_autoplay_turnoffautoplay'
                            settingInstanceTemplateReference = [pscustomobject]@{ settingInstanceTemplateId = 'x' }
                            choiceSettingValue = [pscustomobject]@{ value = 'device_vendor_msft_policy_config_autoplay_turnoffautoplay_1'; children = @() }
                        }
                    }
                )
            }
            'configurationPolicies/.+/settings' {
                return @([pscustomobject]@{
                    id = '0'
                    settingInstance = [pscustomobject]@{
                        settingDefinitionId = 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring'
                        choiceSettingValue = [pscustomobject]@{ value = 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring_1'; children = @() }
                    }
                })
            }
            'deviceCompliancePolicies' {
                return @([pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'cmp1'; displayName = 'Win compliance'
                    passwordRequired = $true; passwordMinimumLength = 8
                    assignments = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
                })
            }
            "managedDevices.+Windows" {
                return @(
                    [pscustomobject]@{ deviceName = 'WS-001'; manufacturer = 'Dell'; model = 'XPS'; operatingSystem = 'Windows'; osVersion = '10.0.26100.4061'; skuFamily = 'Pro'; joinType = 'azureADJoined'; managedDeviceOwnerType = 'company'; userPrincipalName = 'alice@contoso.com'; lastSyncDateTime = '2026-06-01T10:00:00Z' }
                    [pscustomobject]@{ deviceName = 'WS-EOL'; manufacturer = 'HP'; model = 'EliteBook'; operatingSystem = 'Windows'; osVersion = '10.0.19045.5011'; skuFamily = 'Pro'; joinType = 'azureADJoined'; managedDeviceOwnerType = 'company'; userPrincipalName = 'bob@contoso.com'; lastSyncDateTime = '2026-06-02T10:00:00Z' }
                    [pscustomobject]@{ deviceName = 'MAC-01'; manufacturer = 'Apple'; model = 'MacBook Air'; operatingSystem = 'macOS'; osVersion = '14.7.1'; skuFamily = ''; joinType = ''; managedDeviceOwnerType = 'company'; userPrincipalName = 'carol@contoso.com'; lastSyncDateTime = '2026-06-03T10:00:00Z' }
                )
            }
            "managedDevices.+Android" {
                return @([pscustomobject]@{ deviceName = 'Pixel-1'; manufacturer = 'Google'; model = 'Pixel 8'; operatingSystem = 'Android'; osVersion = '15.0'; managedDeviceOwnerType = 'personal'; userPrincipalName = 'alice@contoso.com'; lastSyncDateTime = '2026-06-01T10:00:00Z' })
            }
            'conditionalAccess/policies' {
                return @([pscustomobject]@{
                    displayName = 'Require MFA - all users'; state = 'enabled'
                    conditions = [pscustomobject]@{
                        applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @() }
                        users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @(); excludeGroups = @(); excludeRoles = @() }
                    }
                    grantControls = [pscustomobject]@{ builtInControls = @('mfa'); authenticationStrength = $null }
                })
            }
            'deviceConfigurations' {
                return @(
                    [pscustomobject]@{
                        '@odata.type' = '#microsoft.graph.windows10EndpointProtectionConfiguration'; id = 'dc1'; displayName = 'EP profile'
                        firewallProfileDomain  = [pscustomobject]@{ firewallEnabled = 'allowed' }
                        firewallProfilePrivate = [pscustomobject]@{ firewallEnabled = 'allowed' }
                        firewallProfilePublic  = [pscustomobject]@{ firewallEnabled = 'allowed' }
                        appLockerApplicationControl = 'enforceComponentsAndStoreApps'
                        defenderMonitorFileActivity = 'monitorAllFiles'
                    },
                    [pscustomobject]@{
                        '@odata.type' = '#microsoft.graph.windowsUpdateForBusinessConfiguration'; id = 'dc2'; displayName = 'Ring 1'
                        qualityUpdatesDeferralPeriodInDays = 0; deadlineForQualityUpdatesInDays = 7; deadlineGracePeriodInDays = 2
                        qualityUpdatesPaused = $false; featureUpdatesDeferralPeriodInDays = 14; automaticUpdateMode = 'autoInstallAtMaintenanceTime'
                    }
                )
            }
            'configurationPolicies$|configurationPolicies\?' {
                return @(
                    [pscustomobject]@{ id = 'cp1'; name = 'Defender AV policy'; platforms = 'windows10' }
                    [pscustomobject]@{ id = 'cp2'; name = 'Security Baseline for Windows 10 and later'; platforms = 'windows10'
                                       templateReference = [pscustomobject]@{ templateFamily = 'Baseline' } }
                )
            }
            'intents$|intents\?' {
                return @([pscustomobject]@{ id = 'int1'; displayName = 'MDM Security Baseline - Dec 2020'; templateId = 'tmpl1' })
            }
            'v1\.0/users\?' {
                return @(
                    [pscustomobject]@{ displayName = 'Alice Adams'; userPrincipalName = 'alice@contoso.com'; givenName = 'Alice'; surname = 'Adams'; accountEnabled = $true; assignedLicenses = @(@{ skuId = 'sku1' }); createdDateTime = '2024-01-01T00:00:00Z'; userType = 'Member'; signInActivity = [pscustomobject]@{ lastSignInDateTime = '2026-06-01T00:00:00Z' } }
                    [pscustomobject]@{ displayName = 'Reception'; userPrincipalName = 'reception@contoso.com'; givenName = ''; surname = ''; accountEnabled = $true; assignedLicenses = @(); createdDateTime = '2024-01-01T00:00:00Z'; userType = 'Member'; signInActivity = $null }
                )
            }
            'userRegistrationDetails' {
                return @([pscustomobject]@{ userPrincipalName = 'alice@contoso.com'; userDisplayName = 'Alice Adams'; isMfaRegistered = $true; isMfaCapable = $true; methodsRegistered = @('microsoftAuthenticatorPush') })
            }
            'directoryRoles$|directoryRoles\?' {
                return @([pscustomobject]@{ id = 'role1'; displayName = 'Global Administrator' })
            }
            'directoryRoles/role1/members' {
                return @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; displayName = 'Alice Adams'; userPrincipalName = 'alice@contoso.com' })
            }
            'subscribedSkus' {
                return @([pscustomobject]@{ skuId = 'sku1'; skuPartNumber = 'O365_E3' })
            }
            'organization' {
                return @([pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @([pscustomobject]@{ name = 'contoso.com' }) })
            }
            'intents' { return @() }
            default   { return @() }
        }
    }

    Write-Host '=== OFFLINE SMOKE: Invoke-CeAudit (CloudOnly, stubbed Graph) ===' -ForegroundColor Magenta
    $audit = Invoke-CeAudit -Mode CloudOnly
    Write-Host ("Overall: {0}" -f $audit.Overall)
    $audit.Checks | ForEach-Object { '{0,-12} {1,-8} {2}' -f $_.CheckId, $_.Status, $_.Title } | Write-Host

    Write-Host '=== OFFLINE SMOKE: Export-CeReport (Excel + Json) ===' -ForegroundColor Magenta
    Export-CeReport -Audit $audit -Path $OutPath -Format Both -ForceOverwrite | Out-Null
    Write-Host ("Workbook tabs: {0}" -f (@(Get-ExcelSheetInfo -Path $OutPath).Count))
} (Join-Path $env:TEMP 'CyberEssentialsAudit_offline-smoke.xlsx')

Write-Host 'OFFLINE SMOKE PASSED' -ForegroundColor Green

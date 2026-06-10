# User access control: MFA on cloud services (CE auto-fail item).
# Fixes B2 (only ENABLED policies count as enforcing) and B7 (security
# defaults and actual MFA registration coverage are surfaced).
function Get-CeMfaCheck {
    [CmdletBinding()]
    param([bool]$SecurityDefaultsOn = $false)

    Write-Host 'Reviewing MFA enforcement (Conditional Access, security defaults, registration)...' -ForegroundColor Cyan

    $caPolicies = @()
    $caReadFailed = $false
    try { $caPolicies = Get-CeCollection -Key 'caPolicies' -Uri $script:CeUri.CaPolicies -Area 'ConditionalAccess' }
    catch { $caReadFailed = $true }

    $eval = Get-CeMfaEvaluation -CaPolicies $caPolicies -SecurityDefaultsOn $SecurityDefaultsOn -CaReadFailed $caReadFailed

    # Per-policy detail rows (enabled first, then report-only/disabled tagged).
    $policyRows = @()
    foreach ($group in @(
        @{ Set = $eval.Enforced;   Tag = 'ENABLED (enforcing)' }
        @{ Set = $eval.ReportOnly; Tag = 'REPORT-ONLY (not enforcing)' }
        @{ Set = $eval.Disabled;   Tag = 'DISABLED (not enforcing)' }
    )) {
        foreach ($p in @($group.Set)) {
            $apps  = $p.conditions.applications
            $users = $p.conditions.users
            $includeApps  = @($apps.includeApplications | Where-Object { $_ })
            $excludeApps  = @($apps.excludeApplications | Where-Object { $_ })
            $allApps      = ($includeApps -contains 'All')
            $includeUsers = @($users.includeUsers | Where-Object { $_ })
            $allUsers     = ($includeUsers -contains 'All')
            $exUsers  = @($users.excludeUsers  | Where-Object { $_ } | ForEach-Object { Resolve-CeDirObject $_ })
            $exGroups = @($users.excludeGroups | Where-Object { $_ } | ForEach-Object { Resolve-CeDirObject $_ })
            $exRoles  = @($users.excludeRoles  | Where-Object { $_ } | ForEach-Object { Resolve-CeDirObject $_ })
            $grant = @()
            if ($p.grantControls.builtInControls)        { $grant += $p.grantControls.builtInControls }
            if ($p.grantControls.authenticationStrength) { $grant += "Auth strength: $($p.grantControls.authenticationStrength.displayName)" }
            $policyRows += [ordered]@{
                'Policy name'               = $p.displayName
                'Enforcement'               = $group.Tag
                'State'                     = $p.state
                'Grant control'             = ($grant -join ', ')
                'Applies to all cloud apps' = $(if ($allApps) { 'Yes' } else { 'No' })
                'Included applications'     = $(if ($allApps) { 'All cloud apps' } elseif ($includeApps.Count) { $includeApps -join ', ' } else { 'None' })
                'Excluded applications'     = $(if ($excludeApps.Count) { $excludeApps -join ', ' } else { 'None' })
                'Covers all users'          = $(if ($allUsers) { 'Yes' } else { 'No' })
                'Excluded users'            = $(if ($exUsers.Count)  { $exUsers  -join '; ' } else { 'None' })
                'Excluded groups'           = $(if ($exGroups.Count) { $exGroups -join '; ' } else { 'None' })
                'Excluded roles'            = $(if ($exRoles.Count)  { $exRoles  -join '; ' } else { 'None' })
            }
        }
    }

    # MFA registration coverage (reports/authenticationMethods - needs
    # AuditLog.Read.All; Unknown when unavailable, never silent).
    $regStatus = 'Unknown'; $regReason = ''; $regTotal = 0; $regMfa = 0; $regRows = @()
    try {
        $reg = Get-CeGraphPaged -Uri ("{0}?`$top=999" -f $script:CeUri.UserRegistrationDetails) -Area 'UserRegistration'
        $regTotal = @($reg).Count
        $regMfa   = @($reg | Where-Object { $_.isMfaRegistered }).Count
        $regRows  = @($reg | Where-Object { -not $_.isMfaRegistered } | ForEach-Object {
            [pscustomobject]@{
                User     = [string]$_.userPrincipalName
                Name     = [string]$_.userDisplayName
                MfaCapable = $(if ($_.isMfaCapable) { 'Yes' } else { 'No' })
                Methods  = (@($_.methodsRegistered) -join ', ')
            }
        })
        if ($regTotal -eq 0) {
            $regStatus = 'Unknown'
            $regReason = 'Registration report returned no rows - verify manually'
        } elseif ($regMfa -eq $regTotal) {
            $regStatus = 'Pass'
            $regReason = "All $regTotal user(s) are registered for MFA"
        } else {
            $regStatus = 'Manual'
            $regReason = ("{0} of {1} user(s) are MFA-registered; {2} are not (listed on the MFA tab). Confirm unregistered accounts are not in active use." -f $regMfa, $regTotal, ($regTotal - $regMfa))
        }
    } catch {
        $regStatus = 'Unknown'
        $regReason = 'MFA registration report unavailable (requires AuditLog.Read.All and may need Entra ID P1) - verify registration coverage manually'
    }

    $results = @(
        New-CeCheckResult -Control 'User access control' -CheckId 'CE-UA-01' `
            -Title 'MFA enforced for all users on cloud services' `
            -Status $eval.Status -Reason $eval.Reason `
            -Evidence ("Security defaults: {0}; enabled MFA policies: {1}; report-only: {2}; disabled: {3}" -f `
                $(if ($SecurityDefaultsOn) { 'On' } else { 'Off' }), @($eval.Enforced).Count, @($eval.ReportOnly).Count, @($eval.Disabled).Count) `
            -DetailSheet 'MFA'
        New-CeCheckResult -Control 'User access control' -CheckId 'CE-UA-02' `
            -Title 'Users are registered for MFA' `
            -Status $regStatus -Reason $regReason `
            -Evidence ("{0} of {1} users MFA-registered" -f $regMfa, $regTotal) `
            -DetailSheet 'MFA'
    )

    [pscustomobject]@{
        Results            = $results
        Evaluation         = $eval
        PolicyRows         = @($policyRows)
        CaPolicyCount      = @($caPolicies).Count
        SecurityDefaultsOn = $SecurityDefaultsOn
        RegistrationTotal  = $regTotal
        RegistrationMfa    = $regMfa
        Unregistered       = $regRows
    }
}

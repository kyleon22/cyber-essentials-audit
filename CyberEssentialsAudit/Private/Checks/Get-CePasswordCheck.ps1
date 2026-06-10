# User access control: password-based authentication protections.
# Fixes B9: the previous verdict claimed a CUSTOM banned-password list was
# "REQUIRED" for CE. It is not. CE (Willow and Danzell) accepts any of:
#   a) MFA on the account (covered by CE-UA-01),
#   b) minimum 12-character passwords with no maximum length,
#   c) minimum 8 characters PLUS automatic deny-list of common passwords,
#   d) throttling / account lockout on failed attempts.
# Entra ID tenants get Microsoft's GLOBAL banned-password list and smart
# lockout automatically; a custom banned list (needs Entra ID P1/P2)
# strengthens the evidence but is not mandatory.
function Get-CePasswordCheck {
    [CmdletBinding()]
    param(
        [bool]$SecurityDefaultsOn = $false,
        [bool]$IsHybrid = $false,
        [bool]$AdAvailable = $false,
        [hashtable]$AdParams = @{},
        [object[]]$GpoFindings = @()
    )

    Write-Host 'Reviewing password protections (banned list, lockout, domain policy)...' -ForegroundColor Cyan

    # ---- Entra password rule settings ----------------------------------------
    $bannedListEnabled = $false
    $bannedListMode    = 'Not configured'
    $bannedWordCount   = 0
    $lockoutThreshold  = $null
    $lockoutDuration   = $null
    $settingsRead      = $true
    try {
        $dirSettings = Get-CeGraphJson -Uri $script:CeUri.DirectorySettings -Area 'PasswordSettings'
        foreach ($s in @($dirSettings.value)) {
            if ([string]$s.displayName -ne 'Password Rule Settings') { continue }
            foreach ($v in @($s.values)) {
                switch ([string]$v.name) {
                    'BannedPasswordList' {
                        $list = [string]$v.value
                        if (-not [string]::IsNullOrWhiteSpace($list)) {
                            $bannedWordCount = @($list -split '\t' | Where-Object { $_ }).Count
                        }
                    }
                    'EnableBannedPasswordCheck'         { if ($v.value -match '(?i)true') { $bannedListEnabled = $true } }
                    'BannedPasswordCheckOnPremisesMode' { $bannedListMode = [string]$v.value }
                    'LockoutThreshold'                  { $lockoutThreshold = [string]$v.value }
                    'LockoutDurationInSeconds'          { $lockoutDuration = [string]$v.value }
                }
            }
        }
    } catch { $settingsRead = $false }

    $customBannedInPlace = ($bannedListEnabled -and $bannedWordCount -gt 0)

    # ---- On-prem domain password policy (hybrid) ------------------------------
    $domainPolicy = $null
    if ($IsHybrid -and $AdAvailable) {
        try {
            $dp = Get-ADDefaultDomainPasswordPolicy @AdParams -ErrorAction Stop
            $domainPolicy = [ordered]@{
                'Minimum password length'   = [string]$dp.MinPasswordLength
                'Complexity enabled'        = [string]$dp.ComplexityEnabled
                'Lockout threshold'         = [string]$dp.LockoutThreshold
                'Lockout duration'          = [string]$dp.LockoutDuration
                'Maximum password age'      = [string]$dp.MaxPasswordAge
                'Password history'          = [string]$dp.PasswordHistoryCount
            }
        } catch {
            Write-Warning "Could not read the default domain password policy: $($_.Exception.Message)"
        }
    }

    # ---- Verdict ---------------------------------------------------------------
    # Cloud accounts: Microsoft's global banned list + smart lockout apply to
    # every Entra tenant -> route (d) (and partially (c)) is always present.
    $routes = @()
    $routes += 'Microsoft global banned-password list (automatic for all Entra ID tenants)'
    $routes += ("Smart lockout (threshold: {0}, duration: {1}s)" -f `
        $(if ($null -ne $lockoutThreshold) { $lockoutThreshold } else { 'default 10' }),
        $(if ($null -ne $lockoutDuration)  { $lockoutDuration }  else { 'default 60' }))
    if ($customBannedInPlace) { $routes += ("Custom banned-password list ({0} words)" -f $bannedWordCount) }
    if ($SecurityDefaultsOn)  { $routes += 'Security defaults (MFA for all users)' }

    $status = 'Pass'
    $reason = ("Cloud accounts are protected against password guessing: {0}. CE accepts any of: MFA; 12+ character minimum with no maximum; 8+ characters with a deny list; or throttling/lockout. Danzell raises the expected minimum length to 12 where MFA is not used - confirm the configured minimum for any password-only access." -f ($routes -join '; '))

    if ($IsHybrid) {
        if ($domainPolicy) {
            $minLen = 0
            [void][int]::TryParse([string]$domainPolicy['Minimum password length'], [ref]$minLen)
            $lockout = 0
            [void][int]::TryParse([string]$domainPolicy['Lockout threshold'], [ref]$lockout)
            if ($minLen -ge 12) {
                $reason += (" On-prem domain policy: minimum length {0} (meets the 12-character route)." -f $minLen)
            } elseif ($minLen -ge 8 -and $lockout -gt 0) {
                $reason += (" On-prem domain policy: minimum length {0} with lockout after {1} attempts (meets the 8+ with throttling route - a deny list, e.g. Entra Password Protection for on-prem, is recommended)." -f $minLen, $lockout)
            } else {
                $status = 'Fail'
                $reason = ("On-prem domain password policy does not meet CE: minimum length {0}, lockout threshold {1}. Require 12+ characters, or 8+ with a deny list and lockout enabled. Cloud protections: {2}." -f $minLen, $lockout, ($routes -join '; '))
            }
        } elseif ($AdAvailable) {
            $status = 'Unknown'
            $reason = 'The on-prem domain password policy could not be read - password controls for AD accounts cannot be verified. ' + $reason
        } else {
            $status = 'Manual'
            $reason = 'On-prem AD was not reachable - verify the domain password policy manually. ' + $reason
        }
    }
    if (-not $settingsRead) {
        if ($status -eq 'Pass') { $status = 'Manual' }
        $reason = 'Entra password rule settings could not be read (defaults assumed). ' + $reason
    }

    $details = [ordered]@{
        'Microsoft security defaults enabled' = $(if ($SecurityDefaultsOn) { 'Yes' } else { 'No' })
        'Custom banned password list enabled' = $(if ($bannedListEnabled) { 'Yes' } else { 'No' })
        'Custom banned words configured'      = "$bannedWordCount"
        'On-premises enforcement mode'        = $bannedListMode
        'Smart lockout threshold'             = $(if ($null -ne $lockoutThreshold) { $lockoutThreshold } else { 'Default (10)' })
        'Smart lockout duration (seconds)'    = $(if ($null -ne $lockoutDuration)  { $lockoutDuration }  else { 'Default (60)' })
    }
    if ($domainPolicy) {
        foreach ($k in $domainPolicy.Keys) { $details["On-prem: $k"] = $domainPolicy[$k] }
    }
    $pwGpo = @($GpoFindings | Where-Object { $_.Control -eq 'Password / lockout' })
    if ($pwGpo.Count) {
        $details['On-prem password/lockout GPO setting(s)'] = (($pwGpo | ForEach-Object { "$($_.GPO): $($_.Setting)=$($_.Value)" }) -join '; ')
    }

    [pscustomobject]@{
        Results = @(
            New-CeCheckResult -Control 'User access control' -CheckId 'CE-UA-06' `
                -Title 'Password-based authentication protected (length / deny list / throttling)' `
                -Status $status -Reason $reason `
                -Evidence ("Banned list: {0}; custom words: {1}; security defaults: {2}" -f `
                    $(if ($bannedListEnabled) { 'On' } else { 'Off' }), $bannedWordCount, $(if ($SecurityDefaultsOn) { 'On' } else { 'Off' })) `
                -DetailSheet 'Password'
        )
        Details             = $details
        CustomBannedInPlace = $customBannedInPlace
        DomainPolicy        = $domainPolicy
        GpoFindings         = $pwGpo
    }
}

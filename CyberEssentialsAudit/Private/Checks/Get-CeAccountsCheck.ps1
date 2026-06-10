# Account hygiene: suspected shared accounts (heuristic - always a Manual
# verdict), guest-account review, and stale/leaver accounts (last sign-in
# beyond the threshold; needs AuditLog.Read.All -> Unknown when unavailable).
function Get-CeAccountsCheck {
    [CmdletBinding()]
    param([int]$StaleAccountDays = 90)

    Write-Host 'Reviewing accounts (shared-account heuristics, guests, stale sign-ins)...' -ForegroundColor Cyan

    # SKU id -> part number map for license display.
    if ($script:Ce.SkuMap.Count -eq 0) {
        try {
            foreach ($s in @(Get-CeCollection -Key 'subscribedSkus' -Uri $script:CeUri.SubscribedSkus -Area 'Users')) {
                $script:Ce.SkuMap[[string]$s.skuId] = [string]$s.skuPartNumber
            }
        } catch { }
    }
    $skuMap = $script:Ce.SkuMap

    $sharedKeywords = @(
        'shared','admin','administrator','service','svc','info','support','help',
        'helpdesk','sales','marketing','team','group','noreply','no-reply','donotreply',
        'do-not-reply','mailbox','account','accounts','billing','finance','reception',
        'enquir','contact','general','itsupport','sysadmin','printer','scanner','kiosk',
        'reservation','booking','room','test','demo','training','common'
    )

    $allUsers = @()
    $usersFailed = $false
    $signInAvailable = $true
    # signInActivity needs AuditLog.Read.All (and Entra P1); fall back to the
    # plain select when the first page fails.
    $selectWithSignIn = '$select=displayName,userPrincipalName,givenName,surname,mail,accountEnabled,assignedLicenses,createdDateTime,userType,signInActivity'
    $selectPlain      = '$select=displayName,userPrincipalName,givenName,surname,mail,accountEnabled,assignedLicenses,createdDateTime,userType'
    try {
        $allUsers = Get-CeGraphPaged -Uri ("{0}?{1}&`$top=999" -f $script:CeUri.Users, $selectWithSignIn) -Area 'UsersSignIn'
    } catch {
        $signInAvailable = $false
        try { $allUsers = Get-CeGraphPaged -Uri ("{0}?{1}&`$top=999" -f $script:CeUri.Users, $selectPlain) -Area 'Users' }
        catch { $usersFailed = $true }
    }
    $allUsers = @($allUsers)

    # ---- Suspected shared accounts (heuristic) -------------------------------
    $sharedAccounts = @()
    foreach ($u in $allUsers) {
        $dn  = [string]$u.displayName
        $upn = [string]$u.userPrincipalName
        $local = ($upn -split '@')[0]
        $hay = ("{0} {1}" -f $dn, $local).ToLower()
        $reasons = @()
        foreach ($kw in $sharedKeywords) {
            if ($hay -match ('(?i)\b' + [regex]::Escape($kw))) { $reasons += "name contains '$kw'"; break }
        }
        if ([string]::IsNullOrWhiteSpace([string]$u.givenName) -or [string]::IsNullOrWhiteSpace([string]$u.surname)) {
            $reasons += 'missing first/last name'
        }
        if ($dn -and ($dn -notmatch '\s')) { $reasons += 'single-word display name' }
        if ($reasons.Count -eq 0) { continue }
        $lic = @()
        foreach ($al in @($u.assignedLicenses)) {
            $id = [string]$al.skuId
            if ($id) { $lic += $(if ($skuMap.ContainsKey($id)) { $skuMap[$id] } else { $id }) }
        }
        $sharedAccounts += [pscustomobject]@{
            DisplayName = $dn
            UPN         = $upn
            Enabled     = $(if ($u.accountEnabled) { 'Yes' } else { 'No' })
            UserType    = [string]$u.userType
            Licenses    = $(if ($lic.Count) { ($lic | Sort-Object -Unique) -join ', ' } else { 'Unlicensed' })
            Reasons     = ($reasons | Select-Object -Unique) -join '; '
        }
    }
    $sharedAccounts = @($sharedAccounts | Sort-Object DisplayName)

    # ---- Guests --------------------------------------------------------------
    $guests = @($allUsers | Where-Object { [string]$_.userType -eq 'Guest' } | ForEach-Object {
        [pscustomobject]@{
            DisplayName = [string]$_.displayName
            UPN         = [string]$_.userPrincipalName
            Enabled     = $(if ($_.accountEnabled) { 'Yes' } else { 'No' })
            Created     = [string]$_.createdDateTime
        }
    })

    # ---- Stale accounts (leaver process evidence) -----------------------------
    $staleRows = @()
    $staleCutoff = (Get-Date).AddDays(-1 * $StaleAccountDays)
    if ($signInAvailable -and -not $usersFailed) {
        foreach ($u in $allUsers) {
            if (-not $u.accountEnabled) { continue }
            if ([string]$u.userType -eq 'Guest') { continue }
            $licensed = (@($u.assignedLicenses).Count -gt 0)
            if (-not $licensed) { continue }
            $last = $null
            if ($u.signInActivity -and $u.signInActivity.lastSignInDateTime) {
                $last = [datetime]$u.signInActivity.lastSignInDateTime
            }
            $created = $u.createdDateTime -as [datetime]
            # Never signed in AND created before the cutoff also counts as stale.
            $isStale = $false
            if ($last) { $isStale = ($last -lt $staleCutoff) }
            elseif ($created) { $isStale = ($created -lt $staleCutoff) }
            if (-not $isStale) { continue }
            $staleRows += [pscustomobject]@{
                DisplayName = [string]$u.displayName
                UPN         = [string]$u.userPrincipalName
                LastSignIn  = $(if ($last) { $last.ToString('yyyy-MM-dd') } else { 'Never' })
                Created     = $(if ($created) { $created.ToString('yyyy-MM-dd') } else { '' })
            }
        }
        $staleRows = @($staleRows | Sort-Object LastSignIn)
    }

    # ---- Verdicts --------------------------------------------------------------
    $sharedStatus = $(if ($usersFailed) { 'Unknown' } else { 'Manual' })
    $sharedReason = $(if ($usersFailed) {
        'User list could not be read - shared-account review not possible'
    } elseif ($sharedAccounts.Count -eq 0) {
        'No accounts matched the shared-account heuristics. CE requires unique accounts per user - a manual confirmation is still expected.'
    } else {
        ("{0} account(s) flagged HEURISTICALLY as possibly shared (naming patterns / missing names). These are NOT confirmed - each must be manually verified. CE requires a unique account per user." -f $sharedAccounts.Count)
    })

    if ($usersFailed) {
        $guestStatus = 'Unknown'; $guestReason = 'User list could not be read'
    } elseif ($guests.Count -eq 0) {
        $guestStatus = 'Pass'; $guestReason = 'No guest accounts in the tenant'
    } else {
        $guestStatus = 'Manual'
        $guestReason = ("{0} guest account(s) exist. Confirm each guest still requires access (account creation/disablement process must cover guests)." -f $guests.Count)
    }

    if (-not $signInAvailable) {
        $staleStatus = 'Unknown'
        $staleReason = 'Last sign-in data unavailable (requires AuditLog.Read.All and Entra ID P1) - verify the leaver process manually'
    } elseif ($usersFailed) {
        $staleStatus = 'Unknown'; $staleReason = 'User list could not be read'
    } elseif ($staleRows.Count -eq 0) {
        $staleStatus = 'Pass'
        $staleReason = ("No enabled licensed account has been inactive for over {0} days - consistent with a working leaver/disablement process" -f $StaleAccountDays)
    } else {
        $staleStatus = 'Manual'
        $staleReason = ("{0} enabled, licensed account(s) have not signed in for over {1} days (listed on the Shared accounts tab). CE requires accounts to be disabled/removed when no longer needed - review each." -f $staleRows.Count, $StaleAccountDays)
    }

    $results = @(
        New-CeCheckResult -Control 'User access control' -CheckId 'CE-UA-03' `
            -Title 'Unique accounts per user (no shared accounts)' `
            -Status $sharedStatus -Reason $sharedReason `
            -Evidence ("{0} of {1} account(s) flagged for review" -f $sharedAccounts.Count, $allUsers.Count) `
            -DetailSheet 'Shared accounts'
        New-CeCheckResult -Control 'User access control' -CheckId 'CE-UA-04' `
            -Title 'Accounts disabled when no longer needed (leavers / stale accounts)' `
            -Status $staleStatus -Reason $staleReason `
            -Evidence ("{0} stale account(s) beyond {1} days" -f @($staleRows).Count, $StaleAccountDays) `
            -DetailSheet 'Shared accounts'
        New-CeCheckResult -Control 'User access control' -CheckId 'CE-UA-05' `
            -Title 'Guest / external accounts reviewed' `
            -Status $guestStatus -Reason $guestReason `
            -Evidence ("{0} guest account(s)" -f $guests.Count) `
            -DetailSheet 'Shared accounts'
    )

    [pscustomobject]@{
        Results        = $results
        SharedAccounts = $sharedAccounts
        Guests         = $guests
        StaleAccounts  = @($staleRows)
        TotalUsers     = $allUsers.Count
        AllUsers       = $allUsers
        StaleDays      = $StaleAccountDays
    }
}

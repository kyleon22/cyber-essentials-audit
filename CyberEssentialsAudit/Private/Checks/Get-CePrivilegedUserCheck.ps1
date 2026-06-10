# User access control: separate admin accounts. Enumerates every identity
# holding administrative privilege (Entra roles incl. role-assignable groups
# and PIM-eligible assignments; on-prem AD privileged groups resolved via an
# LDAP_MATCHING_RULE_IN_CHAIN query - fixes B12's 5,000-member and foreign-SID
# failures) and flags standard users that also hold admin (classification via
# the anchored-token Get-CePrivClass - fixes B8).
function Get-CePrivilegedUserCheck {
    [CmdletBinding()]
    param(
        [bool]$IsHybrid = $false,
        [bool]$AdAvailable = $false,
        [hashtable]$AdParams = @{}
    )

    Write-Host 'Reviewing privileged users (admin roles & privileged groups)...' -ForegroundColor Cyan
    $findings = New-Object System.Collections.Generic.List[object]
    $scopeCloud  = 'Cloud (Entra ID)'
    $scopeOnPrem = 'On-premises (AD)'
    $rolesFailed = $false

    $highPrivRoleNames = @(
        'Global Administrator','Privileged Role Administrator','Privileged Authentication Administrator',
        'Security Administrator','Exchange Administrator','SharePoint Administrator','User Administrator',
        'Conditional Access Administrator','Application Administrator','Cloud Application Administrator',
        'Intune Administrator','Authentication Administrator','Helpdesk Administrator','Password Administrator',
        'Hybrid Identity Administrator','Domain Name Administrator','Global Reader'
    )

    # Per-user info, cached for the whole run.
    function Get-CePrivUserInfo {
        param([string]$Id)
        if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
        if ($script:Ce.UserCache.ContainsKey($Id)) { return $script:Ce.UserCache[$Id] }
        $info = $null
        try {
            $u = Get-CeGraphJson -Uri ("{0}/{1}?`$select=id,displayName,userPrincipalName,accountEnabled,userType,assignedLicenses,onPremisesSyncEnabled" -f $script:CeUri.Users, $Id) -Area 'PrivilegedUsers'
            $lic = @()
            foreach ($al in @($u.assignedLicenses)) {
                $sid = [string]$al.skuId
                if ($sid) { $lic += $(if ($script:Ce.SkuMap.ContainsKey($sid)) { $script:Ce.SkuMap[$sid] } else { $sid }) }
            }
            $info = [pscustomobject]@{
                DisplayName  = [string]$u.displayName
                UPN          = [string]$u.userPrincipalName
                Enabled      = [bool]$u.accountEnabled
                UserType     = [string]$u.userType
                Licensed     = ($lic.Count -gt 0)
                Licenses     = $(if ($lic.Count) { ($lic | Sort-Object -Unique) -join ', ' } else { 'Unlicensed' })
                OnPremSynced = [bool]$u.onPremisesSyncEnabled
            }
        } catch { }
        $script:Ce.UserCache[$Id] = $info
        return $info
    }

    function New-CloudPrivRow {
        param($Role, $Via, [bool]$High, $Info, $FallbackName, $FallbackAccount)
        $name = if ($Info -and $Info.DisplayName) { $Info.DisplayName } else { [string]$FallbackName }
        $acct = if ($Info -and $Info.UPN)         { $Info.UPN }         else { [string]$FallbackAccount }
        $enabled  = if ($Info) { $(if ($Info.Enabled) { 'Yes' } else { 'No' }) } else { 'Unknown' }
        $licensed = [bool]($Info -and $Info.Licensed)
        $class    = Get-CePrivClass -Account $acct -Name $name -Licensed $licensed -IsBuiltinAdmin $false
        $isStd    = ($class -match '(?i)standard user')
        $risk = if (-not $Info) { 'Privileged - could not resolve account, verify manually' }
                elseif (-not $Info.Enabled) { 'Disabled account holds an admin role - remove the role' }
                elseif ($isStd -and $High)  { 'HIGH - standard user holds a HIGH-privilege admin role' }
                elseif ($isStd)             { 'Standard user holds an admin role - use a separate admin account' }
                elseif ($licensed)          { 'Licensed admin account - prefer an unlicensed/cloud-only admin' }
                elseif ($High)              { 'High-privilege role - confirm still required' }
                else                        { 'Privileged - confirm still required' }
        [pscustomobject]@{
            Scope = $scopeCloud; DisplayName = $name; Account = $acct; Privilege = $Role
            Assignment = $Via; Enabled = $enabled; AccountClass = $class; Risk = $risk
            Notes = $(if ($Info) { "Type=$($Info.UserType); $($Info.Licenses)$(if ($Info.OnPremSynced) { '; on-prem synced' })" } else { '' })
        }
    }

    # ---- Cloud: activated directory roles ------------------------------------
    try {
        $roles = Get-CeGraphPaged -Uri $script:CeUri.DirectoryRoles -Area 'PrivilegedUsers'
        foreach ($role in @($roles)) {
            $roleName = [string]$role.displayName
            $isHigh   = ($highPrivRoleNames -contains $roleName)
            $members  = @()
            try {
                $members = Get-CeGraphPaged -Uri ("{0}/{1}/members?`$select=id,displayName,userPrincipalName" -f $script:CeUri.DirectoryRoles, $role.id) -Area 'PrivilegedUsers'
            } catch { continue }
            foreach ($m in @($members)) {
                $type = [string]$m.'@odata.type'
                if ($type -match '(?i)\.group$') {
                    # Role-assignable group: every nested user inherits the role.
                    $gusers = @()
                    try {
                        $gusers = @(Get-CeGraphPaged -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers?`$select=id,displayName,userPrincipalName&`$top=999" -f $m.id) -Area 'PrivilegedUsers' |
                            Where-Object { [string]$_.'@odata.type' -match '(?i)\.user$' })
                    } catch { }
                    if ($gusers.Count -eq 0) {
                        $findings.Add([pscustomobject]@{
                            Scope = $scopeCloud; DisplayName = [string]$m.displayName; Account = '(role-assignable group)'
                            Privilege = $roleName; Assignment = 'Group (no nested users)'; Enabled = 'n/a'
                            AccountClass = 'Role-assignable group'; Risk = 'Empty/again-nested group holds a role - review'; Notes = ''
                        })
                    }
                    foreach ($gu in $gusers) {
                        $info = Get-CePrivUserInfo ([string]$gu.id)
                        $findings.Add((New-CloudPrivRow -Role $roleName -Via ("Nested via group: $($m.displayName)") -High $isHigh -Info $info -FallbackName $gu.displayName -FallbackAccount $gu.userPrincipalName))
                    }
                }
                elseif ($type -match '(?i)serviceprincipal') {
                    $findings.Add([pscustomobject]@{
                        Scope = $scopeCloud; DisplayName = [string]$m.displayName; Account = '(service principal / app)'
                        Privilege = $roleName; Assignment = 'Direct (service principal)'; Enabled = 'n/a'
                        AccountClass = 'Service principal (application)'
                        Risk = $(if ($isHigh) { 'Review - application holds a HIGH-privilege role' } else { 'Review - application holds an admin role' })
                        Notes = 'Non-human identity; confirm the app still requires this role.'
                    })
                }
                else {
                    $info = Get-CePrivUserInfo ([string]$m.id)
                    $findings.Add((New-CloudPrivRow -Role $roleName -Via 'Direct' -High $isHigh -Info $info -FallbackName $m.displayName -FallbackAccount $m.userPrincipalName))
                }
            }
        }
    } catch { $rolesFailed = $true }

    # ---- Cloud: PIM-eligible assignments (best effort) -------------------------
    try {
        $elig = Get-CeGraphPaged -Uri $script:CeUri.RoleEligibility -Area 'PimEligibility'
        foreach ($e in @($elig)) {
            $p = $e.principal
            if (-not $p) { continue }
            $rn = [string]$e.roleDefinition.displayName
            if ([string]$p.'@odata.type' -match '(?i)\.user$') {
                $info = Get-CePrivUserInfo ([string]$p.id)
                $findings.Add((New-CloudPrivRow -Role $rn -Via 'Eligible (PIM, not active)' -High ($highPrivRoleNames -contains $rn) -Info $info -FallbackName $p.displayName -FallbackAccount $p.userPrincipalName))
            }
        }
    } catch {
        Write-Verbose 'PIM eligibility not available (no PIM licence or insufficient scope).'
    }

    # ---- On-premises: privileged AD groups (nested-aware, robust) --------------
    if ($IsHybrid -and $AdAvailable) {
        Write-Host '  Enumerating privileged on-premises AD groups (LDAP in-chain)...' -ForegroundColor DarkGray
        $domainSid = $null
        try { $domainSid = (Get-ADDomain @AdParams -ErrorAction Stop).DomainSID.Value } catch { }

        $privSids = @()
        if ($domainSid) {
            # 512 Domain Admins | 518 Schema Admins | 519 Enterprise Admins
            # 520 Group Policy Creator Owners
            foreach ($rid in 512, 518, 519, 520) { $privSids += "$domainSid-$rid" }
        }
        # 544 Administrators | 548 Account Operators | 549 Server Operators
        # 550 Print Operators | 551 Backup Operators | 552 Replicator
        $privSids += @('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551','S-1-5-32-552')

        $adPrivGroups = @()
        foreach ($sid in ($privSids | Select-Object -Unique)) {
            try { $adPrivGroups += (Get-ADGroup -Identity $sid @AdParams -Properties member -ErrorAction Stop) } catch { }
        }
        foreach ($gn in @('DnsAdmins','Key Admins','Enterprise Key Admins','DHCP Administrators')) {
            try { $adPrivGroups += (Get-ADGroup -Identity $gn @AdParams -Properties member -ErrorAction Stop) } catch { }
        }
        $adPrivGroups = @($adPrivGroups | Sort-Object DistinguishedName -Unique)

        $adUserCache = @{}
        $getAdUser = {
            param([string]$Dn)
            if ($adUserCache.ContainsKey($Dn)) { return $adUserCache[$Dn] }
            $d = $null
            try {
                $u = Get-ADUser -Identity $Dn @AdParams -Properties Enabled, DisplayName, SamAccountName, UserPrincipalName, adminCount, Description, SID, lastLogonTimestamp -ErrorAction Stop
                $ll = $null
                if ($u.lastLogonTimestamp) { try { $ll = [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp) } catch { } }
                $d = [pscustomobject]@{
                    Enabled = [bool]$u.Enabled
                    Name    = $(if ($u.DisplayName) { [string]$u.DisplayName } else { [string]$u.SamAccountName })
                    Sam     = [string]$u.SamAccountName
                    UPN     = [string]$u.UserPrincipalName
                    AdminCount = [int]([string]$u.adminCount -as [int])
                    Rid     = ([string]$u.SID.Value -split '-')[-1]
                    LastLogon = $ll
                    Description = [string]$u.Description
                }
            } catch { }
            $adUserCache[$Dn] = $d
            return $d
        }

        # All nested USER members of a group in ONE LDAP query - handles >5,000
        # members and skips foreign security principals / orphaned SIDs that
        # break Get-ADGroupMember -Recursive. Falls back to the cmdlet.
        $getNestedUserDns = {
            param([string]$GroupDn)
            try {
                $escaped = $GroupDn -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29'
                return @(Get-ADUser @AdParams -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$escaped)" -ErrorAction Stop |
                    ForEach-Object { [string]$_.DistinguishedName })
            } catch {
                try {
                    return @(Get-ADGroupMember -Identity $GroupDn @AdParams -Recursive -ErrorAction Stop |
                        Where-Object { $_.objectClass -eq 'user' } | ForEach-Object { [string]$_.distinguishedName })
                } catch { return @() }
            }
        }

        $adPrivMembers = 0
        foreach ($grp in $adPrivGroups) {
            # Direct members from the group's own member attribute (no 5,000 cap).
            $directDns = @($grp.member | ForEach-Object { [string]$_ })
            $allUserDns = & $getNestedUserDns ([string]$grp.DistinguishedName)

            # Which directly-nested sub-group(s) does a nested user inherit through?
            $subGroupMembers = @{}
            foreach ($dn in $directDns) {
                $obj = $null
                try { $obj = Get-ADObject -Identity $dn @AdParams -ErrorAction Stop } catch { continue }
                if ($obj.ObjectClass -eq 'group') {
                    $subGroupMembers[[string]$obj.Name] = @(& $getNestedUserDns $dn)
                }
            }

            foreach ($dn in $allUserDns) {
                $isDirect = ($directDns -contains $dn)
                if ($isDirect) {
                    $via = 'Direct'
                } else {
                    $through = @($subGroupMembers.Keys | Where-Object { $subGroupMembers[$_] -contains $dn })
                    $via = if ($through.Count) { "Nested via $((($through | Sort-Object -Unique) -join ' / '))" } else { 'Nested (via group)' }
                }
                $du = & $getAdUser $dn
                $isBuiltinAdmin = ($du -and $du.Rid -eq '500')
                $name = if ($du) { $du.Name } else { $dn }
                $acct = if ($du -and $du.Sam) { $du.Sam } else { $dn }
                $enabled = if ($du) { $(if ($du.Enabled) { 'Yes' } else { 'No' }) } else { 'Unknown' }
                $class = Get-CePrivClass -Account $acct -Name $name -Licensed $false -IsBuiltinAdmin $isBuiltinAdmin
                $isStd = ($class -match '(?i)standard user')
                $risk = if ($du -and -not $du.Enabled) { 'Disabled account in a privileged group - remove it' }
                        elseif ($isBuiltinAdmin)       { 'Built-in Administrator - secure, monitor & restrict use' }
                        elseif ($isStd -and -not $isDirect) { 'HIGH - standard user inherits admin via NESTED group' }
                        elseif ($isStd)                { 'Standard user is a direct member of a privileged group' }
                        else                           { 'Admin account - confirm still required' }
                $notes = @()
                if ($du) {
                    if ($du.AdminCount -eq 1) { $notes += 'adminCount=1' }
                    if ($du.LastLogon)        { $notes += ("last logon {0:yyyy-MM-dd}" -f $du.LastLogon) }
                    if ($du.Description)      { $notes += $du.Description }
                }
                $findings.Add([pscustomobject]@{
                    Scope = $scopeOnPrem; DisplayName = $name; Account = $acct; Privilege = [string]$grp.Name
                    Assignment = $via; Enabled = $enabled; AccountClass = $class; Risk = $risk
                    Notes = ($notes -join '; ')
                })
                $adPrivMembers++
            }
        }
        Write-Host ("  On-premises: {0} privileged membership(s) across {1} group(s)." -f $adPrivMembers, $adPrivGroups.Count) -ForegroundColor Green
    }

    $all = @($findings.ToArray() | Sort-Object Scope, Privilege, DisplayName)
    $standardUsers = @($all | Where-Object { $_.AccountClass -match '(?i)standard user' })
    $nested        = @($all | Where-Object { $_.Assignment -match '(?i)nested|eligible' })
    $high          = @($all | Where-Object { $_.Risk -match '^HIGH' })

    if ($rolesFailed -and $all.Count -eq 0) {
        $status = 'Unknown'
        $reason = 'Directory roles could not be enumerated (RoleManagement.Read.Directory required) - privileged-access separation cannot be verified'
    } elseif ($standardUsers.Count -gt 0) {
        $status = 'Fail'
        $reason = ("{0} standard (day-to-day) user account(s) hold administrative privilege - CE requires separate admin accounts. Worst offenders: {1}" -f `
            $standardUsers.Count, (($standardUsers | Select-Object -First 5 | ForEach-Object { $_.Account }) -join '; '))
    } else {
        $status = 'Pass'
        $reason = ("All {0} privileged membership(s) belong to dedicated admin accounts, service principals or the built-in Administrator. Confirm each is still required." -f $all.Count)
    }

    [pscustomobject]@{
        Results = @(
            New-CeCheckResult -Control 'User access control' -CheckId 'CE-UA-07' `
                -Title 'Admin privileges separated from day-to-day accounts' `
                -Status $status -Reason $reason `
                -Evidence ("{0} privileged membership(s); {1} standard users with admin; {2} HIGH-risk" -f $all.Count, $standardUsers.Count, $high.Count) `
                -DetailSheet 'Privileged users'
        )
        Findings      = $all
        StandardUsers = $standardUsers
        Nested        = $nested
        High          = $high
    }
}

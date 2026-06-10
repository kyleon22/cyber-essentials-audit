# Resolve a directory object id (user / group / role) to a friendly name,
# CACHED per run (fixes B14: the same excluded group referenced by ten CA
# policies previously cost ten Graph calls).
function Resolve-CeDirObject {
    [CmdletBinding()]
    param([string]$Id)
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    switch ($Id) {
        'All'                   { return 'All' }
        'None'                  { return 'None' }
        'GuestsOrExternalUsers' { return 'Guests / external users' }
    }
    if ($script:Ce.DirCache.ContainsKey($Id)) { return $script:Ce.DirCache[$Id] }
    $name = $Id
    try {
        $o = Get-CeGraphJson -Uri ("{0}/{1}" -f $script:CeUri.DirectoryObjects, $Id) -Area 'DirectoryObjects'
        if     ($o.userPrincipalName) { $name = "$($o.displayName) <$($o.userPrincipalName)>" }
        elseif ($o.displayName)       { $name = [string]$o.displayName }
    } catch { $name = $Id }
    $script:Ce.DirCache[$Id] = $name
    return $name
}

# Summarise an Intune assignment collection into Included / Excluded strings.
function Get-CeAssignmentSummary {
    [CmdletBinding()]
    param($Assignments)
    $inc = @()
    $exc = @()
    foreach ($a in @($Assignments)) {
        $t = $a.target
        if (-not $t) { continue }
        $type = [string]$t.'@odata.type'
        switch ($type) {
            '#microsoft.graph.allDevicesAssignmentTarget'       { $inc += 'All devices'; break }
            '#microsoft.graph.allLicensedUsersAssignmentTarget' { $inc += 'All users'; break }
            '#microsoft.graph.exclusionGroupAssignmentTarget'   { $exc += [string](Resolve-CeDirObject ([string]$t.groupId)); break }
            '#microsoft.graph.groupAssignmentTarget'            { $inc += [string](Resolve-CeDirObject ([string]$t.groupId)); break }
            default                                             { $inc += "Other ($type)"; break }
        }
    }
    [pscustomobject]@{
        Included   = $(if ($inc.Count) { $inc -join '; ' } else { 'Not assigned' })
        Excluded   = $(if ($exc.Count) { $exc -join '; ' } else { 'None' })
        IsAssigned = ($inc.Count -gt 0)
    }
}

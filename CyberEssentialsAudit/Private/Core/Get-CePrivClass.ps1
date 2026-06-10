# Classify a privileged account for the "standard user with admin privileges"
# finding. Fixes B8: admin-naming tokens are ANCHORED so ordinary surnames
# ("Adams", "Ahmadi", "Privett") are not classified as admin-named accounts.
#
# An account "looks admin" when a recognised token appears as a discrete
# element of the account name (start/end, or delimited by . _ - or a digit),
# e.g.: admin.jones, jones.admin, adm-jsmith, svc_backup, jsmith-a, da-jones.
$script:CeAdminTokenPattern = '(?i)(^|[._\-])(adm|admin|administrator|priv|svc|service|da|sa)([._\-\d]|$)|(-a|_a)$'

function Get-CePrivClass {
    [CmdletBinding()]
    param(
        [string]$Account,
        [string]$Name,
        [bool]$Licensed,
        [bool]$IsBuiltinAdmin
    )
    # Match against the local part only (UPNs carry a domain).
    $local = ([string]$Account -split '@')[0]
    $looksAdmin = $IsBuiltinAdmin -or
                  ($local -match $script:CeAdminTokenPattern) -or
                  ($Name -match '(?i)(^|[\s._\-(\[])(admin|administrator|service account|break.?glass)([\s._\-)\]]|$)')

    if ($IsBuiltinAdmin) { return 'Built-in Administrator (expected, secure it)' }
    elseif ($Licensed -and -not $looksAdmin) { return 'Standard user (licensed day-to-day account)' }
    elseif ($Licensed) { return 'Admin-named but LICENSED account' }
    elseif ($looksAdmin) { return 'Dedicated admin account' }
    else { return 'Standard user account' }
}

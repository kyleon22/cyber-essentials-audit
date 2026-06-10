# Graph sign-in supporting both interactive (delegated) and unattended
# app-only (certificate) authentication. Records whether THIS run created the
# connection so the orchestrator only disconnects sessions it owns (fixes B15:
# the old script tore down any pre-existing operator session in its finally
# block).
$script:CeDelegatedScopes = @(
    'DeviceManagementManagedDevices.Read.All',  # Intune devices
    'DeviceManagementConfiguration.Read.All',   # device config / firewall / compliance
    'DeviceManagementApps.Read.All',            # app protection (MAM) policies
    'Policy.Read.All',                          # Conditional Access + security defaults
    'Directory.Read.All',                       # resolve users/groups/roles
    'User.Read.All',                            # account / shared-account review
    'RoleManagement.Read.Directory',            # directory roles, PIM eligibility
    'AuditLog.Read.All'                         # MFA registration + last sign-in activity
)

function Connect-CeGraph {
    [CmdletBinding()]
    param(
        [ValidateSet('Delegated', 'App')][string]$AuthMode = 'Delegated',
        [string]$TenantId,
        # App-only (certificate) auth - required for scheduled/unattended runs.
        [string]$ClientId,
        [string]$CertificateThumbprint
    )

    # Reuse an existing session only if it already carries every scope we need
    # (delegated) - otherwise sign in fresh.
    $existing = $null
    try { $existing = Get-MgContext } catch { }
    if ($existing -and $AuthMode -eq 'Delegated') {
        $missing = @($script:CeDelegatedScopes | Where-Object { @($existing.Scopes) -notcontains $_ })
        if ($missing.Count -eq 0) {
            Write-Verbose 'Reusing the existing Microsoft Graph session (all scopes present).'
            $script:Ce.ConnectedByUs = $false
            return $existing
        }
    }

    if ($AuthMode -eq 'App') {
        if (-not $ClientId -or -not $TenantId -or -not $CertificateThumbprint) {
            throw 'App auth requires -ClientId, -TenantId and -CertificateThumbprint. The app registration needs the application-permission equivalents of the read scopes (see README).'
        }
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId `
            -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    } else {
        $params = @{ Scopes = $script:CeDelegatedScopes; NoWelcome = $true; ErrorAction = 'Stop' }
        if ($TenantId) { $params['TenantId'] = $TenantId }
        Connect-MgGraph @params
    }

    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Failed to establish a Microsoft Graph context.' }
    $script:Ce.ConnectedByUs = $true
    return $ctx
}

function Disconnect-CeGraph {
    [CmdletBinding()]
    param()
    if ($script:Ce -and $script:Ce.ConnectedByUs) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        $script:Ce.ConnectedByUs = $false
    }
}

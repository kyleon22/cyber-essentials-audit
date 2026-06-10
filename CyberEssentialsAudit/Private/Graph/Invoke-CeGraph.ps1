# Graph plumbing: central URI table (B16 - beta endpoint churn is a one-line
# fix), paging on EVERY list (B5), shared collection caches (B14 - the same
# data is never fetched twice in a run), and an error journal so checks can be
# marked Unknown instead of silently passing/failing when a call fails.

# Every Graph URI the tool touches. beta is still required for most Intune
# config reads; keep v1.0 wherever it suffices.
$script:CeUri = @{
    ManagedDevices          = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'
    DeviceConfigurations    = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
    ConfigurationPolicies   = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
    Intents                 = 'https://graph.microsoft.com/beta/deviceManagement/intents'
    Templates               = 'https://graph.microsoft.com/beta/deviceManagement/templates'
    GroupPolicyConfigs      = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
    CompliancePolicies      = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?$expand=assignments'
    FeatureUpdateProfiles   = 'https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles'
    DriverUpdateProfiles    = 'https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles'
    QualityUpdateProfiles   = 'https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles'
    IosAppProtections       = 'https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections?$expand=assignments'
    AndroidAppProtections   = 'https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections?$expand=assignments'
    DirectorySettings       = 'https://graph.microsoft.com/beta/settings'
    CaPolicies              = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    SecurityDefaults        = 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    Users                   = 'https://graph.microsoft.com/v1.0/users'
    DirectoryRoles          = 'https://graph.microsoft.com/v1.0/directoryRoles'
    RoleEligibility         = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=roleDefinition,principal'
    SubscribedSkus          = 'https://graph.microsoft.com/v1.0/subscribedSkus'
    Organization            = 'https://graph.microsoft.com/v1.0/organization'
    DirectoryObjects        = 'https://graph.microsoft.com/v1.0/directoryObjects'
    UserRegistrationDetails = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'
}

# Per-run mutable state. Reset by Invoke-CeAudit before anything else runs.
function Initialize-CeSession {
    [CmdletBinding()]
    param()
    $script:Ce = @{
        GraphErrors   = New-Object System.Collections.Generic.List[object]
        DirCache      = @{}   # directory object id -> friendly name
        UserCache     = @{}   # user id -> privileged-user info
        Collections   = @{}   # cache key -> fetched collection
        TemplateNames = @{}   # templateId -> displayName
        TemplateDefs  = @{}   # templateId -> @{ definitionId = displayName }
        ConnectedByUs = $false
        SkuMap        = @{}
    }
}

# Record a failed Graph call. Checks consult Test-CeAreaFailed to decide
# between Fail ("we looked, nothing is configured") and Unknown ("we could
# not look").
function Add-CeGraphError {
    [CmdletBinding()]
    param([string]$Area, [string]$Uri, [string]$Message)
    $script:Ce.GraphErrors.Add([pscustomobject]@{
        Area    = $Area
        Uri     = $Uri
        Message = $Message
        TimeUtc = [datetime]::UtcNow
    })
    Write-Warning ("Graph call failed [{0}]: {1}" -f $Area, $Message)
}

function Test-CeAreaFailed {
    [CmdletBinding()]
    param([string[]]$Area)
    foreach ($e in $script:Ce.GraphErrors) {
        if ($Area -contains $e.Area) { return $true }
    }
    return $false
}

# Raw GET returning parsed JSON. Bypasses the SDK's typed model binding (which
# can throw uncatchable errors on polymorphic Intune entities). Throws on
# failure AFTER journaling the error.
function Get-CeGraphJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Area = 'Graph'
    )
    try {
        $json = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Json -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($json)) { return $null }
        return ($json | ConvertFrom-Json)
    } catch {
        Add-CeGraphError -Area $Area -Uri $Uri -Message $_.Exception.Message
        throw
    }
}

# Paged GET: follows @odata.nextLink on EVERY collection (fixes B5 - the
# intents endpoint was previously never paginated). Throws on failure.
function Get-CeGraphPaged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Area = 'Graph'
    )
    $out = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    do {
        $resp = Get-CeGraphJson -Uri $next -Area $Area
        if ($resp -and $resp.value) { $out.AddRange(@($resp.value)) }
        $next = $null
        if ($resp) { $next = $resp.'@odata.nextLink' }
    } while ($next)
    # Plain (enumerated) return on purpose: every consumer wraps with @(...).
    return $out.ToArray()
}

# Cached paged fetch: one Graph round-trip per collection per run, no matter
# how many checks consume it (the old script fetched intents and
# configurationPolicies four times each).
function Get-CeCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Uri,
        [string]$Area = 'Graph'
    )
    if ($script:Ce.Collections.ContainsKey($Key)) { return $script:Ce.Collections[$Key] }
    $value = Get-CeGraphPaged -Uri $Uri -Area $Area
    $script:Ce.Collections[$Key] = $value
    return $value
}

# Assignments for an Intune entity.
function Get-CePolicyAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaseUri,   # entity collection URI WITHOUT query string
        [Parameter(Mandatory)][string]$Id,
        [string]$Area = 'Graph'
    )
    $clean = ($BaseUri -split '\?')[0]
    try { return Get-CeGraphPaged -Uri ("{0}/{1}/assignments" -f $clean, $Id) -Area $Area } catch { return @() }
}

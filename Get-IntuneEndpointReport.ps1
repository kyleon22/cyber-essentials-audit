<#
.SYNOPSIS
    Cyber Essentials readiness report - Intune / Microsoft 365 tenant audit.

.DESCRIPTION
    Connects to Microsoft Graph using DELEGATED (interactive) authentication and
    builds an Excel workbook (.xlsx) via the Excel COM object with the tabs:

      * Device list                - Windows & macOS Intune devices + summary
      * MFA                        - Conditional Access MFA enforcement
      * Software firewall          - firewall policies (incl. security baselines)
      * Mobile devices             - Android/iOS devices, MAM app protection
      * Status of autoplay-autorun - AutoPlay/AutoRun disabling settings
      * Shared accounts            - suspected shared accounts + licenses

    Requires:
      * Microsoft.Graph.Authentication module (Install-Module Microsoft.Graph.Authentication)
      * ImportExcel module (auto-installed if missing) - writes native .xlsx
        with NO Microsoft Excel / Office install required (works on servers/DCs)
      * Delegated Graph scopes (consented at sign-in):
          DeviceManagementManagedDevices.Read.All
          DeviceManagementConfiguration.Read.All
          DeviceManagementApps.Read.All
          Policy.Read.All
          Directory.Read.All
          User.Read.All

.NOTES
    Auth : Delegated / interactive (Connect-MgGraph)
#>

[CmdletBinding()]
param(
    # Where the .xlsx is written. Defaults to a timestamped file in the current
    # user's private Documents folder (not the current/working folder, which may
    # be shared). Must end in .xlsx. See the output-safety block below.
    [string]$OutputPath = (Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath ("IntuneEndpointReport_{0:yyyyMMdd_HHmmss}.xlsx" -f (Get-Date))),

    # Check-in window in weeks. Devices not seen within this window are dropped.
    [int]$CheckInWindowWeeks = 6,

    # Optional explicit tenant id for the interactive sign-in.
    [string]$TenantId,

    # Environment scope. If not supplied, the script prompts at launch.
    [ValidateSet('CloudOnly','Hybrid')]
    [string]$Mode,

    # Hybrid: FQDN of a domain controller / AD server to target.
    [string]$DomainController,

    # Hybrid: explicit domain credential. If omitted in Hybrid mode the
    # script prompts with Get-Credential.
    [System.Management.Automation.PSCredential]$ADCredential,

    # Write a baseline-diagnostics.txt dump of every intent's categories,
    # settings and resolved names (for troubleshooting baseline detection).
    [switch]$DiagnoseBaselines,

    # Overwrite an existing output file even if it does not look like a prior
    # report (i.e. not named IntuneEndpointReport_*.xlsx). Off by default so a
    # mistyped path cannot silently destroy an unrelated file.
    [switch]$ForceOverwrite,

    # Pin the exact versions of the PSGallery modules the preflight installs.
    # Override only if you have validated a different version.
    [string]$GraphModuleVersion = '2.25.0',
    [string]$ImportExcelVersion = '7.8.10'
)

$ErrorActionPreference = 'Stop'

# =========================================================================== #
#  Helper functions                                                           #
# =========================================================================== #

# Map a Windows osVersion (build number) to a friendly feature update name.
function Get-WindowsFriendlyOS {
    param([string]$OsVersion)
    if ([string]::IsNullOrWhiteSpace($OsVersion)) { return 'Windows (unknown build)' }
    $parts = $OsVersion.Split('.')
    if ($parts.Count -lt 3) { return "Windows $OsVersion" }
    $build = 0
    [void][int]::TryParse($parts[2], [ref]$build)
    $map = @{
        26100 = 'Windows 11 24H2'; 22631 = 'Windows 11 23H2'; 22621 = 'Windows 11 22H2'
        22000 = 'Windows 11 21H2'; 19045 = 'Windows 10 22H2'; 19044 = 'Windows 10 21H2'
        19043 = 'Windows 10 21H1'; 19042 = 'Windows 10 20H2'; 19041 = 'Windows 10 2004'
        18363 = 'Windows 10 1909'; 18362 = 'Windows 10 1903'; 17763 = 'Windows 10 1809'
    }
    if ($map.ContainsKey($build)) { return $map[$build] }
    if ($build -ge 22000) { return "Windows 11 (build $build)" }
    elseif ($build -ge 10240) { return "Windows 10 (build $build)" }
    else { return "Windows $OsVersion" }
}

# Tidy a SKU family value. Falls back to "Unknown".
function Format-Sku {
    param([string]$Sku)
    if ([string]::IsNullOrWhiteSpace($Sku)) { return 'Unknown' }
    return $Sku.Trim()
}

# =========================================================================== #
#  0. Environment scope (cloud-only vs hybrid)                                #
# =========================================================================== #
if (-not $Mode) {
    Write-Host ''
    Write-Host 'Is this audit for a CLOUD-ONLY environment or a HYBRID environment' -ForegroundColor Cyan
    Write-Host '(on-premises Active Directory / domain controllers + Microsoft 365)?' -ForegroundColor Cyan
    Write-Host '  [1] Cloud only' -ForegroundColor White
    Write-Host '  [2] Hybrid'     -ForegroundColor White
    do {
        $choice = Read-Host 'Enter 1 or 2'
    } until ($choice -in @('1','2'))
    $Mode = if ($choice -eq '2') { 'Hybrid' } else { 'CloudOnly' }
}
$IsHybrid = ($Mode -eq 'Hybrid')
Write-Host ("Audit mode: {0}" -f $Mode) -ForegroundColor Green

# =========================================================================== #
#  0.5 Dependency preflight check                                             #
# =========================================================================== #
# Detects every component the chosen mode needs and, when something is missing,
# offers to install it. Two kinds of dependency:
#   * PowerShell modules from the PSGallery (Microsoft.Graph.Authentication,
#     ImportExcel) -> installed with Install-Module.
#   * RSAT features (ActiveDirectory, GroupPolicy) for hybrid -> installed as
#     Windows capabilities / features (needs elevation).
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Install-RsatFeature {
    param([string]$Module)
    # Map the PowerShell module to its RSAT capability / feature name.
    $capability = switch ($Module) {
        'ActiveDirectory' { 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' }
        'GroupPolicy'     { 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0' }
        default           { $null }
    }
    $feature = switch ($Module) {
        'ActiveDirectory' { 'RSAT-AD-PowerShell' }
        'GroupPolicy'     { 'RSAT-GPMC' }
        default           { $null }
    }
    # On a server (incl. a DC), the AD/GPMC modules ship with the role or are
    # added via Windows Features; on a workstation they are Windows capabilities.
    try {
        if (Get-Command Add-WindowsCapability -ErrorAction SilentlyContinue) {
            $cap = Get-WindowsCapability -Online -Name $capability -ErrorAction Stop
            if ($cap.State -ne 'Installed') {
                Add-WindowsCapability -Online -Name $capability -ErrorAction Stop | Out-Null
            }
            return $true
        }
    } catch { }
    try {
        if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
            Install-WindowsFeature -Name $feature -IncludeManagementTools -ErrorAction Stop | Out-Null
            return $true
        }
    } catch { }
    return $false
}

# Build the required-dependency list for this run. PSGallery modules are
# version-PINNED (supply-chain hygiene: never silently pull "latest" onto a
# privileged audit host / domain controller).
$requiredModules = @(
    @{ Name = 'Microsoft.Graph.Authentication'; Kind = 'PSGallery'; Version = $GraphModuleVersion; Why = 'Microsoft Graph sign-in & API calls' }
    @{ Name = 'ImportExcel';                    Kind = 'PSGallery'; Version = $ImportExcelVersion; Why = 'native .xlsx output (no Office needed)' }
)
if ($IsHybrid) {
    $requiredModules += @{ Name = 'ActiveDirectory'; Kind = 'RSAT'; Why = 'on-premises AD device inventory' }
    $requiredModules += @{ Name = 'GroupPolicy';     Kind = 'RSAT'; Why = 'on-premises GPO review' }
}

Write-Host ''
Write-Host 'Checking dependencies...' -ForegroundColor Cyan
$missing = @()
foreach ($dep in $requiredModules) {
    if (Get-Module -ListAvailable -Name $dep.Name) {
        Write-Host ("  [OK]      {0}" -f $dep.Name) -ForegroundColor Green
    } else {
        Write-Host ("  [MISSING] {0}  - {1}" -f $dep.Name, $dep.Why) -ForegroundColor Yellow
        $missing += $dep
    }
}

if ($missing.Count -gt 0) {
    Write-Host ''
    Write-Host ("{0} dependency/dependencies are missing." -f $missing.Count) -ForegroundColor Yellow
    $ans = Read-Host 'Install the missing dependencies now? [Y/N]'
    if ($ans -notmatch '^(y|yes)$') {
        $instr = $missing | ForEach-Object {
            if ($_.Kind -eq 'PSGallery') { "  Install-Module $($_.Name) -RequiredVersion $($_.Version) -Repository PSGallery -Scope CurrentUser" }
            else { "  Add the RSAT feature for $($_.Name) (Install-WindowsFeature / Add-WindowsCapability)" }
        }
        throw ("Required dependencies are missing. Install them and re-run:`n{0}" -f ($instr -join "`n"))
    }

    $rsatNeedsAdmin = ($missing | Where-Object { $_.Kind -eq 'RSAT' }).Count -gt 0
    if ($rsatNeedsAdmin -and -not (Test-IsAdmin)) {
        throw 'Installing RSAT features (ActiveDirectory / GroupPolicy) requires an elevated session. Re-run PowerShell as Administrator, then run this script again.'
    }

    # Capture PSGallery's current trust state so we can RESTORE it afterwards
    # rather than leaving the repository permanently Trusted on this host.
    $psGalleryPolicy = $null
    try { $psGalleryPolicy = (Get-PSRepository -Name PSGallery -ErrorAction Stop).InstallationPolicy } catch { }

    try {
        foreach ($dep in $missing) {
            Write-Host ("Installing {0}{1}..." -f $dep.Name, $(if ($dep.Version) { " v$($dep.Version)" } else { '' })) -ForegroundColor Cyan
            try {
                if ($dep.Kind -eq 'PSGallery') {
                    # TLS 1.2 for older hosts that default to SSL3/TLS1.0.
                    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
                    # Pinned version, explicit repository; -Force only to bypass the
                    # untrusted-repo prompt non-interactively, NOT to pull "latest".
                    Install-Module $dep.Name -RequiredVersion $dep.Version -Repository PSGallery `
                        -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                } else {
                    if (-not (Install-RsatFeature -Module $dep.Name)) {
                        throw "automatic RSAT install not available on this OS"
                    }
                }
                Write-Host ("  Installed {0}." -f $dep.Name) -ForegroundColor Green
            } catch {
                throw ("Failed to install {0}: {1}. Install it manually and re-run." -f $dep.Name, $_.Exception.Message)
            }
        }
    } finally {
        # Restore PSGallery trust to whatever it was before this run.
        if ($psGalleryPolicy -and $psGalleryPolicy -ne 'Trusted') {
            try { Set-PSRepository -Name PSGallery -InstallationPolicy $psGalleryPolicy -ErrorAction Stop } catch { }
        }
    }
    Write-Host 'All dependencies installed.' -ForegroundColor Green
}

# When importing, load the PINNED version explicitly so a newer copy that may
# also be present on the host is not silently preferred.
$script:GraphModuleVersion  = $GraphModuleVersion
$script:ImportExcelVersion  = $ImportExcelVersion

# =========================================================================== #
#  1. Connect to Microsoft Graph (delegated / interactive)                    #
# =========================================================================== #
Write-Host 'Loading Microsoft.Graph.Authentication module...' -ForegroundColor Cyan
try { Import-Module Microsoft.Graph.Authentication -RequiredVersion $GraphModuleVersion -ErrorAction Stop }
catch { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop }

$connectParams = @{
    Scopes    = @(
        'DeviceManagementManagedDevices.Read.All',   # Intune devices
        'DeviceManagementConfiguration.Read.All',    # device config / firewall / compliance
        'DeviceManagementApps.Read.All',             # app protection (MAM) policies
        'Policy.Read.All',                            # Conditional Access policies
        'Directory.Read.All',                         # resolve users/groups/roles
        'User.Read.All'                               # account / shared-account review
    )
    NoWelcome = $true
}
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

Write-Host 'Signing in to Microsoft Graph (a browser window will open)...' -ForegroundColor Cyan
Connect-MgGraph @connectParams

$ctx = Get-MgContext
if (-not $ctx) { throw 'Failed to establish a Microsoft Graph context.' }
Write-Host ("Connected to tenant: {0} as {1}" -f $ctx.TenantId, $ctx.Account) -ForegroundColor Green

# =========================================================================== #
#  1b. Connect to on-premises Active Directory (hybrid only)                  #
# =========================================================================== #
# This script is intended to run ON a domain controller, so it uses the
# logged-on (integrated) Windows credentials by default. The optional
# -DomainController / -ADCredential parameters override that only if supplied
# (e.g. when run from a management host instead of a DC).
# $AdAvailable gates every on-prem section. $adParams carries any Server /
# Credential splat for the ActiveDirectory & GroupPolicy cmdlets.
$AdAvailable = $false
$adParams    = @{}
if ($IsHybrid) {
    Write-Host 'Hybrid mode: connecting to on-premises Active Directory (integrated auth)...' -ForegroundColor Cyan
    $missing = @()
    foreach ($m in @('ActiveDirectory','GroupPolicy')) {
        if (-not (Get-Module -ListAvailable -Name $m)) { $missing += $m }
    }
    if ($missing.Count) {
        Write-Warning ("Required module(s) not found: {0}. On-premises checks will be skipped. On a domain controller these ship with the AD DS / GPMC role; otherwise install RSAT." -f ($missing -join ', '))
    } else {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Import-Module GroupPolicy     -ErrorAction Stop

            # Use integrated credentials by default; honour overrides if given.
            if ($DomainController) { $adParams['Server']     = $DomainController }
            if ($ADCredential)     { $adParams['Credential'] = $ADCredential }

            # Validate the connection up front (uses current DC context).
            $domInfo = Get-ADDomain @adParams -ErrorAction Stop
            $AdAvailable = $true
            Write-Host ("Connected to AD domain: {0}" -f $domInfo.DNSRoot) -ForegroundColor Green
        } catch {
            Write-Warning "Could not connect to Active Directory: $($_.Exception.Message). On-premises checks will be skipped."
            $AdAvailable = $false
        }
    }
}

# --- Shared Graph helpers (defined after connect; used by every section) ---- #

# Resolve a directory object id (user / group / role) to a friendly name.
function Resolve-DirObject {
    param([string]$Id)
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    switch ($Id) {
        'All'                   { return 'All' }
        'None'                  { return 'None' }
        'GuestsOrExternalUsers' { return 'Guests / external users' }
    }
    try {
        $o = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$Id"
        if     ($o.userPrincipalName) { return "$($o.displayName) <$($o.userPrincipalName)>" }
        elseif ($o.displayName)       { return $o.displayName }
        else                          { return $Id }
    } catch { return $Id }
}

# Robust Graph GET that bypasses the SDK's typed model binding (which can throw
# an uncatchable "Argument types do not match" on polymorphic targets).
function Get-GraphJson {
    param([string]$Uri)
    $json = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Json
    if ([string]::IsNullOrWhiteSpace($json)) { return $null }
    return ($json | ConvertFrom-Json)
}

# Fetch a policy's assignments via a separate call, returning the value array.
function Get-PolicyAssignments {
    param([string]$Uri)
    try { return @((Get-GraphJson $Uri).value) } catch { return @() }
}

# Summarise an assignment collection into Included / Excluded strings.
function Get-AssignmentSummary {
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
            '#microsoft.graph.exclusionGroupAssignmentTarget'   { $exc += [string](Resolve-DirObject ([string]$t.groupId)); break }
            '#microsoft.graph.groupAssignmentTarget'            { $inc += [string](Resolve-DirObject ([string]$t.groupId)); break }
            default                                             { $inc += "Other ($type)"; break }
        }
    }
    [pscustomobject]@{
        Included = $(if ($inc.Count) { $inc -join '; ' } else { 'Not assigned' })
        Excluded = $(if ($exc.Count) { $exc -join '; ' } else { 'None' })
    }
}

# --- Caches & helpers for template-based intents (security baselines) ------- #
$tmplDefCache   = @{}   # templateId -> @{ definitionId = displayName }
$intentCatCache = @{}   # intentId   -> @( @{Category; Setting} )

# Build settingDefinitionId -> display name map for a template (cached).
function Get-TemplateDefMap {
    param([string]$TemplateId)
    if ([string]::IsNullOrWhiteSpace($TemplateId)) { return @{} }
    if ($tmplDefCache.ContainsKey($TemplateId)) { return $tmplDefCache[$TemplateId] }
    $map = @{}
    try {
        $cats = Get-GraphJson "https://graph.microsoft.com/beta/deviceManagement/templates/$TemplateId/categories?`$expand=settingDefinitions"
        foreach ($c in @($cats.value)) {
            foreach ($sd in @($c.settingDefinitions)) {
                if ($sd.id) { $map[[string]$sd.id] = [string]$sd.displayName }
            }
        }
    } catch { }
    $tmplDefCache[$TemplateId] = $map
    return $map
}

# Extract a readable value from an intent setting (scalar, else valueJson).
function Get-IntentSettingValue {
    param($S)
    $v = $S.value
    if ($null -ne $v -and ($v -is [string] -or $v -is [valuetype])) { return "$v" }
    $vj = $S.valueJson
    if ($null -ne $vj) { return ("$vj").Trim('"') }
    return "$v"
}

# Walk an intent's categories; return each setting paired with its category
# display name (cached). Category names like "AutoPlay Policies" are reliable
# even when individual setting definitionIds are opaque.
function Get-IntentCategorySettings {
    param([string]$IntentId)
    if ($intentCatCache.ContainsKey($IntentId)) { return $intentCatCache[$IntentId] }
    $out = @()
    try {
        $cats = Get-GraphJson "https://graph.microsoft.com/beta/deviceManagement/intents/$IntentId/categories"
        foreach ($cat in @($cats.value)) {
            $cs = $null
            try { $cs = Get-GraphJson "https://graph.microsoft.com/beta/deviceManagement/intents/$IntentId/categories/$($cat.id)/settings" } catch { }
            foreach ($s in @($cs.value)) {
                $out += [pscustomobject]@{ Category = [string]$cat.displayName; Setting = $s }
            }
        }
    } catch { }
    $intentCatCache[$IntentId] = $out
    return $out
}

# Map a stateManagementSetting value to a readable firewall state.
function Convert-FwState {
    param($Value)
    $v = [string]$Value
    if ([string]::IsNullOrWhiteSpace($v)) { return 'Not configured' }
    switch ($v) {
        'allowed'       { return 'Enabled' }
        'blocked'       { return 'Disabled' }
        'notConfigured' { return 'Not configured' }
        default         { return $v }
    }
}

# =========================================================================== #
#  2. Intune managed devices (Windows / macOS)                                #
# =========================================================================== #
$cutoff       = (Get-Date).AddDays(-7 * $CheckInWindowWeeks)
$cutoffUtcStr = $cutoff.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$filter = "lastSyncDateTime ge $cutoffUtcStr and (operatingSystem eq 'Windows' or operatingSystem eq 'macOS')"
$select = @('deviceName','manufacturer','model','operatingSystem','osVersion',
            'skuFamily','joinType','managedDeviceOwnerType','userPrincipalName','lastSyncDateTime')
$selectStr = $select -join ','

$uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$filter={0}&$select={1}&$top=200' -f `
            [uri]::EscapeDataString($filter), [uri]::EscapeDataString($selectStr)

Write-Host ("Querying managed devices checked in since {0} (UTC)..." -f $cutoffUtcStr) -ForegroundColor Cyan
$devices = [System.Collections.Generic.List[object]]::new()
do {
    $resp = Get-GraphJson $uri
    if ($resp.value) { $devices.AddRange(@($resp.value)) }
    $uri = $resp.'@odata.nextLink'
} while ($uri)

if ($devices.Count -eq 0) {
    Write-Warning 'No Windows/macOS devices matched the query.'
}
Write-Host ("Retrieved {0} device(s) within the {1}-week window." -f $devices.Count, $CheckInWindowWeeks) -ForegroundColor Green

$rows = foreach ($d in $devices) {
    $os = [string]$d.operatingSystem
    $osVer = [string]$d.osVersion
    $friendlyOS = if ($os -eq 'Windows') { Get-WindowsFriendlyOS -OsVersion $osVer } else { "macOS $osVer" }
    [pscustomobject]@{
        DeviceName   = $d.deviceName
        Manufacturer = $(if ($d.manufacturer) { $d.manufacturer } else { 'Unknown' })
        Model        = $d.model
        OS           = $friendlyOS
        OperatingSys = $os
        SkuFamily    = Format-Sku -Sku $d.skuFamily
        Ownership    = $d.managedDeviceOwnerType
        JoinType     = $d.joinType
        PrimaryUser  = $d.userPrincipalName
        LastCheckIn  = $d.lastSyncDateTime
        Source       = 'Cloud (Intune)'
        IsServer     = $(if ($friendlyOS -match '(?i)server') { $true } else { $false })
    }
}

# --------------------------------------------------------------------------- #
#  On-premises Active Directory device inventory (hybrid only)                #
# --------------------------------------------------------------------------- #
# AD holds only OS name/version + DNS name; hardware (manufacturer/model) and
# the Windows SKU edition are pulled per-device via CIM/WMI where reachable.
#
# Coverage notes:
#  * The search covers the ENTIRE domain subtree (default Get-ADComputer scope),
#    so EVERY container/OU is included - the default "Computers" (CN=Computers)
#    and "Domain Controllers" (OU=Domain Controllers) containers, plus all
#    custom OUs. Domain controllers and member servers are therefore captured.
#  * "Active" is judged from a COMBINED signal, because lastLogonTimestamp
#    replicates only every ~14 days and is frequently stale or null. We treat a
#    computer as active if ANY of lastLogonTimestamp, the computer-account
#    password age (pwdLastSet), or whenChanged falls within the window - or if
#    none of those is available (never drop a real object silently).
$onPremRows = @()
if ($IsHybrid -and $AdAvailable) {
    Write-Host 'Collecting on-premises AD computer inventory (all containers/OUs, CIM per device)...' -ForegroundColor Cyan

    # Enumerate the whole domain subtree from the domain root.
    $searchBase = $null
    try { $searchBase = (Get-ADDomain @adParams -ErrorAction Stop).DistinguishedName } catch { }
    $adcParams = @{} + $adParams
    if ($searchBase) { $adcParams['SearchBase'] = $searchBase; $adcParams['SearchScope'] = 'Subtree' }

    try {
        $adComputers = Get-ADComputer @adcParams -Filter 'Enabled -eq $true' `
            -Properties Name, DNSHostName, OperatingSystem, OperatingSystemVersion, `
                        lastLogonTimestamp, pwdLastSet, whenChanged, CanonicalName, DistinguishedName `
            -ErrorAction Stop
    } catch {
        Write-Warning "Could not enumerate AD computers: $($_.Exception.Message)"
        $adComputers = @()
    }

    $adComputers   = @($adComputers)
    $skippedStale  = 0
    $containerSeen = @{}

    foreach ($c in $adComputers) {
        # Track which container/OU each object lives in (for the coverage log).
        $container = 'Unknown'
        if ($c.DistinguishedName -match '^CN=[^,]+,(.+)$') { $container = $Matches[1] }
        $containerSeen[$container] = ([int]$containerSeen[$container]) + 1

        # Combined activity signal (any one within the window keeps the device).
        $llt = $null; if ($c.lastLogonTimestamp) { $llt = [datetime]::FromFileTimeUtc([int64]$c.lastLogonTimestamp) }
        $pls = $null; if ($c.pwdLastSet)         { $pls = [datetime]::FromFileTimeUtc([int64]$c.pwdLastSet) }
        $wch = $c.whenChanged -as [datetime]
        $dates  = @($llt, $pls, $wch) | Where-Object { $_ }
        $active = $true
        if ($dates.Count -gt 0) {
            $mostRecent = ($dates | Sort-Object -Descending)[0]
            $active = ($mostRecent -ge $cutoff)
        }
        if (-not $active) { $skippedStale++; continue }

        $adOs    = [string]$c.OperatingSystem
        $isSrv   = ($adOs -match '(?i)server')
        $manu = 'Unknown'; $model = ''; $sku = 'Unknown'; $friendly = $adOs
        $target = if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name }

        # Per-device CIM for hardware + OS edition (best effort).
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $target -ErrorAction Stop
            if ($cs.Manufacturer) { $manu = $cs.Manufacturer.Trim() }
            if ($cs.Model)        { $model = $cs.Model.Trim() }
            $osCim = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $target -ErrorAction Stop
            if ($osCim.Caption) { $friendly = ($osCim.Caption -replace '(?i)microsoft ', '').Trim() }
            # OperatingSystemSKU -> edition word (Standard/Datacenter/Pro/Enterprise).
            $sku = switch ([int]$osCim.OperatingSystemSKU) {
                7  { 'Standard' }      8  { 'Datacenter' }
                10 { 'Enterprise' }    48 { 'Pro' }
                4  { 'Enterprise' }    27 { 'Enterprise N' }
                default {
                    if     ($friendly -match '(?i)datacenter') { 'Datacenter' }
                    elseif ($friendly -match '(?i)standard')   { 'Standard' }
                    elseif ($friendly -match '(?i)enterprise') { 'Enterprise' }
                    elseif ($friendly -match '(?i)\bpro\b')    { 'Pro' }
                    else { 'Unknown' }
                }
            }
        } catch {
            Write-Verbose "CIM unreachable for $target : $($_.Exception.Message)"
        }

        # If AD has no OS string (rare) but CIM didn't fill it, leave a marker.
        if ([string]::IsNullOrWhiteSpace($friendly)) { $friendly = 'Windows (OS not reported)' }

        $lastSeen = $dates | Sort-Object -Descending | Select-Object -First 1

        $onPremRows += [pscustomobject]@{
            DeviceName   = $c.Name
            Manufacturer = $manu
            Model        = $model
            OS           = $friendly
            OperatingSys = 'Windows'
            SkuFamily    = $sku
            Ownership    = 'On-premises (domain-joined)'
            JoinType     = 'On-prem AD'
            PrimaryUser  = ''
            LastCheckIn  = $lastSeen
            Source       = 'On-premises (AD)'
            IsServer     = $isSrv
        }
    }

    Write-Host ("AD computers found: {0} across {1} container(s); included: {2}; skipped (stale > {3} wks): {4}." -f `
        $adComputers.Count, $containerSeen.Keys.Count, @($onPremRows).Count, $CheckInWindowWeeks, $skippedStale) -ForegroundColor Green
    foreach ($k in ($containerSeen.Keys | Sort-Object)) {
        Write-Host ("    {0,3} in {1}" -f $containerSeen[$k], $k) -ForegroundColor DarkGray
    }
}

# --------------------------------------------------------------------------- #
#  Unified, de-duplicated asset list (hybrid-safe)                            #
# --------------------------------------------------------------------------- #
# Hybrid-joined devices appear in BOTH Intune and AD. De-duplicate by device
# name (case-insensitive); when a name exists in both, keep the cloud record
# (richer) but tag its source as "Both (Intune + AD)".
$cloudByName = @{}
foreach ($r in $rows) { if ($r.DeviceName) { $cloudByName[$r.DeviceName.ToLower()] = $r } }

$unified = New-Object System.Collections.Generic.List[object]
foreach ($r in $rows) { $unified.Add($r) }

$dupCount = 0
foreach ($o in $onPremRows) {
    $key = ([string]$o.DeviceName).ToLower()
    if ($key -and $cloudByName.ContainsKey($key)) {
        # Same physical machine in both worlds - mark and skip the AD copy.
        $cloudByName[$key].Source = 'Both (Intune + AD)'
        $dupCount++
    } else {
        $unified.Add($o)
    }
}
if ($IsHybrid) {
    Write-Host ("Unified asset list: {0} device(s) ({1} duplicate(s) merged)." -f $unified.Count, $dupCount) -ForegroundColor Green
}

# Split unified list: macOS, Windows workstations, Windows servers.
$macos      = @($unified | Where-Object { $_.OperatingSys -eq 'macOS' } | Sort-Object Manufacturer, OS, DeviceName)
$winAll     = @($unified | Where-Object { $_.OperatingSys -eq 'Windows' })
$servers    = @($winAll  | Where-Object { $_.IsServer } | Sort-Object Manufacturer, OS, DeviceName)
$windows    = @($winAll  | Where-Object { -not $_.IsServer } | Sort-Object Manufacturer, OS, DeviceName)

# Windows workstation summary (Manufacturer + OS + SKU).
$summary = $windows |
    Group-Object Manufacturer, OS, SkuFamily |
    ForEach-Object {
        $first = $_.Group[0]
        [pscustomobject]@{
            Count        = $_.Count
            Manufacturer = $first.Manufacturer
            OS           = $first.OS
            SkuFamily    = $first.SkuFamily
            Description  = "{0}x {1} {2} {3}" -f $_.Count, $first.Manufacturer, $first.OS, $first.SkuFamily
        }
    } | Sort-Object Manufacturer, OS, SkuFamily

# Server summary (total, manufacturer, OS, SKU e.g. "10x HP Windows Server 2019 Standard").
$serverSummary = $servers |
    Group-Object Manufacturer, OS, SkuFamily |
    ForEach-Object {
        $first = $_.Group[0]
        [pscustomobject]@{
            Count        = $_.Count
            Manufacturer = $first.Manufacturer
            OS           = $first.OS
            SkuFamily    = $first.SkuFamily
            Description  = "{0}x {1} {2} {3}" -f $_.Count, $first.Manufacturer, $first.OS, $first.SkuFamily
        }
    } | Sort-Object Manufacturer, OS, SkuFamily

# --------------------------------------------------------------------------- #
#  Device distribution analysis -> GPO vs Intune source of truth (hybrid)     #
# --------------------------------------------------------------------------- #
$cloudWorkstationCount  = @($windows | Where-Object { $_.Source -ne 'On-premises (AD)' }).Count
$onPremWorkstationCount = @($windows | Where-Object { $_.Source -eq 'On-premises (AD)' }).Count
$sourceOfTruth = 'Microsoft Intune'
$distributionVerdict = ''
if ($IsHybrid) {
    if ($onPremWorkstationCount -gt $cloudWorkstationCount) {
        $sourceOfTruth = 'Group Policy (GPO)'
        $distributionVerdict = ("More workstations are managed on-premises ({0}) than in the cloud ({1}). Group Policy (GPO) should be considered the primary source of truth for endpoint controls; Intune policies supplement cloud/hybrid-joined devices." -f $onPremWorkstationCount, $cloudWorkstationCount)
    } elseif ($cloudWorkstationCount -gt $onPremWorkstationCount) {
        $sourceOfTruth = 'Microsoft Intune'
        $distributionVerdict = ("More workstations are managed in the cloud ({0}) than on-premises ({1}). Microsoft Intune should be considered the primary source of truth for endpoint controls; GPO covers the remaining domain-only devices." -f $cloudWorkstationCount, $onPremWorkstationCount)
    } else {
        $sourceOfTruth = 'Mixed (GPO + Intune)'
        $distributionVerdict = ("Workstations are evenly split between cloud ({0}) and on-premises ({1}). Both GPO and Intune are in scope; confirm there is no conflicting/overlapping configuration between them." -f $cloudWorkstationCount, $onPremWorkstationCount)
    }
} else {
    $distributionVerdict = 'Cloud-only environment: Microsoft Intune is the source of truth for endpoint controls.'
}

# =========================================================================== #
#  2.1 Conditional Access policies (MFA + app protection enforcement)         #
# =========================================================================== #
Write-Host 'Reviewing Conditional Access policies for MFA enforcement...' -ForegroundColor Cyan
$caPolicies = @()
try {
    $caResp     = Get-GraphJson 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    $caPolicies = @($caResp.value)
} catch { Write-Warning "Could not read Conditional Access policies: $($_.Exception.Message)" }

$mfaPolicies = foreach ($p in $caPolicies) {
    $builtIn = @()
    if ($p.grantControls -and $p.grantControls.builtInControls) { $builtIn = @($p.grantControls.builtInControls) }
    $authStrength = $null
    if ($p.grantControls -and $p.grantControls.authenticationStrength) { $authStrength = $p.grantControls.authenticationStrength.displayName }
    if (($builtIn -contains 'mfa') -or $authStrength) { $p }
}
$mfaPolicies = @($mfaPolicies)
Write-Host ("Found {0} Conditional Access policy(ies); {1} enforce MFA." -f $caPolicies.Count, $mfaPolicies.Count) -ForegroundColor Green

$mfaFindings = foreach ($p in $mfaPolicies) {
    $apps  = $p.conditions.applications
    $users = $p.conditions.users
    $includeApps = @($apps.includeApplications | Where-Object { $_ })
    $excludeApps = @($apps.excludeApplications | Where-Object { $_ })
    $allApps     = ($includeApps -contains 'All')
    $includeUsers = @($users.includeUsers | Where-Object { $_ })
    $allUsers     = ($includeUsers -contains 'All')
    $exUsers  = @($users.excludeUsers  | Where-Object { $_ } | ForEach-Object { Resolve-DirObject $_ })
    $exGroups = @($users.excludeGroups | Where-Object { $_ } | ForEach-Object { Resolve-DirObject $_ })
    $exRoles  = @($users.excludeRoles  | Where-Object { $_ } | ForEach-Object { Resolve-DirObject $_ })
    $grant = @()
    if ($p.grantControls.builtInControls)        { $grant += $p.grantControls.builtInControls }
    if ($p.grantControls.authenticationStrength) { $grant += "Auth strength: $($p.grantControls.authenticationStrength.displayName)" }
    [ordered]@{
        'Policy name'               = $p.displayName
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
$mfaFindings = @($mfaFindings)

# =========================================================================== #
#  2.2 Software firewall (profiles, settings catalog, baselines/intents)      #
# =========================================================================== #
Write-Host 'Reviewing software firewall policies (Intune)...' -ForegroundColor Cyan
$fwFindings = @()

# 1) Endpoint Protection device-configuration profiles (classic firewall).
Write-Host '  [1/3] Endpoint Protection profiles...' -ForegroundColor DarkGray
try {
    $epUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
    do {
        $epResp = Get-GraphJson $epUri
        foreach ($p in @($epResp.value)) {
            if ($p.'@odata.type' -ne '#microsoft.graph.windows10EndpointProtectionConfiguration') { continue }
            $dom = Convert-FwState $p.firewallProfileDomain.firewallEnabled
            $prv = Convert-FwState $p.firewallProfilePrivate.firewallEnabled
            $pub = Convert-FwState $p.firewallProfilePublic.firewallEnabled
            if ($dom -eq 'Not configured' -and $prv -eq 'Not configured' -and $pub -eq 'Not configured') { continue }
            $asg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($p.id)/assignments")
            $fwFindings += [pscustomobject]@{
                Source = 'Endpoint Protection profile'; PolicyName = $p.displayName; Platform = 'Windows'
                FirewallSetting = "Domain: $dom; Private: $prv; Public: $pub"
                Included = $asg.Included; Excluded = $asg.Excluded
            }
        }
        $epUri = $epResp.'@odata.nextLink'
    } while ($epUri)
} catch { Write-Warning "Could not read Endpoint Protection profiles: $($_.Exception.Message)" }

# 2) Settings catalog configuration policies.
Write-Host '  [2/3] Settings catalog policies...' -ForegroundColor DarkGray
try {
    $scUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
    do {
        $scResp = Get-GraphJson $scUri
        foreach ($p in @($scResp.value)) {
            $sJson = ''
            try { $sJson = Invoke-MgGraphRequest -Method GET -OutputType Json `
                            -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($p.id)/settings" } catch { }
            $hay = "$sJson $($p.name)"
            if ($hay -notmatch '(?i)firewall') { continue }
            $state = if     ($hay -match '(?i)enablefirewall_true' -or $hay -match '(?i)enablefirewall_1') { 'Enabled' }
                     elseif ($hay -match '(?i)enablefirewall_false' -or $hay -match '(?i)enablefirewall_0') { 'Disabled' }
                     else   { 'Configured (review policy)' }
            $asg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($p.id)/assignments")
            $fwFindings += [pscustomobject]@{
                Source = 'Settings catalog policy'; PolicyName = $p.name; Platform = "$($p.platforms)"
                FirewallSetting = "Firewall: $state"; Included = $asg.Included; Excluded = $asg.Excluded
            }
        }
        $scUri = $scResp.'@odata.nextLink'
    } while ($scUri)
} catch { Write-Warning "Could not read Settings catalog policies: $($_.Exception.Message)" }

# 3) Firewall intents AND security baselines (inspect each intent's settings).
Write-Host '  [3/3] Firewall intents & security baselines...' -ForegroundColor DarkGray
try {
    $templateCache = @{}
    $intResp = Get-GraphJson 'https://graph.microsoft.com/beta/deviceManagement/intents'
    foreach ($p in @($intResp.value)) {
        $defMap  = Get-TemplateDefMap ([string]$p.templateId)
        $catSets = Get-IntentCategorySettings ([string]$p.id)
        if (@($catSets).Count -eq 0) { continue }
        $bits = @(); $sawFw = $false
        foreach ($cs in @($catSets)) {
            $s    = $cs.Setting
            $did  = [string]$s.definitionId
            $name = [string]$defMap[$did]
            $hay  = "$($cs.Category) $did $name"
            if ($hay -notmatch '(?i)firewall') { continue }
            $sawFw = $true
            $valStr = Get-IntentSettingValue $s
            if (($hay -match '(?i)enable') -or ($valStr -match '(?i)allowed|true|enabled')) {
                $label = if ($name) { $name } elseif ($cs.Category) { "$($cs.Category) / $(($did -split '[_]') | Select-Object -Last 1)" } else { ($did -split '[_]') | Select-Object -Last 1 }
                $bits += ("{0} = {1}" -f $label, $valStr)
            }
        }
        if (-not $sawFw) { continue }
        $tid = [string]$p.templateId; $tName = $null
        if ($tid) {
            if (-not $templateCache.ContainsKey($tid)) {
                try { $tpl = Get-GraphJson "https://graph.microsoft.com/beta/deviceManagement/templates/$tid"; $templateCache[$tid] = $tpl.displayName }
                catch { $templateCache[$tid] = $null }
            }
            $tName = $templateCache[$tid]
        }
        $src     = if ($tName -match '(?i)firewall') { 'Endpoint security firewall (intent)' } else { 'Security baseline (intent)' }
        $setting = if ($bits.Count) { $bits -join '; ' } else { 'Firewall settings present (review policy)' }
        $asg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/intents/$($p.id)/assignments")
        $fwFindings += [pscustomobject]@{
            Source = $src; PolicyName = $p.displayName; Platform = 'Windows'
            FirewallSetting = $setting; Included = $asg.Included; Excluded = $asg.Excluded
        }
    }
} catch { Write-Warning "Could not read firewall / baseline intents: $($_.Exception.Message)" }

$fwFindings = @($fwFindings)
Write-Host ("Found {0} firewall-related policy/setting(s)." -f $fwFindings.Count) -ForegroundColor Green

# =========================================================================== #
#  2.3 Mobile devices & app protection (MAM)                                  #
# =========================================================================== #
Write-Host 'Reviewing mobile devices and app protection policies...' -ForegroundColor Cyan

# Extract scalar settings from an app protection policy, skipping metadata.
function Get-AppPolicySettings {
    param($Policy)
    $skip = @('id','displayName','description','createdDateTime','lastModifiedDateTime',
              'version','roleScopeTagIds','isAssigned','deployedAppCount','assignments',
              'apps','@odata.type','@odata.context')
    $d = [ordered]@{}
    foreach ($pr in $Policy.PSObject.Properties) {
        $n = $pr.Name
        if ($skip -contains $n) { continue }
        $v = $pr.Value
        if ($null -eq $v) { continue }
        if ($v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double]) { $d[$n] = "$v"; continue }
        if ($v -is [string]) { if (-not [string]::IsNullOrWhiteSpace($v)) { $d[$n] = $v }; continue }
        if ($v -is [System.Collections.IEnumerable]) {
            $parts = @()
            foreach ($i in $v) { if ($i -is [string] -or $i -is [valuetype]) { $parts += "$i" } }
            if ($parts.Count) { $d[$n] = ($parts -join ', ') }
            continue
        }
    }
    return $d
}

$mobileSelect = (@('deviceName','manufacturer','model','operatingSystem','osVersion',
                   'managedDeviceOwnerType','userPrincipalName','lastSyncDateTime') -join ',')
$mobFilter = "operatingSystem eq 'Android' or operatingSystem eq 'iOS' or operatingSystem eq 'iPadOS'"
$mobUri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$filter={0}&$select={1}&$top=200' -f `
            [uri]::EscapeDataString($mobFilter), [uri]::EscapeDataString($mobileSelect)

$mobileDevices = @()
try {
    do {
        $mr = Get-GraphJson $mobUri
        $mobileDevices += @($mr.value)
        $mobUri = $mr.'@odata.nextLink'
    } while ($mobUri)
} catch { Write-Warning "Could not read mobile devices: $($_.Exception.Message)" }

$mobileRows = foreach ($d in $mobileDevices) {
    $os    = [string]$d.operatingSystem
    $major = ([string]$d.osVersion -split '\.')[0]
    [pscustomobject]@{
        DeviceName  = $d.deviceName
        Make        = $(if ($d.manufacturer) { $d.manufacturer } else { 'Unknown' })
        Model       = $d.model
        OS          = ("{0} {1}" -f $os, $major).Trim()
        Ownership   = $d.managedDeviceOwnerType
        PrimaryUser = $d.userPrincipalName
        LastCheckIn = $d.lastSyncDateTime
    }
}
$mobileRows = @($mobileRows | Sort-Object Make, OS, DeviceName)

$mobileSummary = @($mobileRows | Group-Object Make, OS | ForEach-Object {
    $f = $_.Group[0]
    [pscustomobject]@{
        Count = $_.Count; Make = $f.Make; OS = $f.OS
        Description = "{0}x {1} {2}" -f $_.Count, $f.Make, $f.OS
    }
} | Sort-Object Make, OS)
Write-Host ("Found {0} mobile device(s)." -f $mobileRows.Count) -ForegroundColor Green

$appPolicies = @()
foreach ($plat in @(
    @{ Name = 'iOS';     Uri = 'https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections?$expand=assignments' },
    @{ Name = 'Android'; Uri = 'https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections?$expand=assignments' }
)) {
    try {
        $u = $plat.Uri
        do {
            $r = Get-GraphJson $u
            foreach ($p in @($r.value)) {
                $asg = Get-AssignmentSummary $p.assignments
                $appPolicies += [pscustomobject]@{
                    Platform = $plat.Name; Name = $p.displayName
                    Included = $asg.Included; Excluded = $asg.Excluded
                    Settings = (Get-AppPolicySettings $p)
                }
            }
            $u = $r.'@odata.nextLink'
        } while ($u)
    } catch { Write-Warning "Could not read $($plat.Name) app protection policies: $($_.Exception.Message)" }
}
$appPolicies = @($appPolicies)

$caAppEnforce = @()
foreach ($p in @($caPolicies)) {
    $bic = @()
    if ($p.grantControls -and $p.grantControls.builtInControls) { $bic = @($p.grantControls.builtInControls) }
    if ($bic -contains 'compliantApplication') {
        $caAppEnforce += [pscustomobject]@{ Name = $p.displayName; State = $p.state }
    }
}
$caAppEnforce = @($caAppEnforce)

$fallback = @()
try {
    $cpUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?$expand=assignments'
    do {
        $r = Get-GraphJson $cpUri
        foreach ($p in @($r.value)) {
            $t = [string]$p.'@odata.type'
            if ($t -match '(?i)android' -or $t -match '(?i)ios') {
                $asg  = Get-AssignmentSummary $p.assignments
                $plat = if ($t -match '(?i)android') { 'Android' } elseif ($t -match '(?i)ios') { 'iOS' } else { 'Mobile' }
                $fallback += [pscustomobject]@{
                    Name = $p.displayName; Platform = $plat; Type = 'Compliance policy'
                    Included = $asg.Included; Excluded = $asg.Excluded
                }
            }
        }
        $cpUri = $r.'@odata.nextLink'
    } while ($cpUri)
} catch { Write-Warning "Could not read compliance policies: $($_.Exception.Message)" }
$fallback = @($fallback)
Write-Host ("App protection policies: {0}; CA enforcing app protection: {1}; mobile compliance policies: {2}." -f `
    $appPolicies.Count, $caAppEnforce.Count, $fallback.Count) -ForegroundColor Green

# =========================================================================== #
#  2.4 AutoPlay / AutoRun                                                      #
# =========================================================================== #
Write-Host 'Reviewing AutoPlay / AutoRun policies...' -ForegroundColor Cyan

# Recursively walk a settings-catalog settings collection for autoplay/autorun.
function Get-AutoplaySettingsFromCatalog {
    param($SettingsArray)
    $found = @()
    $stack = New-Object System.Collections.Stack
    foreach ($s in @($SettingsArray)) { $stack.Push($s) }
    while ($stack.Count -gt 0) {
        $n = $stack.Pop()
        if ($null -eq $n) { continue }
        $defId = $null
        try { $defId = $n.settingDefinitionId } catch { }
        if ($defId -and ("$defId" -match '(?i)autoplay|autorun')) {
            $val = $null
            if ($n.choiceSettingValue) { $val = $n.choiceSettingValue.value }
            elseif ($n.simpleSettingValue) { $val = $n.simpleSettingValue.value }
            $found += [pscustomobject]@{ Id = "$defId"; Value = "$val" }
        }
        foreach ($prop in @('settingInstance','choiceSettingValue','simpleSettingValue')) {
            try { if ($n.$prop) { $stack.Push($n.$prop) } } catch { }
        }
        foreach ($prop in @('children','value','groupSettingCollectionValue')) {
            try {
                $c = $n.$prop
                if (($c -is [System.Collections.IEnumerable]) -and -not ($c -is [string])) {
                    foreach ($i in $c) { $stack.Push($i) }
                }
            } catch { }
        }
    }
    return $found
}

$autoFindings = @()

# 1) Settings catalog policies.
Write-Host '  [1/4] Settings catalog policies...' -ForegroundColor DarkGray
try {
    $scUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
    do {
        $sc = Get-GraphJson $scUri
        foreach ($p in @($sc.value)) {
            $settingsObj = $null
            try { $settingsObj = Get-GraphJson "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($p.id)/settings" } catch { }
            $hits = @()
            if ($settingsObj) { $hits = @(Get-AutoplaySettingsFromCatalog $settingsObj.value) }
            if ($hits.Count -eq 0) { continue }
            $asg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($p.id)/assignments")
            foreach ($h in $hits) {
                $set   = ("$($h.Id)" -split '_config_')[-1]
                $state = if     ("$($h.Value)" -match '(?i)_1$|_true$|donotexecute|donotplay|enabled') { 'Enabled (disables AutoPlay/AutoRun)' }
                         elseif ("$($h.Value)" -match '(?i)_0$|_false$') { 'Not enforced' }
                         else   { "$($h.Value)" }
                $autoFindings += [pscustomobject]@{
                    Source = 'Settings catalog'; PolicyName = $p.name; Setting = $set
                    State = $state; Included = $asg.Included; Excluded = $asg.Excluded
                }
            }
        }
        $scUri = $sc.'@odata.nextLink'
    } while ($scUri)
} catch { Write-Warning "Could not read Settings catalog policies: $($_.Exception.Message)" }

# 2) Administrative templates (group policy configurations).
Write-Host '  [2/4] Administrative templates...' -ForegroundColor DarkGray
try {
    $gpUri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
    do {
        $g = Get-GraphJson $gpUri
        foreach ($cfg in @($g.value)) {
            $dv = $null
            try { $dv = Get-GraphJson "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($cfg.id)/definitionValues?`$expand=definition" } catch { }
            $cfgAsg = $null
            foreach ($d in @($dv.value)) {
                $name = [string]$d.definition.displayName
                if ($name -notmatch '(?i)autoplay|autorun') { continue }
                if ($null -eq $cfgAsg) {
                    $cfgAsg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($cfg.id)/assignments")
                }
                $autoFindings += [pscustomobject]@{
                    Source = 'Administrative template'; PolicyName = $cfg.displayName; Setting = $name
                    State = $(if ($d.enabled) { 'Enabled' } else { 'Disabled / Not configured' })
                    Included = $cfgAsg.Included; Excluded = $cfgAsg.Excluded
                }
            }
        }
        $gpUri = $g.'@odata.nextLink'
    } while ($gpUri)
} catch { Write-Warning "Could not read Administrative templates: $($_.Exception.Message)" }

# 3) Custom OMA-URI device configuration profiles.
Write-Host '  [3/4] Custom OMA-URI profiles...' -ForegroundColor DarkGray
try {
    $dcUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
    do {
        $dc = Get-GraphJson $dcUri
        foreach ($p in @($dc.value)) {
            if ([string]$p.'@odata.type' -notmatch '(?i)customConfiguration') { continue }
            $dcAsg = $null
            foreach ($oma in @($p.omaSettings)) {
                $omaUri = [string]$oma.omaUri
                if ($omaUri -notmatch '(?i)autoplay|autorun') { continue }
                if ($null -eq $dcAsg) {
                    $dcAsg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($p.id)/assignments")
                }
                $autoFindings += [pscustomobject]@{
                    Source = 'Custom OMA-URI'; PolicyName = $p.displayName
                    Setting = ("{0} [{1}]" -f $oma.displayName, $omaUri)
                    State = "$($oma.value)"; Included = $dcAsg.Included; Excluded = $dcAsg.Excluded
                }
            }
        }
        $dcUri = $dc.'@odata.nextLink'
    } while ($dcUri)
} catch { Write-Warning "Could not read custom OMA-URI profiles: $($_.Exception.Message)" }

# 4) Security baselines / endpoint security intents.
Write-Host '  [4/4] Security baselines (intents)...' -ForegroundColor DarkGray
try {
    $intResp = Get-GraphJson 'https://graph.microsoft.com/beta/deviceManagement/intents'
    foreach ($p in @($intResp.value)) {
        $defMap  = Get-TemplateDefMap ([string]$p.templateId)
        $catSets = Get-IntentCategorySettings ([string]$p.id)
        if (@($catSets).Count -eq 0) { continue }
        $iAsg = $null
        foreach ($cs in @($catSets)) {
            $s    = $cs.Setting
            $did  = [string]$s.definitionId
            $name = [string]$defMap[$did]
            $hay  = "$($cs.Category) $did $name"
            if ($hay -notmatch '(?i)autoplay|autorun') { continue }
            if ($null -eq $iAsg) {
                $iAsg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/intents/$($p.id)/assignments")
            }
            $label = if ($name) { $name } elseif ($cs.Category) { "$($cs.Category) / $(($did -split '[_]') | Select-Object -Last 1)" } else { ($did -split '[_]') | Select-Object -Last 1 }
            $autoFindings += [pscustomobject]@{
                Source = 'Security baseline (intent)'; PolicyName = $p.displayName; Setting = $label
                State = (Get-IntentSettingValue $s); Included = $iAsg.Included; Excluded = $iAsg.Excluded
            }
        }
    }
} catch { Write-Warning "Could not read security baseline intents: $($_.Exception.Message)" }

$autoFindings = @($autoFindings)
Write-Host ("Found {0} AutoPlay/AutoRun-related setting(s)." -f $autoFindings.Count) -ForegroundColor Green

# Optional diagnostics: dump every intent's categories/settings/resolved names.
if ($DiagnoseBaselines) {
    try {
        $diagDir  = Split-Path -Parent ([System.IO.Path]::GetFullPath($OutputPath))
        $diagPath = Join-Path $diagDir 'baseline-diagnostics.txt'
        $lines = New-Object System.Collections.Generic.List[string]
        $intD = Get-GraphJson 'https://graph.microsoft.com/beta/deviceManagement/intents'
        foreach ($p in @($intD.value)) {
            $dm = Get-TemplateDefMap ([string]$p.templateId)
            $cs = Get-IntentCategorySettings ([string]$p.id)
            $lines.Add(("INTENT: {0} | templateId={1} | catSettings={2} | defMap={3}" -f $p.displayName, $p.templateId, @($cs).Count, $dm.Count))
            foreach ($x in @($cs)) {
                $did = [string]$x.Setting.definitionId
                $nm  = [string]$dm[$did]
                $vv  = Get-IntentSettingValue $x.Setting
                $lines.Add(("   [{0}] {1} | {2} | {3}" -f $x.Category, $did, $nm, $vv))
            }
            $lines.Add('')
        }
        Set-Content -Path $diagPath -Value $lines -Encoding UTF8
        Write-Host ("Baseline diagnostics written to: {0}" -f $diagPath) -ForegroundColor Yellow
    } catch { Write-Warning "Diagnostics failed: $($_.Exception.Message)" }
}

# =========================================================================== #
#  2.5 Account review & suspected shared accounts                             #
# =========================================================================== #
Write-Host 'Reviewing accounts and licenses (suspected shared accounts)...' -ForegroundColor Cyan

$skuMap = @{}
try {
    $skus = Get-GraphJson 'https://graph.microsoft.com/v1.0/subscribedSkus'
    foreach ($s in @($skus.value)) { $skuMap[[string]$s.skuId] = [string]$s.skuPartNumber }
} catch { Write-Warning "Could not read subscribed SKUs: $($_.Exception.Message)" }

$sharedKeywords = @(
    'shared','admin','administrator','service','svc','info','support','help',
    'helpdesk','sales','marketing','team','group','noreply','no-reply','donotreply',
    'do-not-reply','mailbox','account','accounts','billing','finance','reception',
    'enquir','contact','general','itsupport','sysadmin','printer','scanner','kiosk',
    'reservation','booking','room','test','demo','training','common'
)

$allUsers = @()
$usrUri = 'https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName,givenName,surname,mail,accountEnabled,assignedLicenses,createdDateTime,userType&$top=999'
try {
    do {
        $r = Get-GraphJson $usrUri
        $allUsers += @($r.value)
        $usrUri = $r.'@odata.nextLink'
    } while ($usrUri)
} catch { Write-Warning "Could not read users: $($_.Exception.Message)" }

$sharedAccounts = @()
foreach ($u in @($allUsers)) {
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
Write-Host ("Reviewed {0} account(s); {1} flagged as suspected shared." -f @($allUsers).Count, $sharedAccounts.Count) -ForegroundColor Green

# =========================================================================== #
#  2.6 Application whitelisting (AppLocker / App Control for Business / WDAC)  #
# =========================================================================== #
Write-Host 'Reviewing application whitelisting policies...' -ForegroundColor Cyan

# Keyword pattern that indicates an application-control / whitelisting setting.
$awPattern = '(?i)applocker|appcontrol|app control|wdac|windowsdefenderapplicationcontrol|application control|codeintegrity|smartappcontrol|applicationcontrol'

$awFindings = @()

# 1) Endpoint Protection profiles (classic) - appLockerApplicationControl.
Write-Host '  [1/4] Endpoint Protection profiles...' -ForegroundColor DarkGray
try {
    $epUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
    do {
        $epResp = Get-GraphJson $epUri
        foreach ($p in @($epResp.value)) {
            if ($p.'@odata.type' -ne '#microsoft.graph.windows10EndpointProtectionConfiguration') { continue }
            $alc = [string]$p.appLockerApplicationControl
            if ([string]::IsNullOrWhiteSpace($alc) -or $alc -eq 'notConfigured') { continue }
            $asg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($p.id)/assignments")
            $awFindings += [pscustomobject]@{
                Source = 'Endpoint Protection profile'; PolicyName = $p.displayName
                Mechanism = 'AppLocker'; Setting = "appLockerApplicationControl = $alc"
                Included = $asg.Included; Excluded = $asg.Excluded
            }
        }
        $epUri = $epResp.'@odata.nextLink'
    } while ($epUri)
} catch { Write-Warning "Could not read Endpoint Protection profiles: $($_.Exception.Message)" }

# 2) Settings catalog policies (App Control for Business / AppLocker / WDAC).
Write-Host '  [2/4] Settings catalog policies...' -ForegroundColor DarkGray
try {
    $scUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
    do {
        $scResp = Get-GraphJson $scUri
        foreach ($p in @($scResp.value)) {
            $sJson = ''
            try { $sJson = Invoke-MgGraphRequest -Method GET -OutputType Json `
                            -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($p.id)/settings" } catch { }
            $hay = "$sJson $($p.name)"
            if ($hay -notmatch $awPattern) { continue }
            $mech = if     ($hay -match '(?i)applocker') { 'AppLocker' }
                    elseif ($hay -match '(?i)appcontrol|app control|wdac|applicationcontrol|codeintegrity') { 'App Control for Business / WDAC' }
                    elseif ($hay -match '(?i)smartappcontrol') { 'Smart App Control' }
                    else   { 'Application control' }
            $asg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($p.id)/assignments")
            $awFindings += [pscustomobject]@{
                Source = 'Settings catalog policy'; PolicyName = $p.name
                Mechanism = $mech; Setting = 'Application-control settings present (review policy)'
                Included = $asg.Included; Excluded = $asg.Excluded
            }
        }
        $scUri = $scResp.'@odata.nextLink'
    } while ($scUri)
} catch { Write-Warning "Could not read Settings catalog policies: $($_.Exception.Message)" }

# 3) Endpoint security / baseline intents (template name or settings).
Write-Host '  [3/4] Endpoint security intents & baselines...' -ForegroundColor DarkGray
try {
    $awTemplateCache = @{}
    $intResp = Get-GraphJson 'https://graph.microsoft.com/beta/deviceManagement/intents'
    foreach ($p in @($intResp.value)) {
        $tid = [string]$p.templateId; $tName = $null
        if ($tid) {
            if (-not $awTemplateCache.ContainsKey($tid)) {
                try { $tpl = Get-GraphJson "https://graph.microsoft.com/beta/deviceManagement/templates/$tid"; $awTemplateCache[$tid] = $tpl.displayName }
                catch { $awTemplateCache[$tid] = $null }
            }
            $tName = $awTemplateCache[$tid]
        }
        $defMap  = Get-TemplateDefMap $tid
        $catSets = Get-IntentCategorySettings ([string]$p.id)
        $matched = $false; $label = $null
        if ("$tName $($p.displayName)" -match $awPattern) { $matched = $true; $label = $tName }
        foreach ($cs in @($catSets)) {
            $did  = [string]$cs.Setting.definitionId
            $name = [string]$defMap[$did]
            if ("$($cs.Category) $did $name" -match $awPattern) { $matched = $true; if (-not $label) { $label = if ($name) { $name } else { $cs.Category } } }
        }
        if (-not $matched) { continue }
        $mech = if     ("$tName $label" -match '(?i)applocker') { 'AppLocker' }
                elseif ("$tName $label" -match '(?i)appcontrol|app control|wdac|applicationcontrol|codeintegrity') { 'App Control for Business / WDAC' }
                else   { 'Application control' }
        $asg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/intents/$($p.id)/assignments")
        $awFindings += [pscustomobject]@{
            Source = $(if ($tName -match '(?i)baseline') { 'Security baseline (intent)' } else { 'Endpoint security (intent)' })
            PolicyName = $p.displayName; Mechanism = $mech
            Setting = $(if ($label) { "Template/setting: $label" } else { 'Application-control template' })
            Included = $asg.Included; Excluded = $asg.Excluded
        }
    }
} catch { Write-Warning "Could not read endpoint security intents: $($_.Exception.Message)" }

# 4) Custom OMA-URI profiles referencing AppLocker / WDAC CSPs.
Write-Host '  [4/4] Custom OMA-URI profiles...' -ForegroundColor DarkGray
try {
    $dcUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
    do {
        $dc = Get-GraphJson $dcUri
        foreach ($p in @($dc.value)) {
            if ([string]$p.'@odata.type' -notmatch '(?i)customConfiguration') { continue }
            $dcAsg = $null
            foreach ($oma in @($p.omaSettings)) {
                $omaUri = [string]$oma.omaUri
                if ($omaUri -notmatch $awPattern) { continue }
                if ($null -eq $dcAsg) {
                    $dcAsg = Get-AssignmentSummary (Get-PolicyAssignments "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($p.id)/assignments")
                }
                $mech = if ($omaUri -match '(?i)applocker') { 'AppLocker' } else { 'App Control for Business / WDAC' }
                $awFindings += [pscustomobject]@{
                    Source = 'Custom OMA-URI'; PolicyName = $p.displayName; Mechanism = $mech
                    Setting = $omaUri; Included = $dcAsg.Included; Excluded = $dcAsg.Excluded
                }
            }
        }
        $dcUri = $dc.'@odata.nextLink'
    } while ($dcUri)
} catch { Write-Warning "Could not read custom OMA-URI profiles: $($_.Exception.Message)" }

$awFindings = @($awFindings)
Write-Host ("Found {0} application-whitelisting policy/setting(s)." -f $awFindings.Count) -ForegroundColor Green

# =========================================================================== #
#  2.7 Password protection (security defaults + banned password list)         #
# =========================================================================== #
Write-Host 'Reviewing password protection (security defaults & banned password list)...' -ForegroundColor Cyan

# Security defaults status.
$securityDefaultsOn = $false
try {
    $sd = Get-GraphJson 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    $securityDefaultsOn = [bool]$sd.isEnabled
} catch { Write-Warning "Could not read security defaults policy: $($_.Exception.Message)" }

# Custom banned password list lives in the directory "Password Rule Settings".
$bannedListEnabled = $false
$bannedListMode    = 'Not configured'
$bannedWordCount   = 0
$lockoutThreshold  = $null
$lockoutDuration   = $null
try {
    $dirSettings = Get-GraphJson 'https://graph.microsoft.com/beta/settings'
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
                'EnableBannedPasswordCheck'           { if ($v.value -match '(?i)true') { $bannedListEnabled = $true } }
                'BannedPasswordCheckOnPremisesMode'   { $bannedListMode = [string]$v.value }
                'LockoutThreshold'                    { $lockoutThreshold = [string]$v.value }
                'LockoutDurationInSeconds'            { $lockoutDuration = [string]$v.value }
            }
        }
    }
} catch { Write-Warning "Could not read password rule settings: $($_.Exception.Message)" }

# A custom banned list is "in place" if the check is enabled with >0 custom words.
$customBannedInPlace = ($bannedListEnabled -and $bannedWordCount -gt 0)

# Build the verdict statement requested for the report.
if ($customBannedInPlace) {
    $pwdVerdict = 'Microsoft security defaults are in place, IN CONJUNCTION WITH a custom banned list of common passwords. This satisfies the Cyber Essentials requirement for a common-password deny list.'
} else {
    $pwdVerdict = 'Microsoft security defaults are in place, BUT a custom banned list of common passwords is NOT configured. A banned list of common passwords is REQUIRED to fulfil the Cyber Essentials requirement.'
}
if (-not $securityDefaultsOn) {
    $pwdVerdict = 'NOTE: Microsoft security defaults are NOT enabled in this tenant. ' + $pwdVerdict
}

$pwdFindings = [ordered]@{
    'Microsoft security defaults enabled' = $(if ($securityDefaultsOn) { 'Yes' } else { 'No' })
    'Custom banned password list enabled' = $(if ($bannedListEnabled) { 'Yes' } else { 'No' })
    'Custom banned words configured'      = "$bannedWordCount"
    'On-premises enforcement mode'        = $bannedListMode
    'Lockout threshold'                   = $(if ($null -ne $lockoutThreshold) { $lockoutThreshold } else { 'Default (10)' })
    'Lockout duration (seconds)'          = $(if ($null -ne $lockoutDuration)  { $lockoutDuration }  else { 'Default (60)' })
}

Write-Host ("Security defaults: {0}; custom banned list: {1} ({2} words)." -f `
    $(if ($securityDefaultsOn) { 'On' } else { 'Off' }),
    $(if ($customBannedInPlace) { 'In place' } else { 'Not in place' }),
    $bannedWordCount) -ForegroundColor Green

# =========================================================================== #
#  2.8 Group Policy review (hybrid only)                                      #
# =========================================================================== #
# Parses every GPO's report XML and searches for the same controls covered by
# the cloud tabs: firewall, AutoPlay/AutoRun, application whitelisting, and
# password / account-lockout policy. Findings feed the GPO review tab and the
# per-control source-of-truth recommendations.
$gpoFindings   = @()   # @{ Control; GPO; Setting; Value; LinkedOUs }
$gpoReviewed   = 0
$gpoControlPatterns = [ordered]@{
    'Firewall'                = '(?i)firewall|MpsSvc|WindowsFirewall'
    'AutoPlay/AutoRun'        = '(?i)autoplay|autorun|NoDriveTypeAutoRun|NoAutorun'
    'Application whitelisting'= '(?i)applocker|app control|wdac|codeintegrity|SrpV2|software restriction'
    'Password / lockout'      = '(?i)password|lockout|PasswordComplexity|MinimumPasswordLength|account lockout'
}

if ($IsHybrid -and $AdAvailable) {
    Write-Host 'Reviewing Group Policy Objects for relevant controls...' -ForegroundColor Cyan
    try {
        $allGpos = Get-GPO @adParams -All -ErrorAction Stop
    } catch {
        Write-Warning "Could not enumerate GPOs: $($_.Exception.Message)"
        $allGpos = @()
    }

    # Map GPO GUID -> linked OU paths (from a domain-wide GP inheritance is
    # heavy; instead read each GPO's <LinksTo> from its own report).
    foreach ($g in @($allGpos)) {
        $gpoReviewed++
        $xml = $null
        try {
            [xml]$xml = Get-GPOReport @adParams -Guid $g.Id -ReportType Xml -ErrorAction Stop
        } catch {
            Write-Verbose "GPO report failed for $($g.DisplayName): $($_.Exception.Message)"
            continue
        }
        $reportText = $xml.OuterXml
        $linksTo = @()
        try { $linksTo = @($xml.GPO.LinksTo.SOMPath | Where-Object { $_ }) } catch { }
        $linkStr = if ($linksTo.Count) { ($linksTo | Sort-Object -Unique) -join '; ' } else { 'Not linked' }

        foreach ($ctrl in $gpoControlPatterns.Keys) {
            if ($reportText -match $gpoControlPatterns[$ctrl]) {
                $gpoFindings += [pscustomobject]@{
                    Control   = $ctrl
                    GPO       = $g.DisplayName
                    Status    = [string]$g.GpoStatus
                    LinkedOUs = $linkStr
                }
            }
        }
    }
    Write-Host ("Reviewed {0} GPO(s); {1} control-relevant finding(s)." -f $gpoReviewed, @($gpoFindings).Count) -ForegroundColor Green
}
$gpoFindings = @($gpoFindings)

# --------------------------------------------------------------------------- #
#  Fold on-prem GPO findings into the existing control tabs                   #
#  (keeps the tab set identical to a cloud-only run; on-prem results appear   #
#   as additional rows tagged "On-prem GPO" in the matching control tab).     #
# --------------------------------------------------------------------------- #
if ($IsHybrid -and $AdAvailable) {
    foreach ($gf in $gpoFindings) {
        $inc = $gf.LinkedOUs
        switch ($gf.Control) {
            'Firewall' {
                $fwFindings += [pscustomobject]@{
                    Source = 'On-prem GPO'; PolicyName = $gf.GPO; Platform = 'Windows (domain)'
                    FirewallSetting = "Configured via GPO (status: $($gf.Status))"
                    Included = $inc; Excluded = 'N/A (GPO link scope)'
                }
            }
            'AutoPlay/AutoRun' {
                $autoFindings += [pscustomobject]@{
                    Source = 'On-prem GPO'; PolicyName = $gf.GPO; Setting = 'AutoPlay/AutoRun policy (see GPO)'
                    State = "Configured via GPO (status: $($gf.Status))"
                    Included = $inc; Excluded = 'N/A (GPO link scope)'
                }
            }
            'Application whitelisting' {
                $awFindings += [pscustomobject]@{
                    Source = 'On-prem GPO'; PolicyName = $gf.GPO
                    Mechanism = 'AppLocker / SRP / WDAC (GPO)'; Setting = "Configured via GPO (status: $($gf.Status))"
                    Included = $inc; Excluded = 'N/A (GPO link scope)'
                }
            }
        }
    }
    # Re-cast so the worksheet writers see arrays.
    $fwFindings   = @($fwFindings)
    $autoFindings = @($autoFindings)
    $awFindings   = @($awFindings)

    # Password / lockout GPOs are appended to the Password tab's detail block.
    $pwGpo = @($gpoFindings | Where-Object { $_.Control -eq 'Password / lockout' })
    if ($pwGpo.Count) {
        $pwdFindings['On-prem password/lockout GPO(s)'] = (($pwGpo | ForEach-Object { "$($_.GPO) [$($_.LinkedOUs)]" }) -join '; ')
    }
}

# =========================================================================== #
#  3. Write the Excel workbook via the ImportExcel module (EPPlus / no Office)#
# =========================================================================== #
# The script may run on a server (e.g. a domain controller) with no Microsoft
# Excel installed, so we do NOT use the Excel COM object. ImportExcel ships the
# EPPlus engine and writes native .xlsx files with no Office dependency.
Write-Host 'Building Excel workbook (ImportExcel / EPPlus)...' -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host ("ImportExcel module not found - installing v{0} from PSGallery..." -f $ImportExcelVersion) -ForegroundColor Yellow
    $prevPolicy = $null
    try { $prevPolicy = (Get-PSRepository -Name PSGallery -ErrorAction Stop).InstallationPolicy } catch { }
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
        Install-Module ImportExcel -RequiredVersion $ImportExcelVersion -Repository PSGallery `
            -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    } catch {
        throw "ImportExcel module is required but could not be installed automatically: $($_.Exception.Message). On an internet-connected machine run: Save-Module ImportExcel -RequiredVersion $ImportExcelVersion -Path C:\Temp ; then copy the folder to this server's module path."
    } finally {
        if ($prevPolicy -and $prevPolicy -ne 'Trusted') {
            try { Set-PSRepository -Name PSGallery -InstallationPolicy $prevPolicy -ErrorAction Stop } catch { }
        }
    }
}
try { Import-Module ImportExcel -RequiredVersion $ImportExcelVersion -ErrorAction Stop }
catch { Import-Module ImportExcel -ErrorAction Stop }
Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

# Colours as System.Drawing.Color (EPPlus uses RGB, not COM's BGR ints).
$headerFill  = [System.Drawing.Color]::FromArgb(68, 84, 106)    # dark blue-grey
$sectionFill = [System.Drawing.Color]::FromArgb(189, 215, 238)  # light blue
$whiteFont   = [System.Drawing.Color]::White
$redFont     = [System.Drawing.Color]::Red
$greenFont   = [System.Drawing.Color]::FromArgb(0, 128, 0)
$solid       = [OfficeOpenXml.Style.ExcelFillStyle]::Solid

$pkg = $null
try {
    $fullPath = [System.IO.Path]::GetFullPath($OutputPath)
    if (Test-Path $fullPath) { Remove-Item $fullPath -Force -ErrorAction SilentlyContinue }
    $pkg = New-Object OfficeOpenXml.ExcelPackage ([System.IO.FileInfo]$fullPath)

    # ----- Address helpers ------------------------------------------------ #
    # ExcelRange is enumerable, so PowerShell treats $ws.Cells[$r,$c] as array
    # slicing (returns an array) instead of EPPlus's [int,int] indexer, which
    # breaks ".Value =". Addressing cells by string ("A1") is unambiguous and
    # always hits the .NET string indexer, returning a single ExcelRange.
    function Get-ColLetter {
        param([int]$n)
        $s = ''
        while ($n -gt 0) { $m = ($n - 1) % 26; $s = [char](65 + $m) + $s; $n = [int](($n - $m) / 26) }
        return $s
    }
    function Get-Addr  { param([int]$r,[int]$c) ('{0}{1}' -f (Get-ColLetter $c), $r) }
    function Get-Range { param([int]$r1,[int]$c1,[int]$r2,[int]$c2) ('{0}:{1}' -f (Get-Addr $r1 $c1), (Get-Addr $r2 $c2)) }

    # ----- EPPlus layout helpers ------------------------------------------ #
    function Set-Title {
        param($Ws, [int]$RowIndex, [int]$Span, [string]$Text, $Fill)
        $Ws.Cells[(Get-Addr $RowIndex 1)].Value = $Text
        $Ws.Cells[(Get-Addr $RowIndex 1)].Style.Font.Bold = $true
        $Ws.Cells[(Get-Addr $RowIndex 1)].Style.Font.Size = 12
        $rng = $Ws.Cells[(Get-Range $RowIndex 1 $RowIndex $Span)]
        $rng.Style.Fill.PatternType = $solid
        $rng.Style.Fill.BackgroundColor.SetColor($Fill)
        $rng.Style.Font.Color.SetColor($whiteFont)
    }

    function Write-Table {
        param($Ws, [ref]$RowRef, [string[]]$Headers, [object[]]$Data, [string[]]$Props, $HeaderFill)
        $r = $RowRef.Value
        $colCount = $Headers.Count
        for ($c = 0; $c -lt $colCount; $c++) {
            $cell = $Ws.Cells[(Get-Addr $r ($c + 1))]
            $cell.Value = $Headers[$c]
            $cell.Style.Font.Bold = $true
            $cell.Style.Fill.PatternType = $solid
            $cell.Style.Fill.BackgroundColor.SetColor($HeaderFill)
            $cell.Style.Font.Color.SetColor($whiteFont)
        }
        $r++
        foreach ($item in $Data) {
            for ($c = 0; $c -lt $colCount; $c++) {
                $val = $item.$($Props[$c])
                if ($val -is [datetime]) { $val = $val.ToString('yyyy-MM-dd HH:mm') }
                $Ws.Cells[(Get-Addr $r ($c + 1))].Value = [string]$val
            }
            $r++
        }
        $RowRef.Value = $r
    }

    function Write-KeyValue {
        param($Ws, [ref]$RowRef, $Pairs)
        $r = $RowRef.Value
        foreach ($k in $Pairs.Keys) {
            $Ws.Cells[(Get-Addr $r 1)].Value = $k
            $Ws.Cells[(Get-Addr $r 1)].Style.Font.Bold = $true
            $Ws.Cells[(Get-Addr $r 2)].Value = [string]$Pairs[$k]
            $r++
        }
        $RowRef.Value = $r
    }

    # AutoFit can fail on Server Core (no GDI+); wrap it so it never aborts.
    function Invoke-AutoFit { param($Ws) try { $Ws.Cells.AutoFitColumns() } catch { } }

    $sheet = $pkg.Workbook.Worksheets.Add('Device list')
    $row = 1

    # ----- Hybrid banner: scope & source-of-truth ------------------------- #
    if ($IsHybrid) {
        $sheet.Cells["A$row"].Value = ("HYBRID ENVIRONMENT - Unified asset list (Intune + on-prem AD, de-duplicated). Cloud workstations: {0}; on-premises workstations: {1}. Primary source of truth: {2}. {3}" -f `
            $cloudWorkstationCount, $onPremWorkstationCount, $sourceOfTruth, $distributionVerdict)
        $sheet.Cells["A$row"].Style.Font.Bold = $true
        $sheet.Cells["A$row:H$row"].Merge = $true
        $sheet.Cells["A$row"].Style.WrapText = $true
        $sheet.Row($row).Height = 60
        $row += 2
    }

    # ----- Device list: Windows workstations ------------------------------ #
    $winHeaders = @('Device name','Manufacturer','Model','OS','SKU family','Ownership','Join type','Primary user UPN','Source')
    $winProps   = @('DeviceName','Manufacturer','Model','OS','SkuFamily','Ownership','JoinType','PrimaryUser','Source')
    Set-Title -Ws $sheet -RowIndex $row -Span $winHeaders.Count -Text 'WINDOWS WORKSTATIONS' -Fill $sectionFill
    $row += 1
    if ($windows.Count -gt 0) {
        $ref = [ref]$row
        Write-Table -Ws $sheet -RowRef $ref -Headers $winHeaders -Data $windows -Props $winProps -HeaderFill $headerFill
        $row = $ref.Value
    } else { $sheet.Cells["A$row"].Value = 'No Windows workstations within the check-in window.'; $row++ }
    $row += 2

    # ----- Device list: servers (listed separately) ----------------------- #
    Set-Title -Ws $sheet -RowIndex $row -Span $winHeaders.Count -Text 'SERVERS' -Fill $sectionFill
    $row += 1
    if ($servers.Count -gt 0) {
        $ref = [ref]$row
        Write-Table -Ws $sheet -RowRef $ref -Headers $winHeaders -Data $servers -Props $winProps -HeaderFill $headerFill
        $row = $ref.Value
    } else { $sheet.Cells["A$row"].Value = 'No servers found in scope.'; $row++ }
    $row += 2

    # ----- Device list: macOS --------------------------------------------- #
    $macHeaders = @('Device name','Manufacturer','Model','OS','Ownership','Join type','Primary user UPN','Source')
    $macProps   = @('DeviceName','Manufacturer','Model','OS','Ownership','JoinType','PrimaryUser','Source')
    Set-Title -Ws $sheet -RowIndex $row -Span $macHeaders.Count -Text 'MACOS DEVICES' -Fill $sectionFill
    $row += 1
    if ($macos.Count -gt 0) {
        $ref = [ref]$row
        Write-Table -Ws $sheet -RowRef $ref -Headers $macHeaders -Data $macos -Props $macProps -HeaderFill $headerFill
        $row = $ref.Value
    } else { $sheet.Cells["A$row"].Value = 'No macOS devices within the check-in window.'; $row++ }
    $row += 2

    # ----- Device list: Windows workstation summary ----------------------- #
    Set-Title -Ws $sheet -RowIndex $row -Span 5 -Text 'WINDOWS WORKSTATION SUMMARY' -Fill $sectionFill
    $row += 1
    $sheet.Cells["A$row"].Value = ("Total Windows workstations: {0}" -f $windows.Count)
    $sheet.Cells["A$row"].Style.Font.Bold = $true
    $row += 2
    if ($summary) {
        $ref = [ref]$row
        Write-Table -Ws $sheet -RowRef $ref -Headers @('Count','Manufacturer','OS','SKU family','Summary') -Data @($summary) -Props @('Count','Manufacturer','OS','SkuFamily','Description') -HeaderFill $headerFill
        $row = $ref.Value
    }
    $row += 2

    # ----- Device list: server summary ------------------------------------ #
    Set-Title -Ws $sheet -RowIndex $row -Span 5 -Text 'SERVER SUMMARY' -Fill $sectionFill
    $row += 1
    $sheet.Cells["A$row"].Value = ("Total servers: {0}" -f $servers.Count)
    $sheet.Cells["A$row"].Style.Font.Bold = $true
    $row += 2
    if ($serverSummary) {
        $ref = [ref]$row
        Write-Table -Ws $sheet -RowRef $ref -Headers @('Count','Manufacturer','OS','SKU family','Summary') -Data @($serverSummary) -Props @('Count','Manufacturer','OS','SkuFamily','Description') -HeaderFill $headerFill
        $row = $ref.Value
    } else { $sheet.Cells["A$row"].Value = 'No servers in scope.'; $row++ }
    Invoke-AutoFit $sheet

    # ===================================================================== #
    #  MFA worksheet                                                        #
    # ===================================================================== #
    $mfaSheet = $pkg.Workbook.Worksheets.Add('MFA')
    $mrow = 1
    Set-Title -Ws $mfaSheet -RowIndex $mrow -Span 2 -Text 'MULTI-FACTOR AUTHENTICATION (CONDITIONAL ACCESS)' -Fill $sectionFill
    $mrow += 2
    $mfaSheet.Cells["A$mrow"].Value = ("Conditional Access policies found: {0}" -f $caPolicies.Count); $mrow++
    $mfaSheet.Cells["A$mrow"].Value = ("Policies enforcing MFA: {0}" -f $mfaFindings.Count); $mfaSheet.Cells["A$mrow"].Style.Font.Bold = $true; $mrow += 2
    if ($mfaFindings.Count -eq 0) {
        $note = if ($caPolicies.Count -eq 0) { 'No Conditional Access policies were returned (none configured, or insufficient permissions).' } else { 'No Conditional Access policy enforcing MFA was found.' }
        $mfaSheet.Cells["A$mrow"].Value = $note; $mrow++
    } else {
        $idx = 1
        foreach ($f in $mfaFindings) {
            Set-Title -Ws $mfaSheet -RowIndex $mrow -Span 2 -Text ("Policy {0} of {1}" -f $idx, $mfaFindings.Count) -Fill $headerFill
            $mrow++
            $ref = [ref]$mrow; Write-KeyValue -Ws $mfaSheet -RowRef $ref -Pairs $f; $mrow = $ref.Value + 1
            $idx++
        }
    }
    Invoke-AutoFit $mfaSheet
    $mfaSheet.Column(2).Width = 70

    # ===================================================================== #
    #  Software firewall worksheet                                          #
    # ===================================================================== #
    $fwSheet = $pkg.Workbook.Worksheets.Add('Software firewall')
    $frow = 1
    Set-Title -Ws $fwSheet -RowIndex $frow -Span 5 -Text 'SOFTWARE FIREWALL (INTUNE POLICIES)' -Fill $sectionFill
    $frow += 2
    $fwSheet.Cells["A$frow"].Value = ("Firewall-related policies found: {0}" -f $fwFindings.Count); $fwSheet.Cells["A$frow"].Style.Font.Bold = $true; $frow += 2
    if ($fwFindings.Count -eq 0) {
        $fwSheet.Cells["A$frow"].Value = 'No Intune policy enabling/enforcing the software firewall was found (or insufficient permissions).'; $frow++
    } else {
        $ref = [ref]$frow
        Write-Table -Ws $fwSheet -RowRef $ref -Headers @('Source','Policy name','Firewall setting','Included (devices / groups)','Excluded (groups)') -Data $fwFindings -Props @('Source','PolicyName','FirewallSetting','Included','Excluded') -HeaderFill $headerFill
        $frow = $ref.Value
    }
    Invoke-AutoFit $fwSheet
    $fwSheet.Column(4).Width = 45
    $fwSheet.Column(5).Width = 35

    # ===================================================================== #
    #  Mobile devices worksheet                                             #
    # ===================================================================== #
    $mobSheet = $pkg.Workbook.Worksheets.Add('Mobile devices')
    $mvrow = 1
    Set-Title -Ws $mobSheet -RowIndex $mvrow -Span 6 -Text 'MOBILE DEVICES (ANDROID & iOS)' -Fill $sectionFill
    $mvrow += 2
    $mobSheet.Cells["A$mvrow"].Value = ("Total mobile devices: {0}" -f $mobileRows.Count); $mobSheet.Cells["A$mvrow"].Style.Font.Bold = $true; $mvrow += 2

    Set-Title -Ws $mobSheet -RowIndex $mvrow -Span 4 -Text 'SUMMARY BY MAKE & OS' -Fill $headerFill
    $mvrow++
    if ($mobileSummary.Count) {
        $ref = [ref]$mvrow
        Write-Table -Ws $mobSheet -RowRef $ref -Headers @('Count','Make','OS','Summary') -Data $mobileSummary -Props @('Count','Make','OS','Description') -HeaderFill $headerFill
        $mvrow = $ref.Value
    } else { $mobSheet.Cells["A$mvrow"].Value = 'No mobile devices found.'; $mvrow++ }
    $mvrow += 2

    Set-Title -Ws $mobSheet -RowIndex $mvrow -Span 6 -Text 'DEVICE LIST' -Fill $headerFill
    $mvrow++
    if ($mobileRows.Count) {
        $ref = [ref]$mvrow
        Write-Table -Ws $mobSheet -RowRef $ref -Headers @('Device name','Make','Model','OS','Ownership','Primary user UPN') -Data $mobileRows -Props @('DeviceName','Make','Model','OS','Ownership','PrimaryUser') -HeaderFill $headerFill
        $mvrow = $ref.Value
    } else { $mobSheet.Cells["A$mvrow"].Value = 'No mobile devices found.'; $mvrow++ }
    $mvrow += 2

    Set-Title -Ws $mobSheet -RowIndex $mvrow -Span 2 -Text 'APP PROTECTION POLICIES (MAM)' -Fill $sectionFill
    $mvrow++
    $mobSheet.Cells["A$mvrow"].Value = ("App protection policies found: {0}" -f $appPolicies.Count); $mobSheet.Cells["A$mvrow"].Style.Font.Bold = $true; $mvrow += 2
    if ($appPolicies.Count -eq 0) {
        $mobSheet.Cells["A$mvrow"].Value = 'No Intune app protection (MAM) policies were found for Android or iOS.'; $mvrow++
    } else {
        foreach ($ap in $appPolicies) {
            Set-Title -Ws $mobSheet -RowIndex $mvrow -Span 2 -Text ("{0} - {1}" -f $ap.Platform, $ap.Name) -Fill $headerFill
            $mvrow++
            $meta = [ordered]@{ 'Platform' = $ap.Platform; 'Assigned to (included)' = $ap.Included; 'Excluded' = $ap.Excluded }
            $ref = [ref]$mvrow; Write-KeyValue -Ws $mobSheet -RowRef $ref -Pairs $meta; $mvrow = $ref.Value
            $mobSheet.Cells["A$mvrow"].Value = 'Settings:'; $mobSheet.Cells["A$mvrow"].Style.Font.Italic = $true; $mvrow++
            if ($ap.Settings.Count) {
                $ref = [ref]$mvrow; Write-KeyValue -Ws $mobSheet -RowRef $ref -Pairs $ap.Settings; $mvrow = $ref.Value
            } else { $mobSheet.Cells["A$mvrow"].Value = '(no individual settings reported)'; $mvrow++ }
            $mvrow += 1
        }
    }
    $mvrow += 1

    Set-Title -Ws $mobSheet -RowIndex $mvrow -Span 2 -Text 'CONDITIONAL ACCESS - REQUIRE APP PROTECTION' -Fill $sectionFill
    $mvrow++
    if ($caAppEnforce.Count) {
        $mobSheet.Cells["A$mvrow"].Value = ("{0} Conditional Access policy(ies) require an approved app / app protection policy:" -f $caAppEnforce.Count); $mvrow++
        foreach ($c in $caAppEnforce) { $mobSheet.Cells["A$mvrow"].Value = (" - {0} [{1}]" -f $c.Name, $c.State); $mvrow++ }
    } else {
        $mobSheet.Cells["A$mvrow"].Value = 'No Conditional Access policy enforces app protection (grant control "compliantApplication").'; $mvrow++
    }
    $mvrow += 2

    Set-Title -Ws $mobSheet -RowIndex $mvrow -Span 5 -Text 'OTHER MOBILE MANAGEMENT POLICIES (COMPLIANCE)' -Fill $sectionFill
    $mvrow++
    if ($appPolicies.Count -eq 0) {
        $mobSheet.Cells["A$mvrow"].Value = 'No app protection policies exist; the policies below are the closest mobile-management controls in place.'; $mobSheet.Cells["A$mvrow"].Style.Font.Italic = $true; $mvrow++
    }
    if ($fallback.Count) {
        $ref = [ref]$mvrow
        Write-Table -Ws $mobSheet -RowRef $ref -Headers @('Name','Platform','Type','Included','Excluded') -Data $fallback -Props @('Name','Platform','Type','Included','Excluded') -HeaderFill $headerFill
        $mvrow = $ref.Value
    } else { $mobSheet.Cells["A$mvrow"].Value = 'No Android/iOS compliance policies found.'; $mvrow++ }
    Invoke-AutoFit $mobSheet
    $mobSheet.Column(2).Width = 50

    # ===================================================================== #
    #  AutoPlay / AutoRun worksheet ('/' not allowed in sheet names)        #
    # ===================================================================== #
    $autoSheet = $pkg.Workbook.Worksheets.Add('Status of autoplay-autorun')
    $arow = 1
    Set-Title -Ws $autoSheet -RowIndex $arow -Span 6 -Text 'AUTOPLAY / AUTORUN POLICIES' -Fill $sectionFill
    $arow += 2
    $autoSheet.Cells["A$arow"].Value = ("Settings disabling/affecting AutoPlay or AutoRun found: {0}" -f $autoFindings.Count); $autoSheet.Cells["A$arow"].Style.Font.Bold = $true; $arow += 2
    if ($autoFindings.Count -eq 0) {
        $autoSheet.Cells["A$arow"].Value = 'No Intune policy or setting that disables AutoPlay/AutoRun was found (or insufficient permissions).'; $arow++
    } else {
        $ref = [ref]$arow
        Write-Table -Ws $autoSheet -RowRef $ref -Headers @('Source','Policy name','Setting','State','Included (groups / users)','Excluded (groups)') -Data $autoFindings -Props @('Source','PolicyName','Setting','State','Included','Excluded') -HeaderFill $headerFill
        $arow = $ref.Value
    }
    Invoke-AutoFit $autoSheet
    $autoSheet.Column(3).Width = 45
    $autoSheet.Column(5).Width = 40
    $autoSheet.Column(6).Width = 30

    # ===================================================================== #
    #  Shared accounts worksheet                                            #
    # ===================================================================== #
    $shSheet = $pkg.Workbook.Worksheets.Add('Shared accounts')
    $srow = 1
    Set-Title -Ws $shSheet -RowIndex $srow -Span 6 -Text 'SUSPECTED SHARED ACCOUNTS' -Fill $sectionFill
    $srow += 2

    # Caveat banner.
    $shSheet.Cells["A$srow"].Value = 'CAVEAT: These accounts are flagged HEURISTICALLY (by naming patterns and missing first/last names). They are NOT confirmed shared accounts. A manual check MUST be performed to confirm whether each account is genuinely shared.'
    $shSheet.Cells["A$srow"].Style.Font.Bold = $true
    $shSheet.Cells["A$srow"].Style.Font.Color.SetColor($redFont)
    $shSheet.Cells["A$srow:F$srow"].Merge = $true
    $shSheet.Cells["A$srow"].Style.WrapText = $true
    $shSheet.Row($srow).Height = 45
    $srow += 2

    $shSheet.Cells["A$srow"].Value = ("Total accounts reviewed: {0}" -f @($allUsers).Count); $srow++
    $shSheet.Cells["A$srow"].Value = ("Suspected shared accounts: {0}" -f $sharedAccounts.Count); $shSheet.Cells["A$srow"].Style.Font.Bold = $true; $srow += 2

    if ($sharedAccounts.Count -eq 0) {
        $shSheet.Cells["A$srow"].Value = 'No accounts matched the shared-account heuristics. (A manual review is still recommended.)'; $srow++
    } else {
        $ref = [ref]$srow
        Write-Table -Ws $shSheet -RowRef $ref -Headers @('Display name','User principal name','Enabled','User type','Licenses','Why flagged (manual check required)') -Data $sharedAccounts -Props @('DisplayName','UPN','Enabled','UserType','Licenses','Reasons') -HeaderFill $headerFill
        $srow = $ref.Value
    }
    Invoke-AutoFit $shSheet
    $shSheet.Column(5).Width = 35
    $shSheet.Column(6).Width = 40

    # ===================================================================== #
    #  Application whitelisting worksheet                                   #
    # ===================================================================== #
    $awSheet = $pkg.Workbook.Worksheets.Add('Application whitelisting')
    $awrow = 1
    Set-Title -Ws $awSheet -RowIndex $awrow -Span 6 -Text 'APPLICATION WHITELISTING (APPLOCKER / APP CONTROL FOR BUSINESS / WDAC)' -Fill $sectionFill
    $awrow += 2
    $awSheet.Cells["A$awrow"].Value = ("Application-whitelisting policies found: {0}" -f $awFindings.Count); $awSheet.Cells["A$awrow"].Style.Font.Bold = $true; $awrow += 2

    if ($awFindings.Count -eq 0) {
        $awSheet.Cells["A$awrow"].Value = 'No Intune application-whitelisting policy (AppLocker, App Control for Business / WDAC, or Smart App Control) was found.'
        $awrow++
        $awSheet.Cells["A$awrow"].Value = 'CAVEAT: The auditor should carry out an additional manual check to confirm whether ThreatLocker, or any other third-party application-whitelisting / allow-listing solution, is installed and enforced on endpoints. Absence of an Intune policy does not necessarily mean no whitelisting is in place.'
        $awSheet.Cells["A$awrow"].Style.Font.Bold = $true
        $awSheet.Cells["A$awrow"].Style.Font.Color.SetColor($redFont)
        $awSheet.Cells["A$awrow:F$awrow"].Merge = $true
        $awSheet.Cells["A$awrow"].Style.WrapText = $true
        $awSheet.Row($awrow).Height = 60
        $awrow++
    } else {
        $ref = [ref]$awrow
        Write-Table -Ws $awSheet -RowRef $ref -Headers @('Source','Policy name','Mechanism','Setting','Included (users / groups)','Excluded (groups)') -Data $awFindings -Props @('Source','PolicyName','Mechanism','Setting','Included','Excluded') -HeaderFill $headerFill
        $awrow = $ref.Value
        $awrow++
        $awSheet.Cells["A$awrow"].Value = 'Note: this covers Intune-managed application control. If full coverage is required, the auditor should also confirm whether ThreatLocker or another third-party whitelisting solution is in use.'
        $awSheet.Cells["A$awrow"].Style.Font.Italic = $true
        $awSheet.Cells["A$awrow:F$awrow"].Merge = $true
        $awSheet.Cells["A$awrow"].Style.WrapText = $true
        $awSheet.Row($awrow).Height = 30
        $awrow++
    }
    Invoke-AutoFit $awSheet
    $awSheet.Column(4).Width = 45
    $awSheet.Column(5).Width = 40
    $awSheet.Column(6).Width = 30

    # ===================================================================== #
    #  Password worksheet                                                   #
    # ===================================================================== #
    $pwSheet = $pkg.Workbook.Worksheets.Add('Password')
    $pwrow = 1
    Set-Title -Ws $pwSheet -RowIndex $pwrow -Span 2 -Text 'PASSWORD PROTECTION (SECURITY DEFAULTS & BANNED PASSWORD LIST)' -Fill $sectionFill
    $pwrow += 2

    # Verdict banner (green if requirement met, red if a banned list is required).
    $pwSheet.Cells["A$pwrow"].Value = $pwdVerdict
    $pwSheet.Cells["A$pwrow"].Style.Font.Bold = $true
    $pwSheet.Cells["A$pwrow"].Style.Font.Color.SetColor($(if ($customBannedInPlace) { $greenFont } else { $redFont }))
    $pwSheet.Cells["A$pwrow:B$pwrow"].Merge = $true
    $pwSheet.Cells["A$pwrow"].Style.WrapText = $true
    $pwSheet.Row($pwrow).Height = 60
    $pwrow += 2

    # Detail key/value table.
    Set-Title -Ws $pwSheet -RowIndex $pwrow -Span 2 -Text 'DETAILS' -Fill $headerFill
    $pwrow++
    $ref = [ref]$pwrow
    Write-KeyValue -Ws $pwSheet -RowRef $ref -Pairs $pwdFindings
    $pwrow = $ref.Value + 1

    $pwSheet.Cells["A$pwrow"].Value = 'Microsoft enforces a global banned-password list automatically for all Entra ID tenants. Cyber Essentials specifically expects a deny list of common passwords; a custom banned list (Entra Password Protection) strengthens and evidences this control.'
    $pwSheet.Cells["A$pwrow"].Style.Font.Italic = $true
    $pwSheet.Cells["A$pwrow:B$pwrow"].Merge = $true
    $pwSheet.Cells["A$pwrow"].Style.WrapText = $true
    $pwSheet.Row($pwrow).Height = 45

    Invoke-AutoFit $pwSheet
    $pwSheet.Column(1).Width = 38
    $pwSheet.Column(2).Width = 60

    # ----- finalise ------------------------------------------------------- #
    $pkg.Save()
    Write-Host ("Report saved to: {0}" -f $fullPath) -ForegroundColor Green
}
finally {
    if ($pkg) { $pkg.Dispose() }
    if (Get-MgContext) { Disconnect-MgGraph | Out-Null }
}

Write-Host 'Done.' -ForegroundColor Green

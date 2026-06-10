# OS identification + end-of-support evaluation (fixes B3 server
# misclassification and B4 missing EOL detection).
#
# Sources of truth encoded below (verify when updating):
#   Windows client : Microsoft "Windows release health" lifecycle table.
#   Windows Server : Microsoft Lifecycle (extended support end).
#   macOS          : Apple ships security updates for the CURRENT major and the
#                    TWO prior majors; older majors are treated as EOL.
#
# REVIEW ANNUALLY: $script:CeMacSupportedMajors after each September macOS
# release, and add new Windows builds as they ship.

# Build -> client feature update. HomeProEnd / EnterpriseEnd = end of servicing
# for Home & Pro / Enterprise & Education editions.
$script:CeWindowsClientBuilds = @{
    26200 = @{ Name = 'Windows 11 25H2'; HomeProEnd = '2027-10-12'; EnterpriseEnd = '2028-10-10' }
    26100 = @{ Name = 'Windows 11 24H2'; HomeProEnd = '2026-10-13'; EnterpriseEnd = '2027-10-12' }
    22631 = @{ Name = 'Windows 11 23H2'; HomeProEnd = '2025-11-11'; EnterpriseEnd = '2026-11-10' }
    22621 = @{ Name = 'Windows 11 22H2'; HomeProEnd = '2024-10-08'; EnterpriseEnd = '2025-10-14' }
    22000 = @{ Name = 'Windows 11 21H2'; HomeProEnd = '2023-10-10'; EnterpriseEnd = '2024-10-08' }
    19045 = @{ Name = 'Windows 10 22H2'; HomeProEnd = '2025-10-14'; EnterpriseEnd = '2025-10-14' }
    19044 = @{ Name = 'Windows 10 21H2'; HomeProEnd = '2023-06-13'; EnterpriseEnd = '2024-06-11' }
    19043 = @{ Name = 'Windows 10 21H1'; HomeProEnd = '2022-12-13'; EnterpriseEnd = '2022-12-13' }
    19042 = @{ Name = 'Windows 10 20H2'; HomeProEnd = '2022-05-10'; EnterpriseEnd = '2023-05-09' }
    19041 = @{ Name = 'Windows 10 2004'; HomeProEnd = '2021-12-14'; EnterpriseEnd = '2021-12-14' }
    18363 = @{ Name = 'Windows 10 1909'; HomeProEnd = '2021-05-11'; EnterpriseEnd = '2022-05-10' }
    18362 = @{ Name = 'Windows 10 1903'; HomeProEnd = '2020-12-08'; EnterpriseEnd = '2020-12-08' }
    17763 = @{ Name = 'Windows 10 1809'; HomeProEnd = '2020-11-10'; EnterpriseEnd = '2021-05-11' }
}

# Build -> server release (extended support end). Some builds are shared with
# client releases; IsServer is decided from SKU/OS hints first.
$script:CeWindowsServerBuilds = @{
    26100 = @{ Name = 'Windows Server 2025';          End = '2034-10-10' }
    25398 = @{ Name = 'Windows Server, version 23H2'; End = '2025-10-24' }
    20348 = @{ Name = 'Windows Server 2022';          End = '2031-10-14' }
    17763 = @{ Name = 'Windows Server 2019';          End = '2029-01-09' }
    16299 = @{ Name = 'Windows Server, version 1709'; End = '2020-10-13' }
    14393 = @{ Name = 'Windows Server 2016';          End = '2027-01-12' }
}
# Builds that only exist as Server releases (safe to classify on build alone).
$script:CeServerOnlyBuilds = @(20348, 25398)

# Server NAME -> extended support end, for on-prem AD records that carry only
# the OperatingSystem display string.
$script:CeServerNameLifecycle = @(
    @{ Pattern = '(?i)server\s*2025'; End = '2034-10-10' }
    @{ Pattern = '(?i)server\s*2022'; End = '2031-10-14' }
    @{ Pattern = '(?i)server\s*2019'; End = '2029-01-09' }
    @{ Pattern = '(?i)server\s*2016'; End = '2027-01-12' }
    @{ Pattern = '(?i)server\s*2012'; End = '2023-10-10' }
    @{ Pattern = '(?i)server\s*2008'; End = '2020-01-14' }
    @{ Pattern = '(?i)server\s*2003'; End = '2015-07-14' }
)

# Apple supports the current major and two prior. Current major: macOS 26
# (Tahoe, September 2025). Apple jumped from 15 to 26 in 2025.
$script:CeMacSupportedMajors = @(26, 15, 14)
$script:CeMacMajorNames = @{
    26 = 'Tahoe'; 15 = 'Sequoia'; 14 = 'Sonoma'; 13 = 'Ventura'
    12 = 'Monterey'; 11 = 'Big Sur'; 10 = 'Catalina or earlier'
}

# Identify an operating system and judge vendor support.
# Returns: FriendlyName, IsServer, SupportStatus (Supported/EOL/Unknown),
#          SupportEnd ([datetime] or $null), SupportNote.
function Get-CeOsInfo {
    [CmdletBinding()]
    param(
        # 'Windows' or 'macOS' (Intune operatingSystem value).
        [string]$OperatingSystem = 'Windows',
        # Intune osVersion, e.g. '10.0.22631.4460' or '14.7.1' for macOS.
        [string]$OsVersion,
        # Intune skuFamily (e.g. 'Pro', 'Enterprise', 'ServerStandard').
        [string]$SkuFamily,
        # Display OS string when known (AD OperatingSystem / CIM Caption).
        [string]$OsName,
        # Evaluate support as of this date (default: now). Injectable for tests.
        [datetime]$AsOf = (Get-Date)
    )

    $result = [pscustomobject]@{
        FriendlyName  = ''
        IsServer      = $false
        SupportStatus = 'Unknown'
        SupportEnd    = $null
        SupportNote   = ''
    }

    if ($OperatingSystem -match '(?i)^mac') {
        $major = 0
        if ($OsVersion -match '^(\d+)') { $major = [int]$Matches[1] }
        $majorName = ''
        if ($script:CeMacMajorNames.ContainsKey($major)) { $majorName = ' ' + $script:CeMacMajorNames[$major] }
        $result.FriendlyName = ("macOS{0} {1}" -f $majorName, $OsVersion).Trim()
        if ($major -eq 0) {
            $result.SupportStatus = 'Unknown'
            $result.SupportNote = 'macOS version not reported'
        } elseif ($script:CeMacSupportedMajors -contains $major) {
            $result.SupportStatus = 'Supported'
            $result.SupportNote = 'Apple supports the current and two prior macOS majors'
        } elseif ($major -gt ($script:CeMacSupportedMajors | Measure-Object -Maximum).Maximum) {
            # Newer than the table knows about - assume supported.
            $result.SupportStatus = 'Supported'
            $result.SupportNote = 'Newer than the encoded lifecycle table - verify'
        } else {
            $result.SupportStatus = 'EOL'
            $result.SupportNote = 'No longer receives Apple security updates (current and two prior majors only)'
        }
        return $result
    }

    # ---- Windows -----------------------------------------------------------
    $build = 0
    if ($OsVersion) {
        $parts = $OsVersion.Split('.')
        if ($parts.Count -ge 3) { [void][int]::TryParse($parts[2], [ref]$build) }
        elseif ($parts.Count -eq 1) { [void][int]::TryParse($parts[0], [ref]$build) }
    }

    # Server detection (B3): explicit SKU / OS-name signal first, then
    # server-only builds.
    $serverHint = ("$SkuFamily $OsName $OperatingSystem" -match '(?i)server')
    $result.IsServer = $serverHint -or ($script:CeServerOnlyBuilds -contains $build)

    if ($result.IsServer) {
        if ($build -gt 0 -and $script:CeWindowsServerBuilds.ContainsKey($build)) {
            $entry = $script:CeWindowsServerBuilds[$build]
            $result.FriendlyName = $entry.Name
            $result.SupportEnd = [datetime]::ParseExact($entry.End, 'yyyy-MM-dd', $null)
            $result.SupportNote = 'Extended support end'
        } elseif ($OsName) {
            $result.FriendlyName = ($OsName -replace '(?i)microsoft ', '').Trim()
            foreach ($lc in $script:CeServerNameLifecycle) {
                if ($OsName -match $lc.Pattern) {
                    $result.SupportEnd = [datetime]::ParseExact($lc.End, 'yyyy-MM-dd', $null)
                    $result.SupportNote = 'Extended support end'
                    break
                }
            }
        } else {
            $result.FriendlyName = "Windows Server (build $build)"
        }
        if (-not $result.FriendlyName) { $result.FriendlyName = "Windows Server (build $build)" }
    } else {
        if ($build -gt 0 -and $script:CeWindowsClientBuilds.ContainsKey($build)) {
            $entry = $script:CeWindowsClientBuilds[$build]
            $result.FriendlyName = $entry.Name
            # Edition-aware lifecycle: Enterprise/Education runs longer.
            $isEnterprise = ($SkuFamily -match '(?i)enterprise|education')
            $endStr = if ($isEnterprise) { $entry.EnterpriseEnd } else { $entry.HomeProEnd }
            $result.SupportEnd = [datetime]::ParseExact($endStr, 'yyyy-MM-dd', $null)
            $result.SupportNote = if ($isEnterprise) { 'Enterprise/Education servicing end' } else { 'Home/Pro servicing end (Enterprise/Education may run longer)' }
        } elseif ($OsName -and $OsName -match '(?i)windows\s*(7|8|xp|vista)\b') {
            $result.FriendlyName = ($OsName -replace '(?i)microsoft ', '').Trim()
            $result.SupportStatus = 'EOL'
            $result.SupportNote = 'Legacy Windows release - long out of support'
            return $result
        } elseif ($build -ge 22000) {
            $result.FriendlyName = "Windows 11 (build $build)"
            $result.SupportNote = 'Build not in lifecycle table - verify support status'
        } elseif ($build -ge 10240) {
            $result.FriendlyName = "Windows 10 (build $build)"
            $result.SupportNote = 'Build not in lifecycle table - verify support status'
        } elseif ($OsName) {
            $result.FriendlyName = ($OsName -replace '(?i)microsoft ', '').Trim()
        } else {
            $result.FriendlyName = $(if ($OsVersion) { "Windows $OsVersion" } else { 'Windows (unknown build)' })
        }
    }

    if ($result.SupportEnd) {
        $result.SupportStatus = if ($AsOf.Date -le $result.SupportEnd.Date) { 'Supported' } else { 'EOL' }
    }
    return $result
}

# Unified asset inventory: Intune (Windows/macOS/mobile) + on-prem AD (hybrid),
# de-duplicated, with per-device OS support status (B4) and reliable server
# classification (B3). Mobile devices now honour the same check-in window as
# desktops (B10). Hybrid hardware enrichment uses CIM sessions with a short
# timeout and can be skipped entirely (B13).
function Get-CeDeviceInventory {
    [CmdletBinding()]
    param(
        [int]$CheckInWindowWeeks = 6,
        [bool]$IsHybrid = $false,
        [bool]$AdAvailable = $false,
        [hashtable]$AdParams = @{},
        [switch]$SkipHardwareInventory
    )

    $cutoff       = (Get-Date).AddDays(-7 * $CheckInWindowWeeks)
    $cutoffUtcStr = $cutoff.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    # ---- Cloud: Windows & macOS ---------------------------------------------
    $select = @('deviceName','manufacturer','model','operatingSystem','osVersion',
                'skuFamily','joinType','managedDeviceOwnerType','userPrincipalName','lastSyncDateTime') -join ','
    $filter = "lastSyncDateTime ge $cutoffUtcStr and (operatingSystem eq 'Windows' or operatingSystem eq 'macOS')"
    $uri = '{0}?$filter={1}&$select={2}&$top=200' -f $script:CeUri.ManagedDevices,
        [uri]::EscapeDataString($filter), [uri]::EscapeDataString($select)

    Write-Host ("Querying managed devices checked in since {0} (UTC)..." -f $cutoffUtcStr) -ForegroundColor Cyan
    $devices = @()
    try { $devices = Get-CeGraphPaged -Uri $uri -Area 'ManagedDevices' } catch { }

    $rows = foreach ($d in $devices) {
        $os    = [string]$d.operatingSystem
        $osVer = [string]$d.osVersion
        $info  = Get-CeOsInfo -OperatingSystem $os -OsVersion $osVer -SkuFamily ([string]$d.skuFamily)
        [pscustomobject]@{
            DeviceName    = $d.deviceName
            Manufacturer  = $(if ($d.manufacturer) { $d.manufacturer } else { 'Unknown' })
            Model         = $d.model
            OS            = $info.FriendlyName
            OperatingSys  = $os
            SkuFamily     = $(if ([string]::IsNullOrWhiteSpace([string]$d.skuFamily)) { 'Unknown' } else { ([string]$d.skuFamily).Trim() })
            Ownership     = $d.managedDeviceOwnerType
            JoinType      = $d.joinType
            PrimaryUser   = $d.userPrincipalName
            LastCheckIn   = $d.lastSyncDateTime
            Source        = 'Cloud (Intune)'
            IsServer      = $info.IsServer
            SupportStatus = $info.SupportStatus
            SupportEnd    = $(if ($info.SupportEnd) { $info.SupportEnd.ToString('yyyy-MM-dd') } else { '' })
            SupportNote   = $info.SupportNote
        }
    }
    $rows = @($rows)
    Write-Host ("Retrieved {0} cloud device(s) within the {1}-week window." -f $rows.Count, $CheckInWindowWeeks) -ForegroundColor Green

    # ---- On-premises AD (hybrid) --------------------------------------------
    $onPremRows   = @()
    $skippedStale = 0
    $containerSeen = @{}
    if ($IsHybrid -and $AdAvailable) {
        Write-Host 'Collecting on-premises AD computer inventory (all containers/OUs)...' -ForegroundColor Cyan
        $searchBase = $null
        try { $searchBase = (Get-ADDomain @AdParams -ErrorAction Stop).DistinguishedName } catch { }
        $adcParams = @{} + $AdParams
        if ($searchBase) { $adcParams['SearchBase'] = $searchBase; $adcParams['SearchScope'] = 'Subtree' }

        $adComputers = @()
        try {
            $adComputers = @(Get-ADComputer @adcParams -Filter 'Enabled -eq $true' `
                -Properties Name, DNSHostName, OperatingSystem, OperatingSystemVersion, `
                            lastLogonTimestamp, pwdLastSet, whenChanged, DistinguishedName `
                -ErrorAction Stop)
        } catch {
            Write-Warning "Could not enumerate AD computers: $($_.Exception.Message)"
        }

        foreach ($c in $adComputers) {
            $container = 'Unknown'
            if ($c.DistinguishedName -match '^CN=[^,]+,(.+)$') { $container = $Matches[1] }
            $containerSeen[$container] = ([int]$containerSeen[$container]) + 1

            # Combined activity signal: lastLogonTimestamp replicates only every
            # ~14 days, so any of three timestamps within the window keeps the
            # device; no timestamps at all also keeps it (never drop silently).
            $llt = $null; if ($c.lastLogonTimestamp) { $llt = [datetime]::FromFileTimeUtc([int64]$c.lastLogonTimestamp) }
            $pls = $null; if ($c.pwdLastSet)         { $pls = [datetime]::FromFileTimeUtc([int64]$c.pwdLastSet) }
            $wch = $c.whenChanged -as [datetime]
            $dates = @($llt, $pls, $wch) | Where-Object { $_ }
            if ($dates.Count -gt 0 -and (($dates | Sort-Object -Descending)[0] -lt $cutoff)) { $skippedStale++; continue }

            $adOs  = [string]$c.OperatingSystem
            $manu = 'Unknown'; $model = ''; $sku = 'Unknown'; $cimName = $null

            # Hardware/edition enrichment via CIM - opt-out (-SkipHardwareInventory)
            # and bounded by a 15s operation timeout so a 500-device estate
            # cannot stall for hours on unreachable hosts (B13).
            if (-not $SkipHardwareInventory) {
                $target = if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name }
                $cim = $null
                try {
                    $cim = New-CimSession -ComputerName $target -OperationTimeoutSec 15 -ErrorAction Stop
                    $cs = Get-CimInstance -CimSession $cim -ClassName Win32_ComputerSystem -OperationTimeoutSec 15 -ErrorAction Stop
                    if ($cs.Manufacturer) { $manu = $cs.Manufacturer.Trim() }
                    if ($cs.Model)        { $model = $cs.Model.Trim() }
                    $osCim = Get-CimInstance -CimSession $cim -ClassName Win32_OperatingSystem -OperationTimeoutSec 15 -ErrorAction Stop
                    if ($osCim.Caption) { $cimName = ($osCim.Caption -replace '(?i)microsoft ', '').Trim() }
                    $sku = switch ([int]$osCim.OperatingSystemSKU) {
                        7  { 'Standard' }      8  { 'Datacenter' }
                        10 { 'Enterprise' }    48 { 'Pro' }
                        4  { 'Enterprise' }    27 { 'Enterprise N' }
                        default {
                            $cap = "$cimName"
                            if     ($cap -match '(?i)datacenter') { 'Datacenter' }
                            elseif ($cap -match '(?i)standard')   { 'Standard' }
                            elseif ($cap -match '(?i)enterprise') { 'Enterprise' }
                            elseif ($cap -match '(?i)\bpro\b')    { 'Pro' }
                            else { 'Unknown' }
                        }
                    }
                } catch {
                    Write-Verbose "CIM unreachable for $target : $($_.Exception.Message)"
                } finally {
                    if ($cim) { Remove-CimSession $cim -ErrorAction SilentlyContinue }
                }
            }

            $osName = if ($cimName) { $cimName } elseif ($adOs) { $adOs } else { 'Windows (OS not reported)' }
            $info = Get-CeOsInfo -OperatingSystem 'Windows' -OsVersion ([string]$c.OperatingSystemVersion) -SkuFamily $sku -OsName $osName
            if (-not $info.FriendlyName -or $info.FriendlyName -eq 'Windows (unknown build)') {
                $info.FriendlyName = $osName
            }
            $lastSeen = $dates | Sort-Object -Descending | Select-Object -First 1

            $onPremRows += [pscustomobject]@{
                DeviceName    = $c.Name
                Manufacturer  = $manu
                Model         = $model
                OS            = $info.FriendlyName
                OperatingSys  = 'Windows'
                SkuFamily     = $sku
                Ownership     = 'On-premises (domain-joined)'
                JoinType      = 'On-prem AD'
                PrimaryUser   = ''
                LastCheckIn   = $lastSeen
                Source        = 'On-premises (AD)'
                IsServer      = $info.IsServer
                SupportStatus = $info.SupportStatus
                SupportEnd    = $(if ($info.SupportEnd) { $info.SupportEnd.ToString('yyyy-MM-dd') } else { '' })
                SupportNote   = $info.SupportNote
            }
        }
        Write-Host ("AD computers: {0} found; {1} included; {2} stale (> {3} wks) skipped." -f `
            $adComputers.Count, @($onPremRows).Count, $skippedStale, $CheckInWindowWeeks) -ForegroundColor Green
    }

    # ---- Unify & de-duplicate (hybrid devices exist in both worlds) ---------
    $cloudByName = @{}
    foreach ($r in $rows) { if ($r.DeviceName) { $cloudByName[$r.DeviceName.ToLower()] = $r } }
    $unified = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) { $unified.Add($r) }
    $dupCount = 0
    foreach ($o in $onPremRows) {
        $key = ([string]$o.DeviceName).ToLower()
        if ($key -and $cloudByName.ContainsKey($key)) {
            $cloudByName[$key].Source = 'Both (Intune + AD)'
            $dupCount++
        } else {
            $unified.Add($o)
        }
    }

    $macos   = @($unified | Where-Object { $_.OperatingSys -eq 'macOS' } | Sort-Object Manufacturer, OS, DeviceName)
    $winAll  = @($unified | Where-Object { $_.OperatingSys -eq 'Windows' })
    $servers = @($winAll | Where-Object { $_.IsServer } | Sort-Object Manufacturer, OS, DeviceName)
    $windows = @($winAll | Where-Object { -not $_.IsServer } | Sort-Object Manufacturer, OS, DeviceName)

    $summarise = {
        param($set)
        @($set | Group-Object Manufacturer, OS, SkuFamily | ForEach-Object {
            $first = $_.Group[0]
            [pscustomobject]@{
                Count = $_.Count; Manufacturer = $first.Manufacturer; OS = $first.OS
                SkuFamily = $first.SkuFamily
                Description = "{0}x {1} {2} {3}" -f $_.Count, $first.Manufacturer, $first.OS, $first.SkuFamily
            }
        } | Sort-Object Manufacturer, OS, SkuFamily)
    }

    # ---- Mobile devices (B10: same check-in window as desktops) -------------
    $mobSelect = @('deviceName','manufacturer','model','operatingSystem','osVersion',
                   'managedDeviceOwnerType','userPrincipalName','lastSyncDateTime') -join ','
    $mobFilter = "lastSyncDateTime ge $cutoffUtcStr and (operatingSystem eq 'Android' or operatingSystem eq 'iOS' or operatingSystem eq 'iPadOS')"
    $mobUri = '{0}?$filter={1}&$select={2}&$top=200' -f $script:CeUri.ManagedDevices,
        [uri]::EscapeDataString($mobFilter), [uri]::EscapeDataString($mobSelect)
    $mobileDevices = @()
    try { $mobileDevices = Get-CeGraphPaged -Uri $mobUri -Area 'ManagedDevices' } catch { }

    $mobileRows = @(foreach ($d in $mobileDevices) {
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
    }) | Sort-Object Make, OS, DeviceName
    $mobileRows = @($mobileRows)

    $mobileSummary = @($mobileRows | Group-Object Make, OS | ForEach-Object {
        $f = $_.Group[0]
        [pscustomobject]@{ Count = $_.Count; Make = $f.Make; OS = $f.OS
                           Description = "{0}x {1} {2}" -f $_.Count, $f.Make, $f.OS }
    } | Sort-Object Make, OS)

    # ---- Source-of-truth analysis (hybrid) ----------------------------------
    $cloudWs  = @($windows | Where-Object { $_.Source -ne 'On-premises (AD)' }).Count
    $onPremWs = @($windows | Where-Object { $_.Source -eq 'On-premises (AD)' }).Count
    $sourceOfTruth = 'Microsoft Intune'
    if ($IsHybrid) {
        if ($onPremWs -gt $cloudWs) {
            $sourceOfTruth = 'Group Policy (GPO)'
            $verdict = ("More workstations are managed on-premises ({0}) than in the cloud ({1}). Group Policy should be considered the primary source of truth for endpoint controls; Intune supplements cloud/hybrid-joined devices." -f $onPremWs, $cloudWs)
        } elseif ($cloudWs -gt $onPremWs) {
            $verdict = ("More workstations are managed in the cloud ({0}) than on-premises ({1}). Microsoft Intune should be considered the primary source of truth; GPO covers the remaining domain-only devices." -f $cloudWs, $onPremWs)
        } else {
            $sourceOfTruth = 'Mixed (GPO + Intune)'
            $verdict = ("Workstations are evenly split between cloud ({0}) and on-premises ({1}). Both GPO and Intune are in scope; confirm there is no conflicting configuration between them." -f $cloudWs, $onPremWs)
        }
    } else {
        $verdict = 'Cloud-only environment: Microsoft Intune is the source of truth for endpoint controls.'
    }

    $eolDevices = @($unified | Where-Object { $_.SupportStatus -eq 'EOL' })

    [pscustomobject]@{
        Unified             = @($unified)
        Windows             = $windows
        Servers             = $servers
        MacOS               = $macos
        Summary             = & $summarise $windows
        ServerSummary       = & $summarise $servers
        Mobile              = $mobileRows
        MobileSummary       = $mobileSummary
        EolDevices          = $eolDevices
        CloudWorkstations   = $cloudWs
        OnPremWorkstations  = $onPremWs
        DuplicatesMerged    = $dupCount
        SkippedStale        = $skippedStale
        SourceOfTruth       = $sourceOfTruth
        DistributionVerdict = $verdict
        CheckInWindowWeeks  = $CheckInWindowWeeks
        CutoffUtc           = $cutoffUtcStr
    }
}

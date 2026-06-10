# Security update management (previously not audited - AUTO-FAIL territory
# under Danzell: high/critical updates within 14 days). Covers Windows Update
# rings (deadline maths via Test-CeUpdateRing), feature/driver/quality update
# profiles, macOS software-update policies, unsupported/EOL operating systems
# from the inventory, hybrid GPO update policies, and the inherently-manual
# third-party patching question.
function Get-CeUpdateCheck {
    [CmdletBinding()]
    param(
        # Inventory object from Get-CeDeviceInventory (for EOL devices).
        $Inventory,
        [object[]]$GpoFindings = @()
    )

    Write-Host 'Reviewing security update management (update rings, deadlines, EOL)...' -ForegroundColor Cyan

    # ---- Update rings --------------------------------------------------------
    $ringRows = @()
    try {
        foreach ($p in @(Get-CeDeviceConfigurations)) {
            if ([string]$p.'@odata.type' -ne '#microsoft.graph.windowsUpdateForBusinessConfiguration') { continue }
            $eval = Test-CeUpdateRing -Ring $p
            $asg  = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.DeviceConfigurations -Id $p.id -Area 'DeviceConfigurations')
            $ringRows += [pscustomobject]@{
                RingName     = $eval.RingName
                Verdict      = $eval.Verdict
                WorstCase    = $(if ($null -ne $eval.MaxDays) { "$($eval.MaxDays) day(s)" } else { 'No deadline' })
                Deferral     = $eval.QualityDeferral
                Deadline     = $(if ($null -ne $eval.Deadline) { $eval.Deadline } else { 'Not set' })
                Grace        = $eval.Grace
                Paused       = $(if ($eval.Paused) { 'YES' } else { 'No' })
                FeatureDefer = $eval.FeatureDeferral
                AutoMode     = $eval.AutomaticMode
                Reason       = $eval.Reason
                Included     = $asg.Included
                Excluded     = $asg.Excluded
                IsAssigned   = $asg.IsAssigned
            }
        }
    } catch { }
    $ringRows = @($ringRows)

    # ---- Feature / driver / quality update profiles --------------------------
    $profileRows = @()
    foreach ($src in @(
        @{ Key = 'featureUpdates'; Uri = $script:CeUri.FeatureUpdateProfiles; Type = 'Feature update profile' }
        @{ Key = 'driverUpdates';  Uri = $script:CeUri.DriverUpdateProfiles;  Type = 'Driver update profile' }
        @{ Key = 'qualityUpdates'; Uri = $script:CeUri.QualityUpdateProfiles; Type = 'Quality update profile (expedite)' }
    )) {
        try {
            foreach ($p in @(Get-CeCollection -Key $src.Key -Uri $src.Uri -Area 'UpdateProfiles')) {
                $desc = @()
                if ($p.featureUpdateVersion)  { $desc += "Target version: $($p.featureUpdateVersion)" }
                if ($p.approvalType)          { $desc += "Approval: $($p.approvalType)" }
                if ($p.expeditedUpdateSettings -and $p.expeditedUpdateSettings.qualityUpdateRelease) { $desc += "Expedited release: $($p.expeditedUpdateSettings.qualityUpdateRelease)" }
                $profileRows += [pscustomobject]@{
                    Type = $src.Type; Name = $p.displayName
                    Detail = $(if ($desc.Count) { $desc -join '; ' } else { 'See policy' })
                }
            }
        } catch { }
    }
    $profileRows = @($profileRows)

    # ---- macOS software updates ----------------------------------------------
    $macUpdateRows = @()
    try {
        foreach ($p in @(Get-CeDeviceConfigurations)) {
            if ([string]$p.'@odata.type' -ne '#microsoft.graph.macOSSoftwareUpdateConfiguration') { continue }
            $asg = Get-CeAssignmentSummary (Get-CePolicyAssignments -BaseUri $script:CeUri.DeviceConfigurations -Id $p.id -Area 'DeviceConfigurations')
            $macUpdateRows += [pscustomobject]@{
                Type = 'macOS software update policy'; Name = $p.displayName
                Detail = ("Critical: {0}; Config-data: {1}; Firmware: {2}; All other: {3}" -f `
                    $p.criticalUpdateBehavior, $p.configDataUpdateBehavior, $p.firmwareUpdateBehavior, $p.allOtherUpdateBehavior)
                Included = $asg.Included; Excluded = $asg.Excluded
            }
        }
    } catch { }
    $macUpdateRows = @($macUpdateRows)

    # ---- Hybrid GPO update policies ------------------------------------------
    $gpoRows = @()
    foreach ($gf in @($GpoFindings | Where-Object { $_.Control -eq 'Security updates' })) {
        $gpoRows += [pscustomobject]@{
            Type = 'On-prem GPO'; Name = $gf.GPO
            Detail = ("{0} = {1} [{2}]" -f $gf.Setting, $gf.Value, $gf.LinkedOUs)
        }
    }
    $gpoRows = @($gpoRows)

    $areaFailed = Test-CeAreaFailed -Area @('DeviceConfigurations', 'UpdateProfiles')

    # ---- Verdict: 14-day patching --------------------------------------------
    $assignedRings = @($ringRows | Where-Object { $_.IsAssigned })
    $failRings   = @($assignedRings | Where-Object { $_.Verdict -eq 'Fail' })
    $passRings   = @($assignedRings | Where-Object { $_.Verdict -eq 'Pass' })
    $manualRings = @($assignedRings | Where-Object { $_.Verdict -eq 'Manual' })

    if ($failRings.Count -gt 0) {
        $ringStatus = 'Fail'
        $ringReason = ("{0} assigned update ring(s) allow more than 14 days (or are paused): {1}. Danzell auto-fails estates that cannot apply high/critical updates within 14 days." -f `
            $failRings.Count, (($failRings | ForEach-Object { "$($_.RingName) ($($_.WorstCase))" }) -join '; '))
    } elseif ($passRings.Count -gt 0 -and $manualRings.Count -eq 0) {
        $ringStatus = 'Pass'
        $ringReason = ("All {0} assigned update ring(s) enforce installation within 14 days" -f $passRings.Count)
    } elseif ($passRings.Count + $manualRings.Count -gt 0) {
        $ringStatus = 'Manual'
        $ringReason = ("{0} ring(s) meet the 14-day requirement; {1} have no enforced deadline - verify those devices actually install updates within 14 days" -f $passRings.Count, $manualRings.Count)
    } elseif ($ringRows.Count -gt 0) {
        $ringStatus = 'Manual'
        $ringReason = 'Update rings exist but none is assigned - verify how Windows updates are actually managed'
    } elseif ($gpoRows.Count -gt 0) {
        $ringStatus = 'Manual'
        $ringReason = 'No Intune update rings; Windows Update is configured via on-prem GPO - verify the GPO enforces installation within 14 days (see Security updates tab)'
    } elseif ($areaFailed) {
        $ringStatus = 'Unknown'
        $ringReason = 'Policy reads failed - update management cannot be verified (see Run info tab)'
    } else {
        $ringStatus = 'Fail'
        $ringReason = 'No Windows Update ring, WUfB policy or GPO update policy was found. Unmanaged updates cannot evidence the 14-day requirement.'
    }

    # ---- Verdict: unsupported / EOL operating systems -------------------------
    $eol = @()
    if ($Inventory) { $eol = @($Inventory.EolDevices) }
    if ($eol.Count -gt 0) {
        $eolStatus = 'Fail'
        $eolNames = ($eol | Group-Object OS | ForEach-Object { "{0}x {1}" -f $_.Count, $_.Name }) -join '; '
        $eolReason = ("{0} in-scope device(s) run an OS that no longer receives security updates: {1}. Unsupported software in scope is a CE FAIL - upgrade, replace, or remove from scope with justification." -f $eol.Count, $eolNames)
    } elseif ($Inventory -and @($Inventory.Unified).Count -gt 0) {
        $eolStatus = 'Pass'
        $eolReason = ("All {0} in-scope device(s) run vendor-supported operating systems (lifecycle table dated - see Device list tab for per-device support end dates)" -f @($Inventory.Unified).Count)
    } else {
        $eolStatus = 'Unknown'
        $eolReason = 'No device inventory available to evaluate OS support status'
    }

    # ---- Verdict: macOS updates ----------------------------------------------
    $macCount = 0
    if ($Inventory) { $macCount = @($Inventory.MacOS).Count }
    if ($macCount -eq 0) {
        $macStatus = 'Manual'; $macReason = 'No macOS devices in scope - not applicable, no action needed.'
    } elseif (@($macUpdateRows).Count -gt 0) {
        $macStatus = 'Pass'; $macReason = ("{0} macOS software-update policy/policies configured" -f @($macUpdateRows).Count)
    } else {
        $macStatus = 'Manual'; $macReason = ("{0} macOS device(s) in scope but no Intune software-update policy found - verify Macs install updates within 14 days (automatic updates on, or another management tool)" -f $macCount)
    }

    $results = @(
        New-CeCheckResult -Control 'Security update management' -CheckId 'CE-SU-01' `
            -Title 'High/critical updates installed within 14 days (Windows)' `
            -Status $ringStatus -Reason $ringReason `
            -Evidence ("{0} update ring(s): {1} pass, {2} fail, {3} no deadline" -f $ringRows.Count, $passRings.Count, $failRings.Count, $manualRings.Count) `
            -DetailSheet 'Security updates'
        New-CeCheckResult -Control 'Security update management' -CheckId 'CE-SU-02' `
            -Title 'All in-scope operating systems are vendor-supported' `
            -Status $eolStatus -Reason $eolReason `
            -Evidence ("{0} EOL device(s)" -f $eol.Count) -DetailSheet 'Security updates'
        New-CeCheckResult -Control 'Security update management' -CheckId 'CE-SU-03' `
            -Title 'macOS devices receive updates within 14 days' `
            -Status $macStatus -Reason $macReason -DetailSheet 'Security updates'
        New-CeCheckResult -Control 'Security update management' -CheckId 'CE-SU-04' `
            -Title 'Third-party applications patched within 14 days' `
            -Status 'Manual' `
            -Reason 'Application patching (browsers, PDF readers, line-of-business apps) cannot be fully verified from Intune policy alone. Evidence the patching mechanism: Winget/Store auto-update, a third-party patching tool, or documented manual process meeting the 14-day requirement. All software must be licensed and supported.' `
            -DetailSheet 'Security updates'
    )

    [pscustomobject]@{
        Results     = $results
        RingRows    = $ringRows
        ProfileRows = $profileRows
        MacRows     = $macUpdateRows
        GpoRows     = $gpoRows
        EolDevices  = $eol
    }
}

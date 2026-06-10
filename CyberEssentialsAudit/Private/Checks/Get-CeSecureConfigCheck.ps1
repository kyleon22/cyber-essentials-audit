# Secure configuration items beyond AutoPlay: device locking (PIN/password to
# unlock) evidenced from compliance policies, and the inherently-manual
# default-credentials question.
function Get-CeSecureConfigCheck {
    [CmdletBinding()]
    param()

    Write-Host 'Reviewing device-locking compliance policies...' -ForegroundColor Cyan
    $lockRows = @()
    try {
        foreach ($p in @(Get-CeCompliancePolicies)) {
            $type = [string]$p.'@odata.type'
            $plat = switch -Regex ($type) {
                '(?i)windows10' { 'Windows' }
                '(?i)macOS'     { 'macOS' }
                '(?i)android'   { 'Android' }
                '(?i)ios'       { 'iOS/iPadOS' }
                default         { $type -replace '#microsoft\.graph\.', '' }
            }
            $lockBits = @()
            foreach ($prop in @('passwordRequired', 'passcodeRequired')) {
                $v = $null
                try { $v = $p.$prop } catch { }
                if ("$v" -match '(?i)true') { $lockBits += "$prop = true" }
            }
            foreach ($prop in @('passwordMinimumLength', 'passcodeMinimumLength', 'passwordMinutesOfInactivityBeforeLock', 'passcodeMinutesOfInactivityBeforeLock')) {
                $v = $null
                try { $v = $p.$prop } catch { }
                if ($null -ne $v -and "$v" -ne '') { $lockBits += "$prop = $v" }
            }
            if ($lockBits.Count -eq 0) { continue }
            $asg = Get-CeAssignmentSummary $p.assignments
            $lockRows += [pscustomobject]@{
                Platform = $plat; PolicyName = [string]$p.displayName
                Settings = ($lockBits -join '; ')
                Included = $asg.Included; Excluded = $asg.Excluded
                IsAssigned = $asg.IsAssigned
            }
        }
    } catch { }
    $lockRows = @($lockRows)
    $assigned = @($lockRows | Where-Object { $_.IsAssigned })
    $areaFailed = Test-CeAreaFailed -Area @('CompliancePolicies')

    if ($assigned.Count -gt 0) {
        $lockStatus = 'Pass'
        $lockReason = ("{0} assigned compliance policy/policies require a password/PIN to unlock: {1}" -f $assigned.Count, (($assigned | Select-Object -First 5 | ForEach-Object { $_.PolicyName }) -join '; '))
    } elseif ($lockRows.Count -gt 0) {
        $lockStatus = 'Manual'
        $lockReason = 'Device-locking compliance settings exist but none is assigned - verify devices actually require unlock credentials'
    } elseif ($areaFailed) {
        $lockStatus = 'Unknown'
        $lockReason = 'Compliance policies could not be read - device locking cannot be verified'
    } else {
        $lockStatus = 'Fail'
        $lockReason = 'No compliance policy requiring device-unlock credentials (PIN/password/biometric) was found'
    }

    [pscustomobject]@{
        Results = @(
            New-CeCheckResult -Control 'Secure configuration' -CheckId 'CE-SC-02' `
                -Title 'Device locking enforced (PIN/password to unlock)' `
                -Status $lockStatus -Reason $lockReason `
                -Evidence ("{0} device-lock policy/policies; {1} assigned" -f $lockRows.Count, $assigned.Count) `
                -DetailSheet 'Mobile devices'
            New-CeCheckResult -Control 'Secure configuration' -CheckId 'CE-SC-03' `
                -Title 'Default credentials changed and unnecessary software removed' `
                -Status 'Manual' `
                -Reason 'Default/vendor passwords (network kit, appliances, pre-installed admin accounts) and removal of unused software/services cannot be verified via Graph. Confirm during the assessment walk-through.' `
        )
        LockRows = $lockRows
    }
}

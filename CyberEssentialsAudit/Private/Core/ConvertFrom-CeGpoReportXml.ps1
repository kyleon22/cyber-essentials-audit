# Structured GPO report parsing (fixes B6). The previous implementation
# regex-matched the ENTIRE report XML, so '(?i)password' hit schema text and
# defaults in virtually every GPO. This parses the actual setting nodes:
#   * Account policy nodes        -> Password / lockout (MinimumPasswordLength,
#                                    LockoutBadCount, ...)
#   * *Profile/EnableFirewall     -> Firewall (per Domain/Private/Public profile)
#   * AppLocker RuleCollection &
#     Software Restriction nodes  -> Application whitelisting
#   * Admin-template Policy nodes -> AutoPlay/AutoRun, Malware protection,
#     (Name + State, i.e. settings    Security updates (matched on the CONFIGURED
#     actually configured)            policy display name only)
#
# XPath uses local-name() so the GPO report namespaces (q1:, q2:, ...) are
# irrelevant. Pure function - testable with fixture XML.
function ConvertFrom-CeGpoReportXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][xml]$Xml,
        [string]$GpoName = '',
        [string]$GpoStatus = ''
    )

    $findings = New-Object System.Collections.Generic.List[object]

    # Linked OUs from the GPO's own <LinksTo> elements.
    $links = @()
    foreach ($n in $Xml.SelectNodes("//*[local-name()='LinksTo']/*[local-name()='SOMPath']")) {
        if ($n.InnerText) { $links += $n.InnerText }
    }
    $linkStr = if ($links.Count) { ($links | Sort-Object -Unique) -join '; ' } else { 'Not linked' }

    function Add-Finding {
        param([string]$Control, [string]$Setting, [string]$Value)
        $findings.Add([pscustomobject]@{
            Control   = $Control
            GPO       = $GpoName
            Setting   = $Setting
            Value     = $Value
            Status    = $GpoStatus
            LinkedOUs = $linkStr
        })
    }

    # ---- Account policy (password & lockout) -------------------------------
    foreach ($acct in $Xml.SelectNodes("//*[local-name()='Account']")) {
        $name = $null; $value = $null
        foreach ($child in $acct.ChildNodes) {
            switch ($child.LocalName) {
                'Name'           { $name = $child.InnerText }
                'SettingNumber'  { $value = $child.InnerText }
                'SettingBoolean' { $value = $child.InnerText }
            }
        }
        if ($name) { Add-Finding -Control 'Password / lockout' -Setting $name -Value "$value" }
    }

    # ---- Firewall profiles --------------------------------------------------
    foreach ($prof in $Xml.SelectNodes("//*[local-name()='DomainProfile' or local-name()='PrivateProfile' or local-name()='PublicProfile']")) {
        $enable = $prof.SelectSingleNode("*[local-name()='EnableFirewall']/*[local-name()='Value']")
        if ($null -ne $enable) {
            Add-Finding -Control 'Firewall' -Setting ("{0}/EnableFirewall" -f $prof.LocalName) -Value $enable.InnerText
        }
    }

    # ---- AppLocker / Software Restriction Policies --------------------------
    foreach ($rc in $Xml.SelectNodes("//*[local-name()='RuleCollection']")) {
        $type = $rc.GetAttribute('Type')
        $mode = $rc.GetAttribute('EnforcementMode')
        if ($type) {
            Add-Finding -Control 'Application whitelisting' -Setting ("AppLocker rule collection: {0}" -f $type) -Value $(if ($mode) { $mode } else { 'NotConfigured' })
        }
    }
    if ($Xml.SelectNodes("//*[local-name()='SoftwareRestrictionPolicies']").Count -gt 0) {
        Add-Finding -Control 'Application whitelisting' -Setting 'Software Restriction Policies' -Value 'Configured'
    }

    # ---- Administrative-template policies (configured Name + State) ---------
    $policyPatterns = @(
        # Separator-tolerant on purpose ("AutoPlay", "Auto Play", "auto-run").
        # Keep in sync with $script:CeAutoplayPattern in ConvertTo-CeAutoplaySetting.ps1.
        @{ Control = 'AutoPlay/AutoRun';   Pattern = '(?i)auto[\s\-_]?(play|run)' }
        @{ Control = 'Malware protection'; Pattern = '(?i)defender|antivirus|virus|real-?time protection' }
        @{ Control = 'Security updates';   Pattern = '(?i)automatic updates|windows update|quality updates|feature updates' }
        @{ Control = 'Firewall';           Pattern = '(?i)firewall' }
    )
    foreach ($pol in $Xml.SelectNodes("//*[local-name()='Policy']")) {
        $name = $null; $state = $null
        foreach ($child in $pol.ChildNodes) {
            switch ($child.LocalName) {
                'Name'  { if (-not $name) { $name = $child.InnerText } }
                'State' { if (-not $state) { $state = $child.InnerText } }
            }
        }
        if (-not $name) { continue }
        foreach ($pp in $policyPatterns) {
            if ($name -match $pp.Pattern) {
                Add-Finding -Control $pp.Control -Setting $name -Value $(if ($state) { $state } else { 'Configured' })
                break
            }
        }
    }

    # Plain (enumerated) return on purpose: every consumer wraps with @(...).
    return $findings.ToArray()
}

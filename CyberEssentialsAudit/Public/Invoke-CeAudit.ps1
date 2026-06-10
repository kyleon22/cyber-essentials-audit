<#
.SYNOPSIS
    Runs the Cyber Essentials readiness audit and returns a typed result object.

.DESCRIPTION
    Read-only audit of a Microsoft 365 / Intune tenant (and optionally on-prem
    Active Directory + Group Policy in Hybrid mode). Every CE sub-requirement
    is evaluated to Pass / Fail / Manual / Unknown. Render the result with
    Export-CeReport (Excel and/or JSON).

    Non-interactive by design (suitable for scheduled runs with -AuthMode App);
    the Start-CyberEssentialsAudit.ps1 launcher provides the interactive TUI.

.EXAMPLE
    $audit = Invoke-CeAudit -Mode CloudOnly
    Export-CeReport -Audit $audit -Path C:\Reports\tenant.xlsx

.EXAMPLE
    Invoke-CeAudit -AuthMode App -TenantId $tid -ClientId $appId -CertificateThumbprint $thumb |
        Export-CeReport -Path .\audit.xlsx -Format Both
#>
function Invoke-CeAudit {
    [CmdletBinding()]
    param(
        [ValidateSet('CloudOnly', 'Hybrid')]
        [string]$Mode = 'CloudOnly',

        [string]$TenantId,

        # Devices not seen within this window are dropped (B18: validated).
        [ValidateRange(1, 52)]
        [int]$CheckInWindowWeeks = 6,

        # Hybrid: target DC and explicit credential (defaults to integrated).
        [string]$DomainController,
        [System.Management.Automation.PSCredential]$ADCredential,

        # Hybrid: skip the per-device CIM hardware/edition enrichment (B13).
        [switch]$SkipHardwareInventory,

        # Enabled+licensed accounts with no sign-in for this many days are
        # flagged as stale (leaver-process evidence).
        [ValidateRange(7, 365)]
        [int]$StaleAccountDays = 90,

        # Auth: Delegated (interactive) or App (certificate, unattended).
        [ValidateSet('Delegated', 'App')]
        [string]$AuthMode = 'Delegated',
        [string]$ClientId,
        [string]$CertificateThumbprint,

        # Write a Start-Transcript log of the run to this path.
        [string]$TranscriptPath
    )

    $started = [datetime]::UtcNow
    $transcriptStarted = $false
    if ($TranscriptPath) {
        try { Start-Transcript -Path $TranscriptPath -ErrorAction Stop | Out-Null; $transcriptStarted = $true }
        catch { Write-Warning "Could not start transcript: $($_.Exception.Message)" }
    }

    Initialize-CeSession
    $IsHybrid = ($Mode -eq 'Hybrid')

    try {
        # ---- Connect --------------------------------------------------------
        Write-Host 'Signing in to Microsoft Graph...' -ForegroundColor Cyan
        $ctx = Connect-CeGraph -AuthMode $AuthMode -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint
        Write-Host ("Connected to tenant: {0} as {1}" -f $ctx.TenantId, $(if ($ctx.Account) { $ctx.Account } else { "$ClientId (app)" })) -ForegroundColor Green

        # ---- Hybrid: on-prem AD ----------------------------------------------
        $AdAvailable = $false
        $adParams = @{}
        if ($IsHybrid) {
            Write-Host 'Hybrid mode: connecting to on-premises Active Directory...' -ForegroundColor Cyan
            $missingMods = @()
            foreach ($m in @('ActiveDirectory', 'GroupPolicy')) {
                if (-not (Get-Module -ListAvailable -Name $m)) { $missingMods += $m }
            }
            if ($missingMods.Count) {
                Write-Warning ("Module(s) not found: {0}. On-premises checks will be skipped (they ship with the AD DS / GPMC role, or install RSAT)." -f ($missingMods -join ', '))
            } else {
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    Import-Module GroupPolicy     -ErrorAction Stop
                    if ($DomainController) { $adParams['Server']     = $DomainController }
                    if ($ADCredential)     { $adParams['Credential'] = $ADCredential }
                    $domInfo = Get-ADDomain @adParams -ErrorAction Stop
                    $AdAvailable = $true
                    Write-Host ("Connected to AD domain: {0}" -f $domInfo.DNSRoot) -ForegroundColor Green
                } catch {
                    Write-Warning "Could not connect to Active Directory: $($_.Exception.Message). On-premises checks will be skipped."
                }
            }
        }

        # ---- Shared reads -----------------------------------------------------
        $securityDefaultsOn = $false
        try {
            $sd = Get-CeGraphJson -Uri $script:CeUri.SecurityDefaults -Area 'SecurityDefaults'
            $securityDefaultsOn = [bool]$sd.isEnabled
        } catch { }

        # ---- Inventory & GPO --------------------------------------------------
        $inventory = Get-CeDeviceInventory -CheckInWindowWeeks $CheckInWindowWeeks `
            -IsHybrid $IsHybrid -AdAvailable $AdAvailable -AdParams $adParams `
            -SkipHardwareInventory:$SkipHardwareInventory

        $gpo = $null
        $gpoFindings = @()
        if ($IsHybrid -and $AdAvailable) {
            $gpo = Get-CeGpoReview -AdParams $adParams
            $gpoFindings = @($gpo.Findings)
        }

        # ---- Checks ------------------------------------------------------------
        $mfa        = Get-CeMfaCheck -SecurityDefaultsOn $securityDefaultsOn
        $firewall   = Get-CeFirewallCheck -GpoFindings $gpoFindings
        $malware    = Get-CeMalwareCheck -GpoFindings $gpoFindings -HasMacs (@($inventory.MacOS).Count -gt 0)
        $updates    = Get-CeUpdateCheck -Inventory $inventory -GpoFindings $gpoFindings
        $autoplay   = Get-CeAutoplayCheck -GpoFindings $gpoFindings
        $accounts   = Get-CeAccountsCheck -StaleAccountDays $StaleAccountDays
        $secureCfg  = Get-CeSecureConfigCheck
        $appControl = Get-CeAppControlCheck -GpoFindings $gpoFindings
        $password   = Get-CePasswordCheck -SecurityDefaultsOn $securityDefaultsOn `
            -IsHybrid $IsHybrid -AdAvailable $AdAvailable -AdParams $adParams -GpoFindings $gpoFindings
        $privileged = Get-CePrivilegedUserCheck -IsHybrid $IsHybrid -AdAvailable $AdAvailable -AdParams $adParams
        $mobile     = Get-CeMobileCheck -Inventory $inventory

        # macOS firewall check is Fail only when Macs are actually in scope.
        foreach ($r in @($firewall.Results)) {
            if ($r.CheckId -eq 'CE-FW-02' -and @($inventory.MacOS).Count -eq 0 -and $r.Status -eq 'Fail') {
                $r.Status = 'Manual'
                $r.Reason = 'No macOS devices in scope - not applicable, no action needed.'
            }
        }

        # ---- Scope -------------------------------------------------------------
        $orgName = ''
        $domains = ''
        try {
            $org = Get-CeGraphPaged -Uri $script:CeUri.Organization -Area 'Organization'
            if (@($org).Count) {
                $orgName = [string]$org[0].displayName
                $domains = (@($org[0].verifiedDomains | ForEach-Object { $_.name }) -join ', ')
            }
        } catch { }
        $scopeDetails = [ordered]@{
            'Organisation'                    = $orgName
            'Tenant id'                       = [string]$ctx.TenantId
            'Verified domains'                = $domains
            'Audit mode'                      = $Mode
            'Check-in window'                 = ("{0} weeks (devices not seen since {1} are excluded)" -f $CheckInWindowWeeks, $inventory.CutoffUtc)
            'Windows workstations'            = @($inventory.Windows).Count
            'Servers'                         = @($inventory.Servers).Count
            'macOS devices'                   = @($inventory.MacOS).Count
            'Mobile devices (Android/iOS)'    = @($inventory.Mobile).Count
            'Cloud-managed workstations'      = $inventory.CloudWorkstations
            'On-prem-managed workstations'    = $inventory.OnPremWorkstations
            'Stale devices excluded'          = $inventory.SkippedStale
            'Duplicates merged (Intune + AD)' = $inventory.DuplicatesMerged
            'Source of truth'                 = $inventory.SourceOfTruth
            'Total user accounts'             = $accounts.TotalUsers
        }
        $scopeResult = New-CeCheckResult -Control 'Scope' -CheckId 'CE-SCOPE-01' `
            -Title 'Whole-organisation scope declared' -Status 'Manual' `
            -Reason 'Danzell requires a detailed scope description (published on the certificate) and per-legal-entity declarations. The Scope tab pre-fills the technical facts; the organisational declaration must be completed by the applicant.' `
            -Evidence ("{0} devices, {1} users, {2} domains" -f @($inventory.Unified).Count, $accounts.TotalUsers, (@($domains -split ',')).Count) `
            -DetailSheet 'Scope'

        # ---- Aggregate -----------------------------------------------------------
        $allChecks = @($scopeResult) + @($firewall.Results) + @($autoplay.Results) + @($secureCfg.Results) +
                     @($mobile.Results) + @($mfa.Results) + @($accounts.Results) + @($password.Results) +
                     @($privileged.Results) + @($malware.Results) + @($appControl.Results) + @($updates.Results)

        $ctx2 = Get-MgContext
        $runInfo = [pscustomobject]@{
            ToolVersion        = '2.0.0'
            StartedUtc         = $started
            FinishedUtc        = [datetime]::UtcNow
            Account            = $(if ($ctx2 -and $ctx2.Account) { [string]$ctx2.Account } else { "$ClientId (app-only)" })
            AuthMode           = $AuthMode
            TenantId           = [string]$ctx.TenantId
            Mode               = $Mode
            CheckInWindowWeeks = $CheckInWindowWeeks
            Scopes             = @($(if ($ctx2) { $ctx2.Scopes } else { @() }))
            AdAvailable        = $(if ($IsHybrid) { "$AdAvailable" } else { 'n/a (cloud-only)' })
            GraphErrors        = @($script:Ce.GraphErrors.ToArray())
            GpoReviewed        = $(if ($gpo) { $gpo.Reviewed } else { 0 })
        }

        $overall = if (@($allChecks | Where-Object { $_.Status -eq 'Fail' }).Count) { 'Fail' }
                   elseif (@($allChecks | Where-Object { $_.Status -eq 'Unknown' }).Count) { 'Unknown' }
                   else { 'Pass (manual items outstanding)' }

        $audit = [pscustomobject]@{
            PSTypeName = 'CyberEssentialsAudit.AuditResult'
            RunInfo    = $runInfo
            Overall    = $overall
            Checks     = @($allChecks)
            Inventory  = $inventory
            Scope      = [pscustomobject]@{ Details = $scopeDetails }
            Sections   = [pscustomobject]@{
                Mfa          = $mfa
                Firewall     = $firewall
                Malware      = $malware
                Updates      = $updates
                Autoplay     = $autoplay
                Accounts     = $accounts
                SecureConfig = $secureCfg
                AppControl   = $appControl
                Password     = $password
                Privileged   = $privileged
                Mobile       = $mobile
                Gpo          = $gpo
            }
        }

        Write-Host ''
        Write-Host ("Audit complete. {0} checks: {1} Pass, {2} Fail, {3} Manual, {4} Unknown." -f `
            @($allChecks).Count,
            @($allChecks | Where-Object { $_.Status -eq 'Pass' }).Count,
            @($allChecks | Where-Object { $_.Status -eq 'Fail' }).Count,
            @($allChecks | Where-Object { $_.Status -eq 'Manual' }).Count,
            @($allChecks | Where-Object { $_.Status -eq 'Unknown' }).Count) -ForegroundColor Green

        return $audit
    }
    finally {
        Disconnect-CeGraph
        if ($transcriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
    }
}

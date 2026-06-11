# Excel rendering layer (ImportExcel / EPPlus - no Office install needed, runs
# on servers and DCs). Collection is fully decoupled: this file only consumes
# the audit result object. Every tenant-controlled string passes through
# Protect-CeCellText (B1).

# ----- shared address/layout helpers ---------------------------------------- #
# ExcelRange is enumerable, so PowerShell treats $ws.Cells[$r,$c] as array
# slicing. Addressing by string ("A1") always hits the .NET string indexer.
function Get-CeColLetter {
    param([int]$n)
    $s = ''
    while ($n -gt 0) { $m = ($n - 1) % 26; $s = [char](65 + $m) + $s; $n = [int](($n - $m) / 26) }
    return $s
}
function Get-CeAddr  { param([int]$r, [int]$c) ('{0}{1}' -f (Get-CeColLetter $c), $r) }
function Get-CeRange { param([int]$r1, [int]$c1, [int]$r2, [int]$c2) ('{0}:{1}' -f (Get-CeAddr $r1 $c1), (Get-CeAddr $r2 $c2)) }

function Export-CeWorkbook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Audit,
        [Parameter(Mandatory)][string]$Path
    )

    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
    $headerFill  = [System.Drawing.Color]::FromArgb(68, 84, 106)
    $sectionFill = [System.Drawing.Color]::FromArgb(189, 215, 238)
    $whiteFont   = [System.Drawing.Color]::White
    $redFont     = [System.Drawing.Color]::Red
    $greenFont   = [System.Drawing.Color]::FromArgb(0, 128, 0)
    $statusFills = @{
        Pass    = [System.Drawing.Color]::FromArgb(198, 239, 206)   # green
        Fail    = [System.Drawing.Color]::FromArgb(255, 199, 206)   # red
        Manual  = [System.Drawing.Color]::FromArgb(255, 235, 156)   # amber
        Unknown = [System.Drawing.Color]::FromArgb(217, 217, 217)   # grey
    }
    $solid = [OfficeOpenXml.Style.ExcelFillStyle]::Solid

    $pkg = $null
    try {
        $pkg = New-Object OfficeOpenXml.ExcelPackage ([System.IO.FileInfo]$Path)

        function Set-CeTitle {
            param($Ws, [int]$RowIndex, [int]$Span, [string]$Text, $Fill)
            $Ws.Cells[(Get-CeAddr $RowIndex 1)].Value = $Text
            $Ws.Cells[(Get-CeAddr $RowIndex 1)].Style.Font.Bold = $true
            $Ws.Cells[(Get-CeAddr $RowIndex 1)].Style.Font.Size = 12
            $rng = $Ws.Cells[(Get-CeRange $RowIndex 1 $RowIndex $Span)]
            $rng.Style.Fill.PatternType = $solid
            $rng.Style.Fill.BackgroundColor.SetColor($Fill)
            $rng.Style.Font.Color.SetColor($whiteFont)
        }

        function Write-CeTable {
            param($Ws, [ref]$RowRef, [string[]]$Headers, [object[]]$Data, [string[]]$Props)
            $r = $RowRef.Value
            for ($c = 0; $c -lt $Headers.Count; $c++) {
                $cell = $Ws.Cells[(Get-CeAddr $r ($c + 1))]
                $cell.Value = $Headers[$c]
                $cell.Style.Font.Bold = $true
                $cell.Style.Fill.PatternType = $solid
                $cell.Style.Fill.BackgroundColor.SetColor($headerFill)
                $cell.Style.Font.Color.SetColor($whiteFont)
            }
            $r++
            foreach ($item in $Data) {
                for ($c = 0; $c -lt $Headers.Count; $c++) {
                    $val = $item.$($Props[$c])
                    if ($val -is [datetime]) { $val = $val.ToString('yyyy-MM-dd HH:mm') }
                    $Ws.Cells[(Get-CeAddr $r ($c + 1))].Value = Protect-CeCellText ([string]$val)
                }
                $r++
            }
            $RowRef.Value = $r
        }

        function Write-CeKeyValue {
            param($Ws, [ref]$RowRef, $Pairs)
            $r = $RowRef.Value
            foreach ($k in $Pairs.Keys) {
                $Ws.Cells[(Get-CeAddr $r 1)].Value = Protect-CeCellText ([string]$k)
                $Ws.Cells[(Get-CeAddr $r 1)].Style.Font.Bold = $true
                $Ws.Cells[(Get-CeAddr $r 2)].Value = Protect-CeCellText ([string]$Pairs[$k])
                $r++
            }
            $RowRef.Value = $r
        }

        function Write-CeBanner {
            param($Ws, [ref]$RowRef, [string]$Text, [int]$Span = 6, $FontColor = $null, [int]$Height = 45)
            $r = $RowRef.Value
            $Ws.Cells[(Get-CeAddr $r 1)].Value = $Text
            $Ws.Cells[(Get-CeAddr $r 1)].Style.Font.Bold = $true
            if ($FontColor) { $Ws.Cells[(Get-CeAddr $r 1)].Style.Font.Color.SetColor($FontColor) }
            $Ws.Cells[(Get-CeRange $r 1 $r $Span)].Merge = $true
            $Ws.Cells[(Get-CeAddr $r 1)].Style.WrapText = $true
            $Ws.Row($r).Height = $Height
            $RowRef.Value = $r + 1
        }

        # AutoFit can fail on Server Core (no GDI+); never abort over it.
        function Invoke-CeAutoFit { param($Ws) try { $Ws.Cells.AutoFitColumns() } catch { } }

        # ================================================================= #
        #  1. SUMMARY - one RAG row per CE sub-requirement                  #
        # ================================================================= #
        $sum = $pkg.Workbook.Worksheets.Add('Summary')
        $row = 1
        Set-CeTitle -Ws $sum -RowIndex $row -Span 6 -Text 'CYBER ESSENTIALS READINESS SUMMARY' -Fill $sectionFill
        $row += 1
        $ref = [ref]$row
        Write-CeBanner -Ws $sum -RowRef $ref -Span 6 -Height 30 -Text ("Tenant: {0} | Mode: {1} | Run: {2:yyyy-MM-dd HH:mm} UTC | Question set: Danzell v3.3 (verify wording against the published set)" -f `
            $Audit.RunInfo.TenantId, $Audit.RunInfo.Mode, $Audit.RunInfo.StartedUtc)
        $row = $ref.Value + 1

        $counts = @{}
        foreach ($s in @('Pass', 'Fail', 'Manual', 'Unknown')) {
            $counts[$s] = @($Audit.Checks | Where-Object { $_.Status -eq $s }).Count
        }
        $sum.Cells[(Get-CeAddr $row 1)].Value = ("Automated verdicts: {0} Pass | {1} Fail | {2} Manual check required | {3} Unknown (could not verify)" -f $counts['Pass'], $counts['Fail'], $counts['Manual'], $counts['Unknown'])
        $sum.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true
        $row += 2

        $headers = @('CE control', 'Check', 'Verdict', 'Why', 'Evidence', 'Detail tab')
        for ($c = 0; $c -lt $headers.Count; $c++) {
            $cell = $sum.Cells[(Get-CeAddr $row ($c + 1))]
            $cell.Value = $headers[$c]
            $cell.Style.Font.Bold = $true
            $cell.Style.Fill.PatternType = $solid
            $cell.Style.Fill.BackgroundColor.SetColor($headerFill)
            $cell.Style.Font.Color.SetColor($whiteFont)
        }
        $row++

        # Order rows by canonical control order, then check id.
        $orderedChecks = @($Audit.Checks | Sort-Object `
            @{ Expression = { $idx = $script:CeControlOrder.IndexOf($_.Control); if ($idx -lt 0) { 99 } else { $idx } } },
            @{ Expression = { $_.CheckId } })
        foreach ($chk in $orderedChecks) {
            $sum.Cells[(Get-CeAddr $row 1)].Value = $chk.Control
            $sum.Cells[(Get-CeAddr $row 2)].Value = ("{0}  {1}" -f $chk.CheckId, $chk.Title)
            $vCell = $sum.Cells[(Get-CeAddr $row 3)]
            $vCell.Value = $(if ($chk.Status -eq 'Manual') { 'Manual check' } else { $chk.Status })
            $vCell.Style.Font.Bold = $true
            if ($statusFills.ContainsKey($chk.Status)) {
                $vCell.Style.Fill.PatternType = $solid
                $vCell.Style.Fill.BackgroundColor.SetColor($statusFills[$chk.Status])
            }
            $sum.Cells[(Get-CeAddr $row 4)].Value = Protect-CeCellText ([string]$chk.Reason)
            $sum.Cells[(Get-CeAddr $row 4)].Style.WrapText = $true
            $sum.Cells[(Get-CeAddr $row 5)].Value = Protect-CeCellText ([string]$chk.Evidence)
            $sum.Cells[(Get-CeAddr $row 6)].Value = $chk.DetailSheet
            $row++
        }
        $row++
        $ref = [ref]$row
        Write-CeBanner -Ws $sum -RowRef $ref -Span 6 -Height 45 -Text 'Verdict semantics: Pass/Fail are judged from tenant data alone. "Manual check" items CANNOT be automated and must be evidenced by the assessor. "Unknown" means a required API call failed (see Run info tab) - it is never an implicit pass.'
        Invoke-CeAutoFit $sum
        $sum.Column(2).Width = 55
        $sum.Column(4).Width = 90
        $sum.Column(5).Width = 45

        # ================================================================= #
        #  2. SCOPE                                                          #
        # ================================================================= #
        $sc = $pkg.Workbook.Worksheets.Add('Scope')
        $row = 1
        Set-CeTitle -Ws $sc -RowIndex $row -Span 2 -Text 'ASSESSMENT SCOPE (Danzell requires a detailed scope description)' -Fill $sectionFill
        $row += 2
        $ref = [ref]$row
        Write-CeKeyValue -Ws $sc -RowRef $ref -Pairs $Audit.Scope.Details
        $row = $ref.Value + 1
        $ref = [ref]$row
        Write-CeBanner -Ws $sc -RowRef $ref -Span 2 -Height 60 -Text 'Complete before submission: legal entity name(s) covered, whether the scope is "whole organisation", any network segregation used to descope, home-worker counts, and cloud services in use. Danzell publishes the scope text on the certificate - write it carefully.'
        Invoke-CeAutoFit $sc
        $sc.Column(1).Width = 42
        $sc.Column(2).Width = 70

        # ================================================================= #
        #  3. DEVICE LIST                                                    #
        # ================================================================= #
        $inv = $Audit.Inventory
        $sheet = $pkg.Workbook.Worksheets.Add('Device list')
        $row = 1
        if ($Audit.RunInfo.Mode -eq 'Hybrid') {
            $ref = [ref]$row
            Write-CeBanner -Ws $sheet -RowRef $ref -Span 11 -Height 60 -Text ("HYBRID ENVIRONMENT - Unified asset list (Intune + on-prem AD, de-duplicated). Cloud workstations: {0}; on-premises workstations: {1}. Primary source of truth: {2}. {3}" -f `
                $inv.CloudWorkstations, $inv.OnPremWorkstations, $inv.SourceOfTruth, $inv.DistributionVerdict)
            $row = $ref.Value + 1
        }
        $winHeaders = @('Device name','Manufacturer','Model','OS','SKU family','Ownership','Join type','Primary user UPN','Source','Support status','Support end')
        $winProps   = @('DeviceName','Manufacturer','Model','OS','SkuFamily','Ownership','JoinType','PrimaryUser','Source','SupportStatus','SupportEnd')

        foreach ($block in @(
            @{ Title = 'WINDOWS WORKSTATIONS'; Data = $inv.Windows; Empty = 'No Windows workstations within the check-in window.' }
            @{ Title = 'SERVERS';              Data = $inv.Servers; Empty = 'No servers found in scope.' }
            @{ Title = 'MACOS DEVICES';        Data = $inv.MacOS;   Empty = 'No macOS devices within the check-in window.' }
        )) {
            Set-CeTitle -Ws $sheet -RowIndex $row -Span $winHeaders.Count -Text $block.Title -Fill $sectionFill
            $row += 1
            $data = @($block.Data)
            if ($data.Count -gt 0) {
                $tableStart = $row + 1
                $ref = [ref]$row
                Write-CeTable -Ws $sheet -RowRef $ref -Headers $winHeaders -Data $data -Props $winProps
                $row = $ref.Value
                # RAG the Support status column.
                for ($r2 = $tableStart; $r2 -lt $row; $r2++) {
                    $cell = $sheet.Cells[(Get-CeAddr $r2 10)]
                    if ("$($cell.Value)" -eq 'EOL') {
                        $cell.Style.Fill.PatternType = $solid
                        $cell.Style.Fill.BackgroundColor.SetColor($statusFills['Fail'])
                        $cell.Style.Font.Bold = $true
                    } elseif ("$($cell.Value)" -eq 'Supported') {
                        $cell.Style.Font.Color.SetColor($greenFont)
                    }
                }
            } else {
                $sheet.Cells[(Get-CeAddr $row 1)].Value = $block.Empty; $row++
            }
            $row += 2
        }

        foreach ($block in @(
            @{ Title = 'WINDOWS WORKSTATION SUMMARY'; Total = ("Total Windows workstations: {0}" -f @($inv.Windows).Count); Data = $inv.Summary }
            @{ Title = 'SERVER SUMMARY';              Total = ("Total servers: {0}" -f @($inv.Servers).Count);              Data = $inv.ServerSummary }
        )) {
            Set-CeTitle -Ws $sheet -RowIndex $row -Span 5 -Text $block.Title -Fill $sectionFill
            $row += 1
            $sheet.Cells[(Get-CeAddr $row 1)].Value = $block.Total
            $sheet.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true
            $row += 2
            if (@($block.Data).Count) {
                $ref = [ref]$row
                Write-CeTable -Ws $sheet -RowRef $ref -Headers @('Count','Manufacturer','OS','SKU family','Summary') -Data @($block.Data) -Props @('Count','Manufacturer','OS','SkuFamily','Description')
                $row = $ref.Value
            }
            $row += 2
        }
        Invoke-CeAutoFit $sheet

        # ================================================================= #
        #  4. MFA                                                            #
        # ================================================================= #
        $mfa = $Audit.Sections.Mfa
        $ws = $pkg.Workbook.Worksheets.Add('MFA')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 2 -Text 'MULTI-FACTOR AUTHENTICATION' -Fill $sectionFill
        $row += 2
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Security defaults enabled: {0}" -f $(if ($mfa.SecurityDefaultsOn) { 'Yes (enforces MFA for all users)' } else { 'No' })); $row++
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Conditional Access policies found: {0}" -f $mfa.CaPolicyCount); $row++
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Policies ENFORCING MFA (state = enabled): {0}" -f @($mfa.Evaluation.Enforced).Count)
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true; $row++
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Report-only MFA policies (NOT enforcing): {0} | Disabled MFA policies: {1}" -f @($mfa.Evaluation.ReportOnly).Count, @($mfa.Evaluation.Disabled).Count); $row++
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("MFA registration: {0} of {1} users registered" -f $mfa.RegistrationMfa, $mfa.RegistrationTotal); $row += 2

        if (@($mfa.PolicyRows).Count -eq 0) {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'No Conditional Access policy referencing MFA was found.'; $row++
        } else {
            $idx = 1
            foreach ($f in @($mfa.PolicyRows)) {
                Set-CeTitle -Ws $ws -RowIndex $row -Span 2 -Text ("Policy {0} of {1}" -f $idx, @($mfa.PolicyRows).Count) -Fill $headerFill
                $row++
                $ref = [ref]$row; Write-CeKeyValue -Ws $ws -RowRef $ref -Pairs $f; $row = $ref.Value + 1
                $idx++
            }
        }
        if (@($mfa.Unregistered).Count -gt 0) {
            Set-CeTitle -Ws $ws -RowIndex $row -Span 4 -Text 'USERS NOT REGISTERED FOR MFA' -Fill $sectionFill
            $row++
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('User','Name','MFA capable','Methods registered') -Data @($mfa.Unregistered) -Props @('User','Name','MfaCapable','Methods')
            $row = $ref.Value
        }
        Invoke-CeAutoFit $ws
        $ws.Column(2).Width = 70

        # ================================================================= #
        #  5. SOFTWARE FIREWALL                                              #
        # ================================================================= #
        $ws = $pkg.Workbook.Worksheets.Add('Software firewall')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 6 -Text 'SOFTWARE FIREWALL' -Fill $sectionFill
        $row += 2
        $fwData = @($Audit.Sections.Firewall.Findings)
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Firewall-related policies found: {0}" -f $fwData.Count)
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true; $row += 2
        if ($fwData.Count -eq 0) {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'No policy enabling/enforcing the software firewall was found (see Summary verdict for interpretation).'; $row++
        } else {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Source','Policy name','Platform','Firewall setting','Included','Excluded') -Data $fwData -Props @('Source','PolicyName','Platform','FirewallSetting','Included','Excluded')
            $row = $ref.Value
        }
        $row++
        $ref = [ref]$row
        Write-CeBanner -Ws $ws -RowRef $ref -Span 6 -Height 40 -Text 'MANUAL EVIDENCE REQUIRED: the internet boundary firewall/router cannot be audited via Graph. Record make/model, confirm the default admin password was changed, and that no unauthenticated inbound services are exposed.' -FontColor $redFont
        Invoke-CeAutoFit $ws
        $ws.Column(4).Width = 45

        # ================================================================= #
        #  6. MALWARE PROTECTION                                             #
        # ================================================================= #
        $ws = $pkg.Workbook.Worksheets.Add('Malware protection')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 6 -Text 'MALWARE PROTECTION (DEFENDER AV / AV POLICIES)' -Fill $sectionFill
        $row += 2
        $mwData = @($Audit.Sections.Malware.Findings)
        $sig = $Audit.Sections.Malware.Signals
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("AV-related policies found: {0} | Real-time protection enforced: {1} | Cloud protection: {2} | PUA protection: {3} | Signature interval: {4}" -f `
            $mwData.Count,
            $(if ($sig.RealTime) { 'Yes' } else { 'Not confirmed' }),
            $(if ($sig.Cloud)    { 'Yes' } else { 'Not confirmed' }),
            $(if ($sig.Pua)      { 'Yes' } else { 'Not confirmed' }),
            $(if ($null -ne $sig.SigCad) { "$($sig.SigCad)h" } else { 'Default (automatic)' }))
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true
        $ws.Cells[(Get-CeRange $row 1 $row 6)].Merge = $true
        $ws.Cells[(Get-CeAddr $row 1)].Style.WrapText = $true
        $ws.Row($row).Height = 30
        $row += 2
        if ($mwData.Count -eq 0) {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'No Intune AV/Defender policies found. Windows Defender runs by default but is unmanaged - see the Summary verdict.'; $row++
        } else {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Source','Policy name','Platform','Key settings','Included','Excluded') -Data $mwData -Props @('Source','PolicyName','Platform','Setting','Included','Excluded')
            $row = $ref.Value
        }
        $row++
        $ref = [ref]$row
        Write-CeBanner -Ws $ws -RowRef $ref -Span 6 -Height 40 -Text 'If a THIRD-PARTY AV product (or allow-listing, e.g. ThreatLocker) provides malware protection instead of Defender, evidence it manually - third-party agents are not visible in Intune policy.'
        Invoke-CeAutoFit $ws
        $ws.Column(4).Width = 60

        # ================================================================= #
        #  7. SECURITY UPDATES                                               #
        # ================================================================= #
        $upd = $Audit.Sections.Updates
        $ws = $pkg.Workbook.Worksheets.Add('Security updates')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 12 -Text 'SECURITY UPDATE MANAGEMENT (14-DAY REQUIREMENT - AUTO-FAIL TERRITORY)' -Fill $sectionFill
        $row += 2
        Set-CeTitle -Ws $ws -RowIndex $row -Span 12 -Text 'WINDOWS UPDATE RINGS' -Fill $headerFill
        $row++
        if (@($upd.RingRows).Count) {
            $tableStart = $row + 1
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref `
                -Headers @('Ring','Verdict','Worst case','Deferral (d)','Deadline (d)','Grace (d)','Paused','Feature deferral (d)','Auto mode','Why','Included','Excluded') `
                -Data @($upd.RingRows) `
                -Props @('RingName','Verdict','WorstCase','Deferral','Deadline','Grace','Paused','FeatureDefer','AutoMode','Reason','Included','Excluded')
            $row = $ref.Value
            for ($r2 = $tableStart; $r2 -lt $row; $r2++) {
                $cell = $ws.Cells[(Get-CeAddr $r2 2)]
                $v = "$($cell.Value)"
                if ($statusFills.ContainsKey($v)) {
                    $cell.Style.Fill.PatternType = $solid
                    $cell.Style.Fill.BackgroundColor.SetColor($statusFills[$v])
                    $cell.Style.Font.Bold = $true
                }
            }
        } else {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'No Windows Update rings (windowsUpdateForBusinessConfiguration) found.'; $row++
        }
        $row += 2

        Set-CeTitle -Ws $ws -RowIndex $row -Span 3 -Text 'FEATURE / DRIVER / EXPEDITE PROFILES' -Fill $headerFill
        $row++
        if (@($upd.ProfileRows).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Type','Name','Detail') -Data @($upd.ProfileRows) -Props @('Type','Name','Detail')
            $row = $ref.Value
        } else { $ws.Cells[(Get-CeAddr $row 1)].Value = 'None found.'; $row++ }
        $row += 2

        Set-CeTitle -Ws $ws -RowIndex $row -Span 5 -Text 'MACOS SOFTWARE UPDATE POLICIES' -Fill $headerFill
        $row++
        if (@($upd.MacRows).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Type','Name','Detail','Included','Excluded') -Data @($upd.MacRows) -Props @('Type','Name','Detail','Included','Excluded')
            $row = $ref.Value
        } else { $ws.Cells[(Get-CeAddr $row 1)].Value = 'None found.'; $row++ }
        $row += 2

        if (@($upd.GpoRows).Count) {
            Set-CeTitle -Ws $ws -RowIndex $row -Span 3 -Text 'ON-PREM GPO UPDATE POLICIES' -Fill $headerFill
            $row++
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Type','GPO','Detail') -Data @($upd.GpoRows) -Props @('Type','Name','Detail')
            $row = $ref.Value
            $row += 2
        }

        Set-CeTitle -Ws $ws -RowIndex $row -Span 6 -Text 'UNSUPPORTED / END-OF-LIFE OPERATING SYSTEMS IN SCOPE' -Fill $headerFill
        $row++
        if (@($upd.EolDevices).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Device name','OS','Support end','Source','Primary user','Note') -Data @($upd.EolDevices) -Props @('DeviceName','OS','SupportEnd','Source','PrimaryUser','SupportNote')
            $row = $ref.Value
        } else {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'None - all in-scope devices run vendor-supported operating systems.'
            $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Color.SetColor($greenFont); $row++
        }
        $row += 1
        $ref = [ref]$row
        Write-CeBanner -Ws $ws -RowRef $ref -Span 12 -Height 40 -Text 'MANUAL EVIDENCE REQUIRED: third-party application patching (browsers, readers, LOB apps) within 14 days, and that all software is licensed and vendor-supported.' -FontColor $redFont
        Invoke-CeAutoFit $ws
        $ws.Column(10).Width = 60

        # ================================================================= #
        #  8. MOBILE DEVICES                                                 #
        # ================================================================= #
        $mob = $Audit.Sections.Mobile
        $ws = $pkg.Workbook.Worksheets.Add('Mobile devices')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 6 -Text 'MOBILE DEVICES (ANDROID & iOS)' -Fill $sectionFill
        $row += 2
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Total mobile devices (within the check-in window): {0}" -f @($inv.Mobile).Count)
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true; $row += 2

        Set-CeTitle -Ws $ws -RowIndex $row -Span 4 -Text 'SUMMARY BY MAKE & OS' -Fill $headerFill
        $row++
        if (@($inv.MobileSummary).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Count','Make','OS','Summary') -Data @($inv.MobileSummary) -Props @('Count','Make','OS','Description')
            $row = $ref.Value
        } else { $ws.Cells[(Get-CeAddr $row 1)].Value = 'No mobile devices found.'; $row++ }
        $row += 2

        Set-CeTitle -Ws $ws -RowIndex $row -Span 6 -Text 'DEVICE LIST' -Fill $headerFill
        $row++
        if (@($inv.Mobile).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Device name','Make','Model','OS','Ownership','Primary user UPN') -Data @($inv.Mobile) -Props @('DeviceName','Make','Model','OS','Ownership','PrimaryUser')
            $row = $ref.Value
        } else { $ws.Cells[(Get-CeAddr $row 1)].Value = 'No mobile devices found.'; $row++ }
        $row += 2

        Set-CeTitle -Ws $ws -RowIndex $row -Span 2 -Text 'APP PROTECTION POLICIES (MAM)' -Fill $sectionFill
        $row++
        if (@($mob.AppPolicies).Count -eq 0) {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'No Intune app protection (MAM) policies were found for Android or iOS.'; $row++
        } else {
            foreach ($ap in @($mob.AppPolicies)) {
                Set-CeTitle -Ws $ws -RowIndex $row -Span 2 -Text ("{0} - {1}" -f $ap.Platform, $ap.Name) -Fill $headerFill
                $row++
                $meta = [ordered]@{ 'Platform' = $ap.Platform; 'Assigned to (included)' = $ap.Included; 'Excluded' = $ap.Excluded }
                $ref = [ref]$row; Write-CeKeyValue -Ws $ws -RowRef $ref -Pairs $meta; $row = $ref.Value
                $ws.Cells[(Get-CeAddr $row 1)].Value = 'Settings:'; $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Italic = $true; $row++
                if ($ap.Settings.Count) {
                    $ref = [ref]$row; Write-CeKeyValue -Ws $ws -RowRef $ref -Pairs $ap.Settings; $row = $ref.Value
                } else { $ws.Cells[(Get-CeAddr $row 1)].Value = '(no individual settings reported)'; $row++ }
                $row += 1
            }
        }
        $row += 1

        Set-CeTitle -Ws $ws -RowIndex $row -Span 2 -Text 'CONDITIONAL ACCESS - REQUIRE APP PROTECTION' -Fill $sectionFill
        $row++
        if (@($mob.CaAppEnforce).Count) {
            foreach ($c in @($mob.CaAppEnforce)) { $ws.Cells[(Get-CeAddr $row 1)].Value = (" - {0} [{1}]" -f $c.Name, $c.State); $row++ }
        } else {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'No Conditional Access policy enforces app protection.'; $row++
        }
        $row += 2

        Set-CeTitle -Ws $ws -RowIndex $row -Span 5 -Text 'MOBILE COMPLIANCE POLICIES' -Fill $sectionFill
        $row++
        if (@($mob.Fallback).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Name','Platform','Type','Included','Excluded') -Data @($mob.Fallback) -Props @('Name','Platform','Type','Included','Excluded')
            $row = $ref.Value
        } else { $ws.Cells[(Get-CeAddr $row 1)].Value = 'No Android/iOS compliance policies found.'; $row++ }
        $row += 2

        Set-CeTitle -Ws $ws -RowIndex $row -Span 5 -Text 'DEVICE-LOCKING COMPLIANCE SETTINGS (ALL PLATFORMS)' -Fill $sectionFill
        $row++
        if (@($Audit.Sections.SecureConfig.LockRows).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Platform','Policy','Settings','Included','Excluded') -Data @($Audit.Sections.SecureConfig.LockRows) -Props @('Platform','PolicyName','Settings','Included','Excluded')
            $row = $ref.Value
        } else { $ws.Cells[(Get-CeAddr $row 1)].Value = 'No device-locking compliance settings found.'; $row++ }
        Invoke-CeAutoFit $ws
        $ws.Column(2).Width = 50

        # ================================================================= #
        #  9. AUTOPLAY / AUTORUN                                             #
        # ================================================================= #
        $ws = $pkg.Workbook.Worksheets.Add('Status of autoplay-autorun')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 6 -Text 'AUTOPLAY / AUTORUN POLICIES' -Fill $sectionFill
        $row += 2
        $autoData = @($Audit.Sections.Autoplay.Findings)
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Settings disabling/affecting AutoPlay or AutoRun found: {0}" -f $autoData.Count)
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true; $row++
        if ($Audit.Sections.Autoplay.Coverage) {
            $ref = [ref]$row
            Write-CeBanner -Ws $ws -RowRef $ref -Span 6 -Height 30 -Text ("Where the audit looked: {0}" -f $Audit.Sections.Autoplay.Coverage)
            $row = $ref.Value
        }
        $row++
        if ($autoData.Count -eq 0) {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'No policy or setting that disables AutoPlay/AutoRun was found in any scanned source.'; $row++
        } else {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Source','Policy name','Setting','State','Included','Excluded') -Data $autoData -Props @('Source','PolicyName','Setting','State','Included','Excluded')
            $row = $ref.Value
        }
        Invoke-CeAutoFit $ws
        $ws.Column(3).Width = 45

        # ================================================================= #
        #  10. SHARED ACCOUNTS (+ stale + guests)                            #
        # ================================================================= #
        $acc = $Audit.Sections.Accounts
        $ws = $pkg.Workbook.Worksheets.Add('Shared accounts')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 6 -Text 'ACCOUNT REVIEW (SHARED / STALE / GUEST)' -Fill $sectionFill
        $row += 2
        $ref = [ref]$row
        Write-CeBanner -Ws $ws -RowRef $ref -Span 6 -FontColor $redFont -Text 'CAVEAT: accounts below are flagged HEURISTICALLY (naming patterns, missing first/last names). They are NOT confirmed shared accounts - each requires a manual check.'
        $row = $ref.Value + 1
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Total accounts reviewed: {0}" -f $acc.TotalUsers); $row++
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Suspected shared accounts: {0}" -f @($acc.SharedAccounts).Count)
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true; $row += 2
        if (@($acc.SharedAccounts).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Display name','User principal name','Enabled','User type','Licenses','Why flagged (manual check required)') -Data @($acc.SharedAccounts) -Props @('DisplayName','UPN','Enabled','UserType','Licenses','Reasons')
            $row = $ref.Value
        } else {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'No accounts matched the shared-account heuristics. (A manual review is still recommended.)'; $row++
        }
        $row += 2

        Set-CeTitle -Ws $ws -RowIndex $row -Span 4 -Text ("STALE ACCOUNTS (no sign-in for {0}+ days, enabled & licensed)" -f $acc.StaleDays) -Fill $sectionFill
        $row++
        if (@($acc.StaleAccounts).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Display name','UPN','Last sign-in','Created') -Data @($acc.StaleAccounts) -Props @('DisplayName','UPN','LastSignIn','Created')
            $row = $ref.Value
        } else { $ws.Cells[(Get-CeAddr $row 1)].Value = 'None found (or sign-in data unavailable - see Summary).'; $row++ }
        $row += 2

        Set-CeTitle -Ws $ws -RowIndex $row -Span 4 -Text 'GUEST ACCOUNTS' -Fill $sectionFill
        $row++
        if (@($acc.Guests).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Display name','UPN','Enabled','Created') -Data @($acc.Guests) -Props @('DisplayName','UPN','Enabled','Created')
            $row = $ref.Value
        } else { $ws.Cells[(Get-CeAddr $row 1)].Value = 'No guest accounts.'; $row++ }
        Invoke-CeAutoFit $ws
        $ws.Column(6).Width = 40

        # ================================================================= #
        #  11. APPLICATION WHITELISTING                                      #
        # ================================================================= #
        $ws = $pkg.Workbook.Worksheets.Add('Application whitelisting')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 6 -Text 'APPLICATION ALLOW-LISTING (APPLOCKER / APP CONTROL FOR BUSINESS / WDAC)' -Fill $sectionFill
        $row += 2
        $awData = @($Audit.Sections.AppControl.Findings)
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Application-control policies found: {0}" -f $awData.Count)
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true; $row += 2
        if ($awData.Count -eq 0) {
            $ref = [ref]$row
            Write-CeBanner -Ws $ws -RowRef $ref -Span 6 -FontColor $redFont -Height 60 -Text 'No Intune application allow-listing policy found. MANUAL CHECK: confirm whether ThreatLocker or another third-party allow-listing solution is enforced on endpoints. Absence of an Intune policy does not necessarily mean no allow-listing is in place.'
            $row = $ref.Value
        } else {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Source','Policy name','Mechanism','Setting','Included','Excluded') -Data $awData -Props @('Source','PolicyName','Mechanism','Setting','Included','Excluded')
            $row = $ref.Value
            $row++
            $ref = [ref]$row
            Write-CeBanner -Ws $ws -RowRef $ref -Span 6 -Height 30 -Text 'Verify enforcement mode (not audit-only). This tab covers Intune-managed application control; confirm any third-party allow-listing separately.'
        }
        Invoke-CeAutoFit $ws
        $ws.Column(4).Width = 45

        # ================================================================= #
        #  12. PASSWORD                                                      #
        # ================================================================= #
        $pwSection = $Audit.Sections.Password
        $pwdCheck = @($Audit.Checks | Where-Object { $_.CheckId -eq 'CE-UA-06' })[0]
        $ws = $pkg.Workbook.Worksheets.Add('Password')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 2 -Text 'PASSWORD-BASED AUTHENTICATION PROTECTIONS' -Fill $sectionFill
        $row += 2
        $verdictColor = if ($pwdCheck -and $pwdCheck.Status -eq 'Pass') { $greenFont } else { $redFont }
        $ref = [ref]$row
        Write-CeBanner -Ws $ws -RowRef $ref -Span 2 -Height 75 -FontColor $verdictColor -Text $(if ($pwdCheck) { "$($pwdCheck.Status): $($pwdCheck.Reason)" } else { 'See Summary tab.' })
        $row = $ref.Value + 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 2 -Text 'DETAILS' -Fill $headerFill
        $row++
        $ref = [ref]$row
        Write-CeKeyValue -Ws $ws -RowRef $ref -Pairs $pwSection.Details
        $row = $ref.Value + 1
        $ref = [ref]$row
        Write-CeBanner -Ws $ws -RowRef $ref -Span 2 -Height 45 -Text 'CE accepts ANY of: MFA on the account; minimum 12 characters with no maximum; minimum 8 characters plus an automatic deny list; or throttling/lockout. Microsoft enforces a global banned-password list and smart lockout for all Entra ID tenants automatically.'
        Invoke-CeAutoFit $ws
        $ws.Column(1).Width = 42
        $ws.Column(2).Width = 60

        # ================================================================= #
        #  13. PRIVILEGED USERS                                              #
        # ================================================================= #
        $priv = $Audit.Sections.Privileged
        $ws = $pkg.Workbook.Worksheets.Add('Privileged users')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 9 -Text 'PRIVILEGED USERS (STANDARD USERS WITH ADMIN PRIVILEGES)' -Fill $sectionFill
        $row += 2
        $ref = [ref]$row
        Write-CeBanner -Ws $ws -RowRef $ref -Span 9 -Height 75 -FontColor $redFont -Text 'Cyber Essentials requires that administrative privilege is controlled and that day-to-day (standard) user accounts are NOT also admin accounts. Rows flagged as a "standard user" holding admin - especially privilege INHERITED via a nested group - should be reviewed: move admin rights to a separate, dedicated (ideally unlicensed / cloud-only) admin account. "Direct" = assigned to the account itself; "Nested via ..." = inherited through group membership.'
        $row = $ref.Value + 1
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Total privileged membership rows: {0}" -f @($priv.Findings).Count); $row++
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Standard user accounts holding admin: {0}" -f @($priv.StandardUsers).Count)
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Color.SetColor($(if (@($priv.StandardUsers).Count -gt 0) { $redFont } else { $greenFont })); $row++
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("Privilege inherited via nested group / PIM-eligible: {0}" -f @($priv.Nested).Count); $row++
        $ws.Cells[(Get-CeAddr $row 1)].Value = ("HIGH-risk findings: {0}" -f @($priv.High).Count)
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Bold = $true
        $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Color.SetColor($(if (@($priv.High).Count -gt 0) { $redFont } else { $greenFont })); $row += 2

        if (@($priv.Findings).Count -eq 0) {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'No privileged role / group memberships were returned (none configured, or insufficient permissions - see Summary/Run info).'; $row++
        } else {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref `
                -Headers @('Scope','Display name','Account','Privilege (role / group)','Assignment','Enabled','Account class','Risk / action','Notes') `
                -Data @($priv.Findings) `
                -Props @('Scope','DisplayName','Account','Privilege','Assignment','Enabled','AccountClass','Risk','Notes')
            $row = $ref.Value
        }
        Invoke-CeAutoFit $ws
        $ws.Column(8).Width = 42

        # ================================================================= #
        #  14. RUN INFO (machine-readable provenance for auditors)           #
        # ================================================================= #
        $ws = $pkg.Workbook.Worksheets.Add('Run info')
        $row = 1
        Set-CeTitle -Ws $ws -RowIndex $row -Span 2 -Text 'RUN MANIFEST' -Fill $sectionFill
        $row += 2
        $ri = $Audit.RunInfo
        $manifest = [ordered]@{
            'Tool'                    = 'CyberEssentialsAudit'
            'Tool version'            = $ri.ToolVersion
            'Run started (UTC)'       = $ri.StartedUtc.ToString('yyyy-MM-dd HH:mm:ss')
            'Run finished (UTC)'      = $ri.FinishedUtc.ToString('yyyy-MM-dd HH:mm:ss')
            'Operator account'        = $ri.Account
            'Auth mode'               = $ri.AuthMode
            'Tenant id'               = $ri.TenantId
            'Audit mode'              = $ri.Mode
            'Check-in window (weeks)' = $ri.CheckInWindowWeeks
            'Graph scopes granted'    = ($ri.Scopes -join ', ')
            'AD reachable (hybrid)'   = $ri.AdAvailable
            'Read-only guarantee'     = 'This tool only issues GET requests to Microsoft Graph and read-only AD/GPO cmdlets.'
        }
        $ref = [ref]$row
        Write-CeKeyValue -Ws $ws -RowRef $ref -Pairs $manifest
        $row = $ref.Value + 1

        Set-CeTitle -Ws $ws -RowIndex $row -Span 3 -Text 'API ERRORS DURING THIS RUN (checks touching these areas are marked Unknown)' -Fill $headerFill
        $row++
        if (@($ri.GraphErrors).Count) {
            $ref = [ref]$row
            Write-CeTable -Ws $ws -RowRef $ref -Headers @('Area','Message','Time (UTC)') -Data @($ri.GraphErrors) -Props @('Area','Message','TimeUtc')
            $row = $ref.Value
        } else {
            $ws.Cells[(Get-CeAddr $row 1)].Value = 'None - all API reads succeeded.'
            $ws.Cells[(Get-CeAddr $row 1)].Style.Font.Color.SetColor($greenFont); $row++
        }
        Invoke-CeAutoFit $ws
        $ws.Column(1).Width = 30
        $ws.Column(2).Width = 80

        $pkg.Save()
    }
    finally {
        if ($pkg) { $pkg.Dispose() }
    }
}

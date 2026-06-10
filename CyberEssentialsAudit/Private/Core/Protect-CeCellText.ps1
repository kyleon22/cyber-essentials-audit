# CSV/formula-injection neutraliser (fixes B1). Tenant/AD-controlled strings
# (policy names, device names, UPNs) can begin with =, +, -, @, tab or CR.
# EPPlus writes inline strings (safe in the .xlsx itself), but if the data is
# re-exported to CSV or opened by a client that auto-interprets formulas, such
# values could execute. Prefix any risky leading character with a single quote.
$script:CeFormulaLeadChars = [char[]]"=+-@`t`r"

function Protect-CeCellText {
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return $Value }
    if ($Value -isnot [string]) { return $Value }   # numbers/dates pass through
    if ($Value.Length -gt 0 -and ($script:CeFormulaLeadChars -contains $Value[0])) {
        return "'" + $Value
    }
    return $Value
}

# The single typed object every check returns. The Excel/JSON layers render
# these; the Summary tab is one row per result. Status semantics:
#   Pass    - automated evidence shows the control is in place
#   Fail    - automated evidence shows the control is NOT in place
#   Manual  - cannot be judged from tenant data; assessor must verify
#   Unknown - a required API call failed (permissions/transient) - NEVER an
#             implicit pass or fail
function New-CeCheckResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Manual', 'Unknown')][string]$Status,
        [string]$Reason = '',
        [string]$Evidence = '',
        [string]$DetailSheet = ''
    )
    [pscustomobject]@{
        PSTypeName  = 'CyberEssentialsAudit.CheckResult'
        Control     = $Control
        CheckId     = $CheckId
        Title       = $Title
        Status      = $Status
        Reason      = $Reason
        Evidence    = $Evidence
        DetailSheet = $DetailSheet
    }
}

# Canonical CE control names (Danzell v3.3) - used for Summary tab ordering.
$script:CeControlOrder = @(
    'Scope'
    'Firewalls'
    'Secure configuration'
    'User access control'
    'Malware protection'
    'Security update management'
)

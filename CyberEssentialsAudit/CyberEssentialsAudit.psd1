@{
    RootModule        = 'CyberEssentialsAudit.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = '7f4c2a91-3b8e-4d56-9c1a-58e0f7d2b4c3'
    Author            = 'Cyber Essentials Audit contributors'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2026. All rights reserved.'
    Description       = 'Read-only Cyber Essentials readiness audit for Microsoft 365 / Intune tenants and hybrid Active Directory estates. Produces an Excel workbook and/or JSON with a Pass / Fail / Manual / Unknown verdict per CE sub-requirement (Danzell v3.3 question set).'
    PowerShellVersion = '5.1'

    # Pinned on purpose (supply-chain hygiene): the audit may run on privileged
    # hosts (domain controllers). Update deliberately, never implicitly.
    RequiredModules   = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.25.0' }
        @{ ModuleName = 'ImportExcel';                    ModuleVersion = '7.8.10' }
    )

    FunctionsToExport = @('Invoke-CeAudit', 'Export-CeReport')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('CyberEssentials', 'Audit', 'Intune', 'Graph', 'Security', 'Compliance')
            ProjectUri   = 'https://github.com/kyleon22/cyber-essentials-audit'
            ReleaseNotes = 'See CHANGELOG.md'
        }
    }
}

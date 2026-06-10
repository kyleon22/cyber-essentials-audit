@{
    # Ruleset for the CyberEssentialsAudit module + launcher.
    # Run:  Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # Interactive console tool: coloured Write-Host status output is the UX.
        'PSAvoidUsingWriteHost',

        # Deliberate best-effort pattern: a policy/assignment read that fails is
        # journaled by Add-CeGraphError where it matters, and individual
        # enrichment lookups (template names, CIM, user detail) intentionally
        # degrade to defaults rather than abort an audit run.
        'PSAvoidUsingEmptyCatchBlock',

        # Collection getters (Get-CeCatalogPolicies etc.) intentionally use
        # plural nouns - they return cached collections.
        'PSUseSingularNouns',

        # New-CeCheckResult / Set-CeTitle build in-memory objects and worksheet
        # cells; nothing touches system state (the tool is read-only).
        'PSUseShouldProcessForStateChangingFunctions',

        # False positives: parameters consumed inside nested functions via
        # dynamic scoping (ConvertFrom-CeGpoReportXml, the launcher preflight).
        'PSReviewUnusedParameter'
    )
}

# Module-shape tests: manifest validity, loader integrity, public surface.
BeforeDiscovery {
    # Discovery-time: -Skip conditions are evaluated before BeforeAll runs.
    $script:HaveDeps = [bool](Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication') -and
                       [bool](Get-Module -ListAvailable -Name 'ImportExcel')
}
BeforeAll {
    $script:ModuleRoot = Join-Path $PSScriptRoot '..\CyberEssentialsAudit'
    $script:ManifestPath = Join-Path $ModuleRoot 'CyberEssentialsAudit.psd1'
}

Describe 'Module manifest' {
    It 'parses as a valid PowerShell data file' {
        { Import-PowerShellDataFile $ManifestPath } | Should -Not -Throw
    }
    It 'exports exactly the two public commands' {
        $data = Import-PowerShellDataFile $ManifestPath
        $data.FunctionsToExport | Sort-Object | Should -Be @('Export-CeReport', 'Invoke-CeAudit')
    }
    It 'pins its required module versions (supply-chain hygiene)' {
        $data = Import-PowerShellDataFile $ManifestPath
        foreach ($rm in $data.RequiredModules) {
            $rm.ModuleVersion | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Module source integrity' {
    It 'every .ps1 under the module parses without syntax errors' {
        $bad = @()
        foreach ($f in (Get-ChildItem -Path $ModuleRoot -Filter '*.ps1' -Recurse -File)) {
            $tokens = $null; $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
            if ($errors.Count) { $bad += "$($f.Name): $($errors[0].Message)" }
        }
        $bad | Should -BeNullOrEmpty
    }
    It 'no function writes to the tenant (read-only guarantee: no POST/PATCH/PUT/DELETE Graph calls)' {
        $hits = Get-ChildItem -Path $ModuleRoot -Filter '*.ps1' -Recurse -File |
            Select-String -Pattern 'Invoke-MgGraphRequest\s+-Method\s+(POST|PATCH|PUT|DELETE)' -AllMatches
        @($hits) | Should -BeNullOrEmpty
    }
}

Describe 'Module import' -Skip:(-not $script:HaveDeps) {
    It 'imports cleanly and exposes the public commands' {
        $m = Import-Module $ManifestPath -Force -PassThru
        $m.ExportedFunctions.Keys | Sort-Object | Should -Be @('Export-CeReport', 'Invoke-CeAudit')
        Remove-Module CyberEssentialsAudit -Force -ErrorAction SilentlyContinue
    }
}

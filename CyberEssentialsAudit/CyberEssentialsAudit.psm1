# CyberEssentialsAudit module loader. Dot-sources every function file; the
# manifest controls what is exported.
$folders = @('Private\Core', 'Private\Graph', 'Private\Checks', 'Private\Excel', 'Public')
foreach ($folder in $folders) {
    $path = Join-Path $PSScriptRoot $folder
    if (-not (Test-Path $path)) { continue }
    foreach ($file in (Get-ChildItem -Path $path -Filter '*.ps1' -File | Sort-Object Name)) {
        . $file.FullName
    }
}

Export-ModuleMember -Function 'Invoke-CeAudit', 'Export-CeReport'

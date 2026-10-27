$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../run-joint-e2e.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Joint runner has parse errors' }
$definition = $ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Resolve-NativeApiDatabaseAllocators'
}, $true)
if ($definition.Count -ne 1) { throw 'Native database allocator resolver is missing' }
Invoke-Expression $definition[0].Extent.Text
$administrative = 'postgresql://test@127.0.0.1:5432/postgres'
$application = 'postgresql://test@127.0.0.1:5432/cotest_service'
$native = Resolve-NativeApiDatabaseAllocators -AdministrativeUrl $administrative -ExplicitColandUrl $application
if ($native.Count -ne 2 -or $native.COTEST_COLAND_DATABASE_URL -ne $administrative -or
    $native.COTEST_COAUTH_DATABASE_URL -ne $administrative) {
    throw 'The verified cluster allocator must reach both isolated service fixtures'
}
foreach ($forbidden in @('DATABASE_URL', 'COLAND_TEST_DATABASE_URL', 'COAUTH_DATABASE_URL')) {
    if ($native.Contains($forbidden)) { throw 'Administrative connections must not become application stores' }
}
$external = Resolve-NativeApiDatabaseAllocators -ExplicitColandUrl $application
if ($external.Count -ne 1 -or $external.COTEST_COLAND_DATABASE_URL -ne $application) {
    throw 'The existing explicit Coland allocator fallback must remain supported'
}
foreach ($blank in @('', '   ')) {
    $unset = Resolve-NativeApiDatabaseAllocators -AdministrativeUrl $blank -ExplicitColandUrl $blank
    if ($unset.Count) { throw 'Absent native PostgreSQL must leave Docker and inherited allocator selection unchanged' }
}
Write-Output 'Native API database allocator precedence and application-store separation passed.'

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$runnerPath = Join-Path $PSScriptRoot "..\run-joint-e2e.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $runnerPath,
    [ref]$tokens,
    [ref]$parseErrors
)
Assert-True ($parseErrors.Count -eq 0) "joint runner must parse as PowerShell"

$runner = $ast.Extent.Text
Assert-True `
    ($runner -match 'org\.arkret\.soland\.conformance\.realm_state_snapshot') `
    "runner must identify a feature-bearing Soland conformance harness binary"
Assert-True `
    ($runner -match '-not \$freshness\.Fresh -or -not \$solandConformanceHarnessPresent') `
    "a source-fresh production Soland binary must not bypass the conformance-harness build"
Assert-True `
    ($runner -match 'soland conformance-harness feature.*fail.*cached binary lacks the conformance-harness marker') `
    "preflight must fail closed when SkipBuild leaves a production-only Soland binary"
Assert-True `
    ($runner -match 'cargo build --manifest-path.*--features conformance-harness') `
    "the managed Soland rebuild must enable conformance-harness"

$solandApi = Get-Content -Raw -LiteralPath (
    Join-Path $PSScriptRoot "..\..\e2e\helpers\soland-api.ts"
)
$authContextMatch = [regex]::Match(
    $solandApi,
    'function eventAuthContext\([\s\S]*?\n\}'
)
Assert-True $authContextMatch.Success "eventAuthContext helper must remain present"
Assert-True `
    ($authContextMatch.Value -match 'authority_refs') `
    "eventAuthContext must bind the sorted authority references"
Assert-True `
    ($authContextMatch.Value -notmatch 'key_epoch') `
    "eventAuthContext must not revive the removed key_epoch wire member"
Assert-True `
    ($authContextMatch.Value -notmatch 'key_id') `
    "eventAuthContext must not duplicate the proof's key identifier"

Write-Host "joint-soland-conformance-feature.tests.ps1: PASS"

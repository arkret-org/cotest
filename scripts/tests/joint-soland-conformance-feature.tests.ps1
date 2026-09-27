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
$producerProofMatch = [regex]::Match(
    $solandApi,
    'function eventEnvelopeProof\([\s\S]*?\r?\n\}(?=\r?\n)'
)
Assert-True $producerProofMatch.Success "producer proof helper must remain present"
Assert-True `
    ($producerProofMatch.Value -match 'return sdkEventEnvelopeProof\(') `
    "producer proof must use the canonical SDK signer"
Assert-True `
    ($producerProofMatch.Value -match 'verificationMethod,\s*createdAt,\s*signingSeedB64url:') `
    "producer proof must bind the registered verification method, creation time and signer"
Assert-True `
    ($producerProofMatch.Value -notmatch '\b(?:auth_context|authority_refs|key_epoch|key_id)\b') `
    "producer proof must not revive removed admission-context fields"

Write-Host "joint-soland-conformance-feature.tests.ps1: PASS"

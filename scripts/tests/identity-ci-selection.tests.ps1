$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ci = Get-Content -LiteralPath (Join-Path $repoRoot ".github\workflows\ci.yml") -Raw
$integration = Get-Content -LiteralPath (Join-Path $repoRoot ".github\workflows\integration.yml") -Raw
$runner = Get-Content -LiteralPath (Join-Path $repoRoot "scripts\run-joint-e2e.ps1") -Raw
$oidc = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\tests\identity\oidc-login-flow.spec.ts") -Raw
$lifecycle = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\tests\identity\device-key-lifecycle.spec.ts") -Raw

function Assert-Contains {
    param([string]$Text, [string]$Needle, [string]$Message)
    if (-not $Text.Contains($Needle)) { throw $Message }
}

function Assert-NotContains {
    param([string]$Text, [string]$Needle, [string]$Message)
    if ($Text.Contains($Needle)) { throw $Message }
}

Assert-Contains $oidc "@returning-login-gate" "returning-login test has no stable CI tag"
Assert-Contains $oidc "@onboarding-recovery-gate" "Recovery Key onboarding test has no stable CI tag"
Assert-Contains $lifecycle "@returning-device-key-gate" "device-key returning test has no stable CI tag"
Assert-NotContains $oidc 'test.describe.configure({ mode: "serial" })' "independent OIDC cases must not cascade-skip after an earlier failure"

Assert-Contains $ci "-PlaywrightProject joint-inkson" "merge CI does not select the joint-inkson project"
Assert-Contains $ci '@returning-login-gate|@onboarding-recovery-gate' "merge CI does not select returning login and Recovery Key onboarding"
Assert-Contains $ci '-RequireScenario "identity/oidc-login-flow.spec.ts"' "merge CI does not require returning-login junit evidence"
Assert-Contains $ci "-ForbidSkippedTests" "merge CI still permits a skipped returning-login false green"

Assert-Contains $integration "-PlaywrightProject joint-inkson" "nightly does not select the joint-inkson project"
Assert-Contains $integration "@returning-login-gate|@returning-device-key-gate|@onboarding-recovery-gate" "nightly does not select all identity cases"
Assert-Contains $integration "identity/oidc-login-flow.spec.ts,identity/device-key-lifecycle.spec.ts" "nightly does not require both identity scenarios"
Assert-NotContains $integration "terminal auth loss|transient self-path failure" "nightly retains the zero-match identity grep"

Assert-Contains $runner '[switch]$ForbidSkippedTests' "joint runner has no non-skip enforcement"
Assert-Contains $runner '[string]$RequireScenario' "joint runner has no required-scenario enforcement"
Assert-Contains $runner 'Playwright selected zero tests' "joint runner has no zero-selection enforcement"

$e2eRoot = Join-Path $repoRoot "e2e"
$playwrightCli = Join-Path $e2eRoot "node_modules\playwright\cli.js"
if (-not (Test-Path -LiteralPath $playwrightCli -PathType Leaf)) {
    throw "Playwright CLI is not installed: $playwrightCli"
}
Push-Location $e2eRoot
try {
    $listed = @(& node $playwrightCli test --config playwright.config.ts --project=joint-inkson --grep "@returning-login-gate|@returning-device-key-gate|@onboarding-recovery-gate" --list 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Playwright identity selection failed:`n$($listed -join [Environment]::NewLine)"
    }
} finally {
    Pop-Location
}
$selection = ($listed -join "`n") -replace '\\', '/'
Assert-Contains $selection "identity/device-key-lifecycle.spec.ts" "joint-inkson did not discover the device-key returning test"
Assert-Contains $selection "identity/oidc-login-flow.spec.ts" "joint-inkson did not discover the OIDC returning-login test"
Assert-Contains $selection "unbound account completes Recovery Key onboarding" "joint-inkson did not discover the Recovery Key onboarding test"
Assert-Contains $selection "Total: 3 tests in 2 files" "identity gate selection changed; review the required scenario matrix"

Write-Host "Identity CI selection regression tests passed."

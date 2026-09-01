$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ci = Get-Content -LiteralPath (Join-Path $repoRoot ".github\workflows\ci.yml") -Raw
$integration = Get-Content -LiteralPath (Join-Path $repoRoot ".github\workflows\integration.yml") -Raw
$runner = Get-Content -LiteralPath (Join-Path $repoRoot "scripts\run-joint-e2e.ps1") -Raw
$selectionGate = Get-Content -LiteralPath (Join-Path $repoRoot "scripts\lib\selection-gate.ps1") -Raw
$playwrightConfig = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\playwright.config.ts") -Raw
$oidc = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\tests\identity\oidc-login-flow.spec.ts") -Raw
$lifecycle = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\tests\identity\device-key-lifecycle.spec.ts") -Raw
$keyBackup = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\tests\encryption\key-backup.spec.ts") -Raw
$contactGraph = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\tests\identity\contact-graph.spec.ts") -Raw
$multiDevice = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\tests\identity\multi-device.spec.ts") -Raw
$realmMatrix = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\tests\identity\recovery-key-to-encrypted-realm.spec.ts") -Raw
$crossMemberKanban = Get-Content -LiteralPath (Join-Path $repoRoot "e2e\tests\kanban\cross-member-encrypted.spec.ts") -Raw
. (Join-Path $repoRoot "scripts\lib\selection-gate.ps1")

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
Assert-Contains $oidc "@onboarding-resume-gate" "accepted onboarding resume test has no stable CI tag"
Assert-Contains $lifecycle "@returning-device-key-gate" "device-key returning test has no stable CI tag"
Assert-Contains $keyBackup "A3 real password/OIDC login restores MLS on a fresh browser with session-grant holder proof @fully-implemented" "fresh-browser Recovery Key restore is not in the default smoke selection"
Assert-Contains $multiDevice "a second-device login stays unauthorized until the first device explicitly approves it" "accepted-device pairing is not in the default smoke selection"
Assert-Contains $multiDevice "a fresh browser can use the 24-word Recovery Key instead of first-device approval" "direct 24-word device recovery is not in the default smoke selection"
Assert-Contains $realmMatrix "fresh browser registration creates, writes, and reloads plaintext and encrypted Realms" "canonical Realm encryption matrix is missing"
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
Assert-Contains $selectionGate 'Playwright selected zero tests' "joint runner has no zero-selection enforcement"
Assert-Contains $runner '"encryption/key-backup"' "joint-smoke does not require fresh-browser Recovery Key restore evidence"
Assert-Contains $runner '"identity/contact-graph"' "joint-smoke does not require the Contact lineage lifecycle"
Assert-Contains $runner '"identity/multi-device"' "joint-smoke does not require both fresh-device entry paths"
Assert-Contains $runner '"identity/recovery-key-to-encrypted-realm"' "joint-smoke does not require the canonical Realm encryption matrix"
Assert-Contains $runner '"kanban/cross-member-encrypted"' "joint-smoke does not require cross-member encrypted kanban evidence"
Assert-Contains $playwrightConfig '"encryption/key-backup.spec.ts"' "joint-inkson does not discover fresh-browser Recovery Key restore"
Assert-Contains $playwrightConfig '"identity/contact-graph.spec.ts"' "joint-inkson does not discover Contact lineage coverage"
Assert-Contains $playwrightConfig '"identity/recovery-key-to-encrypted-realm.spec.ts"' "joint-inkson does not discover the canonical Realm encryption matrix"
Assert-Contains $playwrightConfig '"kanban/cross-member-encrypted.spec.ts"' "joint-inkson does not discover cross-member encrypted kanban"
Assert-Contains $contactGraph 'scope narrowing is reversible on one lineage' "Contact lineage lifecycle coverage is missing"
Assert-Contains $contactGraph '@fully-implemented' "Contact lineage lifecycle is not selected by joint-smoke"
Assert-Contains $crossMemberKanban 'cross-member encrypted kanban @fully-implemented' "cross-member encrypted kanban is not selected by joint-smoke"
Assert-Contains $crossMemberKanban 'assertJointStackNotRequired(' "cross-member encrypted kanban does not fail loud when the required joint stack is unavailable"

$selectedCases = New-Object System.Collections.Generic.List[object]
$selectedCases.Add([pscustomobject]@{ name = "pre-join decrypt"; status = "passed" }) | Out-Null
$selectedJunit = @{
    "kanban/cross-member-encrypted.spec.ts" = [pscustomobject]@{ cases = $selectedCases }
}
$passingTotals = [pscustomobject]@{ passed = 1; failed = 0; skipped = 0; fixme = 0 }
$selectedFailures = @(Get-JointSelectionGateFailures `
        -RequiredScenarios @("kanban\cross-member-encrypted.spec.ts") `
        -JunitByScenario $selectedJunit `
        -Totals $passingTotals `
        -ForbidRuntimeSkips $true `
        -JunitParseError $null)
if ($selectedFailures.Count -ne 0) {
    throw "selected cross-member scenario failed the gate: $($selectedFailures -join '; ')"
}

$missingFailures = @(Get-JointSelectionGateFailures `
        -RequiredScenarios @("kanban/cross-member-encrypted") `
        -JunitByScenario @{} `
        -Totals $passingTotals `
        -ForbidRuntimeSkips $true `
        -JunitParseError $null)
Assert-Contains ($missingFailures -join "`n") "required scenario was not selected: kanban/cross-member-encrypted" "missing required scenario did not fail the selection gate"

$zeroTotals = [pscustomobject]@{ passed = 0; failed = 0; skipped = 0; fixme = 0 }
$zeroFailures = @(Get-JointSelectionGateFailures `
        -RequiredScenarios @() `
        -JunitByScenario @{} `
        -Totals $zeroTotals `
        -ForbidRuntimeSkips $true `
        -JunitParseError $null)
Assert-Contains ($zeroFailures -join "`n") "Playwright selected zero tests" "zero Playwright selection did not fail the selection gate"

$skippedTotals = [pscustomobject]@{ passed = 0; failed = 0; skipped = 1; fixme = 0 }
$skipFailures = @(Get-JointSelectionGateFailures `
        -RequiredScenarios @("kanban/cross-member-encrypted") `
        -JunitByScenario $selectedJunit `
        -Totals $skippedTotals `
        -ForbidRuntimeSkips $true `
        -JunitParseError $null)
Assert-Contains ($skipFailures -join "`n") "selected live tests skipped: 1" "runtime skip did not fail the selection gate"

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

Push-Location $e2eRoot
try {
    $matrixListed = @(& node $playwrightCli test --config playwright.config.ts --project=joint-inkson --grep "A3 real password/OIDC login restores MLS|fresh browser registration creates, writes, and reloads plaintext and encrypted Realms" --list 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Playwright Recovery Key/Realm matrix selection failed:`n$($matrixListed -join [Environment]::NewLine)"
    }
} finally {
    Pop-Location
}
$matrixSelection = ($matrixListed -join "`n") -replace '\\', '/'
Assert-Contains $matrixSelection "encryption/key-backup.spec.ts" "joint-inkson did not discover fresh-browser Recovery Key restore"
Assert-Contains $matrixSelection "identity/recovery-key-to-encrypted-realm.spec.ts" "joint-inkson did not discover the canonical Realm encryption matrix"
Assert-Contains $matrixSelection "Total: 2 tests in 2 files" "Recovery Key/Realm matrix selection changed; review the required scenario matrix"

Push-Location $e2eRoot
try {
    $deviceEntryListed = @(& node $playwrightCli test --config playwright.config.ts --project=joint-inkson --grep "second-device login stays unauthorized|24-word Recovery Key instead" --list 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Playwright fresh-device entry selection failed:`n$($deviceEntryListed -join [Environment]::NewLine)"
    }
} finally {
    Pop-Location
}
$deviceEntrySelection = ($deviceEntryListed -join "`n") -replace '\\', '/'
Assert-Contains $deviceEntrySelection "identity/multi-device.spec.ts" "joint-inkson did not discover both fresh-device entry paths"
Assert-Contains $deviceEntrySelection "Total: 2 tests in 1 file" "fresh-device entry selection changed; review the required scenario matrix"

Push-Location $e2eRoot
try {
    $kanbanListed = @(& node $playwrightCli test --config playwright.config.ts --project=joint-inkson --grep "@fully-implemented" tests/kanban/cross-member-encrypted.spec.ts --list 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Playwright cross-member kanban selection failed:`n$($kanbanListed -join [Environment]::NewLine)"
    }
} finally {
    Pop-Location
}
$kanbanSelection = ($kanbanListed -join "`n") -replace '\\', '/'
Assert-Contains $kanbanSelection "kanban/cross-member-encrypted.spec.ts" "joint-inkson did not discover cross-member encrypted kanban"
Assert-Contains $kanbanSelection "Total: 3 tests in 1 file" "cross-member encrypted kanban smoke selection changed"

Write-Host "Identity CI selection regression tests passed."

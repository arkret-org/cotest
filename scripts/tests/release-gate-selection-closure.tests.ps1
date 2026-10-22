[CmdletBinding()]
param(
    [string]$RepoRoot = (Join-Path $PSScriptRoot "../.."),
    [string]$SourceRoot
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (-not $SourceRoot) { $SourceRoot = $RepoRoot }
$runner = Join-Path $RepoRoot "scripts/run-server-conformance.ps1"
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "Invalid conformance runner syntax" }
foreach ($name in @("Get-ProfileCargoTests", "Get-CiProfile", "Get-ActiveQuarantineEntries", "Assert-CargoTestConfiguration", "Get-CargoTestInvocations", "New-CargoTestArgs", "Add-CargoTestArgsToInvocations", "Get-RequiredTestStatuses", "New-ReleaseGateCheck", "New-ReleaseGate")) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing production function $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$configText = Get-Content (Join-Path $RepoRoot "config/ci-profiles.json") -Raw
$known = @(
    Get-ChildItem (Join-Path $SourceRoot 'tests') -Filter '*.rs' -File | ForEach-Object {
        [pscustomobject]@{ package = 'cotest'; target = $_.BaseName }
    }
    Get-ChildItem (Join-Path $SourceRoot 'crates/inkson-client-tests/tests') -Filter '*.rs' -File | ForEach-Object {
        [pscustomobject]@{ package = 'cotest-inkson-client-tests'; target = $_.BaseName }
    }
)
function Jobs($config) {
    Assert-CargoTestConfiguration -Config $config -KnownTargets $known
    $profile = Get-CiProfile -Config $config -ProfileId 'release-gate'
    $quarantine = @(Get-ActiveQuarantineEntries -Config $config -ExcludedLabels @($profile.excluded_quarantine_labels))
    $jobs = @(Get-CargoTestInvocations -Profile $profile -QuarantineEntries $quarantine -KnownTargets $known -CargoTestPackage $null -CargoTestTarget $null -CargoTestFilter $null)
    return @(Add-CargoTestArgsToInvocations -Invocations $jobs)
}
function Gate($statuses) {
    $passing = [pscustomobject]@{ status = 'passed' }
    return New-ReleaseGate -Profile 'release-gate' -Tests @($statuses) -CoverageGate $passing -SecretScan $passing -SpecSyncGate $passing -JointSmokeGate $passing
}
function Statuses($jobs) {
    return @($jobs | ForEach-Object { [pscustomobject]@{ name = $_.filter; status = 'passed' } })
}
$required = @(
    [pscustomobject]@{ target = 'federation_idempotency_production'; filter = 'canonical_federation_cases_use_real_ingress_and_current_origin_binding' },
    [pscustomobject]@{ target = 'snapshot_handoff_live'; filter = 'three_station_stream_history_survives_unrelated_scope_loss_and_cold_restart' }
)
$config = $configText | ConvertFrom-Json
$jobs = @(Jobs $config)
if ($jobs.Count -ne 24 -or @($jobs | ForEach-Object { "$($_.package)/$($_.target)" } | Sort-Object -Unique).Count -ne 14) { throw 'Unexpected release selection size' }
foreach ($entry in $required) {
    $matches = @($jobs | Where-Object { $_.package -eq 'cotest' -and $_.target -eq $entry.target -and $_.filter -eq $entry.filter })
    if ($matches.Count -ne 1 -or $matches[0].selection_mode -ne 'target-filter' -or $matches[0].include_ignored -or $matches[0].skips.Count -ne 0) { throw 'Required real producer not selected exactly once' }
    $args = @($matches[0].cargo_args)
    if ($args -notcontains '--locked' -or $args -notcontains '--exact' -or $args -contains '--skip' -or $args -contains '--ignored') { throw 'Required producer Cargo command was weakened' }
    $testSource = Get-Content (Join-Path $SourceRoot "tests/$($entry.target).rs") -Raw
    if ($testSource -notmatch ('\bfn\s+' + [regex]::Escape($entry.filter) + '\s*\(')) { throw 'Required producer function is absent from its actual Rust target' }
}
if ((Gate (Statuses $jobs)).status -ne 'passed') { throw 'Actual configured release jobs cannot satisfy the release gate' }
foreach ($entry in $required) {
    foreach ($bad in @('missing', 'failed', 'ignored', 'skipped', 'wrong-name')) {
        $statuses = @(Statuses $jobs | Where-Object { $_.name -ne $entry.filter })
        if ($bad -eq 'wrong-name') { $statuses += [pscustomobject]@{ name = 'unrelated_success'; status = 'passed' } }
        elseif ($bad -ne 'missing') { $statuses += [pscustomobject]@{ name = $entry.filter; status = $bad } }
        $gate = Gate $statuses
        if ($gate.status -ne 'failed' -or @($gate.checks | Where-Object { $_.id -eq 'federation_replay' -and $_.status -eq 'failed' }).Count -ne 1) { throw "$bad required result passed" }
    }
    $missingConfig = $configText | ConvertFrom-Json
    $profile = Get-CiProfile -Config $missingConfig -ProfileId 'release-gate'
    $profile.cargo_tests = @($profile.cargo_tests | Where-Object { $_.filter -ne $entry.filter })
    if ((Gate (Statuses (Jobs $missingConfig))).status -ne 'failed') { throw 'Missing actual configuration entry passed the gate' }
    $wrongConfig = $configText | ConvertFrom-Json
    $profile = Get-CiProfile -Config $wrongConfig -ProfileId 'release-gate'
    ($profile.cargo_tests | Where-Object filter -eq $entry.filter).target = 'not_a_rust_target'
    $rejected = $false
    try { $null = Jobs $wrongConfig } catch { $rejected = $_.Exception.Message -like '*unknown cargo test target*' }
    if (-not $rejected) { throw 'Wrong configured target was accepted' }
}
Write-Host 'release-gate-selection-closure.tests.ps1: PASS (actual config -> production invocation builder -> release statuses; no Cargo or business tests executed)'

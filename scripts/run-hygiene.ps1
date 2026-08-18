[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$SkipCargoDeny,
    [switch]$SkipTypos,
    [switch]$SkipCargoAudit,
    [switch]$SkipE2eTypecheck,
    [switch]$SkipE2eWireTypes,
    [switch]$SkipFixmeDebt,
    [switch]$SkipFixmeQuality,
    [switch]$SkipAgentJourneyTests
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-CommandPath {
    param([Parameter(Mandatory = $true)][string]$Name)

    $command = Get-Command $Name -ErrorAction Stop
    return $command.Source
}

function Invoke-HygieneCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$RunDir,
        [Parameter(Mandatory = $true)][string]$RawLog,
        [string]$WorkingDirectory
    )

    if (-not $WorkingDirectory) {
        $WorkingDirectory = $repoRoot
    }

    $safeLabel = $Label -replace '[^A-Za-z0-9_.-]', '_'
    $stdoutPath = Join-Path $RunDir "$safeLabel.stdout.log"
    $stderrPath = Join-Path $RunDir "$safeLabel.stderr.log"
    $commandLine = "$FilePath $($Arguments -join ' ')"
    $startedAt = Get-Date

    Add-Content -Path $RawLog -Value ""
    Add-Content -Path $RawLog -Value "=== $Label ==="
    Add-Content -Path $RawLog -Value $commandLine

    $startArgs = @{
        FilePath               = $FilePath
        WorkingDirectory       = $WorkingDirectory
        NoNewWindow            = $true
        Wait                   = $true
        PassThru               = $true
        RedirectStandardOutput = $stdoutPath
        RedirectStandardError  = $stderrPath
    }
    if ($Arguments.Count -gt 0) {
        $startArgs.ArgumentList = $Arguments
    }
    $process = Start-Process @startArgs

    foreach ($path in @($stdoutPath, $stderrPath)) {
        if (Test-Path $path) {
            Get-Content -Path $path | Add-Content -Path $RawLog
        }
    }

    $finishedAt = Get-Date
    return [pscustomobject]@{
        label       = $Label
        status      = if ($process.ExitCode -eq 0) { "passed" } else { "failed" }
        exit_code   = $process.ExitCode
        command     = $commandLine
        started_at  = $startedAt.ToString("o")
        finished_at = $finishedAt.ToString("o")
        duration_ms = [int]($finishedAt - $startedAt).TotalMilliseconds
        stdout      = $stdoutPath
        stderr      = $stderrPath
    }
}

function Get-RustsecIgnoresFromDenyToml {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path $Path)) {
        return @()
    }
    $set = [System.Collections.Generic.SortedSet[string]]::new()
    foreach ($line in Select-String -Path $Path -Pattern 'RUSTSEC-\d{4}-\d{4}' -AllMatches) {
        foreach ($match in $line.Matches) {
            [void]$set.Add($match.Value)
        }
    }
    return @($set)
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repoRoot "artifacts\hygiene"
}

$runStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $OutputRoot $runStamp
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$rawLog = Join-Path $runDir "raw.log"
Set-Content -Path $rawLog -Value "cotest local hygiene run $runStamp" -Encoding UTF8

$results = New-Object System.Collections.Generic.List[object]
$cargoPath = Resolve-CommandPath "cargo"

if (-not $SkipCargoDeny) {
    $results.Add((Invoke-HygieneCommand -Label "cargo-deny" -FilePath $cargoPath -Arguments @("deny", "check") -RunDir $runDir -RawLog $rawLog))
}
if (-not $SkipTypos) {
    $typosPath = Resolve-CommandPath "typos"
    $results.Add((Invoke-HygieneCommand -Label "typos" -FilePath $typosPath -Arguments @() -RunDir $runDir -RawLog $rawLog))
}
if (-not $SkipCargoAudit) {
    $auditArgs = @("audit", "--deny", "warnings")
    foreach ($advisory in Get-RustsecIgnoresFromDenyToml -Path (Join-Path $repoRoot "deny.toml")) {
        $auditArgs += @("--ignore", $advisory)
    }
    $results.Add((Invoke-HygieneCommand -Label "cargo-audit" -FilePath $cargoPath -Arguments $auditArgs -RunDir $runDir -RawLog $rawLog))
}
if (-not $SkipE2eTypecheck) {
    $e2eDir = Join-Path $repoRoot "e2e"
    $e2eTsconfig = Join-Path $e2eDir "tsconfig.json"
    # Prefer the e2e-local TypeScript install; tsc resolves `include` paths
    # relative to the tsconfig, so the working directory is irrelevant.
    $tscExe = Join-Path $e2eDir "node_modules\.bin\tsc.cmd"
    if (-not (Test-Path $tscExe)) {
        $tscExe = Join-Path $e2eDir "node_modules\.bin\tsc"
    }
    if ((Test-Path $e2eTsconfig) -and (Test-Path $tscExe)) {
        $results.Add((Invoke-HygieneCommand -Label "e2e-typecheck" -FilePath $tscExe -Arguments @("--noEmit", "-p", $e2eTsconfig) -RunDir $runDir -RawLog $rawLog))
    } else {
        Add-Content -Path $rawLog -Value ""
        Add-Content -Path $rawLog -Value "=== e2e-typecheck (skipped) ==="
        Add-Content -Path $rawLog -Value "tsconfig or local tsc not found; run 'npm install' in e2e/ first"
    }
}
if (-not $SkipE2eWireTypes) {
    # Drift gate for the generated mirrors of the closed arkret-spec object
    # schemas (e2e/helpers/generated/spec-wire-objects.ts). `tsc --noEmit`
    # checks the hand-built wire literals against those mirrors; this check
    # makes sure the mirrors themselves still match the spec artifacts. It
    # reports "SKIP" (exit 0) when the sibling arkret-spec checkout is absent.
    $e2eDir = Join-Path $repoRoot "e2e"
    $generator = Join-Path $e2eDir "scripts\generate-wire-types.mjs"
    if (Test-Path $generator) {
        $nodePath = Resolve-CommandPath "node"
        $results.Add((Invoke-HygieneCommand -Label "e2e-wire-types" -FilePath $nodePath -Arguments @($generator, "--check") -RunDir $runDir -RawLog $rawLog))
    } else {
        Add-Content -Path $rawLog -Value ""
        Add-Content -Path $rawLog -Value "=== e2e-wire-types (skipped) ==="
        Add-Content -Path $rawLog -Value "generator not found at $generator"
    }
}
if (-not $SkipFixmeDebt) {
    # `fixme-debt.md` is a gitignored local derivative, so nothing in CI can
    # diff it. Refresh it here instead: the generator was previously manual-only
    # and the local copy silently went stale (it kept listing suites that had
    # already been deleted).
    $fixmeDebtGenerator = Join-Path $scriptDir "generate-fixme-debt.ps1"
    $pwshPath = Resolve-CommandPath "pwsh"
    $results.Add((Invoke-HygieneCommand -Label "fixme-debt" -FilePath $pwshPath -Arguments @("-NoProfile", "-File", $fixmeDebtGenerator) -RunDir $runDir -RawLog $rawLog))
}
if (-not $SkipFixmeQuality) {
    # `e2e/scripts/check-fixme-quality.mjs` is the policy gate behind
    # docs/fixme-promotion-checklist.md (no empty fixme callbacks, required
    # metadata). It only had an npm alias and no automated caller.
    $fixmeQuality = Join-Path $repoRoot "e2e\scripts\check-fixme-quality.mjs"
    if (Test-Path $fixmeQuality) {
        $nodePath = Resolve-CommandPath "node"
        # The checker resolves its scan root as `path.resolve("tests")`, so it
        # must run from e2e/ (same as `npm run check:fixme`).
        $results.Add((Invoke-HygieneCommand -Label "e2e-fixme-quality" -FilePath $nodePath -Arguments @($fixmeQuality) -RunDir $runDir -RawLog $rawLog -WorkingDirectory (Join-Path $repoRoot "e2e")))
    } else {
        Add-Content -Path $rawLog -Value ""
        Add-Content -Path $rawLog -Value "=== e2e-fixme-quality (skipped) ==="
        Add-Content -Path $rawLog -Value "checker not found at $fixmeQuality"
    }
}
if (-not $SkipAgentJourneyTests) {
    $nodePath = Resolve-CommandPath "node"
    $journeyTests = Join-Path $repoRoot "agent-journeys\scripts\journey.tests.mjs"
    $results.Add((Invoke-HygieneCommand -Label "agent-journey-tests" -FilePath $nodePath -Arguments @("--test", $journeyTests) -RunDir $runDir -RawLog $rawLog))
}
if ($results.Count -eq 0) {
    throw "No hygiene checks were selected"
}

$failed = @($results | Where-Object { $_.exit_code -ne 0 })
$status = if ($failed.Count -eq 0) { "passed" } else { "failed" }
$summary = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    status       = $status
    output_dir   = $runDir
    checks       = $results.ToArray()
}

$summaryJson = Join-Path $runDir "summary.json"
$summaryMd = Join-Path $runDir "summary.md"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryJson -Encoding UTF8

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# cotest local hygiene")
$lines.Add("")
$lines.Add("- status: $status")
$lines.Add("- output: $runDir")
$lines.Add("- raw log: $rawLog")
$lines.Add("")
$lines.Add("| check | status | exit | stdout | stderr |")
$lines.Add("| --- | --- | ---: | --- | --- |")
foreach ($result in $results) {
    $lines.Add("| $($result.label) | $($result.status) | $($result.exit_code) | $($result.stdout) | $($result.stderr) |")
}
$lines | Set-Content -Path $summaryMd -Encoding UTF8

Write-Host "Hygiene summary: $summaryMd"
if ($failed.Count -gt 0) {
    exit 1
}

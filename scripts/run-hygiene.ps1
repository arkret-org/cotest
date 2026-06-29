[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$SkipCargoDeny,
    [switch]$SkipTypos,
    [switch]$SkipCargoAudit,
    [switch]$SkipE2eTypecheck
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
        [Parameter(Mandatory = $true)][string]$RawLog
    )

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
        WorkingDirectory       = $repoRoot
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

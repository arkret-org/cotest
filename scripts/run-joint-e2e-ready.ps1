<#
.SYNOPSIS
Runs the read-only environment gate and then the joint E2E runner.
.EXAMPLE
pwsh -NoProfile -File scripts/run-joint-e2e-ready.ps1 -RunProfile joint-full -ServerCount 3 -StartCoauth
#>
[CmdletBinding()]
param(
    [ValidateSet("joint-smoke", "joint-full")][string]$RunProfile = "joint-smoke",
    [ValidateRange(1, 32)][int]$ServerCount = 1,
    [ValidateSet("full-mesh", "ordered-candidates")][string]$NetworkShape = "full-mesh",
    [switch]$StartCoauth,
    [string]$OutputRoot,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$RunnerArguments = @()
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
foreach ($argument in $RunnerArguments) {
    if ($argument -match '^-SkipPreflight$|^-DualSoland$|^-ForbidSkippedTests:False$') {
        throw "run-joint-e2e-ready.ps1 refuses unsafe or deprecated argument $argument"
    }
}
if (-not $OutputRoot) { $OutputRoot = Join-Path (Split-Path -Parent $PSScriptRoot) "artifacts" }
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$preflightDirectory = Join-Path $OutputRoot ("environment\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
$preflightArgs = @("-ServerCount", "$ServerCount", "-OutputDirectory", $preflightDirectory)
if ($StartCoauth) { $preflightArgs += "-StartCoauth" }
& (Join-Path $PSScriptRoot "check-joint-e2e-prerequisites.ps1") @preflightArgs
$preflightExit = $LASTEXITCODE
if ($preflightExit -ne 0) {
    Write-Host "Joint E2E stopped before service startup. Preflight report: $preflightDirectory"
    exit $preflightExit
}
$runnerArgs = @("-RunProfile", $RunProfile, "-ServerCount", "$ServerCount", "-NetworkShape", $NetworkShape, "-OutputRoot", $OutputRoot)
if ($StartCoauth) { $runnerArgs += "-StartCoauth" }
$runnerArgs += $RunnerArguments
& (Join-Path $PSScriptRoot "run-joint-e2e.ps1") @runnerArgs
$runnerExit = $LASTEXITCODE
Write-Host "Joint E2E output root: $OutputRoot"
Write-Host "Joint E2E exit code: $runnerExit"
exit $runnerExit

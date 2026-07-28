param(
    [Parameter(Mandatory = $true)]
    [string]$ControlPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$control = Get-Content -Raw -LiteralPath $ControlPath | ConvertFrom-Json
$readyPath = [string]$control.ready_signal
$completePath = [string]$control.complete_signal
$timeoutSeconds = [int]$control.timeout_seconds
$journeyScript = [string]$control.journey_script
$runDir = [string]$control.run_dir

[ordered]@{
    ready_at = (Get-Date).ToUniversalTime().ToString("o")
    runtime_manifest = $env:COTEST_RUNTIME_MANIFEST
} | ConvertTo-Json | Set-Content -LiteralPath $readyPath -Encoding UTF8

$deadline = (Get-Date).AddSeconds($timeoutSeconds)
while (-not (Test-Path -LiteralPath $completePath)) {
    if ((Get-Date) -ge $deadline) {
        Write-Error "Agent journey timed out waiting for completion signal: $completePath"
        exit 2
    }
    Start-Sleep -Seconds 1
}

& node $journeyScript validate --run-dir $runDir --finished --gate
exit $LASTEXITCODE


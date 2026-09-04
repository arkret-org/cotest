$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$topologyFiles = @(
    "scripts\run-joint-e2e.ps1",
    "scripts\run-joint-e2e-ready.ps1",
    "scripts\control-joint-e2e-service.ps1",
    "scripts\check-joint-e2e-prerequisites.ps1",
    "scripts\lib\joint-e2e-environment.ps1",
    "e2e\helpers\env.ts"
)
$forbidden = '(?i)(soland|coauth|inkson)[_-](alpha|beta|gamma)|COTEST_(SOLAND|COAUTH|INKSON)_(ALPHA|BETA|GAMMA)'
$violations = @()
foreach ($relative in $topologyFiles) {
    $path = Join-Path $repoRoot $relative
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $path) {
        $lineNumber++
        if ($line -match $forbidden) { $violations += "${relative}:${lineNumber}:$line" }
    }
}
if ($violations.Count -gt 0) { throw "Forbidden fixed topology naming found:`n$($violations -join "`n")" }
Write-Host "joint-topology-naming.tests.ps1: PASS"

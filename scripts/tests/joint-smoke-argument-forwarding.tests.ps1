$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$runner = Join-Path $PSScriptRoot "../run-server-conformance.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "Invalid conformance runner syntax" }
foreach ($name in @("Add-RawLogLine", "ConvertTo-NativeCommandLineArgument", "Invoke-JointSmokeGate")) {
    $function = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $function) { throw "Missing runner function $name" }
    . ([scriptblock]::Create($function.Extent.Text))
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) "cotest joint forwarding $([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path (Join-Path $scratch "scripts") -Force
try {
    # An actual child shell records its argv; no database or service is simulated.
    @'
param(
    [string]$JointDir, [switch]$StartCoauth, [int]$ServerCount,
    [string]$RunProfile, [string]$PlaywrightProject, [string]$DnsSuffix,
    [string]$PostgresAdminUrl, [string]$PostgresToolsDirectory, [string]$PostgresDataDirectory
)
$null = New-Item -ItemType Directory -Path $JointDir -Force
$PSBoundParameters | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $JointDir "arguments.json")
'@ | Set-Content -LiteralPath (Join-Path $scratch "scripts/run-joint-e2e.ps1")
    $tools = Join-Path $scratch "Postgres Tools"
    $data = Join-Path $scratch "Postgres Data"
    $admin = "postgres://fixture@127.0.0.1:54329/fixture"
    $result = Invoke-JointSmokeGate -RepoRoot $scratch -RunDir $scratch `
        -RawLog (Join-Path $scratch "raw.log") -DnsSuffix localhost `
        -PostgresAdminUrl $admin -PostgresToolsDirectory $tools -PostgresDataDirectory $data
    if ($result.exit_code -ne 0) { throw "Joint child did not complete" }
    $actual = Get-Content -Raw -LiteralPath (Join-Path $scratch "joint-smoke/arguments.json") | ConvertFrom-Json
    foreach ($pair in @(
        @("DnsSuffix", "localhost"), @("PostgresAdminUrl", $admin),
        @("PostgresToolsDirectory", $tools), @("PostgresDataDirectory", $data),
        @("RunProfile", "joint-smoke"), @("PlaywrightProject", "chromium")
    )) {
        if ($actual.($pair[0]) -cne $pair[1]) { throw "Child argument $($pair[0]) was changed or omitted" }
    }
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
Write-Host "joint-smoke-argument-forwarding.tests.ps1: PASS"

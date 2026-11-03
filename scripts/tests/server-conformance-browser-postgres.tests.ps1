[CmdletBinding()]
param([string]$RepoRoot = (Join-Path $PSScriptRoot '../..'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepoRoot 'scripts/run-server-conformance.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Runner syntax must be valid' }
$calls = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.Extent.Text.StartsWith('& (Join-Path $PSScriptRoot') -and
    $node.Extent.Text.Contains('-NativeToolsEnvironmentFile $tools')
}, $true))
if ($calls.Count -ne 1) { throw 'Select the actual native browser preparation command' }
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'artifacts/tool-tests'))
$scratch = Join-Path $artifactRoot ('browser-postgres-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch -Force
try {
    # The unmodified production call runs from a real script directory, so its
    # automatic PSScriptRoot resolves our argument-capturing child entry point.
    $entry = @'
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$provided = Get-Content -Raw (Join-Path $PSScriptRoot 'arguments.json') | ConvertFrom-Json -AsHashtable
$PostgresAdminUrl = [string]$provided.PostgresAdminUrl
$PostgresToolsDirectory = [string]$provided.PostgresToolsDirectory
$PostgresDataDirectory = [string]$provided.PostgresDataDirectory
$tools = Join-Path $PSScriptRoot 'native-tools.env'
$browserPreparation = Join-Path $PSScriptRoot 'browser-preparation'
$DnsSuffix = 'localhost'
$env:COLAND_BIN = 'fixture-coland'
$env:COAUTH_BIN = 'fixture-coauth'
'@
    [IO.File]::WriteAllText((Join-Path $scratch 'entry.ps1'), $entry + "`n" + $calls[0].Extent.Text)
    [IO.File]::WriteAllText((Join-Path $scratch 'run-joint-e2e.ps1'), @'
param(
    [switch]$PreflightOnly, [string]$NativeToolsEnvironmentFile, [string]$JointDir,
    [string]$ColandBin, [switch]$StartCoauth, [string]$CoauthBin,
    [switch]$StartMockEmail, [string]$DnsSuffix, [string]$RunProfile,
    [string]$PlaywrightProject, [string]$Grep, [string]$RequireScenario,
    [switch]$ForbidSkippedTests, [string]$PostgresAdminUrl,
    [string]$PostgresToolsDirectory, [string]$PostgresDataDirectory
)
$PSBoundParameters | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $PSScriptRoot 'captured.json') -Encoding utf8
'@)
    foreach ($native in @($true, $false)) {
        $expected = @{
            PostgresAdminUrl = $(if ($native) { 'postgresql://test-admin@127.0.0.1:16432/admin' } else { '' })
            PostgresToolsDirectory = $(if ($native) { Join-Path $scratch 'tools with spaces' } else { '' })
            PostgresDataDirectory = $(if ($native) { Join-Path $scratch 'cluster with spaces' } else { '' })
        }
        # JSON transports empty defaults without depending on the host's native
        # PowerShell -File empty-argument policy. The production call is intact.
        $expected | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $scratch 'arguments.json') -Encoding utf8
        & (Get-Process -Id $PID).Path -NoProfile -File (Join-Path $scratch 'entry.ps1')
        if ($LASTEXITCODE -ne 0) { throw 'Actual browser-preparation invocation failed' }
        $captured = Get-Content -Raw (Join-Path $scratch 'captured.json') | ConvertFrom-Json -AsHashtable
        foreach ($name in $expected.Keys) {
            if (-not $captured.ContainsKey($name) -or [string]$captured[$name] -cne $expected[$name]) {
                throw "Native browser preparation lost $name (native=$native)"
            }
        }
        if (-not $captured.PreflightOnly -or -not $captured.StartCoauth -or
            -not $captured.StartMockEmail -or -not $captured.ForbidSkippedTests -or
            $captured.RequireScenario -cne 'joint/agent-provision-recovery-prerequisite') {
            throw 'The required real browser selection and preflight boundaries changed'
        }
    }
    Write-Host 'Native browser PostgreSQL forwarding: PASS (actual production argv, native and Docker defaults; no service/business execution)'
} finally {
    $prefix = $artifactRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not [IO.Path]::GetFullPath($scratch).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Fixture cleanup escaped its owned artifact root'
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}

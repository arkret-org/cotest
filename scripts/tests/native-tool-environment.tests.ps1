$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../lib/build-freshness.ps1')

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('cotest-tool-env-' + [Guid]::NewGuid().ToString('n'))
$null = New-Item -ItemType Directory -Path $scratch
try {
    $source = Join-Path $scratch 'cotest-wire'
    [IO.File]::WriteAllText($source, "#!/bin/sh`nexit 0`n")
    if (-not $IsWindows) { & chmod 755 $source; if ($LASTEXITCODE -ne 0) { throw 'chmod failed' } }
    $states = @([pscustomobject]@{
        RepositoryRoot = $scratch; Head = ('a' * 40)
        SourceSha256 = ('b' * 64); DirtySha256 = ('c' * 64)
    })
    Write-ArtifactBuildStamp -ArtifactPath $source -RepositoryStates $states | Out-Null
    $frozen = Copy-RunScopedNativeArtifact -ArtifactPath $source -DestinationRoot (Join-Path $scratch 'prepared') -RepositoryStates $states
    [IO.File]::WriteAllText($source, 'Cargo replaced the shared target after preflight')
    Assert-True (Test-ArtifactBuildStamp -ArtifactPath $frozen -RepositoryStates $states).Matches 'prepared bytes must survive a later Cargo build'

    $envFile = Join-Path $scratch 'github-env'
    [IO.File]::WriteAllText($envFile, "EXISTING=preserved`n")
    Write-RunScopedNativeToolEnvironment -Tools @{ COTEST_WIRE_BIN = $frozen } -Path $envFile
    Assert-True ([IO.File]::ReadAllText($envFile) -ceq "EXISTING=preserved`nCOTEST_WIRE_BIN=$frozen`n") 'export must append the frozen path'
    $child = Copy-RunScopedNativeArtifact -ArtifactPath $frozen -CallerProvided -DestinationRoot (Join-Path $scratch 'child')
    Assert-True ((Get-FileHash -LiteralPath $child).Hash -ceq (Get-FileHash -LiteralPath $frozen).Hash) 'the child must receive the prepared bytes, not the rewritten target'
    if (-not $IsWindows) {
        & $child
        Assert-True ($LASTEXITCODE -eq 0) 'the frozen child tool must retain executable permissions'
    }

    foreach ($tools in @(
        @{ UNKNOWN_TOOL = $frozen },
        @{ COTEST_WIRE_BIN = "relative/tool" },
        @{ COTEST_WIRE_BIN = "$frozen`nINJECTED=value" },
        @{ COTEST_PROVISION_BIN = (Join-Path $scratch 'missing') }
    )) {
        $before = [IO.File]::ReadAllText($envFile)
        $rejected = $false
        try { Write-RunScopedNativeToolEnvironment -Tools $tools -Path $envFile }
        catch { $rejected = $true }
        Assert-True $rejected 'invalid tool exports must be rejected'
        Assert-True ([IO.File]::ReadAllText($envFile) -ceq $before) 'a rejected export must leave the environment unchanged'
    }
    [IO.File]::WriteAllText($frozen, 'frozen bytes were tampered with')
    $before = [IO.File]::ReadAllText($envFile)
    $rejected = $false
    try { Write-RunScopedNativeToolEnvironment -Tools @{ COTEST_WIRE_BIN = $frozen } -Path $envFile }
    catch { $rejected = $true }
    Assert-True $rejected 'a tool changed after freezing must not be exported'
    Assert-True ([IO.File]::ReadAllText($envFile) -ceq $before) 'tampered tools must not change the environment'
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Split-Path -Leaf $resolved).StartsWith('cotest-tool-env-', [StringComparison]::Ordinal)) {
        throw 'Tool test cleanup escaped the temporary directory'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Host 'Native tool environment regressions passed.'

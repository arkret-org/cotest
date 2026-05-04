[CmdletBinding()]
param(
    [string]$ImageTag = "cotest-soland:latest",
    [string]$WorkspaceRoot,
    [string]$DockerfilePath,
    [string[]]$CacheFrom = @(),
    [string]$CacheTo,
    [switch]$Pull,
    [switch]$NoCache
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $repoRoot "..")).Path
}
if (-not $DockerfilePath) {
    $DockerfilePath = Join-Path $repoRoot "docker\soland.Dockerfile"
}

$requiredPaths = @(
    (Join-Path $WorkspaceRoot "soland"),
    (Join-Path $WorkspaceRoot "contrix-rust-sdk"),
    $DockerfilePath
)

foreach ($path in $requiredPaths) {
    if (-not (Test-Path $path)) {
        throw "Required path not found: $path"
    }
}

$buildArgs = @("build", "--file", $DockerfilePath, "--tag", $ImageTag)
foreach ($cache in $CacheFrom) {
    if ($cache) {
        $buildArgs += @("--cache-from", $cache)
    }
}
if ($CacheTo) {
    $buildArgs += @("--cache-to", $CacheTo)
}
if ($Pull) {
    $buildArgs += "--pull"
}
if ($NoCache) {
    $buildArgs += "--no-cache"
}
$buildArgs += $WorkspaceRoot

Write-Host "Building $ImageTag from $DockerfilePath with context $WorkspaceRoot"
if ($CacheFrom.Count -gt 0) {
    Write-Host "  cache-from: $($CacheFrom -join ', ')"
}
if ($CacheTo) {
    Write-Host "  cache-to  : $CacheTo"
}
& docker @buildArgs
if ($LASTEXITCODE -ne 0) {
    throw "docker build failed for image $ImageTag"
}

[CmdletBinding()]
param(
    [string]$ImageTag = "cotest-coland:latest",
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
    $DockerfilePath = Join-Path $repoRoot "docker\coland.Dockerfile"
}

$requiredPaths = @(
    (Join-Path $WorkspaceRoot "coland"),
    (Join-Path $WorkspaceRoot "arkret-rust-sdk"),
    (Join-Path $WorkspaceRoot "arkret-spec"),
    (Join-Path $WorkspaceRoot "garth"),
    (Join-Path $WorkspaceRoot "chime"),
    (Join-Path $WorkspaceRoot "inkson"),
    (Join-Path $WorkspaceRoot "floria"),
    (Join-Path $WorkspaceRoot "coauth"),
    (Join-Path $WorkspaceRoot "cotest"),
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

[CmdletBinding()]
param(
    [string]$ImageTag = "cotest-soland:latest",
    [string]$WorkspaceRoot,
    [string]$DockerfilePath
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

Write-Host "Building $ImageTag from $DockerfilePath with context $WorkspaceRoot"
& docker build --file $DockerfilePath --tag $ImageTag $WorkspaceRoot
if ($LASTEXITCODE -ne 0) {
    throw "docker build failed for image $ImageTag"
}

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$BinaryName,
    [string]$PackageName,
    [string[]]$Features = @(),
    [string]$TargetDirectory,
    [ValidateRange(1, 256)][int]$Jobs = 4,
    [string[]]$RepositoryRoots = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib/build-freshness.ps1')

# This entry point prepares exactly one native debug binary, in one serial
# Cargo invocation. Callers cannot stamp an arbitrary executable or command.
$manifest = Resolve-BuildInputPath -Path $ManifestPath
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "Cargo manifest missing: $manifest" }
$workingDirectory = Split-Path -Parent $manifest
$cargo = Get-Command cargo -ErrorAction Stop
$previousTargetDirectory = $env:CARGO_TARGET_DIR
try {
    if ($TargetDirectory) { $env:CARGO_TARGET_DIR = Resolve-BuildInputPath -Path $TargetDirectory }
    $metadata = Invoke-BuildInputNative -FilePath $cargo.Source -WorkingDirectory $workingDirectory -Arguments @(
        'metadata', '--format-version', '1', '--locked', '--offline', '--all-features', '--manifest-path', $manifest
    ) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    $packages = @($metadata.packages | Where-Object {
        $metadata.workspace_members -ccontains $_.id -and
        (-not $PackageName -or $_.name -ceq $PackageName) -and
        @($_.targets | Where-Object { $_.name -ceq $BinaryName -and $_.kind -contains 'bin' }).Count -eq 1
    })
    if ($packages.Count -ne 1) { throw "Cargo metadata must select exactly one workspace binary: $BinaryName (packages=$($packages.Count))" }
    $package = $packages[0]
    $executableName = if ($IsWindows) { "$BinaryName.exe" } else { $BinaryName }
    $artifact = Resolve-BuildInputPath -Path (Join-Path $metadata.target_directory "debug/$executableName")
    $repositoryRoot = (Invoke-BuildInputGit -RepositoryRoot $workingDirectory -Arguments @('rev-parse', '--show-toplevel')).Trim()
    $roots = @($repositoryRoot) + @($RepositoryRoots)
    $before = @(Get-ArtifactBuildRepositoryStates -ArtifactPath $artifact -RepositoryRoots $roots)
    $buildArguments = @('build', '--locked', '--manifest-path', $manifest, '--package', $package.name,
        '--bin', $BinaryName, '--jobs', [string]$Jobs, '--message-format', 'json-render-diagnostics')
    if ($Features.Count -gt 0) { $buildArguments += @('--features', ($Features -join ',')) }
    if ($TargetDirectory) { $buildArguments += @('--target-dir', $env:CARGO_TARGET_DIR) }
    Write-Host "Preparing Cargo binary $($package.name)/$BinaryName (jobs=$Jobs)"
    Push-Location $workingDirectory
    try {
        $messages = @(& $cargo.Source @buildArguments)
        $buildExitCode = $LASTEXITCODE
    } finally { Pop-Location }
    $outputs = @($messages | ForEach-Object {
        $message = $_ | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        if ($message.reason -eq 'compiler-message' -and $message.message.rendered) { Write-Host $message.message.rendered }
        if ($message.reason -eq 'compiler-artifact' -and $message.package_id -ceq $package.id -and
            $message.target.name -ceq $BinaryName -and $message.target.kind -contains 'bin' -and $message.executable) {
            $message
        }
    })
    if ($buildExitCode -ne 0) { throw "Cargo binary preparation failed (exit=$buildExitCode); no build stamp written" }
    if ($outputs.Count -ne 1 -or (Resolve-BuildInputPath -Path $outputs[0].executable) -cne $artifact) {
        throw "Cargo did not report the unique selected binary at its metadata target path; no build stamp written"
    }
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) { throw "Cargo reported a missing binary: $artifact" }
    $after = @(Get-ArtifactBuildRepositoryStates -ArtifactPath $artifact -RepositoryRoots $roots)
    Assert-BuildInputStatesUnchanged -Before $before -After $after
    $stamp = Write-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $after
    $verified = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $after
    if (-not $verified.Matches) { throw "Prepared binary stamp verification failed: $($verified.Detail)" }
    [pscustomobject]@{
        ArtifactPath = $artifact
        StampPath = $stamp
        CargoFresh = [bool]$outputs[0].fresh
        ArtifactTimeUtc = (Get-Item -LiteralPath $artifact -Force).LastWriteTimeUtc
        ArtifactSha256 = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    }
} finally { $env:CARGO_TARGET_DIR = $previousTargetDirectory }

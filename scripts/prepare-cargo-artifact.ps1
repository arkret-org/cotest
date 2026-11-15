[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Single')][string]$BinaryName,
    [Parameter(Mandatory = $true, ParameterSetName = 'Batch')][ValidateNotNullOrEmpty()][string[]]$BinaryNames,
    [string]$PackageName,
    [string[]]$Features = @(),
    [string]$TargetDirectory,
    [ValidateRange(1, 256)][int]$Jobs = 4,
    [string[]]$RepositoryRoots = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib/build-freshness.ps1')

# Each invocation prepares selected native debug binaries from one package and
# feature graph. Callers cannot stamp an arbitrary executable or command.
[string[]]$names = @(if ($PSCmdlet.ParameterSetName -eq 'Batch') { $BinaryNames } else { $BinaryName })
if (@($names | Sort-Object -Unique).Count -ne $names.Count) { throw 'Duplicate batch binary names' }
$timer = [Diagnostics.Stopwatch]::StartNew()
$timings = [ordered]@{}
$manifest = Resolve-BuildInputPath -Path $ManifestPath
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "Cargo manifest missing: $manifest" }
$workingDirectory = Split-Path -Parent $manifest
$cargo = Get-Command cargo -ErrorAction Stop
$previousTargetDirectory = $env:CARGO_TARGET_DIR
try {
    if ($TargetDirectory) { $env:CARGO_TARGET_DIR = Resolve-BuildInputPath -Path $TargetDirectory }
    Initialize-LockedCargoDependencyCache -RepositoryRoots (@($workingDirectory) + @($RepositoryRoots))
    $timings.dependency_seconds = $timer.Elapsed.TotalSeconds
    $phaseStart = $timer.Elapsed.TotalSeconds
    $metadata = Invoke-BuildInputNative -FilePath $cargo.Source -WorkingDirectory $workingDirectory -Arguments @(
        'metadata', '--format-version', '1', '--locked', '--offline', '--all-features', '--manifest-path', $manifest
    ) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    $packages = @($metadata.packages | Where-Object {
        $metadata.workspace_members -ccontains $_.id -and
        (-not $PackageName -or $_.name -ceq $PackageName) -and
        @($_.targets | Where-Object { $names -ccontains $_.name -and $_.kind -contains 'bin' }).Count -eq $names.Count
    })
    if ($packages.Count -ne 1) { throw "Cargo metadata must select all binaries in exactly one workspace package (packages=$($packages.Count))" }
    $package = $packages[0]
    $artifacts = @($names | ForEach-Object {
        $executableName = if ($IsWindows) { "$_.exe" } else { $_ }
        Resolve-BuildInputPath -Path (Join-Path $metadata.target_directory "debug/$executableName")
    })
    $artifact = $artifacts[0]
    $timings.metadata_seconds = $timer.Elapsed.TotalSeconds - $phaseStart
    $phaseStart = $timer.Elapsed.TotalSeconds
    $repositoryRoot = (Invoke-BuildInputGit -RepositoryRoot $workingDirectory -Arguments @('rev-parse', '--show-toplevel')).Trim()
    $roots = @($repositoryRoot) + @($RepositoryRoots)
    $before = @(Get-ArtifactBuildRepositoryStates -ArtifactPath $artifact -RepositoryRoots $roots)
    if ($names.Count -gt 1) { Assert-BatchArtifactInputsEquivalent -ArtifactPaths $artifacts -RepositoryStates $before }
    $timings.before_inputs_seconds = $timer.Elapsed.TotalSeconds - $phaseStart
    $buildArguments = @('build', '--locked', '--manifest-path', $manifest, '--package', $package.name,
        '--jobs', [string]$Jobs, '--message-format', 'json-render-diagnostics')
    foreach ($name in $names) { $buildArguments += @('--bin', $name) }
    if ($Features.Count -gt 0) { $buildArguments += @('--features', ($Features -join ',')) }
    if ($TargetDirectory) { $buildArguments += @('--target-dir', $env:CARGO_TARGET_DIR) }
    Write-Host "Preparing Cargo binaries $($package.name)/$($names -join ',') (jobs=$Jobs)"
    $phaseStart = $timer.Elapsed.TotalSeconds
    Push-Location $workingDirectory
    try {
        $messages = @(& $cargo.Source @buildArguments)
        $buildExitCode = $LASTEXITCODE
    } finally { Pop-Location }
    $timings.build_seconds = $timer.Elapsed.TotalSeconds - $phaseStart
    $outputs = @($messages | ForEach-Object {
        $message = $_ | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        if ($message.reason -eq 'compiler-message' -and $message.message.rendered) { Write-Host $message.message.rendered }
        if ($message.reason -eq 'compiler-artifact' -and $message.package_id -ceq $package.id -and
            $names -ccontains $message.target.name -and $message.target.kind -contains 'bin' -and $message.executable) {
            $message
        }
    })
    if ($buildExitCode -ne 0) { throw "Cargo binary preparation failed (exit=$buildExitCode); no build stamp written" }
    foreach ($index in 0..($names.Count - 1)) {
        $selected = @($outputs | Where-Object { $_.target.name -ceq $names[$index] })
        if ($selected.Count -ne 1 -or (Resolve-BuildInputPath -Path $selected[0].executable) -cne $artifacts[$index]) {
            throw 'Cargo did not report each unique selected binary at its metadata target path; no build stamp written'
        }
        if (-not (Test-Path -LiteralPath $artifacts[$index] -PathType Leaf)) { throw 'Cargo reported a missing binary; no build stamp written' }
    }
    $phaseStart = $timer.Elapsed.TotalSeconds
    $after = @(Get-ArtifactBuildRepositoryStates -ArtifactPath $artifact -RepositoryRoots $roots)
    if ($names.Count -gt 1) { Assert-BatchArtifactInputsEquivalent -ArtifactPaths $artifacts -RepositoryStates $after }
    Assert-BuildInputStatesUnchanged -Before $before -After $after
    $timings.after_inputs_seconds = $timer.Elapsed.TotalSeconds - $phaseStart
    $phaseStart = $timer.Elapsed.TotalSeconds
    $prepared = @(
        foreach ($index in 0..($names.Count - 1)) {
            $artifact = $artifacts[$index]
            $selected = @($outputs | Where-Object { $_.target.name -ceq $names[$index] })[0]
            $stamp = Write-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $after
            $verified = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $after
            if (-not $verified.Matches) { throw "Prepared binary stamp verification failed: $($verified.Detail)" }
            [pscustomobject]@{
                BinaryName = $names[$index]
                ArtifactPath = $artifact
                StampPath = $stamp
                CargoFresh = [bool]$selected.fresh
                ArtifactTimeUtc = (Get-Item -LiteralPath $artifact -Force).LastWriteTimeUtc
                ArtifactSha256 = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
                BatchTimings = $timings
            }
        }
    )
    $timings.stamps_seconds = $timer.Elapsed.TotalSeconds - $phaseStart
    $timings.total_seconds = $timer.Elapsed.TotalSeconds
    $timings.binary_count = $names.Count
    $prepared
} finally { $env:CARGO_TARGET_DIR = $previousTargetDirectory }

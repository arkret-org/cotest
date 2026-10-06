# Source identity and artifact-byte sidecars for runner-managed builds.

function Get-BuildInputDigest {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))).Replace("-", "").ToLowerInvariant()
    } finally { $hasher.Dispose() }
}

function Invoke-BuildInputNative {
    param([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory)
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $FilePath
    if ($WorkingDirectory) { $info.WorkingDirectory = $WorkingDirectory }
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $info.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "Build input inspection failed: $FilePath ($($process.ExitCode)): $($stderr.Result)" }
        return $stdout.Result
    } finally { $process.Dispose() }
}

function Invoke-BuildInputGit {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot, [string[]]$Arguments)
    $git = Get-Command git -ErrorAction Stop
    return Invoke-BuildInputNative -FilePath $git.Source -Arguments (@('-C', $RepositoryRoot) + $Arguments)
}

function Resolve-BuildInputPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $current = [System.IO.Path]::GetPathRoot($full)
    $separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    foreach ($segment in $full.Substring($current.Length).Split($separators, [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $current = Join-Path $current $segment
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        # Resolve directory aliases only. A file link remains a source record
        # with its own link target and the bytes read through that target.
        if ($null -ne $item -and $item.PSIsContainer -and
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            $resolved = $item.ResolveLinkTarget($true)
            if ($null -eq $resolved) { throw "Build input directory link cannot be resolved: $current" }
            $current = $resolved.FullName
        }
    }
    return $current
}

function Resolve-RepositoryBuildInputRoots {
    param([Parameter(Mandatory = $true)][string[]]$RepositoryRoots)
    $roots = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    $cargo = Get-Command cargo -ErrorAction Stop
    foreach ($candidate in $RepositoryRoots) {
        $root = Resolve-BuildInputPath -Path ((Invoke-BuildInputGit -RepositoryRoot $candidate -Arguments @('rev-parse', '--show-toplevel')).Trim())
        $null = $roots.Add($root)
        $manifest = Join-Path $root 'Cargo.toml'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "Build dependency root has no Cargo manifest: $root" }
        # Full offline metadata includes local patches as well as inherited,
        # target-specific, build, dev and optional path dependencies. --no-deps
        # cannot discover a registry dependency replaced by a local patch.
        $metadata = Invoke-BuildInputNative -FilePath $cargo.Source -WorkingDirectory $root -Arguments @(
            'metadata', '--format-version', '1', '--locked', '--offline', '--all-features', '--manifest-path', $manifest
        ) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        if ($metadata -isnot [System.Collections.IDictionary] -or -not $metadata.Contains('packages')) { throw "Cargo build dependency inventory is missing: $root" }
        foreach ($package in $metadata.packages) {
            if ($null -ne $package.source) { continue }
            $packageRoot = Split-Path -Parent $package.manifest_path
            $dependencyRoot = (Invoke-BuildInputGit -RepositoryRoot $packageRoot -Arguments @('rev-parse', '--show-toplevel')).Trim()
            $null = $roots.Add((Resolve-BuildInputPath -Path $dependencyRoot))
        }
    }
    return @($roots)
}

function Get-BuildInputFileRecord {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$RelativePath)
    $path = Join-Path $Root $RelativePath
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return [ordered]@{ path = $RelativePath; kind = 'missing'; mode = ''; target = ''; sha256 = '' }
    }
    $target = if ($item.PSObject.Properties['LinkTarget']) { [string]$item.LinkTarget } elseif ($item.PSObject.Properties['Target']) { [string]($item.Target -join "`0") } else { '' }
    if ($item.PSIsContainer) { throw "Build input directory link requires an explicit dependency root: $path" }
    $mode = if ($item.PSObject.Properties['UnixFileMode']) { [string]$item.UnixFileMode } else { '' }
    return [ordered]@{
        path = $RelativePath
        kind = if ($target) { 'symlink' } else { 'file' }
        mode = $mode
        target = $target
        sha256 = if (Test-Path -LiteralPath $path -PathType Leaf) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } else { "" }
    }
}

function Get-RepositoryBuildInputState {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot, [Parameter(Mandatory = $true)][string]$BinaryPath, [string]$ArtifactRoot)
    $root = Resolve-BuildInputPath -Path $RepositoryRoot
    $binary = Resolve-BuildInputPath -Path $BinaryPath
    $head = (Invoke-BuildInputGit -RepositoryRoot $root -Arguments @('rev-parse', 'HEAD')).Trim()
    # Git's non-ignored inventory includes new source files and deleted tracked
    # paths. Do not guess build inputs from extensions or layout conventions.
    $inventory = Invoke-BuildInputGit -RepositoryRoot $root -Arguments @('ls-files', '--cached', '--others', '--exclude-standard', '-z')
    $paths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($path in $inventory.Split([char[]]@([char]0), [System.StringSplitOptions]::RemoveEmptyEntries)) { $null = $paths.Add($path) }
    $excluded = @($binary, (Get-ArtifactBuildStampPath -ArtifactPath $binary))
    if ($ArtifactRoot) { $ArtifactRoot = Resolve-BuildInputPath -Path $ArtifactRoot; $excluded += $ArtifactRoot }
    $pathspecs = @('.')
    foreach ($output in $excluded) {
        $relative = [System.IO.Path]::GetRelativePath($root, $output).Replace([System.IO.Path]::DirectorySeparatorChar, [char]'/')
        if ($relative -ne '..' -and -not $relative.StartsWith('../')) { $pathspecs += ":(literal,exclude)$relative" }
    }
    $status = Invoke-BuildInputGit -RepositoryRoot $root -Arguments (@('status', '--porcelain=v1', '--untracked-files=all', '-z', '--') + $pathspecs)
    $changes = Invoke-BuildInputGit -RepositoryRoot $root -Arguments (@('diff', '--raw', 'HEAD', '-z', '--') + $pathspecs)
    $records = [System.Collections.Generic.List[object]]::new()
    $latest = [DateTime]::MinValue
    $latestPath = 'HEAD'
    foreach ($path in $paths) {
        $fullPath = [System.IO.Path]::GetFullPath((Join-Path $root $path))
        if ($fullPath -eq $binary -or $fullPath -eq (Get-ArtifactBuildStampPath -ArtifactPath $binary)) { continue }
        if ($ArtifactRoot) {
            $artifactRelative = [System.IO.Path]::GetRelativePath([System.IO.Path]::GetFullPath($ArtifactRoot), $fullPath)
            if ($artifactRelative -ne '..' -and -not $artifactRelative.StartsWith('..' + [System.IO.Path]::DirectorySeparatorChar)) { continue }
        }
        $records.Add((Get-BuildInputFileRecord -Root $root -RelativePath $path))
        if (Test-Path -LiteralPath (Join-Path $root $path) -PathType Leaf) {
            $time = (Get-Item -LiteralPath (Join-Path $root $path) -Force).LastWriteTimeUtc
            if ($time -gt $latest) { $latest = $time; $latestPath = $path }
        }
    }
    # Cargo reads ancestor configuration from the command's working directory,
    # including files outside the package's Git root. Bind those exact bytes too.
    $configurationPaths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    $ancestor = [System.IO.DirectoryInfo]::new($root)
    while ($null -ne $ancestor) {
        foreach ($name in @('.cargo/config', '.cargo/config.toml', 'rust-toolchain', 'rust-toolchain.toml')) {
            $null = $configurationPaths.Add((Join-Path $ancestor.FullName $name))
        }
        $ancestor = $ancestor.Parent
    }
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cargo' }
    foreach ($name in @('config', 'config.toml')) { $null = $configurationPaths.Add((Join-Path $cargoHome $name)) }
    foreach ($configuration in $configurationPaths) {
        $relative = [System.IO.Path]::GetRelativePath($root, $configuration)
        if ($relative -ne '..' -and -not $relative.StartsWith('..' + [System.IO.Path]::DirectorySeparatorChar)) { continue }
        if (Test-Path -LiteralPath $configuration -PathType Leaf) {
            $record = Get-BuildInputFileRecord -Root (Split-Path -Parent $configuration) -RelativePath (Split-Path -Leaf $configuration)
            $record.path = 'cargo_configuration:' + [System.IO.Path]::GetFullPath($configuration)
            $records.Add($record)
        }
    }
    $contentJson = ConvertTo-Json -InputObject @($records.ToArray()) -Depth 4 -Compress
    $sourceHash = Get-BuildInputDigest -Value $contentJson
    $dirtyHash = Get-BuildInputDigest -Value ($status + "`0" + $changes + "`0" + $sourceHash)
    [pscustomobject]@{
        RepositoryRoot = $root
        RepositoryName = Split-Path -Leaf $root
        Head = $head
        SourceSha256 = $sourceHash
        DirtySha256 = $dirtyHash
        BuildInputCount = $records.Count
        BuildInputsDirty = -not [string]::IsNullOrEmpty($status)
        RequiredTimeUtc = $latest
        RequiredBy = $latestPath
        BinaryPath = $binary
        BinaryTimeUtc = if (Test-Path -LiteralPath $binary -PathType Leaf) { (Get-Item -LiteralPath $binary -Force).LastWriteTimeUtc } else { [DateTime]::MinValue }
    }
}

function Get-ArtifactBuildRepositoryStates {
    param([Parameter(Mandatory = $true)][string]$ArtifactPath, [Parameter(Mandatory = $true)][string[]]$RepositoryRoots, [string]$ArtifactRoot)
    return @(
        foreach ($root in (Resolve-RepositoryBuildInputRoots -RepositoryRoots $RepositoryRoots)) {
            Get-RepositoryBuildInputState -RepositoryRoot $root -BinaryPath $ArtifactPath -ArtifactRoot $ArtifactRoot
        }
    )
}

function Assert-BuildInputStatesUnchanged {
    param([Parameter(Mandatory = $true)]$Before, [Parameter(Mandatory = $true)]$After)
    $beforeJson = ConvertTo-Json -InputObject @(ConvertTo-BuildStampInputs -RepositoryStates $Before) -Depth 4 -Compress
    $afterJson = ConvertTo-Json -InputObject @(ConvertTo-BuildStampInputs -RepositoryStates $After) -Depth 4 -Compress
    if ($beforeJson -cne $afterJson) { throw 'Build inputs changed during the managed build; refusing to stamp the artifact' }
}

function Get-ArtifactContentIdentity {
    param([Parameter(Mandatory = $true)][string]$ArtifactPath, [string]$ArtifactRoot, [string[]]$RequiredArtifactPaths = @())
    $path = Resolve-BuildInputPath -Path $ArtifactPath
    $root = if ($ArtifactRoot) { Resolve-BuildInputPath -Path $ArtifactRoot } else { $null }
    $records = [System.Collections.Generic.List[object]]::new()
    if ($root) {
        foreach ($required in $RequiredArtifactPaths) {
            $requiredPath = [System.IO.Path]::GetFullPath((Join-Path $root $required))
            $relative = [System.IO.Path]::GetRelativePath($root, $requiredPath)
            if ($relative -eq '..' -or $relative.StartsWith('..' + [System.IO.Path]::DirectorySeparatorChar) -or
                -not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw "Required served bundle member is missing or outside the root: $required" }
        }
        $relativeArtifact = [System.IO.Path]::GetRelativePath($root, $path)
        if ($relativeArtifact -eq '..' -or $relativeArtifact.StartsWith('..' + [System.IO.Path]::DirectorySeparatorChar)) { throw 'Artifact is outside its bundle root' }
        $paths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($directory in (Get-ChildItem -LiteralPath $root -Directory -Recurse -Force)) {
            if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Served bundle contains an unsupported directory link: $($directory.FullName)" }
        }
        foreach ($file in (Get-ChildItem -LiteralPath $root -File -Recurse -Force)) {
            if ($file.FullName -eq (Get-ArtifactBuildStampPath -ArtifactPath $path)) { continue }
            $null = $paths.Add([System.IO.Path]::GetRelativePath($root, $file.FullName).Replace([System.IO.Path]::DirectorySeparatorChar, [char]'/'))
        }
        foreach ($relative in $paths) { $records.Add((Get-BuildInputFileRecord -Root $root -RelativePath $relative)) }
    } else {
        $records.Add((Get-BuildInputFileRecord -Root (Split-Path -Parent $path) -RelativePath (Split-Path -Leaf $path)))
    }
    [pscustomobject]@{
        Root = $root
        Sha256 = Get-BuildInputDigest -Value (ConvertTo-Json -InputObject @($records.ToArray()) -Depth 4 -Compress)
        Count = $records.Count
    }
}
function Get-ArtifactBuildStampPath {
    param([Parameter(Mandatory = $true)][string]$ArtifactPath)

    return "$(Resolve-BuildInputPath -Path $ArtifactPath).cotest-build-input.json"
}

function ConvertTo-BuildStampInputs {
    param([Parameter(Mandatory = $true)]$RepositoryStates)

    return @(
        $RepositoryStates |
            ForEach-Object {
                [pscustomobject]@{
                    repository_root = Resolve-BuildInputPath -Path ([string]$_.RepositoryRoot)
                    head = ([string]$_.Head).Trim().ToLowerInvariant()
                    source_sha256 = if ($_.PSObject.Properties["SourceSha256"]) { [string]$_.SourceSha256 } else { "" }
                    dirty_sha256 = if ($_.PSObject.Properties["DirtySha256"]) { [string]$_.DirtySha256 } else { "" }
                }
            } |
            Sort-Object repository_root
    )
}

function Write-ArtifactBuildStamp {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)]$RepositoryStates,
        [string]$ArtifactRoot,
        [string[]]$RequiredArtifactPaths = @()
    )

    $stampPath = Get-ArtifactBuildStampPath -ArtifactPath $ArtifactPath
    $identity = Get-ArtifactContentIdentity -ArtifactPath $ArtifactPath -ArtifactRoot $ArtifactRoot -RequiredArtifactPaths $RequiredArtifactPaths
    [pscustomobject]@{
        schema = "cotest.build_input_stamp.v1"
        artifact = Resolve-BuildInputPath -Path $ArtifactPath
        artifact_sha256 = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
        artifact_root = $identity.Root
        artifact_content_sha256 = $identity.Sha256
        artifact_file_count = $identity.Count
        built_at = [DateTimeOffset]::UtcNow.ToString("o")
        inputs = ConvertTo-BuildStampInputs -RepositoryStates $RepositoryStates
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $stampPath -Encoding UTF8
    return $stampPath
}

function Test-ArtifactBuildStamp {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)]$RepositoryStates,
        [string]$ArtifactRoot,
        [string[]]$RequiredArtifactPaths = @()
    )

    $stampPath = Get-ArtifactBuildStampPath -ArtifactPath $ArtifactPath
    if (-not (Test-Path -LiteralPath $stampPath -PathType Leaf)) {
        return [pscustomobject]@{ Matches = $false; Detail = "build-input stamp missing: $stampPath" }
    }
    try {
        $stamp = Get-Content -Raw -LiteralPath $stampPath | ConvertFrom-Json
        if ($stamp.schema -ne "cotest.build_input_stamp.v1") {
            return [pscustomobject]@{ Matches = $false; Detail = "build-input stamp schema is invalid: $stampPath" }
        }
        if ($stamp.artifact -ne (Resolve-BuildInputPath -Path $ArtifactPath) -or
            -not $stamp.PSObject.Properties["artifact_sha256"]) {
            return [pscustomobject]@{ Matches = $false; Detail = "build-input stamp has no matching artifact identity: $stampPath" }
        }
        $artifactHash = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($stamp.artifact_sha256 -cne $artifactHash) {
            return [pscustomobject]@{ Matches = $false; Detail = "artifact bytes changed after the managed build: $ArtifactPath" }
        }
        $identity = Get-ArtifactContentIdentity -ArtifactPath $ArtifactPath -ArtifactRoot $ArtifactRoot -RequiredArtifactPaths $RequiredArtifactPaths
        if (-not $stamp.PSObject.Properties["artifact_content_sha256"] -or
            -not $stamp.PSObject.Properties["artifact_root"] -or
            $stamp.artifact_root -cne $identity.Root -or
            $stamp.artifact_content_sha256 -cne $identity.Sha256 -or
            -not $stamp.PSObject.Properties["artifact_file_count"] -or
            $stamp.artifact_file_count -ne $identity.Count) {
            return [pscustomobject]@{ Matches = $false; Detail = "artifact content inventory changed or is missing: $ArtifactPath" }
        }
        $expected = ConvertTo-BuildStampInputs -RepositoryStates $RepositoryStates
        if (@($expected | Where-Object { $_.source_sha256 -notmatch "^[0-9a-f]{64}$" -or $_.dirty_sha256 -notmatch "^[0-9a-f]{64}$" }).Count -gt 0) {
            return [pscustomobject]@{ Matches = $false; Detail = "build-input content identity is missing: $stampPath" }
        }
        $actual = ConvertTo-BuildStampInputs -RepositoryStates @(
            $stamp.inputs | ForEach-Object {
                [pscustomobject]@{ RepositoryRoot = $_.repository_root; Head = $_.head; SourceSha256 = if ($_.PSObject.Properties["source_sha256"]) { $_.source_sha256 } else { "" }; DirtySha256 = if ($_.PSObject.Properties["dirty_sha256"]) { $_.dirty_sha256 } else { "" } }
            }
        )
        $expectedJson = ConvertTo-Json -InputObject @($expected) -Depth 4 -Compress
        $actualJson = ConvertTo-Json -InputObject @($actual) -Depth 4 -Compress
        if ($actualJson -ne $expectedJson) {
            return [pscustomobject]@{ Matches = $false; Detail = "build-input source identity changed: $stampPath" }
        }
        return [pscustomobject]@{ Matches = $true; Detail = "build-input source and artifact contents match: $stampPath" }
    }
    catch {
        return [pscustomobject]@{ Matches = $false; Detail = "build-input stamp unreadable: $stampPath ($($_.Exception.Message))" }
    }
}

function Test-ArtifactSourceFreshness {
    param(
        [Parameter(Mandatory = $true)][DateTime]$ArtifactTimeUtc,
        [Parameter(Mandatory = $true)]$RepositoryStates,
        [Parameter(Mandatory = $true)][bool]$StampMatches
    )

    if (-not $StampMatches) {
        return $false
    }
    $newest = $RepositoryStates | Sort-Object RequiredTimeUtc -Descending | Select-Object -First 1
    if ($ArtifactTimeUtc -ge $newest.RequiredTimeUtc) {
        return $true
    }
    # A content-bound stamp proves the exact source tree; timestamps are only
    # an additional guard for dirty files newer than the verified build.
    # A clean checkout at the exact stamped commits has the same inputs
    # even when a formatter or checkout has refreshed file modification times.
    # Dirty inputs still require a build newer than their on-disk contents.
    return @($RepositoryStates | Where-Object { $_.BuildInputsDirty }).Count -eq 0
}

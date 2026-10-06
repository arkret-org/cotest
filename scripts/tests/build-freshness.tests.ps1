$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "..\lib\build-freshness.ps1")

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "cotest-build-freshness-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $testRoot
try {
    $artifact = Join-Path $testRoot "service.exe"
    Set-Content -LiteralPath $artifact -Value "synthetic artifact" -Encoding UTF8
    $states = @(
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "service"); Head = ("a" * 40); SourceSha256 = ("c" * 64); DirtySha256 = ("d" * 64) },
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "sdk"); Head = ("b" * 40); SourceSha256 = ("c" * 64); DirtySha256 = ("d" * 64) }
    )

    $missing = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states
    Assert-True (-not $missing.Matches) "an artifact without a commit stamp must be stale"

    Write-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states | Out-Null
    $matching = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states
    Assert-True $matching.Matches "the exact stamped commit set must be fresh"

    $oldArtifactTime = [DateTime]::UtcNow.AddHours(-1)
    $recentInputTime = [DateTime]::UtcNow
    $cleanInputs = @(
        [pscustomobject]@{ RequiredTimeUtc = $recentInputTime; BuildInputsDirty = $false }
    )
    $dirtyInputs = @(
        [pscustomobject]@{ RequiredTimeUtc = $recentInputTime; BuildInputsDirty = $true }
    )
    Assert-True (Test-ArtifactSourceFreshness -ArtifactTimeUtc $oldArtifactTime -RepositoryStates $cleanInputs -StampMatches $true) "a clean checkout at stamped commits may have newer file timestamps"
    Assert-True (-not (Test-ArtifactSourceFreshness -ArtifactTimeUtc $oldArtifactTime -RepositoryStates $dirtyInputs -StampMatches $true)) "dirty build inputs newer than the artifact must rebuild"
    Assert-True (-not (Test-ArtifactSourceFreshness -ArtifactTimeUtc $oldArtifactTime -RepositoryStates $cleanInputs -StampMatches $false)) "a mismatched stamp must rebuild even for a clean checkout"

    # Keep the artifact timestamp unchanged while advancing one repository.
    # This is the fast-forward case that an mtime-only gate cannot detect.
    $advanced = @(
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "service"); Head = ("c" * 40); SourceSha256 = ("c" * 64); DirtySha256 = ("d" * 64) },
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "sdk"); Head = ("b" * 40); SourceSha256 = ("c" * 64); DirtySha256 = ("d" * 64) }
    )
    $stale = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $advanced
    Assert-True (-not $stale.Matches) "a changed HEAD must invalidate an unchanged artifact timestamp"

    $edited = @(
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "service"); Head = ("a" * 40); SourceSha256 = ("3" * 64) },
        $states[1]
    )
    Assert-True (-not (Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $edited).Matches) "changed source bytes at the same HEAD and mtime must invalidate the stamp"

    $repo = Join-Path $testRoot 'source'
    $null = New-Item -ItemType Directory -Path (Join-Path $repo 'src') -Force
    $git = (Get-Command git).Source
    & $git -C $repo init --quiet
    if ($LASTEXITCODE -ne 0) { throw 'fixture Git initialization failed' }
    $tracked = Join-Path $repo 'src/lib.rs'
    $untracked = Join-Path $repo 'src/own_station.rs'
    Set-Content -LiteralPath $tracked -Value 'pub mod own_station;'
    & $git -C $repo add -- src/lib.rs
    if ($LASTEXITCODE -ne 0) { throw 'fixture Git index failed' }
    & $git -C $repo -c user.name=Cotest -c user.email=cotest@example.invalid commit --quiet -m 'source fixture'
    if ($LASTEXITCODE -ne 0) { throw 'fixture Git commit failed' }
    $before = Get-RepositoryBuildInputState -RepositoryRoot $repo -BinaryPath $artifact
    Set-Content -LiteralPath $untracked -Value 'pub fn original() {}'
    $added = Get-RepositoryBuildInputState -RepositoryRoot $repo -BinaryPath $artifact
    Assert-True ($added.BuildInputCount -eq $before.BuildInputCount + 1) 'untracked imported source must be a build input'
    Assert-True ($before.SourceSha256 -ne $added.SourceSha256) 'adding untracked source must invalidate content identity'
    $savedTime = (Get-Item -LiteralPath $untracked).LastWriteTimeUtc
    Set-Content -LiteralPath $untracked -Value 'pub fn changed() {}'
    (Get-Item -LiteralPath $untracked).LastWriteTimeUtc = $savedTime
    $changed = Get-RepositoryBuildInputState -RepositoryRoot $repo -BinaryPath $artifact
    Assert-True ($added.SourceSha256 -ne $changed.SourceSha256) 'editing untracked source at unchanged mtime must invalidate content identity'

    # A normal cargo test can replace the conformance binary at the same HEAD.
    # Preserve mtime too: only the artifact bytes prove this is a different build.
    $originalMtime = (Get-Item -LiteralPath $artifact).LastWriteTimeUtc
    Set-Content -LiteralPath $artifact -Value "different features" -Encoding UTF8
    (Get-Item -LiteralPath $artifact).LastWriteTimeUtc = $originalMtime
    $replaced = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states
    Assert-True (-not $replaced.Matches) "replaced artifact bytes must invalidate a matching source stamp"

    Write-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states | Out-Null
    $rebuilt = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states
    Assert-True $rebuilt.Matches "a verified managed rebuild must refresh the artifact identity"

    $repository = Join-Path $testRoot "actual-source"
    $null = New-Item -ItemType Directory -Path (Join-Path $repository "src") -Force
    Set-Content -LiteralPath (Join-Path $repository ".gitignore") -Value "target/" -Encoding UTF8
    $trackedSource = Join-Path $repository "src/lib.rs"
    Set-Content -LiteralPath $trackedSource -Value "pub fn accepted() {}" -Encoding UTF8
    Invoke-BuildInputGit -RepositoryRoot $repository -Arguments @('init', '--quiet') | Out-Null
    Invoke-BuildInputGit -RepositoryRoot $repository -Arguments @('add', '.') | Out-Null
    Invoke-BuildInputGit -RepositoryRoot $repository -Arguments @('-c', 'user.name=Cotest', '-c', 'user.email=cotest@example.invalid', 'commit', '--quiet', '-m', 'source fixture') | Out-Null
    $originalState = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $artifact
    Write-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates @($originalState) | Out-Null

    $newSource = Join-Path $repository "src/own_station_results.rs"
    Set-Content -LiteralPath $newSource -Value "pub fn historical() {}" -Encoding UTF8
    (Get-Item -LiteralPath $newSource).LastWriteTimeUtc = $oldArtifactTime
    $withNewSource = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $artifact
    Assert-True ($withNewSource.Head -eq $originalState.Head) "new source must preserve HEAD in this regression"
    Assert-True ($withNewSource.BuildInputCount -eq $originalState.BuildInputCount + 1) "non-ignored untracked source must enter the inventory"
    Assert-True (-not (Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates @($withNewSource)).Matches) "new source must invalidate the stamp even with old timestamps and unchanged HEAD"
    Write-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates @($withNewSource) | Out-Null
    Assert-True (Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates @($withNewSource)).Matches "rebuilt dirty inputs must have an exact content identity"
    Set-Content -LiteralPath $newSource -Value "pub fn changed_historical() {}" -Encoding UTF8
    (Get-Item -LiteralPath $newSource).LastWriteTimeUtc = $oldArtifactTime
    $changedUntracked = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $artifact
    Assert-True (-not (Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates @($changedUntracked)).Matches) "editing the same untracked path with preserved mtime must invalidate its content stamp"

    $trackedTime = (Get-Item -LiteralPath $trackedSource).LastWriteTimeUtc
    Set-Content -LiteralPath $trackedSource -Value "pub fn changed_accepted() {}" -Encoding UTF8
    (Get-Item -LiteralPath $trackedSource).LastWriteTimeUtc = $trackedTime
    $changedTracked = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $artifact
    Assert-True ($changedTracked.SourceSha256 -ne $changedUntracked.SourceSha256) "tracked bytes must be hashed independently of mtime"
    $midBuildChangeRejected = $false
    try { Assert-BuildInputStatesUnchanged -Before @($changedUntracked) -After @($changedTracked) }
    catch { $midBuildChangeRejected = $true }
    Assert-True $midBuildChangeRejected "source changes during a build must reject stamping its output"
    Assert-BuildInputStatesUnchanged -Before @($changedTracked) -After @($changedTracked)
    Remove-Item -LiteralPath $trackedSource
    $deleted = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $artifact
    Assert-True ($deleted.SourceSha256 -ne $changedTracked.SourceSha256) "deleting a tracked build input must change its content identity"
    $null = New-Item -ItemType Directory -Path (Join-Path $repository "target")
    Set-Content -LiteralPath (Join-Path $repository "target/output.rs") -Value "ignored build output" -Encoding UTF8
    $ignored = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $artifact
    Assert-True ($ignored.SourceSha256 -eq $deleted.SourceSha256 -and $ignored.DirtySha256 -eq $deleted.DirtySha256) "ignored build output must not contaminate source identity"

    if (-not $IsWindows) {
        $link = Join-Path $repository "src/linked.rs"
        $null = New-Item -ItemType SymbolicLink -Path $link -Target $newSource
        $withLink = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $artifact
        Remove-Item -LiteralPath $link
        $otherTarget = Join-Path $testRoot "other-source.rs"
        Set-Content -LiteralPath $otherTarget -Value (Get-Content -Raw -LiteralPath $newSource) -NoNewline -Encoding UTF8
        $null = New-Item -ItemType SymbolicLink -Path $link -Target $otherTarget
        $retargeted = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $artifact
        Assert-True ($withLink.SourceSha256 -ne $retargeted.SourceSha256) "retargeting a source symlink must change its identity even when target bytes match"
        Remove-Item -LiteralPath $link
    }
    Write-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates @($ignored) | Out-Null
    $legacySourceStampPath = Get-ArtifactBuildStampPath -ArtifactPath $artifact
    $legacySourceStamp = Get-Content -Raw -LiteralPath $legacySourceStampPath | ConvertFrom-Json
    $legacySourceStamp.inputs[0].PSObject.Properties.Remove("source_sha256")
    $legacySourceStamp | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $legacySourceStampPath -Encoding UTF8
    Assert-True (-not (Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates @($ignored)).Matches) "a legacy HEAD-only source stamp must require a real rebuild"

    $bundle = Join-Path $testRoot "public"
    $null = New-Item -ItemType Directory -Path (Join-Path $bundle "wasm") -Force
    $index = Join-Path $bundle "index.html"
    $wasm = Join-Path $bundle "wasm/inkson_bg.wasm"
    Set-Content -LiteralPath $index -Value "unchanged loader" -Encoding UTF8
    Set-Content -LiteralPath $wasm -Value "old wasm" -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $bundle "wasm/inkson.js") -Value "required wasm loader" -Encoding UTF8
    Write-ArtifactBuildStamp -ArtifactPath $index -ArtifactRoot $bundle -RequiredArtifactPaths @("index.html", "wasm/inkson_bg.wasm", "wasm/inkson.js") -RepositoryStates @($ignored) | Out-Null
    Assert-True (Test-ArtifactBuildStamp -ArtifactPath $index -ArtifactRoot $bundle -RequiredArtifactPaths @("index.html", "wasm/inkson_bg.wasm", "wasm/inkson.js") -RepositoryStates @($ignored)).Matches "the bundle identity must exclude its own stamp"
    $wasmTime = (Get-Item -LiteralPath $wasm).LastWriteTimeUtc
    Set-Content -LiteralPath $wasm -Value "current wasm" -Encoding UTF8
    (Get-Item -LiteralPath $wasm).LastWriteTimeUtc = $wasmTime
    Assert-True (-not (Test-ArtifactBuildStamp -ArtifactPath $index -ArtifactRoot $bundle -RequiredArtifactPaths @("index.html", "wasm/inkson_bg.wasm", "wasm/inkson.js") -RepositoryStates @($ignored)).Matches) "wasm replacement must invalidate an unchanged index and preserved timestamps"
    Write-ArtifactBuildStamp -ArtifactPath $index -ArtifactRoot $bundle -RequiredArtifactPaths @("index.html", "wasm/inkson_bg.wasm", "wasm/inkson.js") -RepositoryStates @($ignored) | Out-Null
    Set-Content -LiteralPath (Join-Path $bundle "wasm/loader.js") -Value "new loader" -Encoding UTF8
    Assert-True (-not (Test-ArtifactBuildStamp -ArtifactPath $index -ArtifactRoot $bundle -RequiredArtifactPaths @("index.html", "wasm/inkson_bg.wasm", "wasm/inkson.js") -RepositoryStates @($ignored)).Matches) "adding a served loader must invalidate the bundle inventory"
    Remove-Item -LiteralPath (Join-Path $bundle "wasm/loader.js")
    Remove-Item -LiteralPath $wasm
    Assert-True (-not (Test-ArtifactBuildStamp -ArtifactPath $index -ArtifactRoot $bundle -RequiredArtifactPaths @("index.html", "wasm/inkson_bg.wasm", "wasm/inkson.js") -RepositoryStates @($ignored)).Matches) "deleting served wasm must invalidate the bundle inventory"

    $missingBundleRejected = $false
    try { Write-ArtifactBuildStamp -ArtifactPath $index -ArtifactRoot $bundle -RequiredArtifactPaths @("wasm/inkson_bg.wasm", "wasm/inkson.js") -RepositoryStates @($ignored) | Out-Null }
    catch { $missingBundleRejected = $true }
    Assert-True $missingBundleRejected "a successful process without required wasm must never acquire a build stamp"

    $specialSource = Join-Path $repository ("src/" + "unicode-" + [char]0x03BB + "`tline`nbreak.rs")
    if (-not $IsWindows) {
        Set-Content -LiteralPath $specialSource -Value "pub fn special_path() {}" -Encoding UTF8
        $special = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $artifact
        Assert-True ($special.BuildInputCount -eq $ignored.BuildInputCount + 1) "Unicode, tab and newline source paths must remain one exact inventory entry"
        Remove-Item -LiteralPath $specialSource
    }
    $inRepoArtifact = Join-Path $repository "service.bin"
    Set-Content -LiteralPath $inRepoArtifact -Value "build output outside ignore rules" -Encoding UTF8
    $beforeOutputStamp = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $inRepoArtifact
    Write-ArtifactBuildStamp -ArtifactPath $inRepoArtifact -RepositoryStates @($beforeOutputStamp) | Out-Null
    $afterOutputStamp = Get-RepositoryBuildInputState -RepositoryRoot $repository -BinaryPath $inRepoArtifact
    Assert-True ($beforeOutputStamp.SourceSha256 -eq $afterOutputStamp.SourceSha256 -and $beforeOutputStamp.DirtySha256 -eq $afterOutputStamp.DirtySha256) "the exact artifact and its stamp must not contaminate their own source identity"

    $graphRoot = Join-Path $testRoot "cargo-graph"
    $pathRoot = Join-Path $testRoot "cargo-optional"
    $patchRoot = Join-Path $testRoot "cargo-patch"
    foreach ($root in @($graphRoot, $pathRoot, $patchRoot)) {
        $null = New-Item -ItemType Directory -Path (Join-Path $root "src") -Force
        Set-Content -LiteralPath (Join-Path $root "src/lib.rs") -Value "pub fn source() {}" -Encoding UTF8
        Invoke-BuildInputGit -RepositoryRoot $root -Arguments @('init', '--quiet') | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $pathRoot "Cargo.toml") -Value @'
[package]
name = "freshness_optional"
version = "0.1.0"
edition = "2021"
[features]
Default = []
default = []
'@ -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $patchRoot "Cargo.toml") -Value @'
[package]
name = "freshness_patched"
version = "0.1.0"
edition = "2021"
'@ -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $graphRoot "Cargo.toml") -Value @'
[package]
name = "freshness_root"
version = "0.1.0"
edition = "2021"
[workspace]
resolver = "2"
[dependencies]
freshness_optional = { path = "../cargo-optional", optional = true }
freshness_patched = "=0.1.0"
[patch.crates-io]
freshness_patched = { path = "../cargo-patch" }
'@ -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $graphRoot "Cargo.lock") -Value @'
version = 3
[[package]]
name = "freshness_optional"
version = "0.1.0"
[[package]]
name = "freshness_patched"
version = "0.1.0"
[[package]]
name = "freshness_root"
version = "0.1.0"
dependencies = ["freshness_optional", "freshness_patched"]
'@ -Encoding UTF8
    $graphRoots = @(Resolve-RepositoryBuildInputRoots -RepositoryRoots @($graphRoot))
    $expectedRoots = @($graphRoot, $pathRoot, $patchRoot) | ForEach-Object {
        (Invoke-BuildInputGit -RepositoryRoot $_ -Arguments @('rev-parse', '--show-toplevel')).Trim()
    }
    Assert-True ($graphRoots.Count -eq 3 -and @($expectedRoots | Where-Object { $graphRoots -cnotcontains $_ }).Count -eq 0) "real offline Cargo metadata must include optional local and patched dependency repositories"
    Set-Content -LiteralPath (Join-Path $graphRoot "Cargo.toml") -Value "invalid = [" -Encoding UTF8
    $graphRejected = $false
    try { Resolve-RepositoryBuildInputRoots -RepositoryRoots @($graphRoot) | Out-Null }
    catch { $graphRejected = $true }
    Assert-True $graphRejected "failed actual Cargo metadata must reject freshness rather than falling back to guessed dependencies"

    $stampPath = Get-ArtifactBuildStampPath -ArtifactPath $artifact
    $stamp = Get-Content -Raw -LiteralPath $stampPath | ConvertFrom-Json
    $stamp.PSObject.Properties.Remove("artifact_sha256")
    $stamp | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $stampPath -Encoding UTF8
    $unbound = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states
    Assert-True (-not $unbound.Matches) "a source-only stamp cannot certify the artifact build"
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolvedTestRoot = [System.IO.Path]::GetFullPath($testRoot)
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedTestRoot.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Test cleanup path is outside the temporary directory"
        }
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host "Build freshness regression tests passed."

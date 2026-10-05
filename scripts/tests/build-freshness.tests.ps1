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
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "service"); Head = ("a" * 40); SourceSha256 = ("1" * 64) },
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "sdk"); Head = ("b" * 40); SourceSha256 = ("2" * 64) }
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
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "service"); Head = ("c" * 40); SourceSha256 = ("1" * 64) },
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "sdk"); Head = ("b" * 40); SourceSha256 = ("2" * 64) }
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
    $before = Get-RepositoryBuildContent -RepositoryRoot $repo -GitPath $git -InputPaths @('src')
    Set-Content -LiteralPath $untracked -Value 'pub fn original() {}'
    $added = Get-RepositoryBuildContent -RepositoryRoot $repo -GitPath $git -InputPaths @('src')
    Assert-True ($added.Files -contains 'src/own_station.rs') 'untracked imported source must be a build input'
    Assert-True ($before.SourceSha256 -ne $added.SourceSha256) 'adding untracked source must invalidate content identity'
    $savedTime = (Get-Item -LiteralPath $untracked).LastWriteTimeUtc
    Set-Content -LiteralPath $untracked -Value 'pub fn changed() {}'
    (Get-Item -LiteralPath $untracked).LastWriteTimeUtc = $savedTime
    $changed = Get-RepositoryBuildContent -RepositoryRoot $repo -GitPath $git -InputPaths @('src')
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

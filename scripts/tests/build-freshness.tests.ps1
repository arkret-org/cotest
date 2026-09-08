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
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "service"); Head = ("a" * 40) },
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "sdk"); Head = ("b" * 40) }
    )

    $missing = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states
    Assert-True (-not $missing.Matches) "an artifact without a commit stamp must be stale"

    Write-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states | Out-Null
    $matching = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $states
    Assert-True $matching.Matches "the exact stamped commit set must be fresh"

    # Keep the artifact timestamp unchanged while advancing one repository.
    # This is the fast-forward case that an mtime-only gate cannot detect.
    $advanced = @(
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "service"); Head = ("c" * 40) },
        [pscustomobject]@{ RepositoryRoot = (Join-Path $testRoot "sdk"); Head = ("b" * 40) }
    )
    $stale = Test-ArtifactBuildStamp -ArtifactPath $artifact -RepositoryStates $advanced
    Assert-True (-not $stale.Matches) "a changed HEAD must invalidate an unchanged artifact timestamp"

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

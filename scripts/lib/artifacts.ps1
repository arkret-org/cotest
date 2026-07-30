# Shared artifact layout helpers for cotest runners.

function ConvertTo-ArtifactPathSegment {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [string]$Fallback = "custom"
    )

    $segment = $Value.Trim().ToLowerInvariant() -replace '[^a-z0-9._-]+', '-'
    $segment = $segment.Trim('-', '.', '_')
    if (-not $segment) {
        return $Fallback
    }
    return $segment
}

function Test-IsCompleteCotestRun {
    param(
        [Parameter(Mandatory = $true)][bool]$ProfileIncludesAllTests,
        [string]$CargoTestTarget,
        [string]$CargoTestFilter
    )

    return $ProfileIncludesAllTests -and
        -not $CargoTestTarget -and
        -not $CargoTestFilter
}

function Test-IsStandaloneJointSuite {
    param(
        [Parameter(Mandatory = $true)][bool]$IsStandalone,
        [string]$Grep,
        [string]$ExternalDriverScript,
        [bool]$PreflightOnly
    )

    return $IsStandalone -and
        -not $Grep -and
        -not $ExternalDriverScript -and
        -not $PreflightOnly
}

function New-ArtifactRunDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Family,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$Timestamp = (Get-Date -Format "yyyyMMdd-HHmmss")
    )

    $familySegment = ConvertTo-ArtifactPathSegment -Value $Family
    $labelSegment = ConvertTo-ArtifactPathSegment -Value $Label
    $familyRoot = Join-Path $OutputRoot "runs\$familySegment"
    $null = New-Item -ItemType Directory -Force -Path $familyRoot

    $baseName = "$Timestamp-$labelSegment"
    $candidate = Join-Path $familyRoot $baseName
    $suffix = 1
    while (Test-Path -LiteralPath $candidate) {
        $suffix++
        $candidate = Join-Path $familyRoot ("{0}-{1:d2}" -f $baseName, $suffix)
    }

    return (New-Item -ItemType Directory -Path $candidate).FullName
}

function Remove-StaleArtifactRuns {
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Family,
        [Parameter(Mandatory = $true)][int]$KeepRuns
    )

    if ($KeepRuns -le 0) {
        return
    }

    $familySegment = ConvertTo-ArtifactPathSegment -Value $Family
    $familyRoot = Join-Path $OutputRoot "runs\$familySegment"
    if (-not (Test-Path -LiteralPath $familyRoot -PathType Container)) {
        return
    }

    $resolvedFamilyRoot = [System.IO.Path]::GetFullPath($familyRoot)
    $familyPrefix = $resolvedFamilyRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $staleRuns = @(
        Get-ChildItem -LiteralPath $resolvedFamilyRoot -Directory |
            Sort-Object Name -Descending |
            Select-Object -Skip $KeepRuns
    )
    foreach ($directory in $staleRuns) {
        $resolvedDirectory = [System.IO.Path]::GetFullPath($directory.FullName)
        if (-not $resolvedDirectory.StartsWith(
                $familyPrefix,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Refusing to prune artifact run outside family root: $resolvedDirectory"
        }
        Remove-Item -LiteralPath $resolvedDirectory -Recurse -Force
    }
}

function Write-LatestArtifactIndex {
    param([Parameter(Mandatory = $true)][string]$OutputRoot)

    $latestRoot = Join-Path $OutputRoot "latest"
    $null = New-Item -ItemType Directory -Force -Path $latestRoot
    $descriptions = [ordered]@{
        "full"      = "Most recent unfiltered complete cotest run."
        "joint-e2e" = "Most recent non-targeted joint-e2e suite run; grep-selected runs do not replace it."
    }
    $entries = @()
    foreach ($channel in $descriptions.Keys) {
        $channelRoot = Join-Path $latestRoot $channel
        if (-not (Test-Path -LiteralPath $channelRoot -PathType Container)) {
            continue
        }
        $locationPath = Join-Path $channelRoot "run-location.json"
        $location = $null
        if (Test-Path -LiteralPath $locationPath -PathType Leaf) {
            $location = Get-Content -Raw -LiteralPath $locationPath | ConvertFrom-Json
        }
        $entries += [pscustomobject]@{
            channel           = $channel
            description       = $descriptions[$channel]
            authoritative_run = if ($location) { $location.authoritative_run } else { $null }
            published_at      = if ($location) { $location.published_at } else { $null }
        }
    }

    $indexJson = Join-Path $latestRoot "index.json"
    [pscustomobject]@{
        generated_at = (Get-Date).ToString("o")
        channels     = $entries
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $indexJson -Encoding UTF8

    $markdown = @(
        "# Latest cotest artifacts",
        "",
        "Stable result channels are directories below this file. Timestamped directories under ``../runs/`` are authoritative.",
        ""
    )
    foreach ($entry in $entries) {
        $markdown += "- ``$($entry.channel)/`` - $($entry.description)"
        if ($entry.authoritative_run) {
            $markdown += "  - authoritative run: ``$($entry.authoritative_run)``"
        }
    }
    $markdown | Set-Content -LiteralPath (Join-Path $latestRoot "README.md") -Encoding UTF8
}

function Remove-LegacyLatestCotestMirror {
    param([Parameter(Mandatory = $true)][string]$OutputRoot)

    $resolvedOutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
    $latestRoot = [System.IO.Path]::GetFullPath((Join-Path $resolvedOutputRoot "latest"))
    $fullMirror = Join-Path $latestRoot "full"
    if (-not (Test-Path -LiteralPath $fullMirror -PathType Container)) {
        throw "Refusing to remove the legacy latest mirror before latest/full exists"
    }

    $legacyFiles = @(
        "raw.log",
        "transcript.ndjson",
        "summary.json",
        "summary.md",
        "summary.html",
        "junit.xml",
        "metadata.json",
        "coverage-matrix.json",
        "coverage-matrix.md",
        "coverage-gate.json",
        "coverage-gate.md",
        "joint-smoke-gate.json",
        "joint-smoke-gate.md",
        "release-gate.json",
        "release-gate.md",
        "unresolved-gaps.json",
        "unresolved-gaps.md",
        "registry-gaps.json",
        "ci-profile.json",
        "ci-profile.md",
        "secret-scan.json",
        "secret-scan.md",
        "spec-sync-gate.json",
        "spec-sync-gate.md"
    )
    foreach ($name in $legacyFiles) {
        $candidate = Join-Path $latestRoot $name
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Remove-Item -LiteralPath $candidate -Force
        }
    }

    $legacyServices = Join-Path $latestRoot "services"
    if (Test-Path -LiteralPath $legacyServices -PathType Container) {
        Remove-Item -LiteralPath $legacyServices -Recurse -Force
    }
}

function Publish-ArtifactMirror {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Channel
    )

    if (-not (Test-Path -LiteralPath $SourceDirectory -PathType Container)) {
        throw "Artifact source directory not found: $SourceDirectory"
    }

    $resolvedSourceDirectory = [System.IO.Path]::GetFullPath($SourceDirectory)
    $channelSegment = ConvertTo-ArtifactPathSegment -Value $Channel
    $resolvedOutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
    $latestRoot = Join-Path $resolvedOutputRoot "latest"
    $null = New-Item -ItemType Directory -Force -Path $latestRoot
    $resolvedLatestRoot = [System.IO.Path]::GetFullPath($latestRoot)
    $latestPrefix = $resolvedLatestRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $target = [System.IO.Path]::GetFullPath((Join-Path $resolvedLatestRoot $channelSegment))
    if (-not $target.StartsWith($latestPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to publish artifact mirror outside latest root: $target"
    }
    $sourcePrefix = $resolvedSourceDirectory.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    if ($target.Equals($resolvedSourceDirectory, [System.StringComparison]::OrdinalIgnoreCase) -or
        $target.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to publish an artifact mirror inside its source directory: $target"
    }

    $staging = Join-Path $resolvedLatestRoot ".$channelSegment-$([guid]::NewGuid().ToString('N')).tmp"
    try {
        Copy-Item -LiteralPath $resolvedSourceDirectory -Destination $staging -Recurse -Force
        [pscustomobject]@{
            channel           = $channelSegment
            published_at      = (Get-Date).ToString("o")
            authoritative_run = $resolvedSourceDirectory
        } | ConvertTo-Json -Depth 3 |
            Set-Content -LiteralPath (Join-Path $staging "run-location.json") -Encoding UTF8

        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
        Move-Item -LiteralPath $staging -Destination $target
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }

    Write-LatestArtifactIndex -OutputRoot $resolvedOutputRoot
}

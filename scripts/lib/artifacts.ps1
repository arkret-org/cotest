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

function Test-IsCompleteServerConformanceRun {
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
        [bool]$PreflightOnly
    )

    return $IsStandalone -and
        -not $Grep -and
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
        try {
            Remove-Item -LiteralPath $resolvedDirectory -Recurse -Force -ErrorAction Stop
        }
        catch {
            # Retention is best-effort housekeeping. A previous runner or an
            # artifact viewer may still hold a file handle on Windows; that
            # must not prevent the new test run from starting. Leave the
            # locked run intact and continue pruning the remaining candidates.
            Write-Warning "Unable to prune stale artifact run '$resolvedDirectory': $($_.Exception.Message)"
        }
    }
}

function Write-LatestArtifactIndex {
    param([Parameter(Mandatory = $true)][string]$OutputRoot)

    $latestRoot = Join-Path $OutputRoot "latest"
    $null = New-Item -ItemType Directory -Force -Path $latestRoot
    $descriptions = [ordered]@{
        "server-conformance" = "Most recent unfiltered Arkret Server Conformance suite run."
        "joint-e2e"          = "Most recent non-targeted Arkret Joint Product E2E suite run; grep-selected runs do not replace it."
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
        "# Latest Arkret test artifacts",
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

function Assert-ArtifactReportIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$Channel
    )

    if ($Channel -notin @("server-conformance", "joint-e2e")) {
        return
    }
    $summaryPath = Join-Path $SourceDirectory "summary.json"
    if (-not (Test-Path -LiteralPath $summaryPath -PathType Leaf)) {
        throw "Artifact channel '$Channel' requires summary.json with an explicit suite identity"
    }
    try {
        $summary = Get-Content -Raw -LiteralPath $summaryPath | ConvertFrom-Json
    }
    catch {
        throw "Artifact summary is not valid JSON: $summaryPath"
    }
    $reportSchema = if ($summary.PSObject.Properties.Name -contains "report_schema") { $summary.report_schema } else { $null }
    $suiteKind = if ($summary.PSObject.Properties.Name -contains "suite_kind") { $summary.suite_kind } else { $null }
    if ($reportSchema -ne "arkret.test-report.v1") {
        throw "Artifact summary uses an unsupported report_schema for '$Channel': $reportSchema"
    }
    if ($suiteKind -ne $Channel) {
        throw "Artifact summary suite_kind '$suiteKind' does not match channel '$Channel'"
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

    Assert-ArtifactReportIdentity -SourceDirectory $SourceDirectory -Channel $Channel

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

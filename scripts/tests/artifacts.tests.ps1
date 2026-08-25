$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "..\lib\artifacts.ps1")

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "cotest-artifacts-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $testRoot
$lockedHandle = $null
try {
    Assert-True `
        (Test-IsCompleteServerConformanceRun -ProfileIncludesAllTests $true) `
        "an unfiltered include-all profile must be a complete run"
    Assert-True `
        (-not (Test-IsCompleteServerConformanceRun -ProfileIncludesAllTests $true -CargoTestFilter "one_test")) `
        "a filtered cotest run must not replace the complete-run channel"
    Assert-True `
        (-not (Test-IsCompleteServerConformanceRun -ProfileIncludesAllTests $false)) `
        "a selective profile must not replace the complete-run channel"
    Assert-True `
        (Test-IsStandaloneJointSuite -IsStandalone $true) `
        "an unfiltered standalone joint run must be a suite"
    Assert-True `
        (-not (Test-IsStandaloneJointSuite -IsStandalone $true -Grep "one spec")) `
        "a grep-selected joint run must not replace the joint suite channel"
    Assert-True `
        (-not (Test-IsStandaloneJointSuite -IsStandalone $false)) `
        "an embedded joint run must not replace the standalone joint channel"

    $first = New-ArtifactRunDirectory `
        -OutputRoot $testRoot `
        -Family "server-conformance" `
        -Label "all" `
        -Timestamp "20260730-120000"
    Set-Content -LiteralPath (Join-Path $first "summary.md") -Value "first" -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $first "summary.json") -Value '{"report_schema":"arkret.test-report.v1","suite_kind":"server-conformance"}' -Encoding UTF8
    Publish-ArtifactMirror -SourceDirectory $first -OutputRoot $testRoot -Channel "server-conformance"

    $target = Join-Path $testRoot "latest\server-conformance"
    Assert-True (Test-Path -LiteralPath (Join-Path $target "summary.md")) "server-conformance mirror was not published"
    Assert-True (Test-Path -LiteralPath (Join-Path $target "run-location.json")) "mirror location metadata is missing"
    $unsafePublishRejected = $false
    try {
        Publish-ArtifactMirror `
            -SourceDirectory (Join-Path $testRoot "latest") `
            -OutputRoot $testRoot `
            -Channel "nested"
    }
    catch {
        $unsafePublishRejected = $_.Exception.Message.Contains("inside its source directory")
    }
    Assert-True $unsafePublishRejected "publishing inside the source directory was not rejected"

    Set-Content -LiteralPath (Join-Path $target "stale.txt") -Value "stale" -Encoding UTF8
    $second = New-ArtifactRunDirectory `
        -OutputRoot $testRoot `
        -Family "server-conformance" `
        -Label "all" `
        -Timestamp "20260730-120001"
    Set-Content -LiteralPath (Join-Path $second "summary.md") -Value "second" -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $second "summary.json") -Value '{"report_schema":"arkret.test-report.v1","suite_kind":"server-conformance"}' -Encoding UTF8
    Publish-ArtifactMirror -SourceDirectory $second -OutputRoot $testRoot -Channel "server-conformance"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $target "stale.txt"))) "publishing retained a stale file"

    $third = New-ArtifactRunDirectory `
        -OutputRoot $testRoot `
        -Family "server-conformance" `
        -Label "fast-smoke" `
        -Timestamp "20260730-120002"
    Remove-StaleArtifactRuns -OutputRoot $testRoot -Family "server-conformance" -KeepRuns 2
    Assert-True (-not (Test-Path -LiteralPath $first)) "family retention did not remove the oldest run"
    Assert-True (Test-Path -LiteralPath $second) "family retention removed a retained run"
    Assert-True (Test-Path -LiteralPath $third) "family retention removed the newest run"

    $joint = New-ArtifactRunDirectory `
        -OutputRoot $testRoot `
        -Family "joint-e2e" `
        -Label "joint-full" `
        -Timestamp "20260730-120000"
    Remove-StaleArtifactRuns -OutputRoot $testRoot -Family "server-conformance" -KeepRuns 1
    Assert-True (Test-Path -LiteralPath $joint) "server-conformance retention crossed into the joint-e2e family"

    $untypedReport = Join-Path $testRoot "latest\untyped"
    $null = New-Item -ItemType Directory -Force -Path $untypedReport
    Set-Content -LiteralPath (Join-Path $untypedReport "summary.json") -Value '{"status":"success"}' -Encoding UTF8
    $untypedPublishRejected = $false
    try {
        Publish-ArtifactMirror -SourceDirectory $untypedReport -OutputRoot $testRoot -Channel "server-conformance"
    }
    catch {
        $untypedPublishRejected = $_.Exception.Message.Contains("unsupported report_schema")
    }
    Assert-True $untypedPublishRejected "an untyped report was accepted as server-conformance"
    Write-LatestArtifactIndex -OutputRoot $testRoot

    $lockedOld = New-ArtifactRunDirectory `
        -OutputRoot $testRoot `
        -Family "locked" `
        -Label "old" `
        -Timestamp "20260730-120000"
    $removableOld = New-ArtifactRunDirectory `
        -OutputRoot $testRoot `
        -Family "locked" `
        -Label "middle" `
        -Timestamp "20260730-120001"
    $lockedNewest = New-ArtifactRunDirectory `
        -OutputRoot $testRoot `
        -Family "locked" `
        -Label "newest" `
        -Timestamp "20260730-120002"
    $lockedFile = Join-Path $lockedOld "runner.log"
    Set-Content -LiteralPath $lockedFile -Value "held open" -Encoding UTF8
    $lockedHandle = [System.IO.File]::Open(
        $lockedFile,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
    Remove-StaleArtifactRuns -OutputRoot $testRoot -Family "locked" -KeepRuns 1
    Assert-True (Test-Path -LiteralPath $lockedOld) "locked stale run should be retained for a later prune"
    Assert-True (-not (Test-Path -LiteralPath $removableOld)) "one locked run must not stop other stale runs from being pruned"
    Assert-True (Test-Path -LiteralPath $lockedNewest) "retention removed the newest locked-family run"

    $index = Get-Content -Raw -LiteralPath (Join-Path $testRoot "latest\index.json") | ConvertFrom-Json
    Assert-True (@($index.channels | Where-Object channel -eq "server-conformance").Count -eq 1) "latest index is missing the server-conformance channel"
    Assert-True (@($index.channels | Where-Object channel -eq "full").Count -eq 0) "latest index silently accepted the legacy full channel"
}
finally {
    if ($null -ne $lockedHandle) {
        $lockedHandle.Dispose()
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host "Artifact layout regression tests passed."

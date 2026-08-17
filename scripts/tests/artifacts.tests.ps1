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
try {
    Assert-True `
        (Test-IsCompleteCotestRun -ProfileIncludesAllTests $true) `
        "an unfiltered include-all profile must be a complete run"
    Assert-True `
        (-not (Test-IsCompleteCotestRun -ProfileIncludesAllTests $true -CargoTestFilter "one_test")) `
        "a filtered cotest run must not replace the complete-run channel"
    Assert-True `
        (-not (Test-IsCompleteCotestRun -ProfileIncludesAllTests $false)) `
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
        -Family "cotest" `
        -Label "all" `
        -Timestamp "20260730-120000"
    Set-Content -LiteralPath (Join-Path $first "summary.md") -Value "first" -Encoding UTF8
    Publish-ArtifactMirror -SourceDirectory $first -OutputRoot $testRoot -Channel "full"

    $target = Join-Path $testRoot "latest\full"
    Assert-True (Test-Path -LiteralPath (Join-Path $target "summary.md")) "full mirror was not published"
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
        -Family "cotest" `
        -Label "all" `
        -Timestamp "20260730-120001"
    Set-Content -LiteralPath (Join-Path $second "summary.md") -Value "second" -Encoding UTF8
    Publish-ArtifactMirror -SourceDirectory $second -OutputRoot $testRoot -Channel "full"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $target "stale.txt"))) "publishing retained a stale file"

    $third = New-ArtifactRunDirectory `
        -OutputRoot $testRoot `
        -Family "cotest" `
        -Label "fast-smoke" `
        -Timestamp "20260730-120002"
    Remove-StaleArtifactRuns -OutputRoot $testRoot -Family "cotest" -KeepRuns 2
    Assert-True (-not (Test-Path -LiteralPath $first)) "family retention did not remove the oldest run"
    Assert-True (Test-Path -LiteralPath $second) "family retention removed a retained run"
    Assert-True (Test-Path -LiteralPath $third) "family retention removed the newest run"

    $joint = New-ArtifactRunDirectory `
        -OutputRoot $testRoot `
        -Family "joint-e2e" `
        -Label "joint-full" `
        -Timestamp "20260730-120000"
    Remove-StaleArtifactRuns -OutputRoot $testRoot -Family "cotest" -KeepRuns 1
    Assert-True (Test-Path -LiteralPath $joint) "cotest retention crossed into the joint-e2e family"

    $index = Get-Content -Raw -LiteralPath (Join-Path $testRoot "latest\index.json") | ConvertFrom-Json
    Assert-True (@($index.channels | Where-Object channel -eq "full").Count -eq 1) "latest index is missing the full channel"
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host "Artifact layout regression tests passed."

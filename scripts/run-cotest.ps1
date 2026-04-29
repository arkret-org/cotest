[CmdletBinding()]
param(
    [ValidateSet("process", "docker")]
    [string]$Runtime = "process",
    [string]$SutManifest = "E:\Works\contrix-dev\soland\Cargo.toml",
    [string]$SutImage = "cotest-soland:latest",
    [string]$OutputRoot,
    [string]$CargoTestFilter,
    [switch]$BuildImage
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-DockerImagePresent {
    param([Parameter(Mandatory = $true)][string]$ImageTag)

    & docker image inspect $ImageTag *> $null
    return $LASTEXITCODE -eq 0
}

function Parse-CotestLog {
    param([Parameter(Mandatory = $true)][string]$LogPath)

    $tests = New-Object System.Collections.Generic.List[object]
    foreach ($line in Get-Content $LogPath) {
        if ($line -match '^test (?<name>.+?) \.\.\. (?<status>ok|FAILED|ignored)$') {
            $status = switch ($Matches.status) {
                "ok" { "passed" }
                "FAILED" { "failed" }
                "ignored" { "ignored" }
            }
            $tests.Add([pscustomobject]@{
                    name   = $Matches.name
                    status = $status
                })
        }
    }
    return $tests
}

function New-SummaryMarkdown {
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)]$Tests
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# cotest run summary")
    $lines.Add("")
    $lines.Add("- status: $($Summary.status)")
    $lines.Add("- runtime: $($Summary.runtime)")
    $lines.Add("- sut: $($Summary.sut)")
    $lines.Add("- started_at: $($Summary.started_at)")
    $lines.Add("- duration_seconds: $($Summary.duration_seconds)")
    $lines.Add("- exit_code: $($Summary.exit_code)")
    $lines.Add("- passed: $($Summary.passed)")
    $lines.Add("- failed: $($Summary.failed)")
    $lines.Add("- ignored: $($Summary.ignored)")
    $lines.Add("- raw_log: $($Summary.raw_log)")
    $lines.Add("")

    $failed = @($Tests | Where-Object { $_.status -eq "failed" })
    if ($failed.Count -gt 0) {
        $lines.Add("## Failed tests")
        $lines.Add("")
        foreach ($test in $failed) {
            $lines.Add("- $($test.name)")
        }
        $lines.Add("")
    }

    $lines.Add("## Tests")
    $lines.Add("")
    $lines.Add("| Status | Test |")
    $lines.Add("| --- | --- |")
    foreach ($test in $Tests) {
        $lines.Add("| $($test.status) | $($test.name) |")
    }

    return ($lines -join [Environment]::NewLine)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repoRoot "artifacts"
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $OutputRoot "runs\$timestamp"
$latestDir = Join-Path $OutputRoot "latest"
$null = New-Item -ItemType Directory -Force -Path $runDir
$null = New-Item -ItemType Directory -Force -Path $latestDir

$rawLog = Join-Path $runDir "raw.log"
$summaryJson = Join-Path $runDir "summary.json"
$summaryMd = Join-Path $runDir "summary.md"

if ($Runtime -eq "docker" -and ($BuildImage -or -not (Test-DockerImagePresent -ImageTag $SutImage))) {
    & (Join-Path $PSScriptRoot "build-soland-image.ps1") -ImageTag $SutImage
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build Docker image $SutImage"
    }
}

$originalEnv = @()
foreach ($name in "COTEST_SUT_MODE", "COTEST_SUT_MANIFEST", "COTEST_SUT_IMAGE") {
    $originalEnv += [pscustomobject]@{
        Name   = $name
        Exists = Test-Path "Env:$name"
        Value  = [Environment]::GetEnvironmentVariable($name)
    }
}

$startedAt = Get-Date
$command = @("test")
if ($CargoTestFilter) {
    $command += $CargoTestFilter
}
$command += @("--tests", "--no-fail-fast", "--", "--nocapture")

try {
    $env:COTEST_SUT_MODE = $Runtime
    if ($Runtime -eq "docker") {
        Remove-Item Env:COTEST_SUT_MANIFEST -ErrorAction SilentlyContinue
        $env:COTEST_SUT_IMAGE = $SutImage
    } else {
        $env:COTEST_SUT_MANIFEST = $SutManifest
        Remove-Item Env:COTEST_SUT_IMAGE -ErrorAction SilentlyContinue
    }

    Write-Host ("Running cargo {0}" -f ($command -join " "))
    & cargo @command 2>&1 | Tee-Object -FilePath $rawLog
    $exitCode = $LASTEXITCODE
}
finally {
    foreach ($entry in $originalEnv) {
        if ($entry.Exists) {
            [Environment]::SetEnvironmentVariable($entry.Name, $entry.Value)
        } else {
            Remove-Item "Env:$($entry.Name)" -ErrorAction SilentlyContinue
        }
    }
}

$finishedAt = Get-Date
$tests = Parse-CotestLog -LogPath $rawLog
$passed = @($tests | Where-Object { $_.status -eq "passed" }).Count
$failed = @($tests | Where-Object { $_.status -eq "failed" }).Count
$ignored = @($tests | Where-Object { $_.status -eq "ignored" }).Count

$summary = [pscustomobject]@{
    status           = if ($exitCode -eq 0) { "success" } else { "failure" }
    runtime          = $Runtime
    sut              = if ($Runtime -eq "docker") { "image:$SutImage" } else { "manifest:$SutManifest" }
    started_at       = $startedAt.ToString("o")
    finished_at      = $finishedAt.ToString("o")
    duration_seconds = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 2)
    exit_code        = $exitCode
    passed           = $passed
    failed           = $failed
    ignored          = $ignored
    raw_log          = $rawLog
    tests            = $tests
}

$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryJson -Encoding UTF8
$markdown = New-SummaryMarkdown -Summary $summary -Tests $tests
$markdown | Set-Content -Path $summaryMd -Encoding UTF8

Copy-Item -Path $rawLog -Destination (Join-Path $latestDir "raw.log") -Force
Copy-Item -Path $summaryJson -Destination (Join-Path $latestDir "summary.json") -Force
Copy-Item -Path $summaryMd -Destination (Join-Path $latestDir "summary.md") -Force

Write-Host ""
Write-Host "Summary"
Write-Host "  status : $($summary.status)"
Write-Host "  runtime: $($summary.runtime)"
Write-Host "  sut    : $($summary.sut)"
Write-Host "  passed : $($summary.passed)"
Write-Host "  failed : $($summary.failed)"
Write-Host "  ignored: $($summary.ignored)"
Write-Host "  log    : $rawLog"
Write-Host "  report : $summaryMd"

exit $exitCode

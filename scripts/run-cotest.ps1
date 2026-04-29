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

function ConvertTo-XmlSafe {
    param([AllowNull()][string]$Value)

    return [System.Security.SecurityElement]::Escape($Value)
}

function ConvertTo-HtmlSafe {
    param([AllowNull()][string]$Value)

    return [System.Net.WebUtility]::HtmlEncode($Value)
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
    $lines.Add("- finished_at: $($Summary.finished_at)")
    $lines.Add("- duration_seconds: $($Summary.duration_seconds)")
    $lines.Add("- exit_code: $($Summary.exit_code)")
    $lines.Add("- passed: $($Summary.passed)")
    $lines.Add("- failed: $($Summary.failed)")
    $lines.Add("- ignored: $($Summary.ignored)")
    $lines.Add("- raw_log: $($Summary.raw_log)")
    $lines.Add("- junit_xml: $($Summary.junit_xml)")
    $lines.Add("- html_report: $($Summary.html_report)")
    $lines.Add("- metadata: $($Summary.metadata_path)")
    $lines.Add("- coverage_matrix: $($Summary.coverage_matrix_path)")
    $lines.Add("- unresolved_gaps: $($Summary.unresolved_gaps_path)")
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

function New-SummaryHtml {
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)]$Tests
    )

    $rows = foreach ($test in $Tests) {
        $statusClass = switch ($test.status) {
            "passed" { "passed" }
            "failed" { "failed" }
            default { "ignored" }
        }
        "<tr class='$statusClass'><td>$(ConvertTo-HtmlSafe $test.status)</td><td>$(ConvertTo-HtmlSafe $test.name)</td></tr>"
    }

    @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>cotest summary</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #f5f7fb; color: #172033; }
    .card { background: white; border-radius: 12px; padding: 20px; box-shadow: 0 6px 24px rgba(23,32,51,0.08); margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #dbe2f0; }
    th { background: #eef3fb; }
    .passed td:first-child { color: #0a7a2f; font-weight: 600; }
    .failed td:first-child { color: #b42318; font-weight: 600; }
    .ignored td:first-child { color: #6b7280; font-weight: 600; }
    .metrics { display: grid; grid-template-columns: repeat(3, minmax(140px, 1fr)); gap: 12px; }
    .metric { background: #eef3fb; border-radius: 10px; padding: 12px; }
    .metric strong { display: block; font-size: 20px; margin-top: 6px; }
    code { background: #eef3fb; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>cotest run summary</h1>
    <p>Status: <strong>$(ConvertTo-HtmlSafe $Summary.status)</strong></p>
    <p>Runtime: <code>$(ConvertTo-HtmlSafe $Summary.runtime)</code></p>
    <p>SUT: <code>$(ConvertTo-HtmlSafe $Summary.sut)</code></p>
    <div class="metrics">
      <div class="metric">Passed<strong>$($Summary.passed)</strong></div>
      <div class="metric">Failed<strong>$($Summary.failed)</strong></div>
      <div class="metric">Ignored<strong>$($Summary.ignored)</strong></div>
    </div>
  </div>
  <div class="card">
    <h2>Artifacts</h2>
    <p>raw log: <code>$(ConvertTo-HtmlSafe $Summary.raw_log)</code></p>
    <p>junit xml: <code>$(ConvertTo-HtmlSafe $Summary.junit_xml)</code></p>
    <p>coverage matrix: <code>$(ConvertTo-HtmlSafe $Summary.coverage_matrix_path)</code></p>
    <p>unresolved gaps: <code>$(ConvertTo-HtmlSafe $Summary.unresolved_gaps_path)</code></p>
  </div>
  <div class="card">
    <h2>Tests</h2>
    <table>
      <thead><tr><th>Status</th><th>Test</th></tr></thead>
      <tbody>
        $($rows -join [Environment]::NewLine)
      </tbody>
    </table>
  </div>
</body>
</html>
"@
}

function New-JUnitXml {
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)]$Tests
    )

    $testCases = foreach ($test in $Tests) {
        $name = ConvertTo-XmlSafe $test.name
        switch ($test.status) {
            "failed" {
                "<testcase classname='cotest' name='$name'><failure message='test failed'>See raw log: $([System.Security.SecurityElement]::Escape($Summary.raw_log))</failure></testcase>"
            }
            "ignored" {
                "<testcase classname='cotest' name='$name'><skipped /></testcase>"
            }
            default {
                "<testcase classname='cotest' name='$name' />"
            }
        }
    }

    @"
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="cotest" tests="$($Tests.Count)" failures="$($Summary.failed)" skipped="$($Summary.ignored)" time="$($Summary.duration_seconds)">
    $($testCases -join [Environment]::NewLine)
  </testsuite>
</testsuites>
"@
}

function Get-RepoGitRevision {
    param([Parameter(Mandatory = $true)][string]$RepoPath)

    if (-not (Test-Path (Join-Path $RepoPath ".git"))) {
        return $null
    }

    $revision = (& git -C $RepoPath rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return $revision.Trim()
}

function Get-DirectoryFingerprint {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    if (-not (Test-Path $RootPath)) {
        return $null
    }

    $items = Get-ChildItem -Path $RootPath -Recurse -File | Sort-Object FullName
    $builder = New-Object System.Text.StringBuilder
    foreach ($item in $items) {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $item.FullName).Hash.ToLowerInvariant()
        [void]$builder.AppendLine("$($item.FullName)|$hash")
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($bytes)
    }
    finally {
        $sha.Dispose()
    }
    return "sha256:{0}" -f ([System.BitConverter]::ToString($digest).Replace("-", "").ToLowerInvariant())
}

function Get-SutMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Runtime,
        [Parameter(Mandatory = $true)][string]$SutManifest,
        [Parameter(Mandatory = $true)][string]$SutImage
    )

    if ($Runtime -eq "process") {
        $sutRepo = Split-Path -Parent $SutManifest
        return [pscustomobject]@{
            runtime      = "process"
            manifest     = $SutManifest
            repo_root    = $sutRepo
            git_revision = Get-RepoGitRevision -RepoPath $sutRepo
        }
    }

    $imageId = $null
    & docker image inspect $SutImage --format "{{.Id}}" 2>$null
    if ($LASTEXITCODE -eq 0) {
        $imageId = (& docker image inspect $SutImage --format "{{.Id}}" 2>$null).Trim()
    }
    $localSolandRoot = "E:\Works\contrix-dev\soland"
    return [pscustomobject]@{
        runtime           = "docker"
        image             = $SutImage
        image_id          = $imageId
        local_repo_root   = $localSolandRoot
        local_git_revision = Get-RepoGitRevision -RepoPath $localSolandRoot
    }
}

function Get-SpecMetadata {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $specRoot = "E:\Works\contrix-dev\contrix-spec"
    $fixtureRoot = Join-Path $specRoot "zh\conformance\fixtures"
    return [pscustomobject]@{
        spec_root           = $specRoot
        git_revision        = Get-RepoGitRevision -RepoPath $specRoot
        fixture_root        = $fixtureRoot
        fixture_fingerprint = Get-DirectoryFingerprint -RootPath $fixtureRoot
    }
}

function Get-CoverageMatrix {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $configPath = Join-Path $RepoRoot "config\coverage-profiles.json"
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    $profiles = foreach ($profile in $config.profiles) {
        $implemented = @($profile.requirements | Where-Object { $_.status -eq "implemented" }).Count
        $partial = @($profile.requirements | Where-Object { $_.status -eq "partial" }).Count
        $pending = @($profile.requirements | Where-Object { $_.status -eq "pending" }).Count
        [pscustomobject]@{
            profile_id      = $profile.profile_id
            spec_ref        = $profile.spec_ref
            summary_status  = $profile.summary_status
            implemented     = $implemented
            partial         = $partial
            pending         = $pending
            requirements    = $profile.requirements
        }
    }

    [pscustomobject]@{
        generated_at = (Get-Date).ToString("o")
        profiles     = $profiles
    }
}

function New-CoverageMarkdown {
    param([Parameter(Mandatory = $true)]$Coverage)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# coverage matrix")
    $lines.Add("")
    $lines.Add("| Profile | Status | Implemented | Partial | Pending |")
    $lines.Add("| --- | --- | --- | --- | --- |")
    foreach ($profile in $Coverage.profiles) {
        $lines.Add("| $($profile.profile_id) | $($profile.summary_status) | $($profile.implemented) | $($profile.partial) | $($profile.pending) |")
    }
    $lines.Add("")
    foreach ($profile in $Coverage.profiles) {
        $lines.Add("## $($profile.profile_id)")
        $lines.Add("")
        $lines.Add("| Requirement | Status | Sources |")
        $lines.Add("| --- | --- | --- |")
        foreach ($requirement in $profile.requirements) {
            $sources = if ($requirement.sources.Count -gt 0) { ($requirement.sources -join ", ") } else { "-" }
            $lines.Add("| $($requirement.name) | $($requirement.status) | $sources |")
        }
        $lines.Add("")
    }
    return ($lines -join [Environment]::NewLine)
}

function Get-UnresolvedTodoItems {
    param([Parameter(Mandatory = $true)][string]$TodoPath)

    $items = New-Object System.Collections.Generic.List[object]
    $currentSection = "root"
    foreach ($line in Get-Content $TodoPath) {
        if ($line -match '^##\s+(?<section>.+)$') {
            $currentSection = $Matches.section.Trim()
            continue
        }
        if ($line -match '^\s*-\s+\[\s\]\s+(?<item>.+)$') {
            $items.Add([pscustomobject]@{
                    section = $currentSection
                    item    = $Matches.item.Trim()
                })
        }
    }
    return $items
}

function New-UnresolvedMarkdown {
    param([Parameter(Mandatory = $true)]$Items)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# unresolved spec gaps and pending work")
    $lines.Add("")
    if ($Items.Count -eq 0) {
        $lines.Add("All tracked tasks are complete.")
        return ($lines -join [Environment]::NewLine)
    }

    $grouped = $Items | Group-Object section
    foreach ($group in $grouped) {
        $lines.Add("## $($group.Name)")
        $lines.Add("")
        foreach ($item in $group.Group) {
            $lines.Add("- $($item.item)")
        }
        $lines.Add("")
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
$serviceLogDir = Join-Path $runDir "services"
$null = New-Item -ItemType Directory -Force -Path $runDir
$null = New-Item -ItemType Directory -Force -Path $latestDir
$null = New-Item -ItemType Directory -Force -Path $serviceLogDir

$rawLog = Join-Path $runDir "raw.log"
$summaryJson = Join-Path $runDir "summary.json"
$summaryMd = Join-Path $runDir "summary.md"
$summaryHtml = Join-Path $runDir "summary.html"
$junitXml = Join-Path $runDir "junit.xml"
$metadataJson = Join-Path $runDir "metadata.json"
$coverageJson = Join-Path $runDir "coverage-matrix.json"
$coverageMd = Join-Path $runDir "coverage-matrix.md"
$gapsJson = Join-Path $runDir "unresolved-gaps.json"
$gapsMd = Join-Path $runDir "unresolved-gaps.md"

if ($Runtime -eq "docker" -and ($BuildImage -or -not (Test-DockerImagePresent -ImageTag $SutImage))) {
    & (Join-Path $PSScriptRoot "build-soland-image.ps1") -ImageTag $SutImage
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build Docker image $SutImage"
    }
}

$originalEnv = @()
foreach ($name in "COTEST_SUT_MODE", "COTEST_SUT_MANIFEST", "COTEST_SUT_IMAGE", "COTEST_ARTIFACT_DIR", "COTEST_SERVICE_LOG_DIR") {
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
    $env:COTEST_ARTIFACT_DIR = $runDir
    $env:COTEST_SERVICE_LOG_DIR = $serviceLogDir
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
$tests = @(Parse-CotestLog -LogPath $rawLog)
$passed = @($tests | Where-Object { $_.status -eq "passed" }).Count
$failed = @($tests | Where-Object { $_.status -eq "failed" }).Count
$ignored = @($tests | Where-Object { $_.status -eq "ignored" }).Count
$coverage = Get-CoverageMatrix -RepoRoot $repoRoot
$unresolved = Get-UnresolvedTodoItems -TodoPath (Join-Path $repoRoot "_todos.md")
$sutMetadata = Get-SutMetadata -Runtime $Runtime -SutManifest $SutManifest -SutImage $SutImage
$specMetadata = Get-SpecMetadata -RepoRoot $repoRoot
$metadata = [pscustomobject]@{
    generated_at = $finishedAt.ToString("o")
    sut          = $sutMetadata
    spec         = $specMetadata
}

$summary = [pscustomobject]@{
    status               = if ($exitCode -eq 0) { "success" } else { "failure" }
    runtime              = $Runtime
    sut                  = if ($Runtime -eq "docker") { "image:$SutImage" } else { "manifest:$SutManifest" }
    started_at           = $startedAt.ToString("o")
    finished_at          = $finishedAt.ToString("o")
    duration_seconds     = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 2)
    exit_code            = $exitCode
    passed               = $passed
    failed               = $failed
    ignored              = $ignored
    raw_log              = $rawLog
    junit_xml            = $junitXml
    html_report          = $summaryHtml
    metadata_path        = $metadataJson
    coverage_matrix_path = $coverageJson
    unresolved_gaps_path = $gapsJson
    service_log_dir      = $serviceLogDir
    tests                = $tests
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryJson -Encoding UTF8
$metadata | ConvertTo-Json -Depth 8 | Set-Content -Path $metadataJson -Encoding UTF8
$coverage | ConvertTo-Json -Depth 8 | Set-Content -Path $coverageJson -Encoding UTF8
$unresolved | ConvertTo-Json -Depth 6 | Set-Content -Path $gapsJson -Encoding UTF8

$markdown = New-SummaryMarkdown -Summary $summary -Tests $tests
$markdown | Set-Content -Path $summaryMd -Encoding UTF8

$html = New-SummaryHtml -Summary $summary -Tests $tests
$html | Set-Content -Path $summaryHtml -Encoding UTF8

$xml = New-JUnitXml -Summary $summary -Tests $tests
$xml | Set-Content -Path $junitXml -Encoding UTF8

$coverageMarkdown = New-CoverageMarkdown -Coverage $coverage
$coverageMarkdown | Set-Content -Path $coverageMd -Encoding UTF8

$gapsMarkdown = New-UnresolvedMarkdown -Items $unresolved
$gapsMarkdown | Set-Content -Path $gapsMd -Encoding UTF8

$artifactFiles = @(
    $rawLog,
    $summaryJson,
    $summaryMd,
    $summaryHtml,
    $junitXml,
    $metadataJson,
    $coverageJson,
    $coverageMd,
    $gapsJson,
    $gapsMd
)

foreach ($file in $artifactFiles) {
    Copy-Item -Path $file -Destination (Join-Path $latestDir ([System.IO.Path]::GetFileName($file))) -Force
}
if (Test-Path $serviceLogDir) {
    $latestServiceDir = Join-Path $latestDir "services"
    if (Test-Path $latestServiceDir) {
        Remove-Item -Recurse -Force $latestServiceDir
    }
    Copy-Item -Path $serviceLogDir -Destination $latestServiceDir -Recurse -Force
}

Write-Host ""
Write-Host "Summary"
Write-Host "  status   : $($summary.status)"
Write-Host "  runtime  : $($summary.runtime)"
Write-Host "  sut      : $($summary.sut)"
Write-Host "  passed   : $($summary.passed)"
Write-Host "  failed   : $($summary.failed)"
Write-Host "  ignored  : $($summary.ignored)"
Write-Host "  log      : $rawLog"
Write-Host "  report   : $summaryMd"
Write-Host "  junit    : $junitXml"
Write-Host "  html     : $summaryHtml"
Write-Host "  coverage : $coverageMd"
Write-Host "  gaps     : $gapsMd"
Write-Host "  services : $serviceLogDir"

exit $exitCode

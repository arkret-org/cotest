[CmdletBinding()]
param(
    [ValidateSet("process", "docker")]
    [string]$Runtime = "process",
    [string]$SutManifest,
    [string]$SutImage = "cotest-soland:latest",
    [string]$OutputRoot,
    [string]$CargoTestFilter,
    [ValidateSet("all", "fast-smoke", "compose", "release-gate", "full-nightly", "soak", "joint", "dual-soland", "mock-parity")]
    [string]$Profile = "all",
    [string[]]$RequiredCoverageProfiles = @(),
    [string]$CoverageBaselinePath,
    [ValidateSet("promised", "verified")]
    [string]$CoverageMode = "verified",
    [switch]$FailOnCoverageRegression,
    [switch]$AllowSecretLeaks,
    [switch]$BuildImage,
    [string[]]$DockerCacheFrom = @(),
    [string]$DockerCacheTo,
    [switch]$DockerPull,
    [switch]$DockerNoCache,
    [switch]$SkipJointSmokeGate
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Add-RawLogLine {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][string]$Value = ""
    )

    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        try {
            Add-Content -LiteralPath $Path -Value $Value -Encoding UTF8
            return
        }
        catch [System.IO.IOException] {
            Start-Sleep -Milliseconds (50 * ($attempt + 1))
        }
    }
    Add-Content -LiteralPath $Path -Value $Value -Encoding UTF8
}

function Test-DockerImagePresent {
    param([Parameter(Mandatory = $true)][string]$ImageTag)

    & docker image inspect $ImageTag *> $null
    return $LASTEXITCODE -eq 0
}

function Invoke-JointSmokeGate {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$RunDir,
        [Parameter(Mandatory = $true)][string]$RawLog,
        [string]$OutputName = "joint-smoke",
        [ValidateSet("joint-smoke", "joint-full")][string]$RunProfile = "joint-smoke",
        [string]$PlaywrightProject = "chromium",
        [bool]$StartCoauth = $true,
        [bool]$DualSoland = $false,
        [bool]$StartMocks = $false,
        [string]$Grep,
        [ValidateSet("process", "docker")][string]$SolandRuntime = "process",
        [string]$SolandImage = "cotest-soland:latest",
        [bool]$BuildSolandImage = $false,
        [string[]]$DockerCacheFrom = @(),
        [string]$DockerCacheTo,
        [bool]$DockerPull = $false,
        [bool]$DockerNoCache = $false,
        [bool]$SkipYougen = $false
    )

    $jointScript = Join-Path $RepoRoot "scripts\run-joint-e2e.ps1"
    $jointOutputRoot = Join-Path $RunDir $OutputName
    $psExe = (Get-Process -Id $PID).Path
    $args = @(
        "-NoProfile",
        "-File", $jointScript,
        "-OutputRoot", $jointOutputRoot
    )
    if ($StartCoauth) {
        $args += "-StartCoauth"
    }
    if ($DualSoland) {
        $args += "-DualSoland"
    }
    if ($StartMocks) {
        $args += "-StartMocks"
    }
    if ($SolandRuntime -eq "docker") {
        $args += @("-SolandRuntime", "docker", "-SolandImage", $SolandImage)
        if ($BuildSolandImage) {
            $args += "-BuildSolandImage"
        }
        if ($DockerCacheFrom.Count -gt 0) {
            $args += "-DockerCacheFrom"
            $args += $DockerCacheFrom
        }
        if ($DockerCacheTo) {
            $args += @("-DockerCacheTo", $DockerCacheTo)
        }
        if ($DockerPull) {
            $args += "-DockerPull"
        }
        if ($DockerNoCache) {
            $args += "-DockerNoCache"
        }
    }
    if ($SkipYougen) {
        $args += "-SkipYougen"
    }
    $args += @(
        "-RunProfile", $RunProfile,
        "-PlaywrightProject", $PlaywrightProject
    )
    if ($Grep) {
        $args += @("-Grep", $Grep)
    }
    if (Test-Path (Join-Path $RepoRoot "e2e\node_modules")) {
        $args += "-SkipNpmInstall"
    }

    Add-RawLogLine -Path $RawLog -Value ""
    Add-RawLogLine -Path $RawLog -Value "=== $OutputName $RunProfile ==="
    $startedAt = Get-Date
    $childLabel = ($OutputName -replace '[^A-Za-z0-9_.-]', '_')
    $childStdout = Join-Path $RunDir "$childLabel.stdout.log"
    $childStderr = Join-Path $RunDir "$childLabel.stderr.log"
    $process = Start-Process `
        -FilePath $psExe `
        -ArgumentList $args `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $childStdout `
        -RedirectStandardError $childStderr
    $exitCode = $process.ExitCode
    foreach ($path in @($childStdout, $childStderr)) {
        if (Test-Path $path) {
            foreach ($line in Get-Content -LiteralPath $path) {
                Add-RawLogLine -Path $RawLog -Value $line
            }
        }
    }
    $finishedAt = Get-Date

    $summaryJson = $null
    $summaryMd = $null
    $summaryCandidates = @(Get-ChildItem -Path (Join-Path $jointOutputRoot "runs") -Recurse -Filter "summary.json" -ErrorAction SilentlyContinue |
        Where-Object { (Split-Path -Leaf (Split-Path -Parent $_.FullName)) -eq "joint-e2e" } |
        Sort-Object LastWriteTime)
    if ($summaryCandidates.Count -gt 0) {
        $summaryJson = $summaryCandidates[-1].FullName
        $summaryMd = Join-Path (Split-Path -Parent $summaryJson) "summary.md"
    }

    [pscustomobject]@{
        generated_at     = $finishedAt.ToString("o")
        started_at       = $startedAt.ToString("o")
        status           = if ($exitCode -eq 0) { "passed" } else { "failed" }
        exit_code        = $exitCode
        output_root      = $jointOutputRoot
        summary_json     = $summaryJson
        summary_markdown = $summaryMd
    }
}

function Get-CiProfileConfig {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $configPath = Join-Path $RepoRoot "config\ci-profiles.json"
    if (-not (Test-Path $configPath)) {
        throw "CI profile config not found: $configPath"
    }
    return Get-Content $configPath -Raw | ConvertFrom-Json
}

function Get-CiProfile {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$ProfileId
    )

    $profile = @($Config.profiles | Where-Object { $_.profile_id -eq $ProfileId }) | Select-Object -First 1
    if (-not $profile) {
        throw "Unknown CI profile '$ProfileId'"
    }
    return $profile
}

function Get-ActiveQuarantineEntries {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [string[]]$ExcludedLabels = @()
    )

    $entries = @()
    foreach ($entry in @($Config.quarantined_tests)) {
        $labels = @($entry.labels)
        if ($labels.Count -eq 0 -and $entry.label) {
            $labels = @($entry.label)
        }
        $matchesExcludedLabel = $false
        foreach ($label in $labels) {
            if ($ExcludedLabels -contains $label) {
                $matchesExcludedLabel = $true
                break
            }
        }
        if ($matchesExcludedLabel) {
            $entries += $entry
        }
    }
    return $entries
}

function Get-CargoTestInvocations {
    param(
        [Parameter(Mandatory = $true)]$Profile,
        [Parameter(Mandatory = $true)]$QuarantineEntries,
        [AllowNull()][string]$CargoTestFilter
    )

    if ($CargoTestFilter) {
        return @([pscustomobject]@{
                label = "filter:$CargoTestFilter"
                filter = $CargoTestFilter
                skips = @()
            })
    }

    $quarantinedFilters = @($QuarantineEntries | ForEach-Object { $_.test_filter } | Where-Object { $_ })
    if ($Profile.include_all_tests) {
        return @([pscustomobject]@{
                label = $Profile.profile_id
                filter = $null
                skips = $quarantinedFilters
            })
    }

    $invocations = New-Object System.Collections.Generic.List[object]
    foreach ($filter in @($Profile.cargo_filters)) {
        if ($quarantinedFilters -contains $filter) {
            continue
        }
        $invocations.Add([pscustomobject]@{
                label = $filter
                filter = $filter
                skips = @()
            })
    }
    if ($invocations.Count -eq 0) {
        throw "CI profile '$($Profile.profile_id)' did not produce any cargo test invocations"
    }
    return $invocations
}

function New-CargoTestArgs {
    param(
        [AllowNull()][string]$Filter,
        [string[]]$Skips = @(),
        [switch]$IncludeIgnored
    )

    $args = @("test")
    if ($Filter) {
        $args += $Filter
    }
    $args += @("--tests", "--no-fail-fast", "--", "--nocapture")
    if ($IncludeIgnored) {
        # The soak (CT-18) profile - and any future opt-in long-running
        # profiles - must promote `#[ignore]`'d tests, otherwise the run
        # would silently skip every scenario in the profile.
        $args += "--ignored"
    }
    foreach ($skip in $Skips) {
        if ($skip) {
            $args += @("--skip", $skip)
        }
    }
    return $args
}

function Invoke-CargoTestInvocation {
    param(
        [Parameter(Mandatory = $true)][string[]]$CargoArgs,
        [Parameter(Mandatory = $true)][string]$RawLog,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $header = "=== cotest invocation: $Label ==="
    Add-RawLogLine -Path $RawLog -Value $header
    Write-Host $header
    Write-Host ("Running cargo {0}" -f ($CargoArgs -join " "))

    $safeLabel = ($Label -replace '[^A-Za-z0-9_.-]', '_')
    $stdoutPath = Join-Path ([System.IO.Path]::GetDirectoryName($RawLog)) "cargo-$safeLabel.stdout.log"
    $stderrPath = Join-Path ([System.IO.Path]::GetDirectoryName($RawLog)) "cargo-$safeLabel.stderr.log"
    try {
        $process = Start-Process `
            -FilePath "cargo" `
            -ArgumentList $CargoArgs `
            -NoNewWindow `
            -Wait `
            -PassThru `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath

        foreach ($path in @($stderrPath, $stdoutPath)) {
            if (-not (Test-Path $path)) {
                continue
            }
            foreach ($line in Get-Content $path) {
                Add-RawLogLine -Path $RawLog -Value $line
                Write-Host $line
            }
        }
        return $process.ExitCode
    }
    finally {
        Remove-Item $stdoutPath, $stderrPath -ErrorAction SilentlyContinue
    }
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
    if ($Summary.PSObject.Properties.Name -contains "e2e_coverage_status") {
        $ratio = if ($null -ne $Summary.e2e_coverage_verified_ratio) { "{0:P1}" -f [double]$Summary.e2e_coverage_verified_ratio } else { "n/a" }
        $lines.Add("Promised: $($Summary.e2e_coverage_promised_count) / Verified: $($Summary.e2e_coverage_verified_count) ($ratio)")
        $lines.Add("")
        $lines.Add("| Coverage mode | Promised | Verified | Verified ratio | Verified-only pass |")
        $lines.Add("|---|---:|---:|---:|---|")
        $lines.Add("| $($Summary.coverage_mode) | $($Summary.e2e_coverage_promised_count) | $($Summary.e2e_coverage_verified_count) | $ratio | $($Summary.coverage_gate_verified_only_pass) |")
        $lines.Add("")
    }
    if (($Summary.PSObject.Properties.Name -contains "journey_coverage_rows") -and $Summary.journey_coverage_rows.Count -gt 0) {
        $lines.Add("## Journey Coverage")
        $lines.Add("")
        $lines.Add("| Journey | Live verified | Promised | Domain-fallback promised | Rust-scenario promised | Blocking |")
        $lines.Add("|---|---:|---:|---:|---:|---:|")
        foreach ($journey in $Summary.journey_coverage_rows) {
            $fallbackPromised = if ($journey.PSObject.Properties.Name -contains "domain_fallback_promised") { $journey.domain_fallback_promised } else { "n/a" }
            $rustScenarioPromised = if ($journey.PSObject.Properties.Name -contains "rust_scenario_promised") { $journey.rust_scenario_promised } else { "n/a" }
            $liveVerified = if ($journey.PSObject.Properties.Name -contains "live_verified") { $journey.live_verified } else { $journey.verified }
            $lines.Add("| $($journey.id) | $liveVerified | $($journey.promised) | $fallbackPromised | $rustScenarioPromised | $($journey.blocking) |")
        }
        $lines.Add("")
    }
    $lines.Add("- status: $($Summary.status)")
    $lines.Add("- profile: $($Summary.profile)")
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
    $lines.Add("- transcript: $($Summary.transcript_path)")
    $lines.Add("- junit_xml: $($Summary.junit_xml)")
    $lines.Add("- html_report: $($Summary.html_report)")
    $lines.Add("- metadata: $($Summary.metadata_path)")
    $lines.Add("- coverage_matrix: $($Summary.coverage_matrix_path)")
    if ($Summary.PSObject.Properties.Name -contains "journey_coverage_path") {
        $lines.Add("- journey_coverage: $($Summary.journey_coverage_path) ($($Summary.journey_coverage_status))")
    }
    if ($Summary.PSObject.Properties.Name -contains "fixme_debt_path") {
        $lines.Add("- fixme_debt: $($Summary.fixme_debt_path) ($($Summary.fixme_debt_status))")
    }
    $lines.Add("- coverage_gate: $($Summary.coverage_gate_path) ($($Summary.coverage_gate_status))")
    $lines.Add("- joint_smoke_gate: $($Summary.joint_smoke_gate_path) ($($Summary.joint_smoke_status))")
    $lines.Add("- release_gate: $($Summary.release_gate_path) ($($Summary.release_gate_status))")
    $lines.Add("- unresolved_gaps: $($Summary.unresolved_gaps_path)")
    $lines.Add("- ci_profile: $($Summary.ci_profile_path)")
    $lines.Add("- secret_scan: $($Summary.secret_scan_path) ($($Summary.secret_scan_status))")
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
    <p>Profile: <code>$(ConvertTo-HtmlSafe $Summary.profile)</code></p>
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
    <p>transcript: <code>$(ConvertTo-HtmlSafe $Summary.transcript_path)</code></p>
    <p>junit xml: <code>$(ConvertTo-HtmlSafe $Summary.junit_xml)</code></p>
    <p>coverage matrix: <code>$(ConvertTo-HtmlSafe $Summary.coverage_matrix_path)</code></p>
    <p>coverage gate: <code>$(ConvertTo-HtmlSafe $Summary.coverage_gate_path)</code> ($(ConvertTo-HtmlSafe $Summary.coverage_gate_status))</p>
    <p>joint smoke gate: <code>$(ConvertTo-HtmlSafe $Summary.joint_smoke_gate_path)</code> ($(ConvertTo-HtmlSafe $Summary.joint_smoke_status))</p>
    <p>release gate: <code>$(ConvertTo-HtmlSafe $Summary.release_gate_path)</code> ($(ConvertTo-HtmlSafe $Summary.release_gate_status))</p>
    <p>unresolved gaps: <code>$(ConvertTo-HtmlSafe $Summary.unresolved_gaps_path)</code></p>
    <p>ci profile: <code>$(ConvertTo-HtmlSafe $Summary.ci_profile_path)</code></p>
    <p>secret scan: <code>$(ConvertTo-HtmlSafe $Summary.secret_scan_path)</code> ($(ConvertTo-HtmlSafe $Summary.secret_scan_status))</p>
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
        $hash = Get-Sha256FileHex -Path $item.FullName
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

function Get-Sha256FileHex {
    param([Parameter(Mandatory = $true)][string]$Path)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $digest = $sha.ComputeHash($stream)
        return [System.BitConverter]::ToString($digest).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $sha.Dispose()
    }
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
    $workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $localSolandRoot = Join-Path $workspaceRoot "soland"
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

    $workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $specRoot = Join-Path $workspaceRoot "cokret-spec"
    $artifactRoot = Join-Path $specRoot "spec\v1\artifacts"
    $fixtureRoot = Join-Path $artifactRoot "fixtures"
    return [pscustomobject]@{
        spec_root            = $specRoot
        git_revision         = Get-RepoGitRevision -RepoPath $specRoot
        artifact_root        = $artifactRoot
        fixture_root         = $fixtureRoot
        artifact_fingerprint = Get-DirectoryFingerprint -RootPath $artifactRoot
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
        $skipped = @($profile.requirements | Where-Object { $_.status -eq "skipped" }).Count
        $failed = @($profile.requirements | Where-Object { $_.status -eq "failed" }).Count
        [pscustomobject]@{
            profile_id      = $profile.profile_id
            spec_ref        = $profile.spec_ref
            summary_status  = $profile.summary_status
            implemented     = $implemented
            partial         = $partial
            pending         = $pending
            skipped         = $skipped
            failed          = $failed
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
    $lines.Add("| Profile | Status | Implemented | Partial | Pending | Skipped | Failed |")
    $lines.Add("| --- | --- | --- | --- | --- | --- | --- |")
    foreach ($profile in $Coverage.profiles) {
        $lines.Add("| $($profile.profile_id) | $($profile.summary_status) | $($profile.implemented) | $($profile.partial) | $($profile.pending) | $($profile.skipped) | $($profile.failed) |")
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

function Get-EffectiveRequiredCoverageProfiles {
    param(
        [Parameter(Mandatory = $true)]$Profile,
        [string[]]$Overrides = @()
    )

    if ($Overrides.Count -gt 0) {
        return $Overrides
    }
    return @($Profile.required_coverage_profiles)
}

function Get-CoverageStatusRank {
    param([AllowNull()][string]$Status)

    switch ($Status) {
        "implemented" { return 3 }
        "partial" { return 2 }
        "skipped" { return 1 }
        "pending" { return 1 }
        "failed" { return 0 }
        default { return 0 }
    }
}

function Compare-CoverageToBaseline {
    param(
        [Parameter(Mandatory = $true)]$CurrentCoverage,
        [AllowNull()][string]$BaselinePath,
        [string[]]$RequiredProfiles = @(),
        [AllowNull()]$E2eCoverage,
        [ValidateSet("promised", "verified")]
        [string]$CoverageMode = "verified"
    )

    $regressions = New-Object System.Collections.Generic.List[object]
    $promisedCount = $null
    $verifiedCount = $null
    $verifiedRatio = $null
    if ($E2eCoverage -and $E2eCoverage.status -eq "available") {
        $promisedCount = $E2eCoverage.promised_count
        $verifiedCount = $E2eCoverage.verified_count
        $verifiedRatio = $E2eCoverage.verified_ratio
    }
    $coverageCountForGate = if ($CoverageMode -eq "verified") { $verifiedCount } else { $promisedCount }
    if ($null -ne $coverageCountForGate -and [int]$coverageCountForGate -le 0) {
        $regressions.Add([pscustomobject]@{
                profile_id      = "e2e"
                requirement     = "$CoverageMode coverage count"
                baseline_status = ">0"
                current_status  = "$coverageCountForGate"
            })
    }
    $verifiedOnlyPass = $true
    if ($null -ne $verifiedCount -and [int]$verifiedCount -le 0) {
        $verifiedOnlyPass = $false
    }
    $profileFilter = @($RequiredProfiles)
    if ($profileFilter.Count -eq 0) {
        $profileFilter = @($CurrentCoverage.profiles | ForEach-Object { $_.profile_id })
    }
    foreach ($currentProfile in @($CurrentCoverage.profiles)) {
        if ($profileFilter -notcontains $currentProfile.profile_id) {
            continue
        }
        foreach ($currentRequirement in @($currentProfile.requirements)) {
            if ($currentRequirement.status -eq "failed") {
                $regressions.Add([pscustomobject]@{
                        profile_id      = $currentProfile.profile_id
                        requirement     = $currentRequirement.name
                        baseline_status = "declared"
                        current_status  = "failed"
                    })
            }
        }
    }

    if (-not $BaselinePath -or -not (Test-Path $BaselinePath)) {
        return [pscustomobject]@{
            status            = if ($regressions.Count -gt 0) { "failed" } else { "skipped" }
            baseline_path     = $BaselinePath
            required_profiles = $profileFilter
            coverage_mode     = $CoverageMode
            promised_count    = $promisedCount
            verified_count    = $verifiedCount
            verified_ratio    = $verifiedRatio
            verified_only_pass = $verifiedOnlyPass
            regressions       = $regressions
            reason            = if ($regressions.Count -gt 0) { "current_requirement_failed" } else { "baseline_not_found" }
        }
    }

    $baseline = Get-Content $BaselinePath -Raw | ConvertFrom-Json

    foreach ($currentProfile in @($CurrentCoverage.profiles)) {
        if ($profileFilter -notcontains $currentProfile.profile_id) {
            continue
        }
        $baselineProfile = @($baseline.profiles | Where-Object { $_.profile_id -eq $currentProfile.profile_id }) | Select-Object -First 1
        if (-not $baselineProfile) {
            continue
        }
        foreach ($currentRequirement in @($currentProfile.requirements)) {
            $baselineRequirement = @($baselineProfile.requirements | Where-Object { $_.name -eq $currentRequirement.name }) | Select-Object -First 1
            if (-not $baselineRequirement) {
                continue
            }
            $currentRank = Get-CoverageStatusRank -Status $currentRequirement.status
            $baselineRank = Get-CoverageStatusRank -Status $baselineRequirement.status
            if ($currentRank -lt $baselineRank) {
                $regressions.Add([pscustomobject]@{
                        profile_id      = $currentProfile.profile_id
                        requirement     = $currentRequirement.name
                        baseline_status = $baselineRequirement.status
                        current_status  = $currentRequirement.status
                    })
            }
        }
    }

    return [pscustomobject]@{
        status            = if ($regressions.Count -gt 0) { "failed" } else { "passed" }
        baseline_path     = $BaselinePath
        required_profiles = $profileFilter
        coverage_mode     = $CoverageMode
        promised_count    = $promisedCount
        verified_count    = $verifiedCount
        verified_ratio    = $verifiedRatio
        verified_only_pass = $verifiedOnlyPass
        regressions       = $regressions
        reason            = $null
    }
}

function New-CoverageGateMarkdown {
    param([Parameter(Mandatory = $true)]$Gate)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# coverage gate")
    $lines.Add("")
    $lines.Add("- status: $($Gate.status)")
    if ($Gate.PSObject.Properties.Name -contains "coverage_mode") {
        $lines.Add("- coverage_mode: $($Gate.coverage_mode)")
    }
    if ($Gate.PSObject.Properties.Name -contains "promised_count") {
        $ratio = if ($null -ne $Gate.verified_ratio) { "{0:P1}" -f [double]$Gate.verified_ratio } else { "n/a" }
        $lines.Add("- promised: $($Gate.promised_count)")
        $lines.Add("- verified: $($Gate.verified_count) ($ratio)")
        $lines.Add("- verified_only_pass: $($Gate.verified_only_pass)")
    }
    if ($Gate.baseline_path) {
        $lines.Add("- baseline: $($Gate.baseline_path)")
    }
    if ($Gate.required_profiles.Count -gt 0) {
        $lines.Add("- required_profiles: $($Gate.required_profiles -join ', ')")
    }
    if ($Gate.reason) {
        $lines.Add("- reason: $($Gate.reason)")
    }
    $lines.Add("")
    if ($Gate.regressions.Count -eq 0) {
        $lines.Add("No coverage regressions detected.")
        return ($lines -join [Environment]::NewLine)
    }

    $lines.Add("| Profile | Requirement | Baseline | Current |")
    $lines.Add("| --- | --- | --- | --- |")
    foreach ($regression in $Gate.regressions) {
        $lines.Add("| $($regression.profile_id) | $($regression.requirement) | $($regression.baseline_status) | $($regression.current_status) |")
    }
    return ($lines -join [Environment]::NewLine)
}

function Get-RequiredTestStatuses {
    param(
        [Parameter(Mandatory = $true)]$Tests,
        [string[]]$RequiredTests = @()
    )

    $statuses = New-Object System.Collections.Generic.List[object]
    foreach ($name in $RequiredTests) {
        $matches = @($Tests | Where-Object { $_.name -eq $name })
        $status = "missing"
        if (@($matches | Where-Object { $_.status -eq "passed" }).Count -gt 0) {
            $status = "passed"
        } elseif (@($matches | Where-Object { $_.status -eq "failed" }).Count -gt 0) {
            $status = "failed"
        } elseif (@($matches | Where-Object { $_.status -eq "ignored" }).Count -gt 0) {
            $status = "ignored"
        }
        $statuses.Add([pscustomobject]@{
                name   = $name
                status = $status
            })
    }
    return @($statuses.ToArray())
}

function New-ReleaseGateCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)]$Tests,
        [string[]]$RequiredTests = @(),
        [bool]$AdditionalGatePassed = $true,
        [AllowNull()][string]$AdditionalGateReason
    )

    $testStatuses = @(Get-RequiredTestStatuses -Tests $Tests -RequiredTests $RequiredTests)
    $missingOrFailed = @($testStatuses | Where-Object { $_.status -ne "passed" })
    $status = if ($missingOrFailed.Count -eq 0 -and $AdditionalGatePassed) { "passed" } else { "failed" }
    $reason = if ($status -eq "passed") {
        $null
    } elseif ($missingOrFailed.Count -gt 0) {
        "required_tests_not_passed"
    } else {
        $AdditionalGateReason
    }

    [pscustomobject]@{
        id             = $Id
        description    = $Description
        status         = $status
        reason         = $reason
        required_tests = $testStatuses
    }
}

function New-ReleaseGate {
    param(
        [Parameter(Mandatory = $true)][string]$Profile,
        [Parameter(Mandatory = $true)]$Tests,
        [Parameter(Mandatory = $true)]$CoverageGate,
        [Parameter(Mandatory = $true)]$SecretScan,
        [Parameter(Mandatory = $true)]$SpecSyncGate,
        [AllowNull()]$JointSmokeGate
    )

    if ($Profile -ne "release-gate") {
        return [pscustomobject]@{
            generated_at = (Get-Date).ToString("o")
            profile      = $Profile
            status       = "not_evaluated"
            checks       = @()
        }
    }

    $checks = New-Object System.Collections.Generic.List[object]
    $checks.Add((New-ReleaseGateCheck `
                -Id "profile_conformance" `
                -Description "Core fixture conformance, spec sync, and coverage-regression gate." `
                -Tests $Tests `
                -RequiredTests @(
                    "event_envelope_fixture_suite_matches_reference_semantics",
                    "capability_fixture_suite_matches_reference_semantics",
                    "state_resolution_fixture_suite_matches_reference_semantics",
                    "sync_fixture_suite_matches_reference_semantics"
                ) `
                -AdditionalGatePassed ($CoverageGate.status -ne "failed" -and $SpecSyncGate.status -eq "passed") `
                -AdditionalGateReason "coverage_or_spec_sync_failed"))
    $checks.Add((New-ReleaseGateCheck `
                -Id "privacy_boundary" `
                -Description "Privacy fixture boundary checks, including ciphertext-only forwarding and plaintext denial." `
                -Tests $Tests `
                -RequiredTests @("privacy_security_fixture_suite_matches_reference_semantics")))
    $checks.Add((New-ReleaseGateCheck `
                -Id "anti_enumeration" `
                -Description "Indistinguishable missing/private lookup behavior from the privacy fixture suite." `
                -Tests $Tests `
                -RequiredTests @("privacy_security_fixture_suite_matches_reference_semantics")))
    $checks.Add((New-ReleaseGateCheck `
                -Id "push_wakeup" `
                -Description "Blind wakeup minimization and live push rejection/privacy edges." `
                -Tests $Tests `
                -RequiredTests @(
                    "privacy_security_fixture_suite_matches_reference_semantics",
                    "push_and_moderation_edges_are_enforced"
                )))
    $checks.Add((New-ReleaseGateCheck `
                -Id "key_backup_surface" `
                -Description "Key backup CRUD stays coherent with the protocol surface." `
                -Tests $Tests `
                -RequiredTests @("events_keys_device_blob_push_and_moderation_surfaces_work")))
    $checks.Add((New-ReleaseGateCheck `
                -Id "device_session_revoke" `
                -Description "Logout revokes the bound session/device path and rejects further bearer use." `
                -Tests $Tests `
                -RequiredTests @("account_auth_and_session_edges_are_enforced")))
    $checks.Add((New-ReleaseGateCheck `
                -Id "federation_replay" `
                -Description "Federation replay, invalid semantic, and redaction contract checks." `
                -Tests $Tests `
                -RequiredTests @("federation_replay_snapshot_and_redaction_contracts_work")))
    $checks.Add((New-ReleaseGateCheck `
                -Id "session_grant_bridge" `
                -Description "coauth-style introspection backs soland session grant exchange and push registration." `
                -Tests $Tests `
                -RequiredTests @("session_grant_exchange_uses_configured_coauth_introspection")))
    $checks.Add((New-ReleaseGateCheck `
                -Id "did_resolver_starid_optional" `
                -Description "soland advertises the optional starid did:webvh resolver profile through identity discovery." `
                -Tests $Tests `
                -RequiredTests @("starid_optional_resolver_profile_is_discoverable")))
    $checks.Add((New-ReleaseGateCheck `
                -Id "secret_redaction" `
                -Description "Run logs, transcripts, and service logs do not contain unredacted secret-shaped fields." `
                -Tests $Tests `
                -RequiredTests @() `
                -AdditionalGatePassed ($SecretScan.status -eq "passed") `
                -AdditionalGateReason "secret_scan_failed"))
    $jointSmokeStatus = if ($JointSmokeGate) { $JointSmokeGate.status } else { "skipped" }
    $checks.Add((New-ReleaseGateCheck `
                -Id "joint_smoke" `
                -Description "Live soland + yougen + coauth browser smoke completes before release." `
                -Tests $Tests `
                -RequiredTests @() `
                -AdditionalGatePassed ($jointSmokeStatus -eq "passed" -or $jointSmokeStatus -eq "skipped") `
                -AdditionalGateReason "joint_smoke_failed"))

    $failedChecks = @($checks | Where-Object { $_.status -ne "passed" })
    [pscustomobject]@{
        generated_at = (Get-Date).ToString("o")
        profile      = $Profile
        status       = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
        joint_smoke  = $JointSmokeGate
        checks       = @($checks.ToArray())
    }
}

function New-ReleaseGateMarkdown {
    param([Parameter(Mandatory = $true)]$Gate)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# release gate")
    $lines.Add("")
    $lines.Add("- status: $($Gate.status)")
    $lines.Add("- profile: $($Gate.profile)")
    $lines.Add("- generated_at: $($Gate.generated_at)")
    if ($Gate.PSObject.Properties.Name -contains "joint_smoke" -and $Gate.joint_smoke) {
        $lines.Add("- joint_smoke: $($Gate.joint_smoke.status) ($($Gate.joint_smoke.summary_markdown))")
    }
    $lines.Add("")
    $lines.Add("| Check | Status | Reason | Required tests |")
    $lines.Add("| --- | --- | --- | --- |")
    foreach ($check in $Gate.checks) {
        $required = @($check.required_tests | ForEach-Object { "$($_.name):$($_.status)" })
        $requiredText = if ($required.Count -gt 0) { $required -join "<br>" } else { "-" }
        $reason = if ($check.reason) { $check.reason } else { "-" }
        $lines.Add("| $($check.id) | $($check.status) | $reason | $requiredText |")
    }
    return ($lines -join [Environment]::NewLine)
}

function New-JointSmokeGateMarkdown {
    param([Parameter(Mandatory = $true)]$Gate)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# joint smoke gate")
    $lines.Add("")
    $lines.Add("- status: $($Gate.status)")
    $lines.Add("- generated_at: $($Gate.generated_at)")
    $lines.Add("- started_at: $($Gate.started_at)")
    $lines.Add("- exit_code: $($Gate.exit_code)")
    $lines.Add("- output_root: $($Gate.output_root)")
    $lines.Add("- summary_json: $($Gate.summary_json)")
    $lines.Add("- summary_markdown: $($Gate.summary_markdown)")
    return ($lines -join [Environment]::NewLine)
}

function ConvertTo-SecretPreview {
    param([Parameter(Mandatory = $true)][string]$Line)

    $preview = $Line
    $preview = $preview -replace '(?i)((?:^|\s)authorization\s*:\s*bearer\s+)(?!\[redacted\])\S+', '$1[redacted]'
    $preview = $preview -replace '(?i)("(authorization|access_token|token|push_key|invite_token|signed_link|jws|sig|password|secret|private_key|seed)"\s*:\s*")(?!\[redacted\])([^"]+)(")', '$1[redacted]$5'
    $preview = $preview -replace '(?i)((?:^|[?&\s])(access_token|token|push_key|invite_token|signed_link|jws|sig|password|secret|private_key|seed)=)(?!\[redacted\]|%5[Bb]redacted%5[Dd])([^&\s]+)', '$1[redacted]'
    $preview = $preview -replace '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[^\-]*-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----', '[redacted-private-key]'
    if ($preview.Length -gt 220) {
        return $preview.Substring(0, 220) + "...[truncated]"
    }
    return $preview
}

function Find-SecretLeaks {
    param([Parameter(Mandatory = $true)][string[]]$ScanRoots)

    $patterns = @(
        [pscustomobject]@{ name = "authorization_header"; pattern = '(?i)(?:^|\s)authorization\s*:\s*bearer\s+(?!\[redacted\])\S+' },
        [pscustomobject]@{ name = "json_secret_field"; pattern = '(?i)"(authorization|access_token|token|push_key|invite_token|signed_link|jws|sig|password|secret|private_key|seed)"\s*:\s*"(?!\[redacted\])[^"]+"' },
        [pscustomobject]@{ name = "query_secret_field"; pattern = '(?i)(?:^|[?&\s])(access_token|token|push_key|invite_token|signed_link|jws|sig|password|secret|private_key|seed)=(?!\[redacted\]|%5[Bb]redacted%5[Dd])[^&\s]+' },
        [pscustomobject]@{ name = "did_in_token_field"; pattern = '(?i)"(token|push_key|credential)"\s*:\s*"(did:[^"]+)"' },
        [pscustomobject]@{ name = "private_key_block"; pattern = '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' }
    )
    $leaks = New-Object System.Collections.Generic.List[object]
    foreach ($root in $ScanRoots) {
        if (-not $root -or -not (Test-Path $root)) {
            continue
        }
        $files = if ((Get-Item $root).PSIsContainer) {
            Get-ChildItem -Path $root -Recurse -File
        } else {
            @(Get-Item $root)
        }
        foreach ($file in $files) {
            $lineNo = 0
            foreach ($line in Get-Content -Path $file.FullName -ErrorAction SilentlyContinue) {
                $lineNo += 1
                foreach ($pattern in $patterns) {
                    if ($line -match $pattern.pattern) {
                        $leaks.Add([pscustomobject]@{
                                path    = $file.FullName
                                line    = $lineNo
                                pattern = $pattern.name
                                preview = ConvertTo-SecretPreview -Line $line
                            })
                    }
                }
            }
        }
    }
    return $leaks
}

function New-SecretScanMarkdown {
    param([Parameter(Mandatory = $true)]$SecretScan)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# secret scan")
    $lines.Add("")
    $lines.Add("- status: $($SecretScan.status)")
    $lines.Add("- scanned_files: $($SecretScan.scanned_files)")
    $lines.Add("- leaks: $($SecretScan.leaks.Count)")
    $lines.Add("")
    if ($SecretScan.leaks.Count -eq 0) {
        $lines.Add("No unredacted secret-shaped fields were found in logs or transcripts.")
        return ($lines -join [Environment]::NewLine)
    }
    $lines.Add("| File | Line | Pattern | Preview |")
    $lines.Add("| --- | --- | --- | --- |")
    foreach ($leak in $SecretScan.leaks) {
        $preview = ($leak.preview -replace '\|', '\|')
        $lines.Add("| $($leak.path) | $($leak.line) | $($leak.pattern) | `$preview` |")
    }
    return ($lines -join [Environment]::NewLine)
}

function New-CiProfileMarkdown {
    param([Parameter(Mandatory = $true)]$ProfileReport)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# CI profile")
    $lines.Add("")
    $lines.Add("- profile: $($ProfileReport.profile_id)")
    $lines.Add("- cargo_test_filter: $($ProfileReport.cargo_test_filter)")
    $lines.Add("- invocations: $($ProfileReport.invocations.Count)")
    $lines.Add("")
    $lines.Add("| Label | Filter | Skips |")
    $lines.Add("| --- | --- | --- |")
    foreach ($invocation in $ProfileReport.invocations) {
        $skips = if ($invocation.skips.Count -gt 0) { $invocation.skips -join ", " } else { "-" }
        $filter = if ($invocation.filter) { $invocation.filter } else { "-" }
        $lines.Add("| $($invocation.label) | $filter | $skips |")
    }
    if ($ProfileReport.quarantined_tests.Count -gt 0) {
        $lines.Add("")
        $lines.Add("## Quarantined")
        $lines.Add("")
        $lines.Add("| Test filter | Labels | Reason |")
        $lines.Add("| --- | --- | --- |")
        foreach ($entry in $ProfileReport.quarantined_tests) {
            $labels = @($entry.labels) -join ", "
            $lines.Add("| $($entry.test_filter) | $labels | $($entry.reason) |")
        }
    }
    return ($lines -join [Environment]::NewLine)
}

function Get-UnresolvedTodoItems {
    param([Parameter(Mandatory = $true)][string]$TodoPath)

    $items = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $TodoPath)) {
        return @()
    }

    $currentSection = "root"
    foreach ($line in Get-Content -LiteralPath $TodoPath) {
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
    return @($items.ToArray())
}

function New-UnresolvedMarkdown {
    param([AllowNull()]$Items)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# unresolved spec gaps and pending work")
    $lines.Add("")
    if ($null -eq $Items) {
        $Items = @()
    }
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

function Get-RegistryCoverageGaps {
    param(
        [Parameter(Mandatory = $true)][string]$SpecArtifactsRoot,
        [Parameter(Mandatory = $true)][string]$CoverageProfilesPath
    )

    $gaps = New-Object System.Collections.Generic.List[object]

    # Load coverage profiles to know what tests exist
    $coverageProfiles = @{}
    if (Test-Path $CoverageProfilesPath) {
        $cpJson = Get-Content $CoverageProfilesPath -Raw | ConvertFrom-Json
        foreach ($profile in $cpJson.profiles) {
            foreach ($req in $profile.requirements) {
                foreach ($src in $req.sources) {
                    $coverageProfiles[$src] = $true
                }
            }
        }
    }

    # Event kind registry gaps
    $eventKindPath = Join-Path $SpecArtifactsRoot "registry/event-kind-registry.json"
    if (Test-Path $eventKindPath) {
        $registry = Get-Content $eventKindPath -Raw | ConvertFrom-Json
        $activeKinds = @()
        foreach ($ek in $registry.event_kinds) {
            if ($ek.status -eq "active" -and $ek.wire_scope -ne "deprecated_alias") {
                $activeKinds += $ek.event_kind
            }
        }
        # Check which event kinds are referenced in conformance tests
        $coveredKinds = @{}
        $conformanceDir = Join-Path $repoRoot "src/conformance"
        if (Test-Path $conformanceDir) {
            $sourceFiles = Get-ChildItem -Path $conformanceDir -Filter "*.rs" -Recurse
            foreach ($file in $sourceFiles) {
                $content = Get-Content $file.FullName -Raw
                foreach ($kind in $activeKinds) {
                    if ($content -match [regex]::Escape($kind)) {
                        $coveredKinds[$kind] = $true
                    }
                }
            }
        }
        $scenarioDir = Join-Path $repoRoot "src/scenarios"
        if (Test-Path $scenarioDir) {
            $sourceFiles = Get-ChildItem -Path $scenarioDir -Filter "*.rs" -Recurse
            foreach ($file in $sourceFiles) {
                $content = Get-Content $file.FullName -Raw
                foreach ($kind in $activeKinds) {
                    if ($content -match [regex]::Escape($kind)) {
                        $coveredKinds[$kind] = $true
                    }
                }
            }
        }
        foreach ($kind in $activeKinds) {
            if (-not $coveredKinds.ContainsKey($kind)) {
                $gaps.Add([pscustomobject]@{
                    category = "event_kind"
                    id       = $kind
                    status   = "uncovered"
                })
            }
        }
    }

    # Schema registry gaps
    $schemaPath = Join-Path $SpecArtifactsRoot "registry/schema-registry.json"
    if (Test-Path $schemaPath) {
        $registry = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $coveredSchemas = @{}
        $conformanceDir = Join-Path $repoRoot "src/conformance"
        if (Test-Path $conformanceDir) {
            $sourceFiles = Get-ChildItem -Path $conformanceDir -Filter "*.rs" -Recurse
            foreach ($file in $sourceFiles) {
                $content = Get-Content $file.FullName -Raw
                foreach ($schema in $registry.schemas) {
                    if ($content -match [regex]::Escape($schema.schema_id)) {
                        $coveredSchemas[$schema.schema_id] = $true
                    }
                }
            }
        }
        foreach ($schema in $registry.schemas) {
            if (-not $coveredSchemas.ContainsKey($schema.schema_id)) {
                $gaps.Add([pscustomobject]@{
                    category = "schema"
                    id       = $schema.schema_id
                    status   = "uncovered"
                })
            }
        }
    }

    # Operation registry gaps
    $operationPath = Join-Path $SpecArtifactsRoot "registry/operation-registry.json"
    if (Test-Path $operationPath) {
        $registry = Get-Content $operationPath -Raw | ConvertFrom-Json
        $coveredOps = @{}
        $sourceDirs = @(
            (Join-Path $repoRoot "src/conformance"),
            (Join-Path $repoRoot "src/scenarios"),
            (Join-Path $repoRoot "src/harness.rs")
        )
        foreach ($dir in $sourceDirs) {
            if (Test-Path $dir -PathType Leaf) {
                $content = Get-Content $dir -Raw
                foreach ($op in $registry.operations) {
                    if ($content -match [regex]::Escape($op.operation_id)) {
                        $coveredOps[$op.operation_id] = $true
                    }
                }
            } elseif (Test-Path $dir) {
                $sourceFiles = Get-ChildItem -Path $dir -Filter "*.rs" -Recurse
                foreach ($file in $sourceFiles) {
                    $content = Get-Content $file.FullName -Raw
                    foreach ($op in $registry.operations) {
                        if ($content -match [regex]::Escape($op.operation_id)) {
                            $coveredOps[$op.operation_id] = $true
                        }
                    }
                }
            }
        }
        foreach ($op in $registry.operations) {
            if (-not $coveredOps.ContainsKey($op.operation_id)) {
                $gaps.Add([pscustomobject]@{
                    category = "operation"
                    id       = $op.operation_id
                    status   = "uncovered"
                })
            }
        }
    }

    return $gaps
}

function New-RegistryGapMarkdown {
    param([Parameter(Mandatory = $true)]$Gaps)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("## Registry Coverage Gaps")
    $lines.Add("")
    if ($Gaps.Count -eq 0) {
        $lines.Add("All registered items are referenced in at least one test or scenario.")
        $lines.Add("")
        return ($lines -join [Environment]::NewLine)
    }

    $grouped = $Gaps | Group-Object category
    foreach ($group in $grouped) {
        $lines.Add("### Uncovered $($group.Name)s ($($group.Count))")
        $lines.Add("")
        foreach ($item in $group.Group) {
            $lines.Add("- ``$($item.id)``")
        }
        $lines.Add("")
    }
    return ($lines -join [Environment]::NewLine)
}

function Test-SpecArtifactSync {
    param(
        [Parameter(Mandatory = $true)][string]$SpecRoot,
        [string]$PythonExe = "python"
    )

    $pipelineScript = Join-Path (Join-Path $SpecRoot "tools") "artifact_pipeline.py"
    if (-not (Test-Path $pipelineScript)) {
        return [pscustomobject]@{
            status = "skipped"
            reason = "artifact_pipeline.py not found"
            errors = @()
        }
    }

    $output = & $PythonExe $pipelineScript check 2>&1
    $exitCode = $LASTEXITCODE
    $errors = @($output | Where-Object { $_ -match "^(ERROR|FAIL|DRIFT)" })

    [pscustomobject]@{
        status   = if ($exitCode -eq 0) { "passed" } else { "failed" }
        exit_code = $exitCode
        errors   = $errors
        output   = @($output)
    }
}

function Get-SutDescribeAlignment {
    param(
        [Parameter(Mandatory = $true)][string]$SpecArtifactsRoot,
        [string]$SutBaseUrl
    )

    if (-not $SutBaseUrl) {
        return [pscustomobject]@{
            status = "skipped"
            reason = "no SUT base URL"
            drifts = @()
        }
    }

    $drifts = New-Object System.Collections.Generic.List[object]

    # Check server describe endpoint
    $serverDescribe = $null
    try {
        $response = Invoke-RestMethod -Uri "$SutBaseUrl/server/describe" -Method Get -TimeoutSec 10 -ErrorAction Stop
        $serverDescribe = $response
    } catch {
        $drifts.Add([pscustomobject]@{
            endpoint = "/server/describe"
            issue    = "unreachable"
            detail   = $_.Exception.Message
        })
    }

    # Check integration describe endpoint
    $integrationDescribe = $null
    try {
        $response = Invoke-RestMethod -Uri "$SutBaseUrl/integration/describe" -Method Get -TimeoutSec 10 -ErrorAction Stop
        $integrationDescribe = $response
    } catch {
        $drifts.Add([pscustomobject]@{
            endpoint = "/integration/describe"
            issue    = "unreachable"
            detail   = $_.Exception.Message
        })
    }

    # Validate against spec registries if endpoints responded
    if ($serverDescribe) {
        $eventKindsPath = Join-Path $SpecArtifactsRoot "registry" "event-kind-registry.json"
        if (Test-Path $eventKindsPath) {
            $specRegistry = Get-Content $eventKindsPath -Raw | ConvertFrom-Json
            $specKinds = @($specRegistry.event_kinds | ForEach-Object { $_.kind })
            $sutKinds = @()
            if ($serverDescribe.supported_event_kinds) {
                $sutKinds = @($serverDescribe.supported_event_kinds)
            }
            $missing = @($specKinds | Where-Object { $_ -notin $sutKinds })
            if ($missing.Count -gt 0) {
                $drifts.Add([pscustomobject]@{
                    endpoint = "/server/describe"
                    issue    = "missing_event_kinds"
                    detail   = "$($missing.Count) spec event kinds not in SUT: $($missing[0..4] -join ', ')..."
                })
            }
        }
    }

    [pscustomobject]@{
        status             = if ($drifts.Count -eq 0) { "aligned" } else { "drift_detected" }
        server_describe    = $serverDescribe -ne $null
        integration_describe = $integrationDescribe -ne $null
        drifts             = @($drifts)
    }
}

function New-SpecSyncGateMarkdown {
    param(
        [Parameter(Mandatory = $true)]$ArtifactSync,
        [Parameter(Mandatory = $true)]$DescribeAlignment
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("## Spec Artifact Sync Gate")
    $lines.Add("")

    # Artifact pipeline check
    $lines.Add("### Artifact Pipeline")
    $lines.Add("")
    $lines.Add("- status: $($ArtifactSync.status)")
    if (($ArtifactSync.PSObject.Properties.Name -contains "reason") -and $ArtifactSync.reason) {
        $lines.Add("- reason: $($ArtifactSync.reason)")
    }
    if ($ArtifactSync.errors.Count -gt 0) {
        $lines.Add("")
        $lines.Add("**Errors:**")
        foreach ($err in $ArtifactSync.errors) {
            $lines.Add("- $err")
        }
    }
    $lines.Add("")

    # SUT describe alignment
    $lines.Add("### SUT Describe Alignment")
    $lines.Add("")
    $lines.Add("- status: $($DescribeAlignment.status)")
    $lines.Add("- server_describe: $($DescribeAlignment.server_describe)")
    $lines.Add("- integration_describe: $($DescribeAlignment.integration_describe)")
    if ($DescribeAlignment.drifts.Count -gt 0) {
        $lines.Add("")
        $lines.Add("| Endpoint | Issue | Detail |")
        $lines.Add("| --- | --- | --- |")
        foreach ($drift in $DescribeAlignment.drifts) {
            $detail = ($drift.detail -replace '\|', '\|')
            if ($detail.Length -gt 120) {
                $detail = $detail.Substring(0, 120) + "..."
            }
            $lines.Add("| $($drift.endpoint) | $($drift.issue) | $detail |")
        }
    }
    $lines.Add("")

    return ($lines -join [Environment]::NewLine)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $SutManifest) {
    $SutManifest = Join-Path ((Resolve-Path (Join-Path $repoRoot "..")).Path) "soland\Cargo.toml"
}
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
$coverageGateJson = Join-Path $runDir "coverage-gate.json"
$coverageGateMd = Join-Path $runDir "coverage-gate.md"
$jointSmokeGateJson = Join-Path $runDir "joint-smoke-gate.json"
$jointSmokeGateMd = Join-Path $runDir "joint-smoke-gate.md"
$releaseGateJson = Join-Path $runDir "release-gate.json"
$releaseGateMd = Join-Path $runDir "release-gate.md"
$gapsJson = Join-Path $runDir "unresolved-gaps.json"
$gapsMd = Join-Path $runDir "unresolved-gaps.md"
$ciProfileJson = Join-Path $runDir "ci-profile.json"
$ciProfileMd = Join-Path $runDir "ci-profile.md"
$secretScanJson = Join-Path $runDir "secret-scan.json"
$secretScanMd = Join-Path $runDir "secret-scan.md"
$transcriptNdjson = Join-Path $runDir "transcript.ndjson"
"" | Set-Content -Path $transcriptNdjson -Encoding UTF8
"" | Set-Content -Path $rawLog -Encoding UTF8

if ($Profile -eq "joint") {
    $jointRun = Invoke-JointSmokeGate `
        -RepoRoot $repoRoot `
        -RunDir $runDir `
        -RawLog $rawLog `
        -OutputName "joint" `
        -RunProfile "joint-smoke" `
        -PlaywrightProject "joint-yougen" `
        -StartCoauth $true `
        -SolandRuntime $Runtime `
        -SolandImage $SutImage `
        -BuildSolandImage ([bool]$BuildImage) `
        -DockerCacheFrom $DockerCacheFrom `
        -DockerCacheTo $DockerCacheTo `
        -DockerPull ([bool]$DockerPull) `
        -DockerNoCache ([bool]$DockerNoCache)

    $summary = [pscustomobject]@{
        generated_at           = (Get-Date).ToString("o")
        profile                = $Profile
        status                 = $jointRun.status
        exit_code              = $jointRun.exit_code
        joint_summary_json     = $jointRun.summary_json
        joint_summary_markdown = $jointRun.summary_markdown
        output_root            = $jointRun.output_root
        raw_log                = $rawLog
    }
    $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryJson -Encoding UTF8
    @(
        "# cotest joint profile",
        "",
        "- status: $($summary.status)",
        "- exit_code: $($summary.exit_code)",
        "- joint_summary_json: $($summary.joint_summary_json)",
        "- joint_summary_markdown: $($summary.joint_summary_markdown)",
        "- output_root: $($summary.output_root)",
        "- raw_log: $($summary.raw_log)"
    ) | Set-Content -Path $summaryMd -Encoding UTF8

    Write-Host ""
    Write-Host "Cotest joint profile complete:"
    Write-Host "  status   : $($summary.status)"
    Write-Host "  summary  : $summaryMd"
    Write-Host "  joint    : $($summary.joint_summary_markdown)"
    exit ([int]$jointRun.exit_code)
}

if ($Profile -eq "dual-soland") {
    $dualRun = Invoke-JointSmokeGate `
        -RepoRoot $repoRoot `
        -RunDir $runDir `
        -RawLog $rawLog `
        -OutputName "dual-soland" `
        -RunProfile "joint-full" `
        -PlaywrightProject "chromium" `
        -StartCoauth $true `
        -DualSoland $true `
        -StartMocks $false `
        -Grep "cross-server.federation" `
        -SolandRuntime $Runtime `
        -SolandImage $SutImage `
        -BuildSolandImage ([bool]$BuildImage) `
        -DockerCacheFrom $DockerCacheFrom `
        -DockerCacheTo $DockerCacheTo `
        -DockerPull ([bool]$DockerPull) `
        -DockerNoCache ([bool]$DockerNoCache)

    $summary = [pscustomobject]@{
        generated_at           = (Get-Date).ToString("o")
        profile                = $Profile
        status                 = $dualRun.status
        exit_code              = $dualRun.exit_code
        joint_summary_json     = $dualRun.summary_json
        joint_summary_markdown = $dualRun.summary_markdown
        output_root            = $dualRun.output_root
        raw_log                = $rawLog
    }
    $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryJson -Encoding UTF8
    @(
        "# cotest dual-soland profile",
        "",
        "- status: $($summary.status)",
        "- exit_code: $($summary.exit_code)",
        "- joint_summary_json: $($summary.joint_summary_json)",
        "- joint_summary_markdown: $($summary.joint_summary_markdown)",
        "- output_root: $($summary.output_root)",
        "- raw_log: $($summary.raw_log)"
    ) | Set-Content -Path $summaryMd -Encoding UTF8

    Write-Host ""
    Write-Host "Cotest dual-soland profile complete:"
    Write-Host "  status   : $($summary.status)"
    Write-Host "  summary  : $summaryMd"
    Write-Host "  joint    : $($summary.joint_summary_markdown)"
    exit ([int]$dualRun.exit_code)
}

if ($Runtime -eq "docker" -and ($BuildImage -or -not (Test-DockerImagePresent -ImageTag $SutImage))) {
    $buildArgs = @("-ImageTag", $SutImage)
    if ($DockerCacheFrom.Count -gt 0) {
        $buildArgs += "-CacheFrom"
        $buildArgs += $DockerCacheFrom
    }
    if ($DockerCacheTo) {
        $buildArgs += @("-CacheTo", $DockerCacheTo)
    }
    if ($DockerPull) {
        $buildArgs += "-Pull"
    }
    if ($DockerNoCache) {
        $buildArgs += "-NoCache"
    }
    & (Join-Path $PSScriptRoot "build-soland-image.ps1") @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build Docker image $SutImage"
    }
}

$originalEnv = @()
foreach ($name in "COTEST_SUT_MODE", "COTEST_SUT_MANIFEST", "COTEST_SUT_IMAGE", "COTEST_ARTIFACT_DIR", "COTEST_SERVICE_LOG_DIR", "COTEST_TRANSCRIPT_PATH") {
    $originalEnv += [pscustomobject]@{
        Name   = $name
        Exists = Test-Path "Env:$name"
        Value  = [Environment]::GetEnvironmentVariable($name)
    }
}

$startedAt = Get-Date
$ciConfig = Get-CiProfileConfig -RepoRoot $repoRoot
$ciProfile = Get-CiProfile -Config $ciConfig -ProfileId $Profile
$quarantineEntries = @(Get-ActiveQuarantineEntries -Config $ciConfig -ExcludedLabels @($ciProfile.excluded_quarantine_labels))
$invocations = @(Get-CargoTestInvocations -Profile $ciProfile -QuarantineEntries $quarantineEntries -CargoTestFilter $CargoTestFilter)
$effectiveRequiredCoverageProfiles = @(Get-EffectiveRequiredCoverageProfiles -Profile $ciProfile -Overrides $RequiredCoverageProfiles)
$profileReport = [pscustomobject]@{
    profile_id                 = $Profile
    cargo_test_filter          = if ($CargoTestFilter) { $CargoTestFilter } else { $null }
    required_coverage_profiles = $effectiveRequiredCoverageProfiles
    invocations                = $invocations
    quarantined_tests          = $quarantineEntries
}
$exitCode = 1

try {
    $env:COTEST_SUT_MODE = $Runtime
    $env:COTEST_ARTIFACT_DIR = $runDir
    $env:COTEST_SERVICE_LOG_DIR = $serviceLogDir
    $env:COTEST_TRANSCRIPT_PATH = $transcriptNdjson
    if ($Runtime -eq "docker") {
        Remove-Item Env:COTEST_SUT_MANIFEST -ErrorAction SilentlyContinue
        $env:COTEST_SUT_IMAGE = $SutImage
    } else {
        $env:COTEST_SUT_MANIFEST = $SutManifest
        Remove-Item Env:COTEST_SUT_IMAGE -ErrorAction SilentlyContinue
    }

    $exitCode = 0
    # Profiles whose scenarios are all `#[ignore]` by design (opt-in
    # long-running runs). Promoting `--ignored` here keeps the per-test
    # `#[ignore = "..."]` reason text intact while still letting the
    # profile actually execute the scenarios.
    $promoteIgnored = ($Profile -eq "soak")
    foreach ($invocation in $invocations) {
        $cargoArgs = New-CargoTestArgs -Filter $invocation.filter -Skips @($invocation.skips) -IncludeIgnored:$promoteIgnored
        $invocationExitCode = Invoke-CargoTestInvocation -CargoArgs $cargoArgs -RawLog $rawLog -Label $invocation.label
        if ($invocationExitCode -ne 0 -and $exitCode -eq 0) {
            $exitCode = $invocationExitCode
        }
    }
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
$e2eCoverage = [pscustomobject]@{
    status          = "not_collected"
    promised_count  = $null
    verified_count  = $null
    verified_ratio  = $null
}
$resolvedCoverageBaseline = $CoverageBaselinePath
if (-not $resolvedCoverageBaseline) {
    $candidateBaseline = Join-Path $repoRoot "artifacts\latest\coverage-matrix.json"
    if (Test-Path $candidateBaseline) {
        $resolvedCoverageBaseline = $candidateBaseline
    }
}
$coverageGate = Compare-CoverageToBaseline -CurrentCoverage $coverage -BaselinePath $resolvedCoverageBaseline -RequiredProfiles $effectiveRequiredCoverageProfiles -E2eCoverage $e2eCoverage -CoverageMode $CoverageMode
if ($FailOnCoverageRegression -and $coverageGate.status -eq "failed") {
    $exitCode = 1
}
$unresolved = Get-UnresolvedTodoItems -TodoPath (Join-Path $repoRoot "_todos.md")
$specArtifactsRoot = Join-Path $repoRoot ".." | Join-Path -ChildPath "cokret-spec" | Join-Path -ChildPath "spec\v1\artifacts"
if (-not (Test-Path $specArtifactsRoot)) {
    $specArtifactsRoot = $null
}
$registryGaps = @()
if ($specArtifactsRoot -and (Test-Path (Join-Path $repoRoot "config/coverage-profiles.json"))) {
    $registryGaps = @(Get-RegistryCoverageGaps -SpecArtifactsRoot $specArtifactsRoot -CoverageProfilesPath (Join-Path $repoRoot "config/coverage-profiles.json"))
}

# Spec artifact sync gate
$specRoot = Join-Path $repoRoot ".." | Join-Path -ChildPath "cokret-spec"
$specSyncResult = Test-SpecArtifactSync -SpecRoot $specRoot
$sutDescribeAlignment = [pscustomobject]@{
    status               = "skipped"
    reason               = "no SUT base URL configured"
    server_describe      = $false
    integration_describe = $false
    drifts               = @()
}
# SUT describe alignment only when running against a live SUT with base URL
if ($env:COTEST_SUT_BASE_URL) {
    $sutDescribeAlignment = Get-SutDescribeAlignment -SpecArtifactsRoot $specArtifactsRoot -SutBaseUrl $env:COTEST_SUT_BASE_URL
}
$specSyncGate = [pscustomobject]@{
    generated_at       = $finishedAt.ToString("o")
    artifact_pipeline  = $specSyncResult
    sut_describe       = $sutDescribeAlignment
    status             = if ($specSyncResult.status -eq "failed" -or $sutDescribeAlignment.status -eq "drift_detected") { "failed" } else { "passed" }
}
if ($specSyncGate.status -eq "failed") {
    $exitCode = 1
}

$sutMetadata = Get-SutMetadata -Runtime $Runtime -SutManifest $SutManifest -SutImage $SutImage
$specMetadata = Get-SpecMetadata -RepoRoot $repoRoot
$metadata = [pscustomobject]@{
    generated_at = $finishedAt.ToString("o")
    sut          = $sutMetadata
    spec         = $specMetadata
    sync_gate    = $specSyncGate
}
$jointSmokeGate = [pscustomobject]@{
    generated_at     = (Get-Date).ToString("o")
    started_at       = $null
    status           = "skipped"
    exit_code        = $null
    output_root      = $null
    summary_json     = $null
    summary_markdown = $null
}
if ($Profile -eq "release-gate" -and -not $SkipJointSmokeGate) {
    $jointSmokeGate = Invoke-JointSmokeGate `
        -RepoRoot $repoRoot `
        -RunDir $runDir `
        -RawLog $rawLog `
        -SolandRuntime $Runtime `
        -SolandImage $SutImage `
        -BuildSolandImage $false `
        -DockerCacheFrom $DockerCacheFrom `
        -DockerCacheTo $DockerCacheTo `
        -DockerPull ([bool]$DockerPull) `
        -DockerNoCache ([bool]$DockerNoCache)
    if ($jointSmokeGate.status -eq "failed") {
        $exitCode = 1
    }
}
$scanRoots = @($rawLog, $transcriptNdjson, $serviceLogDir)
$scanFiles = 0
foreach ($root in $scanRoots) {
    if (-not $root -or -not (Test-Path $root)) {
        continue
    }
    if ((Get-Item $root).PSIsContainer) {
        $scanFiles += @(Get-ChildItem -Path $root -Recurse -File).Count
    } else {
        $scanFiles += 1
    }
}
$secretLeaks = @(Find-SecretLeaks -ScanRoots $scanRoots)
$secretScan = [pscustomobject]@{
    generated_at  = $finishedAt.ToString("o")
    status        = if ($secretLeaks.Count -eq 0) { "passed" } else { "failed" }
    scanned_roots = $scanRoots
    scanned_files = $scanFiles
    leaks         = $secretLeaks
}
if (-not $AllowSecretLeaks -and $secretScan.status -eq "failed") {
    $exitCode = 1
}
$releaseGate = New-ReleaseGate `
    -Profile $Profile `
    -Tests $tests `
    -CoverageGate $coverageGate `
    -SecretScan $secretScan `
    -SpecSyncGate $specSyncGate `
    -JointSmokeGate $jointSmokeGate
if ($Profile -eq "release-gate" -and $releaseGate.status -eq "failed") {
    $exitCode = 1
}

$summary = [pscustomobject]@{
    status               = if ($exitCode -eq 0) { "success" } else { "failure" }
    profile              = $Profile
    runtime              = $Runtime
    sut                  = if ($Runtime -eq "docker") { "image:$SutImage" } else { "manifest:$SutManifest" }
    coverage_mode        = $CoverageMode
    e2e_coverage_status  = $e2eCoverage.status
    e2e_coverage_promised_count = $e2eCoverage.promised_count
    e2e_coverage_verified_count = $e2eCoverage.verified_count
    e2e_coverage_verified_ratio = $e2eCoverage.verified_ratio
    started_at           = $startedAt.ToString("o")
    finished_at          = $finishedAt.ToString("o")
    duration_seconds     = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 2)
    exit_code            = $exitCode
    passed               = $passed
    failed               = $failed
    ignored              = $ignored
    raw_log              = $rawLog
    transcript_path      = $transcriptNdjson
    junit_xml            = $junitXml
    html_report          = $summaryHtml
    metadata_path        = $metadataJson
    coverage_matrix_path = $coverageJson
    coverage_gate_path   = $coverageGateJson
    coverage_gate_status = $coverageGate.status
    coverage_gate_verified_only_pass = $coverageGate.verified_only_pass
    joint_smoke_gate_path = $jointSmokeGateJson
    joint_smoke_status    = $jointSmokeGate.status
    release_gate_path    = $releaseGateJson
    release_gate_status  = $releaseGate.status
    unresolved_gaps_path = $gapsJson
    ci_profile_path      = $ciProfileJson
    secret_scan_path     = $secretScanJson
    secret_scan_status   = $secretScan.status
    service_log_dir      = $serviceLogDir
    tests                = $tests
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryJson -Encoding UTF8
$metadata | ConvertTo-Json -Depth 8 | Set-Content -Path $metadataJson -Encoding UTF8
$coverage | ConvertTo-Json -Depth 8 | Set-Content -Path $coverageJson -Encoding UTF8
$coverageGate | ConvertTo-Json -Depth 8 | Set-Content -Path $coverageGateJson -Encoding UTF8
$jointSmokeGate | ConvertTo-Json -Depth 8 | Set-Content -Path $jointSmokeGateJson -Encoding UTF8
$releaseGate | ConvertTo-Json -Depth 8 | Set-Content -Path $releaseGateJson -Encoding UTF8
ConvertTo-Json -InputObject @($unresolved) -Depth 6 | Set-Content -Path $gapsJson -Encoding UTF8
ConvertTo-Json -InputObject @($registryGaps) -Depth 6 | Set-Content -Path (Join-Path $runDir "registry-gaps.json") -Encoding UTF8
$profileReport | ConvertTo-Json -Depth 8 | Set-Content -Path $ciProfileJson -Encoding UTF8
$secretScan | ConvertTo-Json -Depth 8 | Set-Content -Path $secretScanJson -Encoding UTF8

$specSyncGateJson = Join-Path $runDir "spec-sync-gate.json"
$specSyncGateMd = Join-Path $runDir "spec-sync-gate.md"
$specSyncGate | ConvertTo-Json -Depth 8 | Set-Content -Path $specSyncGateJson -Encoding UTF8
$specSyncGateMarkdown = New-SpecSyncGateMarkdown -ArtifactSync $specSyncResult -DescribeAlignment $sutDescribeAlignment
$specSyncGateMarkdown | Set-Content -Path $specSyncGateMd -Encoding UTF8

$markdown = New-SummaryMarkdown -Summary $summary -Tests $tests
$markdown | Set-Content -Path $summaryMd -Encoding UTF8

$html = New-SummaryHtml -Summary $summary -Tests $tests
$html | Set-Content -Path $summaryHtml -Encoding UTF8

$xml = New-JUnitXml -Summary $summary -Tests $tests
$xml | Set-Content -Path $junitXml -Encoding UTF8

$coverageMarkdown = New-CoverageMarkdown -Coverage $coverage
$coverageMarkdown | Set-Content -Path $coverageMd -Encoding UTF8

$coverageGateMarkdown = New-CoverageGateMarkdown -Gate $coverageGate
$coverageGateMarkdown | Set-Content -Path $coverageGateMd -Encoding UTF8

$jointSmokeGateMarkdown = New-JointSmokeGateMarkdown -Gate $jointSmokeGate
$jointSmokeGateMarkdown | Set-Content -Path $jointSmokeGateMd -Encoding UTF8

$releaseGateMarkdown = New-ReleaseGateMarkdown -Gate $releaseGate
$releaseGateMarkdown | Set-Content -Path $releaseGateMd -Encoding UTF8

$gapsMarkdown = New-UnresolvedMarkdown -Items $unresolved
if ($registryGaps.Count -gt 0) {
    $registryGapMarkdown = New-RegistryGapMarkdown -Gaps $registryGaps
    $gapsMarkdown = $gapsMarkdown + [Environment]::NewLine + $registryGapMarkdown
}
$gapsMarkdown | Set-Content -Path $gapsMd -Encoding UTF8

$ciProfileMarkdown = New-CiProfileMarkdown -ProfileReport $profileReport
$ciProfileMarkdown | Set-Content -Path $ciProfileMd -Encoding UTF8

$secretScanMarkdown = New-SecretScanMarkdown -SecretScan $secretScan
$secretScanMarkdown | Set-Content -Path $secretScanMd -Encoding UTF8

$artifactFiles = @(
    $rawLog,
    $transcriptNdjson,
    $summaryJson,
    $summaryMd,
    $summaryHtml,
    $junitXml,
    $metadataJson,
    $coverageJson,
    $coverageMd,
    $coverageGateJson,
    $coverageGateMd,
    $jointSmokeGateJson,
    $jointSmokeGateMd,
    $releaseGateJson,
    $releaseGateMd,
    $gapsJson,
    $gapsMd,
    (Join-Path $runDir "registry-gaps.json"),
    $ciProfileJson,
    $ciProfileMd,
    $secretScanJson,
    $secretScanMd,
    $specSyncGateJson,
    $specSyncGateMd
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
Write-Host "  profile  : $($summary.profile)"
Write-Host "  runtime  : $($summary.runtime)"
Write-Host "  sut      : $($summary.sut)"
Write-Host "  passed   : $($summary.passed)"
Write-Host "  failed   : $($summary.failed)"
Write-Host "  ignored  : $($summary.ignored)"
Write-Host "  log      : $rawLog"
Write-Host "  transcript : $transcriptNdjson"
Write-Host "  report   : $summaryMd"
Write-Host "  junit    : $junitXml"
Write-Host "  html     : $summaryHtml"
Write-Host "  coverage : $coverageMd"
Write-Host "  gate     : $coverageGateMd"
Write-Host "  joint    : $jointSmokeGateMd"
Write-Host "  release  : $releaseGateMd"
Write-Host "  gaps     : $gapsMd"
Write-Host "  ci       : $ciProfileMd"
Write-Host "  secrets  : $secretScanMd"
Write-Host "  sync     : $specSyncGateMd"
Write-Host "  services : $serviceLogDir"

exit $exitCode

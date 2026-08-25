[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$runner = Join-Path $PSScriptRoot "run-server-conformance.ps1"
$pwsh = (Get-Process -Id $PID).Path

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message (expected '$Expected', got '$Actual')"
    }
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-Planner {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $pwsh -NoProfile -File $runner @Arguments -WarningAction SilentlyContinue 2>&1)
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Planner failed for arguments '$($Arguments -join ' ')':`n$($output -join [Environment]::NewLine)"
    }
    return (($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine) | ConvertFrom-Json
}

function Invoke-ExpectedPlannerFailure {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $pwsh -NoProfile -File $runner @Arguments -WarningAction SilentlyContinue 2>&1)
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -eq 0) {
        throw "Planner unexpectedly succeeded for arguments '$($Arguments -join ' ')'"
    }
    $text = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    if ($text.IndexOf($ExpectedMessage, [System.StringComparison]::Ordinal) -lt 0) {
        throw "Planner failure did not contain '$ExpectedMessage':`n$text"
    }
}

$fast = Invoke-Planner -Arguments @("-Profile", "fast-smoke", "-PlanOnly")
Assert-True -Condition ($fast.known_target_count -gt 0) -Message "Cargo metadata returned no integration-test targets"
Assert-Equal -Actual $fast.invocations.Count -Expected 7 -Message "fast-smoke invocation count drifted"
foreach ($invocation in $fast.invocations) {
    Assert-Equal -Actual $invocation.selection_mode -Expected "target-filter" -Message "fast-smoke must be target aware"
    Assert-True -Condition ($invocation.cargo_args -contains "--test") -Message "fast-smoke invocation is missing --test"
    Assert-True -Condition ($invocation.cargo_args -notcontains "--tests") -Message "fast-smoke invocation must not use --tests"
    Assert-True -Condition ($invocation.cargo_args -contains "--exact") -Message "fast-smoke invocation must use exact libtest matching"
}

$release = Invoke-Planner -Arguments @("-Profile", "release-gate", "-PlanOnly")
Assert-Equal -Actual $release.invocations.Count -Expected 30 -Message "release-gate invocation count drifted"
Assert-Equal -Actual @($release.invocations | Select-Object -ExpandProperty target -Unique).Count -Expected 12 -Message "release-gate target count drifted"

$all = Invoke-Planner -Arguments @("-Profile", "all", "-PlanOnly")
Assert-Equal -Actual $all.invocations.Count -Expected 1 -Message "all profile must have one invocation"
Assert-Equal -Actual $all.invocations[0].selection_mode -Expected "all-tests" -Message "all profile mode drifted"
Assert-True -Condition ($all.invocations[0].cargo_args -contains "--tests") -Message "all profile must use --tests"

$targetFilter = Invoke-Planner -Arguments @(
    "-Profile", "all",
    "-CargoTestTarget", "api_contracts_auth",
    "-CargoTestFilter", "account_auth_and_session_edges_are_enforced",
    "-PlanOnly"
)
Assert-Equal -Actual $targetFilter.invocations[0].selection_mode -Expected "target-filter" -Message "manual target/filter mode drifted"

$targetAll = Invoke-Planner -Arguments @("-Profile", "all", "-CargoTestTarget", "api_contracts_auth", "-PlanOnly")
Assert-Equal -Actual $targetAll.invocations[0].selection_mode -Expected "target-all" -Message "manual target-only mode drifted"

$broadScan = Invoke-Planner -Arguments @("-Profile", "all", "-CargoTestFilter", "account_auth_and_session_edges_are_enforced", "-PlanOnly")
Assert-Equal -Actual $broadScan.invocations[0].selection_mode -Expected "broad-scan" -Message "filter-only selection mode drifted"
Assert-True -Condition ($broadScan.invocations[0].cargo_args -contains "--tests") -Message "filter-only mode must remain an explicit broad scan"

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "cotest-planner-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $tempRoot
try {
    $duplicateConfig = Join-Path $tempRoot "duplicate.json"
    @{
        profiles = @(
            @{
                profile_id = "fast-smoke"
                include_all_tests = $false
                cargo_tests = @(
                    @{ target = "service_surface"; filter = "server_exposes_core_service_surface" },
                    @{ target = "service_surface"; filter = "server_exposes_core_service_surface" }
                )
                excluded_quarantine_labels = @()
                required_coverage_profiles = @()
            }
        )
        quarantined_tests = @()
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $duplicateConfig -Encoding UTF8
    Invoke-ExpectedPlannerFailure `
        -Arguments @("-Profile", "fast-smoke", "-ProfileConfigPath", $duplicateConfig, "-PlanOnly") `
        -ExpectedMessage "contains duplicate cargo test selection"

    $emptyConfig = Join-Path $tempRoot "empty.json"
    @{
        profiles = @(
            @{
                profile_id = "fast-smoke"
                include_all_tests = $false
                cargo_tests = @()
                excluded_quarantine_labels = @()
                required_coverage_profiles = @()
            }
        )
        quarantined_tests = @()
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $emptyConfig -Encoding UTF8
    Invoke-ExpectedPlannerFailure `
        -Arguments @("-Profile", "fast-smoke", "-ProfileConfigPath", $emptyConfig, "-PlanOnly") `
        -ExpectedMessage "must declare at least one cargo_tests entry"

    $unknownTargetConfig = Join-Path $tempRoot "unknown-target.json"
    @{
        profiles = @(
            @{
                profile_id = "fast-smoke"
                include_all_tests = $false
                cargo_tests = @(
                    @{ target = "missing_target"; filter = "missing_test" }
                )
                excluded_quarantine_labels = @()
                required_coverage_profiles = @()
            }
        )
        quarantined_tests = @()
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $unknownTargetConfig -Encoding UTF8
    Invoke-ExpectedPlannerFailure `
        -Arguments @("-Profile", "fast-smoke", "-ProfileConfigPath", $unknownTargetConfig, "-PlanOnly") `
        -ExpectedMessage "references unknown cargo test target"

    $quarantineConfig = Join-Path $tempRoot "quarantine.json"
    @{
        profiles = @(
            @{
                profile_id = "fast-smoke"
                include_all_tests = $false
                cargo_tests = @(
                    @{ target = "service_surface"; filter = "server_exposes_core_service_surface" },
                    @{ target = "api_contracts_auth"; filter = "account_auth_and_session_edges_are_enforced"; include_ignored = $true }
                )
                excluded_quarantine_labels = @("flaky")
                required_coverage_profiles = @()
            }
        )
        quarantined_tests = @(
            @{
                test_target = "service_surface"
                test_filter = "server_exposes_core_service_surface"
                labels = @("flaky")
                reason = "planner regression fixture"
            }
        )
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $quarantineConfig -Encoding UTF8
    $quarantine = Invoke-Planner -Arguments @(
        "-Profile", "fast-smoke",
        "-ProfileConfigPath", $quarantineConfig,
        "-PlanOnly"
    )
    Assert-Equal -Actual $quarantine.invocations.Count -Expected 1 -Message "quarantine must remove only its exact target/filter selection"
    Assert-Equal -Actual $quarantine.invocations[0].target -Expected "api_contracts_auth" -Message "quarantine removed the wrong target"
    Assert-True -Condition ($quarantine.invocations[0].cargo_args -contains "--ignored") -Message "include_ignored must reach libtest arguments"
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}

Write-Host "Cotest planner regression tests passed."

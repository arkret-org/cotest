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

    # Catch inside the child so assertions receive the complete exception
    # message, not PowerShell's width-dependent decorated error display.
    $invocationJson = [pscustomobject]@{ runner = $runner; arguments = $Arguments } | ConvertTo-Json -Compress
    $invocationPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($invocationJson))
    $rawFailureCommand = @'
$ErrorActionPreference = "Stop"
$invocation = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("__INVOCATION__")) | ConvertFrom-Json
try {
    $scriptArguments = @($invocation.arguments)
    $namedArguments = @{}
    $switchParameters = @("PlanOnly", "ValidateProfile", "FailOnCoverageRegression", "AllowSecretLeaks", "BuildImage", "DockerPull", "DockerNoCache", "SkipJointSmokeGate")
    for ($index = 0; $index -lt $scriptArguments.Count; $index++) {
        $argument = [string]$scriptArguments[$index]
        if (-not $argument.StartsWith("-")) { throw "Planner fixture expected a named parameter, got '$argument'" }
        $name = $argument.Substring(1)
        if ($namedArguments.ContainsKey($name)) { throw "Planner fixture repeats parameter '$name'" }
        if ($switchParameters -contains $name) { $namedArguments[$name] = $true; continue }
        $index++
        if ($index -ge $scriptArguments.Count) { throw "Planner fixture lacks a value for '$name'" }
        $namedArguments[$name] = $scriptArguments[$index]
    }
    & $invocation.runner @namedArguments -WarningAction SilentlyContinue
}
catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
'@
    $rawFailureCommand = $rawFailureCommand.Replace("__INVOCATION__", $invocationPayload)
    $encodedFailureCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($rawFailureCommand))
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $pwsh -NoProfile -EncodedCommand $encodedFailureCommand 2>&1)
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -eq 0) {
        throw "Planner unexpectedly succeeded for arguments '$($Arguments -join ' ')'"
    }
    $text = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    # Preserve complete expected words; whitespace is presentation-only.
    $normalizedText = [regex]::Replace($text, "\s+", " ")
    $normalizedExpected = [regex]::Replace($ExpectedMessage, "\s+", " ")
    if ($normalizedText.IndexOf($normalizedExpected, [System.StringComparison]::Ordinal) -lt 0) {
        throw "Planner failure did not contain '$ExpectedMessage':`n$text"
    }
}

# Exercise the actual runner function in a separate process. Discovery does
# not run cargo; it proves normalization preserves a runnable child PATH.
$tokens = $null
$parseErrors = $null
$runnerAst = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$parseErrors)
Assert-Equal -Actual $parseErrors.Count -Expected 0 -Message "runner PowerShell syntax is invalid"
$repairFunction = $runnerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Repair-ProcessPathEnvironment"
}, $true)
Assert-True -Condition ($null -ne $repairFunction) -Message "runner PATH repair function is missing"
$childProbe = $repairFunction.Extent.Text + @'

$ErrorActionPreference = "Stop"
$before = [Environment]::GetEnvironmentVariable("PATH", "Process")
Repair-ProcessPathEnvironment
$cargo = Get-Command cargo -CommandType Application -ErrorAction Stop
[pscustomobject]@{ cargo_visible = [bool]$cargo.Source; unix_path_preserved = $IsWindows -or ($before -ceq [Environment]::GetEnvironmentVariable("PATH", "Process")) } | ConvertTo-Json -Compress
'@
$encodedProbe = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childProbe))
$probeOutput = @(& $pwsh -NoProfile -EncodedCommand $encodedProbe)
Assert-Equal -Actual $LASTEXITCODE -Expected 0 -Message "PATH normalization hid cargo from the child process"
$pathProbe = ($probeOutput -join [Environment]::NewLine) | ConvertFrom-Json
Assert-True -Condition $pathProbe.cargo_visible -Message "cargo must remain discoverable after PATH normalization"
Assert-True -Condition $pathProbe.unix_path_preserved -Message "Unix PATH must remain byte-for-byte unchanged"

$fast = Invoke-Planner -Arguments @("-Profile", "fast-smoke", "-PlanOnly")
Assert-True -Condition ($fast.known_target_count -gt 0) -Message "Cargo metadata returned no integration-test targets"
Assert-Equal -Actual $fast.invocations.Count -Expected 7 -Message "fast-smoke invocation count drifted"
foreach ($invocation in $fast.invocations) {
    Assert-Equal -Actual $invocation.package -Expected "cotest" -Message "fast-smoke must select the server harness"
    Assert-True -Condition ($invocation.cargo_args -contains "--locked" -and $invocation.cargo_args -contains "-p") -Message "planner must retain locked package coordinates"
    Assert-Equal -Actual $invocation.selection_mode -Expected "target-filter" -Message "fast-smoke must be target aware"
    Assert-True -Condition ($invocation.cargo_args -contains "--test") -Message "fast-smoke invocation is missing --test"
    Assert-True -Condition ($invocation.cargo_args -notcontains "--tests") -Message "fast-smoke invocation must not use --tests"
    Assert-True -Condition ($invocation.cargo_args -contains "--exact") -Message "fast-smoke invocation must use exact libtest matching"
}

$servicesLive = Invoke-Planner -Arguments @("-Profile", "services-live", "-PlanOnly")
Assert-Equal -Actual $servicesLive.invocations.Count -Expected 6 -Message "services-live invocation count drifted"
foreach ($invocation in $servicesLive.invocations) {
    Assert-Equal -Actual $invocation.package -Expected "cotest" -Message "services-live must not build the client package"
    Assert-Equal -Actual $invocation.selection_mode -Expected "target-filter" -Message "services-live must be target aware"
    # Every scenario in this lane spawns a real service and is therefore
    # `#[ignore]`d for ad hoc runs. Without `--ignored` the lane would select
    # nothing and pass having started no service at all.
    Assert-True -Condition ($invocation.include_ignored) -Message "services-live entry must opt into an ignored test"
    Assert-True -Condition ($invocation.cargo_args -contains "--ignored") -Message "services-live invocation is missing --ignored"
    Assert-True -Condition ($invocation.cargo_args -contains "--exact") -Message "services-live invocation must use exact libtest matching"
}

$release = Invoke-Planner -Arguments @("-Profile", "release-gate", "-PlanOnly")
Assert-Equal -Actual $release.invocations.Count -Expected 23 -Message "release-gate invocation count drifted"
Assert-Equal -Actual @($release.invocations | Select-Object -ExpandProperty target -Unique).Count -Expected 9 -Message "release-gate target count drifted"

$all = Invoke-Planner -Arguments @("-Profile", "all", "-PlanOnly")
Assert-Equal -Actual $all.invocations.Count -Expected 2 -Message "all profile must include both packages"
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
Assert-Equal -Actual @($broadScan.invocations | Where-Object { $_.package -eq "cotest-inkson-client-tests" })[0].selection_mode -Expected "broad-scan" -Message "filter-only selection mode drifted"
Assert-True -Condition ($broadScan.invocations[0].cargo_args -contains "--tests") -Message "filter-only mode must remain an explicit broad scan"

Assert-Equal -Actual $broadScan.invocations.Count -Expected 2 -Message "filter-only must scan both packages"
Assert-Equal -Actual (($all.invocations.package | Sort-Object) -join ',') -Expected 'cotest,cotest-inkson-client-tests' -Message "all must not hide the client package"
$client = Invoke-Planner -Arguments @("-Profile", "inkson-client-live", "-PlanOnly")
Assert-Equal -Actual $client.invocations.Count -Expected 31 -Message "client lane must retain every moved test"
Assert-True -Condition (@($client.invocations | Where-Object { $_.package -ne "cotest-inkson-client-tests" }).Count -eq 0) -Message "client lane coordinates must be explicit"
Assert-True -Condition (@($client.invocations | Where-Object { $_.filter -eq "named_suite_audit_executes_registered_runners_and_exposes_every_gap" }).Count -eq 1) -Message "mandatory combined full audit must execute exactly once"
Invoke-ExpectedPlannerFailure -Arguments @("-Profile", "all", "-CargoTestTarget", "conformance_vectors", "-PlanOnly") -ExpectedMessage "select -CargoTestPackage explicitly"
$split = Invoke-Planner -Arguments @("-Profile", "all", "-CargoTestPackage", "cotest-inkson-client-tests", "-CargoTestTarget", "conformance_vectors", "-CargoTestFilter", "webrtc_media_plaintext_named_suite_returns_one_result_per_case", "-PlanOnly")
Assert-Equal -Actual $split.invocations[0].package -Expected "cotest-inkson-client-tests" -Message "same target name must retain its package"
Invoke-ExpectedPlannerFailure -Arguments @("-Profile", "all", "-CargoTestPackage", "missing-package", "-PlanOnly") -ExpectedMessage "Unknown cargo test package"

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

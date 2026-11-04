param([string]$RunnerPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $RunnerPath) { $RunnerPath = Join-Path $PSScriptRoot '../run-joint-e2e.ps1' }
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($RunnerPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Runner must parse before lifecycle regression' }
$lifecycle = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.TryStatementAst] -and
    $node.CatchClauses.Count -eq 1 -and
    $node.Body.Extent.Text.Contains('$preflightSourceHeads = Get-JointSourceHeads')
}, $true))
if ($lifecycle.Count -ne 1) { throw 'Expected the real managed preparation lifecycle' }
$lifecycle = $lifecycle[0]
$summaryAssignment = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -eq '$summary' -and
    $node.Right.Extent.Text.Contains('flagon_service_resolution =')
}, $true))
if ($summaryAssignment.Count -ne 1) { throw 'Expected the real final joint summary' }
$summaryAssignment = $summaryAssignment[0]
$summaryWrite = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.PipelineAst] -and
    $node.Extent.Text.StartsWith('$summary | ConvertTo-Json') -and
    $node.Extent.Text.Contains('Set-Content -Path $summaryJson')
}, $true))
if ($summaryWrite.Count -ne 1) { throw 'Expected the actual summary JSON write' }
$defaults = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -in @('$flagonIdentity', '$flagonIdentityDirectory', '$previousProvisionCustodyRoot', '$previousReadonlyDatabaseControls', '$previousPythonExecutable', '$previousSdkTlsRoots', '$sourceRepositoryPaths', '$sourceFreezePaths', '$sourceFreezeBefore') -and
    $node.Extent.EndOffset -lt $lifecycle.Extent.StartOffset
}, $true))
foreach ($name in @('Write-ManagedServiceFailureReport', 'Complete-JointSourceFreeze')) {
    $function = @($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true))
    if ($function.Count -ne 1) { throw "Expected real lifecycle helper $name" }
    Invoke-Expression $function[0].Extent.Text
}

$sourceFreezeAssignments = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    (($node.Left.Extent.Text -eq '$sourceFreezeReport' -and $node.Right.Extent.Text.Contains('Complete-JointSourceFreeze')) -or
     ($node.Left.Extent.Text -eq '$exitCode' -and $node.Right.Extent.Text -eq '$sourceFreezeReport.exit_code'))
}, $true) | Sort-Object { $_.Extent.StartOffset })
if ($sourceFreezeAssignments.Count -ne 2) { throw 'Expected the actual final source gate and exit consumption' }

# Only the preparation and process boundaries are mocked. The actual catch,
# finally, summary expression and JSON write remain the production code.
function Start-ManagedCommand { param($Name) throw "Managed command $Name exited with code 101" }
function ConvertTo-SecretPreview { param($Line) return $Line }
function Sync-JointControlledServices { param($TopologyPath, $ManagedServices) return @() }
function Get-ManagedServiceFailures { param($Services) return @() }
function Get-JointTopologyHealthFailures { param($TopologyPath, $ManagedServices) return @() }
function Stop-ManagedCommand { param($Service) $script:stoppedNames += $Service.Name }

function Invoke-EarlyFailureCase([string]$Name, [bool]$OwnedFlagon, [bool]$IdentityReady) {
    $env:COTEST_PYTHON_EXECUTABLE = if ($OwnedFlagon) { "fixture-python-$Name" } else { $null }
    $env:SSL_CERT_FILE = if ($IdentityReady) { "fixture-ca-$Name" } else { $null }
    $expectedPython = $env:COTEST_PYTHON_EXECUTABLE
    $expectedTlsRoots = $env:SSL_CERT_FILE
    # Supply irrelevant report fields, but deliberately never seed either
    # identity variable: their real pre-try initializers are the tested fix.
    foreach ($variable in $summaryAssignment.FindAll({param($node)
        $node -is [Management.Automation.Language.VariableExpressionAst]
    }, $true)) {
        $fieldName = $variable.VariablePath.UserPath
        if ($fieldName -notin @('null', 'true', 'false', 'flagonIdentity', 'flagonIdentityDirectory')) {
            Set-Variable -Name $fieldName -Value $null
        }
    }
    Remove-Variable flagonIdentity, flagonIdentityDirectory -ErrorAction SilentlyContinue
    $jointDir = Join-Path $temporary $Name
    $null = New-Item -ItemType Directory -Path $jointDir
    $StartFlagon = $OwnedFlagon
    $FlagonBaseUrl = if ($OwnedFlagon) { 'https://flagon.fixture.invalid' } else { 'https://attached-directory.fixture.invalid' }
    $managedServices = [Collections.Generic.List[object]]::new()
    $managedServices.Add([pscustomobject]@{Name='already-owned-fixture'})
    $script:stoppedNames = @()
    $managedServiceFailures = @()
    $managedServiceFailuresJson = Join-Path $jointDir 'managed-service-failures.json'
    $managedServiceFailuresMd = Join-Path $jointDir 'managed-service-failures.md'
    $topologyPath = Join-Path $jointDir 'topology.json'
    $KeepServices = $false
    $ephemeralCoauthServer1Postgres = $null; $ephemeralCoauthServer2Postgres = $null
    $ephemeralColandPostgres = $null; $ephemeralColandServer2Postgres = $null
    $additionalServers = @(); $storeDumpFailures = @()
    $jointTlsEnabled = $false; $mockAppletRegistryStateKeyFile = $null
    $provisionCustodyRoot = $null
    $exitCode = 1; $runnerError = $null
    $startedAt = Get-Date; $finishedAt = $startedAt
    $totals = [pscustomobject]@{passed=0;failed=0;skipped=0;fixme=0}
    $secretScan = [pscustomobject]@{status='not_run'}
    $playwrightProjects = @('chrome')
    foreach ($initialization in $defaults) { Invoke-Expression $initialization.Extent.Text }
    $acceptedIdentity = [pscustomobject]@{did='did:web:flagon.fixture.invalid';method_history_head='fixture-head'}
    if ($IdentityReady) { $flagonIdentity = $acceptedIdentity }
    $env:COTEST_PYTHON_EXECUTABLE = 'temporary-run-python'
    $failure = "try { Start-ManagedCommand -Name 'prepare-savfox' } catch $($lifecycle.CatchClauses[0].Body.Extent.Text) finally $($lifecycle.Finally.Extent.Text)"
    Invoke-Expression $failure
    if ($env:COTEST_PYTHON_EXECUTABLE -cne $expectedPython -or $env:SSL_CERT_FILE -cne $expectedTlsRoots) {
        throw 'Early failure must restore the actual prior Python and TLS environment'
    }
    foreach ($assignment in $sourceFreezeAssignments) { Invoke-Expression $assignment.Extent.Text }
    Invoke-Expression $summaryAssignment.Extent.Text
    $summaryJson = Join-Path $jointDir 'summary.json'
    Invoke-Expression $summaryWrite[0].Extent.Text
    $written = Get-Content -LiteralPath $summaryJson -Raw | ConvertFrom-Json
    if ($written.exit_code -ne 1 -or $written.status -cne 'failure' -or
        $written.runner_error.message -cne 'Managed command prepare-savfox exited with code 101') {
        throw 'Preparation error or failing status was masked by finalization'
    }
    if ($script:stoppedNames.Count -ne 1 -or $script:stoppedNames[0] -cne 'already-owned-fixture') {
        throw 'Early failure did not clean up exactly the already-owned process'
    }
    if (-not (Test-Path -LiteralPath $written.runner_error.diagnostic) -or
        -not (Get-Content -LiteralPath $written.runner_error.diagnostic -Raw).Contains('prepare-savfox exited with code 101')) {
        throw 'Original bounded runner diagnostic was not retained'
    }
    if ($written.source_stable -or $written.source_coverage -cne 'unavailable' -or
        -not (Test-Path -LiteralPath $written.source_freeze_json)) {
        throw 'Failure before source capture must report unavailable provenance without masking the original failure'
    }
    if ($written.test_execution -cne 'not_executed') { throw 'Preparation failure must not claim business execution' }
    if ($IdentityReady) {
        if ($written.flagon_service_resolution.did -cne $acceptedIdentity.did) { throw 'Finalization discarded an identity already obtained' }
    } elseif ($null -ne $written.flagon_service_resolution) {
        throw 'An unprepared Directory must not acquire a fake identity'
    }
    Write-Host "PASS $Name (original failure, owned cleanup and actual summary JSON)"
}

$testPreviousPython = $env:COTEST_PYTHON_EXECUTABLE
$testPreviousTlsRoots = $env:SSL_CERT_FILE
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporary = Join-Path $tempBase ('cotest-early-failure-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary
try {
    Invoke-EarlyFailureCase 'managed-directory-before-identity' $true $false
    Invoke-EarlyFailureCase 'attached-directory-before-identity' $false $false
    Invoke-EarlyFailureCase 'retains-already-obtained-identity' $true $true
    Write-Host 'joint-early-failure.tests.ps1: PASS (3 lifecycle cases; no real services)'
} finally {
    $env:COTEST_PYTHON_EXECUTABLE = $testPreviousPython
    $env:SSL_CERT_FILE = $testPreviousTlsRoots
    $resolved = [IO.Path]::GetFullPath($temporary)
    if (-not $resolved.StartsWith($tempBase.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notlike 'cotest-early-failure-*') { throw 'Test cleanup escaped its unique temporary directory' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

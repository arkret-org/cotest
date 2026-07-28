[CmdletBinding()]
param(
    [ValidateSet("Prepare", "Finalize", "Abort", "Validate")]
    [string]$Action = "Prepare",
    [string]$Scenario = "federated-team-incident",
    [ValidateSet("single", "federated")]
    [string]$Topology = "federated",
    [ValidateSet("process", "docker")]
    [string]$SolandRuntime = "process",
    [string]$RunDir,
    [int]$TimeoutSeconds = 14400,
    [switch]$SkipBuild,
    [string]$AbortReason = "Agent journey aborted by operator"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$journeyRoot = Join-Path $repoRoot "agent-journeys"
$journeyScript = Join-Path $journeyRoot "scripts\journey.mjs"
$waitScript = Join-Path $journeyRoot "scripts\wait-for-agent.ps1"
$jointRunner = Join-Path $repoRoot "scripts\run-joint-e2e.ps1"

function Resolve-RunDirectory {
    param([Parameter(Mandatory = $true)][string]$Value)
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Value)
}

function Wait-File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$Seconds,
        [string]$RunnerErrorPath,
        [int]$RunnerPid
    )
    $deadline = (Get-Date).AddSeconds($Seconds)
    while (-not (Test-Path -LiteralPath $Path)) {
        if ($RunnerPid -gt 0 -and -not (Get-Process -Id $RunnerPid -ErrorAction SilentlyContinue)) {
            $detail = if ($RunnerErrorPath -and (Test-Path -LiteralPath $RunnerErrorPath)) {
                Get-Content -Raw -LiteralPath $RunnerErrorPath
            } else {
                ""
            }
            throw "Managed stack runner exited before producing $Path`n$detail"
        }
        if ((Get-Date) -ge $deadline) {
            $detail = if ($RunnerErrorPath -and (Test-Path -LiteralPath $RunnerErrorPath)) {
                Get-Content -Raw -LiteralPath $RunnerErrorPath
            } else {
                ""
            }
            throw "Timed out waiting for $Path`n$detail"
        }
        Start-Sleep -Seconds 1
    }
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Read-Control {
    param([Parameter(Mandatory = $true)][string]$Directory)
    $controlPath = Join-Path $Directory "control.json"
    if (-not (Test-Path -LiteralPath $controlPath)) {
        throw "Agent journey control file not found: $controlPath"
    }
    return Get-Content -Raw -LiteralPath $controlPath | ConvertFrom-Json
}

if ($Action -eq "Prepare") {
    $scenarioPath = Join-Path $journeyRoot "scenarios\$Scenario.json"
    if (-not (Test-Path -LiteralPath $scenarioPath -PathType Leaf)) {
        throw "Agent journey scenario not found: $scenarioPath"
    }
    $scenarioDocument = Get-Content -Raw -LiteralPath $scenarioPath | ConvertFrom-Json
    if ([string]$scenarioDocument.required_topology -ne $Topology) {
        throw "Scenario '$Scenario' requires topology '$($scenarioDocument.required_topology)', not '$Topology'"
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $runId = "$timestamp-$Scenario"
    if (-not $RunDir) {
        $RunDir = Join-Path $repoRoot "artifacts\runs\$timestamp\agent-journey"
    }
    $RunDir = Resolve-RunDirectory -Value $RunDir
    if (Test-Path -LiteralPath $RunDir) {
        throw "Agent journey run directory already exists: $RunDir"
    }
    $null = New-Item -ItemType Directory -Force -Path $RunDir

    & node $journeyScript init --scenario $scenarioPath --run-dir $RunDir --run-id $runId | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to initialize agent journey"
    }

    $stackDir = Join-Path $RunDir "stack"
    $runtimeManifest = Join-Path $RunDir "runtime-manifest.json"
    $readySignal = Join-Path $RunDir "agent-ready.json"
    $completeSignal = Join-Path $RunDir "agent-complete.signal"
    $runnerStdout = Join-Path $RunDir "runner.stdout.log"
    $runnerStderr = Join-Path $RunDir "runner.stderr.log"
    $controlPath = Join-Path $RunDir "control.json"
    $control = [ordered]@{
        schema_version = "v1"
        run_id = $runId
        run_dir = $RunDir
        scenario = $scenarioPath
        topology = $Topology
        runtime_manifest = $runtimeManifest
        ready_signal = $readySignal
        complete_signal = $completeSignal
        timeout_seconds = $TimeoutSeconds
        journey_script = $journeyScript
        runner_pid = $null
        runner_stdout = $runnerStdout
        runner_stderr = $runnerStderr
    }
    $control | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $controlPath -Encoding UTF8

    $runnerArgs = @(
        "-NoProfile",
        "-File", $jointRunner,
        "-JointDir", $stackDir,
        "-StartCoauth",
        "-SkipNpmInstall",
        "-SkipBrowserInstall",
        "-SolandRuntime", $SolandRuntime,
        "-ExternalDriverScript", $waitScript,
        "-ExternalDriverArgument", $controlPath,
        "-RuntimeManifestPath", $runtimeManifest
    )
    if ($Topology -eq "federated") {
        $runnerArgs += "-DualSoland"
    }
    if ($SkipBuild) {
        $runnerArgs += "-SkipBuild"
    }
    $argumentLine = @($runnerArgs | ForEach-Object { Quote-ProcessArgument -Value "$_" })
    $runnerProcess = Start-Process `
        -FilePath "pwsh" `
        -ArgumentList $argumentLine `
        -RedirectStandardOutput $runnerStdout `
        -RedirectStandardError $runnerStderr `
        -WindowStyle Hidden `
        -PassThru
    $control.runner_pid = $runnerProcess.Id
    $control | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $controlPath -Encoding UTF8

    Wait-File -Path $runtimeManifest -Seconds 900 -RunnerErrorPath $runnerStderr -RunnerPid $runnerProcess.Id
    Wait-File -Path $readySignal -Seconds 900 -RunnerErrorPath $runnerStderr -RunnerPid $runnerProcess.Id
    & node $journeyScript bind-runtime --run-dir $RunDir --runtime-manifest $runtimeManifest | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Runtime manifest does not satisfy the journey topology"
    }

    [pscustomobject]@{
        run_id = $runId
        run_dir = $RunDir
        scenario = $scenarioPath
        topology = $Topology
        runtime_manifest = $runtimeManifest
        result = Join-Path $RunDir "result.json"
    }
}

if ($Action -ne "Prepare") {
    if (-not $RunDir) {
        throw "-RunDir is required for $Action"
    }
    $RunDir = Resolve-RunDirectory -Value $RunDir
    $control = Read-Control -Directory $RunDir

    if ($Action -eq "Validate") {
        & node $journeyScript validate --run-dir $RunDir | Out-Host
        exit $LASTEXITCODE
    }

    if ($Action -eq "Abort") {
        & node $journeyScript abort --run-dir $RunDir --reason $AbortReason | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to record journey abort"
        }
    } else {
        & node $journeyScript finish --run-dir $RunDir | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Agent journey cannot be finalized until all required checkpoints have evidence"
        }
    }

    $result = Get-Content -Raw -LiteralPath (Join-Path $RunDir "result.json") | ConvertFrom-Json
    foreach ($actor in @($result.actors)) {
        $sessionName = ("{0}-{1}" -f $result.run_id, $actor.id) -replace '[^a-zA-Z0-9_-]', '-'
        & agent-browser --session $sessionName close 2>$null | Out-Null
    }

    "" | Set-Content -LiteralPath ([string]$control.complete_signal) -Encoding UTF8
    $runnerPid = [int]$control.runner_pid
    $deadline = (Get-Date).AddMinutes(10)
    while (Get-Process -Id $runnerPid -ErrorAction SilentlyContinue) {
        if ((Get-Date) -ge $deadline) {
            throw "Managed stack runner did not exit after completion signal; inspect $($control.runner_stderr)"
        }
        Start-Sleep -Seconds 1
    }

    Get-Content -LiteralPath (Join-Path $RunDir "summary.md")
    if ($Action -eq "Abort") {
        exit 1
    }
    $finalResult = Get-Content -Raw -LiteralPath (Join-Path $RunDir "result.json") | ConvertFrom-Json
    exit $(if ($finalResult.status -eq "PASS") { 0 } else { 1 })
}

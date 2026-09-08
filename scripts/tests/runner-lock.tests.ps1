param(
    [ValidateSet("parent", "wait", "hold")][string]$Mode = "parent",
    [string]$LockPath,
    [string]$SignalPath
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$runner = Join-Path $PSScriptRoot "../run-joint-e2e.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$definition = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Open-ExclusiveRunnerLock"
}, $true)
Invoke-Expression $definition.Extent.Text

if ($Mode -ne "parent") {
    if ($Mode -eq "wait") { [IO.File]::WriteAllText($SignalPath + '.started', 'ready') }
    $lease = Open-ExclusiveRunnerLock -Path $LockPath -Wait
    try {
        [IO.File]::WriteAllText($SignalPath, 'acquired')
        if ($Mode -eq "hold") { Start-Sleep -Seconds 30 }
    } finally { $lease.Dispose() }
    exit 0
}

function Start-LockWorker([string]$WorkerMode, [string]$WorkerSignal) {
    $info = [Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    foreach ($argument in @('-NoProfile', '-File', $PSCommandPath, '-Mode', $WorkerMode,
        '-LockPath', $LockPath, '-SignalPath', $WorkerSignal)) {
        $info.ArgumentList.Add($argument)
    }
    return [Diagnostics.Process]::Start($info)
}
function Wait-Signal([string]$Path) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $Path)) {
        if ([DateTimeOffset]::UtcNow -ge $deadline) { throw "worker signal timed out" }
        Start-Sleep -Milliseconds 50
    }
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempRoot = Join-Path $tempBase ("cotest-runner-lock-" + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tempRoot
$LockPath = Join-Path $tempRoot 'run.lock'
$lease = $null
$worker = $null
try {
    $lease = Open-ExclusiveRunnerLock -Path $LockPath
    $signal = Join-Path $tempRoot 'waiting'
    $worker = Start-LockWorker 'wait' $signal
    Wait-Signal ($signal + '.started')
    Start-Sleep -Milliseconds 600
    if (Test-Path -LiteralPath $signal) { throw 'second process acquired an owned lock' }
    $lease.Dispose()
    $lease = $null
    if (-not $worker.WaitForExit(10000) -or $worker.ExitCode -ne 0) { throw 'queued worker failed' }
    Wait-Signal $signal
    $worker.Dispose()

    $signal = Join-Path $tempRoot 'abandoned'
    $worker = Start-LockWorker 'hold' $signal
    Wait-Signal $signal
    $worker.Kill($true)
    $worker.WaitForExit()
    $lease = Open-ExclusiveRunnerLock -Path $LockPath
    Write-Host 'Runner lock tests passed: process exclusion, queued acquisition, terminated-owner release.'
} finally {
    if ($lease) { $lease.Dispose() }
    if ($worker) {
        if (-not $worker.HasExited) { $worker.Kill($true); $worker.WaitForExit() }
        $worker.Dispose()
    }
    $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
    if (-not $resolvedTemp.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'temporary cleanup path escaped its root'
    }
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
}

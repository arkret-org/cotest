<#
.SYNOPSIS
Controls one runner-owned Soland service for joint E2E fault scenarios.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TopologyPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^server[1-9][0-9]*$')][string]$ServerName,
    [Parameter(Mandatory = $true)][ValidateSet('isolate', 'restore', 'restart', 'status')][string]$Action
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$TopologyPath = [System.IO.Path]::GetFullPath($TopologyPath)
$topology = Get-Content -Raw -LiteralPath $TopologyPath | ConvertFrom-Json
$server = @($topology.servers | Where-Object { $_.name -eq $ServerName }) | Select-Object -First 1
if (-not $server) { throw "Topology does not contain $ServerName" }
if (-not $server.soland.control) { throw "$ServerName is not runner-controlled" }
$control = $server.soland.control
$statePath = [string]$control.state_path
$stateDirectory = Split-Path -Parent $statePath
$null = New-Item -ItemType Directory -Force -Path $stateDirectory

function Write-ControlState {
    param([hashtable]$Value)
    $Value.schema = 'cotest.joint-service-control.v1'
    $Value.server = $ServerName
    $Value.updated_at = (Get-Date).ToUniversalTime().ToString('o')
    $temporary = "$statePath.$PID.tmp"
    [pscustomobject]$Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding utf8NoBOM
    Move-Item -LiteralPath $temporary -Destination $statePath -Force
}

function Read-ControlState {
    if (-not (Test-Path -LiteralPath $statePath)) { return $null }
    return Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
}

function Get-DescendantProcessIds {
    param([int]$RootId)
    $all = if ($IsWindows) {
        @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId)
    } else {
        @(& ps -eo pid=,ppid= | ForEach-Object {
            $parts = ($_ -split '\s+' | Where-Object { $_ })
            if ($parts.Count -ge 2) { [pscustomobject]@{ ProcessId = [int]$parts[0]; ParentProcessId = [int]$parts[1] } }
        })
    }
    $result = [System.Collections.Generic.List[int]]::new()
    $queue = [System.Collections.Generic.Queue[int]]::new()
    $queue.Enqueue($RootId)
    while ($queue.Count -gt 0) {
        $parent = $queue.Dequeue()
        foreach ($child in @($all | Where-Object { [int]$_.ParentProcessId -eq $parent })) {
            $id = [int]$child.ProcessId
            $result.Add($id)
            $queue.Enqueue($id)
        }
    }
    return @($result)
}

function Stop-ExactProcessTree {
    param([int]$RootId)
    $ids = @(Get-DescendantProcessIds -RootId $RootId)
    [array]::Reverse($ids)
    foreach ($id in @($ids) + @($RootId)) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
    try { Wait-Process -Id $RootId -Timeout 20 -ErrorAction SilentlyContinue } catch {}
}

if ($IsWindows -and -not ('CotestNativeProcessControl' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class CotestNativeProcessControl {
    [DllImport("ntdll.dll")] private static extern int NtSuspendProcess(IntPtr handle);
    [DllImport("ntdll.dll")] private static extern int NtResumeProcess(IntPtr handle);
    public static void Suspend(IntPtr handle) { int rc = NtSuspendProcess(handle); if (rc != 0) throw new InvalidOperationException("NtSuspendProcess failed: " + rc); }
    public static void Resume(IntPtr handle) { int rc = NtResumeProcess(handle); if (rc != 0) throw new InvalidOperationException("NtResumeProcess failed: " + rc); }
}
'@
}

if (-not $IsWindows -and -not ('CotestUnixProcessControl' -as [type])) {
    Add-Type @'
using System.Runtime.InteropServices;
public static class CotestUnixProcessControl {
    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    public static extern int Kill(int pid, int signal);
}
'@
}

function Set-ProcessSuspended {
    param([int[]]$ProcessIds, [bool]$Suspended)
    foreach ($id in $ProcessIds) {
        if ($IsWindows) {
            $process = Get-Process -Id $id -ErrorAction SilentlyContinue
            if (-not $process) { continue }
            if ($Suspended) { [CotestNativeProcessControl]::Suspend($process.Handle) }
            else { [CotestNativeProcessControl]::Resume($process.Handle) }
        } else {
            # Native-command completion can wait for descendants holding the
            # service's output pipes after SIGSTOP. Signal directly instead.
            $signal = if ($IsMacOS) { if ($Suspended) { 17 } else { 19 } } else { if ($Suspended) { 19 } else { 18 } }
            if ([CotestUnixProcessControl]::Kill($id, $signal) -ne 0) {
                $errorNumber = [Runtime.InteropServices.Marshal]::GetLastPInvokeError()
                if ($errorNumber -ne 3) { throw "signal $signal failed for PID $id (errno=$errorNumber)" }
            }
        }
    }
}

function Resolve-CurrentProcessId {
    $state = Read-ControlState
    if ($state -and $state.current_process_id) { return [int]$state.current_process_id }
    return [int]$server.soland.process_id
}

$kind = [string]$control.kind
if ($kind -eq 'docker') {
    $container = [string]$server.soland.container_id
    if (-not $container) { throw "$ServerName has no container ID" }
    switch ($Action) {
        'isolate' { & docker stop --time 10 $container | Out-Null; if ($LASTEXITCODE -ne 0) { throw "docker stop failed for $container" }; Write-ControlState @{ kind = $kind; status = 'isolated'; container_id = $container } }
        'restore' { & docker start $container | Out-Null; if ($LASTEXITCODE -ne 0) { throw "docker start failed for $container" }; Write-ControlState @{ kind = $kind; status = 'running'; container_id = $container } }
        'restart' { & docker restart --time 10 $container | Out-Null; if ($LASTEXITCODE -ne 0) { throw "docker restart failed for $container" }; Write-ControlState @{ kind = $kind; status = 'running'; container_id = $container; restarted = $true } }
        'status' { $state = Read-ControlState; if ($state) { $state | ConvertTo-Json -Depth 8 } else { [pscustomobject]@{ kind = $kind; status = 'running'; container_id = $container } | ConvertTo-Json } }
    }
    exit 0
}

if ($kind -ne 'process') { throw "Unsupported control kind '$kind'" }
$rootId = Resolve-CurrentProcessId
switch ($Action) {
    'isolate' {
        $ids = @(Get-DescendantProcessIds -RootId $rootId) + @($rootId)
        if ($ids.Count -lt 2) { throw "$ServerName process tree has no service child" }
        try {
            Set-ProcessSuspended -ProcessIds $ids -Suspended $true
            Write-ControlState @{ kind = $kind; status = 'isolated'; original_process_id = [int]$server.soland.process_id; current_process_id = $rootId; suspended_process_ids = $ids }
        } catch {
            $resumeIds = @($ids)
            [array]::Reverse($resumeIds)
            Set-ProcessSuspended -ProcessIds $resumeIds -Suspended $false
            throw
        }
    }
    'restore' {
        $state = Read-ControlState
        if (-not $state -or $state.status -ne 'isolated') { throw "$ServerName is not recorded as isolated" }
        $ids = @($state.suspended_process_ids | ForEach-Object { [int]$_ })
        [array]::Reverse($ids)
        Set-ProcessSuspended -ProcessIds $ids -Suspended $false
        Write-ControlState @{ kind = $kind; status = 'running'; original_process_id = [int]$server.soland.process_id; current_process_id = [int]$state.current_process_id }
    }
    'restart' {
        $state = Read-ControlState
        if ($state -and $state.status -eq 'isolated') {
            $ids = @($state.suspended_process_ids | ForEach-Object { [int]$_ })
            [array]::Reverse($ids)
            Set-ProcessSuspended -ProcessIds $ids -Suspended $false
        }
        Stop-ExactProcessTree -RootId $rootId
        $command = Get-Content -Raw -LiteralPath ([string]$control.command_log)
        $wrapped = "$command; `$ok = `$?; `$native = `$LASTEXITCODE; if (-not `$ok) { if (`$null -ne `$native -and `$native -ne 0) { exit `$native }; exit 1 }; exit 0"
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
        $stdout = Join-Path ([string]$server.soland.log_directory) "$ServerName.restart-$stamp.stdout.log"
        $stderr = Join-Path ([string]$server.soland.log_directory) "$ServerName.restart-$stamp.stderr.log"
        $startArguments = @{
            FilePath = (Get-Process -Id $PID).Path
            ArgumentList = @('-NoProfile', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapped)))
            WorkingDirectory = [string]$control.working_directory
            RedirectStandardOutput = $stdout
            RedirectStandardError = $stderr
            PassThru = $true
        }
        if ($IsWindows) { $startArguments.WindowStyle = 'Hidden' }
        $process = Start-Process @startArguments
        try {
            Write-ControlState @{ kind = $kind; status = 'running'; original_process_id = [int]$server.soland.process_id; current_process_id = $process.Id; restarted = $true; stdout = $stdout; stderr = $stderr }
        } catch {
            Stop-ExactProcessTree -RootId $process.Id
            throw
        }
    }
    'status' {
        $state = Read-ControlState
        if ($state) { $state | ConvertTo-Json -Depth 8 } else { [pscustomobject]@{ kind = $kind; status = 'running'; current_process_id = $rootId } | ConvertTo-Json }
    }
}

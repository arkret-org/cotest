Set-StrictMode -Version Latest

function Get-CotestProcessIdentity {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    return [pscustomobject]@{
        process_id = $Process.Id
        started_at = $Process.StartTime.ToUniversalTime().ToString('o')
    }
}

function Get-CotestIdentityProcess {
    param([Parameter(Mandatory = $true)]$Identity)
    $process = Get-Process -Id ([int]$Identity.process_id) -ErrorAction SilentlyContinue
    if (-not $process) { return $null }
    try {
        if ($process.StartTime.ToUniversalTime() -ne ([datetime]$Identity.started_at).ToUniversalTime()) {
            $process.Dispose()
            return $null
        }
        return $process
    } catch {
        $process.Dispose()
        return $null
    }
}

function Get-CotestProcessSnapshot {
    $parents = if ($IsWindows) {
        @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, CreationDate)
    } else {
        @(& ps -eo pid=,ppid= | ForEach-Object {
            $parts = ($_ -split '\s+' | Where-Object { $_ })
            if ($parts.Count -ge 2) {
                [pscustomobject]@{ ProcessId = [int]$parts[0]; ParentProcessId = [int]$parts[1] }
            }
        })
    }
    foreach ($entry in $parents) {
        $process = Get-Process -Id ([int]$entry.ProcessId) -ErrorAction SilentlyContinue
        if (-not $process) { continue }
        try {
            $identity = Get-CotestProcessIdentity -Process $process
            # CIM creation dates have microsecond precision. Reject PID reuse
            # between the parent snapshot and opening the process handle.
            if ($IsWindows -and [math]::Abs(($process.StartTime.ToUniversalTime() - $entry.CreationDate.ToUniversalTime()).Ticks) -ge 10) { continue }
            [pscustomobject]@{
                process_id = $identity.process_id
                started_at = $identity.started_at
                parent_process_id = [int]$entry.ParentProcessId
            }
        } catch {
            continue
        } finally {
            $process.Dispose()
        }
    }
}

function Select-CotestOwnedProcessTree {
    param([Parameter(Mandatory = $true)]$RootIdentity, [Parameter(Mandatory = $true)][object[]]$Snapshot)
    $root = @($Snapshot | Where-Object {
        [int]$_.process_id -eq [int]$RootIdentity.process_id -and
        ([datetime]$_.started_at).ToUniversalTime() -eq ([datetime]$RootIdentity.started_at).ToUniversalTime()
    }) | Select-Object -First 1
    if (-not $root) { return @() }
    $queue = [System.Collections.Generic.Queue[object]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $queue.Enqueue($root)
    $null = $seen.Add([int]$root.process_id)
    while ($queue.Count -gt 0) {
        $parent = $queue.Dequeue()
        $parent
        foreach ($child in @($Snapshot | Where-Object { [int]$_.parent_process_id -eq [int]$parent.process_id })) {
            # A retained PPID is not ownership after the parent PID is reused.
            if (([datetime]$child.started_at).ToUniversalTime() -lt ([datetime]$parent.started_at).ToUniversalTime()) { continue }
            if ($seen.Add([int]$child.process_id)) { $queue.Enqueue($child) }
        }
    }
}

function Get-CotestOwnedProcessTree {
    param([Parameter(Mandatory = $true)]$RootIdentity)
    return @(Select-CotestOwnedProcessTree -RootIdentity $RootIdentity -Snapshot @(Get-CotestProcessSnapshot))
}

function Stop-CotestOwnedProcessTree {
    param([Parameter(Mandatory = $true)]$RootIdentity)
    $identities = @(Get-CotestOwnedProcessTree -RootIdentity $RootIdentity)
    [array]::Reverse($identities)
    foreach ($identity in $identities) {
        $process = Get-CotestIdentityProcess -Identity $identity
        if (-not $process) { continue }
        try {
            $process.Kill()
            if (-not $process.WaitForExit(20000)) { throw "Owned process $($identity.process_id) did not exit" }
        } finally {
            $process.Dispose()
        }
    }
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\lib\process-ownership.ps1')

$controller = (Resolve-Path (Join-Path $PSScriptRoot '..\control-joint-e2e-service.ps1')).Path
$root = Join-Path ([System.IO.Path]::GetTempPath()) "cotest-service-control-$PID"
$null = New-Item -ItemType Directory -Force -Path $root
$commandLog = Join-Path $root 'coland-server2.command.txt'
$statePath = Join-Path $root 'controls\server2.json'
$topologyPath = Join-Path $root 'topology.json'
$original = $null
$replacementId = $null
$originalIdentity = $null
$replacementIdentity = $null

try {
    $shellPath = (Get-Process -Id $PID).Path
    $quotedShell = "'" + $shellPath.Replace("'", "''") + "'"
    $sleepCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 60'))
    $command = "& $quotedShell -NoProfile -EncodedCommand $sleepCommand"
    $command | Set-Content -LiteralPath $commandLog -Encoding utf8NoBOM
    $wrapped = "$command; if (-not `$?) { exit 1 }; exit 0"
    $startArguments = @{
        FilePath = $shellPath
        ArgumentList = @('-NoProfile', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapped)))
        WorkingDirectory = $root
        PassThru = $true
    }
    if ($IsWindows) { $startArguments.WindowStyle = 'Hidden' }
    $original = Start-Process @startArguments
    $originalIdentity = Get-CotestProcessIdentity -Process $original
    Start-Sleep -Milliseconds 750
    $topology = [pscustomobject]@{
        schema = 'cotest.joint-topology.v1'
        server_count = 1
        servers = @([pscustomobject]@{
            name = 'server2'
            coland = [pscustomobject]@{
                process_id = $original.Id
                process_started_at = $originalIdentity.started_at
                container_id = $null
                log_directory = $root
                control = [pscustomobject]@{
                    kind = 'process'
                    script_path = $controller
                    state_path = $statePath
                    working_directory = $root
                    command_log = $commandLog
                }
            }
        })
    }
    $topology | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $topologyPath -Encoding utf8NoBOM

    $wrongIdentity = [pscustomobject]@{ process_id = $original.Id; started_at = $original.StartTime.ToUniversalTime().AddSeconds(-1).ToString('o') }
    Stop-CotestOwnedProcessTree -RootIdentity $wrongIdentity
    if (-not (Get-CotestIdentityProcess -Identity $originalIdentity)) { throw 'a reused root PID was stopped' }
    $topology.servers[0].coland.process_started_at = $wrongIdentity.started_at
    $topology | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $topologyPath -Encoding utf8NoBOM
    $rejected = $false
    try { & $controller -TopologyPath $topologyPath -ServerName server2 -Action isolate }
    catch { $rejected = $_.Exception.Message -match 'owned process tree has no service child' }
    if (-not $rejected -or (Test-Path -LiteralPath $statePath)) { throw 'isolate accepted a reused root PID' }
    $topology.servers[0].coland.process_started_at = $originalIdentity.started_at
    $topology | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $topologyPath -Encoding utf8NoBOM

    & $controller -TopologyPath $topologyPath -ServerName server2 -Action isolate
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($state.status -ne 'isolated' -or @($state.suspended_process_ids).Count -lt 2) { throw 'isolate did not capture the process tree' }
    if (@($state.suspended_processes).Count -ne @($state.suspended_process_ids).Count -or ([datetime]$state.current_process_started_at).ToUniversalTime() -ne ([datetime]$originalIdentity.started_at).ToUniversalTime()) { throw 'isolate did not preserve process identities' }

    & $controller -TopologyPath $topologyPath -ServerName server2 -Action restore
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($state.status -ne 'running') { throw 'restore did not return the process tree to running' }

    & $controller -TopologyPath $topologyPath -ServerName server2 -Action restart
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    $replacementId = [int]$state.current_process_id
    $replacementIdentity = [pscustomobject]@{ process_id = $replacementId; started_at = $state.current_process_started_at }
    if (-not $state.restarted -or $replacementId -eq $original.Id -or -not (Get-Process -Id $replacementId -ErrorAction SilentlyContinue)) { throw 'restart did not create a tracked replacement process' }
    Start-Sleep -Milliseconds 750
    & $controller -TopologyPath $topologyPath -ServerName server2 -Action isolate
    & $controller -TopologyPath $topologyPath -ServerName server2 -Action restore
    if (-not (Get-CotestIdentityProcess -Identity $replacementIdentity)) { throw 'replacement identity was not usable after isolate/restore' }
    Write-Host 'joint-service-control.tests.ps1: PASS'
} finally {
    foreach ($identity in @($replacementIdentity, $originalIdentity) | Where-Object { $_ }) {
        Stop-CotestOwnedProcessTree -RootIdentity $identity
    }
    $resolvedRoot = [System.IO.Path]::GetFullPath($root)
    if (-not $resolvedRoot.StartsWith([System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) { throw 'test cleanup escaped its temporary directory' }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

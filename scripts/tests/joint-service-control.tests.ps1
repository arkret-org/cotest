$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$controller = (Resolve-Path (Join-Path $PSScriptRoot '..\control-joint-e2e-service.ps1')).Path
$root = Join-Path ([System.IO.Path]::GetTempPath()) "cotest-service-control-$PID"
$null = New-Item -ItemType Directory -Force -Path $root
$commandLog = Join-Path $root 'soland-server2.command.txt'
$statePath = Join-Path $root 'controls\server2.json'
$topologyPath = Join-Path $root 'topology.json'
$original = $null
$replacementId = $null

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
    Start-Sleep -Milliseconds 750
    $topology = [pscustomobject]@{
        schema = 'cotest.joint-topology.v1'
        server_count = 1
        servers = @([pscustomobject]@{
            name = 'server2'
            soland = [pscustomobject]@{
                process_id = $original.Id
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

    & $controller -TopologyPath $topologyPath -ServerName server2 -Action isolate
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($state.status -ne 'isolated' -or @($state.suspended_process_ids).Count -lt 2) { throw 'isolate did not capture the process tree' }

    & $controller -TopologyPath $topologyPath -ServerName server2 -Action restore
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($state.status -ne 'running') { throw 'restore did not return the process tree to running' }

    & $controller -TopologyPath $topologyPath -ServerName server2 -Action restart
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    $replacementId = [int]$state.current_process_id
    if (-not $state.restarted -or $replacementId -eq $original.Id -or -not (Get-Process -Id $replacementId -ErrorAction SilentlyContinue)) { throw 'restart did not create a tracked replacement process' }
    Write-Host 'joint-service-control.tests.ps1: PASS'
} finally {
    foreach ($id in @($replacementId, $(if ($original) { $original.Id } else { $null })) | Where-Object { $_ }) {
        Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

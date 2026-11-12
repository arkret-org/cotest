$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\lib\process-ownership.ps1')

$controller = (Resolve-Path (Join-Path $PSScriptRoot '..\control-joint-e2e-service.ps1')).Path
$artifactBase = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\artifacts\service-control-tests'))
$root = Join-Path $artifactBase "control-$PID with 'quoted' path"
$null = New-Item -ItemType Directory -Force -Path $root
$commandLog = Join-Path $root 'coland-server2.command.txt'
$statePath = Join-Path $root 'controls\server2.json'
$topologyPath = Join-Path $root 'topology.json'
$original = $null
$replacementId = $null
$originalIdentity = $null
$replacementIdentity = $null

foreach ($serviceName in @('coland', 'coauth')) {
$null = New-Item -ItemType Directory -Force -Path $root
$statePath = Join-Path $root "controls\server2-$serviceName.json"
$replacementIdentity = $null
try {
    $shellPath = (Get-Process -Id $PID).Path
    $nodePath = (Get-Command node -ErrorAction Stop).Source
    $portFile = Join-Path $root 'service-port.txt'
    $failureFile = Join-Path $root 'service-failure.txt'
    $serviceScript = Join-Path $root 'output-service.cjs'
    @'
const fs = require('node:fs');
const http = require('node:http');
const [portFile, failureFile] = process.argv.slice(2);
const fail = code => { fs.writeFileSync(failureFile, code); process.exit(1); };
process.on('SIGHUP', () => fail('SIGHUP'));
process.on('uncaughtException', error => fail(error.code || 'uncaughtException'));
const server = http.createServer((request, response) => {
    response.end('ok');
    if (request.url === '/stop') server.close(() => process.exit(0));
});
server.listen(0, '127.0.0.1', () => {
    fs.writeFileSync(portFile, String(server.address().port));
    setInterval(() => process.stdout.write('service-tick\n'), 100);
});
'@ | Set-Content -LiteralPath $serviceScript -Encoding utf8NoBOM
    $quotedNode = "'" + $nodePath.Replace("'", "''") + "'"
    $serviceArguments = @($serviceScript, $portFile, $failureFile) | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }
    $command = "Start-Sleep -Seconds 5; & $quotedNode " + ($serviceArguments -join ' ')
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
    $originalDeadline = [datetime]::UtcNow.AddSeconds(15)
    do {
        if (@(Get-CotestOwnedProcessTree -RootIdentity $originalIdentity).Count -ge 2) { break }
        Start-Sleep -Milliseconds 50
    } while ([datetime]::UtcNow -lt $originalDeadline)
    $topology = [pscustomobject]@{

        server_count = 1
        servers = @([pscustomobject]@{
            name = 'server2'
            $serviceName = [pscustomobject]@{
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
    $topology.servers[0].$serviceName.process_started_at = $wrongIdentity.started_at
    $topology | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $topologyPath -Encoding utf8NoBOM
    $rejected = $false
    try { & $controller -TopologyPath $topologyPath -ServerName server2 -ServiceName $serviceName -Action isolate }
    catch { $rejected = $_.Exception.Message -match 'owned process tree has no service child' }
    if (-not $rejected -or (Test-Path -LiteralPath $statePath)) { throw 'isolate accepted a reused root PID' }
    $topology.servers[0].$serviceName.process_started_at = $originalIdentity.started_at
    $topology | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $topologyPath -Encoding utf8NoBOM

    & $controller -TopologyPath $topologyPath -ServerName server2 -ServiceName $serviceName -Action isolate
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($state.status -ne 'isolated' -or @($state.suspended_process_ids).Count -lt 2) { throw 'isolate did not capture the process tree' }
    if (@($state.suspended_processes).Count -ne @($state.suspended_process_ids).Count -or ([datetime]$state.current_process_started_at).ToUniversalTime() -ne ([datetime]$originalIdentity.started_at).ToUniversalTime()) { throw 'isolate did not preserve process identities' }

    & $controller -TopologyPath $topologyPath -ServerName server2 -ServiceName $serviceName -Action restore
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($state.status -ne 'running') { throw 'restore did not return the process tree to running' }

    Remove-Item -LiteralPath $portFile -Force -ErrorAction SilentlyContinue
    $restartArguments = @('-NoProfile', '-File', $controller, '-TopologyPath', $topologyPath, '-ServerName', 'server2', '-ServiceName', $serviceName, '-Action', 'restart') | ConvertTo-Json -Compress
    & node -e 'require("node:child_process").execFileSync(process.argv[1], JSON.parse(process.argv[2]), { timeout: 60000, windowsHide: true })' $shellPath $restartArguments
    if ($LASTEXITCODE -ne 0) { throw 'the separate piped restart controller failed' }
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    $replacementId = [int]$state.current_process_id
    $replacementIdentity = [pscustomobject]@{ process_id = $replacementId; started_at = $state.current_process_started_at }
    if (@($state.terminated_processes).Count -lt 2) { throw 'restart did not attest the original service child termination' }
    foreach ($identity in @($state.terminated_processes)) {
        if (Get-CotestIdentityProcess -Identity $identity) { throw 'restart retained an original process identity' }
    }
    if (-not $state.restarted -or $replacementId -eq $original.Id -or -not (Get-Process -Id $replacementId -ErrorAction SilentlyContinue)) { throw 'restart did not create a tracked replacement process' }
    if (@(Get-CotestOwnedProcessTree -RootIdentity $replacementIdentity).Count -lt 2) { throw 'restart returned before the actual service child started' }
    Start-Sleep -Seconds 2
    if (Test-Path -LiteralPath $failureFile) {
        $failure = Get-Content -Raw -LiteralPath $failureFile
        throw "restart lost its output-producing native service after the controller exited ($failure)"
    }
    if (-not (Test-Path -LiteralPath $portFile)) { throw 'replacement native service did not open its health listener' }
    $port = [int](Get-Content -Raw -LiteralPath $portFile)
    if ((Invoke-WebRequest -Uri "http://127.0.0.1:$port/health" -TimeoutSec 5).StatusCode -ne 200) { throw 'replacement native service health failed after controller exit' }
    & $controller -TopologyPath $topologyPath -ServerName server2 -ServiceName $serviceName -Action isolate
    & $controller -TopologyPath $topologyPath -ServerName server2 -ServiceName $serviceName -Action restore
    if (-not (Get-CotestIdentityProcess -Identity $replacementIdentity)) { throw 'replacement identity was not usable after isolate/restore' }
    Write-Host "joint-service-control.tests.ps1 ($serviceName): PASS"
} finally {
    if (Test-Path -LiteralPath $portFile) {
        try {
            $port = [int](Get-Content -Raw -LiteralPath $portFile)
            $null = Invoke-WebRequest -Uri "http://127.0.0.1:$port/stop" -TimeoutSec 2
        } catch { }
    }
    foreach ($identity in @($replacementIdentity, $originalIdentity) | Where-Object { $_ }) {
        Stop-CotestOwnedProcessTree -RootIdentity $identity
    }
    $resolvedRoot = [System.IO.Path]::GetFullPath($root)
    if (-not $resolvedRoot.StartsWith($artifactBase + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'test cleanup escaped its artifact directory' }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

}

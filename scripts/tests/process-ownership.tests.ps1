$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\lib\process-ownership.ps1')

$root = [pscustomobject]@{ process_id = 100; started_at = '2026-10-07T01:00:00.0000000Z' }
$snapshot = @(
    [pscustomobject]@{ process_id = 100; parent_process_id = 1; started_at = $root.started_at },
    [pscustomobject]@{ process_id = 101; parent_process_id = 100; started_at = '2026-10-07T01:00:01.0000000Z' },
    [pscustomobject]@{ process_id = 102; parent_process_id = 101; started_at = '2026-10-07T01:00:02.0000000Z' },
    [pscustomobject]@{ process_id = 200; parent_process_id = 100; started_at = '2026-10-04T01:00:00.0000000Z' },
    [pscustomobject]@{ process_id = 201; parent_process_id = 200; started_at = '2026-10-07T01:00:03.0000000Z' },
    [pscustomobject]@{ process_id = 202; parent_process_id = 101; started_at = '2026-10-07T01:00:00.0000000Z' }
)
$selected = @(Select-CotestOwnedProcessTree -RootIdentity $root -Snapshot $snapshot)
if (($selected.process_id -join ',') -ne '100,101,102') { throw 'stale PPID edges or their descendants were accepted' }
$reused = [pscustomobject]@{ process_id = 100; started_at = '2026-10-04T01:00:00.0000000Z' }
if (@(Select-CotestOwnedProcessTree -RootIdentity $reused -Snapshot $snapshot).Count -ne 0) { throw 'reused root PID was accepted' }
if (@(Select-CotestOwnedProcessTree -RootIdentity $root -Snapshot @($snapshot | Where-Object { $_.process_id -ne 100 })).Count -ne 0) { throw 'missing root was accepted' }
$equivalent = [pscustomobject]@{ process_id = 100; started_at = '2026-10-07T09:00:00.0000000+08:00' }
if (@(Select-CotestOwnedProcessTree -RootIdentity $equivalent -Snapshot $snapshot).Count -ne 3) { throw 'equivalent UTC identity was rejected' }
$identity = Get-CotestProcessIdentity -Process (Get-Process -Id $PID)
$process = Get-CotestIdentityProcess -Identity $identity
if (-not $process) { throw 'live process identity was rejected' }
$process.Dispose()
$roundTrip = ($identity | ConvertTo-Json | ConvertFrom-Json)
$process = Get-CotestIdentityProcess -Identity $roundTrip
if (-not $process) { throw 'JSON identity roundtrip lost birth-time precision' }
$process.Dispose()
$identity.started_at = [datetime]::Parse($identity.started_at).AddSeconds(-1).ToUniversalTime().ToString('o')
if (Get-CotestIdentityProcess -Identity $identity) { throw 'live PID with a different birth time was accepted' }
Write-Host 'process-ownership.tests.ps1: PASS'

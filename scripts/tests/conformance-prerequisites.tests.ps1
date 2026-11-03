$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../lib/conformance-prerequisites.ps1')

foreach ($profile in @('all', 'full-nightly')) {
    $requirements = Get-ConformanceNativeRequirements -Profile $profile
    foreach ($field in @('Services', 'Sdk', 'Binding', 'Media', 'RouteEvidence', 'Browser', 'StorageLocks')) {
        if (-not $requirements.$field) { throw "$profile omits required $field" }
    }
}
$server = Get-ConformanceNativeRequirements -Profile all -Package cotest
if (-not $server.Sdk -or -not $server.Binding -or -not $server.Browser -or $server.Media) { throw 'Server-only selection has incorrect prerequisites' }
foreach ($profile in @('all', 'full-nightly')) {
    $clientAll = Get-ConformanceNativeRequirements -Profile $profile -Package cotest-inkson-client-tests
    foreach ($field in @('Services', 'Sdk', 'Binding', 'Media', 'RouteEvidence', 'Browser', 'StorageLocks')) {
        if (-not $clientAll.$field) { throw "Client package selection omits transitive $field" }
    }
}
$agent = Get-ConformanceNativeRequirements -Profile all -Package cotest -Target agent_vectors_production
if (-not $agent.Binding -or -not $agent.Browser -or $agent.Media -or $agent.Sdk) { throw 'Agent production target omits transitive worker or browser prerequisites' }
$media = Get-ConformanceNativeRequirements -Profile all -Package cotest-inkson-client-tests -Target consent_current_production
if (-not $media.Media -or $media.Sdk -or $media.Binding) { throw 'Media target selection has incorrect prerequisites' }
$aggregate = Get-ConformanceNativeRequirements -Profile all -Package cotest-inkson-client-tests -Target conformance_vectors
if (-not $aggregate.Media -or -not $aggregate.Sdk -or -not $aggregate.Binding -or -not $aggregate.RouteEvidence -or -not $aggregate.Browser) { throw 'Registered dispatcher omits transitive prerequisites' }
$storage = Get-ConformanceNativeRequirements -Profile all -Package cotest -Target key_backup_protocol
if (-not $storage.StorageLocks -or $storage.Media -or $storage.Binding -or $storage.Browser) { throw 'Storage target prerequisites are incorrect' }
$fast = Get-ConformanceNativeRequirements -Profile fast-smoke -Target api_contracts_auth
if ($fast.Services -or $fast.Sdk -or $fast.Binding -or $fast.Media -or $fast.RouteEvidence -or $fast.Browser -or $fast.StorageLocks) { throw 'Fast smoke gained unrelated live requirements' }
Write-Host 'conformance-prerequisites.tests.ps1: PASS'

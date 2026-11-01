param([string]$RunnerPath = (Join-Path $PSScriptRoot '../run-joint-e2e.ps1'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($RunnerPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Managed TLS proxy runner must parse' }
foreach ($name in @('Get-ManagedColandBridgeProxyTopology', 'Resolve-ManagedColandTlsProxyPeer', 'Assert-ManagedColandTlsProxyContainer')) {
    $nodes = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true))
    if ($nodes.Count -ne 1) { throw "Expected one pure topology function $name" }
    Invoke-Expression $nodes[0].Extent.Text
}
function New-TestNetwork {
    return ('{"Name":"bridge","Driver":"bridge","Scope":"local","Internal":false,"Id":"' + ('a' * 64) + '","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}') | ConvertFrom-Json -AsHashtable
}
function New-TestContainer {
    return ('{"networks":{"bridge":{"NetworkID":"' + ('a' * 64) + '","Gateway":"172.17.0.1"}},"mode":"default","ports":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18080"}]}}') | ConvertFrom-Json -AsHashtable
}
$count = 0
function Check-Rejected([scriptblock]$Case) {
    $rejected = $false
    try { & $Case | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid managed TLS proxy topology was accepted' }
    $script:count++
}
$n = New-TestNetwork
if ((Resolve-ManagedColandTlsProxyPeer -ManagedHttps $true -Runtime docker -LinuxHost $true -Network $n) -cne '172.17.0.1') { throw 'Actual bridge gateway must be selected' }; $count++
if ((Resolve-ManagedColandTlsProxyPeer -ManagedHttps $true -Runtime binary -LinuxHost $false) -cne '127.0.0.1') { throw 'Managed binary peer must be loopback' }; $count++
if ($null -ne (Resolve-ManagedColandTlsProxyPeer -ManagedHttps $false -Runtime docker -LinuxHost $false)) { throw 'External/direct TLS must not gain proxy trust' }; $count++
Assert-ManagedColandTlsProxyContainer -Network $n -Container (New-TestContainer) -ExpectedPeer '172.17.0.1' -HostPort 18080 -ContainerPort 8080; $count++
# An unrelated host-gateway destination is not passed to either pure source decision.
$hostGatewayDestination = '192.0.2.77'
if ((Resolve-ManagedColandTlsProxyPeer -ManagedHttps $true -Runtime docker -LinuxHost $true -Network $n) -eq $hostGatewayDestination) { throw 'Outbound host-gateway is not inbound proxy evidence' }; $count++
if ($null -ne (Resolve-ManagedColandTlsProxyPeer -ManagedHttps $true -Runtime docker -LinuxHost $false -Network $n)) { throw 'Non-Linux Docker must retain original behavior without guessed proxy trust' }; $count++
if ($null -ne (Resolve-ManagedColandTlsProxyPeer -ManagedHttps $true -Runtime docker -LinuxHost $false)) { throw 'Non-Linux no-topology path must not acquire new trust' }; $count++
Check-Rejected { Resolve-ManagedColandTlsProxyPeer -ManagedHttps $true -Runtime docker -LinuxHost $true }
Check-Rejected { $bad = New-TestNetwork; $bad.IPAM.Config[0].Gateway = ''; Get-ManagedColandBridgeProxyTopology -Network $bad }
Check-Rejected { $bad = New-TestNetwork; $bad.IPAM.Config[0].Gateway = '172.17.0.0/16'; Get-ManagedColandBridgeProxyTopology -Network $bad }
Check-Rejected { $bad = New-TestNetwork; $bad.IPAM.Config[0].Gateway = '172.18.0.1'; Get-ManagedColandBridgeProxyTopology -Network $bad }
Check-Rejected { $bad = New-TestNetwork; $bad.IPAM.Config[0].Gateway = '127.0.0.1'; Get-ManagedColandBridgeProxyTopology -Network $bad }
Check-Rejected { $bad = New-TestNetwork; $bad.Name = 'custom'; Get-ManagedColandBridgeProxyTopology -Network $bad }
Check-Rejected { $bad = New-TestNetwork; $bad.IPAM.Config += @{Subnet='172.18.0.0/16';Gateway='172.18.0.1'}; Get-ManagedColandBridgeProxyTopology -Network $bad }
Check-Rejected { $bad = New-TestContainer; $bad.mode = 'host'; Assert-ManagedColandTlsProxyContainer -Network $n -Container $bad -ExpectedPeer '172.17.0.1' -HostPort 18080 -ContainerPort 8080 }
Check-Rejected { $bad = New-TestContainer; $bad.networks.bridge.Gateway = '172.17.0.2'; Assert-ManagedColandTlsProxyContainer -Network $n -Container $bad -ExpectedPeer '172.17.0.1' -HostPort 18080 -ContainerPort 8080 }
Check-Rejected { $bad = New-TestContainer; $bad.networks.bridge.NetworkID = 'b' * 64; Assert-ManagedColandTlsProxyContainer -Network $n -Container $bad -ExpectedPeer '172.17.0.1' -HostPort 18080 -ContainerPort 8080 }
Check-Rejected { $bad = New-TestContainer; $bad.networks.other = @{}; Assert-ManagedColandTlsProxyContainer -Network $n -Container $bad -ExpectedPeer '172.17.0.1' -HostPort 18080 -ContainerPort 8080 }
Check-Rejected { $bad = New-TestContainer; $bad.ports['8080/tcp'][0].HostIp = '0.0.0.0'; Assert-ManagedColandTlsProxyContainer -Network $n -Container $bad -ExpectedPeer '172.17.0.1' -HostPort 18080 -ContainerPort 8080 }
Check-Rejected { $bad = New-TestContainer; $bad.ports['8080/tcp'][0].HostPort = '18081'; Assert-ManagedColandTlsProxyContainer -Network $n -Container $bad -ExpectedPeer '172.17.0.1' -HostPort 18080 -ContainerPort 8080 }
$source = [IO.File]::ReadAllText($RunnerPath)
if (-not $source.Contains('if ($jointTlsAssets -and $IsLinux) {')) { throw 'New Docker proxy configuration must be Linux scoped' }
if ($source.Contains("throw 'Managed Docker TLS proxy peer requires verified Linux")) { throw 'Do not regress non-Linux managed Docker startup' }
$count++
Write-Output "PASS $count pure managed TLS proxy topology controls (no Docker/network/product execution)"

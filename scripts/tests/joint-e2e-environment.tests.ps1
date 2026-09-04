$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "..\lib\joint-e2e-environment.ps1")

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Equal($Expected, $Actual, [string]$Message) { if ($Expected -ne $Actual) { throw "$Message expected='$Expected' actual='$Actual'" } }

$original = "127.0.0.1 localhost`r`n10.0.0.8 user-owned.example`r`n"
$marker = New-CotestHostsMarker -RunId "unit-1"
$hosts = Get-CotestJointHostNames -ServerCount 3 -IncludeCoauth $true -IncludeUnregisteredProbe $true
$withBlock = Add-CotestHostsBlock -Content $original -Hosts $hosts -Marker $marker
Assert-True ($withBlock.Contains("127.0.0.1`tsoland-server3.local.host")) "server3 Soland host must be present"
Assert-True ($withBlock.Contains("127.0.0.1`tcoauth-server3.local.host")) "server3 Coauth host must be present"
Assert-Equal 1 (@(Get-CotestHostsMarkers -Content $withBlock).Count) "one marker must be discoverable"
$restored = Remove-CotestHostsBlocks -Content $withBlock -Marker $marker
Assert-Equal $original $restored "exact marker cleanup must preserve user content"

$duplicateRejected = $false
try { Add-CotestHostsBlock -Content $withBlock -Hosts $hosts -Marker $marker | Out-Null } catch { $duplicateRejected = $true }
Assert-True $duplicateRejected "duplicate marker insertion must fail closed"
$foreignRejected = $false
try { Add-CotestHostsBlock -Content $original -Hosts @("example.com") -Marker $marker | Out-Null } catch { $foreignRejected = $true }
Assert-True $foreignRejected "foreign host insertion must fail closed"
$stale = Add-CotestHostsBlock -Content $withBlock -Hosts @("soland-server1.local.host") -Marker (New-CotestHostsMarker -RunId "unit-stale")
Assert-Equal $original (Remove-CotestHostsBlocks -Content $stale) "stale cleanup must remove every cotest block and preserve foreign content"
Assert-True ((Test-CotestAdministrator) -is [bool]) "administrator detection must return a boolean"

$topology = New-CotestServerTopology -ServerCount 3 -StartCoauth $true -NetworkShape full-mesh -TlsPort 24443 -RunRoot "C:\cotest-run"
Assert-CotestTopologyIsolation -Topology $topology
Assert-Equal 3 $topology.servers.Count "three servers must be generated"
Assert-Equal "server1" $topology.servers[0].name "numbering starts at server1"
Assert-Equal "https://soland-server3.local.host:24443" $topology.servers[2].soland.public_url "server3 public URL"
Assert-Equal 2 $topology.servers[0].peers.Count "full mesh peer count"
Assert-True ($topology.servers[0].soland.storage.database -ne $topology.servers[1].soland.storage.database) "Soland stores must be isolated"
Assert-True ($topology.servers[0].coauth.storage.database -ne $topology.servers[1].coauth.storage.database) "Coauth stores must be isolated"
$orderedTopology = New-CotestServerTopology -ServerCount 3 -NetworkShape ordered-candidates
Assert-Equal "server3" $orderedTopology.servers[1].candidate_sources[0] "ordered candidates must use a stable cyclic first source"
Assert-Equal "server1" $orderedTopology.servers[1].candidate_sources[1] "ordered candidates must retain the bounded fallback source"

$duplicate = New-CotestServerTopology -ServerCount 2 -StartCoauth $true
$duplicate.servers[1].soland.listen_address = $duplicate.servers[0].soland.listen_address
$isolationRejected = $false
try { Assert-CotestTopologyIsolation -Topology $duplicate } catch { $isolationRejected = $true }
Assert-True $isolationRejected "reused listen address must fail topology validation"

$windowsPlatform = [pscustomobject]@{ os = "windows"; package_managers = @([pscustomobject]@{ name = "winget" }) }
$windowsAdvice = @(Get-CotestCaddyRepairAdvice -PlatformInfo $windowsPlatform)
Assert-True (($windowsAdvice -join "`n") -match "winget (search|exact-search result)") "Windows advice must resolve a package ID before install"
Assert-True (($windowsAdvice -join "`n") -notmatch "apt") "Windows advice must not contain APT"
$linuxPlatform = [pscustomobject]@{ os = "linux"; package_managers = @([pscustomobject]@{ name = "apt-get" }) }
$linuxAdvice = @(Get-CotestCaddyRepairAdvice -PlatformInfo $linuxPlatform)
Assert-True (($linuxAdvice -join "`n") -match "APT") "Debian advice must reference official APT instructions"
Assert-True (($linuxAdvice -join "`n") -notmatch "winget") "Linux advice must not contain winget"

$readyScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "..\run-joint-e2e-ready.ps1")
Assert-True ($readyScript -match '"-ServerCount", "\$ServerCount"') "ready runner must forward ServerCount"
Assert-True ($readyScript -match '"-NetworkShape", \$NetworkShape') "ready runner must forward NetworkShape"
Assert-True ($readyScript -match 'exit \$runnerExit') "ready runner must preserve the runner exit code"
$setupScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "..\setup-joint-e2e-hosts.ps1")
Assert-True ($setupScript -match 'Test-CotestAdministrator') "setup must require administrator identity"
Assert-True ($setupScript -match 'Export-Clixml' -and $setupScript -match 'Get-FileHash') "setup must back up ACLs and checksum the byte backup"
Assert-True ($setupScript -match '\$\{TestUser\}:\(M\)' -and $setupScript -notmatch '(?i)Everyone:\(M\)|Users:\(M\)') "setup must grant Modify only to the named test user"
$restoreScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "..\restore-joint-e2e-hosts.ps1")
Assert-True ($restoreScript -match 'backup_sha256' -and $restoreScript -match 'SetSecurityDescriptorSddlForm') "restore must validate backup integrity and restore the ACL"

Write-Host "joint-e2e-environment.tests.ps1: PASS"

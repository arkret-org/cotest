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
Assert-CotestTopologyIsolation -Topology (New-CotestServerTopology -ServerCount 1 -StartCoauth $true)
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

$runnerScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "..\run-joint-e2e.ps1")
Assert-True ($runnerScript -match 'initialize-joint-e2e-environment\.ps1') "the sole test entry must invoke environment initialization"
Assert-True ($runnerScript -notmatch '\[switch\]\$SkipPreflight') "the test entry must not expose a bootstrap bypass"
Assert-True ($runnerScript -match 'postgres:18\.6-alpine') "the runner must pin PostgreSQL 18.6 Alpine"
Assert-True ($runnerScript -match 'GetEnvironmentVariable\("Path", "Machine"\)' -and $runnerScript -match 'GetEnvironmentVariable\("Path", "User"\)') "the entry must refresh PATH after child-process installation"
Assert-True ($runnerScript -match '\$resolvedStationUrls = @\(if ' -and $runnerScript -match '\$resolvedInksonUrls = @\(if ') "single-server URL collections must remain arrays under strict mode"
Assert-True ($runnerScript -match '\$ServerCount -lt 3.*@three-server-p0') "broad runs without three servers must not select the fail-closed three-server P0 block"
Assert-True ($runnerScript -match 'System\.IO\.StreamWriter' -and $runnerScript -match 'Write-Host \$safeLine') "Playwright output must stream while the suite is running"
Assert-True ($runnerScript -match 'authorization\\s\*.*\[redacted\\\]') "streamed Playwright output must redact authorization credentials before display and persistence"
Assert-True ($runnerScript -match 'Get-JointTopologyHealthFailures' -and $runnerScript -match 'health endpoint was unavailable after test execution') "post-run reporting must detect managed services that are alive but unhealthy"
Assert-True ($runnerScript -match 'required durable-store export failed' -and $runnerScript -match 'durable_store_coverage') "missing PostgreSQL dumps must fail closed instead of producing a successful secret scan"
Assert-True ($runnerScript -match 'runner-error\.log' -and $runnerScript -match '\$_.ScriptStackTrace') "runner setup failures must retain a bounded stack diagnostic"
Assert-True ($runnerScript -match '\$solandStoragePrefix = if \(\$server\.Index -eq 1\).*\r?\n\s*\$solandManaged') "runtime topology storage paths must recompute their per-server prefix"
Assert-True ($runnerScript -match '\$requiredScenarios = @\(@\(\$requiredScenarios; "federation/three-server-p0"\) \| Sort-Object -Unique\)') "one required three-server scenario must remain collection-shaped"
$initializerScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "..\initialize-joint-e2e-environment.ps1")
Assert-True ($initializerScript -match 'Test-CotestAdministrator' -and $initializerScript -match 'if \(\$isAdministrator\)') "initializer must branch on administrator identity"
Assert-True ($initializerScript -match 'mode = "install-and-check"') "dependency installation must be attempted by default"
Assert-True ($initializerScript -match 'if \(\$isAdministrator\) \{\s*\$null = Initialize-CotestWindowsHostsAccess') "only the hosts ACL initializer must be administrator-gated"
Assert-True ($initializerScript.IndexOf('if ($platform.os -eq "windows")') -lt $initializerScript.LastIndexOf('if ($isAdministrator)')) "package installation must run before the administrator-only hosts branch"
Assert-True ($initializerScript -notmatch 'standard user: read-only check|mode = .*check-only') "standard-user dependency handling must not regress to check-only"
Assert-True ($initializerScript -match '\$answers = @\(\[Net\.Dns\]::GetHostAddresses\(\$hostName\)\)') "single DNS answers must remain collection-shaped under strict mode"
Assert-True ($initializerScript -match '@\(Get-CotestHostsMarkers .*\)\.Count') "zero remaining hosts markers must remain collection-shaped under strict mode"
Assert-True ($initializerScript -match '\$actions \| Where-Object \{ \$_.status -eq "failed" \}') "failed installation or hosts actions must fail the environment report"
Assert-True ($initializerScript -match 'recommended_gb=.*minimum_gb=' -and $initializerScript -match 'elseif \(\$availableMemoryGb -ge \$minimumMemoryGb\) \{\s*"warn"') "memory headroom must warn below the recommendation and fail only below the safety floor"
Assert-True ($initializerScript -match 'Export-Clixml' -and $initializerScript -match 'Get-FileHash') "initializer must back up ACLs and checksum the byte backup"
Assert-True ($initializerScript -match '\$\{targetUser\}:\(M\)' -and $initializerScript -notmatch '(?i)Everyone:\(M\)|Users:\(M\)') "initializer must grant Modify only to the selected test user"
Assert-True ($initializerScript -match 'winget\.Source search --name Caddy --exact') "Caddy installation must resolve the current winget package id"
Assert-True ($initializerScript -notmatch '(?m)^\s*&\s*.*restore-joint-e2e-hosts') "initializer must never invoke restore automatically"
$restoreScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "..\restore-joint-e2e-hosts.ps1")
Assert-True ($restoreScript -match 'backup_sha256' -and $restoreScript -match 'SetSecurityDescriptorSddlForm') "restore must validate backup integrity and restore the ACL"

Write-Host "joint-e2e-environment.tests.ps1: PASS"

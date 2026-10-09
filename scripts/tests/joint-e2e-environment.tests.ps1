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
foreach ($newline in @("`r`n", "`n")) {
    $content = "127.0.0.1 localhost${newline}10.0.0.8 user-owned.example${newline}"
    $mockBlock = Add-CotestHostsBlock -Content $content -Hosts (@($hosts) + @(" Mock-Applet-Registry.Local.Host ", "mock-applet-registry.local.host")) -Marker $marker
    Assert-Equal 1 ([regex]::Matches($mockBlock, '(?m)^127\.0\.0\.1\tmock-applet-registry\.local\.host\r?$').Count) "the exact HTTPS Applet mock must have one normalized loopback entry"
    Assert-Equal $content (Remove-CotestHostsBlocks -Content $mockBlock -Marker $marker) "mock hosts cleanup must preserve user content and newline style"
}
foreach ($foreignMock in @("mock-applet-registry.example.com", "mock-applet-registry.local.host.example.com", "other-mock.local.host", "mock-applet-registry2.local.host", "mock-applet-registry.local.host`n192.0.2.1 example.com")) {
    $rejected = $false
    try { Add-CotestHostsBlock -Content $original -Hosts @("mock-applet-registry.local.host", $foreignMock) -Marker $marker | Out-Null } catch { $rejected = $true }
    Assert-True $rejected "a foreign or injected mock host must fail closed: $foreignMock"
}
$stale = Add-CotestHostsBlock -Content $withBlock -Hosts @("soland-server1.local.host") -Marker (New-CotestHostsMarker -RunId "unit-stale")
Assert-Equal $original (Remove-CotestHostsBlocks -Content $stale) "stale cleanup must remove every cotest block and preserve foreign content"
# Blocks written before `b6ab807b` separated the prefix from the stamp with a
# space. Eight of them survived in this machine's hosts file precisely because
# the detector matched only the current colon form, so they are exercised here:
# a sweep that cannot see the old shape cannot clean up after the change that
# introduced the new one.
$legacyBlock = $original +
    "# cotest-joint-e2e 20260827-002729 begin`r`n" +
    "127.0.0.1`tsoland-server1.local.host`r`n" +
    "# cotest-joint-e2e 20260827-002729 end`r`n"
Assert-Equal 1 (@(Get-CotestHostsMarkers -Content $legacyBlock).Count) "the pre-b6ab807b marker form must still be discoverable"
Assert-Equal $original (Remove-CotestHostsBlocks -Content $legacyBlock) "stale cleanup must remove pre-b6ab807b blocks too"
$mixed = Add-CotestHostsBlock -Content $legacyBlock -Hosts $hosts -Marker (New-CotestHostsMarker -RunId "unit-mixed")
Assert-Equal 2 (@(Get-CotestHostsMarkers -Content $mixed).Count) "both marker forms must be reported together"
Assert-Equal $original (Remove-CotestHostsBlocks -Content $mixed) "a sweep must clear both forms in one pass"

Assert-True ((Test-CotestAdministrator) -is [bool]) "administrator detection must return a boolean"

$runRoot = Join-Path ([System.IO.Path]::GetTempPath()) "cotest-topology-unit"
$topology = New-CotestServerTopology -ServerCount 3 -StartCoauth $true -NetworkShape full-mesh -TlsPort 24443 -RunRoot $runRoot
Assert-CotestTopologyIsolation -Topology $topology
Assert-CotestTopologyIsolation -Topology (New-CotestServerTopology -ServerCount 1 -StartCoauth $true)
Assert-Equal 3 $topology.servers.Count "three servers must be generated"
Assert-Equal "server1" $topology.servers[0].name "numbering starts at server1"
Assert-Equal "https://soland-server3.local.host:24443" $topology.servers[2].soland.public_url "server3 public URL"
Assert-Equal 2 $topology.servers[0].peers.Count "full mesh peer count"
Assert-CotestLoopbackDns -Hosts @('127.0.0.1', '::1')
$publicDnsRejected = $false
try { Assert-CotestLoopbackDns -Hosts @('127.0.0.1', '192.0.2.1') } catch { $publicDnsRejected = $true }
Assert-True $publicDnsRejected "a non-loopback answer must reject the topology"
$localhostTopology = New-CotestServerTopology -ServerCount 3 -StartCoauth $true -TlsPort 24443 -DnsSuffix localhost
Assert-CotestTopologyIsolation -Topology $localhostTopology
Assert-Equal 'https://soland-server3.localhost:24443' $localhostTopology.servers[2].soland.public_url "localhost topology must retain indexed TLS identities"
Assert-Equal 'https://unregistered.localhost:24443' $localhostTopology.unregistered_probe "unregistered localhost probe must remain a separate host"
Assert-Equal 7 @(Get-CotestJointHostNames -ServerCount 3 -DnsSuffix localhost).Count "localhost topology must retain every service and negative probe host"
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
Assert-True ($runnerScript -match '\$allSolandBaseUrls = @\(\$SolandBaseUrl, \$solandServer2BaseUrl\) \+ @\(\$additionalServers \| ForEach-Object \{ \$_.SolandBaseUrl \}\) \| Where-Object \{ \$_ \}' -and
    $runnerScript -match 'New-StationInternalChannelBindings\s+`\s*-StationBaseUrls \$allSolandBaseUrls' -and
    $runnerScript -match '\$resolvedInksonUrls = @\(if ') "single-server Station and Inkson URL collections must remain arrays and feed indexed Station bindings under strict mode"
Assert-True ($runnerScript -match '\$ServerCount -lt 3.*@three-server-p0') "broad runs without three servers must not select the fail-closed three-server P0 block"
Assert-True ($runnerScript -match 'System\.IO\.StreamWriter' -and $runnerScript -match 'Write-Host \$safeLine') "Playwright output must stream while the suite is running"
Assert-True ($runnerScript -match 'authorization\\s\*.*\[redacted\\\]') "streamed Playwright output must redact authorization credentials before display and persistence"
Assert-True ($runnerScript -match 'Get-JointTopologyHealthFailures' -and $runnerScript -match 'health endpoint was unavailable after test execution') "post-run reporting must detect managed services that are alive but unhealthy"
Assert-True ($runnerScript -match 'required durable-store export failed' -and $runnerScript -match 'durable_store_coverage') "missing PostgreSQL dumps must fail closed instead of producing a successful secret scan"
Assert-True ($runnerScript -match 'runner-error\.log' -and $runnerScript -match '\$_.ScriptStackTrace') "runner setup failures must retain a bounded stack diagnostic"
Assert-True ($runnerScript -match '\$solandStoragePrefix = if \(\$server\.Index -eq 1\).*\r?\n\s*\$solandManaged') "runtime topology storage paths must recompute their per-server prefix"
Assert-True ($runnerScript -match '\$requiredScenarios = @\(@\(\$requiredScenarios; "federation/three-server-p0"\) \| Sort-Object -Unique\)') "one required three-server scenario must remain collection-shaped"
Assert-True ($runnerScript -match '-Hosts \(@\(\$jointTlsHostNames\) \+ @\(\$jointTlsUnregisteredProbeHost\)\)') "single-server TLS hosts must remain an array when the unregistered probe is appended"
$initializerScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "..\initialize-joint-e2e-environment.ps1")
Assert-True ($initializerScript -match 'Test-CotestAdministrator' -and $initializerScript -match 'if \(\$isAdministrator\)') "initializer must branch on administrator identity"
Assert-True ($initializerScript -match 'mode = "install-and-check"') "dependency installation must be attempted by default"
Assert-True ($initializerScript -match 'if \(\$RequireBrowser -and \$npx' -and $runnerScript -match 'if \(\$requiresInkson\) \{ \$environmentArgs \+= "-RequireBrowser" \}') "browserless joint-api must not install Chromium"
Assert-True ($runnerScript -match 'if \(\$RequiresInkson\) \{\s*\$browserListOutput') "browserless preflight must not require the Playwright browser registry"
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

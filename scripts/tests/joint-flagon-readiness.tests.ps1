param([string]$RunnerPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $RunnerPath) { $RunnerPath = Join-Path $PSScriptRoot '../run-joint-e2e.ps1' }
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($RunnerPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Runner must parse before its readiness regression' }
foreach ($name in @('Test-JointLoopbackUrl', 'Wait-HttpReady', 'Write-JointCaddyConfig', 'Install-JointLoopbackHosts', 'Remove-JointLoopbackHosts', 'Get-JointFlagonDescription')) {
    $functions = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name}, $true))
    if ($functions.Count -ne 1) { throw "Expected exactly one real runner function $name" }
    Invoke-Expression $functions[0].Extent.Text
}
$shell = (Get-Process -Id $PID).Path
$arguments = @{ FilePath = $shell; ArgumentList = @('-NoProfile', '-Command', 'exit 23'); PassThru = $true }
if ($IsWindows) { $arguments.WindowStyle = 'Hidden' }
$process = Start-Process @arguments
if (-not $process.WaitForExit(10000)) { throw 'Exit fixture did not exit naturally' }
if ($process.ExitCode -ne 23) { throw 'Exit fixture did not produce the real expected exit status' }
$failure = $null
try { Wait-HttpReady -Url 'http://127.0.0.1:1/health' -TimeoutSeconds 30 -ManagedService ([pscustomobject]@{ Kind = 'process'; Name = 'flagon-exited-fixture'; Process = $process }) }
catch { $failure = $_.Exception.Message }
if ($failure -cne 'Managed service flagon-exited-fixture exited before readiness; see its service logs') { throw "Expected existing managed-process fail-fast, got: $failure" }
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('cotest-flagon-caddy-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary
try {
$config = Join-Path $temporary 'Caddyfile'
Write-JointCaddyConfig -Path $config -TlsPort 44321 -CertificatePath 'D:/fixture/public.crt' -KeyPath 'D:/fixture/private.key' -Routes @([pscustomobject]@{ Host = 'flagon.local.host'; BackendPort = 44322; DidRoot = 'D:/fixture/public identity' })
$content = Get-Content -LiteralPath $config -Raw
foreach ($expected in @('https://flagon.local.host:44321 {', '@directoryIdentity path /webvh/flagon/did.json /webvh/flagon/did.jsonl', 'handle @directoryIdentity {', 'root * "D:/fixture/public identity"', 'reverse_proxy 127.0.0.1:44322')) {
    if (-not $content.Contains($expected)) { throw "Missing exact Directory route: $expected" }
}
if ($content.Contains('handle /webvh/*') -or $content.Contains('file_server browse')) { throw 'Directory identity route must not expose a broader filesystem view' }

# Evaluate the exact two production argument hashtables, not copied miniature
# expressions. A WebVH-only helper must never be entered for did:web input.
$verifyCommands = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'Invoke-JointFlagonIdentity' -and
    $node.Extent.Text.Contains("-Command 'verify-remote'")
}, $true))
if ($verifyCommands.Count -ne 2) { throw 'Expected owned/external actual verification argument paths' }
$env:COTEST_WIRE_BIN = 'D:/fixture/cotest-wire.exe'
$jointDir = $temporary
$flagonIdentityDirectory = $null
$jointTlsFlagon = $false
$jointTlsAssets = $null
$FlagonBaseUrl = 'https://directory.example'
$FlagonServiceDid = 'did:web:directory.example'
$FlagonServiceMethodHistoryHead = 'sha256:' + ('a' * 64)
$FlagonServiceVersionId = 'synthetic-jcs-sha256:' + ('a' * 64)
$flagonDescribe = [pscustomobject]@{ service_resolution = [pscustomobject]@{
    did = $FlagonServiceDid; method_history_head = $FlagonServiceMethodHistoryHead; version_id = $FlagonServiceVersionId
} }
function Get-WebvhLogUrlFromDid { param($Did) throw 'did:web entered the WebVH-only helper' }
foreach ($command in $verifyCommands) {
    $tables = @($command.FindAll({param($node) $node -is [Management.Automation.Language.HashtableAst]}, $false))
    if ($tables.Count -ne 1) { throw 'Expected one actual verify-remote input table' }
    $evaluated = Invoke-Expression $tables[0].Extent.Text
    if ($evaluated.did -cne 'did:web:directory.example' -or $null -ne $evaluated.logUrl) { throw 'did:web verification arguments did not preserve the explicit no-history path' }
}
# Exercise the actual hosts lifecycle against an isolated file, never system hosts.
. (Join-Path $PSScriptRoot '../lib/joint-e2e-environment.ps1')
$script:directoryHostsFixture = Join-Path $temporary 'hosts'
function Get-CotestHostsPath { return $script:directoryHostsFixture }
$originalHosts = "127.0.0.1 localhost`r`n192.0.2.10 user-owned.example`r`n"
[IO.File]::WriteAllText($script:directoryHostsFixture, $originalHosts, [Text.UTF8Encoding]::new($false))
$directoryMarker = New-CotestHostsMarker -RunId 'directory-lifecycle'
Install-JointLoopbackHosts -Hosts (Get-CotestJointHostNames -ServerCount 3 -IncludeFlagon $true) -Marker $directoryMarker
$installedHosts = [IO.File]::ReadAllText($script:directoryHostsFixture)
if (-not $installedHosts.Contains("127.0.0.1`tflagon.local.host")) { throw 'Real installer omitted the managed Directory host' }
Remove-JointLoopbackHosts -Marker $directoryMarker
if ([IO.File]::ReadAllText($script:directoryHostsFixture) -cne $originalHosts) { throw 'Real Directory host cleanup changed unrelated hosts' }
# Select the registered Directory binding rather than the Station shared path.
$script:directoryDescribeRequest = $null
function Invoke-RestMethod {
    [CmdletBinding()]
    param($Uri, $Method, $Headers, [switch]$NoProxy, $TimeoutSec, [switch]$SkipCertificateCheck)
    $script:directoryDescribeRequest = @{ uri = [string]$Uri; method = [string]$Method; headers = $Headers }
    return [pscustomobject]@{ service_kind = 'directory_service' }
}
Get-JointFlagonDescription -BaseUrl 'https://directory.example/' | Out-Null
if ($script:directoryDescribeRequest.uri -cne 'https://directory.example/_arkret/find/directory/describe' -or
    $script:directoryDescribeRequest.method -cne 'Get' -or
    $script:directoryDescribeRequest.headers['Arkret-Operation'] -cne 'ak.find.directory.read.describe.v1') {
    throw 'Directory startup description must use its registered path and exact selector'
}
Write-Host 'joint-flagon-readiness.tests.ps1: PASS (real exited process, exact public-file route, did:web paths, real hosts lifecycle, Directory binding)'
} finally {
    $temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedTemporary = [IO.Path]::GetFullPath($temporary)
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    if (-not $resolvedTemporary.StartsWith($temporaryParent, $comparison) -or [IO.Path]::GetFileName($resolvedTemporary) -notlike 'cotest-flagon-caddy-*') { throw 'Readiness test cleanup escaped its unique temporary directory' }
    Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
}

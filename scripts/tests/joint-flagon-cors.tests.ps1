param([Parameter(Mandatory=$true)][string]$CaddyPath, [Parameter(Mandatory=$true)][string]$EvidenceDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
if ($IsWindows -and -not $evidence.StartsWith('D:\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Transport evidence must be on D' }
if (Test-Path -LiteralPath $evidence) { throw 'Transport evidence directory must be new' }
$null = New-Item -ItemType Directory -Path $evidence
$runner = Join-Path $PSScriptRoot '../run-joint-e2e.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Runner must parse before transport regression' }
foreach ($name in @('Find-CommandPath', 'Find-OpenSslPath', 'New-JointTlsAssets', 'Write-JointCaddyConfig')) {
    $function = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name}, $true))
    if ($function.Count -ne 1) { throw "Expected exactly one runner function $name" }
    Invoke-Expression $function[0].Extent.Text
}
function New-TestPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return $listener.LocalEndpoint.Port } finally { $listener.Stop() }
}
$tlsPort = New-TestPort
$backendPort = New-TestPort
$assets = New-JointTlsAssets -Directory (Join-Path $evidence 'tls') -DnsNames @('localhost') -RunLabel 'directory-cors-regression'
$public = Join-Path $evidence 'public'
$null = New-Item -ItemType Directory -Path (Join-Path $public 'webvh/flagon')
foreach ($leaf in @('did.json', 'did.jsonl')) {
    [IO.File]::WriteAllText((Join-Path $public "webvh/flagon/$leaf"), "{`"public`":`"fixture`"}`n", [Text.UTF8Encoding]::new($false))
}
$config = Join-Path $evidence 'Caddyfile'
Write-JointCaddyConfig -Path $config -TlsPort $tlsPort -CertificatePath $assets.ServerPemPath -KeyPath $assets.ServerKeyPath -Routes @(
    [pscustomobject]@{ Host = 'localhost'; BackendPort = $backendPort; DidRoot = $public; CorsOrigins = @('http://127.0.0.1:41001/', 'http://127.0.0.1:41002', 'http://127.0.0.1:41001/') }
)
$text = Get-Content -LiteralPath $config -Raw
if ($text.Contains('Access-Control-Allow-Credentials') -or $text.Contains('Access-Control-Allow-Origin *')) { throw 'Managed public CORS must not admit credentials or wildcard origins' }
foreach ($origin in @('http://127.0.0.1:41001', 'http://127.0.0.1:41002')) {
    if ([regex]::Matches($text, [regex]::Escape("header Origin `"$origin`"")).Count -ne 1) { throw 'Expected exact normalized distinct origins' }
}
$backendScript = Join-Path $evidence 'backend.mjs'
[IO.File]::WriteAllText($backendScript, @'
import http from 'node:http';
const known = new Set(['/_arkret/find/directory/describe', '/_arkret/find/directory/search-realms', '/_arkret/find/directory/resolve-realm']);
http.createServer((req,res) => { res.writeHead(req.method === 'OPTIONS' ? 204 : known.has(req.url) ? 200 : 404, {'Content-Type':'application/json'}); res.end(req.method === 'OPTIONS' ? '' : '{}'); }).listen(Number(process.argv[2]), '127.0.0.1');
'@, [Text.UTF8Encoding]::new($false))
$oldData = $env:XDG_DATA_HOME; $oldConfig = $env:XDG_CONFIG_HOME
$env:XDG_DATA_HOME = Join-Path $evidence 'caddy-data'
$env:XDG_CONFIG_HOME = Join-Path $evidence 'caddy-config'
$processes = @()
try {
    & $CaddyPath adapt --config $config --adapter caddyfile --pretty 1> (Join-Path $evidence 'adapt.json') 2> (Join-Path $evidence 'adapt.stderr.log')
    if ($LASTEXITCODE) { throw "Caddy adapt failed: $LASTEXITCODE" }
    & $CaddyPath validate --config $config --adapter caddyfile 1> (Join-Path $evidence 'validate.log') 2> (Join-Path $evidence 'validate.stderr.log')
    if ($LASTEXITCODE) { throw "Caddy validate failed: $LASTEXITCODE" }
    $backendArgs = @{ FilePath = (Get-Command node).Source; ArgumentList = @($backendScript, [string]$backendPort); PassThru = $true; RedirectStandardOutput = (Join-Path $evidence 'backend.stdout.log'); RedirectStandardError = (Join-Path $evidence 'backend.stderr.log') }
    $caddyArgs = @{ FilePath = $CaddyPath; ArgumentList = @('run', '--config', $config, '--adapter', 'caddyfile'); PassThru = $true; RedirectStandardOutput = (Join-Path $evidence 'caddy.stdout.log'); RedirectStandardError = (Join-Path $evidence 'caddy.stderr.log') }
    if ($IsWindows) { $backendArgs.WindowStyle = 'Hidden'; $caddyArgs.WindowStyle = 'Hidden' }
    $processes += Start-Process @backendArgs
    $processes += Start-Process @caddyArgs
    foreach ($port in @($backendPort, $tlsPort)) {
        $ready = $false; $deadline = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $deadline) {
            if (@($processes | Where-Object HasExited).Count) { throw 'Owned transport process exited before readiness' }
            $tcp = [Net.Sockets.TcpClient]::new()
            try { $tcp.Connect('127.0.0.1', $port); $ready = $true; break } catch { Start-Sleep -Milliseconds 50 } finally { $tcp.Dispose() }
        }
        if (-not $ready) { throw "Owned transport port $port did not become ready" }
    }
    & node (Join-Path $PSScriptRoot 'joint-flagon-cors.test.mjs') $tlsPort $assets.CaPemPath 1> (Join-Path $evidence 'result.json') 2> (Join-Path $evidence 'test.stderr.log')
    if ($LASTEXITCODE) { throw "Real Caddy transport regression failed: $LASTEXITCODE" }
    Write-Host "PASS real Caddy transport regression: $evidence/result.json"
} finally {
    $cleanup = @()
    foreach ($process in $processes) {
        if (-not $process.HasExited) { $process.Kill(); $null = $process.WaitForExit(10000) }
        if (-not $process.HasExited) { throw "Owned process $($process.Id) survived cleanup" }
        $cleanup += [pscustomobject]@{ process_id = $process.Id; exited = $process.HasExited }
    }
    ConvertTo-Json -InputObject $cleanup | Set-Content -LiteralPath (Join-Path $evidence 'cleanup.json') -Encoding utf8NoBOM
    $env:XDG_DATA_HOME = $oldData; $env:XDG_CONFIG_HOME = $oldConfig
}

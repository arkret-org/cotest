param(
    [Parameter(Mandatory = $true)][string]$BinaryPath,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory
)

# Uses the existing managed deployment and canonical Garth journey. It starts
# neither services nor a browser, installs nothing and never invokes Cargo.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
if (-not $IsWindows) { throw 'This regression checks the Windows PE default main stack' }
if (-not $evidence.StartsWith('D:\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence must be on D' }
if (Test-Path -LiteralPath $evidence) { throw 'Evidence directory must be new' }
$null = New-Item -ItemType Directory -Path $evidence

$stream = [IO.File]::OpenRead($binary)
$reader = [IO.BinaryReader]::new($stream)
try {
    $stream.Position = 0x3c
    $peOffset = $reader.ReadUInt32()
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550) { throw 'Provision bridge is not a PE executable' }
    $optionalHeader = $peOffset + 24
    $stream.Position = $optionalHeader
    if ($reader.ReadUInt16() -ne 0x20b) { throw 'Expected a PE32+ provision bridge' }
    $stream.Position = $optionalHeader + 72
    $stackReserve = $reader.ReadUInt64()
} finally { $reader.Dispose() }
if ($stackReserve -ne 1048576) { throw "Expected the original 1 MiB default main stack, got $stackReserve" }

$cli = Join-Path $repoRoot 'e2e/node_modules/playwright/cli.js'
if (-not (Test-Path -LiteralPath $cli)) { throw 'Use the already installed Playwright CLI from the managed run' }
$node = (Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$oldEnvironment = @{}
foreach ($name in @('RUST_MIN_STACK', 'COTEST_PROVISION_BIN', 'COTEST_JOINT_RUN_DIR')) {
    $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$before = @(Get-Process -Name 'cotest-provision' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
$result = [ordered]@{
    binary = $binary
    binary_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    stack_reserve = $stackReserve
    rust_min_stack_present = $false
    selector = 'Garth commits a two-member Realm, exchanges messages and resumes a rebuilt runtime'
    project = 'joint-api'
    passed = $false
    exit_code = $null
    new_bridge_processes_remaining = @()
}
try {
    Remove-Item Env:RUST_MIN_STACK -ErrorAction SilentlyContinue
    $env:COTEST_PROVISION_BIN = $binary
    $env:COTEST_JOINT_RUN_DIR = Join-Path $evidence 'journey'
    Push-Location (Join-Path $repoRoot 'e2e')
    try {
        & $node $cli test 'tests/harness/garth-client.spec.ts' --project=joint-api --workers=1 --retries=0 --grep $result.selector 1> (Join-Path $evidence 'stdout.log') 2> (Join-Path $evidence 'stderr.log')
        $result.exit_code = $LASTEXITCODE
    } finally { Pop-Location }
    if ($result.exit_code -ne 0) { throw "Default-stack Garth journey failed with exit $($result.exit_code)" }
    [xml]$junit = Get-Content -LiteralPath (Join-Path $env:COTEST_JOINT_RUN_DIR 'junit.xml') -Raw
    $cases = @($junit.SelectNodes('//testcase'))
    if ($cases.Count -ne 1 -or $cases[0].SelectNodes('failure|error|skipped').Count -ne 0) {
        throw 'Require exactly one executed successful full Garth journey, with no skipped or failed case'
    }
    # That existing journey checks real two-member commits/messages, durable cursor,
    # whole-process loss/reopen and original Commit equality; no reduced probe substitutes it.
    $result.passed = $true
} finally {
    $result.new_bridge_processes_remaining = @(
        Get-Process -Name 'cotest-provision' -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -notin $before -and $_.Path -eq $binary } |
        Select-Object -ExpandProperty Id
    )
    if ($result.new_bridge_processes_remaining.Count -ne 0) { $result.passed = $false }
    foreach ($name in $oldEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $oldEnvironment[$name], 'Process')
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'result.json') -Encoding utf8
}
if (-not $result.passed) { throw 'The default-stack journey left a bridge process running' }

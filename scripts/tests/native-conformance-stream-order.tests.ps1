[CmdletBinding()]
param([string]$RepoRoot = (Join-Path $PSScriptRoot '../..'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepoRoot 'scripts/run-server-conformance.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Invalid production runner syntax' }
$definitions = foreach ($name in @('Add-RawLogLine', 'ConvertTo-NativeCommandLineArgument', 'Invoke-CargoTestInvocation', 'Parse-CotestLog')) {
    $node = $ast.Find({param($value)
        $value -is [Management.Automation.Language.FunctionDefinitionAst] -and $value.Name -eq $name
    }, $true)
    if (-not $node) { throw "Missing production function $name" }
    $node.Extent.Text
}
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'artifacts/tool-tests'))
$scratch = Join-Path $artifactRoot ('native stream fixture ' + [Guid]::NewGuid().ToString('N'))
foreach ($directory in @('scripts', 'src', 'tests')) {
    $null = New-Item -ItemType Directory -Path (Join-Path $scratch $directory) -Force
}
try {
    [IO.File]::WriteAllText((Join-Path $scratch 'Cargo.toml'), @'
[package]
name = 'native_stream_fixture'
version = '0.1.0'
edition = '2021'
[workspace]
'@)
    [IO.File]::WriteAllText((Join-Path $scratch 'src/lib.rs'), '')
    [IO.File]::WriteAllText((Join-Path $scratch 'tests/first.rs'), @'
use std::sync::Barrier;
static START: Barrier = Barrier::new(2);
#[test]
fn same_name() {
    START.wait();
    println!("fixture stdout diagnostic");
    std::thread::yield_now();
    eprintln!("fixture stderr diagnostic");
    assert_eq!(1, 1);
}
#[test]
fn concurrent_noise() {
    START.wait();
    for _ in 0..64 {
        println!("parallel stdout diagnostic");
        eprintln!("parallel stderr diagnostic");
        std::thread::yield_now();
    }
}
#[test]
#[ignore = "native fixture reason"]
fn ignored_case() {}
'@)
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'scripts/run-native-rust-tests.py') -Destination (Join-Path $scratch 'scripts/run-native-rust-tests.py')
    $body = @'
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Resolve-ConformancePython {
    param([AllowNull()][string]$ExplicitPath)
    if ($ExplicitPath) { return $ExplicitPath }
    foreach ($name in @('python3', 'python')) {
        $python = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($python) { return $python.Source }
    }
    throw 'Real native stream fixture requires Python'
}
# This std-only fixture is independent of an outer native workspace plan.
Remove-Item Env:COTEST_NATIVE_WORKSPACE_PLAN -ErrorAction SilentlyContinue
$env:CARGO_TERM_COLOR = 'always'
$root = Split-Path $PSScriptRoot -Parent
$manifest = Join-Path $root 'Cargo.toml'
$wrapper = Join-Path $PSScriptRoot 'run-native-rust-tests.py'
$parallelSource = [IO.File]::ReadAllText((Join-Path $root 'tests/first.rs'))
foreach ($threads in @(1, 2)) {
    $firstSource = $parallelSource.Replace('Barrier::new(2)', "Barrier::new($threads)")
    [IO.File]::WriteAllText((Join-Path $root 'tests/first.rs'), $firstSource)
    foreach ($negative in @($false, $true)) {
        $source = $firstSource
        if ($negative) { $source = $source.Replace('assert_eq!(1, 1);', 'assert_eq!(1, 2);') }
        [IO.File]::WriteAllText((Join-Path $root 'tests/second.rs'), $source)
        $raw = Join-Path $root ("threads-$threads-" + $(if ($negative) { 'negative.log' } else { 'positive.log' }))
        $exitCode = Invoke-CargoTestInvocation -CargoArgs @(
            'test', '--offline', '--manifest-path', $manifest, '--tests', '--jobs', '1', '--', '--nocapture', "--test-threads=$threads"
        ) -RawLog $raw -Label 'cotest/all-tests//'
        $expectedExit = if ($negative) { 101 } else { 0 }
        if ($exitCode -ne $expectedExit) { throw "Real Cargo exit changed: $exitCode, expected $expectedExit" }
        $rawText = [IO.File]::ReadAllText($raw)
        foreach ($channel in @('stdout', 'stderr')) {
            if ([regex]::Matches($rawText, "fixture $channel diagnostic").Count -ne 2) {
                throw "Real test-body $channel diagnostics were lost or duplicated"
            }
        }
        $parsed = Parse-CotestLog -LogPath $raw
        $cases = @($parsed.tests | Where-Object name -CEQ 'same_name')
        if ($cases.Count -ne 2 -or @($cases.invocation | Sort-Object -Unique).Count -ne 2) {
            throw 'Two real same-named tests must retain their separate binary identity'
        }
        if ($parsed.integrity -cne 'passed' -or $parsed.footer_totals.passed -ne (4 - [int]$negative) -or
            $parsed.footer_totals.failed -ne [int]$negative -or $parsed.footer_totals.ignored -ne 2) {
            throw 'Real libtest results and footer counts must reconcile without hiding a failure'
        }
        if (@($parsed.tests | Where-Object { $_.status -ceq 'ignored' -and $_.reason -ceq 'native fixture reason' }).Count -ne 2) {
            throw 'Real ignored tests must retain their reasons and binary identity'
        }
    }
}
# The no-run machine channel stays pure Cargo JSON; normal stream framing must
# not insert compiler progress or diagnostics into artifact discovery records.
$messages = Join-Path $root 'cargo-messages.jsonl'
$python = Resolve-ConformancePython $env:COTEST_PYTHON_BIN
$cargo = (Get-Command cargo -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
& $python -B $wrapper --cargo-messages $messages $cargo test --offline --manifest-path $manifest --tests --no-run --message-format=json --jobs 1
if ($LASTEXITCODE -ne 0) { throw 'Real Cargo JSON no-run fixture failed' }
$records = @(Get-Content -LiteralPath $messages | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
if (@($records | Where-Object reason -CEQ 'compiler-artifact').Count -lt 3 -or
    @($records | Where-Object reason -CEQ 'build-finished').Count -ne 1) {
    throw 'The machine channel lost real Cargo artifact or completion records'
}
Write-Host 'Native stream order: PASS (real two-binary serial/parallel stdout/stderr success/failure, original exit, distinct identity, pure JSON no-run channel; no service/business execution)'
'@
    $child = Join-Path $scratch 'scripts/run-fixture.ps1'
    [IO.File]::WriteAllText($child, ($definitions -join "`n") + "`n" + $body)
    & (Get-Process -Id $PID).Path -NoProfile -File $child
    if ($LASTEXITCODE -ne 0) { throw 'Real native stream order regression failed' }
} finally {
    $prefix = $artifactRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not [IO.Path]::GetFullPath($scratch).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Fixture cleanup escaped its owned artifact root'
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}

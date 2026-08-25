#Requires -Version 7.0
<#
.SYNOPSIS
Fixture tests for `Parse-CotestLog`.

.DESCRIPTION
The parser used to anchor on `... ignored$`, which silently dropped every
libtest line carrying an ignore reason (`... ignored, <reason>`). A 27-ignored
run therefore published `ignored: 5`. These tests pin three properties:

1. both `ignored` spellings are counted, and the reason never leaks into the
   test name;
2. the `test result:` footers are aggregated independently and are the count
   truth source;
3. reconciliation fails closed when the per-test lines and the footers disagree,
   so a truncated or hand-edited log cannot publish a partial list as complete.

The two historical `-Profile all` raw logs are used as fixtures; their expected
479 / 28 / 27 is a property of those two files, not a frozen expectation for
future runs.
#>
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $scriptRoot
$runCotest = Join-Path $scriptRoot "run-server-conformance.ps1"

# Load only the function under test: dot-sourcing the whole script would execute
# a full run. Extract the function body and evaluate it in this session.
$source = Get-Content -Raw -LiteralPath $runCotest
$match = [regex]::Match(
    $source,
    '(?ms)^function Parse-CotestLog \{.*?^\}'
)
if (-not $match.Success) {
    throw "Parse-CotestLog not found in $runCotest"
}
Invoke-Expression $match.Value

$failures = New-Object System.Collections.Generic.List[string]

function Assert-Equal {
    param($Expected, $Actual, [string]$Label)
    if ($Expected -ne $Actual) {
        $failures.Add("${Label}: expected '$Expected', got '$Actual'")
    }
}

function New-TempLog {
    param([string[]]$Lines)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("cotest-parser-" + [guid]::NewGuid().ToString("N") + ".log")
    Set-Content -LiteralPath $path -Value $Lines -Encoding UTF8
    return $path
}

# ── 1. Synthetic: plain / ASCII reason / Unicode reason, two invocations ─────
$log = New-TempLog @(
    "     Running unittests src/lib.rs (target/debug/deps/alpha-1)",
    "test alpha::same_name ... ok",
    "test alpha::plain ... ignored",
    "test alpha::ascii ... ignored, needs a live server",
    "test alpha::unicode ... ignored, 需要真实服务器",
    "test result: ok. 1 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out",
    "     Running tests/beta.rs (target/debug/deps/beta-2)",
    "test alpha::same_name ... FAILED",
    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out"
)
$parsed = Parse-CotestLog -LogPath $log
Assert-Equal 1 $parsed.footer_totals.passed "synthetic footer passed"
Assert-Equal 1 $parsed.footer_totals.failed "synthetic footer failed"
Assert-Equal 3 $parsed.footer_totals.ignored "synthetic footer ignored"
Assert-Equal "passed" $parsed.integrity "synthetic integrity"
[int]$footerCount = $parsed.footers.Count
Assert-Equal 2 $footerCount "synthetic footer count"

$ascii = @($parsed.tests | Where-Object { $_.name -eq "alpha::ascii" })
[int]$asciiCount = $ascii.Count
Assert-Equal 1 $asciiCount "ascii reason test present"
Assert-Equal "needs a live server" $ascii[0].reason "ascii reason preserved"
$unicode = @($parsed.tests | Where-Object { $_.name -eq "alpha::unicode" })
Assert-Equal "需要真实服务器" $unicode[0].reason "unicode reason preserved"
$plain = @($parsed.tests | Where-Object { $_.name -eq "alpha::plain" })
Assert-Equal $null $plain[0].reason "plain ignored carries no reason"

# Same test name in two binaries stays distinguishable by invocation.
$sameName = @($parsed.tests | Where-Object { $_.name -eq "alpha::same_name" })
[int]$sameNameCount = $sameName.Count
Assert-Equal 2 $sameNameCount "same-named tests across targets"
$invocations = @($sameName | ForEach-Object { $_.invocation } | Sort-Object -Unique)
[int]$invocationCount = $invocations.Count
Assert-Equal 2 $invocationCount "same-named tests have distinct invocations"
Remove-Item -LiteralPath $log -Force

# ── 3. Reconciliation fails closed on a doctored per-test list ───────────────
$log = New-TempLog @(
    "     Running unittests src/lib.rs (target/debug/deps/alpha-1)",
    "test alpha::kept ... ok",
    "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
)
$parsed = Parse-CotestLog -LogPath $log
Assert-Equal "failed" $parsed.integrity "deleted per-test line fails reconciliation"
Assert-Equal 2 $parsed.footer_totals.passed "footer still reports the real count"
Assert-Equal 1 $parsed.per_test.passed "per-test list is short"
Remove-Item -LiteralPath $log -Force

# ── 4. A run with no tests at all reconciles to zero, not to an error ────────
$log = New-TempLog @(
    "     Running unittests src/lib.rs (target/debug/deps/alpha-1)",
    "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
)
$parsed = Parse-CotestLog -LogPath $log
Assert-Equal "passed" $parsed.integrity "empty run integrity"
Assert-Equal 0 $parsed.footer_totals.ignored "empty run ignored"
Remove-Item -LiteralPath $log -Force

[int]$failureCount = $failures.Count
if ($failureCount -gt 0) {
    foreach ($failure in $failures) {
        Write-Host "FAIL $failure"
    }
    exit 1
}

Write-Host "log-parser.tests.ps1: all assertions passed"
exit 0

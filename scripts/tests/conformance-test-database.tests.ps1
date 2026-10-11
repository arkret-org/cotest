#Requires -Version 7.0
<#
.SYNOPSIS
Contract tests for `Resolve-ColandTestDatabaseUrl`.

.DESCRIPTION
`run-server-conformance.ps1 -Profile all` starts a conformance PostgreSQL and
published only `COTEST_COLAND_DATABASE_URL`, which names the store a spawned SUT
uses. Tests that link coland's storage adapter in-process read
`COLAND_TEST_DATABASE_URL` (then `DATABASE_URL`) instead, so four of them
panicked with "no test database is configured" on every clean shell, and the
historical all-green baselines only existed because a developer had exported the
variable by hand. These tests pin three properties:

1. the conformance store is published to the in-process suite when nothing else
   aimed it;
2. a caller's own `COLAND_TEST_DATABASE_URL` or `DATABASE_URL` wins, matching
   coland's own precedence, so a run cannot be silently redirected;
3. nothing is published when no conformance store was resolved, which keeps the
   panic honest instead of pointing the suite at an empty string.
#>
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $PSScriptRoot
$runCotest = Join-Path $scriptRoot "run-server-conformance.ps1"

# Load only the function under test: dot-sourcing the whole script would execute
# a full run. Extract the function body and evaluate it in this session.
$source = Get-Content -Raw -LiteralPath $runCotest
$match = [regex]::Match(
    $source,
    '(?ms)^function Resolve-ColandTestDatabaseUrl \{.*?^\}'
)
if (-not $match.Success) {
    throw "Resolve-ColandTestDatabaseUrl not found in $runCotest"
}
Invoke-Expression $match.Value

$failures = New-Object System.Collections.Generic.List[string]

function Assert-Equal {
    param($Expected, $Actual, [string]$Label)
    if ($Expected -ne $Actual) {
        $failures.Add("${Label}: expected '$Expected', got '$Actual'")
    }
}

$conformance = "postgresql://arkret:arkret@127.0.0.1:55432/arkret"

# 1. Nothing else aimed the suite: publish the conformance store.
Assert-Equal $conformance (Resolve-ColandTestDatabaseUrl `
        -ConformanceDatabaseUrl $conformance `
        -ExistingColandTestDatabaseUrl $null `
        -ExistingDatabaseUrl $null) "publishes the conformance store"

# 2. An explicit COLAND_TEST_DATABASE_URL wins.
Assert-Equal $null (Resolve-ColandTestDatabaseUrl `
        -ConformanceDatabaseUrl $conformance `
        -ExistingColandTestDatabaseUrl "postgresql://dev@127.0.0.1:5432/scratch" `
        -ExistingDatabaseUrl $null) "keeps an explicit COLAND_TEST_DATABASE_URL"

# 3. DATABASE_URL is coland's documented fallback and wins too.
Assert-Equal $null (Resolve-ColandTestDatabaseUrl `
        -ConformanceDatabaseUrl $conformance `
        -ExistingColandTestDatabaseUrl $null `
        -ExistingDatabaseUrl "postgresql://dev@127.0.0.1:5432/scratch") "keeps an explicit DATABASE_URL"

# 4. Whitespace is not a configured value in coland's reader either.
Assert-Equal $conformance (Resolve-ColandTestDatabaseUrl `
        -ConformanceDatabaseUrl $conformance `
        -ExistingColandTestDatabaseUrl "   " `
        -ExistingDatabaseUrl "") "treats blank existing values as unset"

# 5. No conformance store resolved: publish nothing.
Assert-Equal $null (Resolve-ColandTestDatabaseUrl `
        -ConformanceDatabaseUrl $null `
        -ExistingColandTestDatabaseUrl $null `
        -ExistingDatabaseUrl $null) "publishes nothing without a conformance store"

# 6. The variable must survive the run: the entry restores what it overwrote.
# Both names must appear in the `$originalEnv` capture list. The check used to
# require them to be adjacent, which is not the property being asserted and
# broke as soon as another variable was added between them.
$originalEnvList = [regex]::Match(
    $source,
    'foreach\s*\(\$name\s+in\s+(?<names>"[^\r\n]*?")\s*\)\s*\{'
)
if (-not $originalEnvList.Success) {
    $failures.Add("could not locate the saved/restored environment list in run-server-conformance.ps1")
} else {
    foreach ($required in "COTEST_COLAND_DATABASE_URL", "COLAND_TEST_DATABASE_URL") {
        if ($originalEnvList.Groups["names"].Value -notmatch [regex]::Escape("`"$required`"")) {
            $failures.Add("$required is not in the saved/restored environment list")
        }
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host "FAIL: $_" }
    Write-Host "conformance-test-database.tests.ps1: FAIL"
    exit 1
}

Write-Host "conformance-test-database.tests.ps1: PASS"

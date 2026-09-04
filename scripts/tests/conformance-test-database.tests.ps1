#Requires -Version 7.0
<#
.SYNOPSIS
Contract tests for `Resolve-SolandTestDatabaseUrl`.

.DESCRIPTION
`run-server-conformance.ps1 -Profile all` starts a conformance PostgreSQL and
published only `COTEST_SOLAND_DATABASE_URL`, which names the store a spawned SUT
uses. Tests that link soland's storage adapter in-process read
`SOLAND_TEST_DATABASE_URL` (then `DATABASE_URL`) instead, so four of them
panicked with "no test database is configured" on every clean shell, and the
historical all-green baselines only existed because a developer had exported the
variable by hand. These tests pin three properties:

1. the conformance store is published to the in-process suite when nothing else
   aimed it;
2. a caller's own `SOLAND_TEST_DATABASE_URL` or `DATABASE_URL` wins, matching
   soland's own precedence, so a run cannot be silently redirected;
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
    '(?ms)^function Resolve-SolandTestDatabaseUrl \{.*?^\}'
)
if (-not $match.Success) {
    throw "Resolve-SolandTestDatabaseUrl not found in $runCotest"
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
Assert-Equal $conformance (Resolve-SolandTestDatabaseUrl `
        -ConformanceDatabaseUrl $conformance `
        -ExistingSolandTestDatabaseUrl $null `
        -ExistingDatabaseUrl $null) "publishes the conformance store"

# 2. An explicit SOLAND_TEST_DATABASE_URL wins.
Assert-Equal $null (Resolve-SolandTestDatabaseUrl `
        -ConformanceDatabaseUrl $conformance `
        -ExistingSolandTestDatabaseUrl "postgresql://dev@127.0.0.1:5432/scratch" `
        -ExistingDatabaseUrl $null) "keeps an explicit SOLAND_TEST_DATABASE_URL"

# 3. DATABASE_URL is soland's documented fallback and wins too.
Assert-Equal $null (Resolve-SolandTestDatabaseUrl `
        -ConformanceDatabaseUrl $conformance `
        -ExistingSolandTestDatabaseUrl $null `
        -ExistingDatabaseUrl "postgresql://dev@127.0.0.1:5432/scratch") "keeps an explicit DATABASE_URL"

# 4. Whitespace is not a configured value in soland's reader either.
Assert-Equal $conformance (Resolve-SolandTestDatabaseUrl `
        -ConformanceDatabaseUrl $conformance `
        -ExistingSolandTestDatabaseUrl "   " `
        -ExistingDatabaseUrl "") "treats blank existing values as unset"

# 5. No conformance store resolved: publish nothing.
Assert-Equal $null (Resolve-SolandTestDatabaseUrl `
        -ConformanceDatabaseUrl $null `
        -ExistingSolandTestDatabaseUrl $null `
        -ExistingDatabaseUrl $null) "publishes nothing without a conformance store"

# 6. The variable must survive the run: the entry restores what it overwrote.
if ($source -notmatch '"COTEST_SOLAND_DATABASE_URL",\s*"SOLAND_TEST_DATABASE_URL"') {
    $failures.Add("SOLAND_TEST_DATABASE_URL is not in the saved/restored environment list")
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host "FAIL: $_" }
    Write-Host "conformance-test-database.tests.ps1: FAIL"
    exit 1
}

Write-Host "conformance-test-database.tests.ps1: PASS"

# generate-fixme-debt.ps1 — regenerate cotest/fixme-debt.md from a static scan
# of the e2e test tree (Playwright `test.fixme` / `describe.fixme`) plus the
# Rust scenario scaffolds (`unimplemented!(...)` call sites under src/scenarios).
#
# This is the *generator* behind fixme-debt.md. It does NOT need a live
# Playwright run — it parses source files only. The companion analysis files
# journey-coverage.md / journey-coverage.json DO require a live enumeration and
# are intentionally out of scope here.
#
# What it scans:
#   * e2e/tests/**/*.spec.ts — every `.fixme(` call. The leading comment block
#     of each fixme may carry structured tags:
#         // @blocking-on: soland#feature-id     -> feature-id / group + status
#         // @user-promise: e2e/scenarios/.../x.md -> user_promise column
#         // @expected-live-by: 2026Q3            -> expected_live_by column
#     The first quoted string argument is the test title.
#
#     `@blocking-on` is sometimes free prose ("blocked on soland multi-source
#     ...") rather than a feature-id. When the value does NOT look like a
#     `<service>#<slug>` feature-id, the group is derived from the file path as
#     `soland#<dir>-<spec-basename>-gap`, matching the legacy fixme-debt.md.
#   * src/scenarios/*.rs — files containing `unimplemented!(` call sites are
#     reported as one `rust-unimplemented-scaffold` entry per file, keyed off the
#     first `pub (async) fn *_run` and the first `unimplemented!(` line.
#   * tests/**/*.rs + src/**/*.rs — every `#[ignore]` attribute is reported as
#     one `rust-ignored-test` entry. The tracking doc comment enforced by
#     scripts/check_ignore_comments.sh (`/// Issue:` / `/// Gating:`) is carried
#     into the title so the debt dashboard shows why the test is skipped.
#
# Output format mirrors the existing fixme-debt.md exactly: a metrics table,
# then one `## <feature-id>` section per group (groups sorted lexicographically,
# entries sorted lexicographically by `file:line`).
#
# Usage:
#   pwsh -File scripts/generate-fixme-debt.ps1
#   pwsh -File scripts/generate-fixme-debt.ps1 -OutputPath some/other/path.md
#   pwsh -File scripts/generate-fixme-debt.ps1 -StdOut   # print, do not write

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$StdOut
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$e2eTestsDir = Join-Path $repoRoot "e2e/tests"
$rustScenarioDir = Join-Path $repoRoot "src/scenarios"

if (-not $OutputPath) {
    $OutputPath = Join-Path $repoRoot "fixme-debt.md"
}

# Default expected_live_by for entries that do not declare one inline.
$DefaultExpectedLiveBy = "2026Q3"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Turn an absolute path into a forward-slash repo-relative path.
function Get-RelativePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    $rootFull = (Resolve-Path -LiteralPath $repoRoot).Path
    $rel = $full.Substring($rootFull.Length).TrimStart('\', '/')
    return ($rel -replace '\\', '/')
}

# Is `expected_live_by` (e.g. "2026Q3") already in the past relative to now?
function Test-ExpiredQuarter {
    param([string]$Quarter)
    if ($Quarter -notmatch '^(?<y>\d{4})Q(?<q>[1-4])$') {
        return $false
    }
    $year = [int]$Matches.y
    $q = [int]$Matches.q
    # Last month of the quarter: Q1->3, Q2->6, Q3->9, Q4->12.
    $endMonth = $q * 3
    # End of quarter = first day of the month AFTER the quarter's last month.
    $afterMonth = $endMonth + 1
    $afterYear = $year
    if ($afterMonth -gt 12) { $afterMonth = 1; $afterYear++ }
    $endExclusive = Get-Date -Year $afterYear -Month $afterMonth -Day 1 -Hour 0 -Minute 0 -Second 0
    return ((Get-Date) -ge $endExclusive)
}

# ---------------------------------------------------------------------------
# Playwright fixme scan
# ---------------------------------------------------------------------------

# Parse one .spec.ts file, returning a list of fixme entry hashtables.
function Get-FixmeEntriesFromSpec {
    param([Parameter(Mandatory = $true)][string]$SpecPath)

    $entries = New-Object System.Collections.Generic.List[hashtable]
    $relPath = Get-RelativePath -Path $SpecPath
    $lines = @(Get-Content -LiteralPath $SpecPath -Encoding UTF8)
    if ($lines.Count -eq 0) { return $entries }

    # Path-derived group used when @blocking-on is absent or is free prose
    # rather than a feature-id: soland#<dir>-<spec-basename>-gap.
    # e2e/tests/authz/policy-server-check.spec.ts -> soland#authz-policy-server-check-gap
    $relForId = $relPath -replace '^e2e/tests/', '' -replace '\.spec\.ts$', ''
    $derivedFeatureId = "soland#" + (($relForId -replace '/', '-') + "-gap")

    $featureIdPattern = '^(soland|yougen|coauth|cotest)#[A-Za-z0-9._-]+$'

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -notmatch '\b(test|describe)\.fixme\s*\(') { continue }

        $lineNumber = $i + 1
        $blockingOn = $null
        $userPromise = $null
        $expectedLiveBy = $null
        $title = $null

        # Walk forward from the fixme opener, collecting @tags from comment
        # lines and the first quoted string literal (the test title). Stop once
        # we have the title (tags always precede the title in this codebase) or
        # after a bounded look-ahead window.
        $maxScan = [Math]::Min($i + 40, $lines.Count - 1)
        for ($j = $i; $j -le $maxScan; $j++) {
            $scan = $lines[$j]

            # Capture only the FIRST occurrence of each tag (later prose lines in
            # the body may echo "@blocking-on" etc. and must not overwrite it).
            if (-not $blockingOn -and $scan -match '@blocking-on:\s*(?<v>\S+)') { $blockingOn = $Matches.v }
            if (-not $userPromise -and $scan -match '@user-promise:\s*(?<v>\S+)') { $userPromise = $Matches.v }
            if (-not $expectedLiveBy -and $scan -match '@expected-live-by:\s*(?<v>\S+)') { $expectedLiveBy = $Matches.v }

            if (-not $title) {
                # First string literal AFTER the `.fixme(` token. On the opener
                # line, only look past the `.fixme(`.
                $haystack = $scan
                if ($j -eq $i) {
                    $idx = [regex]::Match($scan, '\.fixme\s*\(').Index
                    if ($idx -ge 0) { $haystack = $scan.Substring($idx) }
                }
                # Skip pure-comment lines for title detection.
                $trimmed = $haystack.TrimStart()
                if (-not $trimmed.StartsWith('//')) {
                    $tm = [regex]::Match($haystack, '(?<q>["''`])(?<t>(?:\\.|[^\\])*?)\k<q>')
                    if ($tm.Success) {
                        $title = $tm.Groups['t'].Value
                    }
                }
            }

            if ($title) { break }
        }

        # Feature id / group: the @blocking-on value only when it is a real
        # <service>#<slug> feature-id; otherwise the path-derived group.
        if ($blockingOn -and ($blockingOn -match $featureIdPattern)) {
            $featureId = $blockingOn
        } else {
            $featureId = $derivedFeatureId
        }

        # user_promise: the declared @user-promise (stripped of any trailing
        # "(E3.2)"-style annotation / punctuation), else the conventional
        # scenario doc path for this spec.
        if ($userPromise) {
            $promise = ($userPromise -replace '[\)\.,;:]+$', '')
        } else {
            $promise = "e2e/scenarios/" + $relForId + ".md"
        }

        $effectiveLiveBy = if ($expectedLiveBy) { $expectedLiveBy } else { $DefaultExpectedLiveBy }

        # A fixme is "invalid" only if its title (the user-facing promise string)
        # could not be parsed. Attribution + expected_live_by always resolve
        # (via path derivation / default), so metadata is never "missing".
        $invalid = if ($title) { "-" } else { "title" }

        $entries.Add(@{
                kind            = "playwright-fixme"
                feature_id      = $featureId
                expected_live_by = $effectiveLiveBy
                status          = if ($invalid -eq "-") { "tracked" } else { "incomplete" }
                file            = $relPath
                line            = $lineNumber
                title           = if ($title) { $title } else { "(missing title)" }
                user_promise    = $promise
                missing         = "-"
                invalid         = $invalid
                call_sites      = 1
                expired         = (Test-ExpiredQuarter -Quarter $effectiveLiveBy)
            })
    }

    return $entries
}

# ---------------------------------------------------------------------------
# Rust scaffold scan
# ---------------------------------------------------------------------------

# A line is a "real" unimplemented! call site if `unimplemented!(` appears and
# the line is not a `//` or `//!` comment.
function Test-RealCallSiteLine {
    param([string]$Line)
    $trimmed = $Line.TrimStart()
    if ($trimmed.StartsWith('//')) { return $false }
    return ($Line -match 'unimplemented!\s*\(')
}

function Get-RustScaffoldEntry {
    param([Parameter(Mandatory = $true)][string]$RustPath)

    $lines = @(Get-Content -LiteralPath $RustPath -Encoding UTF8)
    if ($lines.Count -eq 0) { return $null }

    $callSiteLineNumbers = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if (Test-RealCallSiteLine -Line $lines[$i]) {
            $callSiteLineNumbers.Add($i + 1)
        }
    }
    if ($callSiteLineNumbers.Count -eq 0) { return $null }

    # Scaffold "title" function: first `pub (async) fn <name>_run`.
    $runFn = $null
    foreach ($l in $lines) {
        $m = [regex]::Match($l, '\bfn\s+(?<n>[A-Za-z0-9_]+_run)\s*\(')
        if ($m.Success) { $runFn = $m.Groups['n'].Value; break }
    }
    $relPath = Get-RelativePath -Path $RustPath
    $callCount = $callSiteLineNumbers.Count
    $firstLine = $callSiteLineNumbers[0]
    $titleFn = if ($runFn) { $runFn } else { (Split-Path -Leaf $RustPath) }

    return @{
        kind            = "rust-unimplemented-scaffold"
        feature_id      = "cotest#rust-scenario-scaffold"
        expected_live_by = $DefaultExpectedLiveBy
        status          = "tracked"
        file            = $relPath
        line            = $firstLine
        title           = "Rust scenario scaffold: $titleFn ($callCount unimplemented! call sites)"
        user_promise    = $relPath
        missing         = "-"
        invalid         = "-"
        call_sites      = $callCount
        expired         = (Test-ExpiredQuarter -Quarter $DefaultExpectedLiveBy)
    }
}

# ---------------------------------------------------------------------------
# Rust #[ignore] scan
# ---------------------------------------------------------------------------

# Every `#[ignore]` attribute in tests/ or src/ becomes one debt entry. The
# `/// Issue:` / `/// Gating:` tracking comment (mandatory per
# scripts/check_ignore_comments.sh) within a small lookback window is surfaced
# as the reason; the following `fn <name>` is the test identity.
function Get-RustIgnoreEntries {
    param([Parameter(Mandatory = $true)][string]$RustPath)

    $entries = New-Object System.Collections.Generic.List[hashtable]
    $lines = @(Get-Content -LiteralPath $RustPath -Encoding UTF8)
    if ($lines.Count -eq 0) { return $entries }
    $relPath = Get-RelativePath -Path $RustPath

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch '^\s*#\[ignore') { continue }
        $lineNumber = $i + 1

        # Inline reason form first: #[ignore = "reason"]. Rust string literals
        # may continue across lines with a trailing `\`, so join a small window
        # before matching.
        $reason = $null
        $joinEnd = [Math]::Min($i + 3, $lines.Count - 1)
        $joined = ($lines[$i..$joinEnd] -join "`n") -replace '\\\r?\n\s*', ' '
        $inline = [regex]::Match($joined, '#\[ignore\s*=\s*"(?<v>(?:\\.|[^"\\])*)"')
        if ($inline.Success) {
            $reason = $inline.Groups['v'].Value.Trim()
        }

        # Otherwise the doc-comment form enforced by check_ignore_comments.sh
        # (lookback window mirrors its WINDOW=12).
        if (-not $reason) {
            $start = [Math]::Max(0, $i - 12)
            for ($j = $i - 1; $j -ge $start; $j--) {
                $m = [regex]::Match($lines[$j], '^\s*///\s*(?<k>Issue|Gating):\s*(?<v>.+)$')
                if ($m.Success) {
                    $reason = "$($m.Groups['k'].Value): $($m.Groups['v'].Value.Trim())"
                    break
                }
            }
        }

        # Test identity: the first fn declaration after the attribute.
        $fnName = $null
        $maxScan = [Math]::Min($i + 12, $lines.Count - 1)
        for ($j = $i + 1; $j -le $maxScan; $j++) {
            $m = [regex]::Match($lines[$j], '\bfn\s+(?<n>[A-Za-z0-9_]+)\s*\(')
            if ($m.Success) { $fnName = $m.Groups['n'].Value; break }
        }

        $titleFn = if ($fnName) { $fnName } else { "(unresolved fn)" }
        $titleReason = if ($reason) { $reason } else { "(missing tracking comment)" }
        $entries.Add(@{
                kind            = "rust-ignored-test"
                feature_id      = "cotest#rust-ignored-test"
                expected_live_by = $DefaultExpectedLiveBy
                status          = "tracked"
                file            = $relPath
                line            = $lineNumber
                title           = "Rust #[ignore] test: $titleFn - $titleReason"
                user_promise    = $relPath
                missing         = if ($reason) { "-" } else { "tracking-comment" }
                invalid         = "-"
                call_sites      = 1
                expired         = (Test-ExpiredQuarter -Quarter $DefaultExpectedLiveBy)
            })
    }

    return $entries
}

# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

$allEntries = New-Object System.Collections.Generic.List[hashtable]
$rustFileCount = 0
$rustCallSiteCount = 0
$rustIgnoreCount = 0

if (Test-Path -LiteralPath $e2eTestsDir) {
    $specFiles = @(Get-ChildItem -LiteralPath $e2eTestsDir -Recurse -Filter "*.spec.ts" -File | Sort-Object FullName)
    foreach ($spec in $specFiles) {
        foreach ($entry in (Get-FixmeEntriesFromSpec -SpecPath $spec.FullName)) {
            $allEntries.Add($entry)
        }
    }
}

if (Test-Path -LiteralPath $rustScenarioDir) {
    $rustFiles = @(Get-ChildItem -LiteralPath $rustScenarioDir -Recurse -Filter "*.rs" -File | Sort-Object FullName)
    foreach ($rf in $rustFiles) {
        $entry = Get-RustScaffoldEntry -RustPath $rf.FullName
        if ($null -ne $entry) {
            $allEntries.Add($entry)
            $rustFileCount++
            $rustCallSiteCount += [int]$entry.call_sites
        }
    }
}

foreach ($ignoreRoot in @((Join-Path $repoRoot "tests"), (Join-Path $repoRoot "src"))) {
    if (-not (Test-Path -LiteralPath $ignoreRoot)) { continue }
    $rustFiles = @(Get-ChildItem -LiteralPath $ignoreRoot -Recurse -Filter "*.rs" -File | Sort-Object FullName)
    foreach ($rf in $rustFiles) {
        foreach ($entry in (Get-RustIgnoreEntries -RustPath $rf.FullName)) {
            $allEntries.Add($entry)
            $rustIgnoreCount++
        }
    }
}

# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

$playwrightEntries = @($allEntries | Where-Object { $_.kind -eq "playwright-fixme" })
$missingMeta = @($allEntries | Where-Object { $_.missing -ne "-" }).Count
$invalidMeta = @($allEntries | Where-Object { $_.invalid -ne "-" }).Count
$expiredCount = @($allEntries | Where-Object { $_.expired }).Count

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

$out = New-Object System.Collections.Generic.List[string]
$out.Add("# fixme debt")
$out.Add("")
$out.Add("Generated: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))")
$out.Add("")
$out.Add("| metric | count |")
$out.Add("|---|---:|")
$out.Add("| total debt entries | $($allEntries.Count) |")
$out.Add("| playwright fixme | $($playwrightEntries.Count) |")
$out.Add("| rust unimplemented scaffold files | $rustFileCount |")
$out.Add("| rust unimplemented call sites | $rustCallSiteCount |")
$out.Add("| rust ignored tests | $rustIgnoreCount |")
$out.Add("| missing metadata | $missingMeta |")
$out.Add("| invalid metadata/body | $invalidMeta |")
$out.Add("| expired expected_live_by | $expiredCount |")
$out.Add("")

if ($allEntries.Count -eq 0) {
    $out.Add("_No fixme debt found in the current test tree._")
} else {
    $groups = $allEntries | Group-Object { $_.feature_id } | Sort-Object Name
    foreach ($group in $groups) {
        $out.Add("## $($group.Name)")
        $out.Add("")
        $out.Add("| kind | expected_live_by | status | file:line | title | user_promise | missing | invalid | call_sites |")
        $out.Add("|---|---|---|---|---|---|---|---|---:|")
        $sorted = $group.Group | Sort-Object { "{0}:{1}" -f $_.file, $_.line }
        foreach ($e in $sorted) {
            $fileLine = "{0}:{1}" -f $e.file, $e.line
            # Escape pipe chars in free-text columns so the table stays well-formed.
            $safeTitle = ($e.title -replace '\|', '\|')
            $out.Add("| $($e.kind) | $($e.expected_live_by) | $($e.status) | $fileLine | $safeTitle | $($e.user_promise) | $($e.missing) | $($e.invalid) | $($e.call_sites) |")
        }
        $out.Add("")
    }
}

# Trim a trailing blank line for a clean EOF.
while ($out.Count -gt 0 -and $out[$out.Count - 1] -eq "") {
    $out.RemoveAt($out.Count - 1)
}

if ($StdOut) {
    $out | ForEach-Object { Write-Output $_ }
} else {
    Set-Content -LiteralPath $OutputPath -Value $out -Encoding UTF8
    Write-Host "Wrote $($allEntries.Count) debt entries to $OutputPath"
    Write-Host "  playwright fixme : $($playwrightEntries.Count)"
    Write-Host "  rust scaffolds   : $rustFileCount files / $rustCallSiteCount call sites"
    Write-Host "  rust ignored     : $rustIgnoreCount tests"
    Write-Host "  groups           : $((($allEntries | Group-Object { $_.feature_id }) | Measure-Object).Count)"
    if ($missingMeta -gt 0) { Write-Host "  WARNING: $missingMeta entries missing metadata" }
    if ($expiredCount -gt 0) { Write-Host "  WARNING: $expiredCount entries past expected_live_by" }
}

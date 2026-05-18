# promote-fixme.ps1 — convert a Playwright `test.fixme(...)` placeholder
# at a specific spec file:line into a real `test(...)` invocation, replacing
# the empty arrow-function body with the new test body supplied by the
# caller. Use after the server-side / client-side feature behind a fixme
# has landed and the spec is ready to run for real.
#
# Usage:
#   pwsh -File scripts/promote-fixme.ps1 `
#       -SpecPath e2e/tests/identity/onboarding.spec.ts:42 `
#       -NewBody @'
#   async ({ page, request }) => {
#       await page.goto("/onboarding");
#       // ...
#   }
#   '@
#
# Notes:
#   - Verifies the line at `SpecPath` is currently a `test.fixme(` *opening*
#     line before rewriting. Refuses to rewrite if the file shifted.
#   - Captures the test title from the existing fixme call.
#   - Locates the matching closing paren for the fixme call (single-pass
#     bracket counter on the source).
#   - Use -DryRun to preview the rewrite without touching the file.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SpecPath,
    [Parameter(Mandatory = $true)][string]$NewBody,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($SpecPath -notmatch "^(?<file>.+?):(?<line>\d+)$") {
    throw "SpecPath must be of the form '<file>:<line>'; got '$SpecPath'"
}
$specFile = $Matches.file
$lineNumber = [int]$Matches.line

if (-not (Test-Path $specFile)) {
    throw "spec file not found: $specFile"
}

$lines = Get-Content -LiteralPath $specFile
if ($lineNumber -lt 1 -or $lineNumber -gt $lines.Count) {
    throw "line $lineNumber is out of range for $specFile (1..$($lines.Count))"
}

$targetLine = $lines[$lineNumber - 1]
if ($targetLine -notmatch "test\.fixme\s*\(") {
    throw "line $lineNumber in $specFile does not start a test.fixme(... call: '$targetLine'"
}

# Source text from the start of test.fixme( to the matching ')'.
$source = [string]::Join("`n", $lines)
$startLineIndex = $lineNumber - 1
# Find offset of `test.fixme(` in the source string.
$prefixLength = 0
for ($i = 0; $i -lt $startLineIndex; $i++) {
    $prefixLength += $lines[$i].Length + 1 # +1 for the "`n" join
}
$fixmeStart = $source.IndexOf("test.fixme", $prefixLength)
if ($fixmeStart -lt 0) {
    throw "could not locate test.fixme token after line $lineNumber"
}
$openParen = $source.IndexOf("(", $fixmeStart)
if ($openParen -lt 0) {
    throw "could not locate '(' after test.fixme"
}

# Walk bracket depth to find matching ')'. Skip over strings and template
# literals so embedded parens don't throw off the count.
$depth = 0
$index = $openParen
$length = $source.Length
$inString = $null
$inLineComment = $false
$inBlockComment = $false
while ($index -lt $length) {
    $ch = $source[$index]
    $next = if ($index + 1 -lt $length) { $source[$index + 1] } else { "" }

    if ($inLineComment) {
        if ($ch -eq "`n") { $inLineComment = $false }
        $index++
        continue
    }
    if ($inBlockComment) {
        if ($ch -eq "*" -and $next -eq "/") { $inBlockComment = $false; $index += 2; continue }
        $index++
        continue
    }
    if ($inString) {
        if ($ch -eq "\\") { $index += 2; continue }
        if ($ch -eq $inString) { $inString = $null }
        $index++
        continue
    }

    if ($ch -eq "/" -and $next -eq "/") { $inLineComment = $true; $index += 2; continue }
    if ($ch -eq "/" -and $next -eq "*") { $inBlockComment = $true; $index += 2; continue }
    if ($ch -eq "'" -or $ch -eq "`"" -or $ch -eq "``") { $inString = $ch; $index++; continue }

    if ($ch -eq "(") { $depth++ }
    elseif ($ch -eq ")") {
        $depth--
        if ($depth -eq 0) { break }
    }
    $index++
}

if ($depth -ne 0) {
    throw "could not find matching ')' for test.fixme starting at line $lineNumber"
}
$closeParen = $index

# Extract the existing args to recover the test title.
$argsText = $source.Substring($openParen + 1, $closeParen - $openParen - 1)
$titleMatch = [regex]::Match($argsText, '^\s*(?<quote>["''`])(?<title>.*?)(?<!\\)\k<quote>')
if (-not $titleMatch.Success) {
    throw "could not parse string title from test.fixme(...) at line $lineNumber"
}
$title = $titleMatch.Groups['title'].Value
$quote = $titleMatch.Groups['quote'].Value

$replacement = "test($quote$title$quote, $NewBody)"
$newSource = $source.Substring(0, $fixmeStart) + $replacement + $source.Substring($closeParen + 1)

if ($DryRun) {
    Write-Host "Would rewrite $specFile (test '$title') with:"
    Write-Host "----------------"
    Write-Host $replacement
    Write-Host "----------------"
    return
}

Set-Content -LiteralPath $specFile -Value $newSource -NoNewline -Encoding UTF8
Write-Host "Promoted fixme '$title' in $specFile (line $lineNumber)"

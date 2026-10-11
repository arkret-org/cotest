# promote-fixme.ps1 — convert a Playwright `test.fixme(...)` placeholder
# at a specific spec file:line into a real `test(...)` invocation, replacing
# the empty arrow-function body with the new test body supplied by the
# caller. Use after the server-side / client-side feature behind a fixme
# has landed and the spec is ready to run for real.
#
# Usage:
#   pwsh -File scripts/promote-fixme.ps1 `
#       -SpecPath e2e/tests/identity/onboarding.spec.ts:42 `
#       -FeatureId coland#identity-onboarding `
#       -PassedSpecCommand 'npx playwright test --config playwright.config.ts --project chromium e2e/tests/identity/onboarding.spec.ts' `
#       -EvidencePath artifacts/regression/onboarding.har `
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
#   - Requires promotion evidence before modifying a file: backing feature id,
#     one passed single-spec command, and one screenshot/HAR/trace artifact path.
#   - Use -DryRun to preview the rewrite without touching the file.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SpecPath,
    [Parameter(Mandatory = $true)][string]$NewBody,
    [string]$FeatureId,
    [string]$PassedSpecCommand,
    [string]$EvidencePath,
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

function Assert-PromotionEvidence {
    param(
        [string]$FeatureId,
        [string]$PassedSpecCommand,
        [string]$EvidencePath
    )

    if (-not $FeatureId) {
        throw "-FeatureId is required before removing .fixme"
    }
    if ($FeatureId -notmatch '^(coland|inkson|coauth|cotest)#[A-Za-z0-9._-]+$|^GAP-P\d+-\d+$') {
        throw "-FeatureId must look like coland#feature-id, inkson#feature-id, coauth#feature-id, cotest#feature-id, or GAP-Px-yyy; got '$FeatureId'"
    }
    if (-not $PassedSpecCommand -or -not $PassedSpecCommand.Trim()) {
        throw "-PassedSpecCommand is required before removing .fixme"
    }
    if (-not $EvidencePath) {
        throw "-EvidencePath is required before removing .fixme"
    }
    if (-not (Test-Path -LiteralPath $EvidencePath)) {
        throw "promotion evidence not found: $EvidencePath"
    }
    $item = Get-Item -LiteralPath $EvidencePath
    if (-not $item.PSIsContainer) {
        $extension = $item.Extension.ToLowerInvariant()
        if ($extension -notin @(".png", ".jpg", ".jpeg", ".webp", ".har", ".zip", ".trace")) {
            throw "-EvidencePath must be a screenshot, HAR, trace, zip, or directory; got '$EvidencePath'"
        }
    }
}

if (-not $DryRun) {
    Assert-PromotionEvidence `
        -FeatureId $FeatureId `
        -PassedSpecCommand $PassedSpecCommand `
        -EvidencePath $EvidencePath
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
    if ($FeatureId -or $PassedSpecCommand -or $EvidencePath) {
        Write-Host "Evidence:"
        Write-Host "  feature_id         : $FeatureId"
        Write-Host "  passed_spec_command: $PassedSpecCommand"
        Write-Host "  evidence_path      : $EvidencePath"
    }
    Write-Host "----------------"
    Write-Host $replacement
    Write-Host "----------------"
    return
}

Set-Content -LiteralPath $specFile -Value $newSource -NoNewline -Encoding UTF8
Write-Host "Promoted fixme '$title' in $specFile (line $lineNumber)"
Write-Host "Evidence:"
Write-Host "  feature_id         : $FeatureId"
Write-Host "  passed_spec_command: $PassedSpecCommand"
Write-Host "  evidence_path      : $EvidencePath"

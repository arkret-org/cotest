# demote-test.ps1 - convert a Playwright `test(...)` into `test.fixme(...)`.
#
# Use this only as a temporary local harness shim when a regression appears
# before the backing soland/inkson/coauth feature can be repaired. The inserted
# FIXME comment records why the demotion exists so the static fixme checker can
# keep the debt attributable.
#
# Usage:
#   pwsh -File scripts/demote-test.ps1 `
#       -SpecPath e2e/tests/chat/chat-interactions.spec.ts:42 `
#       -Reason "GAP-P1-011 blocked by soland reaction OR-Set"
#
# Use -DryRun to preview the rewrite without changing the file.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SpecPath,
    [Parameter(Mandatory = $true)][string]$Reason,
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
if ($targetLine -match "test\.fixme\s*\(") {
    throw "line $lineNumber in $specFile is already test.fixme(...): '$targetLine'"
}
if ($targetLine -notmatch "^(?<indent>\s*)test\s*\(") {
    throw "line $lineNumber in $specFile does not start a Playwright test(...): '$targetLine'"
}

$indent = $Matches.indent
$cleanReason = ($Reason -replace "(`r`n|`n|`r)", " ").Trim()
if (-not $cleanReason) {
    throw "Reason must not be empty"
}

$comment = "$indent// FIXME: $cleanReason"
$rewrittenLine = $targetLine -replace "^(\s*)test\s*\(", "`$1test.fixme("

$newLines = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($i -eq ($lineNumber - 1)) {
        if ($i -eq 0 -or $lines[$i - 1] -ne $comment) {
            $newLines.Add($comment)
        }
        $newLines.Add($rewrittenLine)
    } else {
        $newLines.Add($lines[$i])
    }
}

if ($DryRun) {
    Write-Host "Would demote $specFile line ${lineNumber}:"
    Write-Host $comment
    Write-Host $rewrittenLine
    return
}

$newLines | Set-Content -LiteralPath $specFile -Encoding UTF8
Write-Host "Demoted test in $specFile (line $lineNumber)"

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

# Load only the production helper, without starting a joint SUT.
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot "../run-joint-e2e.ps1"), [ref]$tokens, [ref]$parseErrors
)
Assert-True ($parseErrors.Count -eq 0) "joint runner must parse"
$function = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq "Test-BinaryContainsAsciiMarker"
}, $true)
Assert-True ($null -ne $function) "production binary marker helper must exist"
Invoke-Expression $function.Extent.Text

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("cotest-binary-marker-" + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $root
try {
    $file = Join-Path $root "fixture.bin"
    $marker = "org.arkret.coland.conformance.realm_state_snapshot"
    $needle = [System.Text.Encoding]::ASCII.GetBytes($marker)
    Assert-True (-not (Test-BinaryContainsAsciiMarker -Path $file -Marker $marker)) "missing file must fail closed"
    [System.IO.File]::WriteAllBytes($file, [byte[]]@())
    Assert-True (-not (Test-BinaryContainsAsciiMarker -Path $file -Marker $marker)) "empty binary must fail closed"
    [System.IO.File]::WriteAllBytes($file, $needle)
    Assert-True (Test-BinaryContainsAsciiMarker -Path $file -Marker $marker) "whole-file marker must match"
    Assert-True (-not (Test-BinaryContainsAsciiMarker -Path $file -Marker $marker.ToUpperInvariant())) "marker matching must remain case sensitive"

    # Every possible split of the actual Coland marker across the 64KiB read.
    for ($split = 1; $split -lt $needle.Length; $split++) {
        $bytes = [byte[]]::new(65536 + $needle.Length + 3)
        [System.Array]::Copy($needle, 0, $bytes, 65536 - $split, $needle.Length)
        $bytes[$bytes.Length - 1] = 255
        [System.IO.File]::WriteAllBytes($file, $bytes)
        Assert-True (Test-BinaryContainsAsciiMarker -Path $file -Marker $marker) "cross-chunk marker split $split must match"
    }
    $bytes = [byte[]]::new(65542)
    $overlap = [System.Text.Encoding]::ASCII.GetBytes("aaaaaaab")
    [System.Array]::Copy($overlap, 0, $bytes, 65534, $overlap.Length)
    [System.IO.File]::WriteAllBytes($file, $bytes)
    Assert-True (Test-BinaryContainsAsciiMarker -Path $file -Marker "aaaab") "overlapping partial prefixes must match across chunks"
    Assert-True (-not (Test-BinaryContainsAsciiMarker -Path $file -Marker "aaaac")) "partial prefix must not admit a missing marker"
    [System.IO.File]::WriteAllBytes($file, [System.Text.Encoding]::ASCII.GetBytes("inkson.test.session_injection.v1/_dioxus"))
    Assert-True (Test-BinaryContainsAsciiMarker -Path $file -Marker "inkson.test.session_injection.v1") "WASM required marker must still match"
    Assert-True (Test-BinaryContainsAsciiMarker -Path $file -Marker "/_dioxus") "WASM forbidden marker must still match"
    [System.IO.File]::WriteAllBytes($file, [byte[]]@(255, 0, 128, 127))
    Assert-True (-not (Test-BinaryContainsAsciiMarker -Path $file -Marker $marker)) "binary bytes must not create a marker"

    # Sparse 256MiB artifact: scan its end and an absent marker, while checking
    # actual managed allocation rather than relying on the artifact's size.
    $stream = [System.IO.File]::OpenWrite($file)
    try {
        $stream.SetLength(256MB)
        $null = $stream.Seek(-$needle.Length, [System.IO.SeekOrigin]::End)
        $stream.Write($needle, 0, $needle.Length)
    } finally { $stream.Dispose() }
    $before = [System.GC]::GetTotalAllocatedBytes($true)
    Assert-True (Test-BinaryContainsAsciiMarker -Path $file -Marker $marker) "large binary end marker must match"
    Assert-True (-not (Test-BinaryContainsAsciiMarker -Path $file -Marker ($marker + ".missing"))) "large binary absent marker must fail closed"
    $allocated = [System.GC]::GetTotalAllocatedBytes($true) - $before
    Assert-True ($allocated -lt 16MB) "large binary scans must allocate bounded buffers, allocated=$allocated"
    Write-Host "binary-marker.tests.ps1: PASS (256MiB end/absent scans, allocated=$allocated bytes)"
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}

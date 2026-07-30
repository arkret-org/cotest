# Synthetic-secret regression test for scripts/lib/secret-scan.ps1.
#
# Verifies the two-sided invariant of the artifact secret gate:
#   1. every planted synthetic secret is DETECTED by Find-SecretLeaks,
#   2. no leak preview (the only value persisted into secret-scan.json/md)
#      contains the original secret bytes, and
#   3. benign long sentences do NOT trip the BIP-39 detector.
#
# run-cotest.ps1 executes this script before every secret scan and fails the
# gate when it fails; it can also be run directly:
#   powershell -ExecutionPolicy Bypass -File scripts\tests\secret-scan.tests.ps1
# Exits 0 on success, 1 with a failure list otherwise.

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\lib\secret-scan.ps1")

$failures = New-Object System.Collections.Generic.List[string]

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        $failures.Add($Message)
    }
}

$scanRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("secret-scan-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $scanRoot -Force | Out-Null
try {
    $mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual"
    $bearer = "synthetic-bearer-token-AAAABBBBCCCC"
    $hexSecret = "deadbeefdeadbeefdeadbeefdeadbeef"
    $didValue = "did:webvh:QmSynthetic:host.example:webvh:alice"
    $plantedSecrets = @($mnemonic, $bearer, $hexSecret, $didValue)

    # One planted secret per line; the file name documents the vector.
    $planted = @(
        [pscustomobject]@{ name = "json-mnemonic.log"; line = "{`"mnemonic`":`"$mnemonic`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-root-private-key.log"; line = "{`"root_private_key`":`"$hexSecret`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-recovery-key.log"; line = "{`"recovery_key`":`"$mnemonic`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-hkdf-prk.log"; line = "{`"hkdf_prk`":`"$hexSecret`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-secret-b64u.log"; line = "{`"secret_b64u`":`"$hexSecret`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-plaintext-keybag.log"; line = "{`"plaintext_keybag`":`"$hexSecret`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-mls-epoch-secret.log"; line = "{`"epoch_secret`":`"$hexSecret`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-mls-private-state.log"; line = "{`"private_state`":`"$hexSecret`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "query-root-seed.log"; line = "GET /callback?root_seed=$hexSecret&state=x"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "bare-mnemonic-string.log"; line = "wrote backup payload `"$mnemonic`" to store"; pattern = "bip39_mnemonic_sequence" },
        [pscustomobject]@{ name = "embedded-mnemonic-string.log"; line = "note `"wrote backup payload $mnemonic`" persisted"; pattern = "bip39_mnemonic_sequence" },
        [pscustomobject]@{ name = "punctuated-mnemonic-string.log"; line = "{`"message`":`"recovery phrase: $mnemonic`"}"; pattern = "bip39_mnemonic_sequence" },
        [pscustomobject]@{ name = "did-in-credential-field.log"; line = "{`"credential`":`"$didValue`"}"; pattern = "did_in_token_field" },
        [pscustomobject]@{ name = "authorization-bearer.log"; line = "authorization: bearer $bearer"; pattern = "authorization_header" },
        [pscustomobject]@{ name = "pem-private-key.log"; line = "-----BEGIN PRIVATE KEY-----$hexSecret-----END PRIVATE KEY-----"; pattern = "private_key_block" },
        [pscustomobject]@{ name = "pem-encrypted-private-key-header.log"; line = "-----BEGIN ENCRYPTED PRIVATE KEY-----"; pattern = "private_key_block" }
    )
    foreach ($vector in $planted) {
        Set-Content -Path (Join-Path $scanRoot $vector.name) -Value $vector.line -Encoding utf8
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $traceSource = Join-Path $scanRoot "trace-source"
    New-Item -ItemType Directory -Path $traceSource | Out-Null
    Set-Content `
        -Path (Join-Path $traceSource "network.json") `
        -Value "{`"mls_secret`":`"$hexSecret`"}" `
        -Encoding utf8
    $traceZip = Join-Path $scanRoot "trace.zip"
    [System.IO.Compression.ZipFile]::CreateFromDirectory($traceSource, $traceZip)
    Remove-Item -LiteralPath $traceSource -Recurse -Force

    # Clean lines that must NOT trigger any pattern. The last two match the
    # BIP-39 candidate regex (12+ quoted lowercase 3-8 letter words) but are
    # ordinary sentences, so the wordlist validator must reject them.
    $cleanLines = @(
        '{"status":"ok","principal_id":"did:webvh:QmExample:host:webvh:alice"}',
        'INFO completed request in 42ms path=/_arkret/describe',
        '"the server logs show that retry loops kept firing until the queue drained fully"',
        '"our nightly release gate runs every suite twice before the deploy window opens for all teams"'
    )
    Set-Content -Path (Join-Path $scanRoot "clean.log") -Value $cleanLines -Encoding utf8

    $leaks = @(Find-SecretLeaks -ScanRoots @($scanRoot))

    foreach ($vector in $planted) {
        $hit = @($leaks | Where-Object { (Split-Path -Leaf $_.path) -eq $vector.name -and $_.pattern -eq $vector.pattern })
        Assert-True ($hit.Count -ge 1) "expected $($vector.name) to be detected as $($vector.pattern); got patterns: $(@($leaks | Where-Object { (Split-Path -Leaf $_.path) -eq $vector.name } | ForEach-Object { $_.pattern }) -join ', ')"
    }
    $traceHit = @($leaks | Where-Object {
            $_.path -like "*trace.zip!network.json" -and
            $_.pattern -eq "json_secret_field"
        })
    Assert-True ($traceHit.Count -eq 1) "expected the secret inside trace.zip to be detected exactly once"

    $cleanHits = @($leaks | Where-Object { (Split-Path -Leaf $_.path) -eq "clean.log" })
    Assert-True ($cleanHits.Count -eq 0) "clean.log must not trigger the scanner; got: $(@($cleanHits | ForEach-Object { $_.pattern }) -join ', ')"

    # The persisted preview must never carry the original secret bytes; this
    # is checked for EVERY leak, so each detector pattern proves its matching
    # redaction (the file-top invariant of secret-scan.ps1).
    foreach ($leak in $leaks) {
        foreach ($secret in $plantedSecrets) {
            Assert-True (-not $leak.preview.Contains($secret)) "preview for $(Split-Path -Leaf $leak.path) ($($leak.pattern)) still contains a planted secret"
        }
        # No three consecutive mnemonic words may survive either.
        $words = $mnemonic -split ' '
        for ($index = 0; $index -le $words.Count - 3; $index++) {
            $run = "$($words[$index]) $($words[$index + 1]) $($words[$index + 2])"
            Assert-True (-not $leak.preview.Contains($run)) "preview for $(Split-Path -Leaf $leak.path) ($($leak.pattern)) contains mnemonic word run starting at index $index"
        }
        Assert-True ($leak.preview.Contains("[redacted")) "preview for $(Split-Path -Leaf $leak.path) ($($leak.pattern)) carries no redaction marker: $($leak.preview)"
    }

    # Direct redaction unit checks, including the $4 back-reference shape and
    # the did_in_token_field / credential coverage.
    $jsonPreview = ConvertTo-SecretPreview -Line "{`"mnemonic`":`"$mnemonic`",`"next`":1}"
    Assert-True ($jsonPreview.Contains('"mnemonic":"[redacted]"')) "json redaction must keep the closing quote intact: $jsonPreview"
    $barePreview = ConvertTo-SecretPreview -Line "`"$mnemonic`""
    Assert-True ($barePreview -eq '"[redacted-mnemonic]"') "bare mnemonic string must redact wholesale: $barePreview"
    $punctuatedPreview = ConvertTo-SecretPreview -Line "{`"message`":`"recovery phrase: $mnemonic`"}"
    Assert-True ($punctuatedPreview.Contains('"message":"[redacted-mnemonic]"')) "punctuated mnemonic string must redact wholesale: $punctuatedPreview"
    $credentialPreview = ConvertTo-SecretPreview -Line "{`"credential`":`"$didValue`"}"
    Assert-True ($credentialPreview.Contains('"credential":"[redacted]"')) "credential field must be redacted: $credentialPreview"
    $pemPreview = ConvertTo-SecretPreview -Line "-----BEGIN PRIVATE KEY-----$hexSecret-----END PRIVATE KEY-----"
    Assert-True ($pemPreview -eq "[redacted-private-key]") "single-line PEM must redact wholesale: $pemPreview"
    $pemHeaderPreview = ConvertTo-SecretPreview -Line "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    Assert-True ($pemHeaderPreview -eq "[redacted-private-key]") "multi-line PEM header must redact: $pemHeaderPreview"

    # Wordlist sanity: exactly the standard 2048-entry BIP-39 English list.
    $wordSet = Get-Bip39WordSet
    Assert-True ($wordSet.Count -eq 2048) "BIP-39 wordlist must contain 2048 words, found $($wordSet.Count)"
    Assert-True ($wordSet.Contains("abandon") -and $wordSet.Contains("zoo")) "BIP-39 wordlist must span abandon..zoo"
    Assert-True (-not $wordSet.Contains("the")) "BIP-39 wordlist must not contain non-list filler words"
} finally {
    Remove-Item -Recurse -Force $scanRoot -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host "secret-scan tests FAILED:" -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host "  - $failure" -ForegroundColor Red
    }
    exit 1
}
Write-Host "secret-scan tests passed"
exit 0

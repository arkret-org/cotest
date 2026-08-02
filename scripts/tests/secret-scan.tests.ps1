# Synthetic-secret regression test for scripts/lib/secret-scan.ps1.
#
# Verifies the invariants of the artifact secret gate:
#   1. every planted synthetic secret is DETECTED by Find-SecretLeaks,
#   2. no leak preview (the only value persisted into secret-scan.json/md)
#      contains the original secret bytes,
#   3. benign long sentences do NOT trip the BIP-39 detector,
#   4. each finding carries the category and the artifact-class verdict the
#      gate reads, and a durable protocol store tolerates credential evidence
#      without ever tolerating recovery private material, and
#   5. the canary round trip holds: the scanner finds the plaintext, the
#      redactor clears it from the artifact, a re-scan of the redacted artifact
#      is clean, and the report still carries file / line / pattern evidence.
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
    # b64url of a synthetic 32-byte seed: the exact shape a private OKP JWK's
    # `d` member and a plaintext keybag entry carry.
    $jwkPrivateScalar = "c3ludGhldGljLXNlZWQtdmFsdWUtZm9yLXNjYW5uZXItdGVzdHM"
    $plantedSecrets = @($mnemonic, $bearer, $hexSecret, $didValue, $jwkPrivateScalar)

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
        [pscustomobject]@{ name = "sql-seed-assignment.sql"; line = "UPDATE recovery_state SET seed = '$hexSecret' WHERE id = 1;"; pattern = "recovery_private_material_assignment" },
        [pscustomobject]@{ name = "query-root-seed.log"; line = "GET /callback?root_seed=$hexSecret&state=x"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "bare-mnemonic-string.log"; line = "wrote backup payload `"$mnemonic`" to store"; pattern = "bip39_mnemonic_sequence" },
        [pscustomobject]@{ name = "embedded-mnemonic-string.log"; line = "note `"wrote backup payload $mnemonic`" persisted"; pattern = "bip39_mnemonic_sequence" },
        [pscustomobject]@{ name = "punctuated-mnemonic-string.log"; line = "{`"message`":`"recovery phrase: $mnemonic`"}"; pattern = "bip39_mnemonic_sequence" },
        [pscustomobject]@{ name = "did-in-credential-field.log"; line = "{`"credential`":`"$didValue`"}"; pattern = "did_in_token_field" },
        [pscustomobject]@{ name = "authorization-bearer.log"; line = "authorization: bearer $bearer"; pattern = "authorization_header" },
        [pscustomobject]@{ name = "pem-private-key.log"; line = "-----BEGIN PRIVATE KEY-----$hexSecret-----END PRIVATE KEY-----"; pattern = "private_key_block" },
        [pscustomobject]@{ name = "pem-encrypted-private-key-header.log"; line = "-----BEGIN ENCRYPTED PRIVATE KEY-----"; pattern = "private_key_block" },
        # Structural vectors: private material travelling under a short generic
        # member name that no field-name list could carry on its own.
        [pscustomobject]@{ name = "jwk-private-member.log"; line = "{`"kty`":`"OKP`",`"crv`":`"Ed25519`",`"d`":`"$jwkPrivateScalar`"}"; pattern = "jwk_private_member" },
        [pscustomobject]@{ name = "jwk-private-member-reordered.log"; line = "{`"d`":`"$jwkPrivateScalar`",`"crv`":`"Ed25519`",`"kty`":`"OKP`"}"; pattern = "jwk_private_member" },
        [pscustomobject]@{ name = "plaintext-keybag-object.log"; line = "{`"keybag`":{`"entries`":1,`"k`":`"$jwkPrivateScalar`"}}"; pattern = "plaintext_keybag_object" },
        # Database dumps carry the column name and its value far apart, so the
        # field-name detectors match nothing; the column list is the anchor.
        [pscustomobject]@{ name = "pg-column-insert.sql"; line = "INSERT INTO public.recovery_state (id, seed) VALUES (1, '$hexSecret');"; pattern = "sql_private_material_column" },
        [pscustomobject]@{ name = "pg-copy-header.sql"; line = "COPY public.recovery_state (id, mnemonic) FROM stdin;"; pattern = "sql_private_material_column" }
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
        # A table whose name merely starts with a private-material word is not a
        # private-material column: `\bseed\b` must not match `seed_catalog`.
        "INSERT INTO public.seed_catalog (id, label) VALUES (3, 'harmless');",
        # Playwright error-context code frames contain source expressions, not
        # runtime values. The bare assignment branch must require a secret-like
        # base64url/hex token rather than treating `Buffer.from(...)` as a seed.
        'const seed = Buffer.from(registered.signingSeedB64url, "base64url");',
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

    # Every finding carries a closed category and the verdict the gate reads.
    foreach ($leak in $leaks) {
        Assert-True ($leak.category -in @("recovery_private_material", "credential_exposure")) "leak for $(Split-Path -Leaf $leak.path) ($($leak.pattern)) has an unknown category '$($leak.category)'"
        Assert-True ($leak.verdict -in @("fail", "allowed_by_artifact_class")) "leak for $(Split-Path -Leaf $leak.path) ($($leak.pattern)) has an unknown verdict '$($leak.verdict)'"
        Assert-True ($leak.artifact_class -eq "log_or_telemetry") "a bare scan root must default to the strict artifact class, got '$($leak.artifact_class)'"
        Assert-True ($leak.verdict -eq "fail") "every finding in a log artifact must fail, got '$($leak.verdict)' for $($leak.pattern)"
    }
    foreach ($privatePattern in @("recovery_private_material_field", "recovery_private_material_assignment", "bip39_mnemonic_sequence", "private_key_block", "jwk_private_member", "plaintext_keybag_object", "sql_private_material_column")) {
        $categorised = @($leaks | Where-Object { $_.pattern -eq $privatePattern })
        Assert-True ($categorised.Count -ge 1) "expected at least one $privatePattern finding to categorise"
        foreach ($leak in $categorised) {
            Assert-True ($leak.category -eq "recovery_private_material") "$privatePattern must be recovery_private_material, got '$($leak.category)'"
        }
    }
    foreach ($credentialPattern in @("authorization_header", "json_secret_field", "query_secret_field", "did_in_token_field")) {
        $categorised = @($leaks | Where-Object { $_.pattern -eq $credentialPattern })
        Assert-True ($categorised.Count -ge 1) "expected at least one $credentialPattern finding to categorise"
        foreach ($leak in $categorised) {
            Assert-True ($leak.category -eq "credential_exposure") "$credentialPattern must be credential_exposure, got '$($leak.category)'"
        }
    }

    # A durable protocol store legitimately holds the signed authorization
    # evidence the spec requires the server to persist, so credential findings
    # there are tolerated. Recovery private material is never tolerated
    # anywhere -- including in a field the credential list also names, because
    # the private-material detectors fire independently.
    $storeRoot = Join-Path $scanRoot "durable-store"
    New-Item -ItemType Directory -Path $storeRoot | Out-Null
    Set-Content -Path (Join-Path $storeRoot "dump.sql") -Value @(
        "INSERT INTO events VALUES ('{`"jws`":`"$bearer`"}');",
        "INSERT INTO recovery VALUES ('{`"mnemonic`":`"$mnemonic`"}');"
    ) -Encoding utf8
    $storeLeaks = @(Find-SecretLeaks -ScanRoots @([pscustomobject]@{ path = $storeRoot; artifact_class = "durable_protocol_store" }))
    $storeCredential = @($storeLeaks | Where-Object { $_.category -eq "credential_exposure" })
    $storePrivate = @($storeLeaks | Where-Object { $_.category -eq "recovery_private_material" })
    Assert-True ($storeCredential.Count -ge 1) "the durable store fixture must produce a credential finding"
    foreach ($leak in $storeCredential) {
        Assert-True ($leak.verdict -eq "allowed_by_artifact_class") "credential evidence in a durable protocol store must be allowed, got '$($leak.verdict)'"
    }
    Assert-True ($storePrivate.Count -ge 1) "the durable store fixture must still produce a private-material finding"
    foreach ($leak in $storePrivate) {
        Assert-True ($leak.verdict -eq "fail") "recovery private material must fail in every artifact class, got '$($leak.verdict)'"
    }
    $storeCounts = Get-SecretScanSummary -Leaks $storeLeaks
    Assert-True ($storeCounts.failing -eq $storePrivate.Count) "only the private-material findings may gate a durable store scan"
    Assert-True ($storeCounts.allowed_by_artifact_class -eq $storeCredential.Count) "credential findings must be counted as allowed, not dropped"

    # Redaction follows the verdict, not the finding count: a store holding only
    # the signed evidence the spec requires it to persist must be left intact,
    # or the dump stops being usable for replay and forensics.
    $evidenceOnlyRoot = Join-Path $scanRoot "durable-store-evidence-only"
    New-Item -ItemType Directory -Path $evidenceOnlyRoot | Out-Null
    $evidenceFile = Join-Path $evidenceOnlyRoot "dump.sql"
    $evidenceLine = "INSERT INTO events VALUES ('{`"jws`":`"$bearer`"}');"
    Set-Content -Path $evidenceFile -Value $evidenceLine -Encoding utf8
    $evidenceLeaks = @(Find-SecretLeaks -ScanRoots @([pscustomobject]@{ path = $evidenceOnlyRoot; artifact_class = "durable_protocol_store" }))
    Assert-True ($evidenceLeaks.Count -ge 1) "the evidence-only fixture must still be reported"
    $evidenceRedaction = Protect-SecretBearingArtifacts -Leaks $evidenceLeaks
    Assert-True ($evidenceRedaction.redacted_files.Count -eq 0) "allowed evidence in a durable store must not be rewritten"
    Assert-True ((Get-Content -LiteralPath $evidenceFile -Raw).Trim() -eq $evidenceLine) "the durable store artifact must be left byte-identical"

    # An unknown artifact class is a configuration error, not a silent default.
    $unknownClassRejected = $false
    try {
        Find-SecretLeaks -ScanRoots @([pscustomobject]@{ path = $storeRoot; artifact_class = "whatever" }) | Out-Null
    } catch {
        $unknownClassRejected = $true
    }
    Assert-True $unknownClassRejected "an unknown artifact class must be rejected rather than defaulted"

    # Canary round trip: detect, redact the artifact itself, re-scan clean, and
    # keep the file/line/pattern evidence in the report. This is what stops a
    # failing Playwright object assertion from leaving the received secret in
    # stdout and error-context.md after the run is collected.
    $canaryRoot = Join-Path $scanRoot "canary"
    New-Item -ItemType Directory -Path $canaryRoot | Out-Null
    $canaryFile = Join-Path $canaryRoot "error-context.md"
    Set-Content -Path $canaryFile -Value @(
        "Expected substring: not present",
        "Received: {`"invite_token`":`"$bearer`",`"mnemonic`":`"$mnemonic`"}",
        "at contact-graph.spec.ts:222"
    ) -Encoding utf8

    $canaryBefore = @(Find-SecretLeaks -ScanRoots @($canaryRoot))
    Assert-True ($canaryBefore.Count -ge 1) "the canary must be detected before redaction"
    $canaryEvidence = @($canaryBefore | Where-Object { $_.line -eq 2 })
    Assert-True ($canaryEvidence.Count -ge 1) "the canary report must record the offending line number"
    Assert-True (@($canaryEvidence | ForEach-Object { $_.pattern }) -contains "json_secret_field") "the canary report must record the matching pattern"

    $canaryRedaction = Protect-SecretBearingArtifacts -Leaks $canaryBefore
    $canaryRedactedCount = @($canaryRedaction.redacted_files).Count
    Assert-True ($canaryRedactedCount -eq 1) "the canary artifact must be redacted in place, redacted $canaryRedactedCount file(s)"
    $canaryText = Get-Content -LiteralPath $canaryFile -Raw
    Assert-True (-not $canaryText.Contains($bearer)) "the redacted artifact must not retain the invite token"
    Assert-True (-not $canaryText.Contains($mnemonic)) "the redacted artifact must not retain the mnemonic"
    Assert-True ($canaryText.Contains("contact-graph.spec.ts:222")) "redaction must preserve the surrounding diagnostic"

    $canaryAfter = @(Find-SecretLeaks -ScanRoots @($canaryRoot))
    Assert-True ($canaryAfter.Count -eq 0) "a re-scan of the redacted artifact must be clean; got: $(@($canaryAfter | ForEach-Object { $_.pattern }) -join ', ')"

    # Wordlist sanity: exactly the standard 2048-entry BIP-39 English list.
    $wordSet = Get-Bip39WordSet
    Assert-True ($wordSet.Count -eq 2048) "BIP-39 wordlist must contain 2048 words, found $($wordSet.Count)"
    Assert-True ($wordSet.Contains("abandon") -and $wordSet.Contains("zoo")) "BIP-39 wordlist must span abandon..zoo"
    Assert-True (-not $wordSet.Contains("the")) "BIP-39 wordlist must not contain non-list filler words"

    # Playwright trace archives capture request headers, bodies, and UI fills
    # before this scanner runs. They therefore cannot be retained safely by
    # default on the joint runner.
    $playwrightConfig = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\..\e2e\playwright.config.ts") -Raw
    Assert-True ($playwrightConfig -match 'trace:\s*"off"') "Playwright trace persistence must remain disabled"
    Assert-True ($playwrightConfig -notmatch 'trace:\s*"retain-on-failure"') "retain-on-failure traces persist joint test secrets"
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

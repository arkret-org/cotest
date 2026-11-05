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
# run-server-conformance.ps1 executes this script before every secret scan and fails the
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
    $dpop = "synthetic.dpop.proof-AAAABBBBCCCC"
    $hashTail = "synthetic-private-hash-tail"
    $hashPassword = "synthetic-password#$hashTail"
    $hexSecret = "deadbeefdeadbeefdeadbeefdeadbeef"
    $didValue = "did:webvh:QmSynthetic:host.example:webvh:alice"
    # b64url of a synthetic 32-byte seed: the exact shape a private OKP JWK's
    # `d` member and a plaintext keybag entry carry.
    $jwkPrivateScalar = "c3ludGhldGljLXNlZWQtdmFsdWUtZm9yLXNjYW5uZXItdGVzdHM"
    $inviteCode = 'ABCD' * 10
    $lookupCode = 'ABCDEFGHJKLMNPQR_23456789'
    $privateBytes = (1..32) -join ','
    $plantedSecrets = @($mnemonic, $bearer, $dpop, $hexSecret, $didValue, $jwkPrivateScalar, $inviteCode, $lookupCode, $privateBytes, $hashPassword, $hashTail)

    # One planted secret per line; the file name documents the vector.
    $planted = @(
        [pscustomobject]@{ name = "json-mnemonic.log"; line = "{`"mnemonic`":`"$mnemonic`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-root-private-key.log"; line = "{`"root_private_key`":`"$hexSecret`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-recovery-key.log"; line = "{`"recovery_key`":`"$mnemonic`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-hkdf-prk.log"; line = "{`"hkdf_prk`":`"$hexSecret`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-secret-b64u.log"; line = "{`"secret_base64url`":`"$hexSecret`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-invite-code.log"; line = "{`"oob_code`":`"$inviteCode`"}"; pattern = "json_secret_field" },
        [pscustomobject]@{ name = "json-token-salt.log"; line = "{`"token_salt`":`"$hexSecret`"}"; pattern = "recovery_private_material_field" },
        [pscustomobject]@{ name = "json-pepper.log"; line = "{`"pepper`":`"$hexSecret`"}"; pattern = "recovery_private_material_field" },
        [pscustomobject]@{ name = "json-signing-seed.log"; line = "{`"signing_seed`":[$privateBytes]}"; pattern = "private_material_byte_array" },
        [pscustomobject]@{ name = "query-invite-code.log"; line = "GET /present?oob_code=$lookupCode"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "password-with-hash.log"; line = "password=$hashPassword"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "fragment-pairing-url.md"; line = "  - textbox `"Agent pairing URL`": https://example.test/pair#token=$bearer&state=public"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "fragment-private-seed.log"; line = "https://example.test/callback#root_seed=$hexSecret"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "fragment-lookup.log"; line = "https://example.test/present#oob_code=$lookupCode"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "fragment-second-field.log"; line = "https://example.test/pair#token=[redacted]#signature=$dpop"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "query-token.log"; line = "token=$bearer"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "query-signature.log"; line = "signature=$dpop"; pattern = "query_secret_field" },
        [pscustomobject]@{ name = "delivered-offline-code.log"; line = "Your invitation code is $inviteCode."; pattern = "invite_delivery_code" },
        [pscustomobject]@{ name = "delivered-lookup-code.log"; line = "Your invitation code is $lookupCode."; pattern = "invite_delivery_code" },
        [pscustomobject]@{ name = "invite-token-url-path.log"; line = "POST /_arkret/open/third-party-invites/present/$inviteCode status=404"; pattern = "invite_token_in_path" },
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
        [pscustomobject]@{ name = "authorization-dpop.log"; line = "    - authorization: DPoP $bearer"; pattern = "authorization_header" },
        [pscustomobject]@{ name = "dpop-proof-header.log"; line = "    - dpop: $dpop"; pattern = "dpop_header" },
        [pscustomobject]@{ name = "redaction-prefix-is-not-marker.log"; line = "{`"jws`":`"[redacted]$bearer`"}"; pattern = "json_secret_field" },
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
        'https://example.test/pair#token=[redacted]&state=public',
        'https://example.test/pair#token=%5Bredacted%5D#state=public',
        'https://example.test/pair?token=[redacted]#state=public',
        '{"status":"ok","principal_id":"ak:did_core:webvh:QmExample"}',
        '{"pepper_id":"pepper-public-id","token_salt_id":"salt-public-id","oob_code_kind":"offline_token"}',
        'INFO completed request in 42ms path=/_arkret/describe',
        'service route signature_verified=1 original_intent=preserved',
        '[consent-call] media_token_issued=1 revoked_token=0',
        '{"artifact_kind":"queued_signal_observation_digest","sha256":"sha256:public-digest","byte_length":1234}',
        # A table whose name merely starts with a private-material word is not a
        # private-material column: `\bseed\b` must not match `seed_catalog`.
        "INSERT INTO public.seed_catalog (id, label) VALUES (3, 'harmless');",
        # Playwright error-context code frames contain source expressions, not
        # runtime values. The bare assignment branch must require a secret-like
        # base64url/hex token rather than treating `Buffer.from(...)` as a seed.
        'const seed = Buffer.from(registered.signingSeedB64url, "base64url");',
        '{"jws":"[redacted:detached_jws]"}',
        '{"credential":"<redacted>"}',
        '{"request":{"url":"https://example.test/blob?access_token=%5Bredacted%5D"},"status":401}',
        '{"request":{"url":"https://example.test/blob?access_token=[redacted]"},"status":401}',
        'url="https://example.test/blob?access_token=%5Bredacted%5D" status=401',
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
    foreach ($privatePattern in @("recovery_private_material_field", "recovery_private_material_assignment", "private_material_byte_array", "bip39_mnemonic_sequence", "private_key_block", "jwk_private_member", "plaintext_keybag_object", "sql_private_material_column")) {
        $categorised = @($leaks | Where-Object { $_.pattern -eq $privatePattern })
        Assert-True ($categorised.Count -ge 1) "expected at least one $privatePattern finding to categorise"
        foreach ($leak in $categorised) {
            Assert-True ($leak.category -eq "recovery_private_material") "$privatePattern must be recovery_private_material, got '$($leak.category)'"
        }
    }
    foreach ($credentialPattern in @("authorization_header", "dpop_header", "invite_delivery_code", "invite_token_in_path", "json_secret_field", "query_secret_field", "did_in_token_field")) {
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
        "Received: {`"pepper`":`"$hexSecret`",`"signing_seed`":[$privateBytes]}",
        "Your invitation code is $inviteCode.",
        "Your invitation code is $lookupCode.",
        "POST /_arkret/open/third-party-invites/present/$lookupCode status=404",
        "  - textbox Agent pairing URL: https://example.test/pair#token=$bearer&state=public",
        "https://example.test/pair#token=[redacted]#signature=$dpop",
        "https://example.test/pair#token=%5Bredacted%5D#signature=$dpop",
        "https://example.test/restore#root_seed=$hexSecret",
        "password=$hashPassword",
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
    foreach ($secret in @($hexSecret, $privateBytes, $inviteCode, $lookupCode, $dpop, $hashPassword, $hashTail)) {
        Assert-True (-not $canaryText.Contains($secret)) "the redacted artifact must not retain provider private material"
    }
    Assert-True ($canaryText.Contains('#token=[redacted]&state=public')) 'fragment redaction must preserve the non-secret surrounding query context'
    Assert-True ($canaryText.Contains('#token=[redacted]#signature=[redacted]')) 'a second fragment credential after a safe marker must also be redacted'
    Assert-True ($canaryText.Contains("contact-graph.spec.ts:222")) "redaction must preserve the surrounding diagnostic"

    $canaryAfter = @(Find-SecretLeaks -ScanRoots @($canaryRoot))
    Assert-True ($canaryAfter.Count -eq 0) "a re-scan of the redacted artifact must be clean; got: $(@($canaryAfter | ForEach-Object { $_.pattern }) -join ', ')"
    $runnerSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\run-joint-e2e.ps1') -Raw
    Assert-True ($runnerSource.Contains("`$directory.Name -eq 'third-party-invites'")) "provider results, JUnit and summary must be included in strict artifact scanning"
    Assert-True ($runnerSource.Contains('playwright-output|playwright-report')) 'the actual collected scan roots must include the browser report, not only failure outputs'

    # Native child streams remain published beside raw.log; scan and redact
    # those originals too, even if the merged log was already sanitized.
    $nativeRoot = Join-Path $scanRoot 'native-invocations'
    New-Item -ItemType Directory -Path $nativeRoot | Out-Null
    $nativeStdout = Join-Path $nativeRoot 'cotest_all.cargo.stdout.log'
    $nativeStderr = Join-Path $nativeRoot 'cotest_all.cargo.stderr.log'
    Set-Content -LiteralPath $nativeStdout -Value "token=$bearer" -Encoding utf8
    Set-Content -LiteralPath $nativeStderr -Value "{`"root_private_key`":`"$hexSecret`"}" -Encoding utf8
    Set-Content -LiteralPath (Join-Path $nativeRoot 'raw.log') -Value 'already sanitized' -Encoding utf8
    $nativeRoots = @(Get-NativeInvocationScanRoots -RunDirectory $nativeRoot)
    Assert-True ($nativeRoots.Count -eq 2) 'both original native streams must be selected'
    Assert-True (@($nativeRoots | Where-Object artifact_class -ne 'log_or_telemetry').Count -eq 0) 'native streams must use strict log classification'
    $nativeLeaks = @(Find-SecretLeaks -ScanRoots $nativeRoots)
    Assert-True (@($nativeLeaks | Where-Object path -eq $nativeStdout).Count -ge 1) 'native stdout canary must fail independently of raw.log'
    Assert-True (@($nativeLeaks | Where-Object path -eq $nativeStderr).Count -ge 1) 'native stderr private material must fail'
    $nativeRedaction = Protect-SecretBearingArtifacts -Leaks $nativeLeaks
    Assert-True (@($nativeRedaction.redacted_files).Count -eq 2) 'both native source logs must be redacted'
    Assert-True (@(Find-SecretLeaks -ScanRoots $nativeRoots).Count -eq 0) 'redacted native streams must rescan clean'
    $nativeRunner = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\run-server-conformance.ps1') -Raw
    Assert-True ($nativeRunner.Contains('Get-NativeInvocationScanRoots -RunDirectory $runDir')) 'production runner must include original native streams'

    # Both ordinary Agent pairing journeys display a private fragment and QR.
    $agentSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\e2e\tests\joint\agent-savfox-split-live.spec.ts') -Raw
    Assert-True ($agentSource -match 'const privatePairingTest = jointTest\.extend\(\{\s*trace: "off",\s*screenshot: "off",\s*video: "off",') 'private Agent pairing must disable credential-bearing automatic captures'
    Assert-True ($agentSource.Contains('privatePairingTest.describe("Agent Savfox split live')) 'runtime replacement must use the protected pairing fixture'
    Assert-True ($agentSource.Contains('privatePairingTest("fresh Agent pairing gates the first send')) 'cold pairing must use the protected pairing fixture'

    $deviceSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\e2e\tests\identity\device-key-lifecycle.spec.ts') -Raw
    Assert-True ($deviceSource.Contains('test.use({ trace: "off", video: "off", screenshot: "off" });')) 'device key pairing must not retain private fragment or QR captures'


    # Actual HAR shape: multiline/reordered name/value members, cookies and
    # escaped request bodies must not bypass the line-oriented detectors.
    $harRoot = Join-Path $scanRoot 'har-capture'
    $null = New-Item -ItemType Directory -Path $harRoot
    $harPath = Join-Path $harRoot 'network.har'
    $harCredential = 'synthetic-har-auth-AAAABBBBCCCCDDDD'
    $harCookie = 'synthetic-har-cookie-EEEEFFFFGGGGHHHH'
    $harPrivate = 'synthetic-har-private-IIIIJJJJKKKKLLLL'
    $har = [ordered]@{ log = [ordered]@{ version = '1.2'; entries = @(@{
        request = @{
            url = 'https://example.invalid/resource'
            headers = @(@{ value = "Bearer $harCredential"; name = 'AUTHORIZATION' }, @{ name = 'dPoP'; value = $harCredential })
            cookies = @(@{ name = 'session'; value = $harCookie })
            postData = @{ text = "{`"root_seed`":`"$harPrivate`"}" }
        }
        response = @{ headers = @(@{ name = 'Set-Cookie'; value = "session=$harCookie" }) }
    }) } }
    $har | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $harPath -Encoding utf8
    $harOriginalHash = (Get-FileHash -LiteralPath $harPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $harLeaks = @(Find-SecretLeaks -ScanRoots @($harPath))
    Assert-True (@($harLeaks | Where-Object pattern -eq 'har_credential_transport_field').Count -gt 0) 'HAR header/cookie name-value pairs must be detected independently of JSON order and newlines'
    Assert-True (@($harLeaks | Where-Object category -eq 'recovery_private_material').Count -gt 0) 'decoded HAR request bodies must retain the private-material verdict'
    $harStoreLeaks = @(Find-SecretLeaks -ScanRoots @(@{path=$harPath;artifact_class='durable_protocol_store'}))
    Assert-True (@($harStoreLeaks | Where-Object { $_.category -eq 'recovery_private_material' -and $_.verdict -eq 'fail' }).Count -gt 0) 'HAR private bodies cannot inherit a durable credential allowance'
    $harPreviews = ($harLeaks | ConvertTo-Json -Depth 6)
    foreach ($secret in @($harCredential,$harCookie,$harPrivate)) {
        Assert-True (-not $harPreviews.Contains($secret)) 'HAR findings must never publish credential or private body bytes'
    }
    $harRedaction = Protect-SecretBearingArtifacts -Leaks $harLeaks
    Assert-True (@($harRedaction.redacted_files).Count -eq 1) 'an unsafe HAR must be replaced by one safe whole-capture receipt'
    $harReceiptText = Get-Content -LiteralPath $harPath -Raw
    $harReceipt = $harReceiptText | ConvertFrom-Json
    Assert-True ($harReceipt.arkret_redaction_receipt.original_sha256 -ceq $harOriginalHash) 'receipt must bind the exact discarded HAR bytes'
    Assert-True (@($harReceipt.log.entries).Count -eq 0) 'a receipt must retain no opaque HTTP capture fields'
    foreach ($secret in @($harCredential,$harCookie,$harPrivate)) {
        Assert-True (-not $harReceiptText.Contains($secret)) 'no credential, cookie or private request body may remain in the receipt'
    }
    Assert-True (@(Find-SecretLeaks -ScanRoots @($harPath)).Count -eq 0) 'the HAR disposal receipt must rescan clean'

    $safeHarPath = Join-Path $harRoot 'safe.har'
    $safeHar = @{log=@{entries=@(@{request=@{
        url='https://example.invalid/public?sort=asc'
        headers=@(@{name='Authorization';value='Bearer [redacted]'},@{name='X-Request-Id';value='public-request-id'})
        cookies=@(@{name='session';value='[redacted]'})
        postData=@{text='{"token":"[redacted]"}'}
    }})}}
    $safeHar | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $safeHarPath -Encoding utf8
    Assert-True (@(Find-SecretLeaks -ScanRoots @($safeHarPath)).Count -eq 0) 'public and exactly redacted HAR fields must remain admissible'
    $safeHar.log.entries[0].request.headers[0].value = 'Bearer [redacted]unsafe-tail'
    $safeHar | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $safeHarPath -Encoding utf8
    Assert-True (@(Find-SecretLeaks -ScanRoots @($safeHarPath)).Count -gt 0) 'a HAR redaction marker with a private suffix must still fail'

    $invalidHarPath = Join-Path $harRoot 'invalid.har'
    Set-Content -LiteralPath $invalidHarPath -Value '{invalid-json'
    Assert-True (@(Find-SecretLeaks -ScanRoots @($invalidHarPath) | Where-Object pattern -eq 'har_uninspectable_capture').Count -gt 0) 'an unreadable HAR must fail closed'

    $harZip = Join-Path $harRoot 'capture.zip'
    $har | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $harPath -Encoding utf8
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($harZip,[IO.Compression.ZipArchiveMode]::Create)
    try { $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$harPath,'nested/network.har') }
    finally { $archive.Dispose() }
    $harZipLeaks = @(Find-SecretLeaks -ScanRoots @($harZip))
    Assert-True (@($harZipLeaks | Where-Object pattern -eq 'har_credential_transport_field').Count -gt 0) 'nested archive HAR credentials require the same structural scan'
    Assert-True (@($harZipLeaks | Where-Object category -eq 'recovery_private_material').Count -gt 0) 'nested archive decoded HAR bodies must retain the private-material detector'
    $harZipRedaction = Protect-SecretBearingArtifacts -Leaks $harZipLeaks
    Assert-True (@($harZipRedaction.not_redacted).Count -gt 0) 'unsafe archives must be reported for whole-archive disposal, never claimed redacted'
    $embeddedReport = Join-Path $harRoot 'legacy-playwright-report.html'
    $embeddedBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($harZip))
    Set-Content -LiteralPath $embeddedReport -Value "<script>window.playwrightReportBase64 = 'data:application/zip;base64,$embeddedBytes';</script>"
    $embeddedHash = (Get-FileHash -LiteralPath $embeddedReport -Algorithm SHA256).Hash
    $embeddedLeaks = @(Find-SecretLeaks -ScanRoots @($embeddedReport))
    Assert-True (@($embeddedLeaks | Where-Object category -eq 'recovery_private_material').Count -gt 0) 'base64 embedded Playwright archives must not conceal private material'
    Assert-True (@($embeddedLeaks | Where-Object pattern -eq 'har_credential_transport_field').Count -gt 0) 'an embedded archive must use the structural HAR scanner too'
    $embeddedRedaction = Protect-SecretBearingArtifacts -Leaks $embeddedLeaks
    Assert-True (@($embeddedRedaction.not_redacted).Count -gt 0) 'encoded archives require explicit whole-capture disposal, not a claimed partial redaction'
    Assert-True ((Get-FileHash -LiteralPath $embeddedReport -Algorithm SHA256).Hash -ceq $embeddedHash) 'report the original encoded capture unchanged until whole-capture disposal'
    $unknownEmbeddedReport = Join-Path $harRoot 'unknown-report-format.html'
    Set-Content -LiteralPath $unknownEmbeddedReport -Value '<script>window.playwrightReportBase64 = "unknown-format";</script>'
    Assert-True (@(Find-SecretLeaks -ScanRoots @($unknownEmbeddedReport) | Where-Object pattern -eq 'uninspectable_embedded_report').Count -gt 0) 'a changed or incomplete encoded report format must fail closed'
    $usersSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../e2e/helpers/users.ts') -Raw
    Assert-True ($usersSource -notmatch 'recordHar\s*:') 'authenticated browser fixtures must never persist raw HAR before sanitization'

    # Wordlist sanity: exactly the standard 2048-entry BIP-39 English list.
    $dpopPattern = Get-SecretLeakPatterns | Where-Object name -eq "dpop_header"
    Assert-True (-not (& $dpopPattern.validate '  265 |     dpop: mintDpopProof({')) "numbered source invocation must not be mistaken for a DPoP credential"
    Assert-True (& $dpopPattern.validate '  265 |     dpop: "synthetic-private-credential",') "literal credentials in source excerpts must still fail"
    Assert-True (& $dpopPattern.validate 'DPoP: synthetic-private-credential') "ordinary DPoP headers must still fail"

    $wordSet = Get-Bip39WordSet
    Assert-True ($wordSet.Count -eq 2048) "BIP-39 wordlist must contain 2048 words, found $($wordSet.Count)"
    Assert-True ($wordSet.Contains("abandon") -and $wordSet.Contains("zoo")) "BIP-39 wordlist must span abandon..zoo"
    Assert-True (-not $wordSet.Contains("the")) "BIP-39 wordlist must not contain non-list filler words"

    # Playwright trace archives capture request headers, bodies, and UI fills
    # before this scanner runs. They therefore cannot be retained safely by
    # default on the joint runner.
    $playwrightConfig = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\..\e2e\playwright.config.ts") -Raw
    Assert-True ($playwrightConfig -match 'trace:\s*"off"') "Playwright trace persistence must remain disabled"
    Assert-True ($playwrightConfig -match '\["html"\s*,') 'browser reporting must use the native Playwright HTML report'
    Assert-True ($playwrightConfig -match 'open:\s*"never"') 'report generation must not open a browser during an automated run'

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

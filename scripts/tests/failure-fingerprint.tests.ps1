# Regression test for scripts/lib/failure-fingerprint.ps1.
#
# Verifies the properties triage depends on:
#   1. the structural facts are extracted from realistic Playwright failure text,
#   2. two failures with the same root cause share a fingerprint while a
#      different endpoint or assertion site does not,
#   3. per-run identity (uuids, DIDs, correlation ids) does not enter the
#      fingerprint, so the same break fingerprints identically across runs,
#   4. no free-form failure text is carried into the record, and
#   5. retry debris from a test that ultimately passed is classified as such
#      instead of counting as a failure.
#
# Run directly:
#   pwsh -ExecutionPolicy Bypass -File scripts\tests\failure-fingerprint.tests.ps1

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\lib\failure-fingerprint.ps1")

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

$scanRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("failure-fp-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $scanRoot -Force | Out-Null
try {
    $detailAlpha = @"
Error: expected 201, got 403
    at tests/identity/contact-graph.spec.ts:222:14
Response from POST https://127.0.0.1:8698/_arkret/self/contacts/ak:contact:019fa9d5-0000-7000-8000-000000000001/respond
{"error":{"code":"capability_denied","message":"no matching grant"}}
status: 403
correlation_id: 01JQZ7K3NB4S9WTX
"@
    $alpha = Get-FailureFingerprint `
        -Scenario "identity/contact-graph.spec.ts" `
        -TestName "S1 add friend with greeting" `
        -Message "expected 201, got 403" `
        -Detail $detailAlpha `
        -SystemOut ""

    Assert-True ($alpha.endpoint -eq "/_arkret/self/contacts/{id}/respond") "endpoint must be extracted and stabilised, got '$($alpha.endpoint)'"
    Assert-True ($alpha.wire_code -eq "capability_denied") "wire code must be extracted, got '$($alpha.wire_code)'"
    Assert-True ($alpha.assertion_site -eq "identity/contact-graph.spec.ts:222") "assertion site must be extracted, got '$($alpha.assertion_site)'"
    Assert-True ($alpha.http_status -eq "403") "http status must be extracted, got '$($alpha.http_status)'"
    Assert-True ($alpha.correlation_id -eq "01JQZ7K3NB4S9WTX") "correlation id must be extracted, got '$($alpha.correlation_id)'"
    Assert-True ($alpha.fingerprint.Length -eq 16) "fingerprint must be a short stable hash, got '$($alpha.fingerprint)'"

    # Same break in a later run: different resource uuid, different correlation
    # id, different test title. The fingerprint must not move.
    $detailBeta = $detailAlpha `
        -replace '019fa9d5-0000-7000-8000-000000000001', '019fb111-0000-7000-8000-0000000000ff' `
        -replace '01JQZ7K3NB4S9WTX', '01JR00AAAA1B2C3D'
    $beta = Get-FailureFingerprint `
        -Scenario "identity/contact-graph.spec.ts" `
        -TestName "S1 add friend with greeting (retry of the same break)" `
        -Message "expected 201, got 403" `
        -Detail $detailBeta `
        -SystemOut ""
    Assert-True ($beta.fingerprint -eq $alpha.fingerprint) "per-run identity must not enter the fingerprint"
    Assert-True ($beta.correlation_id -ne $alpha.correlation_id) "the correlation id must still be carried for lookup"

    # A different endpoint is a different root cause.
    $gamma = Get-FailureFingerprint `
        -Scenario "identity/contact-graph.spec.ts" `
        -TestName "S4 consent_grant evidence pulls friend into a new realm" `
        -Message "expected 201, got 403" `
        -Detail ($detailAlpha -replace '/respond', '/tombstone') `
        -SystemOut ""
    Assert-True ($gamma.fingerprint -ne $alpha.fingerprint) "a different endpoint must fingerprint differently"

    # A different assertion site is a different root cause.
    $delta = Get-FailureFingerprint `
        -Scenario "identity/contact-graph.spec.ts" `
        -TestName "S1 add friend with greeting" `
        -Message "expected 201, got 403" `
        -Detail ($detailAlpha -replace 'contact-graph\.spec\.ts:222:14', 'contact-graph.spec.ts:301:9') `
        -SystemOut ""
    Assert-True ($delta.fingerprint -ne $alpha.fingerprint) "a different assertion site must fingerprint differently"

    # One broken shared helper is one root cause, however many specs trip over
    # it. Each caller fails at its own spec line, so only the helper frame can
    # hold them together.
    $helperDetail = @"
Error: cotest-wire principal-registration-fixture failed with exit 1:
Caused by:
    missing field ``audience_id``
    at cotestWire (D:\cotest\e2e\helpers\soland-api\wire-client.ts:163:11)
    at registerCoauthPasswordAccount (D:\cotest\e2e\helpers\coauth-register.ts:462:19)
    at D:\cotest\e2e\tests\authz\capability-chain.spec.ts:177:59
"@
    $helperAlpha = Get-FailureFingerprint `
        -Scenario "authz/capability-chain.spec.ts" `
        -TestName "grant lifecycle" `
        -Message "cotest-wire principal-registration-fixture failed" `
        -Detail $helperDetail `
        -SystemOut ""
    $helperBeta = Get-FailureFingerprint `
        -Scenario "calls/webrtc.spec.ts" `
        -TestName "ICE config endpoint rejects unauthenticated callers" `
        -Message "cotest-wire principal-registration-fixture failed" `
        -Detail ($helperDetail -replace 'authz\\capability-chain\.spec\.ts:177:59', 'calls\webrtc.spec.ts:37:5') `
        -SystemOut ""
    Assert-True ($helperAlpha.origin_site -eq "helpers/soland-api/wire-client.ts:163") "the deepest shared helper frame must be extracted, got '$($helperAlpha.origin_site)'"
    Assert-True ($helperAlpha.fingerprint -eq $helperBeta.fingerprint) "two scenarios failing in the same helper share one root cause"
    Assert-True ($helperAlpha.assertion_site -ne $helperBeta.assertion_site) "each caller must still report its own assertion site"

    # A different helper line is a different break.
    $helperGamma = Get-FailureFingerprint `
        -Scenario "authz/capability-chain.spec.ts" `
        -TestName "grant lifecycle" `
        -Message "cotest-wire principal-registration-fixture failed" `
        -Detail ($helperDetail -replace 'wire-client\.ts:163:11', 'wire-client.ts:207:11') `
        -SystemOut ""
    Assert-True ($helperGamma.fingerprint -ne $helperAlpha.fingerprint) "a different helper line must fingerprint differently"

    # The same helper line throwing for a different reason is a different break.
    $helperDelta = Get-FailureFingerprint `
        -Scenario "invites/invite-addressing.spec.ts" `
        -TestName "peer invite delivery defers explicit_address evidence" `
        -Message "cotest-wire event-envelope-proof failed" `
        -Detail @"
Error: cotest-wire event-envelope-proof failed with exit 1:
Caused by:
    DID URL must start with did:
    at cotestWire (D:\cotest\e2e\helpers\soland-api\wire-client.ts:163:11)
    at D:\cotest\e2e\tests\invites\invite-addressing.spec.ts:170:24
"@ `
        -SystemOut ""
    Assert-True ($helperAlpha.error_token -eq "missing_field:audience_id") "a serde field name must be extracted, got '$($helperAlpha.error_token)'"
    Assert-True ($helperDelta.error_token -eq "cotest_wire:event-envelope-proof") "the cotest-wire command must discriminate, got '$($helperDelta.error_token)'"
    Assert-True ($helperDelta.fingerprint -ne $helperAlpha.fingerprint) "one helper line throwing for two reasons must not merge into one root cause"

    # Missing evidence degrades to empty fields rather than throwing.
    $sparse = Get-FailureFingerprint -Scenario "" -TestName "" -Message "" -Detail "" -SystemOut ""
    Assert-True ($sparse.endpoint -eq "" -and $sparse.wire_code -eq "" -and $sparse.assertion_site -eq "" -and $sparse.origin_site -eq "" -and $sparse.error_token -eq "") "a failure with no structural evidence must degrade to empty fields"
    Assert-True ($sparse.fingerprint.Length -eq 16) "even an evidence-free failure must get a fingerprint"

    # The record must carry no free-form failure text: a failing object
    # assertion serialises the whole received value, and copying that into
    # another artifact would undo the secret-scan work.
    $leaky = Get-FailureFingerprint `
        -Scenario "identity/contact-graph.spec.ts" `
        -TestName "S1" `
        -Message 'Received: {"invite_token":"synthetic-secret-value-AAAA"}' `
        -Detail 'Received: {"invite_token":"synthetic-secret-value-AAAA"}' `
        -SystemOut 'Received: {"invite_token":"synthetic-secret-value-AAAA"}'
    foreach ($property in $leaky.PSObject.Properties) {
        $value = [string]$property.Value
        Assert-True (-not $value.Contains("synthetic-secret-value-AAAA")) "field '$($property.Name)' carried raw failure text into the report"
    }

    # Retry reconciliation: `alpha` failed for real, `zeta` failed twice then
    # passed. Only alpha's directories may count as failure artifacts.
    $outputDir = Join-Path $scanRoot "playwright-output"
    New-Item -ItemType Directory -Path $outputDir | Out-Null
    foreach ($name in @(
            "identity-contact-graph-S1-add-friend-with-greeting-joint-inkson",
            "identity-contact-graph-S1-add-friend-with-greeting-joint-inkson-retry1",
            "messaging-triad-collaboration-S9-flaky-thing-joint-inkson",
            "messaging-triad-collaboration-S9-flaky-thing-joint-inkson-retry1"
        )) {
        New-Item -ItemType Directory -Path (Join-Path $outputDir $name) | Out-Null
    }
    $reconciliation = Get-RetryArtifactReconciliation `
        -PlaywrightOutputDir $outputDir `
        -FinalFailures @([pscustomobject]@{
            scenario = "identity/contact-graph.spec.ts"
            test     = "S1 add friend with greeting"
        })

    Assert-True ($reconciliation.artifact_directories -eq 4) "every artifact directory must be accounted for, got $($reconciliation.artifact_directories)"
    Assert-True ($reconciliation.final_failure_artifacts -eq 2) "both attempts of the genuinely failing test are failure artifacts, got $($reconciliation.final_failure_artifacts)"
    Assert-True ($reconciliation.retry_only_artifacts -eq 2) "the retried-then-passed test leaves retry debris, not failures, got $($reconciliation.retry_only_artifacts)"
    $retryEntry = @($reconciliation.entries | Where-Object { $_.directory -like "*S9-flaky-thing*retry1" })
    Assert-True ($retryEntry.Count -eq 1) "the retry directory must be listed"
    Assert-True ($retryEntry[0].is_retry) "a `-retry<N>` directory must be marked as a retry"
    Assert-True ($retryEntry[0].attempt -eq 1) "the retry attempt number must be parsed"
    Assert-True ($retryEntry[0].classification -eq "retry_artifact_of_passing_test") "retry debris of a passing test must be classified as such"

    # The real junit parser uses `name` rather than `test`; both record shapes
    # must reconcile identically instead of failing under StrictMode.
    $nameShape = Get-RetryArtifactReconciliation `
        -PlaywrightOutputDir $outputDir `
        -FinalFailures @([pscustomobject]@{
            scenario = "identity/contact-graph.spec.ts"
            name     = "S1 add friend with greeting"
        })
    Assert-True ($nameShape.final_failure_artifacts -eq 2) "junit `name` records must match their final-failure artifacts"

    # An absent output directory is normal (no failures at all), not an error.
    $empty = Get-RetryArtifactReconciliation -PlaywrightOutputDir (Join-Path $scanRoot "missing") -FinalFailures @()
    Assert-True ($empty.artifact_directories -eq 0) "a missing playwright-output directory must reconcile to zero"
} finally {
    Remove-Item -Recurse -Force $scanRoot -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host "failure-fingerprint tests FAILED:" -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host "  - $failure" -ForegroundColor Red
    }
    exit 1
}
Write-Host "failure-fingerprint tests passed"
exit 0

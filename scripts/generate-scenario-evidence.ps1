param([switch]$Check)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$testsRoot = Join-Path $repoRoot "e2e\tests"
$outputPath = Join-Path $repoRoot "e2e\scenarios\evidence-manifest.json"
$scenarios = New-Object System.Collections.Generic.List[object]

# Check the beginning of a concrete UI call against a lexical mask, so a
# comment, import, or quoted code example cannot supply evidence by itself.
# The quoted arguments remain in Source for exact current labels/selectors.
function Test-UiEvidenceCall {
    param([string]$Source, [string]$CodeMask, [string]$Pattern)
    foreach ($candidate in [regex]::Matches($Source, $Pattern)) {
        $token = [regex]::Match($candidate.Value, '\S')
        if ($token.Success -and $CodeMask[$candidate.Index + $token.Index] -notmatch '\s') { return $true }
    }
    return $false
}

foreach ($file in Get-ChildItem -LiteralPath $testsRoot -Recurse -File -Filter "*.spec.ts" | Sort-Object FullName) {
    $source = Get-Content -Raw -LiteralPath $file.FullName
    $relative = [IO.Path]::GetRelativePath($testsRoot, $file.FullName) -replace '\\', '/'
    $scenarioKey = $relative.Substring(0, $relative.Length - ".spec.ts".Length)
    # A TestClient Realm write is not an Inkson page action. Resolve the
    # actual Garth constructor binding before applying the UI name heuristic;
    # mixed specs keep their independently named product page calls.
    $garthClientNames = @([regex]::Matches($source, '\b(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+GarthTestClient\s*\(') | ForEach-Object { $_.Groups[1].Value })
    $usesAgentRuntime = ($source -match '\.pairAgentRuntime\s*\(') -and ($source -match '\.submitAgentMessage\s*\(')
    $usesGarthRuntime = $garthClientNames.Count -gt 0 -or $usesAgentRuntime
    $uiSource = $source
    foreach ($clientName in $garthClientNames) {
        $uiSource = [regex]::Replace($uiSource, '\b' + [regex]::Escape($clientName) + '\.createRealm\s*\(', '.createGarthRealm(')
    }
    # This helper executes registration, OAuth, recovery-key confirmation and
    # principal founding through the ordinary product UI. An import is not a call.
    $uiCodeMask = [regex]::Replace($uiSource, '(?s)"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*''|`(?:\\.|[^`\\])*`|//[^\r\n]*|/\*.*?\*/', [System.Text.RegularExpressions.MatchEvaluator]{
        param($sourceToken)
        return [regex]::Replace($sourceToken.Value, '[^\r\n]', ' ')
    })
    $usesRegisteredUi = $uiSource -match '\bopenRegisteredUserPage\s*\('
    # Opening the actual registration authority is UI coverage, never proof of
    # completed identity establishment.
    $usesRegistrationFormUi = (Test-UiEvidenceCall $uiSource $uiCodeMask '\.locator\(\s*["'']\.register-open-account-authority["'']\s*\)\s*\.click\s*\(') -or (
        (Test-UiEvidenceCall $uiSource $uiCodeMask '\.goto\(\s*["'']/register["'']\s*\)') -and
        (Test-UiEvidenceCall $uiSource $uiCodeMask '\.getByLabel\(\s*["'']Station["'']\s*,\s*\{\s*exact\s*:\s*true\s*\}\s*\)\s*\.fill\(\s*colandBaseUrl\(\)\s*\)') -and
        (Test-UiEvidenceCall $uiSource $uiCodeMask '\.locator\(\s*["'']\.registration-panel["'']\s*\)\s*\.getByRole\(\s*["'']button["'']\s*,\s*\{\s*name\s*:\s*["'']Continue["'']\s*,\s*exact\s*:\s*true\s*\}\s*\)\s*\.click\s*\(')
    )
    $usesInksonUi = ($uiSource -match 'open(?:Dpop)?UserPage|openUserPage|\.goto(?:Home|Login|Setup|Timeline)|\.createRealm\(|\.sendTimelineMessage\(') -or $usesRegisteredUi -or $usesRegistrationFormUi
    $usesCoauthAccountUi = $source -match '\bcoauthBaseUrl\b' -and
        $source -match '["'']/_coauth/account/auth/register["'']' -and
        $source -match '\bsubmitCoauthPasswordCredentials\s*\(' -and $source -match '\.goto\('
    $usesProductUi = $usesInksonUi -or $usesCoauthAccountUi
    $usesCoauthAccountHttpFixture = Test-UiEvidenceCall $uiSource $uiCodeMask '\bawait\s+register(?:Unbound)?CoauthPasswordAccount\s*\('
    $usesRawHttp = $usesCoauthAccountHttpFixture -or $source -match '\brequest\.(?:get|post|put|patch|delete|fetch)\('
    # Agent pairing consumes an existing accepted fixture; the bridge class
    # alone does not mean that this spec executes principal founding itself.
    $usesCanonicalProvisioning = $garthClientNames.Count -gt 0 -or ($source -match '\.(?:provisionUnboundAccount|createAccountHandoff|foundPrincipal|recoverPrincipal)\s*\(|canonicalProvisioning|provisioning-fixture')
    $usesRustBridge = $usesCanonicalProvisioning -or $usesAgentRuntime
    # The joint fixture injects the founding sessions before the spec body.
    # A later OAuth ceremony does not remove that earlier evidence boundary.
    $usesJointSessionFixture = $source -match 'helpers/joint-fixture' -and $source -match '\bjoint(?:Users|Realm)\b'
    $bypasses = New-Object System.Collections.Generic.List[string]
    if ($source -match 'prepareMlsDevice\s*:\s*false') { $bypasses.Add("prepare_mls_device_false") }
    if ($source -match 'allowRecoveryOverride\s*:\s*true') { $bypasses.Add("recovery_override") }
    if ($uiSource -match '\.createRealm\s*\(' -and $source -notmatch 'allowPassivePromptDismissal\s*:\s*false') { $bypasses.Add("create_realm_passive_prompt_dismissal") }
    if (($source -match 'sessionCredential\s*:|openDpopUserPage|openDpopUserPageFromSession|createDpopUserSession') -or $usesJointSessionFixture) { $bypasses.Add("session_injection") }
    if ($source -match 'cotestWire|signedEventEnvelope|registerEventSigner') { $bypasses.Add("test_only_signer_or_wire_builder") }
    if ($usesRawHttp) { $bypasses.Add("raw_http_fixture_or_oracle") }

    $identity = New-Object System.Collections.Generic.List[string]
    $usesDirectIdentityUi = (
        (
            (Test-UiEvidenceCall $uiSource $uiCodeMask '\.locator\(\s*["'']\.choose-new-identity["'']\s*\)\s*\.click\s*\(') -and
            (Test-UiEvidenceCall $uiSource $uiCodeMask '\.locator\(\s*["'']\.onboarding-bind-identity["'']\s*\)\s*\.click\s*\(') -and
            (Test-UiEvidenceCall $uiSource $uiCodeMask '\.getByTestId\(\s*["'']coauth-oauth-approve["'']\s*\)')
        ) -or (
            (Test-UiEvidenceCall $uiSource $uiCodeMask '\.locator\(\s*["'']\.identity-choice-card["'']\s*\)\s*\.getByRole\(\s*["'']button["'']\s*,\s*\{\s*name\s*:\s*["'']Continue["'']\s*,\s*exact\s*:\s*true\s*\}\s*\)\s*\.click\s*\(') -and
            (Test-UiEvidenceCall $uiSource $uiCodeMask '\.locator\(\s*["'']button\.onboarding-bind-identity["'']\s*\)\s*\.click\s*\(') -and
            (Test-UiEvidenceCall $uiSource $uiCodeMask '\.locator\(\s*["'']\.login-container["'']\s*\)\s*\.getByRole\(\s*["'']button["'']\s*,\s*\{\s*name\s*:\s*["'']Allow["'']\s*,\s*exact\s*:\s*true\s*\}\s*\)')
        )
    )
    $usesInksonUi = $usesInksonUi -or $usesDirectIdentityUi
    $usesProductUi = $usesInksonUi -or $usesCoauthAccountUi
    $usesExplicitCoauthRegistrationUi = (Test-UiEvidenceCall $uiSource $uiCodeMask '\.getByRole\(\s*["'']button["'']\s*,\s*\{\s*name\s*:\s*/create account/i\s*\}\s*\)\s*\.click\s*\(') -and
        (Test-UiEvidenceCall $uiSource $uiCodeMask '\bawait\s+registrationEmailCode\s*\(')
    if ($usesRegisteredUi -or ($usesDirectIdentityUi -and $usesExplicitCoauthRegistrationUi)) {
        $identity.Add("coauth_registration_ui")
        $identity.Add("oauth_authorization_ui")
        $identity.Add("inkson_identity_onboarding_ui")
    } elseif ($usesDirectIdentityUi) {
        # This path consumes a Coauth Account fixture. Its actual UI ceremony
        # is OAuth plus principal onboarding, not Coauth account registration.
        $identity.Add("oauth_authorization_ui")
        $identity.Add("inkson_identity_onboarding_ui")
    } elseif ($usesCoauthAccountUi -and -not $usesInksonUi) {
        $identity.Add("coauth_registration_ui")
    } elseif ($source -match 'serverLoginViaCoauth|submitCoauthPasswordCredentials') {
        $identity.Add("oauth_authorization_ui")
    }
    if ($bypasses -contains "session_injection") { $identity.Add("session_injection") }
    # The canonical provisioning chain runs in Rust and reaches this suite
    # through `cotest-provision`. It is neither a UI authorization nor a session
    # injection: the account is registered, authorized and bound for real,
    # without a browser and without an injected credential. Classifying it as
    # `fixture_or_not_applicable` would understate the only browserless path
    # that establishes a principal honestly.
    if ($usesCanonicalProvisioning) { $identity.Add("canonical_provisioning_chain") }
    if ($identity.Count -eq 0) { $identity.Add("fixture_or_not_applicable") }

    $services = New-Object System.Collections.Generic.List[string]
    if ($usesInksonUi) { $services.Add("inkson") }
    if ($source -match 'colandBaseUrl|/_arkret/|\brequest\.') { $services.Add("coland") }
    if ($source -match 'coauthBaseUrl|serverLoginViaCoauth|Coauth') { $services.Add("coauth") }
    if ($usesRegisteredUi) {
        $services.Add("coland")
        $services.Add("coauth")
    }
    foreach ($service in @("flagon", "floria", "savfox", "codmin")) {
        if ($source -match $service) { $services.Add($service) }
    }
    # This classifier reads one file, so a spec that reaches its services
    # through a fixture shows none of the textual signals above. The canonical
    # chain registers at Coauth, reads the verification mail out of the mock
    # inbox, and founds the principal at the Station — say so here rather than
    # letting the fixture make the manifest understate the run.
    if ($usesCanonicalProvisioning) {
        $services.Add("coauth")
        $services.Add("coland")
    }

    $mocks = New-Object System.Collections.Generic.List[string]
    foreach ($mock in @("idp", "email", "witness", "did_host", "push_gateway", "mimi_facade", "applet_registry", "savfox_model", "challenge_provider", "claim_issuer")) {
        $pattern = 'mock[_-]?' + [regex]::Escape($mock)
        if ($source -match $pattern) { $mocks.Add($mock) }
    }
    # Both registration helpers read the managed stack's mock email inbox.
    # Match calls rather than imports when a spec invokes verification directly.
    if ($usesCoauthAccountHttpFixture -or $usesCanonicalProvisioning -or $usesRegisteredUi -or ($source -match '\bregistrationEmailCode\s*\(')) {
        $mocks.Add("email")
    }

    $producers = New-Object System.Collections.Generic.List[string]
    if ($usesInksonUi) { $producers.Add("inkson_product_client") }
    if ($usesCoauthAccountUi) { $producers.Add("coauth_product_client") }
    if ($usesGarthRuntime) { $producers.Add("garth_runtime") }
    if ($source -match 'cotestWire|signedEventEnvelope|canonicalJson') { $producers.Add("cotest_wire_oracle") }
    if ($usesRawHttp) { $producers.Add("raw_http_fixture") }
    if ($usesRustBridge) { $producers.Add("rust_provisioning_bridge") }
    if ($producers.Count -eq 0) { $producers.Add("fixture_or_not_applicable") }

    $evidenceClass = if ($scenarioKey -eq "identity/recovery-key-to-encrypted-realm") {
        "live-product"
    } elseif ($usesCanonicalProvisioning -or $usesAgentRuntime) {
        # Real Coauth, real Coland, a real account and a real PCR genesis. The
        # `harness/` blanket below covers specs that only exercise fixtures;
        # this one exercises server contracts through the canonical chain.
        "server-contract"
    } elseif ($scenarioKey -match '^(conformance|harness)/') {
        "fixture-only"
    } elseif ($usesProductUi -and $bypasses.Count -eq 0) {
        "live-product"
    } elseif (-not $usesProductUi -and $usesRawHttp) {
        "server-contract"
    } else {
        "fixture-only"
    }

    $excludedClaims = New-Object System.Collections.Generic.List[string]
    if ($usesCoauthAccountUi -and -not $usesInksonUi) {
        $excludedClaims.Add("oauth_authorization")
        $excludedClaims.Add("principal_registration_and_recovery_custody")
        $excludedClaims.Add("coland_business_operations")
    }
    if ($bypasses -contains "session_injection") { $excludedClaims.Add("registration_login_authorization") }
    if ($bypasses -contains "prepare_mls_device_false") { $excludedClaims.Add("mls_device_and_keypackage_readiness") }
    if ($bypasses -contains "recovery_override") { $excludedClaims.Add("recovery_configured_encrypted_realm_creation") }
    if ($bypasses -contains "create_realm_passive_prompt_dismissal") { $excludedClaims.Add("mls_backup_unlock_and_missing_recovery_prompt_behavior") }
    if ($bypasses -contains "test_only_signer_or_wire_builder") { $excludedClaims.Add("product_protocol_object_generation") }
    if ($bypasses -contains "raw_http_fixture_or_oracle") { $excludedClaims.Add("ui_driven_business_flow_for_raw_http_steps") }

    $scenarios.Add([ordered]@{
        scenario_key = $scenarioKey
        suite_kind = "joint-e2e"
        realism_level = $evidenceClass
        evidence_class = $evidenceClass
        real_services = @($services | Sort-Object -Unique)
        mocks = @($mocks | Sort-Object -Unique)
        identity_establishment = @($identity | Sort-Object -Unique)
        protocol_object_producers = @($producers | Sort-Object -Unique)
        declared_test_bypasses = @($bypasses | Sort-Object -Unique)
        claims_excluded = @($excludedClaims | Sort-Object -Unique)
    }) | Out-Null
}

$manifest = [ordered]@{

    suite_kind = "joint-e2e"
    scenarios = $scenarios.ToArray()
}
$content = (($manifest | ConvertTo-Json -Depth 8) -replace "`r`n", "`n") + "`n"
if ($Check) {
    if (-not (Test-Path -LiteralPath $outputPath)) {
        throw "scenario evidence manifest is missing: $outputPath"
    }
    $actual = Get-Content -Raw -LiteralPath $outputPath
    if (($actual -replace "`r`n", "`n") -ne ($content -replace "`r`n", "`n")) {
        throw "scenario evidence manifest is stale: $outputPath"
    }
    Write-Host "scenario evidence manifest is current"
} else {
    [System.IO.File]::WriteAllText($outputPath, $content, [System.Text.UTF8Encoding]::new($false))
    Write-Host "updated $outputPath"
}

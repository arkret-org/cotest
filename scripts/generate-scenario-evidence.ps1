param([switch]$Check)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$testsRoot = Join-Path $repoRoot "e2e\tests"
$outputPath = Join-Path $repoRoot "e2e\scenarios\evidence-manifest.json"
$scenarios = New-Object System.Collections.Generic.List[object]

foreach ($file in Get-ChildItem -LiteralPath $testsRoot -Recurse -File -Filter "*.spec.ts" | Sort-Object FullName) {
    $source = Get-Content -Raw -LiteralPath $file.FullName
    $relative = [IO.Path]::GetRelativePath($testsRoot, $file.FullName) -replace '\\', '/'
    $scenarioKey = $relative.Substring(0, $relative.Length - ".spec.ts".Length)
    $usesProductUi = $source -match 'open(?:Dpop)?UserPage|openUserPage|\.goto(?:Home|Login|Setup|Timeline)|\.createRealm\(|\.sendTimelineMessage\('
    $usesRawHttp = $source -match '\brequest\.(?:get|post|put|patch|delete|fetch)\('
    $usesCanonicalProvisioning = $source -match 'ProvisioningBridge|canonicalProvisioning|provisioning-fixture'
    $bypasses = New-Object System.Collections.Generic.List[string]
    if ($source -match 'prepareMlsDevice\s*:\s*false') { $bypasses.Add("prepare_mls_device_false") }
    if ($source -match 'allowRecoveryOverride\s*:\s*true') { $bypasses.Add("recovery_override") }
    if ($source -match '\.createRealm\s*\(' -and $source -notmatch 'allowPassivePromptDismissal\s*:\s*false') { $bypasses.Add("create_realm_passive_prompt_dismissal") }
    if ($source -match 'sessionCredential\s*:|openDpopUserPage|openDpopUserPageFromSession|createDpopUserSession') { $bypasses.Add("session_injection") }
    if ($source -match 'cotestWire|signedEventEnvelope|registerEventSigner') { $bypasses.Add("test_only_signer_or_wire_builder") }
    if ($usesRawHttp) { $bypasses.Add("raw_http_fixture_or_oracle") }

    $identity = New-Object System.Collections.Generic.List[string]
    if ($scenarioKey -eq "identity/recovery-key-to-encrypted-realm") {
        $identity.Add("coauth_registration_ui")
        $identity.Add("oauth_authorization_ui")
        $identity.Add("inkson_identity_onboarding_ui")
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
    if ($usesProductUi) { $services.Add("inkson") }
    if ($source -match 'solandBaseUrl|/_arkret/|\brequest\.') { $services.Add("soland") }
    if ($source -match 'coauthBaseUrl|serverLoginViaCoauth|Coauth') { $services.Add("coauth") }
    foreach ($service in @("teabay", "floria", "savfox", "sodmin")) {
        if ($source -match $service) { $services.Add($service) }
    }
    # This classifier reads one file, so a spec that reaches its services
    # through a fixture shows none of the textual signals above. The canonical
    # chain registers at Coauth, reads the verification mail out of the mock
    # inbox, and founds the principal at the Station — say so here rather than
    # letting the fixture make the manifest understate the run.
    if ($usesCanonicalProvisioning) {
        $services.Add("coauth")
        $services.Add("soland")
    }

    $mocks = New-Object System.Collections.Generic.List[string]
    foreach ($mock in @("idp", "email", "witness", "did_host", "push_gateway", "mimi_facade", "applet_registry", "savfox_model", "challenge_provider", "claim_issuer")) {
        $pattern = 'mock[_-]?' + [regex]::Escape($mock)
        if ($source -match $pattern) { $mocks.Add($mock) }
    }
    if ($usesCanonicalProvisioning) { $mocks.Add("email") }

    $producers = New-Object System.Collections.Generic.List[string]
    if ($usesProductUi) { $producers.Add("inkson_product_client") }
    if ($source -match 'cotestWire|signedEventEnvelope|canonicalJson') { $producers.Add("cotest_wire_oracle") }
    if ($usesRawHttp) { $producers.Add("raw_http_fixture") }
    if ($usesCanonicalProvisioning) { $producers.Add("rust_provisioning_bridge") }
    if ($producers.Count -eq 0) { $producers.Add("fixture_or_not_applicable") }

    $evidenceClass = if ($scenarioKey -eq "identity/recovery-key-to-encrypted-realm") {
        "live-product"
    } elseif ($usesCanonicalProvisioning) {
        # Real Coauth, real Soland, a real account and a real PCR genesis. The
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
    schema = "arkret.scenario-evidence.v1"
    suite_kind = "joint-e2e"
    scenarios = $scenarios.ToArray()
}
$content = ($manifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine
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
    $content | Set-Content -NoNewline -Encoding UTF8 -LiteralPath $outputPath
    Write-Host "updated $outputPath"
}

import path from "node:path";

export function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

export function optionalEnv(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

export type SolandKey = "alpha" | "beta" | "default";

export function solandBaseUrl(key: SolandKey = "default"): string {
  if (key === "alpha") {
    return requiredEnv("COTEST_SOLAND_ALPHA_BASE_URL").replace(/\/$/, "");
  }
  if (key === "beta") {
    return requiredEnv("COTEST_SOLAND_BETA_BASE_URL").replace(/\/$/, "");
  }
  return requiredEnv("COTEST_SOLAND_BASE_URL").replace(/\/$/, "");
}

// Conformance debug endpoints live on the spec-reserved test-only namespace
// `/_arkret/_conformance/*` (service-http-binding.md §2.1.2). The leading `_`
// marks `_conformance` as a reserved test-only segment, NOT a production
// trust-surface classifier; it is profile-gated on `ak.profile.conformance_harness.v1`
// and production builds MUST 404 the whole namespace. Tests target this base;
// the harness only reaches it when the server runs under the conformance build profile.
export function conformanceBaseUrl(key: SolandKey = "default"): string {
  return `${solandBaseUrl(key)}/_arkret/_conformance`;
}

// Service DIDs default to did:webvh (v1 core default service method,
// identity-did.md); the fixture SCID form matches the spec conformance
// vectors. did:web is reserved for explicit no-history / negative fixtures.
export function solandServiceId(key: SolandKey = "default"): string {
  if (key === "alpha") {
    return (
      optionalEnv("COTEST_SOLAND_ALPHA_SERVICE_ID") ??
      "ak:did_core:webvh:z6mkfixture"
    );
  }
  if (key === "beta") {
    return (
      optionalEnv("COTEST_SOLAND_BETA_SERVICE_ID") ??
      "ak:did_core:webvh:z6mkfixture"
    );
  }
  return (
    optionalEnv("COTEST_SOLAND_SERVICE_ID") ??
    "ak:did_core:key:z6MkquRrzPs7F2ueYKgkbi6CgpYqwhbpBRDLeyWEAHVBxAdN"
  );
}

export function solandServiceFullId(key: SolandKey = "default"): string {
  if (key === "alpha") {
    return (
      optionalEnv("COTEST_SOLAND_ALPHA_SERVICE_FULL_ID") ??
      "did:webvh:z6mkfixture:soland-alpha.joint-e2e.local"
    );
  }
  if (key === "beta") {
    return (
      optionalEnv("COTEST_SOLAND_BETA_SERVICE_FULL_ID") ??
      "did:webvh:z6mkfixture:soland-beta.joint-e2e.local"
    );
  }
  return (
    optionalEnv("COTEST_SOLAND_SERVICE_FULL_ID") ??
    "did:key:z6MkquRrzPs7F2ueYKgkbi6CgpYqwhbpBRDLeyWEAHVBxAdN"
  );
}

// True when the dual-soland topology (used by S2 cross-server federation)
// has been provisioned by the harness. Scenarios consult this to skip
// rather than fail when running on the single-server profile.
export function hasDualSoland(): boolean {
  return Boolean(
    optionalEnv("COTEST_SOLAND_ALPHA_BASE_URL") &&
    optionalEnv("COTEST_SOLAND_BETA_BASE_URL"),
  );
}

export function assertDualSolandNotRequired(context: string): void {
  if (process.env.COTEST_REQUIRE_DUAL_SOLAND === "1") {
    throw new Error(
      `${context}: COTEST_REQUIRE_DUAL_SOLAND=1 (dual soland topology declared present) ` +
        `but alpha/beta soland endpoints are unavailable — refusing to silently skip ` +
        `federation coverage and report a false green. Pass -DualSoland to ` +
        `scripts/run-joint-e2e.ps1 or unset COTEST_REQUIRE_DUAL_SOLAND.`,
    );
  }
}

export function inksonBaseUrl(key: SolandKey = "default"): string {
  if (key === "alpha") {
    return (
      optionalEnv("COTEST_INKSON_ALPHA_BASE_URL")?.replace(/\/$/, "") ??
      inksonBaseUrl()
    );
  }
  if (key === "beta") {
    return (
      optionalEnv("COTEST_INKSON_BETA_BASE_URL")?.replace(/\/$/, "") ??
      inksonBaseUrl()
    );
  }
  return requiredEnv("COTEST_INKSON_BASE_URL").replace(/\/$/, "");
}

export function coauthBaseUrl(): string | undefined {
  return optionalEnv("COTEST_COAUTH_BASE_URL")?.replace(/\/$/, "");
}

export function coauthServiceId(): string {
  return (
    optionalEnv("COTEST_COAUTH_SERVICE_ID") ??
    "did:webvh:z6mkfixture:coauth.joint-e2e.local"
  );
}

export function coauthSessionGrantIntrospectionBearer(): string | undefined {
  return optionalEnv("COTEST_COAUTH_SESSION_GRANT_INTROSPECTION_BEARER");
}

export function embeddedWebvhRegistrationBearer(): string | undefined {
  return optionalEnv("COTEST_EMBEDDED_WEBVH_REGISTRATION_BEARER");
}

// The OAuth `client_id` soland is configured to advertise in
// `/_arkret/describe.auth_metadata.methods[].client_id` (soland config
// `oidc_client_id`). The joint harness sets this to the coauth-seeded
// "Inkson Dev" client ULID; tests assert describe surfaces it verbatim.
export function coauthOidcClientId(): string | undefined {
  return optionalEnv("COTEST_OIDC_CLIENT_ID");
}

// Pre-seeded password account usable to drive the *real* coauth browser
// login + consent ceremony (oidc-login-flow.spec.ts). Unset on CI, so the
// UI flow self-skips; set both to opt in locally against a stack whose coauth
// already holds the account.
export function realOidcLoginHandle(): string | undefined {
  return optionalEnv("COTEST_OIDC_LOGIN_HANDLE");
}

export function realOidcLoginPassword(): string | undefined {
  return optionalEnv("COTEST_OIDC_LOGIN_PASSWORD");
}

export function mockIdpBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_IDP_BASE_URL")?.replace(/\/$/, "");
}

export function mockEmailBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_EMAIL_BASE_URL")?.replace(/\/$/, "");
}

export function mockClaimIssuerBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_CLAIM_ISSUER_BASE_URL")?.replace(/\/$/, "");
}

export function mockClaimIssuerDid(): string {
  return (
    optionalEnv("COTEST_MOCK_CLAIM_ISSUER_DID") ??
    "did:webvh:z6mkfixture:vc-issuer.joint-e2e.local"
  );
}

export function mockChallengeProviderBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_CHALLENGE_PROVIDER_BASE_URL")?.replace(
    /\/$/,
    "",
  );
}

export function mockChallengeProviderDid(): string {
  return (
    optionalEnv("COTEST_MOCK_CHALLENGE_PROVIDER_DID") ??
    "did:webvh:z6mkfixture:captcha.joint-e2e.local"
  );
}

export function mockWitnessBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_WITNESS_BASE_URL")?.replace(/\/$/, "");
}

export function mockWitnessDid(): string | undefined {
  return optionalEnv("COTEST_MOCK_WITNESS_DID");
}

export function mockWitnessQuorumBaseUrls(): string[] {
  const raw = optionalEnv("COTEST_MOCK_WITNESS_QUORUM_BASE_URLS");
  if (!raw) {
    const single = mockWitnessBaseUrl();
    return single ? [single] : [];
  }
  return raw
    .split(",")
    .map((value) => value.trim().replace(/\/$/, ""))
    .filter(Boolean);
}

export function mockWitnessQuorumDids(): string[] {
  const raw = optionalEnv("COTEST_MOCK_WITNESS_QUORUM_DIDS");
  if (!raw) {
    const single = mockWitnessDid();
    return single ? [single] : [];
  }
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

export function mockPolicyServerBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_POLICY_SERVER_BASE_URL")?.replace(/\/$/, "");
}

export function mockPolicyServerDid(): string | undefined {
  return optionalEnv("COTEST_MOCK_POLICY_SERVER_DID");
}

export function mockPushGatewayBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_PUSH_GATEWAY_BASE_URL")?.replace(/\/$/, "");
}

export function mockAppletRegistryBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_APPLET_REGISTRY_BASE_URL")?.replace(
    /\/$/,
    "",
  );
}

export function mockAppletRegistryDid(): string | undefined {
  return optionalEnv("COTEST_MOCK_APPLET_REGISTRY_DID");
}

export function mockTspEndpointBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_TSP_ENDPOINT_BASE_URL")?.replace(/\/$/, "");
}

export function mockTspEndpointVid(): string | undefined {
  return optionalEnv("COTEST_MOCK_TSP_ENDPOINT_VID");
}

export function mockMimiFacadeBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_MIMI_FACADE_BASE_URL")?.replace(/\/$/, "");
}

export function mockMimiFacadeDid(): string | undefined {
  return optionalEnv("COTEST_MOCK_MIMI_FACADE_DID");
}

// mock-did-host.mjs — the counting DID document authority (DID-P1-C01).
// See e2e/helpers/did-host.ts for the counting/assertion API.
export function mockDidHostBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_DID_HOST_BASE_URL")?.replace(/\/$/, "");
}

// The authority (host) the mock's generated did:webvh DIDs live under.
export function mockDidHostAuthority(): string | undefined {
  return optionalEnv("COTEST_MOCK_DID_HOST_AUTHORITY");
}

// The did:webvh SCID the mock mints its DIDs with (mirrors
// src/harness/mod.rs FIXTURE_WEBVH_SCID).
export function mockDidHostScid(): string | undefined {
  return optionalEnv("COTEST_MOCK_DID_HOST_SCID");
}

// Prometheus `/metrics` listeners for the two services that export the
// DID-boundary counters (DID-P1-C01). See e2e/helpers/service-metrics.ts.
// coauth / inkson / bridges expose no metrics endpoint, so they have no
// counterpart here — a scenario about them cannot be expressed this way.
export function solandMetricsUrl(): string | undefined {
  return optionalEnv("COTEST_SOLAND_METRICS_URL")?.replace(/\/$/, "");
}

export function teabayMetricsUrl(): string | undefined {
  return optionalEnv("COTEST_TEABAY_METRICS_URL")?.replace(/\/$/, "");
}

// teabay's public REST base URL (the directory face), when the run includes it.
export function teabayBaseUrl(): string | undefined {
  return optionalEnv("COTEST_TEABAY_BASE_URL")?.replace(/\/$/, "");
}

// The joint run directory for this process. playwright.config.ts always sets
// COTEST_JOINT_RUN_DIR (orchestrator value or a fresh joint-e2e-adhoc run)
// before workers spawn, so the fallback here only covers non-Playwright
// callers of these helpers.
export function jointRunDir(): string {
  return (
    optionalEnv("COTEST_JOINT_RUN_DIR") ??
    path.resolve(
      process.cwd(),
      "..",
      "artifacts",
      "runs",
      "joint-e2e-adhoc",
      "fallback",
    )
  );
}

export function diagnosticsRoot(): string {
  return path.join(jointRunDir(), "diagnostics");
}

export function screenshotRoot(): string {
  return (
    optionalEnv("COTEST_UI_SCREENSHOT_DIR") ??
    path.join(jointRunDir(), "screenshots")
  );
}

export function visualBaselineRoot(): string {
  return (
    optionalEnv("COTEST_UI_VISUAL_BASELINE_DIR") ??
    path.join(jointRunDir(), "visual-baselines")
  );
}

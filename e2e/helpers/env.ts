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
// `/_cokret/_conformance/*` (service-http-binding.md §2.1.2). The leading `_`
// marks `_conformance` as a reserved test-only segment, NOT a production
// trust-surface classifier; it is profile-gated on `ck.profile.conformance_harness.v1`
// and production builds MUST 404 the whole namespace. Tests target this base;
// the harness only reaches it when the server runs under the conformance build profile.
export function conformanceBaseUrl(key: SolandKey = "default"): string {
  return `${solandBaseUrl(key)}/_cokret/_conformance`;
}

export function solandServiceDid(key: SolandKey = "default"): string {
  if (key === "alpha") {
    return optionalEnv("COTEST_SOLAND_ALPHA_SERVICE_DID") ?? "did:web:soland-alpha.joint-e2e.local";
  }
  if (key === "beta") {
    return optionalEnv("COTEST_SOLAND_BETA_SERVICE_DID") ?? "did:web:soland-beta.joint-e2e.local";
  }
  return optionalEnv("COTEST_SOLAND_SERVICE_DID") ?? "did:web:soland.joint-e2e.local";
}

// True when the dual-soland topology (used by S2 cross-server federation)
// has been provisioned by the harness. Scenarios consult this to skip
// rather than fail when running on the single-server profile.
export function hasDualSoland(): boolean {
  return Boolean(
    optionalEnv("COTEST_SOLAND_ALPHA_BASE_URL") && optionalEnv("COTEST_SOLAND_BETA_BASE_URL"),
  );
}

export function yougenBaseUrl(key: SolandKey = "default"): string {
  if (key === "alpha") {
    return optionalEnv("COTEST_YOUGEN_ALPHA_BASE_URL")?.replace(/\/$/, "") ?? yougenBaseUrl();
  }
  if (key === "beta") {
    return optionalEnv("COTEST_YOUGEN_BETA_BASE_URL")?.replace(/\/$/, "") ?? yougenBaseUrl();
  }
  return requiredEnv("COTEST_YOUGEN_BASE_URL").replace(/\/$/, "");
}

export function coauthBaseUrl(): string | undefined {
  return optionalEnv("COTEST_COAUTH_BASE_URL")?.replace(/\/$/, "");
}

export function coauthServiceDid(): string {
  return optionalEnv("COTEST_COAUTH_SERVICE_DID") ?? "did:web:coauth.joint-e2e.local";
}

// The OAuth `client_id` soland is configured to advertise in
// `/_cokret/describe.auth_metadata.methods[].client_id` (soland config
// `oidc_client_id`). The joint harness sets this to the coauth-seeded
// "Yougen Dev" client ULID; tests assert describe surfaces it verbatim.
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
    "did:web:vc-issuer.joint-e2e.local"
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
    "did:web:captcha.joint-e2e.local"
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

export function mockAuditAgentBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_AUDIT_AGENT_BASE_URL")?.replace(/\/$/, "");
}

export function mockAuditAgentDid(): string | undefined {
  return optionalEnv("COTEST_MOCK_AUDIT_AGENT_DID");
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
  return optionalEnv("COTEST_MOCK_APPLET_REGISTRY_BASE_URL")?.replace(/\/$/, "");
}

export function mockAppletRegistryDid(): string | undefined {
  return optionalEnv("COTEST_MOCK_APPLET_REGISTRY_DID");
}

export function mockAgentRuntimeBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_AGENT_RUNTIME_BASE_URL")?.replace(/\/$/, "");
}

export function mockAgentRuntimeDid(): string | undefined {
  return optionalEnv("COTEST_MOCK_AGENT_RUNTIME_DID");
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

// The joint run directory for this process. playwright.config.ts always sets
// COTEST_JOINT_RUN_DIR (orchestrator value or a fresh runs/<ts>-adhoc dir)
// before workers spawn, so the fallback here only covers non-Playwright
// callers of these helpers.
export function jointRunDir(): string {
  return (
    optionalEnv("COTEST_JOINT_RUN_DIR") ??
    path.resolve(process.cwd(), "..", "artifacts", "runs", "adhoc", "joint-e2e")
  );
}

export function diagnosticsRoot(): string {
  return path.join(jointRunDir(), "diagnostics");
}

export function screenshotRoot(): string {
  return optionalEnv("COTEST_UI_SCREENSHOT_DIR") ?? path.join(jointRunDir(), "screenshots");
}

export function visualBaselineRoot(): string {
  return optionalEnv("COTEST_UI_VISUAL_BASELINE_DIR") ?? path.join(jointRunDir(), "visual-baselines");
}

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

// Conformance debug endpoints live on soland's product face (/_soland/self/conformance/*),
// not the protocol face. The spec OpenAPI defines no conformance/* path, and soland mounts
// conformance::router() under /_soland/self. Tests must target this product-face base.
export function conformanceBaseUrl(key: SolandKey = "default"): string {
  return `${solandBaseUrl(key)}/_soland/self/conformance`;
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

export function mockIdpBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_IDP_BASE_URL")?.replace(/\/$/, "");
}

export function mockEmailBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_EMAIL_BASE_URL")?.replace(/\/$/, "");
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

export function diagnosticsRoot(): string {
  return path.join(
    optionalEnv("COTEST_JOINT_RUN_DIR") ?? path.resolve(process.cwd(), "..", "artifacts", "joint-e2e-local"),
    "diagnostics",
  );
}

export function screenshotRoot(): string {
  return (
    optionalEnv("COTEST_UI_SCREENSHOT_DIR") ??
    path.resolve(process.cwd(), "..", "artifacts", "joint-e2e-local", "screenshots")
  );
}

export function visualBaselineRoot(): string {
  return (
    optionalEnv("COTEST_UI_VISUAL_BASELINE_DIR") ??
    path.resolve(process.cwd(), "..", "artifacts", "joint-e2e-local", "visual-baselines")
  );
}

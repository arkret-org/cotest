import path from "node:path";
import fs from "node:fs";

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

export type SolandKey = `server${number}` | "default";

type TopologyService = {
  public_url?: string;
  service_id?: string;
  service_did?: string;
};

type TopologyServer = {
  name: string;
  soland?: TopologyService;
  coauth?: TopologyService;
  inkson?: TopologyService;
};

let cachedTopology: { server_count?: number; servers?: TopologyServer[] } | undefined;

function topology(): { server_count?: number; servers?: TopologyServer[] } | undefined {
  if (cachedTopology) return cachedTopology;
  const topologyPath = optionalEnv("COTEST_TOPOLOGY_PATH");
  if (!topologyPath) return undefined;
  cachedTopology = JSON.parse(fs.readFileSync(topologyPath, "utf8"));
  return cachedTopology;
}

function canonicalServer(key: SolandKey): `server${number}` {
  const normalized = key === "default" ? "server1" : key;
  if (!/^server[1-9][0-9]*$/.test(normalized)) {
    throw new Error(`Invalid joint topology server key: ${key}`);
  }
  return normalized;
}

function serverEnvPrefix(key: SolandKey): string {
  return canonicalServer(key).toUpperCase();
}

function topologyServer(key: SolandKey): TopologyServer | undefined {
  const name = canonicalServer(key);
  return topology()?.servers?.find((server) => server.name === name);
}

function requiredServerValue(
  key: SolandKey,
  suffix: string,
  topologyValue: string | undefined,
  server1Fallback?: string,
): string {
  const name = canonicalServer(key);
  const [kind, ...fieldParts] = suffix.split("_");
  const indexedName = `COTEST_${kind}_${serverEnvPrefix(key)}_${fieldParts.join("_")}`;
  const value =
    optionalEnv(indexedName) ??
    topologyValue ??
    (name === "server1" && server1Fallback
      ? optionalEnv(server1Fallback)
      : undefined);
  if (!value) {
    throw new Error(`Missing ${suffix} configuration for ${name}`);
  }
  return value;
}

export function solandBaseUrl(key: SolandKey = "default"): string {
  return requiredServerValue(
    key,
    "SOLAND_BASE_URL",
    topologyServer(key)?.soland?.public_url,
    "COTEST_SOLAND_BASE_URL",
  ).replace(/\/$/, "");
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
  return requiredServerValue(
    key,
    "SOLAND_SERVICE_ID",
    topologyServer(key)?.soland?.service_id,
    "COTEST_SOLAND_SERVICE_ID",
  );
}

export function solandServiceDid(key: SolandKey = "default"): string {
  return requiredServerValue(
    key,
    "SOLAND_SERVICE_DID",
    topologyServer(key)?.soland?.service_did,
    "COTEST_SOLAND_SERVICE_DID",
  );
}

export function solandServiceResolution(
  key: SolandKey = "default",
): { current_record_url: string } {
  const serviceId = solandServiceId(key);
  return {
    current_record_url: `${solandBaseUrl(key)}/_arkret/open/services/${encodeURIComponent(serviceId)}/resolution`,
  };
}

export function configuredServerCount(): number {
  const declared = Number(optionalEnv("COTEST_SERVER_COUNT") ?? topology()?.server_count ?? 1);
  if (!Number.isInteger(declared) || declared < 1) {
    throw new Error(`Invalid COTEST_SERVER_COUNT: ${declared}`);
  }
  return declared;
}

export function hasServerCount(required: number): boolean {
  return configuredServerCount() >= required;
}

export function configuredServerKeys(): SolandKey[] {
  return Array.from(
    { length: configuredServerCount() },
    (_, index) => `server${index + 1}` as SolandKey,
  );
}

export function assertServerCountNotRequired(context: string, required: number): void {
  if (Number(optionalEnv("COTEST_REQUIRED_SERVER_COUNT") ?? 0) >= required) {
    throw new Error(
      `${context}: the run requires ${required} independent servers, but only ` +
        `${configuredServerCount()} are available; refusing a false-green skip.`,
    );
  }
}

export function inksonBaseUrl(key: SolandKey = "default"): string {
  const value =
    optionalEnv(`COTEST_INKSON_${serverEnvPrefix(key)}_BASE_URL`) ??
    topologyServer(key)?.inkson?.public_url ??
    optionalEnv("COTEST_INKSON_BASE_URL");
  if (!value) throw new Error(`Missing Inkson URL for ${canonicalServer(key)}`);
  return value.replace(/\/$/, "");
}

export function coauthBaseUrl(key: SolandKey = "default"): string | undefined {
  return (
    optionalEnv(`COTEST_COAUTH_${serverEnvPrefix(key)}_BASE_URL`) ??
    topologyServer(key)?.coauth?.public_url ??
    (canonicalServer(key) === "server1"
      ? optionalEnv("COTEST_COAUTH_BASE_URL")
      : undefined)
  )?.replace(/\/$/, "");
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

export function mockPushGatewayBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_PUSH_GATEWAY_BASE_URL")?.replace(/\/$/, "");
}

export function mockAppletRegistryBaseUrl(): string | undefined {
  return optionalEnv("COTEST_MOCK_APPLET_REGISTRY_BASE_URL")?.replace(
    /\/$/,
    "",
  );
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

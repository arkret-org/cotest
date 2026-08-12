// Canonical account-first registration helpers.
//
// A Coauth service account is created without a principal DID. The harness then
// runs the same holder-bound OIDC handoff / lease / challenge / register
// protocol as Inkson. All canonical DTO construction and root signatures are
// delegated to cotest-wire, which consumes Garth and the Arkret Rust SDK.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { type APIRequestContext } from "@playwright/test";
import {
  coauthOidcClientId,
  mockEmailBaseUrl,
  solandBaseUrl,
  solandServiceId,
  type SolandKey,
} from "./env";
import {
  dpopDeviceSeedB64url,
  dpopDeviceKeyFromSeedB64url,
  generateDpopDeviceKey,
  kickoffDpopHeaders,
  mintDpopProof,
  type DpopBoundGrant,
  type DpopDeviceKey,
} from "./session-grant-dpop";
import {
  canonicalJson,
  cotestWire,
  projectFullDidToCoreId,
  typedId,
} from "./soland-api";

export const COAUTH_DEV_EMAIL_CODE = "123456";

export type CoauthPasswordAccount = {
  handle: string;
  email: string;
  password: string;
  displayName: string;
  did: string;
  principalId?: string;
  genesisDeviceId: string;
  recoveryKey: string;
  initialGrant: DpopBoundGrant;
  initialHolderKey: DpopDeviceKey;
  pcrGenesisReceipt: Record<string, unknown>;
  principalRegistrationCheckpoint: Record<string, unknown>;
  genesisClaimed?: boolean;
};

export type CanonicalAccountHandoff = {
  requestId: string;
  accountHandoffGrant: string;
  expiresAt: string;
  binding: Record<string, unknown>;
  deviceKey: DpopDeviceKey;
};

type PrincipalRegistrationFixture = {
  did_operation: Record<string, unknown>;
  recovery_key: string;
  checkpoint: Record<string, unknown>;
  challenge_request: Record<string, unknown>;
};

type OidcAuthorization = {
  issuer: string;
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  authorizationCode: string;
  codeVerifier: string;
};

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

async function responseJsonRecord(
  response: Awaited<ReturnType<APIRequestContext["get"]>>,
  context: string,
): Promise<Record<string, unknown>> {
  const raw = await response.text();
  if (!response.ok()) {
    throw new Error(`${context} failed (${response.status()}): ${raw}`);
  }
  const body = objectRecord(raw ? JSON.parse(raw) : {});
  if (!body) {
    throw new Error(`${context} returned a non-object response: ${raw}`);
  }
  return body;
}

export async function latestMockEmailCode(
  request: APIRequestContext,
  email: string,
): Promise<string | undefined> {
  const base = mockEmailBaseUrl();
  if (!base) {
    return undefined;
  }
  const response = await request.get(
    `${base}/mock/email/verification/inbox?to=${encodeURIComponent(email)}`,
  );
  if (!response.ok()) {
    return undefined;
  }
  const body = objectRecord(await response.json());
  const messages = Array.isArray(body?.messages) ? body.messages : [];
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const token = objectRecord(messages[index])?.token;
    if (typeof token === "string" && token.length > 0) {
      return token;
    }
  }
  return undefined;
}

async function registrationEmailCode(
  request: APIRequestContext,
  email: string,
): Promise<string> {
  if (!mockEmailBaseUrl()) {
    return COAUTH_DEV_EMAIL_CODE;
  }
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const code = await latestMockEmailCode(request, email);
    if (code) {
      return code;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`coauth registration email did not arrive for ${email}`);
}

export async function registerUnboundCoauthPasswordAccount(
  request: APIRequestContext,
  coauthBase: string,
  args: {
    handle: string;
    email?: string;
    password?: string;
    displayName?: string;
  },
): Promise<{
  handle: string;
  email: string;
  password: string;
  displayName: string;
}> {
  const email = args.email ?? `${args.handle}@example.test`;
  const password = args.password ?? "ArkretE2E!2026";
  const displayName = args.displayName ?? `E2E ${args.handle}`;
  const base = `${coauthBase}/_coauth/account/auth/register`;
  const startResponse = await request.post(base, {
    data: {
      handle: args.handle,
      email,
      password,
      password_confirm: password,
    },
  });
  const started = await responseJsonRecord(
    startResponse,
    "coauth account-first registration",
  );
  if (started.status !== "success") {
    throw new Error(
      `coauth account-first registration was rejected: ${JSON.stringify(started)}`,
    );
  }
  const registrationId = stringValue(started.id);
  if (!registrationId) {
    throw new Error("coauth account-first registration omitted id");
  }
  let nextStep = stringValue(started.next_step);
  if (nextStep === "verify_email") {
    const code = await registrationEmailCode(request, email);
    const deadline = Date.now() + 30_000;
    let verified: Record<string, unknown> | undefined;
    while (Date.now() < deadline) {
      verified = await responseJsonRecord(
        await request.post(`${base}/${registrationId}/verify-email`, {
          data: { code },
        }),
        "coauth account email verification",
      );
      if (verified.status === "success") {
        break;
      }
      if (verified.error !== "invalid_code") {
        throw new Error(
          `coauth account email verification failed: ${JSON.stringify(verified)}`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    if (verified?.status !== "success") {
      throw new Error(
        `coauth account email verification timed out: ${JSON.stringify(verified)}`,
      );
    }
    nextStep = stringValue(verified.next_step);
  }
  if (nextStep === "display_name") {
    const named = await responseJsonRecord(
      await request.post(`${base}/${registrationId}/display-name`, {
        data: { display_name: displayName },
      }),
      "coauth account display-name step",
    );
    if (named.status !== "success") {
      throw new Error(
        `coauth display-name step failed: ${JSON.stringify(named)}`,
      );
    }
    nextStep = stringValue(named.next_step);
  }
  if (nextStep !== "finish") {
    throw new Error(
      `unsupported coauth registration next_step: ${String(nextStep)}`,
    );
  }
  const finished = await responseJsonRecord(
    await request.post(`${base}/${registrationId}/finish`, { data: {} }),
    "coauth account registration finish",
  );
  if (finished.status !== "success" || finished.did != null) {
    throw new Error(
      `coauth account-first finish returned an invalid outcome: ${JSON.stringify(finished)}`,
    );
  }
  return { handle: args.handle, email, password, displayName };
}

async function authorizeWithCurrentAccount(
  request: APIRequestContext,
  coauthBase: string,
  audience: string,
  deviceId: string,
): Promise<OidcAuthorization> {
  const discovery = await responseJsonRecord(
    await request.get(`${coauthBase}/.well-known/openid-configuration`),
    "coauth OIDC discovery",
  );
  const issuer = stringValue(discovery.issuer);
  const authorizationEndpoint = stringValue(discovery.authorization_endpoint);
  const clientId = coauthOidcClientId();
  if (!issuer || !authorizationEndpoint || !clientId) {
    throw new Error("coauth OIDC discovery/client configuration is incomplete");
  }
  const redirectUri = "http://127.0.0.1/auth/callback";
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const authorize = new URL(authorizationEndpoint);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("redirect_uri", redirectUri);
  authorize.searchParams.set(
    "scope",
    `openid urn:arkret:client:device:${deviceId}`,
  );
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("nonce", nonce);
  authorize.searchParams.set("resource", audience);
  authorize.searchParams.set("code_challenge_method", "S256");
  authorize.searchParams.set("code_challenge", codeChallenge);

  const authorization = await request.get(authorize.toString(), {
    maxRedirects: 0,
  });
  const location = authorization.headers().location;
  if (!location || ![302, 303, 307, 308].includes(authorization.status())) {
    throw new Error(
      `coauth authorize did not enter approval (${authorization.status()}): ${await authorization.text()}`,
    );
  }
  const approvalUrl = new URL(location, coauthBase);
  const grantId = approvalUrl.pathname.split("/").filter(Boolean).at(-1);
  if (!grantId || !approvalUrl.pathname.includes("/oauth/approval/")) {
    throw new Error(
      `coauth authorize returned an unexpected location: ${approvalUrl}`,
    );
  }
  const approved = await responseJsonRecord(
    await request.post(
      `${coauthBase}/_coauth/self/oauth/authorization-grants/${grantId}/decision`,
      { data: { action: "approve" } },
    ),
    "coauth OAuth approval",
  );
  const redirect = stringValue(approved.redirect_url);
  if (approved.status !== "success" || !redirect) {
    throw new Error(
      `coauth OAuth approval did not return a callback: ${JSON.stringify(approved)}`,
    );
  }
  const callback = new URL(redirect);
  if (callback.searchParams.get("state") !== state) {
    throw new Error("coauth OAuth callback state did not match");
  }
  const authorizationCode = callback.searchParams.get("code");
  if (!authorizationCode) {
    throw new Error(`coauth OAuth callback omitted code: ${callback}`);
  }
  return {
    issuer,
    clientId,
    redirectUri,
    state,
    nonce,
    authorizationCode,
    codeVerifier,
  };
}

export function accountHandoffHeaders(args: {
  deviceKey: DpopDeviceKey;
  accountHandoffGrant: string;
  method: string;
  url: string;
}): Record<string, string> {
  return {
    authorization: `DPoP ${args.accountHandoffGrant}`,
    dpop: mintDpopProof({
      deviceKey: args.deviceKey,
      method: args.method,
      url: args.url,
      grantJwt: args.accountHandoffGrant,
    }),
  };
}

export async function createCanonicalAccountHandoff(
  request: APIRequestContext,
  coauthBase: string,
  args: {
    audience: string;
    deviceId: string;
    deviceKey?: DpopDeviceKey;
    account?: { handle: string; password: string };
  },
): Promise<CanonicalAccountHandoff> {
  const deviceKey = args.deviceKey ?? generateDpopDeviceKey();
  if (args.account) {
    const login = await responseJsonRecord(
      await request.post(`${coauthBase}/_coauth/account/auth/login`, {
        data: args.account,
      }),
      "coauth password authentication",
    );
    if (login.status !== "success") {
      throw new Error(
        `coauth password authentication failed: ${JSON.stringify(login)}`,
      );
    }
  }
  const authorization = await authorizeWithCurrentAccount(
    request,
    coauthBase,
    args.audience,
    args.deviceId,
  );
  const requestId = typedId("request");
  const body = cotestWire<Record<string, unknown>>("account-handoff-request", {
    request_id: requestId,
    audience: args.audience,
    issuer: authorization.issuer,
    client_id: authorization.clientId,
    redirect_uri: authorization.redirectUri,
    state: authorization.state,
    nonce: authorization.nonce,
    authorization_code: authorization.authorizationCode,
    code_verifier: authorization.codeVerifier,
    dpop_seed_b64url: dpopDeviceSeedB64url(deviceKey),
  });
  const url = `${coauthBase}/_arkret/gate/account/authentication-handoffs`;
  const outcome = await responseJsonRecord(
    await request.post(url, {
      data: body,
      headers: kickoffDpopHeaders({ deviceKey, method: "POST", url }),
    }),
    "canonical account handoff",
  );
  const validatedOutcome = cotestWire<Record<string, unknown>>(
    "account-handoff-outcome",
    outcome,
  );
  if (validatedOutcome.request_id !== requestId) {
    throw new Error(
      `invalid account handoff outcome: ${JSON.stringify(validatedOutcome)}`,
    );
  }
  const accountHandoffGrant = stringValue(
    validatedOutcome.account_handoff_grant,
  );
  const expiresAt = stringValue(validatedOutcome.expires_at);
  const binding = objectRecord(validatedOutcome.binding);
  if (!accountHandoffGrant || !expiresAt || !binding) {
    throw new Error(
      `incomplete account handoff outcome: ${JSON.stringify(outcome)}`,
    );
  }
  return { requestId, accountHandoffGrant, expiresAt, binding, deviceKey };
}

export async function registerCoauthPasswordAccount(
  request: APIRequestContext,
  coauthBase: string,
  opts: { handle?: string; password?: string; server?: SolandKey } = {},
): Promise<CoauthPasswordAccount> {
  const slug = (opts.handle ?? `e2e-oidc-${randomUUID()}`).toLowerCase();
  if (!/^[a-z0-9_-]+$/.test(slug)) {
    throw new Error(`coauth test handle must be a bare localpart: ${slug}`);
  }
  const password = opts.password ?? "ArkretE2E!2026";
  const email = `${slug}@example.test`;
  const displayName = `E2E ${slug}`;
  await registerUnboundCoauthPasswordAccount(request, coauthBase, {
    handle: slug,
    email,
    password,
    displayName,
  });

  const deviceSuffix = randomUUID().replace(/-/g, "").slice(0, 12);
  const genesisDeviceId = `ak:device:01904100-0000-7000-8000-${deviceSuffix}`;
  const principalDescribe = await responseJsonRecord(
    await request.get(`${solandBaseUrl(opts.server)}/_arkret/describe`),
    "soland describe",
  );
  const trustDomain = stringValue(principalDescribe.trust_domain);
  const audience =
    stringValue(principalDescribe.service_id) ?? solandServiceId(opts.server);
  if (!trustDomain) {
    throw new Error("Principal Server description omitted trust_domain");
  }
  const handoff = await createCanonicalAccountHandoff(request, coauthBase, {
    audience,
    deviceId: genesisDeviceId,
  });
  if (handoff.binding.state !== "identity_creation_active") {
    throw new Error(
      `fresh account did not receive an active identity lease: ${JSON.stringify(handoff.binding)}`,
    );
  }
  const lease = objectRecord(handoff.binding.identity_creation_lease);
  if (!lease) {
    throw new Error(
      `identity-creation handoff omitted lease: ${JSON.stringify(handoff.binding)}`,
    );
  }
  const fixture = cotestWire<PrincipalRegistrationFixture>(
    "principal-registration-fixture",
    {
      principal_server_url: solandBaseUrl(opts.server),
      gate_account_base: `${coauthBase.replace(/\/$/, "")}/_arkret/gate/account`,
      handoff_request_id: handoff.requestId,
      identity_creation_lease: lease,
      device_id: genesisDeviceId,
      trust_domain: trustDomain,
      initial_session: {
        session_public_key: canonicalJson(handoff.deviceKey.publicJwk),
        audience,
      },
    },
  );
  const fullDid = stringValue(fixture.checkpoint.did);
  if (!fullDid || fixture.recovery_key.split(/\s+/).length !== 24) {
    throw new Error("cotest principal registration fixture is incomplete");
  }
  const challengeUrl = `${coauthBase}/_arkret/gate/account/identity-binding-challenges`;
  const challenge = await responseJsonRecord(
    await request.post(challengeUrl, {
      data: fixture.challenge_request,
      headers: accountHandoffHeaders({
        deviceKey: handoff.deviceKey,
        accountHandoffGrant: handoff.accountHandoffGrant,
        method: "POST",
        url: challengeUrl,
      }),
    }),
    "identity-binding challenge",
  );
  const registerBody = cotestWire<Record<string, unknown>>(
    "identity-creation-register-request",
    {
      challenge,
      did_operation: fixture.did_operation,
      pcr_genesis_unit: fixture.checkpoint.pcr_genesis_unit,
      initial_session: fixture.checkpoint.initial_session,
      recovery_key: fixture.recovery_key,
      display_name: displayName,
    },
  );
  const registerUrl = `${coauthBase}/_arkret/gate/account/register`;
  const registered = await responseJsonRecord(
    await request.post(registerUrl, {
      data: registerBody,
      headers: accountHandoffHeaders({
        deviceKey: handoff.deviceKey,
        accountHandoffGrant: handoff.accountHandoffGrant,
        method: "POST",
        url: registerUrl,
      }),
    }),
    "canonical identity-creation register",
  );
  const receipt = objectRecord(registered.binding_receipt);
  const pcrGenesisReceipt = objectRecord(registered.pcr_genesis_receipt);
  const sessionOutcome = objectRecord(registered.session_grant_outcome);
  const registeredPrincipalId = stringValue(registered.principal_id);
  const grantId = stringValue(sessionOutcome?.grant_id);
  const grantJwt = stringValue(sessionOutcome?.session_grant);
  const grantAudience = stringValue(sessionOutcome?.audience);
  const expiresAt = stringValue(sessionOutcome?.expires_at);
  const deviceSigningSeed = stringValue(
    fixture.checkpoint.device_signing_seed_b64url,
  );
  const principalId = projectFullDidToCoreId(fullDid);
  if (
    !registeredPrincipalId ||
    registeredPrincipalId !== principalId ||
    !receipt ||
    receipt.binding_state !== "bound" ||
    receipt.principal_id !== principalId ||
    receipt.full_id !== fullDid ||
    !pcrGenesisReceipt ||
    !sessionOutcome ||
    !grantId ||
    !grantJwt ||
    !grantAudience ||
    !expiresAt ||
    !deviceSigningSeed
  ) {
    throw new Error("canonical account binding returned an incomplete outcome");
  }
  const eventSigningKey = dpopDeviceKeyFromSeedB64url(deviceSigningSeed);
  const initialGrant: DpopBoundGrant = {
    grantId,
    grantJwt,
    dpopJkt: handoff.deviceKey.thumbprint,
    audience: grantAudience,
    scopes: Array.isArray(sessionOutcome.granted_scope)
      ? sessionOutcome.granted_scope.filter(
          (scope): scope is string => typeof scope === "string",
        )
      : [],
    expiresAt,
    principalDid: principalId,
    eventSigningKey,
  };
  return {
    handle: slug,
    email,
    password,
    displayName,
    did: principalId,
    principalId,
    genesisDeviceId,
    recoveryKey: fixture.recovery_key,
    initialGrant,
    initialHolderKey: handoff.deviceKey,
    pcrGenesisReceipt,
    principalRegistrationCheckpoint: {
      ...fixture.checkpoint,
      binding_receipt: receipt,
      stage: "binding_registered",
    },
  };
}

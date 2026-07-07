// Real account onboarding helpers (no dev-login short-circuit).
//
// These drive the genuine coauth -> soland onboarding chain that the
// identity/onboarding.md and identity/account-device-auth.md scenarios
// describe:
//   * coauth mints a `did:webvh:<scid>:<host>:webvh:<ulid>` principal DID via
//     soland's embedded webvh registration (services/soland_webvh.rs), and
//   * issues a device-bound `ck.session.grant` (cnf.jkt == device DPoP key
//     thumbprint), and
//   * registers the principal account on soland.
//
// The vehicle is coauth's password+DPoP login (handlers/account/auth.rs):
// the same code path `helpers/users.ts::createDpopUserSession` already uses.
// It exercises the real onboarding (webvh DID + cross-signing-backed account +
// session grant) WITHOUT the WebAuthn browser ceremony or dev-login, so the
// minted DID is a resolvable did:webvh and the grant works on `/_cokret/self/*`.

import { expect, type APIRequestContext } from "@playwright/test";
import { type SolandKey, solandBaseUrl, solandServiceDid } from "./env";
import {
  registerCoauthPasswordAccount,
  type CoauthPasswordAccount,
} from "./coauth-register";
import {
  generateDpopDeviceKey,
  kickoffDpopHeaders,
  type DpopDeviceKey,
} from "./session-grant-dpop";
import { uniqueUser } from "./users";

export type OnboardedPrincipal = {
  /// The coauth password account backing this principal.
  account: CoauthPasswordAccount;
  /// `did:webvh:<scid>:<host>:webvh:<ulid>` minted by coauth via soland.
  principalDid: string;
  /// `ck:device:<uuidv7>` the session grant is bound to.
  deviceId: string;
  /// The device DPoP key (`cnf.jkt` == its thumbprint).
  deviceKey: DpopDeviceKey;
  /// The issued `ck.session.grant` JWT.
  grantJwt: string;
  /// coauth grant id (DB row id).
  grantId: string;
  /// Audience the grant is bound to (the soland service DID).
  grantAudience: string;
  /// All scopes the grant carries.
  scopes: string[];
};

type JsonRecord = Record<string, unknown>;

type CoauthLoginGrant = {
  grant_jwt: string;
  id: string;
  audience: string;
  scopes: string[];
};

type CoauthLoginResponse = {
  status?: string;
  viewer?: { did?: string };
  session_grant?: CoauthLoginGrant;
};

function objectRecord(value: unknown): JsonRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}

function stringField(
  record: JsonRecord | undefined,
  field: string,
): string | undefined {
  const value = record?.[field];
  return typeof value === "string" ? value : undefined;
}

function parseJsonObject(raw: string): JsonRecord | null {
  try {
    const parsed = raw ? JSON.parse(raw) : {};
    return objectRecord(parsed) ?? null;
  } catch {
    return null;
  }
}

function parseCoauthLoginResponse(raw: string): CoauthLoginResponse | null {
  const record = parseJsonObject(raw);
  if (!record) {
    return null;
  }
  const grantRecord = objectRecord(record.session_grant);
  const scopes = grantRecord?.scopes;
  const grant =
    stringField(grantRecord, "grant_jwt") &&
    stringField(grantRecord, "id") &&
    stringField(grantRecord, "audience") &&
    Array.isArray(scopes) &&
    scopes.every((scope) => typeof scope === "string")
      ? {
          grant_jwt: stringField(grantRecord, "grant_jwt")!,
          id: stringField(grantRecord, "id")!,
          audience: stringField(grantRecord, "audience")!,
          scopes: scopes as string[],
        }
      : undefined;
  return {
    status: stringField(record, "status"),
    viewer: {
      did: stringField(objectRecord(record.viewer), "did"),
    },
    session_grant: grant,
  };
}

/// Drive a full, real onboarding via coauth password+DPoP login. Returns the
/// minted did:webvh principal + a working device-bound session grant. Throws on
/// any failure (so the test fails loudly), except a 404 login (release build
/// without the bridge) which throws a clear message — callers should
/// `test.skip` when `coauthBaseUrl()` is unset rather than relying on a soft
/// return here.
export async function onboardPrincipalViaCoauth(
  request: APIRequestContext,
  coauthBase: string,
  prefix: string,
  opts: { server?: SolandKey; handle?: string } = {},
): Promise<OnboardedPrincipal> {
  const account = await registerCoauthPasswordAccount(request, coauthBase, {
    handle: opts.handle,
    password: "CokretOnboard!2026",
  });
  return loginPrincipalViaCoauth(request, coauthBase, prefix, account, opts);
}

/// Issue a fresh device-bound session grant for an existing coauth account via
/// the password+DPoP login. Each call uses a distinct device key + device id,
/// so this also models a second device acquiring its own device-specific grant.
export async function loginPrincipalViaCoauth(
  request: APIRequestContext,
  coauthBase: string,
  prefix: string,
  account: CoauthPasswordAccount,
  opts: { server?: SolandKey; deviceId?: string } = {},
): Promise<OnboardedPrincipal> {
  const deviceId = opts.deviceId ?? uniqueUser(prefix).deviceId;
  const deviceKey = generateDpopDeviceKey();
  const audience = solandServiceDid(opts.server);
  const loginUrl = `${coauthBase}/_coauth/account/auth/login`;
  const login = await request.post(loginUrl, {
    headers: kickoffDpopHeaders({ deviceKey, method: "POST", url: loginUrl }),
    data: {
      handle: account.handle,
      password: account.password,
      audience,
      device_id: deviceId,
    },
  });
  const raw = await login.text();
  const body = parseCoauthLoginResponse(raw);
  if (!login.ok() || body?.status !== "success") {
    throw new Error(
      `coauth onboarding login returned ${login.status()}: ${raw}`,
    );
  }
  const grant = body?.session_grant;
  const principalDid = body?.viewer?.did;
  if (!principalDid || !grant?.grant_jwt || !grant?.id || !grant?.audience) {
    throw new Error(`coauth onboarding login omitted principal grant: ${raw}`);
  }
  expect(principalDid).toMatch(/^did:webvh:/);
  expect(grant.audience).toBe(audience);
  expect(Array.isArray(grant.scopes)).toBeTruthy();
  expect(grant.scopes).toContain(`urn:cokret:client:device:${deviceId}`);
  return {
    account,
    principalDid,
    deviceId,
    deviceKey,
    grantJwt: grant.grant_jwt,
    grantId: grant.id,
    grantAudience: grant.audience,
    scopes: grant.scopes,
  };
}

/// Resolve a principal DID through soland's public resolver
/// (`POST /_cokret/root/identity/resolve`) and return the DID Document + log.
/// Throws if the resolver does not return the requested DID.
export async function resolvePrincipalDid(
  request: APIRequestContext,
  did: string,
  opts: { server?: SolandKey } = {},
): Promise<{ document: JsonRecord; log: JsonRecord[] }> {
  const url = `${solandBaseUrl(opts.server)}/_cokret/root/identity/resolve`;
  const resp = await request.post(url, { data: { did } });
  const text = await resp.text();
  if (!resp.ok()) {
    throw new Error(`identity resolve ${did} returned ${resp.status()}: ${text}`);
  }
  const body = parseJsonObject(text);
  if (!body) {
    throw new Error(`identity resolve ${did} returned non-object JSON: ${text}`);
  }
  const didDocument = objectRecord(body.did_document);
  const resolvedDid = stringField(didDocument, "did") ?? stringField(body, "did");
  if (resolvedDid !== did) {
    throw new Error(`identity resolve returned ${resolvedDid}, expected ${did}`);
  }
  const document = objectRecord(didDocument?.document) ?? objectRecord(body.document);
  if (!document) {
    throw new Error(`identity resolve ${did} omitted document: ${text}`);
  }
  const logUrl = `${solandBaseUrl(opts.server)}/_cokret/root/identity/log?did=${encodeURIComponent(
    did,
  )}`;
  const logResp = await request.get(logUrl);
  const logText = await logResp.text();
  if (!logResp.ok()) {
    throw new Error(
      `identity log ${did} returned ${logResp.status()}: ${logText}`,
    );
  }
  const logBody = parseJsonObject(logText);
  if (!logBody) {
    throw new Error(`identity log ${did} returned non-object JSON: ${logText}`);
  }
  const log = Array.isArray(logBody.events)
    ? logBody.events.flatMap((entry) => {
        const record = objectRecord(entry);
        const operation = objectRecord(record?.operation);
        return operation ? [operation] : record ? [record] : [];
      })
    : [];
  return { document, log };
}

/// Extract the `<scid>` segment of a `did:webvh:<scid>:<host>:...` DID.
export function webvhScid(did: string): string {
  const parts = did.split(":");
  // did : webvh : <scid> : <host> : ...
  if (parts.length < 4 || parts[0] !== "did" || parts[1] !== "webvh") {
    throw new Error(`not a did:webvh: ${did}`);
  }
  return parts[2];
}

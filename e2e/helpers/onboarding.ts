// Client-custodied principal onboarding resolver helpers.
//
// Principal entry 0 must be built and root-signed by the client after recovery
// custody confirmation. Coauth verifies/binds the submitted operation and the
// accepted PCR-genesis receipt, then issues a device-bound Standard grant; it
// never mints or stores the identity root or authorizes the device Event.

import type { APIRequestContext } from "@playwright/test";
import { type SolandKey, solandBaseUrl } from "./env";
import type { CoauthPasswordAccount } from "./coauth-register";
import type { DpopDeviceKey } from "./session-grant-dpop";

/// Non-secret output of a completed client-custodied onboarding strand.
export type OnboardedPrincipal = {
  account: CoauthPasswordAccount;
  principalDid: string;
  deviceId: string;
  deviceKey: DpopDeviceKey;
  grantJwt: string;
  grantId: string;
  grantAudience: string;
  scopes: string[];
};

type JsonRecord = Record<string, unknown>;

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

/// Resolve a principal DID through soland's public resolver
/// (`POST /_arkret/root/identity/resolve`) and return the DID Document + log.
/// Throws if the resolver does not return the requested DID.
export async function resolvePrincipalDid(
  request: APIRequestContext,
  did: string,
  opts: { server?: SolandKey } = {},
): Promise<{ document: JsonRecord; log: JsonRecord[] }> {
  const url = `${solandBaseUrl(opts.server)}/_arkret/root/identity/resolve`;
  const resp = await request.post(url, { data: { did } });
  const text = await resp.text();
  if (!resp.ok()) {
    throw new Error(
      `identity resolve ${did} returned ${resp.status()}: ${text}`,
    );
  }
  const body = parseJsonObject(text);
  if (!body) {
    throw new Error(
      `identity resolve ${did} returned non-object JSON: ${text}`,
    );
  }
  const didDocument = objectRecord(body.did_document);
  const resolvedDid =
    stringField(didDocument, "id") ??
    stringField(didDocument, "did") ??
    stringField(body, "did");
  if (resolvedDid !== did) {
    throw new Error(
      `identity resolve returned ${resolvedDid}, expected ${did}`,
    );
  }
  const document =
    objectRecord(didDocument?.document) ??
    didDocument ??
    objectRecord(body.document);
  if (!document) {
    throw new Error(`identity resolve ${did} omitted document: ${text}`);
  }
  const logUrl = `${solandBaseUrl(opts.server)}/_arkret/root/identity/log?did=${encodeURIComponent(
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
  if (
    stringField(logBody, "did") !== did ||
    stringField(logBody, "method") !== "did:webvh" ||
    logBody.native_history !== true ||
    logBody.has_more !== false
  ) {
    throw new Error(`identity log ${did} is not a complete native WebVH history`);
  }
  const log = Array.isArray(logBody.entries)
    ? logBody.entries.flatMap((entry) => {
        const record = objectRecord(entry);
        return record ? [record] : [];
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

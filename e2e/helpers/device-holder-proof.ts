// Device holder-proof helpers for session-grant refresh + soft-logout restore.
//
// Contract: arkret-spec/spec/v1/zh/identity/account-lifecycle.md §4.1 +
// crypto-media/device-lifecycle.md §5.4 (service_attested enrollment), and the
// coauth refresh handler
// (coauth/crates/backend/src/handlers/arkret/session_grant/refresh.rs).
//
// The refresh / soft-logout-restore holder proof is signed by the device's
// `ak.device.authorize`-authorized signing key. coauth verifies that proof by
// resolving the authorized device signing key from the Principal Server's device
// directory (`POST /_soland/gate/account/device-signing-keys/query`), NOT from
// the principal DID document. So a black-box harness must first enrol the device
// key into soland's directory, then sign the holder proof with the SAME key.
//
// This module drives the holder proof: canonical `SoftLogoutDidProofClaims`
// signed as an EdDSA detached JWS with the device key, plus the
//      `soft_logout_restore_request_canonical_digest` binding, byte-mirroring the
//      Rust structs in refresh.rs.
//
// Post-bootstrap enrolment remains deliberately unavailable until the typed
// Coauth request carries the accepted actor frontier. Entry-0 enrolment belongs
// to the closed PCR bootstrap unit and is never driven through this helper.

import { createHash, sign } from "node:crypto";
import type { APIRequestContext } from "@playwright/test";
import type { SolandKey } from "./env";
import type { OnboardedPrincipal } from "./onboarding";
import { base64urlJsonCanonical, canonicalJson } from "./soland-api";
import { encodeEd25519PubkeyMultibase } from "./encoding";
import {
  type DpopDeviceKey,
  mintDpopProof,
} from "./session-grant-dpop";

/// Render an Ed25519 raw public key (32 bytes) as the multibase form soland
/// projects (`z` + base58btc(0xed01 ‖ key)). Mirrors soland's
/// `ed25519_pubkey_to_did_key_multibase`.
function ed25519MultibaseFromPublicJwkX(xB64Url: string): string {
  return encodeEd25519PubkeyMultibase(Buffer.from(xB64Url, "base64url"));
}

/// The `did:key:z…` rendering soland returns for an authorized device signing
/// key, derived from the device's DPoP public key. This equals the `kid` the
/// holder proof must carry.
export function deviceSigningKeyDid(deviceKey: DpopDeviceKey): string {
  return `did:key:${ed25519MultibaseFromPublicJwkX(deviceKey.publicJwk.x)}`;
}

/// Whole-second RFC3339 (`…Z`, no fractional part) — the canonical timestamp
/// form coauth re-serializes a parsed `DateTime<Utc>` into (the device-enroll
/// path truncates to seconds for the same reason), so the signed claims bytes
/// round-trip byte-for-byte through coauth's canonicalization.
function rfc3339Seconds(epochSeconds: number): string {
  return `${new Date(epochSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z")}`;
}

/// Enrol a post-bootstrap device's DPoP key into the Principal Server's device
/// directory as a verified, non-revoked device signing key. The first device
/// is authorized inside the closed PCR bootstrap unit and MUST NOT use this
/// isolated-event helper. Returns the
/// `did:key:z…` the directory will surface for it.
///
/// This currently returns `undefined` because the typed device-enroll request
/// does not yet carry the accepted actor frontier / exact `prev_refs`. Sending
/// `actor_seq=1` with an empty predecessor set would counterfeit a bootstrap
/// authorization and is forbidden. Callers must skip until the SDK DTO and
/// Coauth handler expose the post-bootstrap predecessor contract.
export async function enrollOnboardedDeviceSigningKey(
  request: APIRequestContext,
  coauthBase: string,
  onboarded: OnboardedPrincipal,
  opts: { server?: SolandKey } = {},
): Promise<string | undefined> {
  void request;
  void coauthBase;
  void onboarded;
  void opts;
  return undefined;
}

/// `sha256:`-prefixed digest of a JCS-canonical object, matching the SDK
/// `canonical_sha256` wire form.
function canonicalSha256(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

/// `sha256:` digest of the raw grant JWT bytes, mirroring coauth's
/// `session_grant_jwt_hash`.
function sessionGrantJwtHash(grantJwt: string): string {
  return `sha256:${createHash("sha256").update(grantJwt).digest("hex")}`;
}

const SOFT_LOGOUT_RESTORE_OPERATION = "resume_soft_logged_out_session";

export type HolderProofBody = {
  grant_jwt: string;
  audience: string;
  device_id: string;
  proof: {
    proof_kind: "did_bound_signature";
    challenge: string;
    request_canonical_digest: string;
    audience: string;
    issued_at: string;
    expires_at: string;
    signature: string;
    verification_method: string;
  };
};

/// Build a `SessionGrantRefreshRequestBody` carrying a fresh device holder
/// proof, signed by the device key whose signing key is now authorized in the
/// Principal Server directory. Mirrors `SoftLogoutDidProofClaims` +
/// `SoftLogoutRestoreRequestDigest` from refresh.rs byte-for-byte.
export function buildHolderProofRefreshBody(args: {
  grantJwt: string;
  principalDid: string;
  deviceId: string;
  deviceKey: DpopDeviceKey;
  audience: string;
  challenge: string;
}): HolderProofBody {
  const now = Math.floor(Date.now() / 1000);
  const issuedAt = rfc3339Seconds(now);
  const expiresAt = rfc3339Seconds(now + 120);
  const holderKeyId = deviceSigningKeyDid(args.deviceKey);

  // request_canonical_digest binds the proof to this concrete restore request
  // (operation + grant hash + principal + device + audience + holder key).
  const requestCanonicalDigest = canonicalSha256({
    operation: SOFT_LOGOUT_RESTORE_OPERATION,
    grant_jwt_hash: sessionGrantJwtHash(args.grantJwt),
    principal_id: args.principalDid,
    device_id: args.deviceId,
    audience: args.audience,
    grant_binding_key_id: holderKeyId,
  });

  // The signed claims — recomputed identically by coauth from the proof fields.
  const claims = {
    principal_id: args.principalDid,
    device_id: args.deviceId,
    audience: args.audience,
    challenge: args.challenge,
    request_canonical_digest: requestCanonicalDigest,
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  const payloadBytes = Buffer.from(canonicalJson(claims), "utf8");

  // EdDSA detached JWS: protected header carries alg + kid; payload segment is
  // empty; signature is over `b64u(header).b64u(payloadBytes)`.
  const header = { alg: "EdDSA", kid: holderKeyId };
  const headerB64 = base64urlJsonCanonical(header);
  const payloadB64 = payloadBytes.toString("base64url");
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = sign(null, Buffer.from(signingInput, "utf8"), args.deviceKey.privateKey)
    .toString("base64url");
  const detachedJws = `${headerB64}..${signature}`;

  return {
    grant_jwt: args.grantJwt,
    audience: args.audience,
    device_id: args.deviceId,
    proof: {
      proof_kind: "did_bound_signature",
      challenge: args.challenge,
      request_canonical_digest: requestCanonicalDigest,
      audience: args.audience,
      issued_at: issuedAt,
      expires_at: expiresAt,
      signature: detachedJws,
      verification_method: holderKeyId,
    },
  };
}

/// POST a session-grant refresh to coauth with a DPoP proof bound to the grant
/// (the holder-proof body is in `body`). Returns the parsed response + status.
export async function postSessionGrantRefresh(
  request: APIRequestContext,
  coauthBase: string,
  deviceKey: DpopDeviceKey,
  body: HolderProofBody,
): Promise<{ status: number; json: Record<string, unknown>; text: string }> {
  const refreshUrl = `${coauthBase}/_arkret/gate/account/session-grants/refresh`;
  const resp = await request.post(refreshUrl, {
    headers: {
      dpop: mintDpopProof({
        deviceKey,
        method: "POST",
        url: refreshUrl,
        grantJwt: body.grant_jwt,
      }),
    },
    data: body,
  });
  const text = await resp.text();
  let json: Record<string, unknown> = {};
  try {
    json = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    json = {};
  }
  return { status: resp.status(), json, text };
}

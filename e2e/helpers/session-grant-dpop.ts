// Session-grant + DPoP (RFC 9449) helpers for the ②(A+②) authentication model.
//
// Contract: arkret-spec/spec/v1/zh/sync/api-conventions.md §3.3 and
// cotask/tasks/_auth_todos.md "## ② 最终路线".
//
// Under ②, the Principal Server (soland) does not mint a second local
// credential. A client accesses `/_cokret/self/*` by presenting
// `Authorization: Bearer <ck.session.grant>` plus a per-request DPoP proof
// bound to the request (`htm`/`htu`/`ath`). soland verifies the DPoP against
// the grant's `cnf.jkt` (RFC 7638 JWK SHA-256 thumbprint) obtained via
// session-grant introspection at coauth.
//
// These helpers obtain a real DPoP-bound grant WITHOUT driving the full OIDC
// browser ceremony, via coauth's cotest debug seam:
//   POST /_coauth/account/test/debug/issue-dpop-grant
// (coauth: crates/backend/src/handlers/arkret/mod.rs::debug_issue_dpop_grant).
// That route is mounted only in debug builds with COAUTH_ENABLE_TEST_ENDPOINTS
// enabled; `mintDpopBoundGrant` returns `undefined` when it is unavailable so
// callers can `test.skip` cleanly.
//
// The DPoP proof shape mirrors exactly what soland's verifier accepts
// (soland: crates/server/src/routing/identity/auth_grant_dpop.rs):
//   * compact JWS, header `{typ:"dpop+jwt", alg:"EdDSA", jwk:<public OKP jwk>}`
//   * claims `{htm, htu, ath, jti, iat}`
//   * `ath = base64url(sha256(grant_jwt))` (unpadded)
// and the embedded JWK thumbprint equals the grant's `cnf.jkt`.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
  type KeyObject,
} from "node:crypto";
import { type APIRequestContext } from "@playwright/test";
import { type SolandKey, solandServiceDid } from "./env";
import { base64url } from "./encoding";
import { base64urlJsonRaw } from "./soland-api";

/// Public JWK for an Ed25519 OKP key, as emitted by Node and as consumed by
/// both coauth (`PublicJsonWebKey`) and soland (`parse_dpop_jwk`).
export type Ed25519PublicJwk = {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
};

export type DpopDeviceKey = {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicJwk: Ed25519PublicJwk;
  /// RFC 7638 SHA-256 thumbprint (base64url, unpadded) of `publicJwk`.
  thumbprint: string;
};

export type DpopBoundGrant = {
  grantId: string;
  grantJwt: string;
  /// The `cnf.jkt` the grant was minted with — equals the device key thumbprint.
  dpopJkt: string;
  audience: string;
  scopes: string[];
  expiresAt: string;
  /// The minted `did:webvh:…:webvh:<ulid>` principal DID (model B) the grant
  /// subject is bound to. coauth's debug seam mints this with a
  /// `CokretDeviceEnrollmentAuthority` designation, so the harness MUST use it as
  /// the account identity for device enrollment / MLS to resolve the right DID
  /// document (not the coauth-local `…:users:<ulid>` fallback).
  principalDid: string;
};

export type MintDpopGrantOpts = {
  /// Audience the grant is bound to. MUST equal the target soland service DID,
  /// because soland rejects a grant whose audience is not its own service_did.
  audience?: string;
  /// Scopes to bake into the grant. Defaults (applied server-side) carry the
  /// principal-server session.bind scope + a `urn:arkret:client:device:<id>`
  /// scope, which is exactly what the self-path requires.
  scopes?: string[];
  server?: SolandKey;
};

/// Generate a fresh Ed25519 device key and its public JWK + RFC 7638 thumbprint.
export function generateDpopDeviceKey(): DpopDeviceKey {
  let privateKey: KeyObject;
  let publicKey: KeyObject;
  let exported: { kty?: string; crv?: string; x?: string };
  // Regenerate if the base64url public-key x-coordinate begins with `z`. coauth's
  // device-enroll `decode_device_public_key` treats a leading `z` as the
  // MULTIBASE base58btc prefix and tries to base58-decode the remainder, which
  // fails (`invalid base58btc`) whenever the base64url tail contains a
  // base58-excluded char (0/O/I/l). That misdetection makes device enrollment —
  // and therefore the whole MLS path — flake ~1/64 of the time; sidestep it by
  // only ever handing the endpoint an unambiguous (non-`z`-prefixed) base64url.
  for (;;) {
    ({ privateKey, publicKey } = generateKeyPairSync("ed25519"));
    exported = publicKey.export({ format: "jwk" }) as {
      kty?: string;
      crv?: string;
      x?: string;
    };
    if (exported.x && !exported.x.startsWith("z")) {
      break;
    }
  }
  if (exported.kty !== "OKP" || exported.crv !== "Ed25519" || !exported.x) {
    throw new Error(
      `unexpected Ed25519 public JWK shape: ${JSON.stringify(exported)}`,
    );
  }
  const publicJwk: Ed25519PublicJwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: exported.x,
  };
  return {
    privateKey,
    publicKey,
    publicJwk,
    thumbprint: jwkThumbprintEd25519(publicJwk.x),
  };
}

/// Export an Ed25519 device key's private seed as base64url-no-pad of the 32
/// raw seed bytes — the exact on-disk form inkson's `DpopDeviceKeyRecord`
/// persists (`seed_b64`). The JWK `d` member is already base64url-no-pad of the
/// 32-byte seed, so it is returned verbatim. Used by the joint fixture to inject
/// the same key whose thumbprint the minted grant is bound to (`cnf.jkt`).
export function dpopDeviceSeedB64url(key: DpopDeviceKey): string {
  const jwk = key.privateKey.export({ format: "jwk" }) as { d?: string };
  if (!jwk.d) {
    throw new Error(`Ed25519 private JWK missing 'd' seed member: ${JSON.stringify(jwk)}`);
  }
  return jwk.d;
}

/// RFC 7638 JWK SHA-256 thumbprint for an Ed25519 OKP key. The canonical input
/// serializes the required members `{crv, kty, x}` in lexicographic order with
/// no whitespace, matching soland's `jwk_thumbprint_ed25519`.
export function jwkThumbprintEd25519(x: string): string {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
  return base64url(createHash("sha256").update(canonical).digest());
}

/// `ath` claim per RFC 9449 §4.3: base64url-encoded SHA-256 of the presented
/// session credential, unpadded. In Arkret this is the `ck.session.grant` JWT.
export function dpopAth(grantJwt: string): string {
  return base64url(createHash("sha256").update(grantJwt).digest());
}

/// Mint a DPoP proof JWT bound to (method, url, grant) for the given device key.
///
/// `htu` SHOULD be the absolute request URL (scheme://host[:port]/path); query
/// and fragment are normalized away by the verifier. `iatSkewSeconds` lets a
/// negative test push `iat` outside the freshness window.
export function mintDpopProof(args: {
  deviceKey: DpopDeviceKey;
  method: string;
  url: string;
  grantJwt?: string;
  jti?: string;
  iatSkewSeconds?: number;
  /// Omit `ath` for token-minting kickoff requests where no access token exists
  /// yet. Follow-up protected-resource requests keep the default `ath`.
  includeAth?: boolean;
  /// Override the `ath` claim (negative tests: a wrong/absent grant binding).
  athOverride?: string;
}): string {
  const header = {
    typ: "dpop+jwt",
    alg: "EdDSA",
    jwk: args.deviceKey.publicJwk,
  };
  const iat = Math.floor(Date.now() / 1000) + (args.iatSkewSeconds ?? 0);
  const claims: {
    jti: string;
    htm: string;
    htu: string;
    iat: number;
    ath?: string;
  } = {
    jti: args.jti ?? randomUUID(),
    htm: args.method.toUpperCase(),
    // Strip query/fragment so the signed htu matches the verifier's
    // canonicalization (it compares scheme+authority+path only).
    htu: args.url.split("#")[0].split("?")[0],
    iat,
  };
  if (args.includeAth !== false) {
    if (!args.grantJwt && args.athOverride === undefined) {
      throw new Error("mintDpopProof requires grantJwt unless includeAth is false");
    }
    claims.ath = args.athOverride ?? dpopAth(args.grantJwt!);
  }
  const signingInput = `${base64urlJsonRaw(header)}.${base64urlJsonRaw(claims)}`;
  const signature = sign(null, Buffer.from(signingInput, "utf8"), args.deviceKey.privateKey);
  return `${signingInput}.${base64url(signature)}`;
}

/// Build the full header set for a real grant + DPoP request to a soland
/// `/_cokret/self/*` (or `/root/`) endpoint: `Authorization: Bearer <grant>`, a
/// request-bound `DPoP` proof. `deviceKey` MUST be the key the grant is bound
/// to (`cnf.jkt`).
export function selfPathGrantHeaders(args: {
  deviceKey: DpopDeviceKey;
  grantJwt: string;
  method: string;
  url: string;
}): Record<string, string> {
  const dpop = mintDpopProof({
    deviceKey: args.deviceKey,
    method: args.method,
    url: args.url,
    grantJwt: args.grantJwt,
  });
  return {
    authorization: `Bearer ${args.grantJwt}`,
    dpop,
  };
}

/// Build the DPoP header for a session-grant kickoff request. There is no
/// access token yet, so RFC 9449 `ath` is intentionally absent.
export function kickoffDpopHeaders(args: {
  deviceKey: DpopDeviceKey;
  method: string;
  url: string;
}): Record<string, string> {
  return {
    dpop: mintDpopProof({
      deviceKey: args.deviceKey,
      method: args.method,
      url: args.url,
      includeAth: false,
    }),
  };
}

/// Reconstruct a `DpopDeviceKey` from a base64url-no-pad 32-byte Ed25519 seed —
/// the inverse of [`dpopDeviceSeedB64url`]. Used by session-bound helpers that
/// persist only the seed (not the live `KeyObject`) and later need to mint a
/// proof.
export function dpopDeviceKeyFromSeedB64url(seedB64url: string): DpopDeviceKey {
  const seed = Buffer.from(seedB64url, "base64url");
  if (seed.length !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
  }
  // Wrap the raw 32-byte seed in the fixed Ed25519 PKCS#8 DER prefix so Node can
  // import it as a private KeyObject (RFC 8410 OneAsymmetricKey, OID 1.3.101.112).
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  const exported = publicKey.export({ format: "jwk" }) as { x?: string };
  if (!exported.x) {
    throw new Error("failed to derive Ed25519 public x from seed");
  }
  const publicJwk: Ed25519PublicJwk = { kty: "OKP", crv: "Ed25519", x: exported.x };
  return {
    privateKey,
    publicKey,
    publicJwk,
    thumbprint: jwkThumbprintEd25519(publicJwk.x),
  };
}

/// Request a DPoP-bound `ck.session.grant` from coauth's cotest debug seam.
///
/// Returns `undefined` when the debug endpoint is not available (404 — the
/// route is gated on debug builds + `COAUTH_ENABLE_TEST_ENDPOINTS`), so callers
/// can `test.skip` rather than fail. Throws on any other non-2xx so genuine
/// misconfiguration is visible.
export async function mintDpopBoundGrant(
  request: APIRequestContext,
  coauthBase: string,
  actorDid: string,
  deviceId: string,
  deviceKey: DpopDeviceKey,
  opts: MintDpopGrantOpts = {},
): Promise<DpopBoundGrant | undefined> {
  const audience = opts.audience ?? solandServiceDid(opts.server);
  const response = await request.post(
    `${coauthBase}/_coauth/account/test/debug/issue-dpop-grant`,
    {
      data: {
        actor_id: actorDid,
        device_id: deviceId,
        dpop_jwk: deviceKey.publicJwk,
        audience,
        ...(opts.scopes ? { scopes: opts.scopes } : {}),
      },
    },
  );
  if (response.status() === 404) {
    // Route absent: release build or COAUTH_ENABLE_TEST_ENDPOINTS not set.
    return undefined;
  }
  const text = await response.text();
  if (!response.ok()) {
    throw new Error(
      `debug issue-dpop-grant returned ${response.status()}: ${text}`,
    );
  }
  const body = JSON.parse(text) as {
    grant_id: string;
    grant_jwt: string;
    dpop_jkt: string;
    audience: string;
    scopes: string[];
    expires_at: string;
    principal_did?: string;
  };
  return {
    grantId: body.grant_id,
    grantJwt: body.grant_jwt,
    dpopJkt: body.dpop_jkt,
    audience: body.audience,
    scopes: body.scopes,
    expiresAt: body.expires_at,
    // Fall back to the requested actor DID for older coauth builds that predate
    // the model-B principal_did response field.
    principalDid: body.principal_did ?? actorDid,
  };
}

// Session-grant + DPoP (RFC 9449) helpers for the ②(A+②) authentication model.
//
// Contract: cokret-spec/spec/v1/zh/sync/api-conventions.md §3.3 and
// cotask/tasks/_auth_todos.md "## ② 最终路线".
//
// Under ②, the Principal Server (soland) mints no local bearer and offers no
// grant→bearer exchange. A client accesses `/_cokret/self/*` by presenting
// `Authorization: Bearer <ck.session.grant>` plus a per-request DPoP proof
// bound to the request (`htm`/`htu`/`ath`). soland verifies the DPoP against
// the grant's `cnf.jkt` (RFC 7638 JWK SHA-256 thumbprint) obtained via
// session-grant introspection at coauth.
//
// These helpers obtain a real DPoP-bound grant WITHOUT driving the full OIDC
// browser ceremony, via coauth's cotest debug seam:
//   POST /_coauth/gate/account/test/debug/issue-dpop-grant
// (coauth: crates/backend/src/handlers/cokret/mod.rs::debug_issue_dpop_grant).
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
  generateKeyPairSync,
  randomUUID,
  sign,
  type KeyObject,
} from "node:crypto";
import { type APIRequestContext } from "@playwright/test";
import { type SolandKey, solandServiceDid } from "./env";

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
};

export type MintDpopGrantOpts = {
  /// Audience the grant is bound to. MUST equal the target soland service DID,
  /// because soland rejects a grant whose audience is not its own service_did.
  audience?: string;
  /// Scopes to bake into the grant. Defaults (applied server-side) carry the
  /// principal-server session.bind scope + a `urn:cokret:client:device:<id>`
  /// scope, which is exactly what the self-path requires.
  scopes?: string[];
  server?: SolandKey;
};

function b64urlNoPad(input: Buffer): string {
  return input.toString("base64url");
}

/// Generate a fresh Ed25519 device key and its public JWK + RFC 7638 thumbprint.
export function generateDpopDeviceKey(): DpopDeviceKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const exported = publicKey.export({ format: "jwk" }) as {
    kty?: string;
    crv?: string;
    x?: string;
  };
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

/// RFC 7638 JWK SHA-256 thumbprint for an Ed25519 OKP key. The canonical input
/// serializes the required members `{crv, kty, x}` in lexicographic order with
/// no whitespace, matching soland's `jwk_thumbprint_ed25519`.
export function jwkThumbprintEd25519(x: string): string {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
  return b64urlNoPad(createHash("sha256").update(canonical).digest());
}

/// `ath` claim per RFC 9449 §4.3: `base64url(sha256(access_token))` (unpadded),
/// where the access token here is the `ck.session.grant` JWT.
export function dpopAth(grantJwt: string): string {
  return b64urlNoPad(createHash("sha256").update(grantJwt).digest());
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
  grantJwt: string;
  jti?: string;
  iatSkewSeconds?: number;
  /// Override the `ath` claim (negative tests: a wrong/absent grant binding).
  athOverride?: string;
}): string {
  const header = {
    typ: "dpop+jwt",
    alg: "EdDSA",
    jwk: args.deviceKey.publicJwk,
  };
  const iat = Math.floor(Date.now() / 1000) + (args.iatSkewSeconds ?? 0);
  const claims = {
    jti: args.jti ?? randomUUID(),
    htm: args.method.toUpperCase(),
    // Strip query/fragment so the signed htu matches the verifier's
    // canonicalization (it compares scheme+authority+path only).
    htu: args.url.split("#")[0].split("?")[0],
    iat,
    ath: args.athOverride ?? dpopAth(args.grantJwt),
  };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(claims)}`;
  const signature = sign(null, Buffer.from(signingInput, "utf8"), args.deviceKey.privateKey);
  return `${signingInput}.${b64urlNoPad(signature)}`;
}

function b64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
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
    `${coauthBase}/_coauth/gate/account/test/debug/issue-dpop-grant`,
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
  };
  return {
    grantId: body.grant_id,
    grantJwt: body.grant_jwt,
    dpopJkt: body.dpop_jkt,
    audience: body.audience,
    scopes: body.scopes,
    expiresAt: body.expires_at,
  };
}

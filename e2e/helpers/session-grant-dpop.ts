// Session-grant + DPoP (RFC 9449) helpers for the ②(A+②) authentication model.
//
// Contract: arkret-spec/spec/v1/zh/sync/api-conventions.md §3.3 and
// arkret-work/tasks/_auth_todos.md "## ② 最终路线".
//
// Under ②, the Station (coland) does not mint a second local
// credential. A client accesses `/_arkret/self/*` by presenting
// `Authorization: DPoP <ak.session.grant>` plus a per-request DPoP proof
// bound to the request (`htm`/`htu`/`ath`). coland verifies the DPoP against
// the grant's `cnf.jkt` (RFC 7638 JWK SHA-256 thumbprint) obtained via
// session-grant introspection at coauth.
//
// These helpers mint the DPoP proofs and headers a caller presents alongside a
// grant it already holds. The grant itself comes from the canonical chain in
// `coauth-register.ts`; the debug seam that used to mint one here
// (`POST /_coauth/account/test/debug/issue-dpop-grant`) had no callers left and
// is gone, so nothing in this suite obtains a grant by asking coauth to skip
// the ceremony.
//
// The DPoP proof shape mirrors exactly what coland's verifier accepts
// (coland: crates/http/src/routing/identity/auth_grant_dpop.rs):
//   * compact JWS, header `{typ:"dpop+jwt", alg:"Ed25519", jwk:<public OKP jwk>}`
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
import { base64url } from "./encoding";
import { base64urlJsonRaw } from "./coland-api";

/// Public JWK for an Ed25519 OKP key, as emitted by Node and as consumed by
/// both coauth (`PublicJsonWebKey`) and coland (`parse_dpop_jwk`).
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
  /// Exact Station account whose durable session chain issued the grant.
  accountId: { principal_id: string; station_id: string };
  /// The `cnf.jkt` the grant was minted with — equals the device key thumbprint.
  dpopJkt: string;
  audience: string;
  scopes: string[];
  expiresAt: string;
  /// The verified principal DID the issuer bound to the grant subject.
  principalId: string;
  /// Long-term founding Event signer, deliberately distinct from the
  /// ephemeral holder/DPoP key. Present on PCR-genesis registration outcomes.
  eventSigningKey?: DpopDeviceKey;
};

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

/// Rehydrate a persisted Ed25519 seed into the same holder/device-key shape.
/// Registration fixtures use this to keep the genesis device signer stable
/// across the accepted PCR receipt and the immediately-issued Standard grant.
export function dpopDeviceKeyFromSeedB64url(seed: string): DpopDeviceKey {
  const rawSeed = Buffer.from(seed, "base64url");
  if (rawSeed.length !== 32) {
    throw new Error(
      `persisted Ed25519 seed must be 32 bytes, got ${rawSeed.length}`,
    );
  }
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      rawSeed,
    ]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey);
  const exported = publicKey.export({ format: "jwk" }) as {
    kty?: string;
    crv?: string;
    x?: string;
  };
  if (exported.kty !== "OKP" || exported.crv !== "Ed25519" || !exported.x) {
    throw new Error("persisted Ed25519 seed produced an invalid public JWK");
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
    throw new Error(
      `Ed25519 private JWK missing 'd' seed member: ${JSON.stringify(jwk)}`,
    );
  }
  return jwk.d;
}

/// RFC 7638 JWK SHA-256 thumbprint for an Ed25519 OKP key. The canonical input
/// serializes the required members `{crv, kty, x}` in lexicographic order with
/// no whitespace, matching coland's `jwk_thumbprint_ed25519`.
export function jwkThumbprintEd25519(x: string): string {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
  return base64url(createHash("sha256").update(canonical).digest());
}

/// `ath` claim per RFC 9449 §4.3: base64url-encoded SHA-256 of the presented
/// session credential, unpadded. In Arkret this is the `ak.session.grant` JWT.
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
    alg: "Ed25519",
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
      throw new Error(
        "mintDpopProof requires grantJwt unless includeAth is false",
      );
    }
    claims.ath = args.athOverride ?? dpopAth(args.grantJwt!);
  }
  const signingInput = `${base64urlJsonRaw(header)}.${base64urlJsonRaw(claims)}`;
  const signature = sign(
    null,
    Buffer.from(signingInput, "utf8"),
    args.deviceKey.privateKey,
  );
  return `${signingInput}.${base64url(signature)}`;
}

/// Build the full header set for a real grant + DPoP request to a coland
/// `/_arkret/self/*` (or `/root/`) endpoint: `Authorization: DPoP <grant>`, a
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
    authorization: `DPoP ${args.grantJwt}`,
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

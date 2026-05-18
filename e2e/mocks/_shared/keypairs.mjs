// Shared keypair helpers for cotest mocks. Each mock that needs to sign
// tokens / attestations uses a generated keypair so the harness can serve
// the matching public key over /jwks and verifiers can validate signatures
// without any shared secret.
//
// Two flavors are exported:
//   - createRsaKeyPair(kid, alg = "RS256")
//   - createEd25519KeyPair(kid, alg = "EdDSA")
//
// Both return { publicKey, privateKey, jwks } so the caller can stash the
// objects and pass them to signing helpers below.

import { generateKeyPairSync } from "node:crypto";

export function createRsaKeyPair(kid, { modulusLength = 2048, alg = "RS256" } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength });
  const publicJwk = publicKey.export({ format: "jwk" });
  const jwks = {
    keys: [
      {
        ...publicJwk,
        kid,
        alg,
        use: "sig",
      },
    ],
  };
  return { publicKey, privateKey, jwks };
}

export function createEd25519KeyPair(kid, { alg = "EdDSA" } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const jwks = {
    keys: [
      {
        ...publicJwk,
        kid,
        alg,
        use: "sig",
      },
    ],
  };
  return { publicKey, privateKey, jwks };
}

export function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

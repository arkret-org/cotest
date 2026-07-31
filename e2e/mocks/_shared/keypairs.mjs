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

const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// base58btc (Bitcoin alphabet) encoder. Port of the `base58btcEncode` in
/// e2e/helpers/encoding.ts, kept here so `.mjs` mocks do not need the
/// TypeScript helper module (they run under bare `node`, no ts loader).
export function base58btcEncode(bytes) {
  const input = Buffer.from(bytes);
  let leadingZeros = 0;
  while (leadingZeros < input.length && input[leadingZeros] === 0) leadingZeros += 1;
  const digits = [0];
  for (let index = leadingZeros; index < input.length; index += 1) {
    let carry = input[index];
    for (let position = 0; position < digits.length; position += 1) {
      carry += digits[position] << 8;
      digits[position] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(leadingZeros);
  for (let position = digits.length - 1; position >= 0; position -= 1) {
    out += BASE58BTC_ALPHABET[digits[position]];
  }
  return out;
}

/// Encode a raw 32-byte Ed25519 public key as a `z`-prefixed multibase string
/// with the `ed25519-pub` multicodec prefix (0xed 0x01) — the
/// `publicKeyMultibase` form used in DID documents.
export function encodeEd25519PubkeyMultibase(rawPublicKey) {
  const raw = Buffer.from(rawPublicKey);
  if (raw.length !== 32) {
    throw new Error(`ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  return `z${base58btcEncode(Buffer.concat([Buffer.from([0xed, 0x01]), raw]))}`;
}

/// Raw 32-byte Ed25519 public key from a node `KeyObject`.
export function rawEd25519PublicKey(publicKey) {
  const jwk = publicKey.export({ format: "jwk" });
  if (!jwk.x) throw new Error("ed25519 JWK missing x coordinate");
  return Buffer.from(jwk.x, "base64url");
}

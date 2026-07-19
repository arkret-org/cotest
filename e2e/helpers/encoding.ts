// Shared low-level encoders for the e2e harness.
//
// Base58BTC was previously re-implemented (inconsistently) in
// helpers/webvh-api.ts, helpers/cross-signing-harness.ts and
// helpers/contact-api.ts. This module is the single source of truth. The
// implementation handles leading zero bytes (each is emitted as a leading `1`),
// matching soland's `bs58`-backed decoder so multibase `z…` renderings produced
// here round-trip on a live server.

import type { KeyObject } from "node:crypto";

const BASE58BTC_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// multicodec ed25519-pub (0xed 0x01) varint prefix.
const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);

/// Encode arbitrary bytes as Base58BTC (Bitcoin alphabet), preserving leading
/// zero bytes as leading `1` characters.
export function base58btcEncode(bytes: Buffer): string {
  if (bytes.length === 0) {
    return "";
  }
  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) {
    leadingZeros += 1;
  }
  const digits: number[] = [];
  for (let i = leadingZeros; i < bytes.length; i += 1) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j += 1) {
      const value = (digits[j] << 8) + carry;
      digits[j] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = "1".repeat(leadingZeros);
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    out += BASE58BTC_ALPHABET[digits[i]];
  }
  return out;
}

/// Render a raw 32-byte Ed25519 public key as the `z…` multibase form soland
/// decodes (`z` + base58btc(0xed01 ‖ key)). Mirrors soland's
/// `ed25519_pubkey_to_did_key_multibase` / SDK `decode_ed25519_multibase`.
export function encodeEd25519PubkeyMultibase(rawPublicKey: Buffer): string {
  if (rawPublicKey.length !== 32) {
    throw new Error(
      `Ed25519 public key must be 32 bytes, got ${rawPublicKey.length}`,
    );
  }
  const envelope = Buffer.concat([ED25519_MULTICODEC_PREFIX, rawPublicKey]);
  return `z${base58btcEncode(envelope)}`;
}

/// Extract the raw 32-byte Ed25519 public key from an SPKI-exported KeyObject.
/// The DER SPKI tail is always the 32-byte key, so this slices it off without a
/// full ASN.1 parse — mirrors what the helpers previously open-coded.
export function rawEd25519PublicKey(publicKey: KeyObject): Buffer {
  const der = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  if (der.length < 32) {
    throw new Error("Ed25519 SPKI public key is too short");
  }
  return der.subarray(der.length - 32);
}

/// Export the raw 32-byte seed from an Ed25519 private KeyObject as
/// base64url without padding. Node's private OKP JWK represents that seed in
/// the `d` member.
export function ed25519PrivateKeySeedB64url(privateKey: KeyObject): string {
  const jwk = privateKey.export({ format: "jwk" }) as { d?: string };
  if (!jwk.d) {
    throw new Error("Ed25519 private key export did not contain a seed");
  }
  return jwk.d;
}

/// Authoritative base64url (no padding) encoder. Node's `Buffer.toString
/// ("base64url")` already omits padding, so this is the single thin wrapper the
/// harness shares instead of re-defining `b64url`/`b64urlNoPad`/`base64url`
/// per helper.
export function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

// Shared low-level encoders for the e2e harness.
//
// Base58BTC was previously re-implemented (inconsistently) in
// helpers/webvh-api.ts, helpers/cross-signing-harness.ts and
// helpers/contact-api.ts. This module is the single source of truth. The
// implementation handles leading zero bytes (each is emitted as a leading `1`),
// matching soland's `bs58`-backed decoder so multibase `z…` renderings produced
// here round-trip on a live server.

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

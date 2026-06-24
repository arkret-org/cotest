// Cross-signing key-management harness for the device-lifecycle §5 ingest path.
//
// Contract: cokret-spec/spec/v1/zh/crypto-media/device-lifecycle.md §5.1
// (ck.cross_signing.publish — PSK→{SSK,USK} bindings) + §5.2 (per-device
// cross_signing_binding, the SSK signature over the ck-device-trust-bind-v1
// canonical input).
//
// soland verifies these for real at event ingest:
//   * validate_cross_signing_publish (routing/identity/cross_signing.rs) anchors
//     the published PSK via the DID resolver, then checks the PSK→SSK and
//     PSK→USK binding signatures over the §5.1 ck-cross-signing-bind-v1 input
//     at the CAS-guarded generation.
//   * validate_device_authorize_binding → check_device_cross_signing_binding
//     verifies a ck.device.authorize's cross_signing_binding with the accepted
//     SSK over the §5.2 ck-device-trust-bind-v1 input at the live generation.
//
// The PSK is published under a self-contained `did:key:z…` verification method
// so soland's DidKeyResolver (last resolver in the chain) anchors it without a
// did:webvh document — a dev-login principal (`did:web:<slug>.example`) has no
// resolvable control document, so the PSK control anchor here is the did:key
// itself. The published `principal_id` is still the dev principal; only the PSK
// kid is a did:key. This drives the real publish + binding cryptography, which
// is what the §5.2 ingest path checks (it resolves the PSK kid + byte-matches
// the published key; it does not require the PSK controller to equal
// principal_id).

import { generateKeyPairSync, sign } from "node:crypto";
import { canonicalJson } from "./soland-api";

const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcEncode(bytes: Buffer): string {
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
    out += BASE58_ALPHABET[digits[i]];
  }
  return out;
}

/// Render a raw 32-byte Ed25519 public key as the `z…` multibase form soland
/// decodes (`z` + base58btc(0xed01 ‖ key)). Mirrors soland's
/// `ed25519_pubkey_to_did_key_multibase` / SDK `decode_ed25519_multibase`.
function ed25519Multibase(rawPublicKey: Buffer): string {
  if (rawPublicKey.length !== 32) {
    throw new Error(
      `Ed25519 public key must be 32 bytes, got ${rawPublicKey.length}`,
    );
  }
  const envelope = Buffer.concat([ED25519_MULTICODEC_PREFIX, rawPublicKey]);
  return `z${base58btcEncode(envelope)}`;
}

/// A freshly-generated Ed25519 cross-signing key, carrying its raw public key,
/// the `z…` multibase rendering soland projects, and a `did:key:z…` kid.
export type CrossSigningKey = {
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
  /// Raw 32-byte Ed25519 public key.
  rawPublicKey: Buffer;
  /// `z…` multibase rendering (the `public_key` field with key_format multibase).
  multibase: string;
  /// `did:key:z…` — the self-contained verification method id.
  didKey: string;
};

/// Generate a fresh Ed25519 cross-signing key (PSK / SSK / USK).
export function generateCrossSigningKey(): CrossSigningKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) {
    throw new Error("Ed25519 public JWK missing 'x'");
  }
  const rawPublicKey = Buffer.from(jwk.x, "base64url");
  const multibase = ed25519Multibase(rawPublicKey);
  return {
    privateKey,
    rawPublicKey,
    multibase,
    didKey: `did:key:${multibase}`,
  };
}

/// EdDSA-sign `message` with `key` and return the detached signature as
/// base64url (no padding) — the encoding soland's `ed25519_verify` decodes.
function signB64url(message: Buffer, key: CrossSigningKey): string {
  return sign(null, message, key.privateKey).toString("base64url");
}

/// Canonical signing input for a PSK→subordinate binding
/// (`ck-cross-signing-bind-v1`, device-lifecycle.md §5.1). Byte-mirrors the SDK
/// `canonical_cross_signing_binding_input`.
function crossSigningBindingInput(args: {
  principalId: string;
  trustDomain: string;
  subordinateKind: "self_signing" | "user_signing";
  subordinateKid: string;
  subordinateAlg: string;
  subordinatePublicKey: string;
  generation: number;
}): Buffer {
  const body = canonicalJson({
    principal_id: args.principalId,
    trust_domain: args.trustDomain,
    subordinate_key_kind: args.subordinateKind,
    subordinate_kid: args.subordinateKid,
    subordinate_alg: args.subordinateAlg,
    subordinate_public_key: args.subordinatePublicKey,
    generation: args.generation,
  });
  return Buffer.concat([
    Buffer.from("ck-cross-signing-bind-v1\n", "utf8"),
    Buffer.from(body, "utf8"),
  ]);
}

/// Canonical signing input for a per-device SSK→device binding
/// (`ck-device-trust-bind-v1`, device-lifecycle.md §5.2). Byte-mirrors the SDK
/// `canonical_device_trust_binding_input`.
function deviceTrustBindingInput(args: {
  principalId: string;
  deviceId: string;
  devicePublicKey: string;
  sskGeneration: number;
}): Buffer {
  const body = canonicalJson({
    principal_id: args.principalId,
    device_id: args.deviceId,
    device_public_key: args.devicePublicKey,
    ssk_generation: args.sskGeneration,
  });
  return Buffer.concat([
    Buffer.from("ck-device-trust-bind-v1\n", "utf8"),
    Buffer.from(body, "utf8"),
  ]);
}

/// The accepted cross-signing identity for a principal: the PSK plus the SSK
/// and USK it cross-signed, and the generation they were published at.
export type CrossSigningIdentity = {
  principalId: string;
  trustDomain: string;
  generation: number;
  psk: CrossSigningKey;
  ssk: CrossSigningKey;
  usk: CrossSigningKey;
};

/// Generate a fresh cross-signing identity (PSK + SSK + USK) for `principalId`
/// at `generation` (1 for the first publish).
export function generateCrossSigningIdentity(args: {
  principalId: string;
  trustDomain?: string;
  generation?: number;
}): CrossSigningIdentity {
  return {
    principalId: args.principalId,
    trustDomain: args.trustDomain ?? "ck:trust_domain:soland.local",
    generation: args.generation ?? 1,
    psk: generateCrossSigningKey(),
    ssk: generateCrossSigningKey(),
    usk: generateCrossSigningKey(),
  };
}

/// Build the `ck.cross_signing.publish` payload (device-lifecycle.md §5.1),
/// with real PSK→SSK and PSK→USK binding signatures. The shape mirrors the SDK
/// `CrossSigningPublishContent` (the type soland deserializes at ingest).
export function buildCrossSigningPublishPayload(
  identity: CrossSigningIdentity,
  opts: { expectedPreviousGeneration?: number } = {},
): Record<string, unknown> {
  const expectedPrevious =
    opts.expectedPreviousGeneration ?? identity.generation - 1;
  const selfSigningInput = crossSigningBindingInput({
    principalId: identity.principalId,
    trustDomain: identity.trustDomain,
    subordinateKind: "self_signing",
    subordinateKid: identity.ssk.didKey,
    subordinateAlg: "EdDSA",
    subordinatePublicKey: identity.ssk.multibase,
    generation: identity.generation,
  });
  const userSigningInput = crossSigningBindingInput({
    principalId: identity.principalId,
    trustDomain: identity.trustDomain,
    subordinateKind: "user_signing",
    subordinateKid: identity.usk.didKey,
    subordinateAlg: "EdDSA",
    subordinatePublicKey: identity.usk.multibase,
    generation: identity.generation,
  });
  return {
    principal_id: identity.principalId,
    trust_domain: identity.trustDomain,
    principal_signing_key: {
      kid: identity.psk.didKey,
      alg: "EdDSA",
      public_key: identity.psk.multibase,
      key_format: "multibase",
    },
    self_signing_key: {
      kid: identity.ssk.didKey,
      alg: "EdDSA",
      public_key: identity.ssk.multibase,
      key_format: "multibase",
      binding: {
        verification_method: identity.psk.didKey,
        alg: "EdDSA",
        signature: signB64url(selfSigningInput, identity.psk),
      },
    },
    user_signing_key: {
      kid: identity.usk.didKey,
      alg: "EdDSA",
      public_key: identity.usk.multibase,
      key_format: "multibase",
      binding: {
        verification_method: identity.psk.didKey,
        alg: "EdDSA",
        signature: signB64url(userSigningInput, identity.psk),
      },
    },
    expected_previous_generation: expectedPrevious,
    generation: identity.generation,
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  };
}

/// Build the `cross_signing_binding` object for a `ck.device.authorize` payload
/// (device-lifecycle.md §5.2): the accepted SSK signs the device's
/// `device_public_key` (`z…` multibase) over the ck-device-trust-bind-v1 input.
export function buildDeviceCrossSigningBinding(args: {
  identity: CrossSigningIdentity;
  deviceId: string;
  /// The new device's verify key as the `z…` multibase the directory exposes.
  devicePublicKeyMultibase: string;
}): Record<string, unknown> {
  const input = deviceTrustBindingInput({
    principalId: args.identity.principalId,
    deviceId: args.deviceId,
    devicePublicKey: args.devicePublicKeyMultibase,
    sskGeneration: args.identity.generation,
  });
  return {
    verification_method: args.identity.ssk.didKey,
    alg: "EdDSA",
    ssk_generation: args.identity.generation,
    signature: signB64url(input, args.identity.ssk),
  };
}

/// Render a freshly-generated device verify key as the `z…` multibase form
/// soland stores under `device_public_key` and re-exposes as a `did:key`.
export function deviceVerifyKeyMultibase(): {
  multibase: string;
  didKey: string;
} {
  const key = generateCrossSigningKey();
  return { multibase: key.multibase, didKey: key.didKey };
}

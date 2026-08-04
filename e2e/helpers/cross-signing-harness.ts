// Cross-signing key-management harness for the device-lifecycle §5 ingest path.
//
// Contract: arkret-spec/spec/v1/zh/crypto-media/device-lifecycle.md §5.1
// (ak.cross_signing.publish — PSK→{SSK,USK} bindings) + §5.2 (per-device
// cross_signing_binding, the SSK signature over the ak-device-trust-bind-v1
// canonical input).
//
// soland verifies these for real at event ingest:
//   * validate_cross_signing_publish (routing/identity/cross_signing.rs) anchors
//     the published PSK via the DID resolver, then checks the PSK→SSK and
//     PSK→USK binding signatures over the §5.1 ak-cross-signing-bind-v1 input
//     at the CAS-guarded generation.
//   * validate_device_authorize_binding → check_device_cross_signing_binding
//     verifies a ak.device.authorize's cross_signing_binding with the accepted
//     SSK over the §5.2 ak-device-trust-bind-v1 input at the live generation.
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
import { encodeEd25519PubkeyMultibase } from "./encoding";
import { canonicalJson, canonicalTimestamp } from "./soland-api";

/// A freshly-generated Ed25519 cross-signing key, carrying its raw public key,
/// the `z…` multibase rendering soland projects, and did:key identifiers.
export type CrossSigningKey = {
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
  /// Raw 32-byte Ed25519 public key.
  rawPublicKey: Buffer;
  /// `z…` multibase rendering (the `public_key` field with key_format multibase).
  multibase: string;
  /// `did:key:z…` — the self-contained DID.
  didKey: string;
  /// `did:key:z…#z…` — the concrete verification method id.
  verificationMethod: string;
};

/// Generate a fresh Ed25519 cross-signing key (PSK / SSK / USK).
export function generateCrossSigningKey(): CrossSigningKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) {
    throw new Error("Ed25519 public JWK missing 'x'");
  }
  const rawPublicKey = Buffer.from(jwk.x, "base64url");
  const multibase = encodeEd25519PubkeyMultibase(rawPublicKey);
  const didKey = `did:key:${multibase}`;
  return {
    privateKey,
    rawPublicKey,
    multibase,
    didKey,
    verificationMethod: `${didKey}#${multibase}`,
  };
}

/// Ed25519-sign `message` with `key` and return the detached signature as
/// base64url (no padding) — the encoding soland's `ed25519_verify` decodes.
function signB64url(message: Buffer, key: CrossSigningKey): string {
  return sign(null, message, key.privateKey).toString("base64url");
}

/// Canonical signing input for a PSK→subordinate binding
/// (`ak.cross-signing-bind-v1`, device-lifecycle.md §5.1). Byte-mirrors the SDK
/// `canonical_cross_signing_binding_input`.
///
/// 05-2 — exported so the cross-language golden-vector regression
/// (`cross-signing-golden.spec.ts`) can assert these bytes stay identical to the
/// SDK-authoritative `CrossSigningPublishContent::{self,user}_signing_binding_input`
/// emitted by the `cotest-wire` bin.
export function crossSigningBindingInput(args: {
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
    subordinate_algorithm: args.subordinateAlg,
    subordinate_public_key: args.subordinatePublicKey,
    generation: args.generation,
  });
  return Buffer.concat([
    Buffer.from("ak.cross-signing-bind-v1\n", "utf8"),
    Buffer.from(body, "utf8"),
  ]);
}

/// Canonical signing input for a per-device SSK→device binding
/// (`ak.device-trust-bind-v1`, device-lifecycle.md §5.2). Byte-mirrors the SDK
/// `canonical_device_trust_binding_input`.
///
/// 05-2 — exported for the cross-language golden-vector regression against the
/// SDK-authoritative `DeviceTrustBinding::canonical_input`.
export function deviceTrustBindingInput(args: {
  principalId: string;
  deviceId: string;
  devicePublicKey: string;
  hpkeKey: string;
  algorithms: string[];
  sskGeneration: number;
}): Buffer {
  // §5.2: algorithms MUST be UTF-8 bytewise ascending and deduplicated
  // before entering the signing input.
  const canonicalAlgorithms = [...new Set(args.algorithms)].sort();
  const body = canonicalJson({
    principal_id: args.principalId,
    device_id: args.deviceId,
    device_public_key: args.devicePublicKey,
    hpke_key: args.hpkeKey,
    algorithms: canonicalAlgorithms,
    ssk_generation: args.sskGeneration,
  });
  return Buffer.concat([
    Buffer.from("ak.device-trust-bind-v1\n", "utf8"),
    Buffer.from(body, "utf8"),
  ]);
}

function deviceAuthorizePossessionInput(args: {
  principalId: string;
  deviceId: string;
  devicePublicKey: string;
  hpkeKey: string;
  algorithms: string[];
  deviceKeyAlgorithm: string;
  authorizedBy: string;
  notBefore: string;
  expiresAt?: string | null;
  scopes?: string[] | null;
  recoverySessionId?: string | null;
  authorizationBindingKind:
    "cross_signing" | "bootstrap" | "enrollment_authority";
  crossSigningGeneration?: number | null;
}): Buffer {
  const canonicalAlgorithms = [...new Set(args.algorithms)].sort();
  const canonicalScopes = args.scopes ? [...new Set(args.scopes)].sort() : null;
  const body = canonicalJson({
    principal_id: args.principalId,
    device_id: args.deviceId,
    device_public_key: args.devicePublicKey,
    hpke_key: args.hpkeKey,
    algorithms: canonicalAlgorithms,
    device_key_algorithm: args.deviceKeyAlgorithm,
    authorized_by: args.authorizedBy,
    not_before: args.notBefore,
    expires_at: args.expiresAt ?? null,
    scopes: canonicalScopes,
    recovery_session_id: args.recoverySessionId ?? null,
    authorization_binding_kind: args.authorizationBindingKind,
    cross_signing_generation: args.crossSigningGeneration ?? null,
  });
  return Buffer.concat([
    Buffer.from("ak.device-authorize-possession-v1\n", "utf8"),
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
    trustDomain: args.trustDomain ?? "ak:trust_domain:soland.local",
    generation: args.generation ?? 1,
    psk: generateCrossSigningKey(),
    ssk: generateCrossSigningKey(),
    usk: generateCrossSigningKey(),
  };
}

/// Build the `ak.cross_signing.publish` payload (device-lifecycle.md §5.1),
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
    subordinateKid: identity.ssk.verificationMethod,
    subordinateAlg: "Ed25519",
    subordinatePublicKey: identity.ssk.multibase,
    generation: identity.generation,
  });
  const userSigningInput = crossSigningBindingInput({
    principalId: identity.principalId,
    trustDomain: identity.trustDomain,
    subordinateKind: "user_signing",
    subordinateKid: identity.usk.verificationMethod,
    subordinateAlg: "Ed25519",
    subordinatePublicKey: identity.usk.multibase,
    generation: identity.generation,
  });
  return {
    principal_id: identity.principalId,
    trust_domain: identity.trustDomain,
    principal_signing_key: {
      kid: identity.psk.verificationMethod,
      alg: "Ed25519",
      public_key: identity.psk.multibase,
      key_format: "multibase",
    },
    self_signing_key: {
      kid: identity.ssk.verificationMethod,
      alg: "Ed25519",
      public_key: identity.ssk.multibase,
      key_format: "multibase",
      binding: {
        verification_method: identity.psk.verificationMethod,
        alg: "Ed25519",
        signature: signB64url(selfSigningInput, identity.psk),
      },
    },
    user_signing_key: {
      kid: identity.usk.verificationMethod,
      alg: "Ed25519",
      public_key: identity.usk.multibase,
      key_format: "multibase",
      binding: {
        verification_method: identity.psk.verificationMethod,
        alg: "Ed25519",
        signature: signB64url(userSigningInput, identity.psk),
      },
    },
    expected_previous_generation: expectedPrevious,
    generation: identity.generation,
    issued_at: canonicalTimestamp(),
  };
}

/// Build the `cross_signing_binding` object for a `ak.device.authorize` payload
/// (device-lifecycle.md §5.2): the accepted SSK signs the device's
/// `device_public_key`, `hpke_key` and canonical `algorithms` over the
/// ak-device-trust-bind-v1 input.

/// Canonical default algorithm set for test device records; matches the
/// hpke-suite-registry default-MUST row plus the MLS group algorithm.
export const TEST_DEVICE_ALGORITHMS = [
  "ak.hpke_x25519_aead_chacha20poly1305.v1",
  "ak.mls.v1",
];
export function buildDeviceCrossSigningBinding(args: {
  identity: CrossSigningIdentity;
  deviceId: string;
  /// The new device's verify key as the `z…` multibase the directory exposes.
  devicePublicKeyMultibase: string;
  /// The device HPKE sealing key covered by the §5.2 transcript.
  hpkeKeyMultibase: string;
  /// Canonical algorithm ids covered by the §5.2 transcript.
  algorithms: string[];
}): Record<string, unknown> {
  const input = deviceTrustBindingInput({
    principalId: args.identity.principalId,
    deviceId: args.deviceId,
    devicePublicKey: args.devicePublicKeyMultibase,
    hpkeKey: args.hpkeKeyMultibase,
    algorithms: args.algorithms,
    sskGeneration: args.identity.generation,
  });
  return {
    verification_method: args.identity.ssk.verificationMethod,
    alg: "Ed25519",
    ssk_generation: args.identity.generation,
    signature: signB64url(input, args.identity.ssk),
  };
}

/// Render a freshly-generated device verify key as the `z…` multibase form
/// soland stores under `device_public_key` and re-exposes as a `did:key`.
/// Build the ak-device-authorize-possession-v1 signature made by the device
/// identity key, proving possession of `device_public_key`.
export function buildDevicePossessionSignature(args: {
  identity: CrossSigningIdentity;
  deviceId: string;
  devicePublicKeyMultibase: string;
  hpkeKeyMultibase: string;
  algorithms: string[];
  deviceKeyAlgorithm: string;
  authorizedBy: string;
  notBefore: string;
  expiresAt?: string | null;
  scopes?: string[] | null;
  recoverySessionId?: string | null;
  privateKey: CrossSigningKey["privateKey"];
}): string {
  const input = deviceAuthorizePossessionInput({
    principalId: args.identity.principalId,
    deviceId: args.deviceId,
    devicePublicKey: args.devicePublicKeyMultibase,
    hpkeKey: args.hpkeKeyMultibase,
    algorithms: args.algorithms,
    deviceKeyAlgorithm: args.deviceKeyAlgorithm,
    authorizedBy: args.authorizedBy,
    notBefore: args.notBefore,
    expiresAt: args.expiresAt,
    scopes: args.scopes,
    recoverySessionId: args.recoverySessionId,
    authorizationBindingKind: "cross_signing",
    crossSigningGeneration: args.identity.generation,
  });
  return sign(null, input, args.privateKey).toString("base64url");
}

/// Render a freshly-generated device verify key as the multibase form soland
/// stores under `device_public_key` and re-exposes as a `did:key`.
export function deviceVerifyKeyMultibase(): {
  rawPublicKey: Buffer;
  multibase: string;
  didKey: string;
  privateKey: CrossSigningKey["privateKey"];
} {
  const key = generateCrossSigningKey();
  return {
    rawPublicKey: key.rawPublicKey,
    multibase: key.multibase,
    didKey: key.didKey,
    privateKey: key.privateKey,
  };
}

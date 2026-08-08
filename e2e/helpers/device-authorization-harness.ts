import {
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";

import {
  encodeEd25519PubkeyMultibase,
  rawEd25519PublicKey,
} from "./encoding";
import { canonicalJson } from "./soland-api";

export const TEST_DEVICE_ALGORITHMS = [
  "ak.hpke_x25519_aead_chacha20poly1305.v1",
] as const;

export type DeviceAuthorizationKey = {
  privateKey: KeyObject;
  rawPublicKey: Buffer;
  multibase: string;
  didKey: string;
};

export function generateDeviceAuthorizationKey(): DeviceAuthorizationKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const rawPublicKeyBytes = rawEd25519PublicKey(publicKey);
  const multibase = encodeEd25519PubkeyMultibase(rawPublicKeyBytes);
  return {
    privateKey,
    rawPublicKey: rawPublicKeyBytes,
    multibase,
    didKey: `did:key:${multibase}`,
  };
}

export function buildDevicePossessionSignature(args: {
  principalId: string;
  deviceId: string;
  devicePublicKey: string;
  hpkeKey: string;
  algorithms: readonly string[];
  authorizedBy: string;
  authorizationBindingKind: "root_anchored" | "accepted_device";
  notBefore: string;
  privateKey: KeyObject;
  recoverySessionId?: string | null;
}): string {
  const body = {
    principal_id: args.principalId,
    device_id: args.deviceId,
    device_public_key: args.devicePublicKey,
    hpke_key: args.hpkeKey,
    algorithms: [...args.algorithms],
    device_key_algorithm: "Ed25519",
    authorized_by: args.authorizedBy,
    not_before: args.notBefore,
    expires_at: null,
    scopes: null,
    recovery_session_id: args.recoverySessionId ?? null,
    authorization_binding_kind: args.authorizationBindingKind,
  };
  const transcript = Buffer.concat([
    Buffer.from("ak.device-authorize-possession-proof-v1\n", "utf8"),
    Buffer.from(canonicalJson(body), "utf8"),
  ]);
  return nodeSign(null, transcript, args.privateKey).toString("base64url");
}

export function acceptedDeviceAuthorizePayload(args: {
  principalId: string;
  authorizerDeviceId: string;
  targetDeviceId: string;
  targetKey: DeviceAuthorizationKey;
  hpkeKey?: string;
  notBefore: string;
}): Record<string, unknown> {
  const hpkeKey = args.hpkeKey ?? "z6LSCotestE2eDeviceHpkeKey";
  const signature = buildDevicePossessionSignature({
    principalId: args.principalId,
    deviceId: args.targetDeviceId,
    devicePublicKey: args.targetKey.didKey,
    hpkeKey,
    algorithms: TEST_DEVICE_ALGORITHMS,
    authorizedBy: args.authorizerDeviceId,
    authorizationBindingKind: "accepted_device",
    notBefore: args.notBefore,
    privateKey: args.targetKey.privateKey,
  });
  return {
    principal_id: args.principalId,
    device_id: args.targetDeviceId,
    device_public_key: args.targetKey.didKey,
    hpke_key: hpkeKey,
    algorithms: [...TEST_DEVICE_ALGORITHMS],
    device_key_algorithm: "Ed25519",
    device_signature: signature,
    authorized_by: args.authorizerDeviceId,
    not_before: args.notBefore,
    authorization_binding_kind: "accepted_device",
  };
}

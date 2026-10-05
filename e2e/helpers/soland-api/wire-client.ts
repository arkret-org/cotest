import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type CotestWireCommand =
  | "canonical-json"
  | "sha256-canonical-json"
  | "did-document-digest"
  | "event-envelope-proof"
  | "event-derived-id"
  | "verify-realm-state-snapshot"
  | "invite-subject-proof"
  | "key-backup-auth-signature"
  | "mimi-consent-proof"
  | "mimi-request-consent-proof"
  | "mls-keypackage-upload-entry"
  | "mls-keypackages"
  | "mls-genesis"
  | "mls-keypackage-claim-request"
  | "mls-add-member"
  | "mls-welcome-delivery"
  | "mls-install-commit"
  | "mls-join-welcome"
  | "mls-encrypt-message"
  | "mls-encrypt-signal"
  | "mls-open-signals"
  | "principal-control-realm-id"
  | "webvh-placeholder-did"
  | "webvh-genesis"
  | "account-handoff-outcome"
  | "account-handoff-request"
  | "principal-registration-fixture"
  | "identity-creation-register-request"
  | "device-pairing-target-proof"
  | "device-pairing-approval"
  | "human-session-grant-request";

type CotestWireCanonicalJson = { canonical: string };
type CotestWireDigest = { digest: string; digest_hex: string };

const cotestRepoRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
);

export function sha256CanonicalJson(value: unknown): string {
  assertJsonTransportable(value, "$");
  return cotestWire<CotestWireDigest>("sha256-canonical-json", {
    value,
  }).digest_hex;
}

export function canonicalJson(value: unknown): string {
  assertJsonTransportable(value, "$");
  return cotestWire<CotestWireCanonicalJson>("canonical-json", {
    value,
  }).canonical;
}

export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

export function base64urlJsonCanonical(value: unknown): string {
  return Buffer.from(canonicalJson(value), "utf8").toString("base64url");
}

export function base64urlJsonRaw(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

// `cotest-wire event-envelope-proof` binds the proof to the core id it projects
// out of the authoring DID, so this argument is a resolvable `did:` DID — never
// an already-projected `ak:did_core:` core id. Callers that only hold a core id
// take the DID from the signer's verification method (the DID URL prefix).
export function sdkEventEnvelopeProof(args: {
  actorDid: string;
  event: Record<string, unknown>;
  verificationMethod: string;
  createdAt: string;
  signingSeedB64url?: string;
}): Record<string, unknown> {
  assertJsonTransportable(args.event, "$.event");
  if (!args.actorDid.startsWith("did:")) {
    throw new Error(
      `event proof requires an authoring DID, not a projected core id: ${args.actorDid}`,
    );
  }
  return cotestWire<Record<string, unknown>>("event-envelope-proof", {
    actor_did: args.actorDid,
    event: args.event,
    verification_method: args.verificationMethod,
    created_at: args.createdAt,
    signing_seed_b64url: args.signingSeedB64url,
  });
}

export function sdkEventDerivedIds(event: Record<string, unknown>): {
  event_id: string;
  realm_id: string;
  object_id?: string;
} {
  assertJsonTransportable(event, "$.event");
  return cotestWire<{ event_id: string; realm_id: string }>(
    "event-derived-id",
    event,
  );
}

export function sdkInviteSubjectProof(args: {
  subjectAccountId: { principal_id: string; station_id: string };
  inviteId: string;
  realmId: string;
  tokenCommitment: string;
  claimNonce: string;
  verificationId: string;
  bindingProof: Record<string, unknown>;
  verificationMethod: string;
  subjectDid: string;
  rootPublicKeyMultibase: string;
  recoveryKey: string;
  negativeDeviceSigningSeedB64url?: string;
}): Record<string, unknown> {
  return cotestWire<Record<string, unknown>>("invite-subject-proof", {
    subject_account_id: args.subjectAccountId,
    invite_id: args.inviteId,
    realm_id: args.realmId,
    token_commitment: args.tokenCommitment,
    claim_nonce: args.claimNonce,
    verification_id: args.verificationId,
    binding_proof: args.bindingProof,
    verification_method: args.verificationMethod,
    subject_did: args.subjectDid,
    root_public_key_multibase: args.rootPublicKeyMultibase,
    negative_device_signing_seed_b64url: args.negativeDeviceSigningSeedB64url,
    recovery_key: args.recoveryKey,
  });
}

/// The device signature `auth_data.signature` of a key-backup envelope
/// (key-management.md section 7.4.1), over the SDK transcript. `envelope` is
/// unsigned; the same envelope comes back with the signature attached.
export function sdkKeyBackupAuthSignature(args: {
  envelope: Record<string, unknown>;
  signingSeedB64url: string;
}): Record<string, unknown> {
  assertJsonTransportable(args.envelope, "$.envelope");
  return cotestWire<Record<string, unknown>>("key-backup-auth-signature", {
    envelope: args.envelope,
    signing_seed_b64url: args.signingSeedB64url,
  });
}

export function sdkEventDerivedObjectId(
  event: Record<string, unknown>,
): string {
  const objectId = sdkEventDerivedIds(event).object_id;
  if (!objectId) {
    throw new Error(
      `Event kind ${String(event.kind)} does not derive an object id`,
    );
  }
  return objectId;
}

export function sdkMimiConsentProof(args: {
  request: Record<string, unknown>;
  verificationMethod: string;
  createdAt: string;
  domain: string;
  audience: string;
  signingSeedB64url?: string;
}): Record<string, unknown> {
  assertJsonTransportable(args.request, "$.request");
  return cotestWire<Record<string, unknown>>("mimi-consent-proof", {
    request: args.request,
    verification_method: args.verificationMethod,
    created_at: args.createdAt,
    domain: args.domain,
    audience: args.audience,
    signing_seed_b64url: args.signingSeedB64url,
  });
}

/// The requester proof `mimi_request_consent_request_body.proofs[]` requires.
///
/// `request` is the unsigned body — `requester_actor_id`, `holder_account_id`,
/// `purpose` and any optional members. The digest is taken over exactly that,
/// so the proof never covers itself.
export function sdkMimiRequestConsentProof(args: {
  request: Record<string, unknown>;
  verificationMethod: string;
  createdAt: string;
  domain: string;
  audience: string;
  signingSeedB64url?: string;
}): Record<string, unknown> {
  assertJsonTransportable(args.request, "$.request");
  return cotestWire<Record<string, unknown>>("mimi-request-consent-proof", {
    request: args.request,
    verification_method: args.verificationMethod,
    created_at: args.createdAt,
    domain: args.domain,
    audience: args.audience,
    signing_seed_b64url: args.signingSeedB64url,
  });
}

export function cotestWire<T>(command: CotestWireCommand, input: unknown): T {
  const binary = process.env.COTEST_WIRE_BIN;
  const result = spawnSync(
    binary ?? "cargo",
    binary
      ? [command]
      : [
          "run",
          "--quiet",
          // `cotest-wire` moved to `crates/test-support`, whose graph is SDK +
          // Garth. Without `-p` Cargo resolves the bin through the root
          // package and rebuilds Inkson and the soland crates with it.
          "-p",
          "cotest-test-support",
          "--bin",
          "cotest-wire",
          "--",
          command,
        ],
    {
      cwd: cotestRepoRoot,
      encoding: "utf8",
      input: JSON.stringify(input),
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `cotest-wire ${command} failed with exit ${result.status}:\n${result.stderr}`,
    );
  }
  try {
    return JSON.parse(result.stdout.trim()) as T;
  } catch {
    throw new Error(
      `cotest-wire ${command} returned non-JSON output: ${result.stdout}`,
    );
  }
}

function assertJsonTransportable(value: unknown, path: string): void {
  if (value === null) {
    return;
  }

  switch (typeof value) {
    case "string":
    case "boolean":
      return;
    case "number":
      if (!Number.isFinite(value) || Object.is(value, -0)) {
        throw new TypeError(`non-JSON number at ${path}: ${value}`);
      }
      return;
    case "object":
      break;
    default:
      throw new TypeError(`non-JSON value at ${path}: ${typeof value}`);
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      if (item === undefined) {
        throw new TypeError(`non-JSON undefined item at ${path}[${index}]`);
      }
      assertJsonTransportable(item, `${path}[${index}]`);
    });
    return;
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError(`non-JSON object at ${path}`);
  }

  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (item === undefined) {
      throw new TypeError(`non-JSON undefined member at ${path}.${key}`);
    }
    assertJsonTransportable(item, `${path}.${key}`);
  }
}

export function stripUndefined(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) =>
      item === undefined ? null : stripUndefined(item),
    );
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .map(([key, item]) => [key, stripUndefined(item)]),
    );
  }
  return value;
}

import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { chmodSync, closeSync, mkdtempSync, openSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type CotestWireCommand =
  | "canonical-json"
  | "sha256-canonical-json"
  | "did-document-digest"
  | "event-envelope-proof"
  | "event-derived-id"
  | "local-message-payload"
  | "historical-human-signer-query"
  | "historical-human-signer-fact"
  | "project-committed-stream-scan"
  | "verify-realm-state-snapshot"
  | "verify-consent-current"
  | "validate-applet-authority-material"
  | "key-backup-auth-signature"
  | "mimi-consent-proof"
  | "mimi-request-consent-proof"
  | "mls-keypackage-upload-entry"
  | "mls-keypackages"
  | "mls-genesis-material"
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
  | "realm-actor-inception"
  | "applet-realm-actor-author"
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

// A regular read-only descriptor has a finite EOF independently of the
// parent's synchronous stdio pump. Preserve the exact JSON bytes and keep
// temporary private material accessible only to this user, then remove it.
export function runCotestWireJsonProcess(
  executable: string,
  args: string[],
  inputJson: string,
  { cwd, timeoutMs = 90_000 }: { cwd: string; timeoutMs?: number },
): SpawnSyncReturns<string> {
  const scratch = mkdtempSync(join(tmpdir(), "cotest-wire-json-"));
  let descriptor: number | undefined;
  try {
    chmodSync(scratch, 0o700);
    const inputPath = join(scratch, "stdin.json");
    writeFileSync(inputPath, inputJson, { encoding: "utf8", flag: "wx", mode: 0o600 });
    descriptor = openSync(inputPath, "r");
    return spawnSync(executable, args, {
      cwd,
      encoding: "utf8",
      stdio: [descriptor, "pipe", "pipe"],
      maxBuffer: 10 * 1024 * 1024,
      timeout: timeoutMs,
    });
  } finally {
    try {
      if (descriptor !== undefined) closeSync(descriptor);
    } finally {
      rmSync(scratch, { recursive: true, force: true, maxRetries: 3, retryDelay: 10 });
    }
  }
}

export function cotestWire<T>(command: CotestWireCommand, input: unknown): T {
  const binary = process.env.COTEST_WIRE_BIN;
  const inputJson = JSON.stringify(input);
  if (typeof inputJson !== "string") throw new TypeError(`cotest-wire ${command} requires JSON input`);
  const result = runCotestWireJsonProcess(
    binary ?? "cargo",
    binary
      ? [command]
      : [
          "run",
          "--quiet",
          // `cotest-wire` moved to `crates/test-support`, whose graph is SDK +
          // Garth. Without `-p` Cargo resolves the bin through the root
          // package and rebuilds Inkson and the coland crates with it.
          "-p",
          "cotest-test-support",
          "--bin",
          "cotest-wire",
          "--",
          command,
        ],
    inputJson,
    {
      cwd: cotestRepoRoot,
      // Joint lanes bind a prebuilt oracle. Preserve the standalone Cargo
      // preparation fallback without imposing a native-call build deadline.
      timeoutMs: binary ? 90_000 : 0,
    },
  );
  if (result.error) {
    throw new Error(`cotest-wire ${command} launch failed: ${(result.error as NodeJS.ErrnoException).code ?? "unknown"}; input_bytes=${Buffer.byteLength(inputJson)}; stdout_bytes=${Buffer.byteLength(result.stdout ?? "")}; stderr_bytes=${Buffer.byteLength(result.stderr ?? "")}`, { cause: result.error });
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

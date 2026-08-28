import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type CotestWireCommand =
  | "canonical-json"
  | "sha256-canonical-json"
  | "event-envelope-proof"
  | "event-derived-id"
  | "mimi-consent-proof"
  | "join-receipt-proof"
  | "mls-keypackage-upload-entry"
  | "principal-control-realm-id"
  | "webvh-placeholder-did"
  | "webvh-genesis"
  | "account-handoff-outcome"
  | "account-handoff-request"
  | "principal-registration-fixture"
  | "identity-creation-register-request"
  | "principal-bootstrap-seal"
  | "principal-successor-seal";

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

export function sdkEventEnvelopeProof(args: {
  actorId: string;
  event: Record<string, unknown>;
  verificationMethod: string;
  createdAt: string;
  signingSeedB64url?: string;
}): Record<string, unknown> {
  assertJsonTransportable(args.event, "$.event");
  return cotestWire<Record<string, unknown>>("event-envelope-proof", {
    actor_did: args.actorId,
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

export function sdkJoinReceiptProof(args: {
  actorId: string;
  realmId: string;
  receiptDigest: string;
  createdAt: string;
  context: string;
  applicationRef?: string;
  applicationRevisionDigest?: string;
  executedBy?: string;
  verificationMethod: string;
  signingSeedB64url?: string;
}): Record<string, unknown> {
  return cotestWire<Record<string, unknown>>("join-receipt-proof", {
    actor_did: args.actorId,
    realm_id: args.realmId,
    receipt_digest: args.receiptDigest,
    created_at: args.createdAt,
    context: args.context,
    application_ref: args.applicationRef,
    application_revision_digest: args.applicationRevisionDigest,
    executed_by: args.executedBy,
    verification_method: args.verificationMethod,
    signing_seed_b64url: args.signingSeedB64url,
  });
}

export function cotestWire<T>(command: CotestWireCommand, input: unknown): T {
  const binary = process.env.COTEST_WIRE_BIN;
  const result = spawnSync(
    binary ?? "cargo",
    binary
      ? [command]
      : ["run", "--quiet", "--bin", "cotest-wire", "--", command],
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

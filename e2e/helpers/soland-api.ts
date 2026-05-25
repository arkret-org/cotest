import { createHash, randomBytes } from "node:crypto";
import { expect, type APIRequestContext, type APIResponse } from "@playwright/test";
import { type SolandKey, solandBaseUrl, solandServiceDid } from "./env";

export type OperationKind =
  | "event"
  | "flow"
  | "mls_group"
  | "mls_keypackage"
  | "mls_welcome"
  | "operation"
  | "realm"
  | "space";

export type SignedEventEnvelopeArgs = {
  actorDid: string;
  realmId: string;
  kind: string;
  payload: Record<string, unknown>;
  actorSeq?: number;
  createdAt?: string;
  eventId?: string;
  operationId?: string;
  schemaId?: string;
  proofVerificationMethod?: string;
};

export function authHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

export function typedId(kind: OperationKind): string {
  return `cx:${kind}:${uuidV7()}`;
}

export function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

export function wireErrCode(body: unknown): string | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const record = body as Record<string, unknown>;
  const nested = record.error && typeof record.error === "object"
    ? (record.error as Record<string, unknown>)
    : undefined;
  return stringValue(record.errcode)
    ?? stringValue(record.code)
    ?? stringValue(record.error_code)
    ?? stringValue(record.reason)
    ?? stringValue(nested?.errcode)
    ?? stringValue(nested?.code)
    ?? stringValue(nested?.error_code)
    ?? stringValue(nested?.reason);
}

export function singleDidAnchorer(did: string): Record<string, unknown> {
  return {
    type: "single_did",
    did,
    recovery_members: ["did:web:recovery.soland.local"],
    controller_organization: "did:web:organization.primary.soland.local",
    recovery_controller_organizations: ["did:web:organization.recovery.soland.local"],
  };
}

export async function expectJsonOk<T = Record<string, unknown>>(
  response: APIResponse,
  context: string,
): Promise<T> {
  const text = await response.text();
  expect(
    response.ok(),
    `${context} returned ${response.status()}: ${text}`,
  ).toBeTruthy();
  return JSON.parse(text) as T;
}

export async function createSpaceApi(
  request: APIRequestContext,
  token: string,
  data: {
    title: string;
    summary?: string;
    discoverability?: string;
    history_visibility?: string;
    encryption_profile?: string;
    invitees?: string[];
    plaintext_visible_services?: string[];
    public?: boolean;
    ownerDid?: string;
    audit_disclosure_policy?: Record<string, unknown>;
  },
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const ownerDid = data.ownerDid ?? await currentActorDidApi(request, token, opts);
  const realmId = typedId("realm");
  const createdAt = canonicalTimestamp();
  const plaintextVisibleServices =
    data.plaintext_visible_services ??
    Array.from(new Set([solandServiceDid(opts.server), "did:web:soland.local"]));

  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: ownerDid,
      realmId,
      kind: "cx.realm.create",
      createdAt,
      payload: {
        plaintext_visible_services: plaintextVisibleServices,
        object: {
          id: realmId,
          schema: "cx.schema.realm.v1",
          title: data.title,
          summary: data.summary,
          created_by_principal: ownerDid,
          trust_domain: "cx:trust_domain:soland.local",
          schema_refs: ["cx.schema.realm.v1"],
          default_discoverability: data.discoverability ?? (data.public ? "public" : "listed"),
          default_join_rule: "invite",
          history_visibility: data.history_visibility ?? "shared",
          encryption_profile: data.encryption_profile ?? "none",
          plaintext_visible_services: plaintextVisibleServices,
          ...(data.audit_disclosure_policy
            ? { audit_disclosure_policy: data.audit_disclosure_policy }
            : {}),
          security_class: "standard",
          federation_policy: "restricted",
          anchor_profile: "single_did",
          digest_algorithm: "sha256",
          anchorer: singleDidAnchorer(ownerDid),
          created_at: createdAt,
        },
      },
    }),
    { server: opts.server, context: `create realm ${data.title}` },
  );

  for (const invitee of data.invitees ?? []) {
    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: ownerDid,
        realmId,
        kind: "cx.member.state",
        payload: {
          actor_id: invitee,
          member: invitee,
          membership: "invite",
        },
      }),
      { server: opts.server, context: `invite ${invitee}` },
    );
  }

  return realmId;
}

export async function addSpaceMemberApi(
  request: APIRequestContext,
  token: string,
  spaceId: string,
  memberDid: string,
  opts: { server?: SolandKey } = {},
) {
  const actorDid = await currentActorDidApi(request, token, opts);
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId: spaceId,
      kind: "cx.member.state",
      payload: {
        actor_id: memberDid,
        member: memberDid,
        membership: "join",
        delivery_status: "unroutable",
      },
    }),
    { server: opts.server, context: `add member ${memberDid}` },
  );
}

export async function acceptInviteApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  spaceId: string,
  inviteId: string,
  opts: { server?: SolandKey } = {},
) {
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId: spaceId,
      kind: "cx.member.state",
      payload: {
        actor_id: actorDid,
        membership: "join",
        reason: "invite_accept",
        invite_id: inviteId,
        delivery_status: "unroutable",
      },
    }),
    { server: opts.server, context: `accept invite ${inviteId}` },
  );
}

export async function listInvitesApi(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<Array<{ invite_id: string; space_id: string; invitee?: string; state?: string; status?: string }>> {
  const response = await request.get(`${solandBaseUrl(opts.server)}/api/v1/authz/invites`, {
    headers: authHeaders(token),
  });
  const body = await expectJsonOk<{ invites?: Array<{ invite_id: string; space_id: string; invitee?: string }> }>(
    response,
    "list invites",
  );
  return body.invites ?? [];
}

export async function sendMessageApi(
  request: APIRequestContext,
  token: string,
  spaceId: string,
  body: string,
  opts: { server?: SolandKey; encrypted?: boolean } = {},
) {
  const actorDid = await currentActorDidApi(request, token, opts);
  const envelope = signedEventEnvelope({
    actorDid,
    realmId: spaceId,
    kind: "cx.message.create",
    payload: {
      flow_id: flowIdFromRealmId(spaceId),
      track: "discussion",
      content: {
        kind: "cx.content.text",
        body,
      },
      encrypted: opts.encrypted ?? false,
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `send message to ${spaceId}`,
  });
  return {
    event_id: String(envelope.event_id),
    space_id: spaceId,
    sender: actorDid,
  };
}

export async function querySpaceEventsApi(
  request: APIRequestContext,
  token: string,
  spaceId: string,
  opts: { server?: SolandKey; limit?: number } = {},
) {
  const queryParam = spaceId.startsWith("cx:realm:") ? "realms" : "space_id";
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/api/v1/events?${queryParam}=${encodeURIComponent(spaceId)}&limit=${opts.limit ?? 100}`,
    { headers: authHeaders(token) },
  );
  return await expectJsonOk<Record<string, unknown>>(response, `query events for ${spaceId}`);
}

export async function currentActorDidApi(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const response = await request.get(`${solandBaseUrl(opts.server)}/api/v1/account/me`, {
    headers: authHeaders(token),
  });
  const body = await expectJsonOk<{ did?: string }>(response, "read current actor");
  expect(body.did, "current actor DID").toBeTruthy();
  return body.did!;
}

export function signedEventEnvelope(
  args: SignedEventEnvelopeArgs,
): Record<string, unknown> {
  const createdAt = args.createdAt ?? canonicalTimestamp();
  const payload = stripUndefined(args.payload) as Record<string, unknown>;
  return {
    event_id: args.eventId ?? typedId("event"),
    kind: args.kind,
    schema_id: args.schemaId ?? "cx.schema.event.v1",
    realm_id: args.realmId,
    actor_id: args.actorDid,
    actor_seq: args.actorSeq ?? nextActorSeq(),
    created_at: createdAt,
    prev_refs: [],
    refs: [],
    requirements: {
      schema: ["cx.schema.event.v1"],
      features: [],
      critical_extensions: [],
    },
    payload,
    unsigned: {
      local_operation_idempotency_alias:
        args.operationId ?? typedId("operation"),
    },
    proofs: [
      {
        type: "dev-proof",
        verification_method:
          args.proofVerificationMethod ?? `${args.actorDid}#device`,
        payload_digest: `sha256:${sha256CanonicalJson(payload)}`,
      },
    ],
  };
}

export async function submitSignedEventApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: { server?: SolandKey; context?: string } = {},
) {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/api/v1/events`,
    {
      headers: authHeaders(token),
      data: envelope,
    },
  );
  const text = await response.text();
  expect(
    [200, 201],
    `${opts.context ?? `submit ${String(envelope.kind)}`} returned ${response.status()}: ${text}`,
  ).toContain(response.status());
  return JSON.parse(text) as Record<string, unknown>;
}

export function flowIdFromRealmId(realmId: string): string {
  const suffix = realmId.replace(/^cx:(realm|space):/, "");
  return `cx:flow:${suffix}`;
}

export function canonicalTimestamp(date: Date = new Date()): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function makeOperation(args: {
  operationId?: string;
  spaceId: string;
  objectType: string;
  operationType?: string;
  payload: Record<string, unknown>;
}) {
  return {
    schema: "cx.local.operation_draft.v1",
    operation_id: args.operationId ?? typedId("operation"),
    type: "operation",
    operation_type: args.operationType ?? "create",
    realm_id: realmIdForOperation(args.spaceId),
    space_id: args.spaceId,
    object_id: undefined,
    object_type: args.objectType,
    payload: args.payload,
    created_at: new Date().toISOString(),
  };
}

function realmIdForOperation(spaceId: string): string {
  return spaceId.replace(/^cx:space:/, "cx:realm:");
}

export async function pushFederationOperations(
  request: APIRequestContext,
  operations: Array<Record<string, unknown>>,
  opts: {
    origin: string;
    destination?: string;
    spaceId: string;
    server?: SolandKey;
    serviceBindingRef?: string;
  },
) {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/api/v1/federation/push-operations`,
    {
      data: {
        origin: opts.origin,
        destination: opts.destination ?? solandServiceDid(opts.server),
        space_id: opts.spaceId,
        service_binding_ref: opts.serviceBindingRef ?? `${opts.origin}#cotest-federation-smoke`,
        operations,
      },
    },
  );
  return await expectJsonOk<{
    accepted?: string[];
    rejected?: Array<Record<string, unknown>>;
    quarantine?: unknown[];
  }>(response, "push federation operations");
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

let actorSeqCounter = 1;

function nextActorSeq(): number {
  const seq = actorSeqCounter;
  actorSeqCounter += 1;
  return seq;
}

function sha256CanonicalJson(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function stripUndefined(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => (item === undefined ? null : stripUndefined(item)));
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

function uuidV7(): string {
  const time = Date.now().toString(16).padStart(12, "0").slice(-12);
  const random = randomBytes(9).toString("hex");
  const variant = (8 + (randomBytes(1)[0] & 0x03)).toString(16);
  return [
    time.slice(0, 8),
    time.slice(8, 12),
    `7${random.slice(0, 3)}`,
    `${variant}${random.slice(3, 6)}`,
    random.slice(6, 18),
  ].join("-");
}

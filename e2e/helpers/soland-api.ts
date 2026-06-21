import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { type SolandKey, solandBaseUrl, solandServiceDid } from "./env";

export type OperationKind =
  | "circle"
  | "device"
  | "event"
  | "grant"
  | "strand"
  | "invite"
  | "mls_group"
  | "mls_keypackage"
  | "mls_welcome"
  | "operation"
  | "realm"
  | "relation"
  | "space";

export type SignedEventEnvelopeArgs = {
  actorDid: string;
  realmId: string;
  kind: string;
  payload: Record<string, unknown>;
  actorSeq?: number;
  createdAt?: string;
  eventId?: string;
  schemaId?: string;
  proofVerificationMethod?: string;
  anchorRef?: string;
  refs?: Array<Record<string, unknown>>;
};

export type EventProofMode = "dev-proof" | "detached-jws";

export function authHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

export function typedId(kind: OperationKind): string {
  return `ck:${kind}:${uuidV7()}`;
}

export function principalControlRealmForDid(did: string): string {
  const realmId = derivePrincipalControlRealmForDid(did);
  assertPrincipalControlRealmVectors(did, realmId);
  return realmId;
}

function derivePrincipalControlRealmForDid(did: string): string {
  const digest = createHash("sha256")
    .update("ck:realm:principal-control:v1:")
    .update(did)
    .digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `ck:realm:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

export function wireErrCode(body: unknown): string | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const record = body as Record<string, unknown>;
  const nested =
    record.error && typeof record.error === "object"
      ? (record.error as Record<string, unknown>)
      : undefined;
  return (
    stringValue(record.errcode) ??
    stringValue(record.code) ??
    stringValue(record.error_code) ??
    stringValue(record.reason) ??
    stringValue(nested?.errcode) ??
    stringValue(nested?.code) ??
    stringValue(nested?.error_code) ??
    stringValue(nested?.reason)
  );
}

export function singleDidNotary(did: string): Record<string, unknown> {
  return {
    type: "single_did",
    did,
    recovery_members: ["did:web:recovery.soland.local"],
    controller_organization: "did:web:organization.primary.soland.local",
    recovery_controller_organizations: [
      "did:web:organization.recovery.soland.local",
    ],
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

export async function createRealmApi(
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
    federation_policy?: string;
    ownerDid?: string;
    owning_organizations?: string[];
    audit_disclosure_policy?: Record<string, unknown>;
    retention_policy?: Record<string, unknown>;
  },
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const ownerDid =
    data.ownerDid ?? (await currentActorDidApi(request, token, opts));
  const realmId = typedId("realm");
  const createdAt = canonicalTimestamp();
  const plaintextVisibleServices =
    data.plaintext_visible_services ??
    Array.from(
      new Set([solandServiceDid(opts.server), "did:web:soland.local"]),
    );

  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: ownerDid,
      realmId,
      kind: "ck.realm.create",
      createdAt,
      payload: {
        // `plaintext_visible_services` lives on the realm object only — the
        // realm_create_payload root is additionalProperties:false and rejects
        // it (it stays inside `object` below, which is additionalProperties:true).
        object: {
          id: realmId,
          schema: "ck.schema.realm.v1",
          title: data.title,
          summary: data.summary,
          created_by: ownerDid,
          trust_domain: "ck:trust_domain:soland.local",
          schema_refs: ["ck.schema.realm.v1"],
          default_discoverability:
            data.discoverability ?? (data.public ? "public" : "listed"),
          default_join_rule: "invite",
          history_visibility: data.history_visibility ?? "shared",
          encryption_profile: data.encryption_profile ?? "none",
          plaintext_visible_services: plaintextVisibleServices,
          ...(data.owning_organizations
            ? { owning_organizations: data.owning_organizations }
            : {}),
          ...(data.audit_disclosure_policy
            ? { audit_disclosure_policy: data.audit_disclosure_policy }
            : {}),
          ...(data.retention_policy
            ? { retention_policy: data.retention_policy }
            : {}),
          security_class: "standard",
          federation_policy: data.federation_policy ?? "restricted",
          notary_profile: "single_did",
          digest_algorithm: "sha256",
          notary: singleDidNotary(ownerDid),
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
        kind: "ck.member.state",
        payload: {
          realm_id: realmId,
          actor_id: invitee,
          membership: "invite",
        },
      }),
      { server: opts.server, context: `invite ${invitee}` },
    );
  }

  return realmId;
}

export async function addRealmMemberApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  memberDid: string,
  opts: { server?: SolandKey } = {},
) {
  const actorDid = await currentActorDidApi(request, token, opts);
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.member.state",
      payload: {
        // `realm_id` inside the payload is a spec-defined membership_payload
        // property (event-payload.schema.json#/$defs/membership_payload) and is
        // required by soland's registry-backed payload validator in dev-proof
        // mode; include it so the membership op validates regardless of the
        // active proof profile.
        realm_id: realmId,
        actor_id: memberDid,
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
  realmId: string,
  inviteId: string,
  opts: { server?: SolandKey } = {},
) {
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.member.state",
      payload: {
        realm_id: realmId,
        actor_id: actorDid,
        membership: "join",
        reason: "invite_accept",
        invite_ref: inviteId,
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
): Promise<
  Array<{
    invite_id: string;
    realm_id: string;
    invitee?: string;
    state?: string;
    status?: string;
  }>
> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/authz/invites`,
    {
      headers: authHeaders(token),
    },
  );
  const body = await expectJsonOk<{
    invites?: Array<{ invite_id: string; realm_id: string; invitee?: string }>;
  }>(response, "list invites");
  return body.invites ?? [];
}

export async function sendMessageApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  body: string,
  opts: { server?: SolandKey; encrypted?: boolean; createdAt?: string } = {},
) {
  const actorDid = await currentActorDidApi(request, token, opts);
  const strandId = await resolveDefaultStrandId(request, token, realmId, { server: opts.server });
  const envelope = signedEventEnvelope({
    actorDid,
    realmId,
    kind: "ck.message.create",
    createdAt: opts.createdAt,
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      content: {
        kind: "ck.content.text",
        body,
      },
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `send message to ${realmId}`,
  });
  return {
    event_id: String(envelope.event_id),
    realm_id: realmId,
    actor_id: actorDid,
  };
}

export async function queryRealmEventsApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey; limit?: number } = {},
) {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=${opts.limit ?? 100}`,
    { headers: authHeaders(token) },
  );
  return await expectJsonOk<Record<string, unknown>>(
    response,
    `query events for ${realmId}`,
  );
}

export async function accountSubscribeDeltaApi(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<Record<string, unknown>> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/account/subscribe?catchup=true`,
    { headers: { ...authHeaders(token), accept: "application/x-ndjson" } },
  );
  const text = await response.text();
  expect(response.status(), `account subscribe returned ${response.status()}: ${text}`).toBe(200);
  const frames = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  const delta = frames.find((frame) => frame.kind === "delta") ?? frames[0];
  expect(delta, "account subscribe delta frame").toBeTruthy();
  return delta;
}

export async function putAccountDataViaEventApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  key: string,
  body: Record<string, unknown>,
  opts: { server?: SolandKey; context?: string } = {},
) {
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.account_data.set",
      payload: {
        key,
        owner: actorDid,
        body,
        updated_at: canonicalTimestamp(),
      },
    }),
    {
      server: opts.server,
      context: opts.context ?? `set account_data ${key}`,
    },
  );
}

export async function currentActorDidApi(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/account/viewer`,
    {
      headers: authHeaders(token),
    },
  );
  const body = await expectJsonOk<{ principal_id?: string; did?: string }>(
    response,
    "read current actor",
  );
  const actorDid = body.principal_id ?? body.did;
  expect(actorDid, "current actor DID").toBeTruthy();
  return actorDid!;
}

export function signedEventEnvelope(
  args: SignedEventEnvelopeArgs,
): Record<string, unknown> {
  const createdAt = args.createdAt ?? canonicalTimestamp();
  const payload = stripUndefined(args.payload) as Record<string, unknown>;
  const event = stripUndefined({
    event_id: args.eventId ?? typedId("event"),
    kind: args.kind,
    realm_id: args.realmId,
    actor_id: args.actorDid,
    actor_seq: args.actorSeq ?? nextActorSeq(),
    created_at: createdAt,
    prev_refs: [],
    refs: args.refs ?? [],
    ...(args.anchorRef ? { anchor_ref: args.anchorRef } : {}),
    requirements: {
      schema: [args.schemaId ?? schemaIdForEventKind(args.kind)],
      features: [],
      critical_extensions: [],
    },
    payload,
  }) as Record<string, unknown>;
  return {
    ...event,
    proofs: [
      eventProof({
        actorDid: args.actorDid,
        event,
        verificationMethod: args.proofVerificationMethod,
      }),
    ],
  };
}

export function eventProof(args: {
  actorDid: string;
  event: Record<string, unknown>;
  verificationMethod?: string;
}): Record<string, unknown> {
  const mode = eventProofMode();
  const verificationMethod =
    args.verificationMethod ?? `${args.actorDid}#device`;
  const eventDigest = `sha256:${sha256CanonicalJson(args.event)}`;
  const createdAt = canonicalTimestamp();

  if (mode === "dev-proof") {
    return {
      type: "dev-proof",
      verification_method: verificationMethod,
      event_digest: eventDigest,
    };
  }

  return {
    kind: "detached_jws",
    alg: "EdDSA",
    verification_method: verificationMethod,
    event_digest: eventDigest,
    created_at: createdAt,
    signing_profile: "cotest.detached_jws.fixture.v1",
    jws: detachedJwsFixture({
      actorDid: args.actorDid,
      verificationMethod,
      eventDigest,
      createdAt,
    }),
  };
}

export async function submitSignedEventApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: { server?: SolandKey; context?: string } = {},
) {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_cokret/self/events`,
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

// COT-06-004: discover a Realm's default discussion Strand via the projection face
// instead of deriving it from the Realm UUID. `ck:realm:<uuid>` and
// `ck:strand:<uuid>` are independent id kinds (registry/id-kind-registry.json)
// that do not derive from each other; the previous `strandIdFromRealmId` helper
// hard-coded soland's internal minting rule. The spec-faithful source of truth
// is the Realm projection's authoritative `default_strand_id` (nullable), with the
// Strand projection's derived `is_default` marker as a fallback discovery path.
export async function resolveDefaultStrandId(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  // Primary: Realm projection carries the authoritative default_strand_id.
  const realmResp = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/realms/${encodeURIComponent(realmId)}`,
    { headers: authHeaders(token) },
  );
  if (realmResp.ok()) {
    const realm = (await realmResp.json()) as { default_strand_id?: unknown };
    if (typeof realm.default_strand_id === "string" && realm.default_strand_id) {
      return realm.default_strand_id;
    }
  }

  // Fallback: discover via the Strand projection's derived is_default marker.
  const flowsResp = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/projection/strands?realm_id=${encodeURIComponent(realmId)}`,
    { headers: authHeaders(token) },
  );
  expect(
    flowsResp.ok(),
    `resolveDefaultStrandId: strand projection for ${realmId} returned ${flowsResp.status()}`,
  ).toBeTruthy();
  const body = (await flowsResp.json()) as {
    strands?: Array<{ strand_id?: string; is_default?: boolean }>;
    items?: Array<{ strand_id?: string; is_default?: boolean }>;
  };
  const strands = Array.isArray(body.strands)
    ? body.strands
    : Array.isArray(body.items)
      ? body.items
      : [];
  const def = strands.find((strand) => strand.is_default === true);
  if (def?.strand_id) {
    return def.strand_id;
  }
  // Final fallback: the yougen UI realm-create flow does not emit an explicit
  // ck.realm.set_default_strand, so soland never marks a strand is_default for
  // those realms. yougen itself addresses the default strand by a deterministic
  // convention (default_strand_id_for_realm in yougen/src/local_state): the
  // realm UUID suffix under the ck:strand: prefix. Derive the same id so events
  // submitted here land on the strand yougen renders.
  return deriveDefaultStrandId(realmId);
}

/// Mirror yougen's `default_strand_id_for_realm` convention: `ck:realm:<uuid>`
/// maps to `ck:strand:<uuid>`.
export function deriveDefaultStrandId(realmId: string): string {
  const suffix = realmId.startsWith("ck:realm:")
    ? realmId.slice("ck:realm:".length)
    : realmId;
  return `ck:strand:${suffix}`;
}

export function canonicalTimestamp(date: Date = new Date()): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function makeFederationEvent(args: {
  eventId?: string;
  actorDid?: string;
  realmId: string;
  kind: string;
  payload: Record<string, unknown>;
}) {
  return signedEventEnvelope({
    eventId: args.eventId,
    actorDid: args.actorDid ?? "did:web:cotest-federation.example",
    realmId: args.realmId,
    kind: args.kind,
    schemaId: schemaIdForEventKind(args.kind),
    payload: args.payload,
  });
}

export async function pushFederationEvents(
  request: APIRequestContext,
  events: Array<Record<string, unknown>>,
  opts: {
    origin: string;
    destination?: string;
    realmId: string;
    server?: SolandKey;
    idempotencyKey?: string;
  },
) {
  const response = await rawPushFederationEvents(request, events, opts);
  return await expectJsonOk<{
    status?: string;
    accepted?: string[];
    duplicate?: string[];
    rejected?: Array<Record<string, unknown>>;
    quarantine?: unknown[];
  }>(response, "push federation events");
}

export async function rawPushFederationEvents(
  request: APIRequestContext,
  events: Array<Record<string, unknown>>,
  opts: {
    origin: string;
    destination?: string;
    realmId: string;
    server?: SolandKey;
    idempotencyKey?: string;
    tamperSignature?: boolean;
    relaySourceDid?: string;
    // Negative-coverage hook: submit a digest that diverges from the
    // receiver's registry-derived value (expect reducer_profile_mismatch).
    reducerProfileDigestOverride?: string;
  },
) {
  const destination = opts.destination ?? solandServiceDid(opts.server);
  const url = `${solandBaseUrl(opts.server)}/_cokret/peer/events`;
  const body = peerEventsSubmitBody(
    opts.realmId,
    events.map(federationEventWireBody),
    opts.idempotencyKey,
    { reducerProfileDigest: opts.reducerProfileDigestOverride },
  );
  const sourceDid = opts.relaySourceDid ?? opts.origin;
  const headers = signedFederationPushHeaders(
    sourceDid,
    destination,
    url,
    body,
  );
  if (opts.tamperSignature) {
    headers.signature = `sig1=:${Buffer.alloc(64).toString("base64")}:`;
  }
  return await request.post(url, {
    data: canonicalJson(body),
    headers,
  });
}

export type InviteDeliveryRequestBody = {
  schema: "ck.schema.invite_delivery_request.v1";
  invite_event: Record<string, unknown>;
  invite_address: {
    subject_id: string;
    recipient_service_did: string;
    recipient_service_type?: "principal_server";
  };
  introduction_evidence: Record<string, unknown>;
  idempotency_key: string;
};

export async function submitPeerInviteDeliveryApi(
  request: APIRequestContext,
  body: InviteDeliveryRequestBody,
  opts: {
    origin: string;
    destination?: string;
    server?: SolandKey;
  },
) {
  const response = await rawSubmitPeerInviteDeliveryApi(request, body, opts);
  return await expectJsonOk<{
    status: "accepted" | "duplicate" | "deferred";
    received_at?: string;
    retry_after_ms?: number;
  }>(response, "submit peer invite delivery");
}

export async function rawSubmitPeerInviteDeliveryApi(
  request: APIRequestContext,
  body: InviteDeliveryRequestBody,
  opts: {
    origin: string;
    destination?: string;
    server?: SolandKey;
  },
) {
  const destination =
    opts.destination ?? body.invite_address.recipient_service_did;
  const url = `${solandBaseUrl(opts.server)}/_cokret/peer/invites`;
  return await request.post(url, {
    data: canonicalJson(body),
    headers: signedFederationPushHeaders(opts.origin, destination, url, body),
  });
}

function federationEventWireBody(
  event: Record<string, unknown>,
): Record<string, unknown> {
  return stripUndefined(event) as Record<string, unknown>;
}

export async function queryPeerEventsApi(
  request: APIRequestContext,
  opts: {
    server?: SolandKey;
    realmId?: string;
    actorDid?: string;
    limit?: number;
    after?: string;
    sourceDid?: string;
  },
) {
  const params = new URLSearchParams({
    limit: String(opts.limit ?? 100),
  });
  if (opts.realmId) {
    params.set("realms", opts.realmId);
  }
  if (opts.actorDid) {
    params.set("actors", opts.actorDid);
  }
  if (opts.after) {
    params.set("after", opts.after);
  }
  const targetUri = `${solandBaseUrl(opts.server)}/_cokret/peer/events?${params.toString()}`;
  const response = await request.get(targetUri, {
    headers: peerGetHeaders(opts.sourceDid, solandServiceDid(opts.server), targetUri),
  });
  return await expectJsonOk<{
    events: Array<Record<string, unknown>>;
    next_cursor?: string;
    prev_cursor?: string;
    has_more?: boolean;
  }>(response, "query peer events");
}

export async function peerEventFrontierApi(
  request: APIRequestContext,
  realmId: string,
  opts: { server?: SolandKey; sourceDid?: string } = {},
) {
  const targetUri = `${solandBaseUrl(opts.server)}/_cokret/peer/events/frontier?realm_id=${encodeURIComponent(realmId)}`;
  const response = await request.get(targetUri, {
    headers: peerGetHeaders(opts.sourceDid, solandServiceDid(opts.server), targetUri),
  });
  return await expectJsonOk<{
    realm_id: string;
    heads: string[];
    frontier_root: string;
    actor_seq_upper_bounds?: Record<string, number>;
  }>(response, "peer event frontier");
}

function schemaIdForEventKind(kind: string): string {
  if (kind === "ck.message.create") {
    return "ck.schema.message.v1";
  }
  if (kind === "ck.message.redact") {
    return "ck.schema.message.v1";
  }
  if (kind === "ck.member.state") {
    return "ck.schema.event_payload.v1";
  }
  if (kind.startsWith("ck.space.")) {
    return "ck.schema.space.v1";
  }
  return "ck.schema.event.v1";
}

// ── Federation reducer profile digest ───────────────────────────────────────
// Spec: cokret-spec/spec/v1/zh/sync/federation.md §4.1.1 (normative). The only
// machine-readable source for service_binding_ref.reducer_profile_digest is
// spec/v1/artifacts/registry/reducer-profile-registry.json: resolve the row
// whose profile_id equals the Realm's declared reducer profile and hash ONLY
// that row's digest_input object (Cokret canonical JSON → sha256 lowercase
// hex). Registered vector: ck.vector.federation.reducer_profile_digest.v1
// (federation-fixture.json case reducer_profile_digest_federation_minimal),
// used below as a drift guard on the computed value.

// helpers → e2e → cotest → cokret root → cokret-spec/spec/v1/artifacts.
const SPEC_ARTIFACTS_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "cokret-spec",
  "spec",
  "v1",
  "artifacts",
);
const E2E_FIXTURES_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "fixtures");

// The reducer profile soland declares for its federation surface
// (ck.peer.events.query.describe → supported_profiles), also the vector's profile.
export const FEDERATION_REDUCER_PROFILE_ID = "ck.profile.federation_minimal.v1";

const reducerProfileDigestCache = new Map<string, string>();

export function reducerProfileDigest(profileId: string): string {
  const cached = reducerProfileDigestCache.get(profileId);
  if (cached) {
    return cached;
  }
  const registry = JSON.parse(
    readFileSync(
      join(SPEC_ARTIFACTS_ROOT, "registry", "reducer-profile-registry.json"),
      "utf8",
    ),
  ) as {
    canonicalization?: string;
    digest_suite?: string;
    profiles?: Array<{
      profile_id?: string;
      status?: string;
      digest_input?: unknown;
    }>;
  };
  // federation.md §4.1.1 fail-closed preconditions.
  if (
    registry.canonicalization !== "json_jcs" ||
    registry.digest_suite !== "sha256"
  ) {
    throw new Error(
      "reducer-profile-registry canonicalization/digest_suite unsupported; fail closed",
    );
  }
  const row = (registry.profiles ?? []).find(
    (profile) => profile.profile_id === profileId,
  );
  if (!row || row.status !== "active" || row.digest_input === undefined) {
    throw new Error(
      `reducer profile ${profileId} has no active reducer-profile-registry row; fail closed`,
    );
  }
  const digest = `sha256:${sha256CanonicalJson(row.digest_input)}`;
  assertReducerProfileDigestMatchesVectors(profileId, digest, registry);
  reducerProfileDigestCache.set(profileId, digest);
  return digest;
}

let principalControlRealmVectorsChecked = false;

function assertPrincipalControlRealmVectors(did: string, realmId: string): void {
  const fixture = JSON.parse(
    readFileSync(
      join(E2E_FIXTURES_ROOT, "principal-control-realm-vectors.json"),
      "utf8",
    ),
  ) as {
    vectors?: Array<{
      principal_id?: string;
      principal_control_realm_id?: string;
    }>;
  };
  const vectors = fixture.vectors ?? [];
  if (!principalControlRealmVectorsChecked) {
    for (const vector of vectors) {
      if (!vector.principal_id || !vector.principal_control_realm_id) {
        throw new Error("principal-control-realm-vectors.json contains an incomplete vector");
      }
      const actual = derivePrincipalControlRealmForDid(vector.principal_id);
      if (actual !== vector.principal_control_realm_id) {
        throw new Error(
          `principal_control_realm_id ${actual} drifted from vector ${vector.principal_control_realm_id} for ${vector.principal_id}`,
        );
      }
    }
    principalControlRealmVectorsChecked = true;
  }
  const pinned = vectors.find((vector) => vector.principal_id === did);
  if (pinned?.principal_control_realm_id && pinned.principal_control_realm_id !== realmId) {
    throw new Error(
      `principal_control_realm_id ${realmId} drifted from pinned vector ${pinned.principal_control_realm_id} for ${did}`,
    );
  }
}

let reducerProfileVectorsChecked = false;

function assertReducerProfileDigestMatchesVectors(
  profileId: string,
  digest: string,
  registry: {
    profiles?: Array<{
      profile_id?: string;
      status?: string;
      digest_input?: unknown;
    }>;
  },
): void {
  const fixture = JSON.parse(
    readFileSync(
      join(E2E_FIXTURES_ROOT, "reducer-profile-digest-vectors.json"),
      "utf8",
    ),
  ) as { vectors?: Array<{ profile_id?: string; expected_digest?: string }> };
  const vectors = new Map(
    (fixture.vectors ?? []).map((entry) => [entry.profile_id, entry.expected_digest]),
  );
  const expected = vectors.get(profileId);
  if (!expected) {
    throw new Error(
      `reducer-profile-digest-vectors.json lacks a vector for ${profileId}`,
    );
  }
  if (expected !== digest) {
    throw new Error(
      `computed reducer_profile_digest ${digest} drifted from vector ${expected} for ${profileId}`,
    );
  }
  if (reducerProfileVectorsChecked) {
    return;
  }
  for (const row of registry.profiles ?? []) {
    if (row.status !== "active") {
      continue;
    }
    if (!row.profile_id || row.digest_input === undefined) {
      throw new Error("reducer-profile-registry contains an incomplete active profile");
    }
    const rowExpected = vectors.get(row.profile_id);
    if (!rowExpected) {
      throw new Error(
        `reducer-profile-digest-vectors.json lacks an active profile vector for ${row.profile_id}`,
      );
    }
    const actual = `sha256:${sha256CanonicalJson(row.digest_input)}`;
    if (actual !== rowExpected) {
      throw new Error(
        `active reducer profile ${row.profile_id} digest ${actual} drifted from vector ${rowExpected}`,
      );
    }
  }
  reducerProfileVectorsChecked = true;
}

// federation.md §4.1: membership_frontier / delivery_binding_frontier are the
// sender's causal frontiers (`id[]`). The harness acts as the origin peer of a
// fabricated realm whose entire causal history is the submitted batch, so the
// frontier is the batch's head event ids (events no other batch event
// references via prev_refs).
function batchFrontierEventIds(
  events: Array<Record<string, unknown>>,
): string[] {
  const referenced = new Set<string>();
  for (const event of events) {
    const prevRefs = Array.isArray(event.prev_refs) ? event.prev_refs : [];
    for (const entry of prevRefs) {
      if (typeof entry === "string") {
        referenced.add(entry);
      } else if (entry && typeof entry === "object") {
        const id = (entry as Record<string, unknown>).event_id;
        if (typeof id === "string") {
          referenced.add(id);
        }
      }
    }
  }
  const heads = events
    .map((event) => event.event_id)
    .filter(
      (id): id is string => typeof id === "string" && !referenced.has(id),
    );
  return heads.length > 0 ? heads : [typedId("event")];
}

function peerEventsSubmitBody(
  realmId: string,
  events: Array<Record<string, unknown>>,
  idempotencyKey?: string,
  overrides: { reducerProfileDigest?: string } = {},
): Record<string, unknown> {
  const frontier = batchFrontierEventIds(events);
  return stripUndefined({
    service_binding_ref: {
      realm_id: realmId,
      // Spec v1 registers no computation vector for realm_policy_digest (it
      // is the sender-local "Realm policy hash", federation.md §4.1 table);
      // hash an explicitly harness-scoped policy snapshot so the value can
      // never be mistaken for a spec identifier.
      realm_policy_digest: `sha256:${sha256CanonicalJson({
        domain: "cotest.harness.realm_policy_snapshot.v1",
        realm_id: realmId,
      })}`,
      membership_frontier: frontier,
      delivery_binding_frontier: frontier,
      destination_service_type: "principal_server",
      // §4.1.1 registry-derived canonical digest (override only exists for
      // the reducer_profile_mismatch negative case).
      reducer_profile_digest:
        overrides.reducerProfileDigest ??
        reducerProfileDigest(FEDERATION_REDUCER_PROFILE_ID),
    },
    events,
    idempotency_key: idempotencyKey,
  }) as Record<string, unknown>;
}

function peerGetHeaders(
  sourceDid = "did:web:cotest-peer.example",
  destinationDid: string,
  targetUri: string,
): Record<string, string> {
  const sourceTrustDomain = trustDomainFromServiceDid(sourceDid);
  const destinationTrustDomain = trustDomainFromServiceDid(destinationDid);
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 300;
  const keyid = `${sourceDid}#federation-fanout-key`;
  const signatureParams =
    `("@method" "@target-uri" "@authority" "source-service-did" ` +
    `"destination-service-did" "source-trust-domain" "destination-trust-domain");` +
    `created=${created};expires=${expires};keyid="${keyid}";alg="ed25519"`;
  const signatureBase = [
    `"@method": GET`,
    `"@target-uri": ${targetUri}`,
    `"@authority": ${new URL(targetUri).host}`,
    `"source-service-did": ${sourceDid}`,
    `"destination-service-did": ${destinationDid}`,
    `"source-trust-domain": ${sourceTrustDomain}`,
    `"destination-trust-domain": ${destinationTrustDomain}`,
    `"@signature-params": ${signatureParams}`,
  ].join("\n");
  const signature = sign(
    null,
    Buffer.from(signatureBase, "utf8"),
    developmentServicePrivateKey(sourceDid),
  );
  return {
    "source-service-did": sourceDid,
    "destination-service-did": destinationDid,
    "source-trust-domain": sourceTrustDomain,
    "destination-trust-domain": destinationTrustDomain,
    "signature-input": `sig1=${signatureParams}`,
    signature: `sig1=:${signature.toString("base64")}:`,
  };
}

function signedFederationPushHeaders(
  sourceDid: string,
  destinationDid: string,
  targetUri: string,
  body: unknown,
): Record<string, string> {
  const bodyBytes = Buffer.from(canonicalJson(body), "utf8");
  const contentDigest = `sha-256=:${createHash("sha256").update(bodyBytes).digest("base64")}:`;
  const requestDigest = `sha256:${createHash("sha256").update(bodyBytes).digest("hex")}`;
  const sourceTrustDomain = trustDomainFromServiceDid(sourceDid);
  const destinationTrustDomain = trustDomainFromServiceDid(destinationDid);
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 300;
  const keyid = `${sourceDid}#federation-fanout-key`;
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" "source-service-did" ` +
    `"destination-service-did" "source-trust-domain" "destination-trust-domain" ` +
    `"request-canonical-digest");created=${created};expires=${expires};keyid="${keyid}";alg="ed25519"`;
  const signatureBase = [
    `"@method": POST`,
    `"@target-uri": ${targetUri}`,
    `"@authority": ${new URL(targetUri).host}`,
    `"content-digest": ${contentDigest}`,
    `"source-service-did": ${sourceDid}`,
    `"destination-service-did": ${destinationDid}`,
    `"source-trust-domain": ${sourceTrustDomain}`,
    `"destination-trust-domain": ${destinationTrustDomain}`,
    `"request-canonical-digest": ${requestDigest}`,
    `"@signature-params": ${signatureParams}`,
  ].join("\n");
  const signature = sign(
    null,
    Buffer.from(signatureBase, "utf8"),
    developmentServicePrivateKey(sourceDid),
  );
  return {
    "content-type": "application/json",
    "content-digest": contentDigest,
    "request-canonical-digest": requestDigest,
    "source-service-did": sourceDid,
    "destination-service-did": destinationDid,
    "source-trust-domain": sourceTrustDomain,
    "destination-trust-domain": destinationTrustDomain,
    "signature-input": `sig1=${signatureParams}`,
    signature: `sig1=:${signature.toString("base64")}:`,
  };
}

function eventProofMode(): EventProofMode {
  const mode = process.env.COTEST_EVENT_PROOF_MODE ?? "detached-jws";
  if (mode !== "dev-proof" && mode !== "detached-jws") {
    throw new Error(
      `unsupported COTEST_EVENT_PROOF_MODE=${JSON.stringify(mode)}; expected dev-proof or detached-jws`,
    );
  }
  if (mode === "dev-proof" && process.env.COTEST_FORBID_DEV_PROOF === "1") {
    throw new Error(
      "COTEST_FORBID_DEV_PROOF=1 forbids the legacy dev-proof fixture; set COTEST_EVENT_PROOF_MODE=detached-jws",
    );
  }
  return mode;
}

function detachedJwsFixture(args: {
  actorDid: string;
  verificationMethod: string;
  eventDigest: string;
  createdAt: string;
}): string {
  const protectedHeader = base64urlJson({
    alg: "EdDSA",
    kid: args.verificationMethod,
    typ: "ck-event-proof+jws",
  });
  const payload = base64urlJson({
    actor_id: args.actorDid,
    created_at: args.createdAt,
    event_digest: args.eventDigest,
    verification_method: args.verificationMethod,
  });
  const signature = sign(
    null,
    Buffer.from(`${protectedHeader}.${payload}`, "utf8"),
    developmentServicePrivateKey(args.actorDid),
  );
  return `${protectedHeader}..${signature.toString("base64url")}`;
}

function base64urlJson(value: unknown): string {
  return Buffer.from(canonicalJson(value), "utf8").toString("base64url");
}

// FIXTURE ONLY — publicly derivable, MUST NOT be trusted by any non-test code.
// The private key is `sha256("soland:anchorer-ephemeral:" + serviceDid)`, so
// anyone who knows the serviceDid can recompute it. This intentionally mirrors
// soland's *dev* anchorer-ephemeral derivation (soland: federation.rs /
// state.rs) so the mock's federation signatures verify against a dev soland —
// production soland MUST reject keys produced by this convention.
function developmentServicePrivateKey(serviceDid: string) {
  const seed = createHash("sha256")
    .update("soland:anchorer-ephemeral:")
    .update(serviceDid)
    .digest();
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function trustDomainFromServiceDid(serviceDid: string): string {
  const scope = serviceDid
    .replace(/^did:(web|key|webvh):/, "")
    .toLowerCase()
    .replace(/:/g, ".");
  return `ck:trust_domain:${scope || "local"}`;
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

// Canonical JSON gate for e2e signing/hash fixtures. This intentionally rejects
// values outside the Cokret canonical profile instead of silently producing a
// digest for non-canonical JavaScript data.
export function sha256CanonicalJson(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function canonicalJson(value: unknown): string {
  return canonicalJsonValue(value, "$");
}

function canonicalJsonValue(value: unknown, path: string): string {
  if (value === null) {
    return "null";
  }
  switch (typeof value) {
    case "string":
      assertCanonicalString(value, path);
      return JSON.stringify(value);
    case "number":
      assertCanonicalNumber(value, path);
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "object":
      break;
    default:
      throw new TypeError(`non-canonical JSON value at ${path}: ${typeof value}`);
  }

  if (Array.isArray(value)) {
    return `[${value
      .map((item, index) => canonicalJsonValue(item, `${path}[${index}]`))
      .join(",")}]`;
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError(`non-canonical JSON object at ${path}`);
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort(compareJsonKeys)
    .map((key) => {
      assertCanonicalString(key, `${path}.${key}`);
      if (record[key] === undefined) {
        throw new TypeError(`non-canonical undefined member at ${path}.${key}`);
      }
      return `${JSON.stringify(key)}:${canonicalJsonValue(record[key], `${path}.${key}`)}`;
    })
    .join(",")}}`;
}

function compareJsonKeys(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function assertCanonicalString(value: string, path: string): void {
  if (value.includes("\uFEFF")) {
    throw new TypeError(`non-canonical BOM in string at ${path}`);
  }
  if (value.normalize("NFC") !== value) {
    throw new TypeError(`non-canonical non-NFC string at ${path}`);
  }
}

function assertCanonicalNumber(value: number, path: string): void {
  if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
    throw new TypeError(`non-canonical number at ${path}: ${value}`);
  }
}

function stripUndefined(value: unknown): unknown {
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

export function uuidV7(): string {
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

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes,
  sign,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { operationSelector } from "./arkret-test";
import {
  type SolandKey,
  configuredServerKeys,
  solandBaseUrl,
  solandServiceDid,
  solandServiceId,
  solandServiceResolution,
  teabayBaseUrl,
} from "./env";
import { base64url } from "./encoding";
import type {
  ActorId,
  InviteObject,
  CapabilityGrantObject,
  CapabilityGrantPayload,
  CommitStreamHead,
  EventAdmissionSubmission,
  InviteDeliveryRequestBody,
  RealmGenesisObject,
  RealmObject,
  SelfInviteDispatchRequestBody,
  RealmJoinPrepareRequestBody,
  MessagePrepareRequestBody,
} from "./generated/spec-wire-objects";
import {
  accountSubscribeDeltaApi,
  accountSubscribeFramesApi,
  accountSubscribeRealmFramesApi,
} from "./soland-api/account-stream";
import { activateRealmMlsApi } from "./soland-api/mls";
import {
  authHeaders,
  expectJsonOk,
  registerRequestAuth,
  wireErrCode,
} from "./soland-api/request";
import {
  base64urlJsonCanonical,
  base64urlJsonRaw,
  canonicalBytes,
  canonicalJson,
  cotestWire,
  sdkEventDerivedIds,
  sdkEventDerivedObjectId,
  sdkEventEnvelopeProof,
  sdkMimiConsentProof,
  sdkMimiRequestConsentProof,
  sha256CanonicalJson,
  stripUndefined,
} from "./soland-api/wire-client";

export {
  accountSubscribeDeltaApi,
  accountSubscribeFramesApi,
  accountSubscribeRealmFramesApi,
  authHeaders,
  base64urlJsonCanonical,
  base64urlJsonRaw,
  canonicalBytes,
  canonicalJson,
  cotestWire,
  expectJsonOk,
  registerRequestAuth,
  sdkEventDerivedIds,
  sdkEventDerivedObjectId,
  sdkEventEnvelopeProof,
  sdkMimiConsentProof,
  sdkMimiRequestConsentProof,
  sha256CanonicalJson,
  wireErrCode,
};
type SignedEventEnvelopeArgs = {
  actorId: string | ActorId;
  realmId: string;
  kind: string;
  payload: Record<string, unknown>;
  createdAt?: string;
  eventId?: string;
  proofVerificationMethod?: string;
  semanticRefs?: Array<Record<string, unknown>>;
  scopeRef?: Record<string, unknown>;
  authorizationRef?: string;
  executedBy?: ActorId;
  appletId?: string;
  /// The Station coordinate of the Event's account Actor. It is nested in
  /// actor_id.account_id, never an independent Event envelope member.
  stationId?: string;
  server?: SolandKey;
};
type EventProofMode = "dev-proof" | "detached-jws";

type RegisteredEventSigner = {
  deviceId: string;
  verificationMethod: string;
  signingSeedB64url?: string;
  /// A sibling device paired after the founding device signs only when a
  /// caller names its verification method; it never becomes the implicit
  /// signer of its actor.
  explicitOnly: boolean;
};

const registeredEventSigners = new Map<
  string,
  Map<string, RegisteredEventSigner>
>();
const realmAuthorityControllers = new Map<string, ActorId>();
const principalControlEvents = new Map<
  string,
  Array<Record<string, unknown>>
>();

// capabilities.md §3.2 — the only Realm authority source an operational
// authorization may resolve against. It is now an ordinary reference to the
// accepted Realm-genesis Event, so a Realm the harness did not author itself
// simply has no entry here and its Events carry no root claim.
const realmAuthorityRootEventIds = new Map<string, string>();

export function realmAuthorityRootRef(
  server: SolandKey | undefined,
  realmId: string,
): string | undefined {
  return realmAuthorityRootEventIds.get(
    realmAuthorityControllerKey(server, realmId),
  );
}

function requireRealmAuthorityRootRef(
  server: SolandKey | undefined,
  realmId: string,
): string {
  const eventId = realmAuthorityRootRef(server, realmId);
  if (!eventId) {
    throw new Error("capability grant requires an accepted Realm genesis reference");
  }
  return eventId;
}

async function discoverRealmAuthorityRootRef(
  request: APIRequestContext,
  token: string,
  realmId: string,
  server?: SolandKey,
): Promise<void> {
  if (realmAuthorityRootRef(server, realmId)) return;
  const { events, commits } = await scanRealmStreamApi(request, token, realmId, {
    server,
    limit: 1,
  });
  const genesis = events[0];
  const commit = commits[0];
  if (!genesis || !commit) {
    throw new Error("capability grant cannot resolve accepted Realm genesis");
  }
  expect(genesis.kind).toBe("ak.realm.create");
  expect(sdkEventDerivedIds(genesis).realm_id).toBe(realmId);
  expect(commit.realm_id).toBe(realmId);
  expect(commit.stream_position).toBe(0);
  assertAuthoritySubmitOutcome({ status: "committed", commit }, genesis,
    "resolve capability grant Realm genesis");
  const eventId = stringValue(genesis.event_id);
  expect(eventId && retypeEventDerivedId(eventId, "realm")).toBe(realmId);
  realmAuthorityRootEventIds.set(realmAuthorityControllerKey(server, realmId), eventId!);
}

function realmAuthorityControllerKey(
  server: SolandKey | undefined,
  realmId: string,
): string {
  return `${server ?? "default"}\0${realmId}`;
}

/**
 * Register the real browser device signer for direct API events emitted by the
 * same test actor. This keeps the event-key lifecycle separate from DPoP while
 * ensuring both submission paths produce a proof for the authorized device.
 */
export function registerEventSigner(args: {
  actorId: string;
  deviceId: string;
  verificationMethod: string;
  signingSeedB64url?: string;
  explicitOnly?: boolean;
}): void {
  const actorId = requireDidCoreId(args.actorId);
  if (!args.verificationMethod.endsWith(`#${args.deviceId}`)) {
    throw new Error(
      `event signer verification method does not name device ${args.deviceId}`,
    );
  }
  const byMethod = registeredEventSigners.get(actorId) ?? new Map();
  const previous = byMethod.get(args.verificationMethod);
  const signer = {
    deviceId: args.deviceId,
    verificationMethod: args.verificationMethod,
    // A seed-less re-registration (e.g. dev-login after the canonical
    // provisioning already registered the real device signer) must not clobber
    // the seed of an existing registration for the same verification method.
    signingSeedB64url:
      args.signingSeedB64url ??
      (previous?.verificationMethod === args.verificationMethod
        ? previous.signingSeedB64url
        : undefined),
    explicitOnly: args.explicitOnly ?? previous?.explicitOnly ?? false,
  };
  byMethod.set(args.verificationMethod, signer);
  registeredEventSigners.set(actorId, byMethod);
}

function eventSignerFor(
  actorId: string,
  requestedVerificationMethod?: string,
): RegisteredEventSigner | undefined {
  const byMethod = registeredEventSigners.get(actorId);
  if (!byMethod) {
    return undefined;
  }
  if (requestedVerificationMethod !== undefined) {
    return byMethod.get(requestedVerificationMethod);
  }
  const implicit = [...byMethod.values()].filter((signer) => !signer.explicitOnly);
  return implicit.length === 1 ? implicit[0] : undefined;
}

export function registeredEventVerificationMethod(
  actorId: string,
  deviceId?: string,
): string | undefined {
  const byMethod = registeredEventSigners.get(actorId);
  const signer = deviceId
    ? [...(byMethod?.values() ?? [])].find(
        (candidate) => candidate.deviceId === deviceId,
      )
    : eventSignerFor(actorId);
  if (!signer) {
    return undefined;
  }
  if (!deviceId || signer.deviceId === deviceId) {
    return signer.verificationMethod;
  }
  return undefined;
}

export function registeredEventSigningSeedB64url(
  actorId: string,
  verificationMethod?: string,
): string | undefined {
  return eventSignerFor(actorId, verificationMethod)?.signingSeedB64url;
}

export function signWithRegisteredEventSigner(
  actorId: string,
  verificationMethod: string,
  signingInput: string,
): string | undefined {
  const registered = eventSignerFor(actorId, verificationMethod);
  if (!registered) {
    return undefined;
  }
  if (!registered.signingSeedB64url) {
    return undefined;
  }
  const seed = Buffer.from(registered.signingSeedB64url, "base64url");
  if (seed.length !== 32) {
    throw new Error("registered event signing seed must decode to 32 bytes");
  }
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
  return sign(null, Buffer.from(signingInput, "utf8"), privateKey).toString(
    "base64url",
  );
}

// Frozen full-token coordinates for negative/mock cases that have no accepted
// create Event to consume. They are intentionally finite: callers must not
// fall back to UUID minting or reuse an identity after the pool is exhausted.
const EVENT_DERIVED_FIXTURE_TOKEN_BODIES = [
  "Aa90z7xF10veB5kq69MWxtT48QQlzCdhmmbskzElVa5p",
  "AaaV5G8rACWz0A_AfDNtAvW_ConNcll4oFZ_LaD4uJgJ",
  "AaBHX3lRc1CFrtax_a7-AMM-ykNvbGptE-rF2rMhJHpk",
  "AaeZ8deENFbCUflsuaJ26bhcritF3A0DEiAgV3VXl2oZ",
  "AafiSe5-0DLIzxypKeEYStsz0tPrLS0bvyfdfmJHrGtZ",
  "AaFkuSVtHcmpSTwun3O77ySLPpa7WleqRUq8Stzi_0WZ",
  "AagGd6PB1SqZp__DzubMh3BTpUU-oWosY3NoR_k38pxq",
  "AaIU5-FloksbTF8lIRYIpxdzmtMlKw6ZQ46eU2SAH2-4",
  "AaJxiT8EaaLu-lpzPZYBhPCfcKggB0wZGeXncuADY8UV",
  "AamoRNGFU65QceSF_1sOMBzEncXa6v055qULEAVWcDYs",
  "AamYARiCCubbYQ3GoHbppXPhsNkI0kDOZQi17eTRhQ94",
  "AaT867J_6iZXViVxSlPnsRXFVJ3T8aNB8AB93oRyOx5J",
  "Aau0Y6KyQiOs0dkWoG9aKzqocxoClsKqFs3t1Yt3-snC",
  "Aay8a3LT8Kuk87okmFQYB95EV3mcCNn7hip788Ke0rZs",
  "Ab_ETJ_SYwARfEbvgIqRR8Q-l8kS3rwWRFVQd2C6aHE_",
  "Ab1ksa-umr9kNJE_n2EEj6AVhUsqM_Xml_hJgWyMpwq8",
  "Ab1wW6h5QnGMlhhFi-yxg6txnBC4jwSBbzmiKBpMOfTO",
  "Ab2pkzspV8u_ui9GZc5DlrHR35Zu9b0zIqAMaJOju1hx",
  "Ab8fF-_JIKTb1BX6GXVZLOEoeeVFftSuQTq3Y8wtAvJT",
  "Ab9hGz5-hIWYOFjFTtAHrFUC3voDLMSPQRaQvtRQEO3-",
  "AbAWvgHwDMsvHp-83ayUI2TKbLu45n6bfQhAgod9_Q_P",
  "AbFb45zjGe7948bxdQ_XQkZemaqYwlxOtGBoKt9Sd2cW",
  "AbhlmtxK_Ztvb71Puy1rF1R7yQqMvSbBLqxVlKPuP49y",
  "AbLdslMbLh-jujIabWk8ckX47W1Lu1IEgMvZ3Ahiz1dm",
  "AbLUaNO9m_tRCJn4qAM03Ym0bFcN-oRmeEHjTinQpPUu",
  "AbmZo_Q7CHRfJYVqari3NAaEZm6tfSbZppTL7IsJJ7Gl",
  "AboOf819TDn4X36iZWtVada6Ett2u_Oy_8F9XJDxA0gm",
  "AbTJRA159xoBFUoYTOIMDQve32eQFpWkEb-dThX1wCmA",
  "AbvcNWSd5e4klWqpBg898thvN1RK57j6lqpZDeC83zBZ",
  "AbyX-ijAQZ4DkcySKE3VusrcCoBFT8DGS4fx8tpo-PNm",
  "Ac0RSITUWs2Ftqgb902qaA5SlygUXgX0yAce_06OOjek",
  "Ac7Jx0nM91NkaWFhRqF0fyU9p6cslo0kWgavyrWTViZS",
] as const;
let eventDerivedFixtureCursor = 0;

export function typedId(kind: string): string {
  if (
    [
      "actor_profile",
      "audit_binding",
      "audit_session",
      "audit_release",
      "call",
      "circle",
      "sidecar",
      "strand",
      "event",
      "grant",
      "invite",
      "message",
      "morph",
      "relation",
      "report",
      "moderation_queue_item",
      "space",
      "realm",
      "view",
    ].includes(kind)
  ) {
    const token = EVENT_DERIVED_FIXTURE_TOKEN_BODIES[eventDerivedFixtureCursor];
    if (!token) {
      throw new Error(
        `event-derived fixture token pool exhausted at ${eventDerivedFixtureCursor}`,
      );
    }
    eventDerivedFixtureCursor += 1;
    return `ak:${kind}:${token}`;
  }
  return `ak:${kind}:${uuidV7()}`;
}

export function retypeEventDerivedId(eventId: string, kind: string): string {
  if (!eventId.startsWith("ak:event:")) {
    throw new Error(`cannot retype non-Event id ${eventId}`);
  }
  return `ak:${kind}:${eventId.slice("ak:event:".length)}`;
}

const acceptedPrincipalControlRealms = new Map<string, string>();

export function registerPrincipalControlRealm(
  principalId: string,
  realmId: string,
): void {
  requireDidCoreId(principalId);
  const previous = acceptedPrincipalControlRealms.get(principalId);
  if (previous && previous !== realmId) {
    throw new Error(
      `principal ${principalId} was bound to two different PCR ids`,
    );
  }
  acceptedPrincipalControlRealms.set(principalId, realmId);
}

export function registerPrincipalControlEvents(
  principalId: string,
  events: Array<Record<string, unknown>>,
): void {
  principalControlEvents.set(
    requireDidCoreId(principalId),
    events.map(
      (event) => JSON.parse(canonicalJson(event)) as Record<string, unknown>,
    ),
  );
}

export function principalControlRealmForId(principalId: string): string {
  requireDidCoreId(principalId);
  const realmId = principalControlRealmForIdIfKnown(principalId);
  if (!realmId) {
    throw new Error(
      `event-derived PCR id for ${principalId} is unavailable; register its accepted create Event first`,
    );
  }
  return realmId;
}

export function principalControlRootAuthorizationRefForId(principalId: string): string {
  const events = principalControlEvents.get(requireDidCoreId(principalId));
  const create = events?.[0];
  if (create?.kind !== "ak.realm.create" || typeof create.event_id !== "string") {
    throw new Error(`accepted PCR root Event for ${principalId} is unavailable`);
  }
  return create.event_id;
}

function principalControlRealmForIdIfKnown(
  principalId: string,
): string | undefined {
  return acceptedPrincipalControlRealms.get(requireDidCoreId(principalId));
}

// Re-exported authoritative base64url encoder (single source: encoding.ts).
export { base64url };

export function projectDidToCoreId(did: string): string {
  if (did.startsWith("did:webvh:")) {
    const [scid] = did.slice("did:webvh:".length).split(":", 1);
    if (!scid) {
      throw new Error(`invalid did:webvh notary DID: ${did}`);
    }
    return `ak:did_core:webvh:${scid}`;
  }
  if (did.startsWith("did:web:")) {
    return `ak:did_core:web:${did.slice("did:web:".length)}`;
  }
  if (did.startsWith("did:key:")) {
    return `ak:did_core:key:${did.slice("did:key:".length)}`;
  }
  throw new Error(`unsupported notary DID method: ${did}`);
}

export function requireDidCoreId(id: string): string {
  if (!id.startsWith("ak:did_core:")) {
    throw new Error(`expected Arkret did_core_id: ${id}`);
  }
  return id;
}

export function accountActorId(
  principalId: string,
  server?: SolandKey,
  stationId?: string,
): Extract<ActorId, { kind: "account" }> {
  return {
    kind: "account",
    account_id: {
      principal_id: requireDidCoreId(principalId),
      station_id: requireDidCoreId(stationId ?? solandServiceId(server)),
    },
  };
}

/// Canonical composite cell subject: `base64url_nopad(sha256(canonical_json([...])))`
/// over the components in the order the family's `cell_subject` declares
/// (encoding.md section 9.5).
export function compositeCellSubject(parts: unknown[]): string {
  return createHash("sha256").update(canonicalJson(parts), "utf8").digest(
    "base64url",
  );
}

/// The Realm live-target slot for one invitee account.
///
/// governance-objects.md section 5.3: the subject is the single-component
/// canonical_json composite over `payload.invitee_account_id` and carries no
/// `realm_id` — the cell is already located by the Event envelope's Realm.
export function inviteLiveTargetCell(
  accountId: Record<string, unknown>,
): string {
  const subject = compositeCellSubject([canonicalJson(accountId)]);
  return `ak:cell:ak.component.invite.live_target.v1:${subject}`;
}

export function serviceActorId(serviceId: string): ActorId {
  return { kind: "service", service_id: requireDidCoreId(serviceId) };
}

/** Read the canonical Actor without accepting the retired scalar envelope. */
function eventActorId(
  event: Record<string, unknown>,
): ActorId {
  const actor = event.actor_id as ActorId | undefined;
  if (actor?.kind === "account" && actor.account_id) {
    requireDidCoreId(actor.account_id.principal_id);
    requireDidCoreId(actor.account_id.station_id);
    return actor;
  }
  if (actor?.kind === "service") {
    requireDidCoreId(actor.service_id);
    return actor;
  }
  throw new Error("Event envelope requires a complete account or service actor_id");
}

export function eventPrincipalId(event: Record<string, unknown>): string {
  const actor = eventActorId(event);
  return actor.kind === "account" ? actor.account_id.principal_id : actor.service_id;
}
function eventSigningPrincipalId(event: Record<string, unknown>): string {
  return eventPrincipalId({ actor_id: event.executed_by ?? event.actor_id });
}

// Default stand-in federation source for helpers that do not impersonate one
// of the configured local servers. Aligned with the typed
// `ProvisionedTestPrincipal` bootstrap: did:webvh is the v1 core default
// service method (identity-did.md) and did:web is reserved for explicit
// no-history / negative fixtures, so the retired `did:web:cotest-peer.example`
// default no longer resolves. The `source-service-id` header carries the
// projected core id (soland parses it as a `DidCoreId`); the Signature-Input
// keyid must be the DID URL whose controller projects back to it.
const COTEST_PEER_FIXTURE_DID = "did:webvh:z6mkpeer:cotest-peer.example";
const COTEST_PEER_FIXTURE_CORE_ID = projectDidToCoreId(
  COTEST_PEER_FIXTURE_DID,
);

// Inverse spelling of projectDidToCoreId for harness-synthetic services:
// a federation Signature-Input keyid must be a DID URL whose controller
// projects to the Source-Service-ID core id (soland federation signature.rs
// validate_signature_input), even though the header itself carries the core
// id. Only the did:web adapter and the named did:webvh fixtures have a unique
// inverse spelling.
function serviceCoreIdToDid(serviceId: string): string {
  if (serviceId.startsWith("ak:did_core:web:")) {
    return `did:web:${serviceId.slice("ak:did_core:web:".length)}`;
  }
  if (serviceId === COTEST_PEER_FIXTURE_CORE_ID) {
    return COTEST_PEER_FIXTURE_DID;
  }
  throw new Error(`no fixture DID is registered for service id ${serviceId}`);
}

export function plaintextVisibleServiceDeclarations(serviceIds: string[]) {
  return Array.from(
    new Set(serviceIds.map((service) => service.trim()).filter(Boolean)),
  ).map((serviceId) => ({
    service_id: requireDidCoreId(serviceId),
    service_kind: "station",
    data_classes: [
      "message_content",
      "attachment_plaintext",
      "attachment_preview",
      "thumbnail",
      "full_text_index",
      "notification_summary",
      "inbox_preview",
    ],
    purposes: [
      "message_index",
      "attachment_download",
      "notification_fanout",
      "inbox_preview",
    ],
    visibility: "private_plaintext",
  }));
}

// `identity-resolution.schema.json#/$defs/service_resolution_carrier` pins
// `resolution_url` to `https://`, and invite-addressing.md §6 requires the
// durable `invite_delivery_target.service_resolution` and the delivery
// `invite_address.service_resolution` to be byte-for-byte equal (§7 step 6
// re-checks it on the receiving side). Both producers therefore go through this
// single normalizer instead of hand-rolling the scheme per call site.
export function canonicalServiceResolution(server?: SolandKey): {
  resolution_url: string;
} {
  const { resolution_url } = solandServiceResolution(server);
  return {
    resolution_url: resolution_url.replace(/^http:\/\//, "https://"),
  };
}

export type AcceptedRealmBootstrap = {
  events: Array<Record<string, unknown>>;
  submission: Record<string, unknown>;
  outcome: Record<string, unknown>;
};

export async function createRealmApi(
  request: APIRequestContext,
  token: string,
  data: {
    title: string;
    summary?: string;
    // The policy axes are the closed `realm.schema.json` enums, not free
    // strings: a typo used to travel all the way to the server.
    discoverability?: RealmObject["default_discoverability"];
    history_access?: RealmObject["history_access"];
    /// Activate MLS for the new Realm: the owner's registered device founds
    /// the group and its `ak.mls.genesis` is accepted before any invite
    /// (`soland-api/mls.ts`). There is no declared profile to compare
    /// against: a scope is end-to-end encrypted exactly when that genesis has
    /// been accepted. Members that join afterwards need an Add Commit
    /// (`addRealmMlsMemberApi`) before new ciphertext is admitted.
    mls_activated?: boolean;
    invitees?: string[];
    /**
     * Optional home Station DID for directed invite-create events.
     * Seed-member (`ak.member.state{membership=invite}`) events intentionally
     * have no delivery target; callers exercising cross-server invite fanout
     * opt in here so the helper emits the canonical `ak.invite.create` event
     * and submits it through `ak.self.invites.command.dispatch.v1`. The
     * Station, rather than the test process, then owns the durable peer
     * delivery.
     */
    invitee_ids?: Record<string, string>;
    /**
     * Override the creator's home Station. The helper defaults this
     * to the selected Soland because the standard availability policy needs a
     * joined-member Station before any post-genesis Control Move can
     * be sealed.
     */
    creator_id?: string;
    plaintext_visible_services?: string[];
    public?: boolean;
    federation_policy?: RealmObject["federation_policy"];
    schema_refs?: RealmObject["schema_refs"];
    ownerId?: string;
    default_join_rule?: RealmObject["default_join_rule"];
    created_at?: string;
  },
  opts: {
    server?: SolandKey;
    onAcceptedBootstrap?: (bootstrap: AcceptedRealmBootstrap) => void;
  } = {},
): Promise<string> {
  const ownerId =
    data.ownerId ?? (await currentActorIdApi(request, token, opts));
  const createdAt = data.created_at ?? canonicalTimestamp();
  const plaintextVisibleServiceIds =
    data.plaintext_visible_services ??
    (data.mls_activated ? [] : [solandServiceId(opts.server)]);
  const plaintextVisibleServices = plaintextVisibleServiceDeclarations(
    plaintextVisibleServiceIds,
  );
  // Genesis declares the initial axes; the registered bootstrap also includes
  // matching typed-current facet writes in its fixed slot order.
  const realmGenesis: RealmGenesisObject = {
    schema: "ak.schema.realm_genesis.v1",
    purpose: "collaboration",
    genesis_salt: base64url(randomBytes(32)),
    trust_domain: "ak:trust_domain:soland.local",
    security_class: "standard",
    governance_station_id: solandServiceId(opts.server),
    initial_join_rule: data.default_join_rule ?? "invite",
    initial_history_access: data.history_access ?? "since_join",
    initial_discoverability:
      data.discoverability ?? (data.public ? "public" : "listed"),
  };
  const { envelope: realmCreateEvent, realmId } = signedRealmGenesisEnvelope({
    actorId: ownerId,
    server: opts.server,
    stationId: data.creator_id,
    // The genesis names no Realm; the envelope builder derives both its own id
    // and the Realm's from the finished envelope.
    realmId: "",
    kind: "ak.realm.create",
    createdAt,
    payload: {
      object: realmGenesis,
    },
  });
  // The genesis Event names itself to everything that follows, and its id is
  // derived from the envelope, so the chain can only be built afterwards.
  const bootstrapEvents = [realmCreateEvent];
  const pushBootstrapEvent = (
    kind: string,
    payload: Record<string, unknown>,
  ): void => {
    bootstrapEvents.push(
      signedEventEnvelope({
        actorId: ownerId,
        server: opts.server,
        stationId: data.creator_id,
        realmId,
        kind,
        createdAt,
        authorizationRef: stringValue(realmCreateEvent.event_id),
        payload,
      }),
    );
  };
  pushBootstrapEvent("ak.realm.profile", {
    schema: "ak.schema.realm_profile.v1",
    title: data.title,
    ...(data.summary === undefined ? {} : { summary: data.summary }),
  });
  // Whether content must be end-to-end encrypted is no longer a declared
  // profile: it follows from whether this scope has an accepted
  // `ak.mls.genesis`. The bundle therefore carries only what is still policy.
  pushBootstrapEvent("ak.realm.policy_bundle", {
    policy_revision: 1,
    federation_policy: data.federation_policy ?? "restricted",
  });
  pushBootstrapEvent("ak.realm.join_rule", {
    value: realmGenesis.initial_join_rule,
  });
  pushBootstrapEvent("ak.realm.history_access", {
    from: null,
    to: realmGenesis.initial_history_access,
  });
  pushBootstrapEvent("ak.realm.discovery", {
    value: { discoverability: realmGenesis.initial_discoverability },
  });
  if (plaintextVisibleServices.length > 0) {
    pushBootstrapEvent("ak.realm.plaintext_visible_services", {
      services: plaintextVisibleServices,
    });
  }
  const creatorServiceId =
    data.creator_id ?? solandServiceId(opts.server);
  const creatorActorId = {
    kind: "account",
    account_id: {
      principal_id: requireDidCoreId(ownerId),
      station_id: creatorServiceId,
    },
  };
  pushBootstrapEvent("ak.member.state", {
    member_id: creatorActorId,
    membership: "join",
  });

  // The registered bootstrap is one atomic request; each Event still receives
  // its own consecutive RealmCommit, with no unit-level ordering artifact.
  const submission = {
    unit_kind: "ordinary_realm_bootstrap",
    idempotency_key: uuidV7(),
    events: bootstrapEvents.map((event) => ({ event })),
  };
  const eventsUrl = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
  const response = await request.post(eventsUrl, {
    headers: {
      ...authHeaders(token, "POST", eventsUrl),
      "content-type": "application/json",
    },
    data: canonicalJson(submission),
  });
  const text = await response.text();
  expect([200, 201], `create realm ${data.title}: ${response.status()}: ${text}`)
    .toContain(response.status());
  const outcome = JSON.parse(text) as Record<string, unknown>;
  expect(outcome.unit_kind).toBe("ordinary_realm_bootstrap");
  expect(["committed", "duplicate"]).toContain(outcome.status);
  expect(Array.isArray(outcome.commits)).toBe(true);
  const commits = outcome.commits as Array<Record<string, unknown>>;
  expect(commits).toHaveLength(bootstrapEvents.length);
  for (const [index, event] of bootstrapEvents.entries()) {
    const commit = commits[index]!;
    assertAuthoritySubmitOutcome({ status: outcome.status, commit }, event,
      `create realm ${data.title} slot ${index}`);
    expect(
      commit?.stream_position,
      `realm bootstrap Event ${index} did not take Realm stream position ${index}`,
    ).toBe(index);
    const previous = commits[index - 1];
    expect(
      commit?.previous_commit_ref ?? null,
      `realm bootstrap Event ${index} does not follow its predecessor commit`,
    ).toEqual(previous ? previous.commit_id : null);
  }
  rememberPublicationEvidence(bootstrapEvents, outcome, { token, server: opts.server });
  opts.onAcceptedBootstrap?.({
    events: structuredClone(bootstrapEvents),
    submission: structuredClone(submission),
    outcome: structuredClone(outcome),
  });
  realmAuthorityControllers.set(
    realmAuthorityControllerKey(opts.server, realmId),
    accountActorId(ownerId, opts.server),
  );
  const genesisEventId = stringValue(realmCreateEvent.event_id);
  if (genesisEventId) {
    realmAuthorityRootEventIds.set(
      realmAuthorityControllerKey(opts.server, realmId),
      genesisEventId,
    );
  }
  if (data.mls_activated) {
    // Genesis precedes every invite: each later join advances the scope's
    // key-access revision, which the joiner's Add Commit then covers
    // (`addRealmMlsMemberApi`).
    const ownerMethod = registeredEventVerificationMethod(ownerId);
    const ownerDeviceId = ownerMethod?.split("#", 2)[1];
    if (!ownerDeviceId) {
      throw new Error(`MLS Genesis needs the registered device signer of ${ownerId}`);
    }
    await activateRealmMlsApi(
      request,
      { id: ownerId, deviceId: ownerDeviceId, token, server: opts.server },
      realmId,
      { stationId: data.creator_id },
    );
  }
  for (const invitee of data.invitees ?? []) {
    const recipientServiceId =
      data.invitee_ids?.[invitee] ?? solandServiceId(opts.server);
    const recipientServer = configuredServerKeys().find(
      (server) => solandServiceId(server) === recipientServiceId,
    );
    if (!recipientServer) throw new Error("directed invite recipient Station is not configured");
    const inviteeAccountId = accountActorId(invitee, recipientServer, recipientServiceId).account_id;
    const evidence = { kind: "explicit_address" } as const;
    const inviteEvent = signedEventEnvelope({
      actorId: ownerId,
      realmId,
      kind: "ak.invite.create",
      payload: {
        invitee_account_id: inviteeAccountId,
        introduction_evidence_digest: `sha256:${sha256CanonicalJson(evidence)}`,
        expires_at: canonicalTimestamp(
          new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        ),
      },
    });
    await submitSignedEventApi(request, token, inviteEvent, {
      server: opts.server,
      context: `directed invite ${invitee}`,
    });
    if (data.invitee_ids?.[invitee] !== undefined) {
      const inviteEventId = stringValue(inviteEvent.event_id);
      if (!inviteEventId) {
        throw new Error(`directed invite ${invitee} is missing event_id`);
      }
      const dispatchBody = selfInviteDispatchBody({
        eventId: inviteEventId,
        inviteAddress: {
          account_id: inviteeAccountId,
          service_resolution: canonicalServiceResolution(recipientServer),
        },
        evidence,
      });
      await expect.poll(async () => {
        const dispatch = await dispatchSelfInviteApi(
          request,
          token,
          dispatchBody,
          { server: opts.server },
        );
        return dispatch.status;
      }, {
        message: `directed invite dispatch for ${invitee}`,
        timeout: 30_000,
        intervals: [250, 500, 1_000, 2_000],
      }).toMatch(/^(accepted|duplicate)$/);
    }
  }

  return realmId;
}

/// Bring an account into a Realm on the owner's Station.
///
/// common-fields.md section 4.5 lists exactly two writers for the
/// `leave -> join` edge: the target itself, or the exact target's acceptance
/// of an invite. An administrator never writes somebody else's
/// `member.state{join}`. The owner therefore issues a directed
/// `ak.invite.create`, and the member signs `ak.invite.accept` with its own
/// session; the `invite_id` is `retype(create_event.event_id)`
/// (governance-objects.md section 5.3).
export async function joinRealmMemberByInviteApi(
  request: APIRequestContext,
  ownerToken: string,
  realmId: string,
  member: { id: string; token: string },
  opts: { server?: SolandKey } = {},
) {
  const ownerId = await currentActorIdApi(request, ownerToken, opts);
  const evidence = { kind: "explicit_address" } as const;
  const inviteEvent = signedEventEnvelope({
    actorId: ownerId,
    server: opts.server,
    realmId,
    kind: "ak.invite.create",
    payload: {
      invitee_account_id: accountActorId(member.id, opts.server).account_id,
      introduction_evidence_digest: `sha256:${sha256CanonicalJson(evidence)}`,
      expires_at: canonicalTimestamp(
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ),
    },
  });
  await submitSignedEventApi(request, ownerToken, inviteEvent, {
    server: opts.server,
    context: `directed invite ${member.id}`,
  });
  return await acceptInviteApi(
    request,
    member.token,
    member.id,
    realmId,
    retypeEventDerivedId(String(inviteEvent.event_id), "invite"),
    { server: opts.server },
  );
}

// The current `realm_policy_bundle` typed result of a Realm.
//
// event-kind-registry.json projects every accepted `ak.realm.policy_bundle`
// with `result_projection: {kind: "set", value: {field: "payload"}}`, and
// authz/event-auth-state-resolution.md section 6 makes the last accepted write
// on the Realm stream the current value. The committed stream scan
// (`ak.self.realm.read.streams.v1` / `/_arkret/self/streams/scan`) is therefore
// the read surface: the payload of the last committed bundle Event is the
// complete current component set.
export async function readCurrentRealmPolicyBundleApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey } = {},
): Promise<Record<string, unknown>> {
  const scan = await scanRealmStreamApi(request, token, realmId, { server: opts.server });
  expect(scan.truncated, `Realm ${realmId} stream scan must reach the stream head`).toBe(false);
  const bundles = scan.events.filter(
    (event) => event?.kind === "ak.realm.policy_bundle",
  );
  expect(bundles.length, `Realm ${realmId} has an accepted policy bundle`).toBeGreaterThan(0);
  const payload = bundles[bundles.length - 1].payload;
  expect(
    payload !== null && typeof payload === "object" && !Array.isArray(payload),
    `Realm ${realmId} policy bundle payload is a closed object`,
  ).toBe(true);
  const policy = payload as Record<string, unknown>;
  expect(typeof policy.policy_revision, `Realm ${realmId} policy_revision`).toBe("number");
  return policy;
}

// join-policy.md §3 — write the per-Realm `join_policy` component as a
// `ak.realm.policy_bundle` revision.
//
// The payload IS the flat closed `realm_policy_bundle_payload`
// (`required: ["policy_revision"]`, `minProperties: 2`,
// `additionalProperties: false`) — not a `{value: ...}` state-payload wrapper,
// and it carries no `realm_id`: the governed Realm is the envelope's.
//
// Every revision restates the complete component set with a strictly
// monotonic `policy_revision` (models/realm-and-space.md section 2.5).
// Preserve every current component and change only `policy_revision` +
// `join_policy`; omitting current components can violate one-way policy
// ratchets.
export async function writeJoinPolicyApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  joinPolicy: Record<string, unknown>,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const actorId = await currentActorIdApi(request, token, opts);
  const digest = `sha256:${sha256CanonicalJson(joinPolicy)}`;
  const currentPolicy = await readCurrentRealmPolicyBundleApi(request, token, realmId, opts);
  const policyRevision = Number(currentPolicy.policy_revision) + 1;
  const policyEvent = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.realm.policy_bundle",
    payload: {
      ...currentPolicy,
      policy_revision: policyRevision,
      join_policy: joinPolicy,
    },
  });
  await submitSignedEventApi(request, token, policyEvent, {
    server: opts.server,
    context: `write join policy ${realmId}`,
  });
  await expect
    .poll(
      async () => {
        const current = await readCurrentRealmPolicyBundleApi(request, token, realmId, opts);
        const projectedJoinPolicy = current.join_policy;
        return (
          current.policy_revision === policyRevision &&
          projectedJoinPolicy !== undefined &&
          `sha256:${sha256CanonicalJson(projectedJoinPolicy)}` === digest
        );
      },
      {
        message: `join policy ${realmId} revision ${policyRevision} is the current policy bundle`,
        timeout: 30_000,
        intervals: [250, 500, 1_000, 2_000],
      },
    )
    .toBe(true);
  joinPolicyDigestCache.set(joinWorkflowKey(opts.server, realmId), digest);
  return digest;
}

// Grant a Realm-scoped capability to a peer service DID.
// sync/federation.md §4.4: the grant subject is a service DID; revoking it
// makes the source Station stop pushing future events to that peer.
export async function grantServiceCapabilityApi(
  request: APIRequestContext,
  ownerToken: string,
  args: {
    ownerId: string;
    realmId: string;
    subjectServiceId: string;
    action?: string;
    server?: SolandKey;
  },
): Promise<string> {
  await discoverRealmAuthorityRootRef(request, ownerToken, args.realmId, args.server);
  const issuedAt = canonicalTimestamp();
  // Use a core collaboration action advertised by both federation peers; the
  // service actor subject and Realm resource make this a peer-service grant.
  const action = args.action ?? "ak.message.create";
  // `capability-grant.schema.json` is a closed object; annotating the literal
  // makes an unregistered member or a misspelled resource kind a `tsc` error
  // instead of a reducer rejection. The producer proof is attached after signing.
  const unsignedGrant: CapabilityGrantPayload["grant"] = {
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer_id: accountActorId(args.ownerId, args.server),
    subject: serviceActorId(args.subjectServiceId),
    actions: [action],
    resources: [{ kind: "realm", realm_id: args.realmId }],
    issued_at: issuedAt,
    issuer_authority_refs: [
      {
        kind: "realm_root",
        realm_id: args.realmId,
        authority_event_ref: requireRealmAuthorityRootRef(args.server, args.realmId),
        authority_generation: 0,
      },
    ],
  };
  const grantEvent = signedEventEnvelope({
    actorId: args.ownerId,
    realmId: args.realmId,
    kind: "ak.capability.grant",
    createdAt: issuedAt,
    payload: {
      // The grant body is closed and carries no inner proof; the Event
      // envelope proof is the sole durable issuer signature.
      grant: unsignedGrant,
    },
  });
  await submitSignedEventApi(request, ownerToken, grantEvent, {
    server: args.server,
    context: `grant ${action} service capability to ${args.subjectServiceId}`,
  });
  const grantId = retypeEventDerivedId(String(grantEvent.event_id), "grant");
  return grantId;
}

// Mint a realm-scoped `ak.capability.grant` event for an arbitrary action set
// and return both the immutable grant id (`ak:grant:*`) and its carrying Event
// id (`ak:event:*`). capabilities.md §10.3 requires
// `semantic_refs[authorized_by]` to
// name the grant itself; the Event id remains useful only for Event-history
// causality and diagnostics.
type CapabilityGrantEventArgs = {
  ownerId: string;
  realmId: string;
  subjectId: string;
  subjectStationId?: string;
  subjectServer?: SolandKey;
  actions: string[];
  // capabilities.md §6.1 / §8: optional finite validity upper bound. The
  // helper lowers this shorthand into a standalone global temporal
  // constraint; the closed grant object has no top-level expires_at field.
  // Child grants issued from grant refs MUST narrow: child
  // effective_expires_at MUST be <= the issuer authority's (§10.1).
  expiresAt?: string;
  // capabilities.md §10: a grant can authorize a derived grant only when an
  // authority_control constraint explicitly permits it. Omitting this field
  // is the canonical non-delegable form (effective max_authority_depth = 0).
  constraints?: CapabilityGrantObject["constraints"];
  // capabilities.md §3.2 / §10: typed authority anchors. Omitted only by this
  // test helper, which then emits the initial Realm authority-root ref.
  issuerAuthorityRefs?: CapabilityGrantObject["issuer_authority_refs"];
  server?: SolandKey;
};

// Build (but do not submit) a signed `ak.capability.grant` envelope. Exposed
// separately from grantCapabilityEventApi so negative suites (authority
// widening, revoked-ancestor re-granting, ...) can submit the same canonical
// envelope shape raw and assert the reducer rejection instead of the 200 the
// happy-path helper pins.
export function buildCapabilityGrantEnvelope(args: CapabilityGrantEventArgs): {
  envelope: Record<string, unknown>;
  grantId: string;
  eventId: string;
} {
  const issuedAt = canonicalTimestamp();
  const constraints: CapabilityGrantObject["constraints"] = [
    ...(args.constraints ?? []),
    ...(args.expiresAt
      ? [
          {
            constraint_kind: "temporal" as const,
            effect: "allow" as const,
            evaluation_class: "stateless" as const,
            expires_at: args.expiresAt,
          },
        ]
      : []),
  ];
  // `capability-grant.schema.json` is a closed object; annotating the literal
  // makes an unregistered member or a misspelled resource kind a `tsc` error
  // instead of a reducer rejection. The producer proof is attached after signing.
  const unsignedGrant: CapabilityGrantPayload["grant"] = {
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer_id: accountActorId(args.ownerId, args.server),
    subject: accountActorId(args.subjectId, args.subjectServer ?? args.server, args.subjectStationId),
    actions: args.actions,
    resources: [{ kind: "realm", realm_id: args.realmId }],
    issued_at: issuedAt,
    ...(constraints.length > 0 ? { constraints } : {}),
    issuer_authority_refs: args.issuerAuthorityRefs ?? [
      {
        kind: "realm_root",
        realm_id: args.realmId,
        authority_event_ref: requireRealmAuthorityRootRef(args.server, args.realmId),
        authority_generation: 0,
      },
    ],
  };
  const envelope = signedEventEnvelope({
    actorId: args.ownerId,
    server: args.server,
    realmId: args.realmId,
    kind: "ak.capability.grant",
    createdAt: issuedAt,
    // capability_grant_payload (event-payload.schema.json) is closed; typed
    // issuer-authority refs travel inside the grant object.
    payload: {
      // The grant body is closed and carries no inner proof; the Event
      // envelope proof is the sole durable issuer signature.
      grant: unsignedGrant,
    },
  });
  // The grant Event's id is derived from the envelope, so it can only be read
  // back once the envelope exists.
  const eventId = envelope.event_id as string;
  return {
    envelope,
    grantId: retypeEventDerivedId(eventId, "grant"),
    eventId,
  };
}

export async function grantCapabilityEventApi(
  request: APIRequestContext,
  ownerToken: string,
  args: CapabilityGrantEventArgs,
): Promise<{ grantId: string; eventId: string }> {
  if (args.issuerAuthorityRefs === undefined) {
    await discoverRealmAuthorityRootRef(request, ownerToken, args.realmId, args.server);
  }
  const { envelope } = buildCapabilityGrantEnvelope(args);
  await submitSignedEventApi(request, ownerToken, envelope, {
    server: args.server,
    context: `grant [${args.actions.join(", ")}] to ${args.subjectId}`,
  });
  const eventId = String(envelope.event_id);
  return { grantId: retypeEventDerivedId(eventId, "grant"), eventId };
}

// Revoke a previously granted capability by grant_id.
export async function revokeCapabilityApi(
  request: APIRequestContext,
  ownerToken: string,
  args: {
    ownerId: string;
    realmId: string;
    grantId: string;
    server?: SolandKey;
  },
) {
  const outcome = await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorId: args.ownerId,
      realmId: args.realmId,
      kind: "ak.capability.revoke",
      payload: {
        grant_id: args.grantId,
      },
    }),
    { server: args.server, context: `revoke grant ${args.grantId}` },
  );
  return outcome;
}

// join-policy.md §7.1 stage 1 — `ak.member.state{membership=knock}`. The
// knock Control Move carries no application body (spec §8 keeps free text out
// of the public knock event).
const joinPolicyDigestCache = new Map<string, string>();

// Last `policy_revision` this process wrote per (server, realm).
//
// `ak.component.realm.policy_bundle.v1` is sequenced state whose supersession
// binds by value, so the revision is what gives a bundle family its generation
// dimension: a stateless constant makes the second write of a Realm a repeat of
// the first, and the register has no way to order them. The helper therefore
// has to hold this per (server, realm) rather than derive it from the payload.
// The `createRealmApi` genesis already occupies `policy_revision: 1`
function joinWorkflowKey(
  server: SolandKey | undefined,
  realmId: string,
  actorId?: string,
): string {
  return `${server ?? "default"}\0${realmId}\0${actorId ?? ""}`;
}

export async function acceptInviteApi(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  inviteId: string,
  opts: {
    server?: SolandKey;
    previousState?: "pending" | "claimed";
    /// Set `false` for a third-party invite, which stores no account.
    ///
    /// governance-objects.md section 5.3 binds the optional
    /// `invitee_account_id` to the persisted pre-state with
    /// `stored_field_matches_payload`: a directed invite that omits it strands
    /// its live-target slot, and a third-party invite that carries one is
    /// forging a release of somebody else's. Directed is the default because
    /// it is the shape every scenario here accepts.
    directed?: boolean;
  } = {},
) {
  // join-policy section 6: candidates are hints, and there is no basis for the
  // invitee to fetch first — the accept Event is complete when it is signed and
  // the invitee's own Station forwards it to the Realm's governance Station.
  return await submitSignedEventApi(request, token, signedEventEnvelope({
    actorId,
    server: opts.server,
    realmId,
    kind: "ak.invite.accept",
    payload: {
      invite_id: inviteId,
      previous_state: opts.previousState ?? "pending",
      ...(opts.directed === false ? {} : {
        invitee_account_id: accountActorId(actorId, opts.server).account_id,
      }),
    },
  }), { server: opts.server, context: `accept invite ${inviteId}` });
}

async function readOwnInviteDeliveryApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey },
  inviteId?: string,
) {
  const dataUrl = `${solandBaseUrl(opts.server)}/_arkret/self/account_data`;
  const holder = await expectJsonOk<{ account_data_entries: Array<{
    account_data_key: string; content: { delivery_entries?: Array<{
      invite_id: string; realm_id: string;
      // `invite-delivery.schema.json#/$defs/delivery_entry.authority_locator_hints`:
      // the untrusted governance locators the delivery chain carried.
      authority_locator_hints: RealmJoinPrepareRequestBody["target"]["authority_locator_hints"];
    }> };
  }> }>(await request.get(dataUrl, {
    headers: authHeaders(token, "GET", dataUrl),
  }), "read own invite delivery");
  return holder.account_data_entries
    .find((entry) => entry.account_data_key === "ak.account.invite_delivery")
    ?.content.delivery_entries?.find((entry) => (!inviteId || entry.invite_id === inviteId) && entry.realm_id === realmId);
}

export async function waitForInviteDeliveryApi(
  request: APIRequestContext,
  token: string,
  inviteeId: string,
  realmId: string,
  server: SolandKey,
) {
  expect(await currentActorIdApi(request, token, { server })).toBe(inviteeId);
  let delivery: Awaited<ReturnType<typeof readOwnInviteDeliveryApi>>;
  await expect.poll(async () => {
    delivery = await readOwnInviteDeliveryApi(request, token, realmId, { server });
    return Boolean(delivery);
  }, { message: "own protected invitation notification", timeout: 45_000, intervals: [1000, 2000, 5000] }).toBe(true);
  return { id: delivery!.invite_id, realm_id: delivery!.realm_id };
}

/** Join through the applicant's own Station without reading foreign governance. */
export async function acceptPreparedInviteApi(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  inviteId: string,
  opts: {
    server?: SolandKey;
    onAccepted?: (outcome: Record<string, unknown>) => void;
  } = {},
) {
  const account = accountActorId(actorId, opts.server).account_id;
  const delivery = await readOwnInviteDeliveryApi(request, token, realmId, opts, inviteId);
  expect(Boolean(delivery), "own invitation credential must be available").toBe(true);
  // realm-join-intake: the applicant's Station resolves the Realm's current
  // governance Station from the locator hints the invitation delivered, never
  // from its own identity. The hints stay untrusted; prepare verifies them.
  expect(delivery!.authority_locator_hints.length).toBeGreaterThan(0);
  const input: RealmJoinPrepareRequestBody = {
    request_id: typedId("request"),
    target: {
      realm_id: realmId,
      invite_id: inviteId,
      authority_locator_hints: delivery!.authority_locator_hints,
    },
    intent: { kind: "invite_accept", invite_id: inviteId },
  };
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/realm-joins/prepare`;
  const prepare = () => request.post(url, {
    headers: { ...authHeaders(token, "POST", url), "content-type": "application/json" },
    data: canonicalJson(input),
  });
  const prepared = await expectJsonOk<Record<string, any>>(await prepare(), "own-Station join prepare");
  // Prepare is context, not a reservation: repeating it returns the same
  // authority bundle and the same Realm stream head, and reserves nothing.
  expect(prepared.request_id).toBe(input.request_id);
  expect(prepared.authority_bundle?.realm_id).toBe(realmId);
  const head = prepared.realm_stream_head as CommitStreamHead;
  expect(head.stream_ref).toEqual({ kind: "realm", realm_id: realmId });
  expect(typeof head.stream_position).toBe("number");
  expect(head.commit_id).toMatch(/^ak:realm_commit:/);

  // The producer authors its own Event against that context. There is no
  // actor frontier to reserve and no predecessor graph to extend.
  const event = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.invite.accept",
    // `event-payload.schema.json#/$defs/invite_accept_payload`: a directed
    // invite moves out of `pending` and carries the stored invitee account.
    payload: { invite_id: inviteId, previous_state: "pending", invitee_account_id: account },
    server: opts.server,
  });
  const submitUrl = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
  const signed = canonicalJson({ event });
  const submit = () => request.post(submitUrl, {
    headers: { ...authHeaders(token, "POST", submitUrl), "content-type": "application/json" },
    data: signed,
  });
  // Submission is synchronous: the governance Station answers committed or
  // duplicate, and an exact retry of the same bytes is the only status read.
  const accepted = await expectJsonOk<Record<string, any>>(await submit(), "prepared join submit");
  expect(accepted.status).toBe("committed");
  expect(accepted.commit?.event_ref).toBe(event.event_id);
  const replay = await expectJsonOk<Record<string, any>>(await submit(), "exact join submit replay");
  expect(replay.status).toBe("duplicate");
  expect(replay.commit?.commit_id).toBe(accepted.commit?.commit_id);
  opts.onAccepted?.(structuredClone(accepted));
  return event;
}

export async function listInvitesApi(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<InviteObject[]> {
  const url = new URL(
    "/_arkret/self/authz/invites",
    solandBaseUrl(opts.server),
  );
  const response = await request.get(url.toString(), {
    headers: {
      ...authHeaders(token, "GET", url.toString()),
      "Arkret-Operation": "ak.self.authz.invites.read.list.v1",
    },
  });
  const body = await expectJsonOk<{
    invites?: InviteObject[];
  }>(response, "list invites");
  return body.invites ?? [];
}

/** Exercise prepare, exact replay and the ordinary submit without re-authoring. */
export async function sendPreparedMessageApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  body: string,
  opts: { server?: SolandKey } = {},
) {
  const principal = await currentActorIdApi(request, token, opts);
  const actor = accountActorId(principal, opts.server);
  const strandId = await resolveDefaultStrandId(request, token, realmId, opts);
  const content = { kind: "ak.content.text" as const, body };
  const intent: MessagePrepareRequestBody["intent"] = {
    strand_id: strandId,
    track_name: "discussion",
    content: { kind: "plaintext", content },
  };
  const prepare: MessagePrepareRequestBody = {
    request_id: typedId("request"),
    account_id: actor.account_id,
    realm_id: realmId,
    intent,
    created_at: canonicalTimestamp(),
  };
  const prepareUrl = `${solandBaseUrl(opts.server)}/_arkret/self/messages/prepare`;
  const fetch = () => request.post(prepareUrl, {
    headers: {
      ...authHeaders(token, "POST", prepareUrl),
      "content-type": "application/json",
    },
    data: canonicalJson(prepare),
  });
  const prepared = await expectJsonOk<Record<string, any>>(
    await fetch(), "typed message prepare",
  );
  expect(await expectJsonOk(await fetch(), "exact prepare replay")).toEqual(prepared);
  const conflicting = await request.post(prepareUrl, {
    headers: {
      ...authHeaders(token, "POST", prepareUrl),
      "content-type": "application/json",
    },
    data: canonicalJson({
      ...prepare,
      intent: {
        ...intent,
        content: { kind: "plaintext", content: { ...content, body: `${body} changed` } },
      },
    }),
  });
  expect(conflicting.status()).toBe(409);
  expect(wireErrCode(await conflicting.json())).toBe("duplicate_conflict");
  expect(prepared.request_digest).toBe(`sha256:${sha256CanonicalJson(prepare)}`);
  const unsigned = JSON.parse(
    Buffer.from(prepared.draft.unsigned_event_bytes, "base64url").toString("utf8"),
  );
  expect(unsigned.kind).toBe("ak.message.create");
  expect(unsigned.realm_id).toBe(realmId);
  expect(unsigned.actor_id).toEqual(actor);
  expect(unsigned.created_at).toBe(prepare.created_at);
  expect(unsigned.scope_ref).toEqual({ kind: "realm", realm_id: realmId });
  expect(unsigned.payload).toEqual({
    strand_id: strandId, track_name: "discussion", content,
  });
  // A prepared draft is the producer envelope and nothing else: the Station
  // supplies position, predecessor and coverage when it commits, so none of the
  // retired ordering members may appear in the bytes the producer signs.
  for (const retired of [
    "actor_seq",
    "prev_refs",
    "causal_refs",
    "preconditions",
    "hlc",
    "seal_ref",
    "basis",
  ]) {
    expect(
      retired in unsigned,
      `prepared draft reintroduced the retired member ${retired}`,
    ).toBe(false);
  }
  expect(unsigned.semantic_refs ?? []).toEqual([]);
  const derived = sdkEventDerivedIds(unsigned);
  const event = { ...unsigned, event_id: derived.event_id };
  expect(prepared.draft.event_digest).toBe(`sha256:${sha256CanonicalJson(unsigned)}`);
  event.producer_proof = eventEnvelopeProof({ actorId: principal, event });
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
  const submission = canonicalJson({ event });
  const submit = () => request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: submission,
  });
  const outcome = await expectJsonOk<Record<string, unknown>>(
    await submit(), "prepared message submit",
  );
  assertAuthoritySubmitOutcome(outcome, event, "prepared message submit");
  expect(outcome.status).toBe("committed");
  const committed = outcome.commit as Record<string, unknown>;
  // The exact signed bytes replay to the commit that already admitted them and
  // consume no second stream position.
  const replay = await expectJsonOk<Record<string, unknown>>(
    await submit(), "exact signed submission replay",
  );
  assertAuthoritySubmitOutcome(replay, event, "exact signed submission replay");
  expect(replay.status).toBe("duplicate");
  expect((replay.commit as Record<string, unknown>).commit_id).toBe(
    committed.commit_id,
  );
  expect((replay.commit as Record<string, unknown>).stream_position).toBe(
    committed.stream_position,
  );
  return {
    event_id: event.event_id,
    realm_id: realmId,
    actor_id: principal,
    commit_id: String(committed.commit_id),
    stream_position: Number(committed.stream_position),
  };
}

export async function sendMessageApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  body: string,
  opts: {
    server?: SolandKey;
    encrypted?: boolean;
    createdAt?: string;
    retryTemporarilyUnavailable?: boolean;
    // A bare string is the mention subject's principal DID; it is completed
    // with this server's Station to form the whole AccountId the wire needs
    // (identity-handles.md 3.8). Pass the object form to address another
    // Station explicitly.
    mentions?: Array<
      | string
      | {
          kind: "mention";
          subject_account_id: { principal_id: string; station_id: string };
          handle_at_time?: string;
          mention_text_original?: string;
        }
    >;
  } = {},
) {
  const actorId = await currentActorIdApi(request, token, opts);
  const strandId = await resolveDefaultStrandId(request, token, realmId, {
    server: opts.server,
  });
  const envelope = signedEventEnvelope({
    actorId,
    server: opts.server,
    realmId,
    kind: "ak.message.create",
    createdAt: opts.createdAt,
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      content: {
        kind: "ak.content.text",
        body,
        ...(opts.mentions
          ? {
              mentions: opts.mentions.map((mention) =>
                typeof mention === "string"
                  ? {
                      kind: "mention",
                      subject_account_id: accountActorId(mention, opts.server)
                        .account_id,
                    }
                  : mention,
              ),
            }
          : {}),
      },
    },
  });
  const submission = await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `send message to ${realmId}`,
    retryTemporarilyUnavailable: opts.retryTemporarilyUnavailable,
  });
  const commit = submission.commit as Record<string, unknown> | undefined;
  return {
    event_id: String(envelope.event_id),
    realm_id: realmId,
    actor_id: actorId,
    commit_id: commit ? String(commit.commit_id) : undefined,
    stream_position: commit ? Number(commit.stream_position) : undefined,
    cursor:
      typeof submission.cursor === "string" ? submission.cursor : undefined,
  };
}

export async function setStrandWatchLevelApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  strandId: string,
  watcherActorId: string,
  level: "mentions_only" | "participating" | "all" | "muted" | null,
  opts: { server?: SolandKey; levelPublic?: boolean; context?: string } = {},
) {
  const actorId = await currentActorIdApi(request, token, opts);
  const payload: Record<string, unknown> = {
    strand_id: strandId,
    watcher_actor_id: accountActorId(watcherActorId, opts.server),
    level,
  };
  if (level !== null) {
    payload.level_public = opts.levelPublic ?? false;
  }
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId,
      realmId,
      kind: "ak.strand.watch.set",
      payload,
    }),
    {
      server: opts.server,
      context:
        opts.context ??
        `set strand watch ${level ?? "mentions_only"} for ${strandId}`,
    },
  );
}

/// Read a Realm's own commit stream through `ak.self.committed_event.read.scan.v1`.
///
/// There is no Realm-wide Event query any more: a reader walks one stream by
/// continuous `stream_position`. The flattened `events` list is returned in
/// commit order alongside the commits that carry them, so a caller can assert
/// either the Event payloads or the ordering the Station assigned them.
export async function scanRealmStreamApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: {
    server?: SolandKey;
    limit?: number;
    streamRef?: Record<string, unknown>;
    waitForJoinedCut?: boolean;
    afterPosition?: number;
  } = {},
): Promise<{
  commits: Array<Record<string, unknown>>;
  events: Array<Record<string, unknown>>;
  truncated: boolean;
  authorizationPending?: boolean;
}> {
  const streamRef = opts.streamRef ?? { kind: "realm", realm_id: realmId };
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/streams/scan`;
  const response = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({
      realm_id: realmId,
      stream_ref: streamRef,
      after_position: opts.afterPosition ?? null,
      limit: opts.limit ?? 256,
    }),
  });
  if (opts.waitForJoinedCut && [403, 503].includes(response.status())) {
    const problem = await response.json() as { type?: string; detail?: string };
    if ((response.status() === 403 &&
         problem.type === "https://arkret.org/problems/capability_denied" &&
         problem.detail === "the stream is not readable by this caller") ||
        (response.status() === 503 &&
         problem.type === "https://arkret.org/problems/temporarily_unavailable" &&
         problem.detail === "the caller's readable interval cannot be proved at this cut")) {
      return { commits: [], events: [], truncated: false, authorizationPending: true };
    }
  }
  const body = await expectJsonOk<{
    committed_events: Array<{
      commit: Record<string, unknown>;
      event: Record<string, unknown>;
    }>;
    truncated?: boolean;
  }>(response, `scan Realm stream for ${realmId}`);
  const items = body.committed_events;
  expect(Array.isArray(items), "stream scan must return committed_events").toBeTruthy();
  return {
    commits: items.map((item) => item.commit),
    events: items.map((item) => item.event),
    truncated: body.truncated === true,
  };
}

/// Back-compatible projection of [`scanRealmStreamApi`] for callers that only
/// read the Event list. The Events arrive in the order the governance Station
/// committed them, which is the only order that exists.
///
/// A `CommittedEventView` withheld row (`{commit, event_disclosure}`,
/// service-http-binding.md §3.1) carries no Event, so it is absent from
/// `events`; `commits` keeps every slot of the verifiable chain.
export async function queryRealmEventsApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey; limit?: number; waitForJoinedCut?: boolean; afterPosition?: number } = {},
): Promise<Record<string, unknown>> {
  const scan = await scanRealmStreamApi(request, token, realmId, opts);
  return {
    events: scan.events.filter((event) => event !== undefined),
    commits: scan.commits,
    ...(scan.authorizationPending ? { authorizationPending: true } : {}),
  };
}

/// The holder-signed `ak.account_data.set` both account-data endpoints now take.
///
/// The kind's actor-private cell subject is
/// `composite[envelope.actor_id, payload.key]`, so the Event's actor is half the
/// cell address: the holder signs, and the service cannot author it under its own
/// DID. Omit `value` for the tombstone the DELETE endpoint requires.
function accountDataSetSubmission(args: {
  actorId: string;
  key: string;
  expectedRevision: number;
  value?: unknown;
  privateValue?: boolean;
}): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    key: args.key,
    expected_server_revision: args.expectedRevision,
  };
  if (args.value === undefined) {
    payload.tombstone = true;
  } else if (args.privateValue ?? privateAccountDataKeys.has(args.key)) {
    payload.encrypted_payload = args.value;
  } else {
    payload.body = args.value;
  }
  return {
    event: signedEventEnvelope({
      actorId: args.actorId,
      realmId: principalControlRealmForId(args.actorId),
      kind: "ak.account_data.set",
      payload,
    }),
  };
}
async function prepareAccountDataSetSubmissionApi(
  request: APIRequestContext,
  token: string,
  args: Parameters<typeof accountDataSetSubmission>[0],
  opts: { server?: SolandKey; context?: string } = {},
): Promise<Record<string, unknown>> {
  const draft = accountDataSetSubmission(args);
  const event = draft.event as Record<string, unknown>;
  return { event };
}

export async function replaceAccountDataApi(
  request: APIRequestContext,
  token: string,
  actorId: string,
  key: string,
  body: Record<string, unknown>,
  expectedRevision: number,
  opts: { server?: SolandKey; context?: string } = {},
) {
  const content = privateAccountDataKeys.has(key)
    ? encryptedAccountDataValue(accountActorId(actorId, opts.server), key, body)
    : body;
  const setEvent = await prepareAccountDataSetSubmissionApi(
    request,
    token,
    {
      actorId,
      key,
      expectedRevision,
      value: content,
    },
    opts,
  );
  const response = await request.put(
    `${solandBaseUrl(opts.server)}/_arkret/self/account_data/${encodeURIComponent(key)}`,
    {
      headers: {
        ...authHeaders(token, "PUT", `${solandBaseUrl(opts.server)}/_arkret/self/account_data/${encodeURIComponent(key)}`),
        "content-type": "application/json",
      },
      data: canonicalJson({
        set_event: setEvent,
      }),
    },
  );
  const text = await response.text();
  expect(
    [200, 201],
    `${opts.context ?? `replace account_data ${key}`} returned ${response.status()}: ${text}`,
  ).toContain(response.status());
  return parseJsonOrRaw(text) as Record<string, unknown>;
}

const privateAccountDataKeys = new Set([
  "ak.account.blocklist",
  "ak.dnd_schedule",
  "ak.push_rules",
]);

function encryptedAccountDataValue(
  actorId: ActorId,
  dataType: string,
  content: Record<string, unknown>,
): Record<string, unknown> {
  const schema = "ak.schema.account_data_encrypted_value.v1";
  const version = "1.0";
  const accountSecret = randomBytes(32);
  const keyInfo = Buffer.from(
    canonicalJson({ schema, actor_id: actorId, account_data_key: dataType }),
    "utf8",
  );
  const key = Buffer.from(
    hkdfSync(
      "sha256",
      accountSecret,
      Buffer.from("arkret-account-data-value-hkdf-v1", "utf8"),
      keyInfo,
      32,
    ),
  );
  const aad = {
    schema,
    version,
    actor_id: actorId,
    account_data_key: dataType,
  };
  const aadBytes = Buffer.from(canonicalJson(aad), "utf8");
  const plaintext = Buffer.from(canonicalJson(content), "utf8");
  const nonce = randomBytes(24);
  const ciphertext = Buffer.from(
    xchacha20poly1305(key, nonce, aadBytes).encrypt(plaintext),
  );
  const digest = (bytes: Uint8Array) =>
    `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  return {
    schema,
    version,
    aead_profile: "ak.aead.xchacha20_poly1305.v1",
    key_ref: digest(key),
    nonce: base64url(nonce),
    ciphertext: base64url(ciphertext),
    aad,
  };
}

export async function currentActorIdApi(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/account/viewer`;
  const response = await request.get(url, {
    headers: authHeaders(token, "GET", url),
  });
  const body = await expectJsonOk<{ principal_id: string }>(
    response,
    "read current actor",
  );
  return requireDidCoreId(body.principal_id);
}

type AccountCoordinate = { principal_id: string; station_id: string };

function requireSignerEvidenceRef(value: unknown, context: string): string {
  if (
    typeof value !== "string" ||
    !/^ak:signer_evidence:sha256:[0-9a-f]{64}$/.test(value)
  ) {
    throw new Error(`${context} omitted a canonical signer evidence ref`);
  }
  return value;
}

/**
 * Confirm that one exact human account-device signer is current before the
 * harness authors Events with it.
 *
 * device-lifecycle.md section 8.2.2 has a single producer rule for every Event
 * a human device signs, whatever its kind: the governance Station resolves the
 * signer from its own PCR (same Station) or from `authority_forward`
 * `producer_device_evidence` (cross Station). The producer proof carries no
 * evidence ref, so nothing is installed on the signer. This only checks that
 * the account viewer row is active and verified and that the keys/query row
 * projects the same authorization at the current generation with its complete
 * section 8.2 signer evidence ref.
 */
export async function verifyRegisteredEventSignerDeviceApi(
  request: APIRequestContext,
  token: string,
  args: {
    actorId: string;
    accountId: AccountCoordinate;
    deviceId: string;
    verificationMethod: string;
    server?: SolandKey;
  },
): Promise<void> {
  if (args.accountId.principal_id !== args.actorId) {
    throw new Error("signer evidence account principal does not match actor");
  }

  const viewerUrl = `${solandBaseUrl(args.server)}/_arkret/self/account/viewer`;
  const viewer = await expectJsonOk<{
    principal_id?: unknown;
    devices?: Array<{
      device_id?: unknown;
      status?: unknown;
      verification_state?: unknown;
      authorized_event_ref?: unknown;
    }>;
  }>(
    await request.get(viewerUrl, {
      headers: authHeaders(token, "GET", viewerUrl),
    }),
    `read post-Seal account viewer for ${args.deviceId}`,
  );
  if (viewer.principal_id !== args.actorId) {
    throw new Error("account viewer principal does not match signer actor");
  }
  const viewerRows = (viewer.devices ?? []).filter(
    (row) => row.device_id === args.deviceId,
  );
  if (viewerRows.length !== 1) {
    throw new Error(
      `account viewer must contain exactly one row for session device ${args.deviceId}`,
    );
  }
  const viewerRow = viewerRows[0]!;
  if (
    viewerRow.status !== "active" ||
    viewerRow.verification_state !== "verified"
  ) {
    throw new Error(
      `session device ${args.deviceId} is not active and verified in account viewer`,
    );
  }
  const authorizedEventRef = stringValue(viewerRow.authorized_event_ref);
  if (!authorizedEventRef?.startsWith("ak:event:")) {
    throw new Error(
      `verified account viewer row for ${args.deviceId} omitted authorized_event_ref`,
    );
  }
  if (Object.hasOwn(viewerRow, "signer_resolution_evidence_ref")) {
    throw new Error(
      `account viewer row for ${args.deviceId} carries the retired signer_resolution_evidence_ref`,
    );
  }

  const keysUrl = `${solandBaseUrl(args.server)}/_arkret/self/keys/query`;
  const keys = await expectJsonOk<{
    device_keys?: Array<{
      account_id?: unknown;
      device_keys?: Record<
        string,
        {
          signer_evidence_ref?: unknown;
          device_projection?: {
            device_authorize_event_id?: unknown;
            authorized_generation_ref?: unknown;
            device_status?: unknown;
          };
        }
      >;
    }>;
    device_generations?: Array<{
      account_id?: unknown;
      generation_state?: {
        current_device_generation_ref?: unknown;
      };
    }>;
  }>(
    await request.post(keysUrl, {
      headers: {
        ...authHeaders(token, "POST", keysUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({
        device_keys: [
          { account_id: args.accountId, device_ids: [args.deviceId] },
        ],
      }),
    }),
    `query signer device row for ${args.deviceId}`,
  );
  const accountKey = canonicalJson(args.accountId);
  const keyEntries = (keys.device_keys ?? []).filter(
    (entry) => canonicalJson(entry.account_id) === accountKey,
  );
  if (keyEntries.length !== 1) {
    throw new Error(
      `keys/query must contain exactly one entry for session account ${accountKey}`,
    );
  }
  const dataRow = keyEntries[0]!.device_keys?.[args.deviceId];
  if (!dataRow) {
    throw new Error(
      `keys/query omitted exact session device ${args.deviceId}`,
    );
  }
  const projection = dataRow.device_projection;
  if (
    projection?.device_status !== "active" ||
    projection.device_authorize_event_id !== authorizedEventRef
  ) {
    throw new Error(
      `keys/query projection for ${args.deviceId} does not match the active viewer authorization`,
    );
  }
  const generationEntries = (keys.device_generations ?? []).filter(
    (entry) => canonicalJson(entry.account_id) === accountKey,
  );
  if (generationEntries.length !== 1) {
    throw new Error(
      `keys/query must contain exactly one generation for session account ${accountKey}`,
    );
  }
  const generation = generationEntries[0]!.generation_state;
  if (
    typeof generation?.current_device_generation_ref !== "number" ||
    !Number.isSafeInteger(generation.current_device_generation_ref) ||
    generation.current_device_generation_ref < 1 ||
    generation.current_device_generation_ref !==
      projection.authorized_generation_ref
  ) {
    throw new Error(
      `keys/query generation does not authorize session device ${args.deviceId}`,
    );
  }
  requireSignerEvidenceRef(
    dataRow.signer_evidence_ref,
    `keys/query row for ${args.deviceId}`,
  );
}

export function signedEventEnvelope(
  args: SignedEventEnvelopeArgs,
): Record<string, unknown> {
  const createdAt = canonicalEventTimestamp(
    args.createdAt === undefined ? undefined : new Date(args.createdAt),
  );
  const payload = stripUndefined(args.payload) as Record<string, unknown>;
  const actor = typeof args.actorId === "string"
    ? accountActorId(args.actorId, args.server, args.stationId)
    : args.actorId;
  // A Realm genesis is the one Event that names no Realm: `realm_id` is
  // `retype(event_id)` of the genesis itself, and `scope_ref` carries the
  // closed `realm_genesis` form. Sending either would be
  // `realm_id_not_event_derived`.
  const isRealmGenesis = args.kind === "ak.realm.create";
  const unidentified = stripUndefined({
    kind: args.kind,
    realm_id: isRealmGenesis ? undefined : args.realmId,
    scope_ref:
      args.scopeRef ??
      (isRealmGenesis
        ? { kind: "realm_genesis" }
        : { kind: "realm", realm_id: args.realmId }),
    actor_id: actor,
    executed_by: args.executedBy,
    authorization_ref: args.authorizationRef,
    applet_id: args.appletId,
    created_at: createdAt,
    semantic_refs: args.semanticRefs?.length ? args.semanticRefs : undefined,
    payload,
  }) as Record<string, unknown>;
  // `event_id` sits outside the digest preimage, so deriving it from the
  // finished envelope and adding it afterwards does not disturb the digest the
  // proof below signs. An explicit `eventId` stays honoured: a wire-negative
  // case needs to be able to present an id the producer would never derive.
  const derived = args.eventId ? undefined : sdkEventDerivedIds(unidentified);
  const event = {
    ...unidentified,
    event_id: args.eventId ?? derived!.event_id,
  } as Record<string, unknown>;
  return {
    ...event,
    producer_proof: eventEnvelopeProof({
      actorId: eventSigningPrincipalId(event),
      event,
      verificationMethod: args.proofVerificationMethod,
    }),
  };
}

/// A Realm genesis envelope together with the Realm id it derives.
///
/// The genesis is the one Event that MUST NOT carry `realm_id` on the wire
/// while its caller still has to learn the Realm id, so the pair is returned
/// rather than smuggled through the envelope.
export function signedRealmGenesisEnvelope(args: SignedEventEnvelopeArgs): {
  envelope: Record<string, unknown>;
  realmId: string;
} {
  const envelope = signedEventEnvelope(args);
  const eventId = stringValue(envelope.event_id);
  if (!eventId) {
    throw new Error("Realm genesis Event is missing event_id");
  }
  // Re-derived from the finished envelope rather than recomputed here: the
  // genesis Realm id is protocol arithmetic and belongs to the SDK, not to a
  // second implementation in the harness.
  return { envelope, realmId: sdkEventDerivedIds(envelope).realm_id };
}

export function refreshEventEnvelopeProof(
  envelope: Record<string, unknown>,
  proofVerificationMethod?: string,
): void {
  const actorId = eventSigningPrincipalId(envelope);
  const event = { ...envelope };
  delete event.producer_proof;
  // An Event id is a
  // function of that digest, so re-signing without re-deriving would leave the
  // envelope carrying the id of content it no longer has.
  delete event.event_id;
  const derived = sdkEventDerivedIds(event);
  event.event_id = derived.event_id;
  envelope.event_id = derived.event_id;
  envelope.producer_proof = eventEnvelopeProof({
    actorId,
    event,
    verificationMethod: proofVerificationMethod,
  });
}

function eventEnvelopeProof(args: {
  actorId: string;
  event: Record<string, unknown>;
  verificationMethod?: string;
}): Record<string, unknown> {
  const mode = eventProofMode();
  const registeredSigner = eventSignerFor(
    args.actorId,
    args.verificationMethod,
  );
  // event-envelope.schema.json: a did_core_id is never concatenated into a DID
  // URL. Without this guard an unregistered `ak:did_core:` actor silently
  // produced `ak:did_core:...#device`, which only surfaces later as an opaque
  // SDK parse error instead of naming the missing registerEventSigner call.
  const fallbackVerificationMethod = args.actorId.startsWith("did:")
    ? `${args.actorId}#device`
    : undefined;
  const verificationMethod =
    args.verificationMethod ??
    registeredSigner?.verificationMethod ??
    fallbackVerificationMethod;
  if (verificationMethod === undefined) {
    throw new Error(
      `no event signer registered for ${args.actorId}; call registerEventSigner ` +
        "with a DID URL verification method before authoring its Events",
    );
  }
  // device-lifecycle.md section 8.2.2: every Event a human device signs uses
  // the same producer proof, whatever its kind. There is no Control/Data split
  // and the proof carries no signer evidence ref; the governance Station
  // resolves the signer itself.
  if (!stringValue(args.event.kind)) {
    throw new Error("event proof requires a string Event kind");
  }
  const createdAt = canonicalEventTimestamp();

  if (mode === "dev-proof") {
    const eventDigest = `sha256:${sha256CanonicalJson(args.event)}`;
    return {
      type: "dev-proof",
      verification_method: verificationMethod,
      event_digest: eventDigest,
    };
  }

  // The resolved verification method is always a DID URL (explicit argument,
  // registered signer, or the `did:`-only fallback above), so its DID prefix is
  // the authoring DID the SDK projects back to `args.actorId`. Falling back to
  // `args.actorId` instead would hand the wire CLI a projected core id.
  return sdkEventEnvelopeProof({
    actorDid: verificationMethod.split("#", 1)[0]!,
    event: args.event,
    verificationMethod,
    createdAt,
    signingSeedB64url: registeredSigner?.signingSeedB64url,
  });
}

/// Submit one producer-signed Event to its Realm's current governance Station.
///
/// The producer Event carries no position, predecessor or coverage: the Station
/// supplies all three by returning the `RealmCommit` that admitted it. There is
/// A temporarily unavailable cut is retried with the exact signed submission;
/// an admission refusal fails immediately without re-authoring the Event.
export async function submitSignedEventApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: {
    server?: SolandKey;
    context?: string;
    controlObserverToken?: string;
    retryTemporarilyUnavailable?: boolean;
  } = {},
) {
  const context = opts.context ?? `submit ${String(envelope.kind)}`;
  const eventsUrl = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
  const submission = canonicalJson({ event: envelope });
  const deadline = Date.now() + 30_000;
  let response: APIResponse;
  let text: string;
  for (;;) {
    response = await request.post(eventsUrl, {
      headers: {
        ...authHeaders(token, "POST", eventsUrl),
        "content-type": "application/json",
      },
      data: submission,
    });
    text = await response.text();
    if (response.status() !== 503 || Date.now() >= deadline || opts.retryTemporarilyUnavailable === false) break;
    let problem: unknown;
    try { problem = JSON.parse(text); } catch { break; }
    if (wireErrCode(problem) !== "temporarily_unavailable") break;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  expect(
    [200, 201],
    `${context} returned ${response.status()}: ${text}`,
  ).toContain(response.status());
  const outcome = JSON.parse(text) as Record<string, unknown>;
  assertAuthoritySubmitOutcome(outcome, envelope, context);
  rememberPublicationEvidence([envelope], outcome, {
    token: opts.controlObserverToken ?? token,
    server: opts.server,
  });
  return outcome;
}

/// The commit the Station returns must admit the exact Event that was
/// submitted, into the one stream that Event's scope names.
///
/// `CommitStreamRef` is closed to `realm` / `circle` / `sidecar`; there is no
/// Realm-global chain and no Realm-global position, so the only ordering the
/// outcome may carry is `stream_position` inside `stream_ref`.
export function assertAuthoritySubmitOutcome(
  outcome: Record<string, unknown>,
  envelope: Record<string, unknown>,
  context: string,
): void {
  const status = stringValue(outcome.status);
  expect(
    ["committed", "duplicate"],
    `${context}: unexpected submit status ${String(status)}`,
  ).toContain(status);
  const commit = outcome.commit as Record<string, unknown> | undefined;
  if (!commit) {
    throw new Error(`${context}: an accepted submission returns its RealmCommit`);
  }
  expect(commit.event_ref, `${context}: commit does not name the submitted Event`)
    .toBe(envelope.event_id);
  const streamRef = commit.stream_ref as Record<string, unknown> | undefined;
  const kind = stringValue(streamRef?.kind);
  expect(
    ["realm", "circle", "sidecar"],
    `${context}: unregistered commit stream kind ${String(kind)}`,
  ).toContain(kind);
  expect(
    commitStreamRefForScope(envelope),
    `${context}: the commit landed in another stream`,
  ).toEqual(streamRef);
  expect(
    typeof commit.stream_position === "number" &&
      Number.isSafeInteger(commit.stream_position),
    `${context}: a commit carries an integer stream_position`,
  ).toBe(true);
  for (const forbidden of [
    "global_position",
    "realm_position",
    "seal_ref",
    "frontier",
  ]) {
    expect(
      forbidden in commit,
      `${context}: the commit reintroduced ${forbidden}`,
    ).toBe(false);
  }
  if (commit.stream_position === 0) {
    expect(
      commit.previous_commit_ref ?? null,
      `${context}: the first commit of a stream has no predecessor`,
    ).toBeNull();
  } else {
    expect(
      typeof commit.previous_commit_ref === "string",
      `${context}: every successor commit names its predecessor`,
    ).toBe(true);
  }
}

/// The commit stream an Event's own `scope_ref` selects.
export function commitStreamRefForScope(
  envelope: Record<string, unknown>,
): Record<string, unknown> {
  const scope = envelope.scope_ref as Record<string, unknown> | undefined;
  const realmId = scope?.kind === "realm_genesis"
    ? sdkEventDerivedIds(envelope).realm_id
    : stringValue(envelope.realm_id) ?? stringValue(scope?.realm_id);
  if (!realmId) {
    throw new Error("an Event outside Realm genesis carries its realm_id");
  }
  switch (stringValue(scope?.kind)) {
    case "circle":
      return { kind: "circle", realm_id: realmId, circle_id: scope!.circle_id };
    case "sidecar":
      return {
        kind: "sidecar",
        realm_id: realmId,
        sidecar_id: scope!.sidecar_id,
      };
    default:
      // `realm` and `realm_genesis` both commit into the Realm stream.
      return { kind: "realm", realm_id: realmId };
  }
}

/// The `EventAdmissionSubmission` DTO: one producer Event and any required
/// approval signatures. This helper is used only for events without an
/// approval-layer requirement.
///
/// There is exactly one Event submission shape in the authority-commit
/// protocol. A prepared submission therefore carries no lease, no precondition
/// set and no chain material — the Station derives every ordering fact from its
/// own stream when it mints the `RealmCommit`.
export async function prepareSignedEventSubmissionApi(
  _request: APIRequestContext,
  _token: string,
  envelope: Record<string, unknown>,
  _opts: { server?: SolandKey; context?: string } = {},
): Promise<Record<string, unknown>> {
  return { event: envelope };
}

/// Prepare several independent `EventAdmissionSubmission` bodies.
///
/// This helper returns separate requests. Registered atomic units use the
/// closed branches of `self_submit_request` and must be constructed explicitly.
export async function prepareSignedEventBatchSubmissionsApi(
  _request: APIRequestContext,
  _token: string,
  events: Array<Record<string, unknown>>,
  _opts: { server?: SolandKey; context?: string } = {},
): Promise<Array<Record<string, unknown>>> {
  return events.map((event) => ({ event }));
}

/**
 * Submit a signed Event and hand back the raw response.
 *
 * Negative cases need the Station's own verdict bytes: an authority that
 * refuses an Event answers with a reason code rather than a commit, and that
 * refusal is the assertion. There is no preparation call to make first and no
 * retry ladder to climb — the producer Event is complete when it is signed.
 */
export async function rawSubmitSignedEventApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: { server?: SolandKey } = {},
): Promise<APIResponse> {
  const eventsUrl = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
  return await request.post(eventsUrl, {
    headers: {
      ...authHeaders(token, "POST", eventsUrl),
      "content-type": "application/json",
    },
    data: canonicalJson({ event: envelope }),
  });
}

function parseJsonOrRaw(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { raw: text };
  }
}

// Where each Event this process published was accepted. Federation reads the
// exact accepted `(RealmCommit, Event)` pair back from that source Station
// (`CommittedEventView`), so only the caller-scoped source is remembered.
const publicationSourceByEventId = new Map<string, { token: string; server?: SolandKey }>();

function rememberPublicationEvidence(
  events: Array<Record<string, unknown>>,
  outcome: Record<string, unknown>,
  source: { token: string; server?: SolandKey },
): void {
  const commits = Array.isArray(outcome.commits)
    ? (outcome.commits as Array<Record<string, unknown>>)
    : outcome.commit
      ? [outcome.commit as Record<string, unknown>]
      : [];
  if (commits.length !== 0 && commits.length !== events.length) {
    throw new Error(
      `publication returned ${commits.length} RealmCommits for ${events.length} Events: ${JSON.stringify(
        {
          status: outcome.status,
          reason_code: outcome.reason_code,
        },
      )}`,
    );
  }
  events.forEach((event) => {
    const eventId = stringValue(event.event_id);
    if (!eventId) {
      throw new Error("published Event is missing event_id");
    }
    publicationSourceByEventId.set(eventId, source);
  });
}

/// Wait until every Event submitted for `realmId` is durably committed.
///
/// `ak.self.events.command.submit.v1` answers with the RealmCommit it produced,
/// so acceptance is already synchronous; what can still lag is the Station's
/// own projection of that commit. Callers that need the projection read it
/// back directly, so this is now a no-op kept for call-site readability.
/// The current head of one independent commit stream.
///
/// `ak.self.committed_event.read.scan.v1` returns accepted `{commit, event}` pairs in
/// stream order; the last one is the head. A Realm, each Circle and each
/// Sidecar own separate linear streams, so a head only ever names its own.
export async function readCommitStreamHeadApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey; streamRef?: Record<string, unknown> } = {},
): Promise<CommitStreamHead | undefined> {
  const streamRef = opts.streamRef ?? { kind: "realm", realm_id: realmId };
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/streams/scan`;
  let afterPosition: number | null = null;
  let head: CommitStreamHead | undefined;
  for (;;) {
    const response = await request.post(url, {
      headers: {
        ...authHeaders(token, "POST", url),
        "content-type": "application/json",
      },
      data: canonicalJson({
        realm_id: realmId,
        stream_ref: streamRef,
        after_position: afterPosition,
        limit: 256,
      }),
    });
    const body = await expectJsonOk<{
      committed_events: Array<{ commit: CommitStreamHead & { stream_position: number } }>;
      truncated: boolean;
    }>(response, `scan commit stream for ${realmId}`);
    const commits = body.committed_events;
    expect(Array.isArray(commits), "stream scan must return committed_events").toBeTruthy();
    if (commits.length === 0) return head;
    const last = commits[commits.length - 1]!.commit;
    head = {
      stream_ref: streamRef as CommitStreamHead["stream_ref"],
      stream_position: last.stream_position,
      commit_id: last.commit_id,
    };
    if (!body.truncated) return head;
    afterPosition = last.stream_position;
  }
}

// COT-06-004: discover a Realm's default discussion Strand via the projection face.
// Realm and Strand identities are independent Event-derived tokens; neither can
// be retyped from the other's token. The spec-faithful source of truth
// is the Realm projection's authoritative `default_strand_id` (nullable), with the
// Strand projection's derived `is_default` marker as a fallback discovery path.
export async function resolveDefaultStrandId(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: {
    server?: SolandKey;
    authorityRootController?: string;
  } = {},
): Promise<string> {
  const realmUrl = `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
  const strandsUrl = `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}/strands`;
  const actorId = await currentActorIdApi(request, token, opts);
  const controller = realmAuthorityControllers.get(
    realmAuthorityControllerKey(opts.server, realmId),
  );
  if (opts.authorityRootController === undefined &&
      canonicalJson(controller ?? null) !== canonicalJson(accountActorId(actorId, opts.server))) {
    let observed: string | undefined;
    await expect.poll(async () => {
      const response = await request.get(realmUrl, {
        headers: authHeaders(token, "GET", realmUrl),
      });
      if (response.ok()) {
        const realm = await response.json() as { default_strand_id?: unknown };
        if (typeof realm.default_strand_id === "string" && realm.default_strand_id) {
          observed = realm.default_strand_id;
          return true;
        }
      } else if (![403, 404].includes(response.status())) {
        throw new Error(`default Strand read returned ${response.status()}`);
      }
      const responseStrands = await request.get(strandsUrl, {
        headers: authHeaders(token, "GET", strandsUrl),
      });
      if (![200, 403, 404].includes(responseStrands.status())) {
        throw new Error(`default Strand projection returned ${responseStrands.status()}`);
      }
      if (responseStrands.ok()) {
        const projection = await responseStrands.json() as {
          strands?: Array<{ strand_id?: string; is_default?: boolean }>;
        };
        observed = projection.strands?.find((strand) => strand.is_default)?.strand_id;
      }
      return observed !== undefined;
    }, { timeout: 45_000, intervals: [100, 250, 500, 1_000],
      message: `accepted default Strand reaches member Station for ${realmId}` }).toBe(true);
    return observed!;
  }

  // Primary: Realm projection carries the authoritative default_strand_id.
  const realmResp = await request.get(realmUrl, {
    headers: authHeaders(token, "GET", realmUrl),
  });
  if (realmResp.ok()) {
    const realm = (await realmResp.json()) as { default_strand_id?: unknown };
    if (
      typeof realm.default_strand_id === "string" &&
      realm.default_strand_id
    ) {
      return realm.default_strand_id;
    }
  }

  // Fallback: discover via the Strand projection's derived is_default marker.
  const flowsResp = await request.get(strandsUrl, {
    headers: authHeaders(token, "GET", strandsUrl),
  });
  expect(
    flowsResp.ok(),
    `resolveDefaultStrandId: strand projection for ${realmId} returned ${flowsResp.status()}`,
  ).toBeTruthy();
  const body = (await flowsResp.json()) as {
    strands?: Array<{ strand_id?: string; is_default?: boolean }>;
  };
  const strands = body.strands ?? [];
  const def = strands.find((strand) => strand.is_default === true);
  if (def?.strand_id) {
    return def.strand_id;
  }
  if (opts.authorityRootController !== undefined) {
    expect(
      requireDidCoreId(opts.authorityRootController),
      "default Strand fixture authority-root controller must match the authenticated actor",
    ).toBe(requireDidCoreId(actorId));
    // UI-authored Realm bootstrap is outside this API helper's in-memory
    // registry. The fixture supplies the genesis actor it just observed so
    // applyRegisteredCbsPlane can stamp the explicit authority-root claim;
    // Soland still validates that claim against the accepted Seal state.
    realmAuthorityControllers.set(
      realmAuthorityControllerKey(opts.server, realmId),
      accountActorId(actorId, opts.server),
    );
  }
  const createdAt = canonicalTimestamp();
  const envelope = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.strand.create",
    server: opts.server,
    createdAt,
    payload: {
      object: {
        schema: "ak.schema.strand.v1",
        realm_id: realmId,
        tracks: {
          discussion: {
            enabled: true,
            is_primary: true,
            profile: "discussion",
          },
        },
        created_by: accountActorId(actorId, opts.server),
        created_at: createdAt,
      },
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `create discussion Strand for ${realmId}`,
  });
  const strandId = retypeEventDerivedId(String(envelope.event_id), "strand");
  await expect
    .poll(
      async () => {
        const response = await request.get(strandsUrl, {
          headers: authHeaders(token, "GET", strandsUrl),
        });
        if (!response.ok()) return false;
        const body = (await response.json()) as {
          strands?: Array<{ strand_id?: string }>;
        };
        return (body.strands ?? []).some(
          (strand) => strand.strand_id === strandId,
        );
      },
      {
        message: `discussion Strand ${strandId} reaches the accepted projection`,
        timeout: 30_000,
        intervals: [100, 250, 500, 1_000],
      },
    )
    .toBe(true);
  const setDefault = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.realm.set_default_strand",
    server: opts.server,
    payload: { realm_id: realmId, strand_id: strandId },
  });
  await submitSignedEventApi(request, token, setDefault, {
    server: opts.server,
    context: `set default discussion Strand for ${realmId}`,
  });
  await expect
    .poll(
      async () => {
        const response = await request.get(strandsUrl, {
          headers: authHeaders(token, "GET", strandsUrl),
        });
        if (!response.ok()) return false;
        const body = (await response.json()) as {
          strands?: Array<{
            strand_id?: string;
            is_default?: boolean;
          }>;
        };
        return (body.strands ?? []).some(
          (strand) =>
            strand.strand_id === strandId && strand.is_default === true,
        );
      },
      {
        message: `Realm ${realmId} projects default Strand ${strandId}`,
        timeout: 30_000,
        intervals: [100, 250, 500, 1_000],
      },
    )
    .toBe(true);
  return strandId;
}

export function canonicalTimestamp(date: Date = new Date()): string {
  if (!Number.isFinite(date.getTime())) {
    throw new TypeError("invalid canonical timestamp");
  }
  return date.toISOString();
}

export function canonicalEventTimestamp(date: Date = new Date()): string {
  // Event Envelope `created_at` is canonical only with exactly three UTC
  // fractional digits (`YYYY-MM-DDTHH:mm:ss.SSSZ`). `Date#toISOString`
  // already emits precisely that wire form.
  if (!Number.isFinite(date.getTime())) {
    throw new TypeError("invalid Event Envelope created_at");
  }
  return date.toISOString();
}


export function makeFederationEvent(args: {
  eventId?: string;
  actorId?: string;
  realmId: string;
  kind: string;
  payload: Record<string, unknown>;
  sealBasis?: Record<string, unknown>;
}) {
  return signedEventEnvelope({
    eventId: args.eventId,
    actorId: args.actorId ?? "did:web:cotest-federation.example",
    realmId: args.realmId,
    kind: args.kind,
    payload: args.payload,
  });
}

// `authority-commit-operations.schema.json#/$defs/peer_committed_replication_outcome_record`.
export type PeerCommittedReplicationOutcomeRecord =
  | { status: "stored" | "duplicate" }
  | { status: "rejected"; reason_code: string };

// `authority-commit-operations.schema.json#/$defs/peer_committed_replication_outcome`:
// `replication_outcomes` has exactly the length and order of the request's
// `replications`, so a row is identified by its position alone. There is no
// top-level `accepted[]` / `duplicate[]` (api-conventions.md, Event submit).
export type PeerCommittedReplicationOutcome = {
  branch: "committed_replication";
  replication_outcomes: PeerCommittedReplicationOutcomeRecord[];
};

/// Push exact source-committed `(Event, RealmCommit)` pairs to a peer through
/// the `committed_replication` branch of `ak.peer.events.command.submit.v1`
/// and return the per-item outcome, checked against the request order.
export async function pushFederationEvents(
  request: APIRequestContext,
  events: Array<Record<string, unknown>>,
  opts: {
    origin: string;
    destination?: string;
    realmId: string;
    server?: SolandKey;
  },
): Promise<PeerCommittedReplicationOutcome> {
  const response = await rawPushFederationEvents(request, events, opts);
  const outcome = await expectJsonOk<PeerCommittedReplicationOutcome>(
    response,
    "push federation events",
  );
  expect(outcome.branch).toBe("committed_replication");
  expect(outcome.replication_outcomes).toHaveLength(events.length);
  return outcome;
}

/// The items of `outcome` whose status is not in `allowed`, paired with the
/// Event they judged, for readable assertion messages.
export function replicationOutcomesOutside(
  events: Array<Record<string, unknown>>,
  outcome: PeerCommittedReplicationOutcome,
  allowed: ReadonlyArray<PeerCommittedReplicationOutcomeRecord["status"]>,
): Array<{ event_id: unknown; kind: unknown } & PeerCommittedReplicationOutcomeRecord> {
  return outcome.replication_outcomes.flatMap((record, index) =>
    allowed.includes(record.status)
      ? []
      : [{ event_id: events[index]?.event_id, kind: events[index]?.kind, ...record }],
  );
}

type PeerPushOpts = {
  origin: string;
  destination?: string;
  realmId: string;
  server?: SolandKey;
  tamperSignature?: boolean;
  // Negative-coverage hook: drive the RFC 9421 freshness window past its
  // bound so verify rejects on expiry (federation.md §3.2). The signature
  // itself stays cryptographically valid — only created/expires are stale.
  expireSignature?: boolean;
  relaySourceServiceId?: string;
};

export async function rawPushFederationEvents(
  request: APIRequestContext,
  events: Array<Record<string, unknown>>,
  opts: PeerPushOpts & {
    // Applet transactions accept Events outside the self-submit helper's
    // publication cache. Resolve their original accepted bytes at this source.
    acceptedSource?: { token: string; server?: SolandKey };
  },
) {
  return await rawPushCommittedReplication(
    request,
    await committedReplicationRows(request, events, opts, opts.acceptedSource),
    opts,
  );
}

/// Replicate already paired `(RealmCommit, Event)` rows, e.g. a page read
/// through `scanPeerRealmStreamApi`, and return the per-item outcome.
export async function pushCommittedRowsApi(
  request: APIRequestContext,
  rows: CommittedEventFullView[],
  opts: PeerPushOpts,
): Promise<PeerCommittedReplicationOutcome> {
  const response = await rawPushCommittedReplication(
    request,
    rows.map(committedRowForReplication),
    opts,
  );
  const outcome = await expectJsonOk<PeerCommittedReplicationOutcome>(
    response,
    "push committed rows",
  );
  expect(outcome.branch).toBe("committed_replication");
  expect(outcome.replication_outcomes).toHaveLength(rows.length);
  return outcome;
}

async function rawPushCommittedReplication(
  request: APIRequestContext,
  replications: CommittedEventSubmission[],
  opts: PeerPushOpts,
) {
  const destination = opts.destination ?? solandServiceId(opts.server);
  const url = `${solandBaseUrl(opts.server)}/_arkret/peer/events`;
  const body = peerCommittedReplicationBody(opts.realmId, replications);
  const sourceServiceId = opts.relaySourceServiceId ?? opts.origin;
  // `ak.peer.events.command.submit.v1` is `canonical_hash / full_body`: the
  // replay identity is the complete canonical body, never an Idempotency-Key.
  const headers = signedFederationPushHeaders(
    sourceServiceId,
    destination,
    url,
    body,
    { expireSignature: opts.expireSignature },
  );
  if (opts.tamperSignature) {
    headers.signature = `sig1=:${Buffer.alloc(64).toString("base64")}:`;
  }
  return await request.post(url, {
    data: canonicalJson(body),
    headers,
  });
}

// `invite-delivery-request.schema.json` is a closed object, so the body is
// generated. The hand-written version modelled `invite_event` and
// `introduction_evidence` as opaque records and omitted the address members
// the schema actually requires.
export type InviteDeliveryRequestBodyBodyBody = InviteDeliveryRequestBody;
export type { SelfInviteDispatchRequestBody };
// The closed `invite_delivery_outcome`
// (`invite-delivery-request.schema.json#/$defs/invite_delivery_outcome`).
// `disclosed_outcome` is closed to `delivered | blocked` and, per
// invite-addressing.md §5.1, MUST be absent whenever `status` is `deferred`.
export type InviteDeliveryOutcomeView = {
  status: "accepted" | "duplicate" | "deferred";
  disclosed_outcome?: "delivered" | "blocked";
  received_at?: string;
  retry_after_ms?: number;
};

// Build the §7 dispatch body from the accepted Event id. The Station
// resolves its own stored canonical Event bytes; clients never echo them.
// `idempotency_key` defaults to the accepted `event_id` so an uncertain
// transport outcome is retried with the same body and the same key, exactly as
// §7 requires.
export function selfInviteDispatchBody(args: {
  eventId: string;
  inviteAddress: InviteDeliveryRequestBodyBodyBody["invite_address"];
  evidence: InviteDeliveryRequestBodyBodyBody["introduction_evidence"];
  idempotencyKey?: string;
}): SelfInviteDispatchRequestBody {
  return {
    schema: "ak.schema.invite_delivery_request.v1",
    invite_event_id: args.eventId,
    invite_address: args.inviteAddress,
    introduction_evidence: args.evidence,
    idempotency_key: args.idempotencyKey ?? args.eventId,
  };
}

export async function dispatchSelfInviteApi(
  request: APIRequestContext,
  token: string,
  body: SelfInviteDispatchRequestBody,
  opts: { server?: SolandKey } = {},
): Promise<InviteDeliveryOutcomeView> {
  const response = await rawDispatchSelfInviteApi(request, token, body, opts);
  return await expectJsonOk<InviteDeliveryOutcomeView>(
    response,
    "dispatch self invite delivery",
  );
}

export async function rawDispatchSelfInviteApi(
  request: APIRequestContext,
  token: string,
  body: SelfInviteDispatchRequestBody,
  opts: { server?: SolandKey } = {},
) {
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/invites/dispatch`;
  return await request.post(url, {
    data: canonicalJson(body),
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
  });
}

// ── Peer-layer direct submission. NOT a client path. ──
//
// `ak.peer.invites.command.submit.v1` is a Station-to-Station
// operation: invite-addressing.md §7 step 1 binds it to verified S2S
// authentication. This helper self-signs those federation headers, so calling
// it makes the test process impersonate an inviter Station. That is
// legitimate ONLY for exercising the receiving side directly — peer-layer
// negative cases and cross-server receive-policy coverage. A test that models
// what a conforming CLIENT does MUST use `dispatchSelfInviteApi` instead; §7
// forbids clients from synthesizing federation trust headers or faking a peer
// session.
export async function submitPeerInviteDeliveryApi(
  request: APIRequestContext,
  body: InviteDeliveryRequestBodyBodyBody,
  opts: {
    origin: string;
    destination?: string;
    server?: SolandKey;
  },
) {
  const response = await rawSubmitPeerInviteDeliveryApi(request, body, opts);
  return await expectJsonOk<InviteDeliveryOutcomeView>(
    response,
    "submit peer invite delivery",
  );
}
// Same peer submission without the 2xx expectation, so a notification rejection
// can be read as a status plus a registered wire code.
export async function rawSubmitPeerInviteDeliveryApi(
  request: APIRequestContext,
  body: InviteDeliveryRequestBodyBodyBody,
  opts: {
    origin: string;
    destination?: string;
    server?: SolandKey;
  },
) {
  const destination =
    opts.destination ?? body.invite_address.account_id.station_id;
  const url = `${solandBaseUrl(opts.server)}/_arkret/peer/invites`;
  return await request.post(url, {
    data: canonicalJson(body),
    headers: signedFederationPushHeaders(opts.origin, destination, url, body),
  });
}

// `authority-commit-operations.schema.json#/$defs/committed_event_submission`:
// the exact source Event as `{event}` (never `approval_signatures`) paired with
// the source-signed RealmCommit that accepted it.
type CommittedEventSubmission = {
  event_submission: { event: Record<string, unknown> };
  source_commit: Record<string, unknown>;
  producer_signer_fact?: Record<string, unknown>;
  genesis_event_ref?: string;
  welcomes?: Array<Record<string, unknown>>;
};

async function committedReplicationRows(
  request: APIRequestContext,
  events: Array<Record<string, unknown>>,
  opts: PeerPushOpts,
  acceptedSource?: { token: string; server?: SolandKey },
): Promise<CommittedEventSubmission[]> {
  return Promise.all(events.map(async (event) => {
    const eventId = stringValue(event.event_id);
    const source = (eventId ? publicationSourceByEventId.get(eventId) : undefined) ?? acceptedSource;
    if (!eventId || !source) {
      throw new Error(`federation requires an accepted source Event: ${eventId ?? "<missing event_id>"}`);
    }
    if (event.kind === "ak.mls.commit") {
      // A replicated MLS Commit also needs the governance-frozen
      // `genesis_event_ref`; this helper has no such provenance to carry.
      throw new Error(`committed replication of ak.mls.commit ${eventId} needs genesis_event_ref`);
    }
    // Read the exact accepted Event and covering Commit from the registered
    // caller-scoped resource. A withheld view cannot be forwarded as an Event.
    const url = `${solandBaseUrl(source.server)}/_arkret/self/committed-events/${eventId}`;
    const response = await request.get(url, {
      headers: authHeaders(source.token, "GET", url),
    });
    const view = await expectJsonOk<{
      commit?: Record<string, unknown>;
      event?: Record<string, unknown>;
    }>(response, "read accepted source Event for federation");
    if (!view.event || view.event.event_id !== eventId || !view.commit) {
      throw new Error(`source Station did not disclose the accepted Event ${eventId}`);
    }
    const original = { event: view.event, commit: view.commit };
    if (view.commit.producer_signer_fact_digest !== undefined) {
      // Self Full deliberately has no peer-only facts. Read only the existing
      // destination-authorized peer scan, at this exact Realm-stream position.
      const stream = view.commit.stream_ref as Record<string, unknown> | undefined;
      const position = view.commit.stream_position;
      if (stream?.kind !== "realm" || stream.realm_id !== opts.realmId ||
          !Number.isSafeInteger(position) || Number(position) < 0) {
        throw new Error("replication source lacks an authorized original signer fact carrier");
      }
      const page = await scanPeerRealmStreamApi(request, {
        server: source.server ?? "server1",
        sourceServiceId: opts.destination ?? solandServiceId(opts.server),
        realmId: opts.realmId,
        afterPosition: Number(position) === 0 ? null : Number(position) - 1,
        limit: 1,
      });
      const rows = fullCommittedRows(page);
      if (rows.length !== 1 || canonicalJson(rows[0]) !== canonicalJson(original)) {
        throw new Error("authorized peer source does not disclose the exact original Event and Commit");
      }
      return committedRowForReplication(rows[0]);
    }
    return committedRowForReplication(original);
  }));
}

// `service-operation-dtos.schema.json#/$defs/CommittedEventView`, full branch:
// one RealmCommit with the exact producer-signed Event it accepted.
export type CommittedEventFullView = {
  commit: Record<string, unknown>;
  event: Record<string, unknown>;
};

// `authority-commit-operations.schema.json#/$defs/stream_scan_outcome`.
export type StreamScanOutcome = {
  committed_events: Array<CommittedEventFullView | {
    commit: Record<string, unknown>;
    event_disclosure: Record<string, unknown>;
  }>;
  readable_floor?: {
    oldest_position: number;
    floor_commit_id: string;
    floor_reason: "stream_start" | "membership_join" | "history_access_policy";
  };
  truncated: boolean;
};

/// `ak.peer.committed_event.read.scan.v1`: one Station replicates one
/// visibility-authorized stream from the Realm's current governance Station
/// (federation.md §3). The request is signed as `sourceServiceId`; the Realm
/// stream is scanned upward from the caller's readable floor.
export async function scanPeerRealmStreamApi(
  request: APIRequestContext,
  opts: {
    server: SolandKey;
    sourceServiceId: string;
    realmId: string;
    afterPosition?: number | null;
    limit?: number;
  },
): Promise<StreamScanOutcome> {
  const body = {
    realm_id: opts.realmId,
    stream_ref: { kind: "realm", realm_id: opts.realmId },
    after_position: opts.afterPosition ?? null,
    limit: opts.limit ?? 100,
  };
  const targetUri = `${solandBaseUrl(opts.server)}/_arkret/peer/streams/scan`;
  const response = await request.post(targetUri, {
    data: canonicalJson(body),
    headers: signedFederationPushHeaders(
      opts.sourceServiceId,
      solandServiceId(opts.server),
      targetUri,
      body,
    ),
  });
  return await expectJsonOk<StreamScanOutcome>(response, "scan peer Realm stream");
}

/// The full rows of a scan page, in stream order. A withheld row carries no
/// Event bytes and can never be replicated as one.
// Local association only: Full remains the official closed {event, commit}.
// Peer-only facts belong to the registered page sibling, never to self Full.
const originalPeerRowMaterials = new WeakMap<CommittedEventFullView, {
  originalFull: string;
  producerSignerFact?: Record<string, unknown>;
}>();

function committedRowForReplication(row: CommittedEventFullView): CommittedEventSubmission {
  const material = originalPeerRowMaterials.get(row);
  if (material && material.originalFull !== canonicalJson(row)) {
    throw new Error("replication original changed after its authorized peer scan");
  }
  if (row.event.event_id !== row.commit.event_ref) {
    throw new Error("replication requires the exact original Event and covering Commit");
  }
  // These two registered readers do not carry governance-frozen MLS Genesis
  // or destination Welcome inventory. Never infer either from a base/current.
  if (row.event.kind === "ak.mls.commit") {
    throw new Error("replicated MLS Commit requires original genesis_event_ref provenance");
  }
  const digest = row.commit.producer_signer_fact_digest;
  const fact = material?.producerSignerFact;
  if ((digest !== undefined) !== (fact !== undefined) || digest === null ||
      (digest !== undefined && (typeof digest !== "string" ||
        digest !== `sha256:${sha256CanonicalJson(fact)}`))) {
    throw new Error("replication signer fact and original Commit digest must match");
  }
  return {
    event_submission: { event: row.event }, source_commit: row.commit,
    ...(fact === undefined ? {} : { producer_signer_fact: fact }),
  };
}

export function fullCommittedRows(page: StreamScanOutcome): CommittedEventFullView[] {
  // Match the SDK PeerStreamScanOutcome ordered exact-target association.
  const facts = (page as unknown as Record<string, unknown>).producer_signer_facts;
  if (!Array.isArray(facts)) {
    throw new Error("authorized peer scan lacks its registered original signer fact inventory");
  }
  const rows = page.committed_events.filter(
    (row): row is CommittedEventFullView => "event" in row,
  );
  let next = 0;
  for (const row of rows) {
    let fact: Record<string, unknown> | undefined;
    if (row.commit.producer_signer_fact_digest !== undefined) {
      const entry = facts[next++] as { target?: unknown; producer_signer_fact?: unknown } | undefined;
      const target = {
        event_id: row.event.event_id, commit_id: row.commit.commit_id,
        stream_ref: row.commit.stream_ref, stream_position: row.commit.stream_position,
      };
      if (!entry || canonicalJson(entry.target) !== canonicalJson(target) ||
          !entry.producer_signer_fact || typeof entry.producer_signer_fact !== "object" ||
          Array.isArray(entry.producer_signer_fact)) {
        throw new Error("peer Full row lacks its exact ordered original signer fact");
      }
      fact = entry.producer_signer_fact as Record<string, unknown>;
      if (row.commit.producer_signer_fact_digest !== `sha256:${sha256CanonicalJson(fact)}`) {
        throw new Error("peer original signer fact differs from its original Commit digest");
      }
    }
    originalPeerRowMaterials.set(row, {
      originalFull: canonicalJson(row), producerSignerFact: fact,
    });
  }
  if (next !== facts.length) {
    throw new Error("peer scan contains extra or unordered original signer facts");
  }
  return rows;
}

/// Every full row of the Realm stream that `sourceServiceId` may read from
/// `server`, in stream order. Continuation is the largest `stream_position`
/// of the previous page; the scan stops when a page is not truncated.
export async function scanPeerRealmStreamRowsApi(
  request: APIRequestContext,
  opts: { server: SolandKey; sourceServiceId: string; realmId: string },
): Promise<CommittedEventFullView[]> {
  const rows: CommittedEventFullView[] = [];
  let afterPosition: number | null = null;
  for (let page = 0; page < 100; page += 1) {
    const outcome = await scanPeerRealmStreamApi(request, {
      ...opts,
      afterPosition,
      limit: 1000,
    });
    rows.push(...fullCommittedRows(outcome));
    const last = outcome.committed_events.at(-1);
    if (!outcome.truncated || !last) return rows;
    afterPosition = Number(last.commit.stream_position);
  }
  throw new Error(`peer scan of ${opts.realmId} did not reach the readable head`);
}

function schemaIdForEventKind(kind: string): string {
  if (kind === "ak.message.create") {
    return "ak.schema.message.v1";
  }
  if (kind === "ak.message.redact") {
    return "ak.schema.message.v1";
  }
  if (kind === "ak.member.state") {
    return "ak.schema.event_payload.v1";
  }
  if (kind.startsWith("ak.space.")) {
    return "ak.schema.space.v1";
  }
  return "ak.schema.event.v1";
}

// helpers → e2e → cotest → arkret root → arkret-spec/spec/v1/artifacts.
const SPEC_ARTIFACTS_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "arkret-spec",
  "spec",
  "v1",
  "artifacts",
);

let fixtureCapabilityActionCache: Map<string, string> | undefined;
let realmRootAuthorableEventKinds: Set<string> | undefined;

function fixtureCapabilityAction(eventKind: string): string {
  if (!fixtureCapabilityActionCache) {
    const registry = JSON.parse(
      readFileSync(
        join(
          SPEC_ARTIFACTS_ROOT,
          "registry",
          "capability-action-registry.json",
        ),
        "utf8",
      ),
    ) as {
      actions?: Array<{
        action?: unknown;
        target_event_kinds?: unknown;
      }>;
    };
    fixtureCapabilityActionCache = new Map();
    for (const row of registry.actions ?? []) {
      if (
        typeof row.action !== "string" ||
        !Array.isArray(row.target_event_kinds)
      ) {
        continue;
      }
      for (const target of row.target_event_kinds) {
        if (typeof target === "string") {
          const previous = fixtureCapabilityActionCache.get(target);
          if (!previous || row.action === target) {
            fixtureCapabilityActionCache.set(target, row.action);
          }
        }
      }
    }
  }
  return fixtureCapabilityActionCache.get(eventKind) ?? "ak.realm.admin";
}

const E2E_FIXTURES_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "fixtures",
);

// `authority-commit-operations.schema.json#/$defs/peer_submit_request`,
// `committed_replication` branch. Routing basis, membership witnesses and
// destination echoes are absent: the receiver derives authorization from the
// verified committed history alone (federation.md §4.1.1).
function peerCommittedReplicationBody(
  realmId: string,
  replications: CommittedEventSubmission[],
): { branch: "committed_replication"; replications: CommittedEventSubmission[] } {
  if (replications.length < 1 || replications.length > 100) {
    throw new Error(`committed_replication carries 1..100 items, got ${replications.length}`);
  }
  for (const row of replications) {
    if (replicatedEventRealmId(row.event_submission.event) !== realmId) {
      throw new Error(`replicated Event ${String(row.event_submission.event.event_id)} is not in ${realmId}`);
    }
  }
  return { branch: "committed_replication", replications };
}

// realm-and-space.md §2.5.0: the genesis `ak.realm.create` omits the envelope
// `realm_id` and carries `scope_ref = {"kind":"realm_genesis"}`; its Realm is
// `retype(event_id, "realm")`. Every other Event names its Realm explicitly.
function replicatedEventRealmId(event: Record<string, unknown>): unknown {
  const scopeRef = event.scope_ref as { kind?: unknown } | undefined;
  if (
    event.kind === "ak.realm.create" &&
    event.realm_id === undefined &&
    scopeRef?.kind === "realm_genesis" &&
    typeof event.event_id === "string"
  ) {
    return retypeEventDerivedId(event.event_id, "realm");
  }
  return event.realm_id;
}

function signedFederationPushHeaders(
  sourceServiceId: string,
  destinationServiceId: string,
  targetUri: string,
  body: unknown,
  opts: { expireSignature?: boolean } = {},
): Record<string, string> {
  const method = "POST";
  const selector = operationSelector(method, targetUri);
  if (!selector) {
    throw new Error(
      `federation request has no registered operation selector: ${method} ${targetUri}`,
    );
  }
  const bodyBytes = Buffer.from(canonicalJson(body), "utf8");
  const contentDigest = `sha-256=:${createHash("sha256").update(bodyBytes).digest("base64")}:`;
  const sourceTrustDomain = trustDomainFromServiceId(sourceServiceId);
  const destinationTrustDomain = trustDomainFromServiceId(destinationServiceId);
  const nowSeconds = Math.floor(Date.now() / 1000);
  // When asked, push created/expires fully behind the accepted freshness
  // window (federation.md §3.2): expires < now and created beyond the ±30s
  // skew bound. The signature still covers these params, so it verifies — the
  // request is rejected on the freshness check, not on a bad signature.
  const created = opts.expireSignature ? nowSeconds - 600 : nowSeconds;
  const expires = opts.expireSignature ? nowSeconds - 300 : created + 300;
  const sourceKey = configuredServerKeys().find(
    (key) => solandServiceId(key) === sourceServiceId,
  );
  const keyid = `${sourceKey ? solandServiceDid(sourceKey) : serviceCoreIdToDid(sourceServiceId)}#federation-fanout-key`;
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" "arkret-operation" "source-service-id" ` +
    `"destination-service-id" "source-trust-domain" "destination-trust-domain"` +
    `);created=${created};expires=${expires};keyid="${keyid}";alg="ed25519"`;
  const signatureBase = [
    `"@method": ${method}`,
    `"@target-uri": ${targetUri}`,
    `"@authority": ${new URL(targetUri).host}`,
    `"content-digest": ${contentDigest}`,
    `"arkret-operation": ${selector}`,
    `"source-service-id": ${sourceServiceId}`,
    `"destination-service-id": ${destinationServiceId}`,
    `"source-trust-domain": ${sourceTrustDomain}`,
    `"destination-trust-domain": ${destinationTrustDomain}`,
    `"@signature-params": ${signatureParams}`,
  ].join("\n");
  const signature = sign(
    null,
    Buffer.from(signatureBase, "utf8"),
    serviceHttpPrivateKey(sourceServiceId),
  );
  return {
    "content-type": "application/json",
    "content-digest": contentDigest,
    "arkret-operation": selector,
    "source-service-id": sourceServiceId,
    "destination-service-id": destinationServiceId,
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
      "COTEST_FORBID_DEV_PROOF=1 forbids the dev-proof fixture; set COTEST_EVENT_PROOF_MODE=detached-jws",
    );
  }
  return mode;
}

function developmentProtocolPrivateKey(verificationMethod: string) {
  const seed = createHash("sha256")
    .update("arkret-sdk:development-signing-key-v1\0")
    .update(verificationMethod)
    .digest();
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

// FIXTURE ONLY: mirrors soland development_mode service HTTP signing keys.
function serviceHttpPrivateKey(serviceId: string) {
  const seed = serviceSigningSeed(serviceId);
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function serviceSigningSeed(serviceId: string): Buffer {
  return (
    configuredServiceSigningSeed(serviceId) ??
    createHash("sha256")
      .update("soland:notary-ephemeral:")
      .update(serviceId)
      .digest()
  );
}

function configuredServiceSigningSeed(serviceId: string): Buffer | undefined {
  const server = configuredServerKeys().find(
    (candidate) => solandServiceId(candidate) === serviceId,
  );
  const indexedName = server
    ? `COTEST_SOLAND_${String(server).toUpperCase()}_SERVICE_SIGNING_KEY`
    : undefined;
  const encoded =
    (indexedName ? process.env[indexedName]?.trim() : undefined) ??
    (server === "server1"
      ? process.env.COTEST_SOLAND_SERVICE_SIGNING_KEY?.trim()
      : undefined);
  if (!encoded) {
    return undefined;
  }
  const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const seed = Buffer.from(padded, "base64");
  if (seed.length !== 32) {
    throw new Error(
      `configured Soland service signing key for ${serviceId} must decode to 32 bytes`,
    );
  }
  return seed;
}

function trustDomainFromServiceId(serviceId: string): string {
  requireDidCoreId(serviceId);
  const localKey = configuredServerKeys().find(
    (key) => solandServiceId(key) === serviceId,
  );
  if (localKey) {
    return "ak:trust_domain:local.host";
  }
  const serviceDid = serviceCoreIdToDid(serviceId);
  const webHost = serviceDid.startsWith("did:web:")
    ? serviceDid.slice("did:web:".length).split(":")[0]
    : undefined;
  const webvhHost = serviceDid.startsWith("did:webvh:")
    ? serviceDid.slice("did:webvh:".length).split(":")[1]
    : undefined;
  const rawScope = webHost ?? webvhHost;
  if (!rawScope) {
    throw new Error(`unsupported federation service DID: ${serviceDid}`);
  }
  const scope = rawScope
    .split(/%3a/i)[0]
    .replace(/\.+$/, "")
    .toLowerCase()
    .replace(/[^a-z0-9.\-_:]/g, "");
  return `ak:trust_domain:${scope || "local"}`;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
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

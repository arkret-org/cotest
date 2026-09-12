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
  EventFederationSubmission,
  InviteDeliveryRequestBody,
  RealmObject,
  RealmSealFrontierView,
  SelfInviteDispatchRequestBody,
  RealmJoinPrepareRequestBody,
  MessagePrepareRequestBody,
} from "./generated/spec-wire-objects";
import {
  accountSubscribeDeltaApi,
  accountSubscribeFramesApi,
} from "./soland-api/account-stream";
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
  actorSeq?: number;
  createdAt?: string;
  hlc?: string;
  eventId?: string;
  schemaId?: string;
  /// Override the full `requirements.schema[]` binding.
  requirementsSchema?: string[];
  requirementsCriticalExtensions?: Array<Record<string, unknown>>;
  proofVerificationMethod?: string;
  refs?: Array<Record<string, unknown>>;
  preconditions?: Array<Record<string, unknown>>;
  sealRef?: string;
  sealBasis?: Record<string, unknown>;
  authContext?: Record<string, unknown>;
  prevRefs?: string[];
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
  verificationMethod: string;
  signingSeedB64url?: string;
};

const registeredEventSigners = new Map<string, RegisteredEventSigner>();
const realmAuthorityControllers = new Map<string, ActorId>();
const principalControlEvents = new Map<
  string,
  Array<Record<string, unknown>>
>();

// capabilities.md §3.2 — the only Realm authority source an operational
// authorization may resolve against.
export const REALM_AUTHORITY_ROOT_CELL =
  "ak:cell:ak.component.realm.authority_root.v1:null";

function realmAuthorityControllerKey(
  server: SolandKey | undefined,
  realmId: string,
): string {
  return `${server ?? "default"}\0${realmId}`;
}

/**
 * Register the real browser device signer for direct API events emitted by the
 * same test actor. This keeps the event-key lifecycle separate from DPoP while
 * ensuring both submission paths produce proofs for the authorized device.
 */
export function registerEventSigner(args: {
  actorId: string;
  deviceId: string;
  verificationMethod: string;
  signingSeedB64url?: string;
}): void {
  const actorId = requireDidCoreId(args.actorId);
  const previous = registeredEventSigners.get(actorId);
  const signer = {
    verificationMethod: args.verificationMethod,
    // A seed-less re-registration (e.g. dev-login after the canonical
    // provisioning already registered the real device signer) must not clobber
    // the seed of an existing registration for the same verification method.
    signingSeedB64url:
      args.signingSeedB64url ??
      (previous?.verificationMethod === args.verificationMethod
        ? previous.signingSeedB64url
        : undefined),
  };
  registeredEventSigners.set(actorId, signer);
}

function eventSignerFor(
  actorId: string,
  requestedVerificationMethod?: string,
): RegisteredEventSigner | undefined {
  const registered = registeredEventSigners.get(actorId);
  if (
    !registered ||
    (requestedVerificationMethod !== undefined &&
      requestedVerificationMethod !== registered.verificationMethod)
  ) {
    return undefined;
  }
  return registered;
}

export function registeredEventVerificationMethod(
  actorId: string,
  deviceId?: string,
): string | undefined {
  const signer = eventSignerFor(actorId);
  if (!signer) {
    return undefined;
  }
  if (!deviceId || signer.verificationMethod.endsWith(`#${deviceId}`)) {
    return signer.verificationMethod;
  }
  const did = signer.verificationMethod.split("#", 1)[0];
  return `${did}#${deviceId}`;
}

export function registeredEventSigningSeedB64url(
  actorId: string,
): string | undefined {
  return eventSignerFor(actorId)?.signingSeedB64url;
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

export async function submitPrincipalSuccessorSealApi(
  request: APIRequestContext,
  token: string,
  actorId: string,
  event: Record<string, unknown>,
  opts: { server?: SolandKey } = {},
): Promise<void> {
  requireDidCoreId(actorId);
  const events = principalControlEvents.get(actorId);
  const signer = eventSignerFor(actorId);
  const realmId = principalControlRealmForId(actorId);
  if (!events || !signer?.signingSeedB64url) {
    throw new Error(
      `principal successor Seal material is unavailable for ${actorId}`,
    );
  }
  if (events.some((known) => known.event_id === event.event_id)) {
    return;
  }
  const frontierUrl = `${solandBaseUrl(opts.server)}/_arkret/self/seals/frontier`;
  const frontierResponse = await request.fetch(frontierUrl, {
    method: "QUERY",
    headers: {
      ...authHeaders(token, "QUERY", frontierUrl),
      "content-type": "application/json",
    },
    data: canonicalJson({ realm_id: realmId }),
  });
  const frontier = await expectJsonOk<{
    frontier: { seal_basis?: { leaves?: unknown } };
  }>(frontierResponse, `read principal Seal frontier for ${actorId}`);
  const leaves = frontier.frontier?.seal_basis?.leaves;
  if (
    !Array.isArray(leaves) ||
    leaves.length !== 1 ||
    typeof leaves[0] !== "string"
  ) {
    throw new Error(
      `principal Seal frontier for ${actorId} is not a single accepted leaf`,
    );
  }
  const eventDigest = (
    event.proofs as Array<Record<string, unknown>> | undefined
  )?.[0]?.event_digest;
  if (typeof eventDigest !== "string") {
    throw new Error("principal successor Event proof omits event_digest");
  }
  const prepareUrl = `${solandBaseUrl(opts.server)}/_arkret/self/seals/prepare`;
  const prepareRequest = {
    realm_id: realmId,
    predecessor_refs: [leaves[0]],
    event_digests: [eventDigest],
    hlc: nextEnvelopeHlc(realmId, new Date().toISOString()),
  };
  const outcome = await expectJsonOk<Record<string, unknown>>(
    await request.post(prepareUrl, {
      headers: { ...authHeaders(token, "POST", prepareUrl), "content-type": "application/json" },
      data: canonicalJson(prepareRequest),
    }), `prepare principal successor Seal for ${actorId}`,
  );
  const seal = cotestWire<Record<string, unknown>>("principal-successor-seal", {
    request: prepareRequest, outcome,
    signer_did: signer.verificationMethod.split("#", 1)[0],
    verification_method: signer.verificationMethod,
    device_signing_seed_b64url: signer.signingSeedB64url,
  });
  const sealUrl = `${solandBaseUrl(opts.server)}/_arkret/self/seals`;
  await expectJsonOk(
    await request.post(sealUrl, {
      headers: {
        ...authHeaders(token, "POST", sealUrl),
        "content-type": "application/json",
      },
      data: canonicalJson(seal),
    }),
    `submit principal successor Seal for ${actorId}`,
  );
  events.push(JSON.parse(canonicalJson(event)) as Record<string, unknown>);
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

/// The `head_eq` guard an invite Move owes on the live-target slot.
///
/// `ak.invite.create` asserts the free value, which is `null`: an unwritten
/// `cas_register` cell reads `null` (§9.3.1.1), and so does a released slot,
/// because a release is an explicit `set null`. The old `"__unset__"` spelling
/// was the deleted `initial_value` mechanism; soland compares `head_eq` against
/// `unwritten_cell_head()`, which is `Value::Null`, so that spelling made every
/// harness-authored invite `failed_precondition`. Every registered
/// release asserts the stored value, which is the occupying create Event id in
/// `ak:event:` form. `invite_id` and `create_event_id` are the same 33-octet
/// token under two prefixes, and only the `ak:event:` spelling ever matches —
/// the other silently strands the slot, so the retype happens here once.
function inviteLiveTargetPreconditions(
  kind: string,
  payload: Record<string, unknown>,
): Array<Record<string, unknown>> | undefined {
  const account = payload.invitee_account_id;
  if (!account || typeof account !== "object") return undefined;
  const cell = inviteLiveTargetCell(account as Record<string, unknown>);
  if (kind === "ak.invite.create") {
    return [{ cell_id: cell, predicate: { op: "head_eq", value: null } }];
  }
  if (
    kind !== "ak.invite.accept" && kind !== "ak.invite.cancel" &&
    kind !== "ak.invite.revoke"
  ) {
    return undefined;
  }
  const inviteId = payload.invite_id;
  if (typeof inviteId !== "string" || !inviteId.startsWith("ak:invite:")) {
    return undefined;
  }
  const createEventId = `ak:event:${inviteId.slice("ak:invite:".length)}`;
  return [{
    cell_id: cell,
    predicate: { op: "head_eq", value: createEventId },
  }];
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

// `realm.schema.json` notary: `kind` is the sole discriminator and every signer
// is a frozen descriptor (exact verification method, key kind, JOSE alg and key
// digest). The Realm names the Station's own notary key, so the
// descriptor is derived from the same development seed soland freezes into
// `service_notary_signer_descriptor()`. No controlling organization is derived
// for the development deployment, so the org-diversity members stay absent.
export function singleSignerNotaryFromDid(
  did: string,
): RealmObject["notary"] {
  const actorId = projectDidToCoreId(did);
  const publicKey = serviceNotaryPublicKey(actorId);
  return {
    kind: "single_signer",
    signer: {
      actor_id: serviceActorId(actorId),
      verification_method: `${did}#notary-key`,
      key_kind: "ed25519_raw32",
      jose_algorithm: "Ed25519",
      frozen_public_key_b64u: publicKey.toString("base64url"),
      frozen_public_key_digest: `sha256:${createHash("sha256")
        .update(publicKey)
        .digest("hex")}`,
    },
  };
}

// FIXTURE ONLY: mirrors soland development_mode notary keys, which are derived
// from the same seed as the service HTTP signing key.
function serviceNotaryPublicKey(serviceId: string): Buffer {
  const spki = createPublicKey(serviceHttpPrivateKey(serviceId)).export({
    format: "der",
    type: "spki",
  });
  return Buffer.from(spki.subarray(spki.length - 32));
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
    encryption_profile?: RealmObject["encryption_profile"];
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
    (data.encryption_profile === "mls_rfc9420"
      ? []
      : [solandServiceId(opts.server)]);
  const plaintextVisibleServices = plaintextVisibleServiceDeclarations(
    plaintextVisibleServiceIds,
  );
  const realmGenesis = {
    schema: "ak.schema.realm_genesis.v1",
    purpose: "collaboration",
    genesis_salt: base64url(randomBytes(32)),
    trust_domain: "ak:trust_domain:soland.local",
    schema_refs: data.schema_refs ?? ["ak.schema.realm.v1"],
    reducer_profile: "ak.reducer.core.v1",
    encryption_profile: data.encryption_profile ?? "none",
    security_class: "standard",
    digest_algorithm: "sha256",
    // This helper creates Station-hosted collaboration Realms. The
    // service owns the notary key and materializes Event Seals; the principal
    // remains the Realm creator and root authority-cell controller.
    notary: singleSignerNotaryFromDid(solandServiceDid(opts.server)),
    // Create-locked (realm-and-space.md section 2.5): the reducer copies this
    // into the Realm authority-root cell, which is what gives the creator
    // effective `ak.realm.owner`. v1 issues no genesis self-grant.
  };
  const realmCreateCell = "ak:cell:ak.component.realm.create.v1:null";
  const { envelope: realmCreateEvent, realmId } = signedRealmGenesisEnvelope({
    actorId: ownerId,
    // The genesis names no Realm; the envelope builder derives both its own id
    // and the Realm's from the finished envelope.
    realmId: "",
    kind: "ak.realm.create",
    actorSeq: 0,
    createdAt,
    preconditions: [
      {
        cell_id: realmCreateCell,
        predicate: { op: "head_eq", value: null },
      },
    ],
    payload: {
      object: realmGenesis,
    },
  });
  // The genesis Event names itself to everything that follows, and its id is
  // derived from the envelope, so the chain can only be built afterwards.
  const bootstrapEvents = [realmCreateEvent];
  const pushBootstrapEvent = (
    kind: string,
    cell: string,
    payload: Record<string, unknown>,
  ): void => {
    const predecessorId = stringValue(
      bootstrapEvents[bootstrapEvents.length - 1]?.event_id,
    );
    if (!predecessorId) {
      throw new Error(
        `Realm bootstrap predecessor for ${kind} is missing event_id`,
      );
    }
    bootstrapEvents.push(
      signedEventEnvelope({
        actorId: ownerId,
        realmId,
        kind,
        actorSeq: bootstrapEvents.length,
        createdAt,
        prevRefs: [predecessorId],
        authorizationRef: REALM_AUTHORITY_ROOT_CELL,
        preconditions: [
          {
            cell_id: cell,
            predicate: { op: "head_eq", value: null },
          },
        ],
        payload,
      }),
    );
  };
  pushBootstrapEvent(
    "ak.realm.profile",
    "ak:cell:ak.component.realm.profile.v1:null",
    {
      schema: "ak.schema.realm_profile.v1",
      title: data.title,
      ...(data.summary === undefined ? {} : { summary: data.summary }),
    },
  );
  pushBootstrapEvent(
    "ak.realm.policy_bundle",
    "ak:cell:ak.component.realm.policy_bundle.v1:null",
    {
      policy_revision: 1,
      federation_policy: data.federation_policy ?? "restricted",
      content_encryption_floor:
        data.encryption_profile === "mls_rfc9420"
          ? "e2ee_required"
          : "allow_plaintext",
      metadata_encryption_floor:
        data.encryption_profile === "mls_rfc9420"
          ? "e2ee_required"
          : "allow_plaintext",
    },
  );
  pushBootstrapEvent(
    "ak.realm.join_rule",
    "ak:cell:ak.component.realm.join_rule.v1:null",
    { value: data.default_join_rule ?? "invite" },
  );
  pushBootstrapEvent(
    "ak.realm.history_access",
    "ak:cell:ak.component.realm.history_access.v1:null",
    {
      // event-payload.schema.json#/$defs/history_access_payload models this
      // facet as an explicit FSM transition. The ordinary Realm bootstrap is
      // the one legal initial transition, so it must author null -> value
      // rather than relying on the reducer to infer the missing predecessor.
      from: null,
      to: data.history_access ?? "since_join",
    },
  );
  pushBootstrapEvent(
    "ak.realm.discovery",
    "ak:cell:ak.component.realm.discovery.v1:null",
    {
      value: {
        discoverability:
          data.discoverability ?? (data.public ? "public" : "listed"),
      },
    },
  );
  if (plaintextVisibleServices.length > 0) {
    pushBootstrapEvent(
      "ak.realm.plaintext_visible_services",
      "ak:cell:ak.component.realm.plaintext_visible_services.v1:null",
      { services: plaintextVisibleServices },
    );
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
  const creatorActorCanonical = canonicalJson(creatorActorId);
  const memberCellSubject = base64url(
    createHash("sha256")
      .update(canonicalJson([creatorActorCanonical]))
      .digest(),
  );
  pushBootstrapEvent(
    "ak.member.state",
    `ak:cell:ak.component.member.state.v1:${memberCellSubject}`,
    {
      realm_id: realmId,
      member_id: creatorActorId,
      membership: "join",
    },
  );

  const bootstrapOutcome = await submitSignedEventBatchApi(
    request,
    token,
    bootstrapEvents,
    {
      server: opts.server,
      context: `create realm ${data.title}`,
    },
  );
  opts.onAcceptedBootstrap?.({
    events: structuredClone(bootstrapEvents),
    outcome: structuredClone(bootstrapOutcome),
  });
  realmAuthorityControllers.set(
    realmAuthorityControllerKey(opts.server, realmId),
    accountActorId(ownerId, opts.server),
  );
  // The founding unit is accepted before the durable coordinator publishes
  // its first Seal. Do not let the next helper call mistake that short window
  // for an uninitialised conformance-only Realm and inject a synthetic basis:
  // the real genesis Seal must atomically cover the complete founding unit.
  await waitForRealmSealBasis(request, token, realmId, opts.server);

  for (const invitee of data.invitees ?? []) {
    const recipientServiceId =
      data.invitee_ids?.[invitee] ?? solandServiceId(opts.server);
    const recipientServer = configuredServerKeys().find(
      (server) => solandServiceId(server) === recipientServiceId,
    );
    if (!recipientServer) throw new Error("directed invite recipient Station is not configured");
    const inviteeAccountId = accountActorId(invitee, recipientServer, recipientServiceId).account_id;
    const evidence = { kind: "explicit_address" } as const;
    const sealBasis = await readRealmSealBasis(
      request,
      token,
      realmId,
      opts.server,
    );
    const inviteEvent = signedEventEnvelope({
      actorId: ownerId,
      realmId,
      kind: "ak.invite.create",
      sealBasis,
      payload: {
        invitee_account_id: inviteeAccountId,
        introduction_evidence_digest: `sha256:${sha256CanonicalJson(evidence)}`,
        expires_at: canonicalTimestamp(
          new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        ),
      },
    });
    await advanceEnvelopeToActorFrontier(
      request,
      token,
      inviteEvent,
      opts.server,
    );
    await submitSignedEventApi(request, token, inviteEvent, {
      server: opts.server,
      context: `directed invite ${invitee}`,
    });
    if (data.invitee_ids?.[invitee] !== undefined) {
      const inviteEventId = stringValue(inviteEvent.event_id);
      if (!inviteEventId) {
        throw new Error(`directed invite ${invitee} is missing event_id`);
      }
      const dispatch = await dispatchSelfInviteApi(
        request,
        token,
        selfInviteDispatchBody({
          eventId: inviteEventId,
          inviteAddress: {
            account_id: inviteeAccountId,
            service_resolution: canonicalServiceResolution(recipientServer),
          },
          evidence,
        }),
        { server: opts.server },
      );
      if (dispatch.status !== "accepted" && dispatch.status !== "duplicate") {
        throw new Error(
          `directed invite dispatch for ${invitee} returned ${dispatch.status}`,
        );
      }
    }
  }

  return realmId;
}

export async function addRealmMemberApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  memberId: string | ActorId,
  opts: { server?: SolandKey } = {},
) {
  const actorId = await currentActorIdApi(request, token, opts);
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId,
      server: opts.server,
      realmId,
      kind: "ak.member.state",
      payload: {
        // `realm_id` inside the payload is a spec-defined membership_payload
        // property (event-payload.schema.json#/$defs/membership_payload) and is
        // required by soland's registry-backed payload validator in dev-proof
        // mode; include it so the membership op validates regardless of the
        // active proof profile.
        realm_id: realmId,
        member_id: typeof memberId === "string" ? accountActorId(memberId, opts.server) : memberId,
        membership: "join",
      },
    }),
    { server: opts.server, context: `add member ${memberId}` },
  );
}

// join-policy.md §3 — write the per-Realm `join_policy` component as a
// `ak.realm.policy_bundle` revision.
//
// The payload IS the flat closed `realm_policy_bundle_payload`
// (`required: ["policy_revision"]`, `minProperties: 2`,
// `additionalProperties: false`) — not a `{value: ...}` state-payload wrapper,
// and it carries no `realm_id`: the governed Realm is the envelope's.
//
// The cell is a `cas_register`: every revision is a complete replacement and
// must carry a `head_eq` guard over the exact current value. Preserve every
// current component and change only `policy_revision` + `join_policy`; omitting
// the guard admits concurrent candidates and correctly collapses the cell to
// Bottom, while omitting current components can violate one-way policy
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
  const previousFrontier = await readRealmSealFrontier(
    request,
    token,
    realmId,
    opts.server,
  );
  const policyCell = "ak:cell:ak.component.realm.policy_bundle.v1:null";
  const currentResponse = await request.get(
    `${solandBaseUrl(opts.server)}/_soland/admin/cells/${encodeURIComponent(policyCell)}?realm_id=${encodeURIComponent(realmId)}`,
    { headers: authHeaders(token) },
  );
  const currentText = await currentResponse.text();
  expect(currentResponse.status(), currentText).toBe(200);
  const currentCell = JSON.parse(currentText) as {
    state?: string;
    value?: Record<string, unknown>;
  };
  expect(currentCell.state, currentText).toBe("value");
  expect(currentCell.value, currentText).toBeTruthy();
  const currentPolicy = currentCell.value!;
  const currentRevision = currentPolicy.policy_revision;
  expect(typeof currentRevision, currentText).toBe("number");
  const policyRevision = Number(currentRevision) + 1;
  const policyEvent = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.realm.policy_bundle",
    payload: {
      ...currentPolicy,
      policy_revision: policyRevision,
      join_policy: joinPolicy,
    },
    preconditions: [
      {
        cell_id: policyCell,
        predicate: { op: "head_eq", value: currentPolicy },
      },
    ],
  });
  await submitSignedEventApi(request, token, policyEvent, {
    server: opts.server,
    context: `write join policy ${realmId}`,
  });
  const proposalDigest = Array.isArray(policyEvent.proofs)
    ? stringValue(
        (policyEvent.proofs[0] as Record<string, unknown> | undefined)
          ?.event_digest,
      )
    : undefined;
  if (!proposalDigest) {
    throw new Error(`join policy ${realmId} is missing its proposal digest`);
  }
  await expect
    .poll(
      async () => {
        const current = await readRealmSealFrontier(
          request,
          token,
          realmId,
          opts.server,
        );
        return (
          current.control_event_set_root !==
            previousFrontier.control_event_set_root &&
          !current.pending_proposal_digests.includes(proposalDigest)
        );
      },
      {
        message: `join policy ${realmId} proposal ${proposalDigest} reaches the control Seal frontier`,
        timeout: 30_000,
        intervals: [250, 500, 1_000, 2_000],
      },
    )
    .toBe(true);
  await expect
    .poll(
      async () => {
        const response = await request.get(
          `${solandBaseUrl(opts.server)}/_soland/admin/cells/${encodeURIComponent(policyCell)}?realm_id=${encodeURIComponent(realmId)}`,
          { headers: authHeaders(token) },
        );
        if (!response.ok()) {
          return false;
        }
        const cell = (await response.json()) as {
          state?: string;
          value?: Record<string, unknown>;
        };
        const projectedJoinPolicy = cell.value?.join_policy;
        return (
          cell.state === "value" &&
          cell.value?.policy_revision === policyRevision &&
          projectedJoinPolicy !== undefined &&
          `sha256:${sha256CanonicalJson(projectedJoinPolicy)}` === digest
        );
      },
      {
        message: `join policy ${realmId} revision ${policyRevision} reaches the reducer projection`,
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
  const issuedAt = canonicalTimestamp();
  // Use a core collaboration action advertised by both federation peers; the
  // service actor subject and Realm resource make this a peer-service grant.
  const action = args.action ?? "ak.message.create";
  // `capability-grant.schema.json` is a closed object; annotating the literal
  // makes an unregistered member or a misspelled resource kind a `tsc` error
  // instead of a reducer rejection. `proofs` is attached after signing.
  const unsignedGrant: Omit<CapabilityGrantObject, "id" | "proofs"> = {
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
        cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null",
        controller_epoch_at_issuance: 0,
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
// id (`ak:event:*`). capabilities.md §10.3 requires `refs[authorized_by]` to
// name the grant itself; the Event id remains useful only for Event-history
// causality and diagnostics.
type CapabilityGrantEventArgs = {
  ownerId: string;
  realmId: string;
  subjectId: string;
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
  // instead of a reducer rejection. `proofs` is attached after signing.
  const unsignedGrant: Omit<CapabilityGrantObject, "id" | "proofs"> = {
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer_id: accountActorId(args.ownerId, args.server),
    subject: accountActorId(args.subjectId, args.server),
    actions: args.actions,
    resources: [{ kind: "realm", realm_id: args.realmId }],
    issued_at: issuedAt,
    ...(constraints.length > 0 ? { constraints } : {}),
    issuer_authority_refs: args.issuerAuthorityRefs ?? [
      {
        kind: "realm_root",
        realm_id: args.realmId,
        cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null",
        controller_epoch_at_issuance: 0,
        authority_generation: 0,
      },
    ],
  };
  const envelope = signedEventEnvelope({
    actorId: args.ownerId,
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
  const { envelope } = buildCapabilityGrantEnvelope(args);
  await submitSignedEventApi(request, ownerToken, envelope, {
    server: args.server,
    context: `grant [${args.actions.join(", ")}] to ${args.subjectId}`,
  });
  // A derived grant must be authored against a predecessor Seal that already
  // contains its parent. Returning while this grant is merely pending lets a
  // caller submit parent and child into one frozen-predecessor batch, where
  // the child correctly cannot observe the parent authority.
  await waitForRealmControlIdleApi(request, ownerToken, args.realmId, {
    server: args.server,
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
  await waitForRealmControlIdleApi(request, ownerToken, args.realmId, {
    server: args.server,
  });
  return outcome;
}

// join-policy.md §7.1 stage 1 — `ak.member.state{membership=knock}`. The
// knock Control Move carries no application body (spec §8 keeps free text out
// of the public knock event).
const joinPolicyDigestCache = new Map<string, string>();

// Last `policy_revision` this process wrote per (server, realm).
//
// `ak.component.realm.policy_bundle.v1` is a `cas_register` whose supersession
// binds by value, so the revision is what gives a bundle family its generation
// dimension: a stateless constant makes the second write of a Realm a repeat of
// the first, and the register has no way to order them. The helper therefore
// has to hold this per (server, realm) rather than derive it from the payload.
// The `createRealmApi` genesis already occupies `policy_revision: 1`
// (soland-api.ts pushBootstrapEvent) and the reducer enforces strict prev+1
// (apply_realm_policy.rs), so the first post-genesis write is revision 2.
const joinPolicyRevisionCache = new Map<string, number>();
const knockRefCache = new Map<string, string>();
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
    sealBasis?: Record<string, unknown>;
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
  let sealBasis = opts.sealBasis;
  if (!sealBasis) {
    if (!teabayBaseUrl()) {
      throw new Error("invite acceptance needs an authenticated invite Seal basis or an independently configured Directory");
    }
    await expect.poll(async () => {
      sealBasis = await readDirectoryJoinCandidateSealBasis(request, realmId, actorId, "invite_accept");
      return Boolean(sealBasis);
    }, { message: "invite-accept join candidate Seal basis", timeout: 30_000 }).toBe(true);
  }
  // join-policy section 6: candidates are hints; the invitee submits at its own Station.
  return await submitSignedEventApi(request, token, signedEventEnvelope({
    actorId,
    server: opts.server,
    realmId,
    kind: "ak.invite.accept",
    actorSeq: 0,
    sealBasis,
    payload: {
      invite_id: inviteId,
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
      invite_id: string; realm_id: string; invite_token: string;
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
  opts: { server?: SolandKey; waitForStatus?: boolean } = {},
) {
  const account = accountActorId(actorId, opts.server).account_id;
  const delivery = await readOwnInviteDeliveryApi(request, token, realmId, opts, inviteId);
  expect(Boolean(delivery), "own invitation credential must be available").toBe(true);
  const input: RealmJoinPrepareRequestBody = {
    request_id: typedId("request"), account_id: account, realm_id: realmId,
    intent: { intent: "invite_accept", invite_id: inviteId, invite_token: delivery!.invite_token },
    created_at: canonicalTimestamp(),
  };
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/realm-joins/prepare`;
  const prepare = () => request.post(url, {
    headers: { ...authHeaders(token, "POST", url), "content-type": "application/json" },
    data: canonicalJson(input),
  });
  const prepared = await expectJsonOk<Record<string, any>>(await prepare(), "own-Station join prepare");
  expect(await expectJsonOk(await prepare(), "exact join prepare replay")).toEqual(prepared);
  expect(prepared.request_digest).toBe(`sha256:${createHash("sha256")
    .update("ak.realm-join-prepare-request-v1\0", "utf8").update(canonicalJson(input)).digest("hex")}`);
  const event = prepared.unsigned_event;
  expect(event.kind).toBe("ak.invite.accept");
  expect(event.realm_id).toBe(realmId);
  expect(event.actor_id).toEqual(accountActorId(actorId, opts.server));
  expect(event.scope_ref).toEqual({ kind: "realm", realm_id: realmId });
  expect(event.created_at).toBe(input.created_at);
  expect(event.hlc).toBeUndefined();
  expect(event.payload).toEqual({ invite_id: inviteId, invitee_account_id: account });
  expect(event.actor_seq).toBe(prepared.accepted_actor_frontier.next_actor_seq);
  expect(event.prev_refs).toEqual(prepared.accepted_actor_frontier.frontier_event_ids);
  expect(event.event_id).toBe(sdkEventDerivedIds(event).event_id);
  event.proofs = [eventEnvelopeProof({ actorId, event })];
  const submitUrl = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
  const signed = canonicalJson({ event });
  const submit = () => request.post(submitUrl, {
    headers: { ...authHeaders(token, "POST", submitUrl), "content-type": "application/json" },
    data: signed,
  });
  const accepted = await expectJsonOk<Record<string, any>>(await submit(), "prepared join submit");
  expect(accepted.accepted).toContain(event.event_id);
  const replay = await expectJsonOk<Record<string, any>>(await submit(), "exact join submit replay");
  expect(replay.duplicate).toContain(event.event_id);
  if (opts.waitForStatus !== false) {
    const statusUrl = `${solandBaseUrl(opts.server)}/_arkret/self/realm-joins/application-status`;
    await expect.poll(async () => {
      const response = await request.post(statusUrl, {
        headers: { ...authHeaders(token, "POST", statusUrl), "content-type": "application/json" },
        data: { request_id: typedId("request"), account_id: account, realm_id: realmId, event_id: event.event_id },
      });
      const status = await expectJsonOk<Record<string, any>>(response, "own join application status");
      expect(status.account_id).toEqual(account);
      expect(status.event_id).toBe(event.event_id);
      if (status.realm_state !== "sealed") return status.realm_state ?? status.origin_state;
      expect(status.accepted_seal_id).toMatch(/^ak:seal:/);
      return "sealed";
    }, { timeout: 120_000, intervals: [1000, 2000, 5000] }).toBe("sealed");
  }
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
  expect(unsigned.actor_seq).toBe(prepared.accepted_actor_frontier.next_actor_seq);
  expect(unsigned.prev_refs).toEqual(prepared.accepted_actor_frontier.frontier_event_ids);
  expect(unsigned.refs ?? []).toEqual([]);
  expect(unsigned.causal_refs ?? []).toEqual([]);
  expect(unsigned.preconditions ?? []).toEqual([]);
  const derived = sdkEventDerivedIds(unsigned);
  const event = { ...unsigned, event_id: derived.event_id };
  expect(prepared.draft.event_digest).toBe(`sha256:${sha256CanonicalJson(unsigned)}`);
  event.proofs = [eventEnvelopeProof({ actorId: principal, event })];
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
  expect(outcome.status).toBe("accepted");
  expect(outcome.accepted).toEqual([event.event_id]);
  const replay = await expectJsonOk<Record<string, unknown>>(
    await submit(), "exact signed submission replay",
  );
  expect(replay.status).toBe("duplicate");
  expect(replay.duplicate).toEqual([event.event_id]);
  expect(replay.frontiers).toEqual(outcome.frontiers);
  expect(replay.ingress_receipts).toEqual(outcome.ingress_receipts);
  return {
    event_id: event.event_id,
    realm_id: realmId,
    actor_id: principal,
    actor_seq: Number(event.actor_seq),
    prev_refs: event.prev_refs,
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
    actorSeq?: number;
  } = {},
) {
  const actorId = await currentActorIdApi(request, token, opts);
  const strandId = await resolveDefaultStrandId(request, token, realmId, {
    server: opts.server,
  });
  const envelope = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.message.create",
    actorSeq: opts.actorSeq,
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
  if (opts.actorSeq === undefined) {
    await advanceEnvelopeToActorFrontier(request, token, envelope, opts.server);
  }
  const submission = await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `send message to ${realmId}`,
  });
  return {
    event_id: String(envelope.event_id),
    realm_id: realmId,
    actor_id: actorId,
    actor_seq: Number(envelope.actor_seq),
    prev_refs: [...(envelope.prev_refs as string[])],
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

export async function queryRealmEventsApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey; limit?: number } = {},
) {
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
  const response = await request.fetch(url, {
    method: "QUERY",
    data: canonicalJson({ realm_ids: [realmId], limit: opts.limit ?? 100 }),
    headers: {
      ...authHeaders(token, "QUERY", url),
      "content-type": "application/json",
    },
  });
  return await expectJsonOk<Record<string, unknown>>(
    response,
    `query events for ${realmId}`,
  );
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
    expected_revision: args.expectedRevision,
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
  // actor_private_event is outside the shared Realm Data/Control planes: the
  // spec forbids seal_ref, seal_basis, CBS and shared-reducer coverage here.
  // It still participates in the holder's signed actor chain, so align that
  // frontier but do not ask the shared Event lease endpoint to authorize it.
  await advanceEnvelopeToActorFrontier(request, token, event, opts.server);
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
        ...authHeaders(token),
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

export function signedEventEnvelope(
  args: SignedEventEnvelopeArgs,
): Record<string, unknown> {
  const createdAt = canonicalEventTimestamp(
    args.createdAt === undefined ? undefined : new Date(args.createdAt),
  );
  const hlc = args.hlc ?? nextEnvelopeHlc(args.realmId, createdAt);
  const payload = stripUndefined(args.payload) as Record<string, unknown>;
  const actor = typeof args.actorId === "string"
    ? accountActorId(args.actorId, args.server, args.stationId)
    : args.actorId;
  // A Realm genesis is the one Event that names no Realm: `realm_id` is
  // `retype(event_id)` of the genesis itself, and `scope_ref` carries the
  // closed `realm_genesis` form. Sending either would be
  // `realm_id_not_event_derived`.
  const isRealmGenesis = args.kind === "ak.realm.create";
  const preconditions = args.preconditions ?? inviteLiveTargetPreconditions(args.kind, payload);
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
    actor_seq: args.actorSeq ?? nextActorSeq(),
    created_at: createdAt,
    hlc,
    prev_refs: args.prevRefs ?? [],
    refs: args.refs?.length ? args.refs : undefined,
    // An invite Move that writes the live-target slot MUST carry that cell's
    // head_eq. Deriving it here keeps every harness-authored invite conformant
    // without each scenario re-spelling the cell; an explicit precondition list
    // still wins, which is how a negative case proves a wrong guard is refused.
    preconditions: preconditions?.length ? preconditions : undefined,
    seal_ref: args.sealRef,
    seal_basis: args.sealBasis,
    auth_context: args.authContext,
    requirements: {
      schema: args.requirementsSchema ?? [
        args.schemaId ?? schemaIdForEventKind(args.kind),
      ],
      ...(args.requirementsCriticalExtensions?.length
        ? { critical_extensions: args.requirementsCriticalExtensions }
        : {}),
    },
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
    proofs: [
      eventEnvelopeProof({
        actorId: eventSigningPrincipalId(event),
        event,
        verificationMethod: args.proofVerificationMethod,
      }),
    ],
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
  delete event.proofs;
  // Callers reach this after rewriting `actor_seq` / `prev_refs` to a fresh
  // actor frontier, and both sit inside the digest preimage. An Event id is a
  // function of that digest, so re-signing without re-deriving would leave the
  // envelope carrying the id of content it no longer has.
  delete event.event_id;
  const derived = sdkEventDerivedIds(event);
  event.event_id = derived.event_id;
  envelope.event_id = derived.event_id;
  envelope.proofs = [
    eventEnvelopeProof({
      actorId,
      event,
      verificationMethod: proofVerificationMethod,
    }),
  ];
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

export async function submitSignedEventApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: {
    server?: SolandKey;
    context?: string;
    controlObserverToken?: string;
  } = {},
) {
  const context = opts.context ?? `submit ${String(envelope.kind)}`;
  await applyRegisteredCbsPlane(request, token, envelope, opts.server);
  await advanceEnvelopeToActorFrontier(request, token, envelope, opts.server);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const controlControlProposalAck = await issueControlProposalAckApi(
      request,
      token,
      envelope,
      undefined,
      opts.server,
      context,
    );
    const realmId = stringValue(envelope.realm_id);
    const actorId = eventPrincipalId(envelope);
    const actorControlRealm = actorId
      ? principalControlRealmForIdIfKnown(actorId)
      : undefined;
    const previousControlRoot =
      controlControlProposalAck &&
      realmId &&
      envelope.kind !== "ak.invite.accept" &&
      (!actorControlRealm || realmId !== actorControlRealm)
        ? (await readRealmSealFrontier(request, token, realmId, opts.server))
            .control_event_set_root
        : undefined;
    const eventsUrl = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
    const response = await request.post(eventsUrl, {
      headers: {
        ...authHeaders(token, "POST", eventsUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({
        event: envelope,
        ...(controlControlProposalAck
          ? { control_proposal_ack: controlControlProposalAck }
          : {}),
      }),
    });
    const text = await response.text();
    if ([200, 201].includes(response.status())) {
      const outcome = JSON.parse(text) as Record<string, unknown>;
      rememberPublicationEvidence([envelope], [], outcome,
        { token: opts.controlObserverToken ?? token, server: opts.server }, [controlControlProposalAck]);
      if (realmId && previousControlRoot) {
        // A successful leave may immediately remove the author from the
        // Realm's read surface. Observe the resulting Control frontier with
        // an explicitly authorised member when the caller supplies one;
        // using the departed actor would correctly collapse to not_found.
        await waitForRealmControlIdleApi(
          request,
          opts.controlObserverToken ?? token,
          realmId,
          {
          server: opts.server,
          afterControlEventSetRoot: previousControlRoot,
          timeoutMs: 60_000,
          },
        );
      }
      return outcome;
    }
    const body = JSON.parse(text) as unknown;
    if (
      response.status() === 403 &&
      wireErrCode(body) === "capability_denied" &&
      !(
        realmId &&
        realmAuthorityControllers.has(
          realmAuthorityControllerKey(opts.server, realmId),
        )
      ) &&
      attempt < 2
    ) {
      await forceConformanceCbsBasis(request, envelope, opts.server);
      continue;
    }
    const actorFrontierRefreshRequired = requiresActorFrontierRefresh(
      response.status(),
      body,
      text,
    );
    if (!actorFrontierRefreshRequired || attempt === 2) {
      expect(
        [200, 201],
        `${context} returned ${response.status()}: ${text}`,
      ).toContain(response.status());
    }
    await advanceEnvelopeToActorFrontier(request, token, envelope, opts.server);
  }
  throw new Error(`${context}: exhausted actor-frontier retry loop`);
}

export async function prepareSignedEventSubmissionApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: { server?: SolandKey; context?: string } = {},
): Promise<Record<string, unknown>> {
  const context = opts.context ?? `prepare ${String(envelope.kind)}`;
  await applyRegisteredCbsPlane(request, token, envelope, opts.server);
  // This helper returns an EventInitialSubmission for a later endpoint to
  // admit, so it cannot rely on the ordinary submit path's retry after an
  // actor-frontier rejection. Bind the envelope to the current frontier
  // before issuing its authorization lease.
  await advanceEnvelopeToActorFrontier(request, token, envelope, opts.server);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const leaseResponse = await issueAuthorizationLeasesApi(
      request,
      token,
      [envelope],
      opts.server,
    );
    const leaseText = await leaseResponse.text();
    if (![200, 201].includes(leaseResponse.status())) {
      const leaseBody = parseJsonOrRaw(leaseText);
      if (
        !requiresActorFrontierRefresh(
          leaseResponse.status(),
          leaseBody,
          leaseText,
        ) ||
        attempt === 2
      ) {
        expect(
          [200, 201],
          `${context} lease issuance returned ${leaseResponse.status()}: ${leaseText}`,
        ).toContain(leaseResponse.status());
      }
      await advanceEnvelopeToActorFrontier(
        request,
        token,
        envelope,
        opts.server,
      );
      continue;
    }
    const authorizationLease = authorizationLeasesFromIssueOutcome(
      leaseText,
      1,
      context,
    )[0];
    const controlProposalAck = await issueControlProposalAckApi(
      request,
      token,
      envelope,
      authorizationLease,
      opts.server,
      context,
    );
    return {
      event: envelope,
      authorization_lease: authorizationLease,
      ...(controlProposalAck
        ? { control_proposal_ack: controlProposalAck }
        : {}),
    };
  }
  throw new Error(`${context}: exhausted actor-frontier retry loop`);
}

export async function prepareSignedEventBatchSubmissionsApi(
  request: APIRequestContext,
  token: string,
  events: Array<Record<string, unknown>>,
  opts: { server?: SolandKey; context?: string } = {},
): Promise<Array<Record<string, unknown>>> {
  if (events.length === 0) {
    return [];
  }
  const context = opts.context ?? "prepare Event batch";
  for (const event of events) {
    await applyRegisteredCbsPlane(request, token, event, opts.server);
  }
  await advanceEnvelopeToActorFrontier(request, token, events[0], opts.server);
  refreshBatchActorChain(events);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const leaseResponse = await issueAuthorizationLeasesApi(
      request,
      token,
      events,
      opts.server,
    );
    const leaseText = await leaseResponse.text();
    if (![200, 201].includes(leaseResponse.status())) {
      const leaseBody = parseJsonOrRaw(leaseText);
      if (
        !requiresActorFrontierRefresh(
          leaseResponse.status(),
          leaseBody,
          leaseText,
        ) ||
        attempt === 2
      ) {
        expect(
          [200, 201],
          `${context} lease issuance returned ${leaseResponse.status()}: ${leaseText}`,
        ).toContain(leaseResponse.status());
      }
      await advanceEnvelopeToActorFrontier(
        request,
        token,
        events[0],
        opts.server,
      );
      refreshBatchActorChain(events);
      continue;
    }
    const leases = authorizationLeasesFromIssueOutcome(
      leaseText,
      events.length,
      context,
    );
    const submissions: Array<Record<string, unknown>> = [];
    for (const [index, event] of events.entries()) {
      const controlProposalAck = await issueControlProposalAckApi(
        request,
        token,
        event,
        leases[index],
        opts.server,
        context,
      );
      submissions.push({
        event,
        authorization_lease: leases[index],
        ...(controlProposalAck
          ? { control_proposal_ack: controlProposalAck }
          : {}),
      });
    }
    return submissions;
  }
  throw new Error(`${context}: exhausted actor-frontier retry loop`);
}

export async function submitSignedEventBatchApi(
  request: APIRequestContext,
  token: string,
  events: Array<Record<string, unknown>>,
  opts: { server?: SolandKey; context?: string } = {},
) {
  if (events.length === 0) {
    throw new Error("Event batch must contain at least one Event");
  }
  const context = opts.context ?? "submit Event batch";
  if (events[0]?.kind !== "ak.realm.create") {
    for (const event of events) {
      await applyRegisteredCbsPlane(request, token, event, opts.server);
    }
    // Leases authorize a candidate but do not repair its causal sequence.
    // Bind the first Event to the accepted frontier, then author each sibling
    // against its exact predecessor before obtaining any publication evidence.
    await advanceEnvelopeToActorFrontier(request, token, events[0], opts.server);
    refreshBatchActorChain(events);
  }
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const leaseResponse = await issueAuthorizationLeasesApi(
      request,
      token,
      events,
      opts.server,
    );
    const leaseText = await leaseResponse.text();
    if (![200, 201].includes(leaseResponse.status())) {
      const leaseBody = parseJsonOrRaw(leaseText);
      const actorFrontierRefreshRequired = requiresActorFrontierRefresh(
        leaseResponse.status(),
        leaseBody,
        leaseText,
      );
      if (!actorFrontierRefreshRequired || attempt === 2) {
        expect(
          [200, 201],
          `${context} lease issuance returned ${leaseResponse.status()}: ${leaseText}`,
        ).toContain(leaseResponse.status());
      }
      await advanceEnvelopeToActorFrontier(
        request,
        token,
        events[0],
        opts.server,
      );
      refreshBatchActorChain(events);
      continue;
    }
    const authorizationLeases = authorizationLeasesFromIssueOutcome(
      leaseText,
      events.length,
      context,
    );
    const anchorUnit = events[0]?.kind === "ak.realm.create";
    const submissions: Array<Record<string, unknown>> = [];
    for (const [index, event] of events.entries()) {
      const controlControlProposalAck = anchorUnit
        ? undefined
        : await issueControlProposalAckApi(
            request,
            token,
            event,
            authorizationLeases[index],
            opts.server,
            context,
          );
      submissions.push({
        event,
        authorization_lease: authorizationLeases[index],
        ...(controlControlProposalAck
          ? { control_proposal_ack: controlControlProposalAck }
          : {}),
      });
    }
    const realmId = stringValue(events[0]?.realm_id);
    const actorId = eventPrincipalId(events[0]);
    const actorControlRealm = actorId
      ? principalControlRealmForIdIfKnown(actorId)
      : undefined;
    const previousControlRoot =
      realmId &&
      events.every((event) => stringValue(event.realm_id) === realmId) &&
      submissions.some((submission) => submission.control_proposal_ack) &&
      !events.some((event) => event.kind === "ak.invite.accept") &&
      (!actorControlRealm || realmId !== actorControlRealm)
        ? (await readRealmSealFrontier(request, token, realmId, opts.server))
            .control_event_set_root
        : undefined;
    const eventsUrl = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
    const response = await request.post(eventsUrl, {
      headers: {
        ...authHeaders(token, "POST", eventsUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({
        events: submissions,
      }),
    });
    const text = await response.text();
    if ([200, 201].includes(response.status())) {
      const outcome = JSON.parse(text) as Record<string, unknown>;
      rememberPublicationEvidence(events, authorizationLeases, outcome,
        { token, server: opts.server }, submissions.map((submission) => submission.control_proposal_ack));
      if (realmId && previousControlRoot) {
        await waitForRealmControlIdleApi(request, token, realmId, {
          server: opts.server,
          afterControlEventSetRoot: previousControlRoot,
          timeoutMs: 60_000,
        });
      }
      return outcome;
    }
    const body = JSON.parse(text) as unknown;
    if (
      response.status() === 403 &&
      wireErrCode(body) === "capability_denied" &&
      !events.some((event) => {
        const realmId = stringValue(event.realm_id);
        return (
          realmId !== undefined &&
          realmAuthorityControllers.has(
            realmAuthorityControllerKey(opts.server, realmId),
          )
        );
      }) &&
      attempt < 2
    ) {
      for (const event of events) {
        await forceConformanceCbsBasis(request, event, opts.server);
      }
      continue;
    }
    const actorFrontierRefreshRequired = requiresActorFrontierRefresh(
      response.status(),
      body,
      text,
    );
    if (!actorFrontierRefreshRequired || attempt === 2) {
      expect(
        [200, 201],
        `${context} returned ${response.status()}: ${text}`,
      ).toContain(response.status());
    }
    await advanceEnvelopeToActorFrontier(
      request,
      token,
      events[0],
      opts.server,
    );
    refreshBatchActorChain(events);
  }
  throw new Error(`${context}: exhausted actor-frontier retry loop`);
}

/**
 * Submit a signed Event through the canonical lease + publication rail while
 * preserving the raw response for negative tests that intentionally expect a
 * non-2xx policy verdict.
 */
export async function rawSubmitSignedEventApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: { server?: SolandKey; retryActorFrontier?: boolean } = {},
): Promise<APIResponse> {
  await applyRegisteredCbsPlane(request, token, envelope, opts.server);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const leaseResponse = await issueAuthorizationLeasesApi(
      request,
      token,
      [envelope],
      opts.server,
    );
    if (![200, 201].includes(leaseResponse.status())) {
      const leaseText = await leaseResponse.text();
      const leaseBody = parseJsonOrRaw(leaseText);
      if (
        opts.retryActorFrontier === false ||
        !requiresActorFrontierRefresh(
          leaseResponse.status(),
          leaseBody,
          leaseText,
        ) ||
        attempt === 2
      ) {
        return leaseResponse;
      }
      await advanceEnvelopeToActorFrontier(
        request,
        token,
        envelope,
        opts.server,
      );
      continue;
    }

    const authorizationLease = authorizationLeasesFromIssueOutcome(
      await leaseResponse.text(),
      1,
      `submit ${String(envelope.kind)}`,
    )[0];
    const controlControlProposalAck = await issueControlProposalAckApi(
      request,
      token,
      envelope,
      authorizationLease,
      opts.server,
      `submit ${String(envelope.kind)}`,
    );
    const eventsUrl = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
    const response = await request.post(eventsUrl, {
      headers: {
        ...authHeaders(token, "POST", eventsUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({
        event: envelope,
        authorization_lease: authorizationLease,
        ...(controlControlProposalAck
          ? { control_proposal_ack: controlControlProposalAck }
          : {}),
      }),
    });
    const responseText = await response.text();
    const responseBody = parseJsonOrRaw(responseText);
    if (
      opts.retryActorFrontier === false ||
      !requiresActorFrontierRefresh(
        response.status(),
        responseBody,
        responseText,
      ) ||
      attempt === 2
    ) {
      return response;
    }
    await advanceEnvelopeToActorFrontier(request, token, envelope, opts.server);
  }
  throw new Error(
    `submit ${String(envelope.kind)} exhausted actor-frontier retry loop`,
  );
}

async function issueControlProposalAckApi(
  request: APIRequestContext,
  token: string,
  event: Record<string, unknown>,
  authorizationLease: Record<string, unknown> | undefined,
  server: SolandKey | undefined,
  context: string,
): Promise<Record<string, unknown> | undefined> {
  // In the Standard submission context, seal_basis distinguishes an ordinary
  // non-genesis Control Move from a DataEvent. Anchor units are filtered by
  // their batch caller and must never enter this operation.
  if (event.seal_basis == null) {
    return undefined;
  }
  if (isAuthorityAuthoredSelfPrincipalMove(event)) {
    // cbs-profiles.md §4: once the human PCR genesis is accepted, a current
    // device authoring in its own principal-control Realm is the authority.
    // This exceptional Control Move must omit an independent Proposal Ack.
    return undefined;
  }
  const url = `${solandBaseUrl(server)}/_arkret/self/control-proposal-acks`;
  const response = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({
      event,
      publication_mode: authorizationLease ? "delayed" : "online",
      ...(authorizationLease ? { authorization_lease: authorizationLease } : {}),
    }),
  });
  const text = await response.text();
  expect(
    [200, 201],
    `${context} Control Proposal Ack issuance returned ${response.status()}: ${text}`,
  ).toContain(response.status());
  const body = parseJsonOrRaw(text) as Record<string, unknown>;
  const member = body.authority_ack as Record<string, unknown> | undefined;
  if (!member) {
    throw new Error(
      `${context} Control Proposal Ack issuance omitted authority_ack`,
    );
  }
  return {
    kind: "signed_ack",
    realm_id: member.realm_id,
    proposal_digest: member.proposal_digest,
    received_at: member.received_at,
    decision_due_at: member.decision_due_at,
    absolute_due_at: member.absolute_due_at,
    defer_count: 0,
    authority_set_ref: member.authority_set_ref,
    authority_acks: [member],
  };
}

function isAuthorityAuthoredSelfPrincipalMove(
  event: Record<string, unknown>,
): boolean {
  const actorId = eventPrincipalId(event);
  const scopeRef = event.scope_ref as Record<string, unknown> | undefined;
  const realmId =
    stringValue(event.realm_id) ?? stringValue(scopeRef?.realm_id);
  const actorControlRealm = actorId
    ? principalControlRealmForIdIfKnown(actorId)
    : undefined;
  if (
    !actorId ||
    !realmId ||
    !actorControlRealm ||
    realmId !== actorControlRealm
  ) {
    return false;
  }
  return true;
}

export async function issueAuthorizationLeasesApi(
  request: APIRequestContext,
  token: string,
  events: Array<Record<string, unknown>>,
  server?: SolandKey,
): Promise<APIResponse> {
  const requestBody = {
    submissions: events.map((event) => ({ event })),
  };
  const requestDigest = sha256CanonicalJson(requestBody);
  const url = `${solandBaseUrl(server)}/_arkret/self/authorization-leases`;
  return await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
      "idempotency-key": `cotest-lease-${requestDigest}`,
    },
    data: canonicalJson(requestBody),
  });
}

/// Bind an authored Event to the same current CBS plane and actor frontier
/// used by `prepareSignedEventSubmissionApi`, but stop before requesting the
/// lease. Negative conformance cases use this boundary to assert that a lease
/// issuer performs full pre-admission and therefore refuses an Event that
/// cannot be admitted; a lease is never a way to create missing authority.
export async function prepareEventForAuthorizationLeaseApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  server?: SolandKey,
): Promise<void> {
  await applyRegisteredCbsPlane(request, token, envelope, server);
  await advanceEnvelopeToActorFrontier(request, token, envelope, server);
}

export function authorizationLeasesFromIssueOutcome(
  text: string,
  expectedCount: number,
  context: string,
): Array<Record<string, unknown>> {
  const body = parseJsonOrRaw(text);
  const leases =
    body &&
    typeof body === "object" &&
    Array.isArray((body as Record<string, unknown>).authorization_leases)
      ? ((body as Record<string, unknown>).authorization_leases as Array<
          Record<string, unknown>
        >)
      : undefined;
  if (!leases || leases.length !== expectedCount) {
    throw new Error(
      `${context} lease issuance returned ${leases?.length ?? 0} leases for ${expectedCount} Events: ${text}`,
    );
  }
  return leases;
}

function parseJsonOrRaw(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { raw: text };
  }
}

// `service-operation-dtos.schema.json#/$defs/EventFederationSubmission` — the
// exact body `federationEventWireBody` pushes to `/_arkret/peer/events`, so it
// is generated rather than restated. It was three opaque
// `Record<string, unknown>` members before.
type PublicationEvidence = EventFederationSubmission;

const publicationEvidenceByEventId = new Map<string, PublicationEvidence>();
const publicationSourceByEventId = new Map<string, { token: string; server?: SolandKey }>();

function rememberPublicationEvidence(
  events: Array<Record<string, unknown>>,
  leases: Array<Record<string, unknown>>,
  outcome: Record<string, unknown>,
  source: { token: string; server?: SolandKey },
  controlProposalAcks: unknown[],
): void {
  const receipts = Array.isArray(outcome.ingress_receipts)
    ? (outcome.ingress_receipts as Array<Record<string, unknown>>)
    : [];
  if (receipts.length !== 0 && receipts.length !== events.length) {
    throw new Error(
      `publication returned ${receipts.length} ingress receipts for ${events.length} Events: ${JSON.stringify({
        status: outcome.status,
        rejection_codes: Array.isArray(outcome.rejections)
          ? outcome.rejections.map((item: Record<string, unknown>) => item.reason_code ?? item.code)
          : [],
        rejection_topics: Array.isArray(outcome.rejections)
          ? outcome.rejections.map((item: Record<string, unknown>) => [
              "actor_seq", "prev_refs", "digest", "proof", "seal_basis", "authorization_lease",
              "control_proposal_ack", "unknown field", "canonical", "dot", "frontier", "signature",
              "payload", "binding", "causal", "lease", "sequence", "schema", "metadata",
            ].filter((topic) => String(item.detail ?? item.message ?? "").includes(topic)))
          : [],
      })}`,
    );
  }
  events.forEach((event, index) => {
    const eventId = stringValue(event.event_id);
    if (!eventId) {
      throw new Error("published Event is missing event_id");
    }
    publicationEvidenceByEventId.set(eventId, {
      event: stripUndefined(event) as PublicationEvidence["event"],
      ...(leases[index]
        ? {
            authorization_lease: leases[
              index
            ] as PublicationEvidence["authorization_lease"],
          }
        : {}),
      ingress_receipts: (receipts[index]
        ? [receipts[index]]
        : []) as PublicationEvidence["ingress_receipts"],
      ...(controlProposalAcks[index] ? {
        control_proposal_ack: controlProposalAcks[index] as PublicationEvidence["control_proposal_ack"],
      } : {}),
    });
    publicationSourceByEventId.set(eventId, source);
  });
}

function requiresActorFrontierRefresh(
  status: number,
  body: unknown,
  text: string,
): boolean {
  return (
    (status === 409 &&
      wireErrCode(body) === "cas_conflict" &&
      text.includes("actor_seq is older than the accepted actor frontier")) ||
    (status === 422 &&
      wireErrCode(body) === "schema_violation" &&
      (text.includes("actor-chain genesis must use actor_seq=0") ||
        text.includes(
          "prev_refs must include the preceding actor sequence in the same Realm",
        )))
  );
}

function refreshBatchActorChain(events: Array<Record<string, unknown>>): void {
  for (let index = 1; index < events.length; index += 1) {
    const previous = events[index - 1];
    const current = events[index];
    const previousActorSeq = previous.actor_seq;
    const previousEventId = stringValue(previous.event_id);
    if (
      typeof previousActorSeq !== "number" ||
      !Number.isSafeInteger(previousActorSeq) ||
      !previousEventId
    ) {
      throw new Error("Event batch predecessor has an invalid actor chain");
    }
    current.actor_seq = previousActorSeq + 1;
    current.prev_refs = [previousEventId];
    const proofVerificationMethod = Array.isArray(current.proofs)
      ? stringValue(
          (current.proofs[0] as Record<string, unknown> | undefined)
            ?.verification_method,
        )
      : undefined;
    refreshEventEnvelopeProof(current, proofVerificationMethod);
  }
}

export async function advanceEnvelopeToActorFrontier(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  server?: SolandKey,
  allowInvisibleRealmGenesis = false,
  invisibleActorFrontier?: {
    nextActorSeq: number;
    frontierEventIds: string[];
  },
): Promise<void> {
  const actorId = eventActorId(envelope);
  const realmId = stringValue(envelope.realm_id);
  if (!realmId) {
    throw new Error(
      "Event envelope realm_id is required to refresh its frontier",
    );
  }
  const frontierUrl = `${solandBaseUrl(server)}/_arkret/self/events/frontier`;
  const response = await request.fetch(frontierUrl, {
    method: "QUERY",
    data: canonicalJson({ actor_id: actorId, realm_id: realmId }),
    headers: {
      ...authHeaders(token, "QUERY", frontierUrl),
      "content-type": "application/json",
    },
  });
  if (allowInvisibleRealmGenesis && response.status() === 404) {
    const proofVerificationMethod = Array.isArray(envelope.proofs)
      ? stringValue(
          (envelope.proofs[0] as Record<string, unknown> | undefined)
            ?.verification_method,
        )
      : undefined;
    envelope.actor_seq = invisibleActorFrontier?.nextActorSeq ?? 0;
    envelope.prev_refs = invisibleActorFrontier?.frontierEventIds ?? [];
    refreshEventEnvelopeProof(envelope, proofVerificationMethod);
    return;
  }
  const body = await expectJsonOk<{
    frontier?: {
      kind?: unknown;
      realm_id?: unknown;
      actor_id?: unknown;
      next_actor_seq?: unknown;
      frontier_event_ids?: unknown;
    };
  }>(response, `read Realm actor frontier for (${realmId}, ${actorId})`);
  if (
    body.frontier?.kind !== "realm_actor" ||
    body.frontier.realm_id !== realmId ||
    canonicalJson(body.frontier.actor_id) !== canonicalJson(actorId)
  ) {
    throw new Error(
      "combined Event frontier response does not match its selector",
    );
  }
  const actorSeq = body.frontier.next_actor_seq;
  if (typeof actorSeq !== "number" || !Number.isSafeInteger(actorSeq)) {
    throw new Error(
      `Realm actor frontier for ${actorId} has no valid next_actor_seq`,
    );
  }
  if (
    !Array.isArray(body.frontier.frontier_event_ids) ||
    body.frontier.frontier_event_ids.some((value) => typeof value !== "string")
  ) {
    throw new Error(
      `Realm actor frontier for ${actorId} has invalid frontier_event_ids`,
    );
  }
  const proofVerificationMethod = Array.isArray(envelope.proofs)
    ? stringValue(
        (envelope.proofs[0] as Record<string, unknown> | undefined)
          ?.verification_method,
      )
    : undefined;
  envelope.actor_seq = actorSeq;
  envelope.prev_refs = [...body.frontier.frontier_event_ids];
  refreshEventEnvelopeProof(envelope, proofVerificationMethod);
}

export async function readRealmSealBasis(
  request: APIRequestContext,
  token: string,
  realmId: string,
  server?: SolandKey,
): Promise<Record<string, unknown>> {
  const frontier = await readRealmSealFrontier(request, token, realmId, server);
  // `event-envelope.schema.json`: the sorted Seal leaves are the sole producer
  // commitment. The Seal roots stay on the Seal — a receiver resolves each leaf
  // and recomputes them — so copying them into the Event is an unknown member.
  return { leaves: [frontier.seal_id] };
}

// Local projection of the registered `RealmSealFrontierView`: the single
// accepted leaf of a `single_signer` test Realm, plus the roots the caller
// recomputes from that resolved leaf Seal, plus a flat pending-digest list.
//
// The view itself carries no root hint — `event-auth-state-resolution.md`
// requires the consumer to resolve and verify every leaf Seal — so the two
// roots below come from `ak.self.seals.read.resolve.v1`, never from the frontier
// response.
type RealmSealFrontier = {
  seal_id: string;
  control_event_set_root: string;
  state_root: string;
  pending_proposal_digests: string[];
};

export async function readAcceptedSeal(
  request: APIRequestContext,
  token: string,
  realmId: string,
  sealId: string,
  server?: SolandKey,
): Promise<Record<string, unknown>> {
  const resolveUrl = `${solandBaseUrl(server)}/_arkret/self/seals/resolve`;
  const response = await request.fetch(resolveUrl, {
    method: "QUERY",
    data: canonicalJson({ realm_id: realmId, seal_refs: [sealId] }),
    headers: {
      ...authHeaders(token, "QUERY", resolveUrl),
      "content-type": "application/json",
    },
  });
  const body = await expectJsonOk<{
    seals?: Array<Record<string, unknown>>;
  }>(response, `resolve accepted Seal ${sealId}`);
  const seal = (body.seals ?? []).find((candidate) => candidate.id === sealId);
  if (!seal) {
    throw new Error(
      `accepted Seal ${sealId} did not resolve: ${JSON.stringify(body)}`,
    );
  }
  return seal;
}

// Receiver-relative CBS dependency closure (cbs-profiles.md section 5).
// The caller must separately transport any control Events missing at the peer.
export async function readAcceptedSealBundle(
  request: APIRequestContext,
  token: string,
  realmId: string,
  targetSealRef: string,
  server?: SolandKey,
): Promise<Record<string, unknown>> {
  const seals = new Map<string, Record<string, unknown>>();
  const pending = [targetSealRef];
  while (pending.length > 0) {
    const id = pending.pop()!;
    if (seals.has(id)) continue;
    if (seals.size >= 256) throw new Error("CBS Seal closure exceeds the v1 bound");
    const seal = await readAcceptedSeal(request, token, realmId, id, server);
    seals.set(id, seal);
    for (const predecessor of (seal.predecessor_refs ?? []) as string[]) {
      pending.push(predecessor);
    }
  }
  return {
    target_seal_ref: targetSealRef,
    seals: [...seals.entries()]
      .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
      .map(([, seal]) => seal),
    control_moves: [],
    inclusion_proofs: [],
    availability_proofs: [],
  };
}

async function resolveAcceptedSeal(
  request: APIRequestContext,
  token: string,
  realmId: string,
  sealId: string,
  server?: SolandKey,
): Promise<{ control_event_set_root: string; state_root: string }> {
  const resolveUrl = `${solandBaseUrl(server)}/_arkret/self/seals/resolve`;
  const response = await request.fetch(resolveUrl, {
    method: "QUERY",
    data: canonicalJson({ realm_id: realmId, seal_refs: [sealId] }),
    headers: {
      ...authHeaders(token, "QUERY", resolveUrl),
      "content-type": "application/json",
    },
  });
  const body = await expectJsonOk<{
    seals?: Array<{
      id?: unknown;
      control_event_set_root?: unknown;
      state_root?: unknown;
    }>;
  }>(response, `resolve accepted Seal ${sealId}`);
  const seal = (body.seals ?? []).find((candidate) => candidate.id === sealId);
  if (
    !seal ||
    typeof seal.control_event_set_root !== "string" ||
    typeof seal.state_root !== "string"
  ) {
    throw new Error(
      `accepted Seal ${sealId} did not resolve: ${JSON.stringify(body)}`,
    );
  }
  return {
    control_event_set_root: seal.control_event_set_root,
    state_root: seal.state_root,
  };
}

async function readRealmSealFrontier(
  request: APIRequestContext,
  token: string,
  realmId: string,
  server?: SolandKey,
): Promise<RealmSealFrontier> {
  const frontierUrl = `${solandBaseUrl(server)}/_arkret/self/seals/frontier`;
  const response = await request.fetch(frontierUrl, {
    method: "QUERY",
    data: canonicalJson({ realm_id: realmId }),
    headers: {
      ...authHeaders(token, "QUERY", frontierUrl),
      "content-type": "application/json",
    },
  });
  // The endpoint answers 200 with an absent frontier before the genesis Seal
  // lands, so every member is treated as possibly missing and re-checked at
  // runtime below.
  const body = await expectJsonOk<{
    frontier?: {
      kind?: string;
      seal_basis?: { leaves?: unknown };
      governance_health?: Partial<RealmSealFrontierView["governance_health"]>;
    };
  }>(response, `read Realm Seal frontier for ${realmId}`);
  const frontier = body.frontier;
  const leaves = frontier?.seal_basis?.leaves;
  if (
    frontier?.kind !== "realm_seal" ||
    !Array.isArray(leaves) ||
    leaves.length !== 1 ||
    typeof leaves[0] !== "string"
  ) {
    throw new Error(
      `Realm Seal frontier for ${realmId} has an invalid shape: ${JSON.stringify(body)}`,
    );
  }
  const sealId = leaves[0];
  const roots = await resolveAcceptedSeal(
    request,
    token,
    realmId,
    sealId,
    server,
  );
  return {
    seal_id: sealId,
    control_event_set_root: roots.control_event_set_root,
    state_root: roots.state_root,
    pending_proposal_digests: (
      frontier.governance_health?.pending_proposals ?? []
    ).flatMap((proposal) =>
      typeof proposal.control_proposal_ack.proposal_digest === "string"
        ? [proposal.control_proposal_ack.proposal_digest]
        : [],
    ),
  };
}

async function waitForRealmSealBasis(
  request: APIRequestContext,
  token: string,
  realmId: string,
  server?: SolandKey,
  timeoutMs = 15_000,
): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const frontier = await readRealmSealFrontier(
        request,
        token,
        realmId,
        server,
      );
      if (frontier.pending_proposal_digests.length === 0) {
        return {
          leaves: [frontier.seal_id],
          control_event_set_root: frontier.control_event_set_root,
          state_root: frontier.state_root,
        };
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(
    `Realm ${realmId} founding Seal was not materialized within ${timeoutMs}ms`,
    { cause: lastError },
  );
}

export async function waitForRealmControlIdleApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: {
    server?: SolandKey;
    afterControlEventSetRoot?: string;
    timeoutMs?: number;
  } = {},
): Promise<Record<string, unknown>> {
  const deadline = Date.now() + (opts.timeoutMs ?? 30_000);
  let lastFrontier: RealmSealFrontier | undefined;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      lastFrontier = await readRealmSealFrontier(
        request,
        token,
        realmId,
        opts.server,
      );
      if (
        lastFrontier.pending_proposal_digests.length === 0 &&
        (!opts.afterControlEventSetRoot ||
          lastFrontier.control_event_set_root !== opts.afterControlEventSetRoot)
      ) {
        return {
          leaves: [lastFrontier.seal_id],
          control_event_set_root: lastFrontier.control_event_set_root,
          state_root: lastFrontier.state_root,
        };
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(
    `Realm ${realmId} control frontier did not become idle after ${opts.afterControlEventSetRoot ?? "its current root"} within ${opts.timeoutMs ?? 30_000}ms; last frontier=${JSON.stringify(lastFrontier)}; last error=${String(lastError instanceof Error ? lastError.message : lastError).replace(/[A-Za-z0-9_-]{32,}/g, "[redacted]").slice(0, 600)}`,
    { cause: lastError },
  );
}

async function applyRegisteredCbsPlane(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  server?: SolandKey,
): Promise<void> {
  const kind = stringValue(envelope.kind);
  const realmId = stringValue(envelope.realm_id);
  const actorId = eventPrincipalId(envelope);
  if (!kind || !realmId || !actorId) {
    throw new Error("CBS preparation requires kind, realm_id, and actor_id");
  }
  const descriptor = eventKindDescriptor(kind);
  if (
    !descriptor?.reducer_input ||
    kind === "ak.realm.create" ||
    kind === "ak.device.reanchor"
  ) {
    return;
  }

  let changed = false;
  const canonicalRealm = realmAuthorityControllers.has(
    realmAuthorityControllerKey(server, realmId),
  );
  const actorControlRealm = principalControlRealmForIdIfKnown(actorId);
  const actorControlsRealm =
    canonicalJson(realmAuthorityControllers.get(
      realmAuthorityControllerKey(server, realmId),
    ) ?? null) === canonicalJson(eventActorId(envelope)) || actorControlRealm === realmId;
  if (
    envelope.authorization_ref === undefined &&
    actorControlsRealm &&
    realmRootMayAuthorEventKind(kind)
  ) {
    // realm-and-space.md section 2.5: the creator identity is only audit
    // metadata. Operational owner authority is an explicit inclusion proof of
    // the registered authority-root cell at this Event's governance basis.
    envelope.authorization_ref = REALM_AUTHORITY_ROOT_CELL;
    changed = true;
  }
  if (descriptor.plane === "control") {
    const sealBasis = envelope.seal_basis as
      Record<string, unknown> | undefined;
    if (
      !sealBasis ||
      !Array.isArray(sealBasis.leaves) ||
      sealBasis.leaves.length === 0
    ) {
      try {
        envelope.seal_basis = await readRealmSealBasis(
          request,
          token,
          realmId,
          server,
        );
      } catch {
        if (canonicalRealm && actorControlsRealm) {
          envelope.seal_basis = await waitForRealmSealBasis(
            request,
            token,
            realmId,
            server,
            60_000,
          );
        } else {
          const directoryBasis = await readDirectoryJoinCandidateSealBasis(
            request,
            realmId,
            actorId,
          );
          if (directoryBasis) {
            envelope.seal_basis = directoryBasis;
          } else {
            await forceConformanceCbsBasis(request, envelope, server);
            return;
          }
        }
      }
      changed = true;
    }
  } else if (descriptor.plane === "data") {
    if (
      envelope.seal_ref === undefined ||
      envelope.auth_context === undefined
    ) {
      try {
        const basis = await readRealmSealBasis(request, token, realmId, server);
        const leaves = basis.leaves;
        if (!Array.isArray(leaves) || typeof leaves[0] !== "string") {
          throw new Error(`Realm ${realmId} has no citable Seal leaf`);
        }
        envelope.seal_ref = leaves[0];
      } catch {
        if (canonicalRealm) {
          const basis = await waitForRealmSealBasis(
            request,
            token,
            realmId,
            server,
            60_000,
          );
          const leaves = basis.leaves;
          if (!Array.isArray(leaves) || typeof leaves[0] !== "string") {
            throw new Error(`Realm ${realmId} has no citable Seal leaf`);
          }
          envelope.seal_ref = leaves[0];
        } else {
          // Only an isolated conformance Realm has no canonical Seal frontier.
          // A canonically created Realm must use its real frozen governance
          // state; the server refuses synthetic state grafts onto that DAG.
          const response = await request.post(
            `${solandBaseUrl(server)}/_arkret/_conformance/realm-basis`,
            {
              data: {
                realm_id: realmId,
                subject: actorId,
                data_plane_actions: [kind],
              },
            },
          );
          const basis = await expectJsonOk<{ seal_id: string }>(
            response,
            `seed conformance Realm basis for ${kind}`,
          );
          envelope.seal_ref = basis.seal_id;
        }
      }
      const proof = Array.isArray(envelope.proofs)
        ? (envelope.proofs[0] as Record<string, unknown> | undefined)
        : undefined;
      const verificationMethod =
        stringValue(proof?.verification_method) ?? `${actorId}#device`;
      envelope.auth_context = eventAuthContext(verificationMethod);
      changed = true;
    }
  }

  if (changed) {
    const proof = Array.isArray(envelope.proofs)
      ? (envelope.proofs[0] as Record<string, unknown> | undefined)
      : undefined;
    refreshEventEnvelopeProof(
      envelope,
      stringValue(proof?.verification_method),
    );
  }
}

async function readDirectoryJoinCandidateSealBasis(
  request: APIRequestContext,
  realmId: string,
  actorId: string,
  joinMethod?: string,
): Promise<Record<string, unknown> | undefined> {
  const directory = teabayBaseUrl();
  if (!directory) return undefined;
  // A Station session grant must never be disclosed to a Directory service.
  const response = await request.post(`${directory}/_arkret/find/directory/resolve-realm`, {
    data: { realm_id: realmId, requester_id: actorId },
  });
  if (!response.ok()) return undefined;
  const body = await response.json() as {
    join_candidates?: Array<{join_methods?: string[]; seal_basis?: Record<string, unknown>}>;
  };
  return body.join_candidates?.find(candidate => {
    const basis = candidate.seal_basis;
    return (!joinMethod || candidate.join_methods?.includes(joinMethod)) &&
      basis && Array.isArray(basis.leaves) && basis.leaves.length > 0;
  })?.seal_basis;
}

async function forceConformanceCbsBasis(
  request: APIRequestContext,
  envelope: Record<string, unknown>,
  server?: SolandKey,
): Promise<void> {
  const kind = stringValue(envelope.kind);
  const realmId = stringValue(envelope.realm_id);
  const actorId = eventPrincipalId(envelope);
  if (!kind || !realmId || !actorId) {
    throw new Error("CBS fixture basis requires kind, realm_id, and actor_id");
  }
  const descriptor = eventKindDescriptor(kind);
  if (!descriptor?.reducer_input) {
    return;
  }
  const proof = Array.isArray(envelope.proofs)
    ? (envelope.proofs[0] as Record<string, unknown> | undefined)
    : undefined;
  const verificationMethod = stringValue(proof?.verification_method);
  const signerDid = verificationMethod?.split("#", 1)[0];
  if (!signerDid?.startsWith("did:")) {
    throw new Error(
      `CBS fixture basis requires a canonical signer DID for ${kind}`,
    );
  }
  const response = await request.post(
    `${solandBaseUrl(server)}/_arkret/_conformance/realm-basis`,
    {
      headers: { "content-type": "application/json" },
      data: canonicalJson({
        realm_id: realmId,
        subject: signerDid,
        data_plane_actions: [fixtureCapabilityAction(kind)],
      }),
    },
  );
  const basis = await expectJsonOk<{
    seal_id: string;
    control_event_set_root: string;
    state_root: string;
  }>(response, `seed conformance Realm basis for ${kind}`);
  if (descriptor.plane === "control") {
    envelope.seal_basis = {
      leaves: [basis.seal_id],
    };
    delete envelope.seal_ref;
    delete envelope.auth_context;
  } else {
    envelope.seal_ref = basis.seal_id;
    envelope.auth_context = eventAuthContext(
      verificationMethod ?? `${actorId}#device`,
    );
    delete envelope.seal_basis;
  }
  refreshEventEnvelopeProof(envelope, stringValue(proof?.verification_method));
}

function eventAuthContext(verificationMethod: string): Record<string, unknown> {
  // `auth_context.key_id` is an opaque local key label
  // (`event-envelope.schema.json` closes it over `^(?!ak:)[A-Za-z0-9._:-]{1,128}$`),
  // decoupled from the verification-method fragment: the fragment may stay a
  // typed device id, but the `ak:` sigil is stripped before it becomes a key_id
  // (same fragment→key_id mapping as inkson `event_submit.rs` and soland
  // `cbs_basis.rs`).
  const fragmentIndex = verificationMethod.indexOf("#");
  const fragment =
    fragmentIndex >= 0
      ? verificationMethod.slice(fragmentIndex + 1)
      : verificationMethod;
  return {
    key_id: fragment.startsWith("ak:") ? fragment.slice(3) : fragment,
    key_epoch: 0,
  };
}

export async function prepareSignedEventCbsApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: { server?: SolandKey } = {},
): Promise<void> {
  await applyRegisteredCbsPlane(request, token, envelope, opts.server);
}

export async function seedConformanceRealmBasisApi(
  request: APIRequestContext,
  realmId: string,
  subjectId: string,
  dataPlaneActions: string[],
  server?: SolandKey,
): Promise<{
  seal_id: string;
  control_event_set_root: string;
  state_root: string;
}> {
  const response = await request.post(
    `${solandBaseUrl(server)}/_arkret/_conformance/realm-basis`,
    {
      data: {
        realm_id: realmId,
        subject: subjectId,
        data_plane_actions: dataPlaneActions,
      },
    },
  );
  return await expectJsonOk(response, "seed conformance Realm basis");
}

export async function alignSignedEventToActorFrontierApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: { server?: SolandKey } = {},
): Promise<void> {
  await advanceEnvelopeToActorFrontier(request, token, envelope, opts.server);
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
  // Primary: Realm projection carries the authoritative default_strand_id.
  const realmUrl = `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
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
  const strandsUrl = `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}/strands`;
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
  const actorId = await currentActorIdApi(request, token, opts);
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

const cotestHlcNodeSecret = randomBytes(16).toString("hex");
const cotestHlcStateByNode = new Map<
  string,
  { unixMs: number; logical: number }
>();

function nextEnvelopeHlc(realmId: string, createdAt: string): string {
  const requestedUnixMs = Date.parse(createdAt);
  if (!Number.isFinite(requestedUnixMs)) {
    throw new TypeError(`invalid event created_at for HLC: ${createdAt}`);
  }
  const unixMs = Math.trunc(requestedUnixMs);
  const nodeIdHash = createHash("sha256")
    .update("arkret-hlc-v1")
    .update("\0")
    .update(realmId)
    .update("\0")
    .update(cotestHlcNodeSecret)
    .digest("hex")
    .slice(0, 8);
  const stateKey = `${realmId}\0${nodeIdHash}`;
  const previous = cotestHlcStateByNode.get(stateKey);
  let nextUnixMs = unixMs;
  let logical = 0;
  if (previous) {
    if (unixMs > previous.unixMs) {
      nextUnixMs = unixMs;
    } else {
      nextUnixMs = previous.unixMs;
      logical = previous.logical + 1;
      if (logical > 0xffff) {
        throw new Error(`cotest HLC logical overflow for realm ${realmId}`);
      }
    }
  }
  cotestHlcStateByNode.set(stateKey, { unixMs: nextUnixMs, logical });
  return `${nextUnixMs.toString(16).padStart(12, "0").slice(-12)}-${logical
    .toString(16)
    .padStart(4, "0")}-${nodeIdHash}`;
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
    schemaId: schemaIdForEventKind(args.kind),
    sealBasis: args.sealBasis,
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
    serviceBindingFrontier?: string[];
    cbsProofBundles?: Array<Record<string, unknown>>;
  },
) {
  const response = await rawPushFederationEvents(request, events, opts);
  return await expectJsonOk<{
    status?: string;
    accepted?: string[];
    duplicate?: string[];
    rejections?: Array<Record<string, unknown>>;
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
    // Negative-coverage hook: drive the RFC 9421 freshness window past its
    // bound so verify rejects on expiry (federation.md §3.2). The signature
    // itself stays cryptographically valid — only created/expires are stale.
    expireSignature?: boolean;
    relaySourceServiceId?: string;
    serviceBindingFrontier?: string[];
    cbsProofBundles?: Array<Record<string, unknown>>;
    // Applet transactions accept Events outside the self-submit helper's
    // publication cache. Resolve their original accepted bytes at this source.
    acceptedSource?: { token: string; server?: SolandKey };
  },
) {
  const destination = opts.destination ?? solandServiceId(opts.server);
  const url = `${solandBaseUrl(opts.server)}/_arkret/peer/events`;
  const body = peerEventsSubmitBody(
    opts.realmId,
    await federationEventWireBodies(request, events, opts.acceptedSource),
    {
      serviceBindingFrontier: opts.serviceBindingFrontier,
      cbsProofBundles: opts.cbsProofBundles,
    },
  );
  const sourceServiceId = opts.relaySourceServiceId ?? opts.origin;
  const headers = signedFederationPushHeaders(
    sourceServiceId,
    destination,
    url,
    body,
    {
      expireSignature: opts.expireSignature,
      idempotencyKey: opts.idempotencyKey,
    },
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

async function federationEventWireBodies(
    request: APIRequestContext,
    events: Array<Record<string, unknown>>,
    acceptedSource?: { token: string; server?: SolandKey },
): Promise<PublicationEvidence[]> {
  const groups = new Map<string, { token: string; server?: SolandKey; eventIds: string[] }>();
  const entries = events.map((event) => {
    const eventId = stringValue(event.event_id);
    const evidence = (eventId ? publicationEvidenceByEventId.get(eventId) : undefined)
      ?? (acceptedSource ? { event: event as PublicationEvidence["event"], ingress_receipts: [] } : undefined);
    const source = (eventId ? publicationSourceByEventId.get(eventId) : undefined) ?? acceptedSource;
    if (!eventId || !evidence || !source) {
      throw new Error(`federation requires an accepted source Event and publication evidence: ${eventId ?? "<missing event_id>"}`);
    }
    const key = `${solandBaseUrl(source.server)}\0${source.token}`;
    const group = groups.get(key) ?? { ...source, eventIds: [] };
    group.eventIds.push(eventId);
    groups.set(key, group);
    return { eventId, evidence };
  });
  const accepted = new Map<string, PublicationEvidence["event"]>();
  for (const group of groups.values()) {
    // The source Station owns its admission proof. Read its accepted Event;
    // never forward the producer-only draft or synthesize a Station signature.
    const url = `${solandBaseUrl(group.server)}/_arkret/self/events/resolve`;
    const response = await request.fetch(url, {
      method: "QUERY",
      headers: { ...authHeaders(group.token, "QUERY", url), "content-type": "application/json" },
      data: canonicalJson({ event_ids: [...new Set(group.eventIds)], include_payload: true }),
    });
    const body = await expectJsonOk<Record<string, unknown>>(response, "resolve accepted source Events for federation");
    for (const event of (body.events ?? []) as PublicationEvidence["event"][]) {
      accepted.set(event.event_id, event);
    }
  }
  return entries.map(({ eventId, evidence }) => {
    const event = accepted.get(eventId);
    if (!event) throw new Error(`source Station did not return the accepted Event ${eventId}`);
    return { ...evidence, event };
  });
}

export async function queryPeerEventsApi(
  request: APIRequestContext,
  opts: {
    server?: SolandKey;
    realmId?: string;
    actorId?: string;
    limit?: number;
    after?: string;
    sourceServiceId?: string;
  },
) {
  const body = stripUndefined({
    realm_ids: opts.realmId ? [opts.realmId] : undefined,
    actor_ids: opts.actorId ? [accountActorId(opts.actorId, opts.server)] : undefined,
    limit: opts.limit ?? 100,
    after: opts.after,
  });
  const targetUri = `${solandBaseUrl(opts.server)}/_arkret/peer/events`;
  const sourceServiceId =
    opts.sourceServiceId ?? COTEST_PEER_FIXTURE_CORE_ID;
  const destinationServiceId = solandServiceId(opts.server);
  const response = await request.fetch(targetUri, {
    method: "QUERY",
    data: canonicalJson(body),
    headers: signedFederationPushHeaders(
      sourceServiceId,
      destinationServiceId,
      targetUri,
      body,
      { method: "QUERY" },
    ),
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
  opts: { server?: SolandKey; sourceServiceId?: string } = {},
) {
  const body = { realm_id: realmId };
  const targetUri = `${solandBaseUrl(opts.server)}/_arkret/peer/events/frontier`;
  const sourceServiceId =
    opts.sourceServiceId ?? COTEST_PEER_FIXTURE_CORE_ID;
  const destinationServiceId = solandServiceId(opts.server);
  const response = await request.fetch(targetUri, {
    method: "QUERY",
    data: canonicalJson(body),
    headers: signedFederationPushHeaders(
      sourceServiceId,
      destinationServiceId,
      targetUri,
      body,
      { method: "QUERY" },
    ),
  });
  return await expectJsonOk<{
    realm_id: string;
    heads: string[];
    frontier_root: string;
    actor_seq_upper_bounds?: Record<string, number>;
  }>(response, "peer event frontier");
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

type EventKindRegistryRow = {
  event_kind?: string;
  reducer_input?: boolean;
  plane?: "control" | "data";
};

let eventKindRegistryCache: Map<string, EventKindRegistryRow> | undefined;

function eventKindDescriptor(kind: string): EventKindRegistryRow | undefined {
  if (!eventKindRegistryCache) {
    const registry = JSON.parse(
      readFileSync(
        join(SPEC_ARTIFACTS_ROOT, "registry", "event-kind-registry.json"),
        "utf8",
      ),
    ) as { event_kinds?: EventKindRegistryRow[] };
    eventKindRegistryCache = new Map(
      (registry.event_kinds ?? [])
        .filter(
          (row): row is EventKindRegistryRow & { event_kind: string } =>
            typeof row.event_kind === "string",
        )
        .map((row) => [row.event_kind, row]),
    );
  }
  return eventKindRegistryCache.get(kind);
}

let fixtureCapabilityActionCache: Map<string, string> | undefined;
let realmRootAuthorableEventKinds: Set<string> | undefined;

function realmRootMayAuthorEventKind(eventKind: string): boolean {
  if (!realmRootAuthorableEventKinds) {
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
        root_control_only?: unknown;
      }>;
    };
    realmRootAuthorableEventKinds = new Set<string>();
    for (const row of registry.actions ?? []) {
      if (!Array.isArray(row.target_event_kinds)) {
        continue;
      }
      if (row.action !== "ak.realm.owner" && row.root_control_only !== true) {
        continue;
      }
      for (const target of row.target_event_kinds) {
        if (typeof target === "string") {
          realmRootAuthorableEventKinds.add(target);
        }
      }
    }
  }
  return realmRootAuthorableEventKinds.has(eventKind);
}

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

// federation.md §4.1: membership_frontier is the sender's causal frontier
// (`id[]`). For a batch-local frontier, use the accepted nested Events rather
// than their federation transport wrappers. A wider frontier is caller-supplied.
function batchFrontierEventIds(
  events: Array<PublicationEvidence["event"]>,
): string[] {
  const referenced = new Set<string>();
  for (const event of events) {
    const prevRefs = Array.isArray(event.prev_refs) ? event.prev_refs : [];
    for (const entry of prevRefs) {
      if (typeof entry === "string") {
        referenced.add(entry);
      }
    }
  }
  const heads = events
    .map((event) => event.event_id)
    .filter(
      (id): id is string => typeof id === "string" && !referenced.has(id),
    );
  // An empty batch has no heads. Fabricating one would mean minting an
  // `ak:event:` id, and an Event id is derived from an Event that exists.
  return heads;
}

function peerEventsSubmitBody(
  realmId: string,
  events: PublicationEvidence[],
  overrides: {
    serviceBindingFrontier?: string[];
    cbsProofBundles?: Array<Record<string, unknown>>;
  } = {},
): Record<string, unknown> {
  const frontier =
    overrides.serviceBindingFrontier &&
    overrides.serviceBindingFrontier.length > 0
      ? overrides.serviceBindingFrontier
      : batchFrontierEventIds(events.map((submission) => submission.event));
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
      destination_kind: "station",
    },
    events,
    cbs_proof_bundles: overrides.cbsProofBundles,
  }) as Record<string, unknown>;
}

function signedFederationPushHeaders(
  sourceServiceId: string,
  destinationServiceId: string,
  targetUri: string,
  body: unknown,
  opts: {
    expireSignature?: boolean;
    idempotencyKey?: string;
    method?: "POST" | "QUERY";
  } = {},
): Record<string, string> {
  const method = opts.method ?? "POST";
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
  const idempotencyComponent = opts.idempotencyKey ? ' "idempotency-key"' : "";
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" "arkret-operation" "source-service-id" ` +
    `"destination-service-id" "source-trust-domain" "destination-trust-domain"` +
    `${idempotencyComponent});created=${created};expires=${expires};keyid="${keyid}";alg="ed25519"`;
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
    ...(opts.idempotencyKey
      ? [`"idempotency-key": ${opts.idempotencyKey}`]
      : []),
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
    ...(opts.idempotencyKey ? { "idempotency-key": opts.idempotencyKey } : {}),
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

let actorSeqCounter = 1;

function nextActorSeq(): number {
  const seq = actorSeqCounter;
  actorSeqCounter += 1;
  return seq;
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

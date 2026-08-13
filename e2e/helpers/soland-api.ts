import { spawnSync } from "node:child_process";
import {
  createHash,
  createPrivateKey,
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
import {
  type SolandKey,
  solandBaseUrl,
  solandServiceFullId,
  solandServiceId,
} from "./env";
import { base64url } from "./encoding";
import type {
  CapabilityGrantObject,
  EventFederationSubmission,
  InviteDeliveryRequestBody,
  RealmObject,
  RealmSealFrontierView,
} from "./generated/spec-wire-objects";

export type SignedEventEnvelopeArgs = {
  actorDid: string;
  realmId: string;
  kind: string;
  payload: Record<string, unknown>;
  actorSeq?: number;
  createdAt?: string;
  hlc?: string;
  eventId?: string;
  schemaId?: string;
  /// Override the full `requirements.schema[]` binding. morph.md §4.1 S1/S2
  /// requires schema-evolving events (ak.morph.schema_migrate /
  /// schema_refs-changing ak.morph.update) to bind the active Morph schema set
  /// (the union of from/to schema_refs) here, not just the payload schema id.
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
};

export type EventProofMode = "dev-proof" | "detached-jws";

type RegisteredEventSigner = {
  verificationMethod: string;
  signingSeedB64url?: string;
};

const registeredEventSigners = new Map<string, RegisteredEventSigner>();
const registeredRequestAuth = new Map<
  string,
  (method: string, url: string) => Record<string, string>
>();
const localControlProposalAuthorityAcks = new Map<
  string,
  Record<string, unknown>
>();
const realmAuthorityControllers = new Map<string, string>();

const REALM_AUTHORITY_ROOT_CELL =
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
  actorDid: string;
  deviceId: string;
  verificationMethod?: string;
  signingSeedB64url?: string;
}): void {
  const actorId = canonicalDidCoreId(args.actorDid);
  const verificationMethod =
    args.verificationMethod ??
    (args.actorDid.startsWith("did:")
      ? `${args.actorDid}#${args.deviceId}`
      : undefined);
  if (!verificationMethod) {
    throw new Error(
      "registerEventSigner requires a full-DID verification method for a core actor id",
    );
  }
  const signer = {
    verificationMethod,
    signingSeedB64url: args.signingSeedB64url,
  };
  registeredEventSigners.set(args.actorDid, signer);
  registeredEventSigners.set(actorId, signer);
}

function eventSignerFor(
  actorDid: string,
  requestedVerificationMethod?: string,
): RegisteredEventSigner | undefined {
  const registered = registeredEventSigners.get(actorDid);
  if (
    !registered ||
    (requestedVerificationMethod !== undefined &&
      requestedVerificationMethod !== registered.verificationMethod)
  ) {
    return undefined;
  }
  return registered;
}

export function signWithRegisteredEventSigner(
  actorDid: string,
  verificationMethod: string,
  signingInput: string,
): string | undefined {
  const registered = eventSignerFor(actorDid, verificationMethod);
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

export function registerRequestAuth(
  token: string,
  buildHeaders: (method: string, url: string) => Record<string, string>,
): void {
  registeredRequestAuth.set(token, buildHeaders);
}

export function authHeaders(
  token: string,
  method?: string,
  url?: string,
): Record<string, string> {
  const buildHeaders = registeredRequestAuth.get(token);
  if (buildHeaders) {
    if (!method || !url) {
      throw new Error(
        "DPoP-bound session grant requires the exact request method and URL",
      );
    }
    return buildHeaders(method, url);
  }
  return { authorization: `Bearer ${token}` };
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
  if (["event", "realm", "circle", "strand"].includes(kind)) {
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

function retypeEventDerivedId(eventId: string, kind: string): string {
  if (!eventId.startsWith("ak:event:")) {
    throw new Error(`cannot retype non-Event id ${eventId}`);
  }
  return `ak:${kind}:${eventId.slice("ak:event:".length)}`;
}

const acceptedPrincipalControlRealms = new Map<string, string>();

export function registerPrincipalControlRealm(
  did: string,
  realmId: string,
): void {
  const principalId = canonicalDidCoreId(did);
  const previous = acceptedPrincipalControlRealms.get(principalId);
  if (previous && previous !== realmId) {
    throw new Error(
      `principal ${principalId} was bound to two different PCR ids`,
    );
  }
  acceptedPrincipalControlRealms.set(principalId, realmId);
}

export function principalControlRealmForDid(did: string): string {
  const principalId = canonicalDidCoreId(did);
  const realmId = principalControlRealmForDidIfKnown(principalId);
  if (!realmId) {
    throw new Error(
      `event-derived PCR id for ${principalId} is unavailable; register its accepted create Event first`,
    );
  }
  return realmId;
}

export function principalControlRealmForDidIfKnown(
  did: string,
): string | undefined {
  return acceptedPrincipalControlRealms.get(canonicalDidCoreId(did));
}

// Re-exported authoritative base64url encoder (single source: encoding.ts).
export { base64url };

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
    stringValue(record.reason_code) ??
    stringValue(nested?.errcode) ??
    stringValue(nested?.code) ??
    stringValue(nested?.error_code) ??
    stringValue(nested?.reason_code) ??
    stringValue(record.reason) ??
    stringValue(nested?.reason)
  );
}

export function projectFullDidToCoreId(fullDid: string): string {
  if (fullDid.startsWith("did:webvh:")) {
    const [scid] = fullDid.slice("did:webvh:".length).split(":", 1);
    if (!scid) {
      throw new Error(`invalid did:webvh notary DID: ${fullDid}`);
    }
    return `ak:did_core:webvh:${scid}`;
  }
  if (fullDid.startsWith("did:web:")) {
    return `ak:did_core:web:${fullDid.slice("did:web:".length)}`;
  }
  if (fullDid.startsWith("did:key:")) {
    return `ak:did_core:key:${fullDid.slice("did:key:".length)}`;
  }
  throw new Error(`unsupported notary DID method: ${fullDid}`);
}

export function canonicalDidCoreId(did: string): string {
  return did.startsWith("ak:did_core:") ? did : projectFullDidToCoreId(did);
}

export function singleDidNotaryFromFullDid(
  fullDid: string,
): RealmObject["notary"] {
  return {
    kind: "single_did",
    actor_id: canonicalDidCoreId(fullDid),
    recovery_members: ["ak:did_core:web:recovery.soland.local"],
    controller_organization:
      "ak:did_core:web:organization.primary.soland.local",
    recovery_controller_organizations: [
      "ak:did_core:web:organization.recovery.soland.local",
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

export function plaintextVisibleServiceDeclarations(serviceIds: string[]) {
  return Array.from(
    new Set(serviceIds.map((service) => service.trim()).filter(Boolean)),
  ).map((serviceId) => ({
    service_id: canonicalDidCoreId(serviceId),
    service_kind: "principal_server",
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
    history_visibility?: RealmObject["history_visibility"];
    encryption_profile?: RealmObject["encryption_profile"];
    content_scheme?: RealmObject["content_scheme"];
    invitees?: string[];
    /**
     * Optional home Principal Server DID for directed invite-create events.
     * Seed-member (`ak.member.state{membership=invite}`) events intentionally
     * have no delivery target; callers exercising cross-server invite fanout
     * opt in here so the helper emits the canonical `ak.invite.create` event.
     */
    invitee_service_ids?: Record<string, string>;
    /**
     * Materialize the creator's home Principal Server as a canonical routable
     * member binding inside the founding batch. Cross-server Realms need this
     * so a remote member can route its accept/join and later Events back to
     * the creator.
     */
    creator_service_id?: string;
    plaintext_visible_services?: string[];
    // Hand-written mirror replaced by the generated one: the role /
    // service_kind / visibility_scope enums live in `realm.schema.json`.
    sync_endpoints?: RealmObject["sync_endpoints"];
    public?: boolean;
    federation_policy?: RealmObject["federation_policy"];
    schema_refs?: RealmObject["schema_refs"];
    ownerDid?: string;
    default_join_rule?: RealmObject["default_join_rule"];
    created_at?: string;
  },
  opts: {
    server?: SolandKey;
    onAcceptedBootstrap?: (bootstrap: AcceptedRealmBootstrap) => void;
  } = {},
): Promise<string> {
  const ownerDid =
    data.ownerDid ?? (await currentActorDidApi(request, token, opts));
  const createdAt = data.created_at ?? canonicalTimestamp();
  const plaintextVisibleServiceIds =
    data.plaintext_visible_services ??
    (data.encryption_profile === "mls_rfc9420"
      ? []
      : [solandServiceId(opts.server), "did:web:soland.local"]);
  const plaintextVisibleServices = plaintextVisibleServiceDeclarations(
    plaintextVisibleServiceIds,
  );
  if (data.history_visibility === "restricted") {
    throw new Error(
      "createRealmApi requires an explicit history-sharing policy for restricted history",
    );
  }
  const realmGenesis = {
    schema: "ak.schema.realm_genesis.v1",
    purpose: "collaboration",
    genesis_salt: base64url(randomBytes(32)),
    trust_domain: "ak:trust_domain:soland.local",
    schema_refs: data.schema_refs ?? ["ak.schema.realm.v1"],
    reducer_profile: "ak.reducer.core.v1",
    encryption_profile: data.encryption_profile ?? "none",
    security_class: "standard",
    notary_profile: "single_did",
    digest_algorithm: "sha256",
    // This helper creates Principal-Server-hosted collaboration Realms. The
    // service owns the notary key and materializes Event Seals; the principal
    // remains the Realm creator and root authority-cell controller.
    notary: singleDidNotaryFromFullDid(solandServiceFullId(opts.server)),
    // Create-locked (realm-and-space.md section 2.5): the reducer copies this
    // into the Realm authority-root cell, which is what gives the creator
    // effective `ak.realm.owner`. v1 issues no genesis self-grant.
    capability_action_registry_digest: sdkCapabilityActionRegistryDigest(),
  };
  const realmCreateCell = "ak:cell:ak.component.realm.create.v1:null";
  const { envelope: realmCreateEvent, realmId } = signedRealmGenesisEnvelope({
    actorDid: ownerDid,
    // The genesis names no Realm; the envelope builder derives both its own id
    // and the Realm's from the finished envelope.
    realmId: "",
    kind: "ak.realm.create",
    actorSeq: 0,
    createdAt,
    preconditions: [
      {
        cell: realmCreateCell,
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
        actorDid: ownerDid,
        realmId,
        kind,
        actorSeq: bootstrapEvents.length,
        createdAt,
        prevRefs: [predecessorId],
        authorizationRef: REALM_AUTHORITY_ROOT_CELL,
        preconditions: [
          {
            cell,
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
      ...(data.content_scheme ? { content_scheme: data.content_scheme } : {}),
      ...(data.sync_endpoints ? { sync_endpoints: data.sync_endpoints } : {}),
    },
  );
  pushBootstrapEvent(
    "ak.realm.join_rule",
    "ak:cell:ak.component.realm.join_rule.v1:null",
    { value: data.default_join_rule ?? "invite" },
  );
  pushBootstrapEvent(
    "ak.realm.history_visibility",
    "ak:cell:ak.component.realm.history_visibility.v1:null",
    { value: data.history_visibility ?? "shared" },
  );
  pushBootstrapEvent(
    "ak.realm.discovery",
    "ak:cell:ak.component.realm.discovery.v1:null",
    {
      value: data.discoverability ?? (data.public ? "public" : "listed"),
    },
  );
  if (plaintextVisibleServices.length > 0) {
    pushBootstrapEvent(
      "ak.realm.plaintext_visible_services",
      "ak:cell:ak.component.realm.plaintext_visible_services.v1:null",
      { services: plaintextVisibleServices },
    );
  }
  let creatorDeliveryBinding: Record<string, unknown> | undefined;
  let deliveryPolicy: Record<string, unknown> = {
    realm_id: realmId,
    unroutable_membership_allowed: true,
  };
  if (data.creator_service_id) {
    const didDocumentResponse = await request.get(
      `${solandBaseUrl(opts.server)}/_soland/root/identity/${encodeURIComponent(ownerDid)}/did-document`,
    );
    const didDocument = await expectJsonOk<Record<string, unknown>>(
      didDocumentResponse,
      `resolve creator DID document ${ownerDid}`,
    );
    deliveryPolicy = {
      realm_id: realmId,
      allowed_binding_sources: ["did_document_default"],
      did_document_default_allowed: true,
      allowed_recipient_services: [data.creator_service_id],
      required_endorsers: [],
      unroutable_membership_allowed: true,
      rebind_authorization: "member",
    };
    creatorDeliveryBinding = {
      recipient_service_id: data.creator_service_id,
      recipient_service_kind: "principal_server",
      binding_scope: "realm",
      binding_source: "did_document_default",
      delivery_modes: ["events", "sync", "to_device", "push", "key_packages"],
      service_endpoint: solandBaseUrl(opts.server),
      did_document_digest: `sha256:${sha256CanonicalJson(didDocument)}`,
      resolved_at: createdAt,
    };
  }
  pushBootstrapEvent(
    "ak.realm.delivery_binding_policy",
    "ak:cell:ak.component.realm.delivery_binding_policy.v1:null",
    deliveryPolicy,
  );
  pushBootstrapEvent(
    "ak.member.state",
    `ak:cell:ak.component.member.state.v1:${ownerDid}`,
    {
      realm_id: realmId,
      actor_id: canonicalDidCoreId(ownerDid),
      membership: "join",
      delivery_status: creatorDeliveryBinding ? "routable" : "unroutable",
      ...(creatorDeliveryBinding
        ? { delivery_binding: creatorDeliveryBinding }
        : {}),
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
    ownerDid,
  );
  // The founding unit is accepted before the durable coordinator publishes
  // its first Seal. Do not let the next helper call mistake that short window
  // for an uninitialised conformance-only Realm and inject a synthetic basis:
  // the real genesis Seal must atomically cover the complete founding unit.
  await waitForRealmSealBasis(request, token, realmId, opts.server);

  for (const invitee of data.invitees ?? []) {
    const recipientServiceId =
      data.invitee_service_ids?.[invitee] ?? solandServiceId(opts.server);
    const evidence = { kind: "explicit_address" };
    const inviteId = typedId("invite");
    const sealBasis = await readRealmSealBasis(
      request,
      token,
      realmId,
      opts.server,
    );
    const inviteEvent = signedEventEnvelope({
      actorDid: ownerDid,
      realmId,
      kind: "ak.invite.create",
      sealBasis,
      payload: {
        invite_id: inviteId,
        invitee,
        invite_delivery_target: {
          recipient_service_id: recipientServiceId,
          recipient_service_kind: "principal_server",
        },
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
      kind: "ak.member.state",
      payload: {
        // `realm_id` inside the payload is a spec-defined membership_payload
        // property (event-payload.schema.json#/$defs/membership_payload) and is
        // required by soland's registry-backed payload validator in dev-proof
        // mode; include it so the membership op validates regardless of the
        // active proof profile.
        realm_id: realmId,
        actor_id: canonicalDidCoreId(memberDid),
        membership: "join",
        delivery_status: "unroutable",
      },
    }),
    { server: opts.server, context: `add member ${memberDid}` },
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
// `content_scheme` is deliberately NOT restated. The cell is a `cas_register`,
// so a revision clears every component it omits, and restating a component
// this helper never wrote would be inventing a value — `content_scheme` has a
// one-way ratchet in the reducer, so an invented one risks a downgrade
// rejection that presents as an unrelated join-policy failure. `writeJoinPolicy`
// is the only `ak.realm.policy_bundle` producer in this suite (`createRealmApi`
// writes none), so there is no prior component set to carry forward. A caller
// that starts writing other components must restate them here.
export async function writeJoinPolicyApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  joinPolicy: Record<string, unknown>,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const actorDid = await currentActorDidApi(request, token, opts);
  const digest = `sha256:${sha256CanonicalJson(joinPolicy)}`;
  const previousFrontier = await readRealmSealFrontier(
    request,
    token,
    realmId,
    opts.server,
  );
  const policyRevision = nextJoinPolicyRevision(opts.server, realmId);
  const policyEvent = signedEventEnvelope({
    actorDid,
    realmId,
    kind: "ak.realm.policy_bundle",
    payload: {
      policy_revision: policyRevision,
      join_policy: joinPolicy,
    },
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
        const cellId = "ak:cell:ak.component.realm.policy_bundle.v1:null";
        const response = await request.get(
          `${solandBaseUrl(opts.server)}/_soland/admin/cells/${encodeURIComponent(cellId)}?realm_id=${encodeURIComponent(realmId)}`,
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

// Grant a realm-scoped `ak.realm.join.review` capability to a subject. Used
// by the knock-application scenario to make a non-owner reviewer, whose
// capability can later be revoked (join-policy.md §7.5 #3 re-check).
export async function grantRealmReviewCapabilityApi(
  request: APIRequestContext,
  ownerToken: string,
  args: {
    ownerDid: string;
    realmId: string;
    subjectDid: string;
    server?: SolandKey;
  },
): Promise<string> {
  const issuedAt = canonicalTimestamp();
  const previousFrontier = await readRealmSealFrontier(
    request,
    ownerToken,
    args.realmId,
    args.server,
  );
  // `capability-grant.schema.json` is a closed object; annotating the literal
  // makes an unregistered member or a misspelled resource kind a `tsc` error
  // instead of a reducer rejection. `proofs` is attached after signing.
  const unsignedGrant: Omit<CapabilityGrantObject, "id" | "proofs"> = {
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer: canonicalDidCoreId(args.ownerDid),
    subject: canonicalDidCoreId(args.subjectDid),
    actions: ["ak.realm.join.review"],
    capability_action_registry_digest: sdkCapabilityActionRegistryDigest(),
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
    actorDid: args.ownerDid,
    realmId: args.realmId,
    kind: "ak.capability.grant",
    createdAt: issuedAt,
    payload: {
      // `capability_grant_payload`: the grant body is closed and carries no
      // inner proof — the Event envelope proof is the sole durable issuer
      // signature, and it already covers actor, scope, authority refs, payload
      // and time.
      grant: unsignedGrant,
    },
  });
  await submitSignedEventApi(request, ownerToken, grantEvent, {
    server: args.server,
    context: `grant ak.realm.join.review to ${args.subjectDid}`,
  });
  const grantId = retypeEventDerivedId(String(grantEvent.event_id), "grant");
  const proposalDigest = Array.isArray(grantEvent.proofs)
    ? stringValue(
        (grantEvent.proofs[0] as Record<string, unknown> | undefined)
          ?.event_digest,
      )
    : undefined;
  if (!proposalDigest) {
    throw new Error(
      `review capability grant ${grantId} is missing its proposal digest`,
    );
  }
  await expect
    .poll(
      async () => {
        const current = await readRealmSealFrontier(
          request,
          ownerToken,
          args.realmId,
          args.server,
        );
        return (
          current.control_event_set_root !==
            previousFrontier.control_event_set_root &&
          !current.pending_proposal_digests.includes(proposalDigest)
        );
      },
      {
        message: `review capability grant ${grantId} reaches the control Seal frontier`,
        timeout: 30_000,
        intervals: [250, 500, 1_000, 2_000],
      },
    )
    .toBe(true);
  return grantId;
}

// Grant a Realm-scoped capability to a peer service DID.
// sync/federation.md §4.4: the grant subject is a service DID; revoking it
// makes the source Principal Server stop pushing future events to that peer.
export async function grantServiceCapabilityApi(
  request: APIRequestContext,
  ownerToken: string,
  args: {
    ownerDid: string;
    realmId: string;
    subjectServiceId: string;
    action?: string;
    server?: SolandKey;
  },
): Promise<string> {
  const issuedAt = canonicalTimestamp();
  // `ak.realm.delivery_binding_policy` is an Event kind, not a capability
  // action. Use a core collaboration action advertised by both federation
  // peers; the service-DID subject and Realm resource make this a service
  // service grant, independently of which registered action is granted.
  const action = args.action ?? "ak.message.create";
  // `capability-grant.schema.json` is a closed object; annotating the literal
  // makes an unregistered member or a misspelled resource kind a `tsc` error
  // instead of a reducer rejection. `proofs` is attached after signing.
  const unsignedGrant: Omit<CapabilityGrantObject, "id" | "proofs"> = {
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer: canonicalDidCoreId(args.ownerDid),
    subject: canonicalDidCoreId(args.subjectServiceId),
    actions: [action],
    capability_action_registry_digest: sdkCapabilityActionRegistryDigest(),
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
    actorDid: args.ownerDid,
    realmId: args.realmId,
    kind: "ak.capability.grant",
    createdAt: issuedAt,
    payload: {
      // The grant body is closed and carries no inner proof; the Event
      // envelope proof is the sole durable issuer signature.
      grant: unsignedGrant,
    },
  });
  await submitSignedEventApi(
    request,
    ownerToken,
    grantEvent,
    {
      server: args.server,
      context: `grant ${action} service capability to ${args.subjectServiceId}`,
    },
  );
  const grantId = retypeEventDerivedId(String(grantEvent.event_id), "grant");
  return grantId;
}

// Mint a realm-scoped `ak.capability.grant` event for an arbitrary action set
// and return both the immutable grant id (`ak:grant:*`) and its carrying Event
// id (`ak:event:*`). capabilities.md §10.3 requires `refs[authorized_by]` to
// name the grant itself; the Event id remains useful only for Event-history
// causality and diagnostics.
export type CapabilityGrantEventArgs = {
  ownerDid: string;
  realmId: string;
  subjectDid: string;
  actions: string[];
  // capabilities.md §8: optional finite validity upper bound. Child grants
  // issued from grant refs MUST narrow: child effective_expires_at MUST be
  // <= the issuer authority's (§10.1).
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
  // `capability-grant.schema.json` is a closed object; annotating the literal
  // makes an unregistered member or a misspelled resource kind a `tsc` error
  // instead of a reducer rejection. `proofs` is attached after signing.
  const unsignedGrant: Omit<CapabilityGrantObject, "id" | "proofs"> = {
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer: canonicalDidCoreId(args.ownerDid),
    subject: canonicalDidCoreId(args.subjectDid),
    actions: args.actions,
    capability_action_registry_digest: sdkCapabilityActionRegistryDigest(),
    resources: [{ kind: "realm", realm_id: args.realmId }],
    issued_at: issuedAt,
    ...(args.expiresAt ? { expires_at: args.expiresAt } : {}),
    ...(args.constraints ? { constraints: args.constraints } : {}),
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
    actorDid: args.ownerDid,
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
    context: `grant [${args.actions.join(", ")}] to ${args.subjectDid}`,
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
    ownerDid: string;
    realmId: string;
    grantId: string;
    server?: SolandKey;
  },
) {
  const outcome = await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: args.ownerDid,
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
const joinPolicyRevisionCache = new Map<string, number>();

function nextJoinPolicyRevision(
  server: SolandKey | undefined,
  realmId: string,
): number {
  const key = joinWorkflowKey(server, realmId);
  const next = (joinPolicyRevisionCache.get(key) ?? 0) + 1;
  joinPolicyRevisionCache.set(key, next);
  return next;
}
const knockRefCache = new Map<string, string>();
const joinApplicationCache = new Map<
  string,
  {
    applicantDid: string;
    realmId: string;
    applicationRevisionDigest: string;
  }
>();

function joinWorkflowKey(
  server: SolandKey | undefined,
  realmId: string,
  actorDid?: string,
): string {
  return `${server ?? "default"}\0${realmId}\0${actorDid ?? ""}`;
}

function joinReceiptProof(args: {
  actorDid: string;
  realmId: string;
  receiptDigest: string;
  createdAt: string;
  context: string;
  applicationRef?: string;
  applicationRevisionDigest?: string;
}): Record<string, unknown> {
  const registeredSigner = eventSignerFor(args.actorDid);
  const verificationMethod =
    registeredSigner?.verificationMethod ?? `${args.actorDid}#device`;
  const binding = stripUndefined({
    context: args.context,
    receipt_digest: args.receiptDigest,
    realm_id: args.realmId,
    application_ref: args.applicationRef,
    application_revision_digest: args.applicationRevisionDigest,
    actor_id: canonicalDidCoreId(args.actorDid),
    verification_method: verificationMethod,
    created_at: args.createdAt,
  });
  const protectedHeader = base64urlJsonCanonical({ alg: "Ed25519" });
  const signingInput = `${protectedHeader}.${base64urlJsonCanonical(binding)}`;
  const signature =
    signWithRegisteredEventSigner(
      args.actorDid,
      verificationMethod,
      signingInput,
    ) ??
    sign(
      null,
      Buffer.from(signingInput, "utf8"),
      developmentProtocolPrivateKey(verificationMethod),
    ).toString("base64url");
  return {
    kind: "detached_jws",
    alg: "Ed25519",
    verification_method: verificationMethod,
    payload_digest: args.receiptDigest,
    created_at: args.createdAt,
    jws: `${protectedHeader}..${signature}`,
  };
}

export async function submitKnockApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  opts: { server?: SolandKey; createdAt?: string } = {},
) {
  const envelope = signedEventEnvelope({
    actorDid,
    realmId,
    kind: "ak.member.state",
    actorSeq: 0,
    prevRefs: [],
    createdAt: opts.createdAt,
    payload: {
      realm_id: realmId,
      actor_id: canonicalDidCoreId(actorDid),
      membership: "knock",
    },
  });
  const outcome = await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `knock ${realmId}`,
  });
  const knockRef = String(envelope.event_id ?? "");
  if (knockRef) {
    knockRefCache.set(
      joinWorkflowKey(opts.server, realmId, actorDid),
      knockRef,
    );
  }
  return { ...outcome, event_id: knockRef };
}

// join-policy.md §7.1.1 / §7.2 — signed profile-private application receipt.
export async function submitApplicationApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  application: {
    knockRef?: string;
    policyVersionDigest?: string;
    answers?: Array<{ question_id: string; value: unknown }>;
    receiptDigest?: string;
  },
  opts: { server?: SolandKey; createdAt?: string } = {},
): Promise<string> {
  const policyVersionDigest =
    application.policyVersionDigest ??
    joinPolicyDigestCache.get(joinWorkflowKey(opts.server, realmId));
  const knockRef =
    application.knockRef ??
    knockRefCache.get(joinWorkflowKey(opts.server, realmId, actorDid));
  if (!policyVersionDigest || !knockRef) {
    throw new Error(
      "join application requires a known policyVersionDigest and knockRef",
    );
  }
  const submittedAt = canonicalTimestamp(
    opts.createdAt === undefined ? undefined : new Date(opts.createdAt),
  );
  const answers = application.answers ?? [];
  const gateProofs: Array<Record<string, unknown>> = [];
  const privateBody = {
    mode: "server_protected",
    answers,
  };
  const applicationRevisionDigest = `sha256:${sha256CanonicalJson({
    answers,
    gate_proofs: gateProofs,
    policy_version_digest: policyVersionDigest,
  })}`;
  const unsignedReceipt = {
    candidate_kind: "member.application",
    realm_id: realmId,
    applicant_did: actorDid,
    knock_ref: knockRef,
    policy_version_digest: policyVersionDigest,
    application_revision_digest: applicationRevisionDigest,
    private_body_digest: `sha256:${sha256CanonicalJson(privateBody)}`,
    submitted_at: submittedAt,
  };
  const applicationReceiptDigest =
    application.receiptDigest ??
    `sha256:${sha256CanonicalJson(unsignedReceipt)}`;
  const receipt = {
    ...unsignedReceipt,
    application_receipt_digest: applicationReceiptDigest,
    proof: joinReceiptProof({
      actorDid,
      realmId,
      receiptDigest: applicationReceiptDigest,
      createdAt: submittedAt,
      context: "ak.join-application-receipt-proof-v1",
    }),
  };
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}/join-applications`,
    {
      headers: {
        ...authHeaders(token),
        "Idempotency-Key": `application:${applicationReceiptDigest}`,
      },
      data: { receipt, private_body: privateBody },
    },
  );
  const outcome = await expectJsonOk<{
    application_ref: string;
    receipt_ref?: string;
  }>(response, `submit join application ${realmId}`);
  joinApplicationCache.set(applicationReceiptDigest, {
    applicantDid: actorDid,
    realmId,
    applicationRevisionDigest,
  });
  return outcome.application_ref;
}

// join-policy.md §7.1.1 / §7.3 — signed profile-private review receipt.
export async function submitApplicationReviewApi(
  request: APIRequestContext,
  token: string,
  reviewerDid: string,
  applicantDid: string,
  realmId: string,
  review: {
    applicationRef: string;
    decision: "accept" | "reject" | "request_changes";
    reasonCode?: string;
    reasonText?: string;
    grantId: string;
    reviewReceiptDigest?: string;
  },
  opts: { server?: SolandKey; createdAt?: string } = {},
): Promise<string> {
  const application = joinApplicationCache.get(review.applicationRef);
  if (
    !application ||
    application.realmId !== realmId ||
    application.applicantDid !== applicantDid
  ) {
    throw new Error(`unknown join application ${review.applicationRef}`);
  }
  const reviewedAt = canonicalTimestamp(
    opts.createdAt === undefined ? undefined : new Date(opts.createdAt),
  );
  const grantId = review.grantId;
  const unsignedReceipt = stripUndefined({
    candidate_kind: "member.application.review",
    realm_id: realmId,
    application_ref: review.applicationRef,
    application_revision_digest: application.applicationRevisionDigest,
    reviewer_did: reviewerDid,
    decision: review.decision,
    reason_code: review.reasonCode,
    reason_text: review.reasonText,
    reviewer_capability_proof: {
      grant_id: grantId,
      frontier_digest: `sha256:${sha256CanonicalJson({
        grant_id: grantId,
        realm_id: realmId,
        reviewer_did: reviewerDid,
      })}`,
    },
    reviewed_at: reviewedAt,
  }) as Record<string, unknown>;
  const reviewReceiptDigest =
    review.reviewReceiptDigest ??
    `sha256:${sha256CanonicalJson(unsignedReceipt)}`;
  const receipt = {
    ...unsignedReceipt,
    review_receipt_digest: reviewReceiptDigest,
    proof: joinReceiptProof({
      actorDid: reviewerDid,
      realmId,
      receiptDigest: reviewReceiptDigest,
      createdAt: reviewedAt,
      context: "ak.join-application-review-receipt-proof-v1",
      applicationRef: review.applicationRef,
      applicationRevisionDigest: application.applicationRevisionDigest,
    }),
  };
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}/join-applications/${encodeURIComponent(review.applicationRef)}/reviews`,
    {
      headers: {
        ...authHeaders(token),
        "Idempotency-Key": `review:${reviewReceiptDigest}`,
      },
      data: { receipt },
    },
  );
  const outcome = await expectJsonOk<{ receipt_ref?: string }>(
    response,
    `review join application ${review.applicationRef}`,
  );
  return outcome.receipt_ref ?? reviewReceiptDigest;
}

// join-policy.md §5 — auto-resolve join: `ak.member.state{membership=join}`
// carrying `gate_proofs[]`. The reducer validates the gates inline.
export async function submitJoinWithProofsApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  gateProofs: Array<Record<string, unknown>>,
  opts: {
    server?: SolandKey;
    createdAt?: string;
    invisibleActorFrontier?: {
      nextActorSeq: number;
      frontierEventIds: string[];
    };
  } = {},
) {
  const envelope = signedEventEnvelope({
    actorDid,
    realmId,
    kind: "ak.member.state",
    createdAt: opts.createdAt,
    payload: {
      realm_id: realmId,
      actor_id: canonicalDidCoreId(actorDid),
      membership: "join",
      delivery_status: "unroutable",
      gate_proofs: gateProofs,
    },
  });
  await advanceEnvelopeToActorFrontier(
    request,
    token,
    envelope,
    opts.server,
    true,
    opts.invisibleActorFrontier,
  );
  return await rawSubmitSignedEventApi(request, token, envelope, {
    server: opts.server,
  });
}

// join-policy.md §3.1 `cooldown` gate — applicant leaves the Realm.
export async function submitLeaveApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  opts: { server?: SolandKey; createdAt?: string } = {},
) {
  const envelope = signedEventEnvelope({
    actorDid,
    realmId,
    kind: "ak.member.state",
    createdAt: opts.createdAt,
    payload: {
      realm_id: realmId,
      actor_id: canonicalDidCoreId(actorDid),
      membership: "leave",
    },
  });
  const response = await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `leave ${realmId}`,
  });
  return {
    ...response,
    event_id: String(envelope.event_id),
    actor_seq: Number(envelope.actor_seq),
  };
}

// join-policy.md §7.5 — `ak.invite.create` whose
// `refs[role="join_authorised_by"]` binds to the review accept receipt.
export async function submitInviteCreateApi(
  request: APIRequestContext,
  token: string,
  inviterDid: string,
  realmId: string,
  subjectDid: string,
  joinAuthorisedByRef: string,
  opts: { server?: SolandKey } = {},
) {
  const inviteId = typedId("invite");
  const expiresAt = canonicalTimestamp(new Date(Date.now() + 86_400_000));
  const sealBasis = await readRealmSealBasis(
    request,
    token,
    realmId,
    opts.server,
  );
  const envelope = signedEventEnvelope({
    actorDid: inviterDid,
    realmId,
    kind: "ak.invite.create",
    sealBasis,
    refs: [{ role: "join_authorised_by", id: joinAuthorisedByRef }],
    // Directed invite-create payload shape per event-payload.schema.json
    // `invite_payload` (variant: invitee + invite_delivery_target +
    // introduction_evidence_digest + expires_at). The subject is carried by
    // `invitee` (a DID); the forbidden `subject_did` wire field and the
    // non-schema `realm_id` / `inviter` keys are intentionally absent.
    payload: {
      invite_id: inviteId,
      invitee: subjectDid,
      invite_delivery_target: {
        recipient_service_id: solandServiceId(opts.server),
        recipient_service_kind: "principal_server",
      },
      introduction_evidence_digest: `sha256:${sha256CanonicalJson({ kind: "explicit_address" })}`,
      expires_at: expiresAt,
    },
  });
  await advanceEnvelopeToActorFrontier(request, token, envelope, opts.server);
  return await request.post(
    `${solandBaseUrl(opts.server)}/_arkret/self/events`,
    {
      headers: authHeaders(token),
      data: envelope,
    },
  );
}

// join-policy.md §7.1.1 / §9 — list viewer-scoped private applications.
export async function listMemberApplicationsApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey } = {},
): Promise<{
  applications: Array<Record<string, unknown>>;
  viewer_is_reviewer: boolean;
}> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}/join-applications`,
    { headers: authHeaders(token) },
  );
  return await expectJsonOk<{
    applications: Array<Record<string, unknown>>;
    viewer_is_reviewer: boolean;
  }>(response, `list applications ${realmId}`);
}

export async function listJoinApplicationAuditApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  applicationRef: string,
  opts: { server?: SolandKey } = {},
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}/join-applications/${encodeURIComponent(applicationRef)}/audit`,
    { headers: authHeaders(token) },
  );
  const outcome = await expectJsonOk<{
    entries: Array<Record<string, unknown>>;
  }>(response, `list application audit ${applicationRef}`);
  return outcome.entries;
}

export async function acceptInviteApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  inviteId: string,
  opts: {
    server?: SolandKey;
    candidateTokens?: Partial<Record<SolandKey, string>>;
  } = {},
) {
  let sealBasis: Record<string, unknown> | undefined;
  let candidateServiceId: string | undefined;
  await expect
    .poll(
      async () => {
        const resolutionResponse = await request.post(
          `${solandBaseUrl(opts.server)}/_arkret/find/directory/resolve-realm`,
          {
            headers: authHeaders(token),
            data: { realm_id: realmId, requester: actorDid },
          },
        );
        const resolution = await expectJsonOk<{
          join_candidates?: Array<{
            service_id?: string;
            join_methods?: string[];
            seal_basis?: Record<string, unknown>;
          }>;
        }>(resolutionResponse, `resolve invite join candidate for ${realmId}`);
        const candidate = resolution.join_candidates?.find((candidate) =>
          candidate.join_methods?.includes("invite_accept"),
        );
        sealBasis = candidate?.seal_basis;
        candidateServiceId = candidate?.service_id;
        return sealBasis;
      },
      {
        message: "invite-accept join candidate Seal basis",
        timeout: 30_000,
        intervals: [250, 500, 1_000, 2_000],
      },
    )
    .toBeTruthy();
  const candidateServer = (["alpha", "beta"] as const).find(
    (server) => solandServiceId(server) === candidateServiceId,
  );
  if (!candidateServer) {
    throw new Error(
      `invite-accept candidate ${candidateServiceId ?? "<missing>"} is not a managed Soland service`,
    );
  }
  const candidateToken = opts.candidateTokens?.[candidateServer] ?? token;

  return await submitSignedEventApi(
    request,
    candidateToken,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ak.invite.accept",
      actorSeq: 0,
      sealBasis,
      payload: {
        invite_id: inviteId,
      },
    }),
    { server: candidateServer, context: `accept invite ${inviteId}` },
  );
}

export async function listInvitesApi(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<
  Array<{
    id: string;
    realm_id: string;
    invitee?: string;
    state?: string;
    status?: string;
  }>
> {
  const actorDid = await currentActorDidApi(request, token, opts);
  const url = new URL(
    "/_arkret/self/authz/invites",
    solandBaseUrl(opts.server),
  );
  url.searchParams.set("subject", actorDid);
  const response = await request.get(url.toString(), {
    headers: authHeaders(token),
  });
  const body = await expectJsonOk<{
    invites?: Array<{ id: string; realm_id: string; invitee?: string }>;
  }>(response, "list invites");
  return body.invites ?? [];
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
    mentions?: string[];
    actorSeq?: number;
  } = {},
) {
  const actorDid = await currentActorDidApi(request, token, opts);
  const strandId = await resolveDefaultStrandId(request, token, realmId, {
    server: opts.server,
  });
  const envelope = signedEventEnvelope({
    actorDid,
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
        ...(opts.mentions ? { mentions: opts.mentions } : {}),
      },
    },
  });
  if (opts.actorSeq === undefined) {
    await advanceEnvelopeToActorFrontier(request, token, envelope, opts.server);
  }
  await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `send message to ${realmId}`,
  });
  return {
    event_id: String(envelope.event_id),
    realm_id: realmId,
    actor_id: actorDid,
    actor_seq: Number(envelope.actor_seq),
    prev_refs: [...(envelope.prev_refs as string[])],
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
  const actorDid = await currentActorDidApi(request, token, opts);
  const payload: Record<string, unknown> = {
    strand_id: strandId,
    watcher_actor_id: watcherActorId,
    level,
  };
  if (level !== null) {
    payload.level_public = opts.levelPublic ?? false;
  }
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
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
    data: canonicalJson({ realms: [realmId], limit: opts.limit ?? 100 }),
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

export async function accountSubscribeDeltaApi(
  request: APIRequestContext,
  token: string,
  opts: {
    server?: SolandKey;
    filter?: Record<string, unknown>;
    catchup?: boolean;
    after?: string;
    timeoutMs?: number;
    headers?: Record<string, string>;
  } = {},
): Promise<Record<string, unknown>> {
  const frames = await accountSubscribeFramesApi(request, token, opts);
  const delta = frames.find((frame) => frame.kind === "delta") ?? frames[0];
  expect(delta, "account subscribe delta frame").toBeTruthy();
  return delta;
}

export async function accountSubscribeFramesApi(
  request: APIRequestContext,
  token: string,
  opts: {
    server?: SolandKey;
    filter?: Record<string, unknown>;
    catchup?: boolean;
    after?: string;
    timeoutMs?: number;
    headers?: Record<string, string>;
  } = {},
): Promise<Array<Record<string, unknown>>> {
  void request;
  const url = new URL(
    `${solandBaseUrl(opts.server)}/_arkret/self/account/subscribe`,
  );
  if (opts.catchup !== false) {
    url.searchParams.set("catchup", "true");
  }
  if (opts.filter) {
    url.searchParams.set("filter", JSON.stringify(opts.filter));
  }
  if (opts.after) {
    url.searchParams.set("after", opts.after);
  }

  const controller = new AbortController();
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const frames: Array<Record<string, unknown>> = [];
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetch(url, {
      headers: {
        ...(opts.headers ?? authHeaders(token)),
        accept: "application/x-ndjson",
      },
      signal: controller.signal,
    });
    if (response.status !== 200) {
      const text = await response.text();
      expect(
        response.status,
        `account subscribe returned ${response.status}: ${text}`,
      ).toBe(200);
    }
    if (!response.body) {
      const text = await response.text();
      frames.push(...parseNdjsonFrames(text));
      return frames;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let pending = "";
    let decided = false;
    while (!decided) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      pending += decoder.decode(chunk.value, { stream: true });
      let newline = pending.search(/\r?\n/);
      while (newline >= 0) {
        const line = pending.slice(0, newline).trim();
        pending = pending.slice(
          pending.charCodeAt(newline) === 13 ? newline + 2 : newline + 1,
        );
        if (line) {
          const frame = JSON.parse(line) as Record<string, unknown>;
          frames.push(frame);
          if (accountSubscribeFrameCompletesSnapshot(frame)) {
            decided = true;
            break;
          }
        }
        newline = pending.search(/\r?\n/);
      }
    }
    const tail = (pending + decoder.decode()).trim();
    if (!decided && tail) {
      frames.push(...parseNdjsonFrames(tail));
    }
    await reader.cancel().catch(() => undefined);
  } catch (error) {
    if (timedOut || (error instanceof Error && error.name === "AbortError")) {
      throw new Error(`account subscribe timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }

  expect(frames.length, "account subscribe frames").toBeGreaterThan(0);
  return frames;
}

function accountSubscribeFrameCompletesSnapshot(
  frame: Record<string, unknown>,
): boolean {
  return (
    frame.kind === "catchup_complete" ||
    frame.kind === "dropped" ||
    frame.kind === "resync_required" ||
    frame.kind === "unauthorized"
  );
}

function parseNdjsonFrames(text: string): Array<Record<string, unknown>> {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

/// The holder-signed `ak.account_data.set` both account-data endpoints now take.
///
/// The kind's actor-private cell subject is
/// `composite[envelope.actor_id, payload.key]`, so the Event's actor is half the
/// cell address: the holder signs, and the service cannot author it under its own
/// DID. Omit `value` for the tombstone the DELETE endpoint requires.
export function accountDataSetSubmission(args: {
  actorDid: string;
  key: string;
  expectedRevision: number;
  value?: unknown;
  privateValue?: boolean;
}): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    key: args.key,
    owner: args.actorDid,
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
      actorDid: args.actorDid,
      realmId: principalControlRealmForDid(args.actorDid),
      kind: "ak.account_data.set",
      payload,
    }),
  };
}

export async function replaceAccountDataApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  key: string,
  body: Record<string, unknown>,
  expectedRevision: number,
  opts: { server?: SolandKey; context?: string } = {},
) {
  const content = privateAccountDataKeys.has(key)
    ? encryptedAccountDataValue(actorDid, key, body)
    : body;
  const response = await request.put(
    `${solandBaseUrl(opts.server)}/_arkret/self/account_data/${encodeURIComponent(key)}`,
    {
      headers: authHeaders(token),
      data: {
        set_event: accountDataSetSubmission({
          actorDid,
          key,
          expectedRevision,
          value: content,
        }),
      },
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
  actorDid: string,
  dataType: string,
  content: Record<string, unknown>,
): Record<string, unknown> {
  const schema = "ak.schema.account_data_encrypted_value.v1";
  const version = "1.0";
  const accountSecret = randomBytes(32);
  const keyInfo = Buffer.from(
    canonicalJson({ schema, actor_id: actorDid, account_data_key: dataType }),
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
    actor_id: actorDid,
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
    aad_digest: digest(aadBytes),
    ciphertext_digest: digest(ciphertext),
  };
}

export async function currentActorDidApi(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/account/viewer`;
  const response = await request.get(url, {
    headers: authHeaders(token, "GET", url),
  });
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
  const createdAt = canonicalEventTimestamp(
    args.createdAt === undefined ? undefined : new Date(args.createdAt),
  );
  const hlc = args.hlc ?? nextEnvelopeHlc(args.realmId, createdAt);
  const payload = stripUndefined(args.payload) as Record<string, unknown>;
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
    actor_id: canonicalDidCoreId(args.actorDid),
    authorization_ref: args.authorizationRef,
    actor_seq: args.actorSeq ?? nextActorSeq(),
    created_at: createdAt,
    hlc,
    prev_refs: args.prevRefs ?? [],
    refs: args.refs ?? [],
    preconditions: args.preconditions,
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
        actorDid: args.actorDid,
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
  const actorDid =
    typeof envelope.actor_id === "string" ? envelope.actor_id : undefined;
  if (!actorDid) {
    throw new Error("Event envelope actor_id is required to refresh proofs");
  }
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
      actorDid,
      event,
      verificationMethod: proofVerificationMethod,
    }),
  ];
}

function eventEnvelopeProof(args: {
  actorDid: string;
  event: Record<string, unknown>;
  verificationMethod?: string;
}): Record<string, unknown> {
  const mode = eventProofMode();
  const registeredSigner = eventSignerFor(
    args.actorDid,
    args.verificationMethod,
  );
  const verificationMethod =
    args.verificationMethod ??
    registeredSigner?.verificationMethod ??
    `${args.actorDid}#device`;
  const createdAt = canonicalEventTimestamp();

  if (mode === "dev-proof") {
    const eventDigest = `sha256:${sha256CanonicalJson(args.event)}`;
    return {
      type: "dev-proof",
      verification_method: verificationMethod,
      event_digest: eventDigest,
    };
  }

  return sdkEventEnvelopeProof({
    actorDid:
      registeredSigner?.verificationMethod.split("#", 1)[0] ?? args.actorDid,
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
  opts: { server?: SolandKey; context?: string } = {},
) {
  const context = opts.context ?? `submit ${String(envelope.kind)}`;
  await applyRegisteredCbaPlane(request, token, envelope, opts.server);
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
    const controlControlProposalAck = await issueControlProposalAckApi(
      request,
      token,
      envelope,
      authorizationLease,
      opts.server,
      context,
    );
    const realmId = stringValue(envelope.realm_id);
    const actorDid = stringValue(envelope.actor_id);
    const actorControlRealm = actorDid
      ? principalControlRealmForDidIfKnown(actorDid)
      : undefined;
    const previousControlRoot =
      controlControlProposalAck &&
      realmId &&
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
        authorization_lease: authorizationLease,
        ...(controlControlProposalAck
          ? { control_proposal_ack: controlControlProposalAck }
          : {}),
      }),
    });
    const text = await response.text();
    if ([200, 201].includes(response.status())) {
      const outcome = JSON.parse(text) as Record<string, unknown>;
      rememberPublicationEvidence([envelope], [authorizationLease], outcome);
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
      !(
        realmId &&
        realmAuthorityControllers.has(
          realmAuthorityControllerKey(opts.server, realmId),
        )
      ) &&
      attempt < 2
    ) {
      await forceConformanceCbaBasis(request, envelope, opts.server);
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
  await applyRegisteredCbaPlane(request, token, envelope, opts.server);
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
      await applyRegisteredCbaPlane(request, token, event, opts.server);
    }
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
      rememberPublicationEvidence(events, authorizationLeases, outcome);
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
        await forceConformanceCbaBasis(request, event, opts.server);
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
  await applyRegisteredCbaPlane(request, token, envelope, opts.server);
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
  authorizationLease: Record<string, unknown>,
  server: SolandKey | undefined,
  context: string,
): Promise<Record<string, unknown> | undefined> {
  // In the Standard submission context, seal_basis distinguishes an ordinary
  // non-genesis Control Move from a DataEvent. Anchor units are filtered by
  // their batch caller and must never enter this operation.
  if (event.seal_basis == null) {
    return undefined;
  }
  const localAck = localPrincipalControlProposalAck(event);
  if (localAck) {
    return localAck;
  }
  const url = `${solandBaseUrl(server)}/_arkret/self/control-proposal-acks`;
  const response = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({
      event,
      authorization_lease: authorizationLease,
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

export function localPrincipalControlProposalAck(
  event: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const actorDid = stringValue(event.actor_id);
  const scopeRef = event.scope_ref as Record<string, unknown> | undefined;
  const realmId =
    stringValue(event.realm_id) ?? stringValue(scopeRef?.realm_id);
  const actorControlRealm = actorDid
    ? principalControlRealmForDidIfKnown(actorDid)
    : undefined;
  if (
    !actorDid ||
    !realmId ||
    !actorControlRealm ||
    realmId !== actorControlRealm
  ) {
    return undefined;
  }
  const proof = Array.isArray(event.proofs)
    ? (event.proofs[0] as Record<string, unknown> | undefined)
    : undefined;
  const registeredSigner = eventSignerFor(
    actorDid,
    stringValue(proof?.verification_method),
  );
  const verificationMethod =
    registeredSigner?.verificationMethod ??
    stringValue(proof?.verification_method) ??
    `${actorDid}#device`;
  const proposalPayload = { ...event };
  delete proposalPayload.proofs;
  delete proposalPayload.unsigned;
  delete proposalPayload.actor_kind;
  // `event_id` is derived from the Event digest and therefore cannot be part
  // of that digest's preimage. Keep this local principal ack byte-identical to
  // `arkret_wire::event_digest_preimage`.
  delete proposalPayload.event_id;
  const proposalDigest = `sha256:${sha256CanonicalJson(proposalPayload)}`;
  const authoritySetRef = `sha256:${sha256CanonicalJson({
    kind: "single_did",
    actor_id: actorDid,
  })}`;
  const cacheKey = `${proposalDigest}\0${authoritySetRef}\0${verificationMethod}`;
  let member = localControlProposalAuthorityAcks.get(cacheKey);
  if (!member) {
    const receivedAt = new Date();
    const memberWithoutSignature = {
      realm_id: realmId,
      proposal_digest: proposalDigest,
      received_at: receivedAt.toISOString(),
      decision_due_at: new Date(receivedAt.getTime() + 30_000).toISOString(),
      absolute_due_at: new Date(receivedAt.getTime() + 90_000).toISOString(),
      authority_set_ref: authoritySetRef,
    };
    const payloadDigest = `sha256:${sha256CanonicalJson(
      memberWithoutSignature,
    )}`;
    const transcript = {
      context: "ak.control-proposal-authority-ack-proof-v1",
      payload_digest: payloadDigest,
      verification_method: verificationMethod,
      created_at: memberWithoutSignature.received_at,
    };
    const protectedHeader = base64urlJsonCanonical({ alg: "Ed25519" });
    const signingInput = `${protectedHeader}.${base64urlJsonCanonical(
      transcript,
    )}`;
    const signature =
      signWithRegisteredEventSigner(
        actorDid,
        verificationMethod,
        signingInput,
      ) ??
      sign(
        null,
        Buffer.from(signingInput, "utf8"),
        developmentProtocolPrivateKey(verificationMethod),
      ).toString("base64url");
    member = {
      ...memberWithoutSignature,
      signature: {
        alg: "Ed25519",
        verification_method: verificationMethod,
        payload_digest: payloadDigest,
        created_at: memberWithoutSignature.received_at,
        jws: `${protectedHeader}..${signature}`,
      },
    };
    localControlProposalAuthorityAcks.set(cacheKey, member);
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

async function issueAuthorizationLeasesApi(
  request: APIRequestContext,
  token: string,
  events: Array<Record<string, unknown>>,
  server?: SolandKey,
): Promise<APIResponse> {
  const requestBody = { events };
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

function authorizationLeasesFromIssueOutcome(
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

function rememberPublicationEvidence(
  events: Array<Record<string, unknown>>,
  leases: Array<Record<string, unknown>>,
  outcome: Record<string, unknown>,
): void {
  const receipts = Array.isArray(outcome.ingress_receipts)
    ? (outcome.ingress_receipts as Array<Record<string, unknown>>)
    : [];
  if (receipts.length !== events.length) {
    throw new Error(
      `publication returned ${receipts.length} ingress receipts for ${events.length} Events`,
    );
  }
  events.forEach((event, index) => {
    const eventId = stringValue(event.event_id);
    if (!eventId) {
      throw new Error("published Event is missing event_id");
    }
    publicationEvidenceByEventId.set(eventId, {
      event: stripUndefined(event) as PublicationEvidence["event"],
      authorization_lease: leases[
        index
      ] as PublicationEvidence["authorization_lease"],
      ingress_receipts: [
        receipts[index],
      ] as PublicationEvidence["ingress_receipts"],
    });
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
    (status === 400 &&
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
  const actorDid = stringValue(envelope.actor_id);
  if (!actorDid) {
    throw new Error(
      "Event envelope actor_id is required to refresh its frontier",
    );
  }
  const realmId = stringValue(envelope.realm_id);
  if (!realmId) {
    throw new Error(
      "Event envelope realm_id is required to refresh its frontier",
    );
  }
  const frontierUrl = `${solandBaseUrl(server)}/_arkret/self/events/frontier`;
  const response = await request.fetch(frontierUrl, {
    method: "QUERY",
    data: canonicalJson({ actor_id: actorDid, realm_id: realmId }),
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
  }>(response, `read Realm actor frontier for (${realmId}, ${actorDid})`);
  if (
    body.frontier?.kind !== "realm_actor" ||
    body.frontier.realm_id !== realmId ||
    body.frontier.actor_id !== actorDid
  ) {
    throw new Error(
      "combined Event frontier response does not match its selector",
    );
  }
  const actorSeq = body.frontier.next_actor_seq;
  if (typeof actorSeq !== "number" || !Number.isSafeInteger(actorSeq)) {
    throw new Error(
      `Realm actor frontier for ${actorDid} has no valid next_actor_seq`,
    );
  }
  if (
    !Array.isArray(body.frontier.frontier_event_ids) ||
    body.frontier.frontier_event_ids.some((value) => typeof value !== "string")
  ) {
    throw new Error(
      `Realm actor frontier for ${actorDid} has invalid frontier_event_ids`,
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

// Local projection of the wire view: the callers only need the seal head plus
// a flat digest list. The members are typed off
// `service-operation-dtos.schema.json#/$defs/RealmSealFrontierView` so a
// renamed or retyped wire member is a `tsc` error here.
type RealmSealFrontier = Pick<
  RealmSealFrontierView,
  "seal_id" | "control_event_set_root" | "state_root"
> & {
  pending_proposal_digests: string[];
};

async function readRealmSealFrontier(
  request: APIRequestContext,
  token: string,
  realmId: string,
  server?: SolandKey,
): Promise<RealmSealFrontier> {
  const frontierUrl = `${solandBaseUrl(server)}/_arkret/self/events/frontier`;
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
    frontier?: Partial<RealmSealFrontierView>;
  }>(response, `read Realm Seal frontier for ${realmId}`);
  const frontier = body.frontier;
  if (
    frontier?.kind !== "realm_seal" ||
    typeof frontier.seal_id !== "string" ||
    typeof frontier.control_event_set_root !== "string" ||
    typeof frontier.state_root !== "string"
  ) {
    throw new Error(
      `Realm Seal frontier for ${realmId} has an invalid shape: ${JSON.stringify(body)}`,
    );
  }
  return {
    seal_id: frontier.seal_id,
    control_event_set_root: frontier.control_event_set_root,
    state_root: frontier.state_root,
    pending_proposal_digests: (
      frontier.governance_health?.pending_proposals ?? []
    ).flatMap((proposal) =>
      typeof proposal.proposal_digest === "string"
        ? [proposal.proposal_digest]
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
    `Realm ${realmId} control frontier did not become idle after ${opts.afterControlEventSetRoot ?? "its current root"} within ${opts.timeoutMs ?? 30_000}ms; last frontier=${JSON.stringify(lastFrontier)}`,
    { cause: lastError },
  );
}

async function applyRegisteredCbaPlane(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  server?: SolandKey,
): Promise<void> {
  const kind = stringValue(envelope.kind);
  const realmId = stringValue(envelope.realm_id);
  const actorDid = stringValue(envelope.actor_id);
  if (!kind || !realmId || !actorDid) {
    throw new Error("CBA preparation requires kind, realm_id, and actor_id");
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
  if (
    envelope.authorization_ref === undefined &&
    realmAuthorityControllers.get(
      realmAuthorityControllerKey(server, realmId),
    ) === actorDid &&
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
        if (canonicalRealm) {
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
            token,
            realmId,
            actorDid,
            server,
          );
          if (directoryBasis) {
            envelope.seal_basis = directoryBasis;
          } else {
            await forceConformanceCbaBasis(request, envelope, server);
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
                subject: actorDid,
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
        stringValue(proof?.verification_method) ?? `${actorDid}#device`;
      envelope.auth_context = eventAuthContext(actorDid, verificationMethod);
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
  token: string,
  realmId: string,
  actorDid: string,
  server?: SolandKey,
): Promise<Record<string, unknown> | undefined> {
  const response = await request.post(
    `${solandBaseUrl(server)}/_arkret/find/directory/resolve-realm`,
    {
      headers: authHeaders(token),
      data: { realm_id: realmId, requester: actorDid },
    },
  );
  if (!response.ok()) {
    return undefined;
  }
  const body = (await response.json()) as {
    join_candidates?: Array<{
      seal_basis?: Record<string, unknown>;
    }>;
  };
  const basis = body.join_candidates?.find((candidate) => {
    const value = candidate.seal_basis;
    return (
      value &&
      Array.isArray(value.leaves) &&
      value.leaves.length > 0 &&
      typeof value.control_event_set_root === "string" &&
      typeof value.state_root === "string"
    );
  })?.seal_basis;
  return basis;
}

async function forceConformanceCbaBasis(
  request: APIRequestContext,
  envelope: Record<string, unknown>,
  server?: SolandKey,
): Promise<void> {
  const kind = stringValue(envelope.kind);
  const realmId = stringValue(envelope.realm_id);
  const actorDid = stringValue(envelope.actor_id);
  if (!kind || !realmId || !actorDid) {
    throw new Error("CBA fixture basis requires kind, realm_id, and actor_id");
  }
  const descriptor = eventKindDescriptor(kind);
  if (!descriptor?.reducer_input) {
    return;
  }
  const response = await request.post(
    `${solandBaseUrl(server)}/_arkret/_conformance/realm-basis`,
    {
      headers: { "content-type": "application/json" },
      data: canonicalJson({
        realm_id: realmId,
        subject: actorDid,
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
    const proof = Array.isArray(envelope.proofs)
      ? (envelope.proofs[0] as Record<string, unknown> | undefined)
      : undefined;
    const verificationMethod =
      stringValue(proof?.verification_method) ?? `${actorDid}#device`;
    envelope.auth_context = eventAuthContext(actorDid, verificationMethod);
    delete envelope.seal_basis;
  }
  const proof = Array.isArray(envelope.proofs)
    ? (envelope.proofs[0] as Record<string, unknown> | undefined)
    : undefined;
  refreshEventEnvelopeProof(envelope, stringValue(proof?.verification_method));
}

function eventAuthContext(
  actorDid: string,
  verificationMethod: string,
): Record<string, unknown> {
  const fragmentIndex = verificationMethod.indexOf("#");
  return {
    actor_id: actorDid,
    key_id:
      fragmentIndex >= 0
        ? verificationMethod.slice(fragmentIndex + 1)
        : verificationMethod,
    key_epoch: 0,
  };
}

export async function prepareSignedEventCbaApi(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: { server?: SolandKey } = {},
): Promise<void> {
  await applyRegisteredCbaPlane(request, token, envelope, opts.server);
}

export async function seedConformanceRealmBasisApi(
  request: APIRequestContext,
  realmId: string,
  subjectDid: string,
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
        subject: subjectDid,
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
  opts: { server?: SolandKey } = {},
): Promise<string> {
  // Primary: Realm projection carries the authoritative default_strand_id.
  const realmResp = await request.get(
    `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
    { headers: authHeaders(token) },
  );
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
  const flowsResp = await request.get(
    `${solandBaseUrl(opts.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}/strands`,
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
  throw new Error(
    `resolveDefaultStrandId: accepted projections for ${realmId} expose no default Strand`,
  );
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
  actorDid?: string;
  realmId: string;
  kind: string;
  payload: Record<string, unknown>;
  sealBasis?: Record<string, unknown>;
}) {
  return signedEventEnvelope({
    eventId: args.eventId,
    actorDid: args.actorDid ?? "did:web:cotest-federation.example",
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
    // Negative-coverage hook: drive the RFC 9421 freshness window past its
    // bound so verify rejects on expiry (federation.md §3.2). The signature
    // itself stays cryptographically valid — only created/expires are stale.
    expireSignature?: boolean;
    relaySourceDid?: string;
    serviceBindingFrontier?: string[];
  },
) {
  const destination = opts.destination ?? solandServiceId(opts.server);
  const url = `${solandBaseUrl(opts.server)}/_arkret/peer/events`;
  const body = peerEventsSubmitBody(
    opts.realmId,
    events.map(federationEventWireBody),
    {
      serviceBindingFrontier: opts.serviceBindingFrontier,
    },
  );
  const sourceDid = opts.relaySourceDid ?? opts.origin;
  const headers = signedFederationPushHeaders(
    sourceDid,
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
  return await expectJsonOk<{
    status: "accepted" | "duplicate" | "deferred";
    received_at?: string;
    retry_after_ms?: number;
  }>(response, "submit peer invite delivery");
}

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
    opts.destination ?? body.invite_address.recipient_service_id;
  const url = `${solandBaseUrl(opts.server)}/_arkret/peer/invites`;
  return await request.post(url, {
    data: canonicalJson(body),
    headers: signedFederationPushHeaders(opts.origin, destination, url, body),
  });
}

function federationEventWireBody(
  event: Record<string, unknown>,
): Record<string, unknown> {
  const eventId = stringValue(event.event_id);
  const evidence = eventId
    ? publicationEvidenceByEventId.get(eventId)
    : undefined;
  if (!evidence) {
    throw new Error(
      `federation requires stored authorization lease and ingress receipt for Event ${eventId ?? "<missing event_id>"}`,
    );
  }
  return stripUndefined(evidence) as Record<string, unknown>;
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
  const body = stripUndefined({
    realms: opts.realmId ? [opts.realmId] : undefined,
    actors: opts.actorDid ? [opts.actorDid] : undefined,
    limit: opts.limit ?? 100,
    after: opts.after,
  });
  const targetUri = `${solandBaseUrl(opts.server)}/_arkret/peer/events`;
  const sourceDid = opts.sourceDid ?? "did:web:cotest-peer.example";
  const destinationDid = solandServiceId(opts.server);
  const response = await request.fetch(targetUri, {
    method: "QUERY",
    data: canonicalJson(body),
    headers: signedFederationPushHeaders(
      sourceDid,
      destinationDid,
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
  opts: { server?: SolandKey; sourceDid?: string } = {},
) {
  const body = { realm_id: realmId };
  const targetUri = `${solandBaseUrl(opts.server)}/_arkret/peer/events/frontier`;
  const sourceDid = opts.sourceDid ?? "did:web:cotest-peer.example";
  const destinationDid = solandServiceId(opts.server);
  const response = await request.fetch(targetUri, {
    method: "QUERY",
    data: canonicalJson(body),
    headers: signedFederationPushHeaders(
      sourceDid,
      destinationDid,
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
  // An empty batch has no heads. Fabricating one would mean minting an
  // `ak:event:` id, and an Event id is derived from an Event that exists.
  return heads;
}

function peerEventsSubmitBody(
  realmId: string,
  events: Array<Record<string, unknown>>,
  overrides: {
    serviceBindingFrontier?: string[];
  } = {},
): Record<string, unknown> {
  const frontier =
    overrides.serviceBindingFrontier &&
    overrides.serviceBindingFrontier.length > 0
      ? overrides.serviceBindingFrontier
      : batchFrontierEventIds(events);
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
      destination_service_kind: "principal_server",
    },
    events,
  }) as Record<string, unknown>;
}

function signedFederationPushHeaders(
  sourceDid: string,
  destinationDid: string,
  targetUri: string,
  body: unknown,
  opts: {
    expireSignature?: boolean;
    idempotencyKey?: string;
    method?: "POST" | "QUERY";
  } = {},
): Record<string, string> {
  const method = opts.method ?? "POST";
  const bodyBytes = Buffer.from(canonicalJson(body), "utf8");
  const contentDigest = `sha-256=:${createHash("sha256").update(bodyBytes).digest("base64")}:`;
  const sourceTrustDomain = trustDomainFromServiceId(sourceDid);
  const destinationTrustDomain = trustDomainFromServiceId(destinationDid);
  const nowSeconds = Math.floor(Date.now() / 1000);
  // When asked, push created/expires fully behind the accepted freshness
  // window (federation.md §3.2): expires < now and created beyond the ±30s
  // skew bound. The signature still covers these params, so it verifies — the
  // request is rejected on the freshness check, not on a bad signature.
  const created = opts.expireSignature ? nowSeconds - 600 : nowSeconds;
  const expires = opts.expireSignature ? nowSeconds - 300 : created + 300;
  const keyid = `${sourceDid}#federation-fanout-key`;
  const idempotencyComponent = opts.idempotencyKey ? ' "idempotency-key"' : "";
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" "source-service-id" ` +
    `"destination-service-id" "source-trust-domain" "destination-trust-domain"` +
    `${idempotencyComponent});created=${created};expires=${expires};keyid="${keyid}";alg="ed25519"`;
  const signatureBase = [
    `"@method": ${method}`,
    `"@target-uri": ${targetUri}`,
    `"@authority": ${new URL(targetUri).host}`,
    `"content-digest": ${contentDigest}`,
    `"source-service-id": ${sourceDid}`,
    `"destination-service-id": ${destinationDid}`,
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
    serviceHttpPrivateKey(sourceDid),
  );
  return {
    "content-type": "application/json",
    "content-digest": contentDigest,
    "source-service-id": sourceDid,
    "destination-service-id": destinationDid,
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
      "COTEST_FORBID_DEV_PROOF=1 forbids the legacy dev-proof fixture; set COTEST_EVENT_PROOF_MODE=detached-jws",
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
  let encoded: string | undefined;
  if (serviceId === solandServiceId("default")) {
    encoded = process.env.COTEST_SOLAND_SERVICE_SIGNING_KEY?.trim();
  } else if (serviceId === solandServiceId("beta")) {
    encoded = process.env.COTEST_SOLAND_BETA_SERVICE_SIGNING_KEY?.trim();
  }
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
  const webHost = serviceId.startsWith("did:web:")
    ? serviceId.slice("did:web:".length).split(":")[0]
    : undefined;
  const webvhHost = serviceId.startsWith("did:webvh:")
    ? serviceId.slice("did:webvh:".length).split(":")[1]
    : undefined;
  const keyScope = serviceId.startsWith("did:key:")
    ? serviceId.slice("did:key:".length)
    : undefined;
  const rawScope = webHost ?? webvhHost ?? keyScope ?? serviceId;
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

type CotestWireCommand =
  | "canonical-json"
  | "sha256-canonical-json"
  | "capability-action-registry-digest"
  | "event-proof"
  | "event-envelope-proof"
  | "event-derived-id"
  | "mimi-consent-proof"
  | "principal-control-realm-id"
  | "account-handoff-outcome"
  | "account-handoff-request"
  | "principal-registration-fixture"
  | "principal-service-binding-proof"
  | "identity-creation-register-request"
  | "principal-bootstrap-seal"
  | "principal-successor-seal";

type CotestWireCanonicalJson = { canonical: string };
type CotestWireDigest = { digest: string; digest_hex: string };
type CotestWireCapabilityRegistryDigest = { digest: string };
const cotestRepoRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
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

/// Canonical (JCS key-ordered) JSON serialized to UTF-8 bytes. Authoritative
/// replacement for the per-helper `canonicalBytes` thin wrappers.
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

let capabilityActionRegistryDigest: string | undefined;

/** The digest of the SDK-embedded complete capability-action registry. */
export function sdkCapabilityActionRegistryDigest(): string {
  capabilityActionRegistryDigest ??=
    cotestWire<CotestWireCapabilityRegistryDigest>(
      "capability-action-registry-digest",
      {},
    ).digest;
  return capabilityActionRegistryDigest;
}

/// base64url of the *canonical* (JCS) JSON encoding of `value`. Use this for any
/// signing input whose bytes must be deterministic key-ordered JSON (detached
/// JWS over a canonical transcript, anchorer payloads, holder proofs).
export function base64urlJsonCanonical(value: unknown): string {
  return Buffer.from(canonicalJson(value), "utf8").toString("base64url");
}

/// base64url of the *insertion-order* (`JSON.stringify`) JSON encoding of
/// `value`. Use this where the wire format is NOT JCS — notably JWT/JWS headers
/// and DPoP claims (RFC 7519 does not mandate JCS), where the verifier expects
/// the exact bytes the signer emitted in field-declaration order.
export function base64urlJsonRaw(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function sdkEventEnvelopeProof(args: {
  actorDid: string;
  event: Record<string, unknown>;
  verificationMethod: string;
  createdAt: string;
  signingSeedB64url?: string;
}): Record<string, unknown> {
  assertJsonTransportable(args.event, "$.event");
  return cotestWire<Record<string, unknown>>("event-envelope-proof", {
    actor_did: args.actorDid,
    event: args.event,
    verification_method: args.verificationMethod,
    created_at: args.createdAt,
    signing_seed_b64url: args.signingSeedB64url,
  });
}

/// The content-bound `event_id` the SDK derives for this envelope.
///
/// An Event id is a function of the Event's own digest and is excluded from
/// that digest's preimage, so a producer builds the envelope first and derives
/// the complete suite-tagged digest identity second. Every SDK-side parse
/// rejects an identity that does not match the digest preimage.
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

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
import { base64url } from "./encoding";

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
  | "space"
  | "view";

export type SignedEventEnvelopeArgs = {
  actorDid: string;
  realmId: string;
  kind: string;
  payload: Record<string, unknown>;
  actorSeq?: number;
  createdAt?: string;
  eventId?: string;
  schemaId?: string;
  /// Override the full `requirements.schema[]` binding. morph.md §4.1 S1/S2
  /// requires schema-evolving events (ck.morph.schema_migrate /
  /// schema_refs-changing ck.morph.update) to bind the active Morph schema set
  /// (the union of from/to schema_refs) here, not just the payload schema id.
  requirementsSchema?: string[];
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

// Re-exported authoritative base64url encoder (single source: encoding.ts).
export { base64url };

/// @deprecated string-only alias for `base64url`; retained for existing callers.
export function b64url(value: string): string {
  return base64url(value);
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
    stringValue(nested?.errcode) ??
    stringValue(nested?.code) ??
    stringValue(nested?.error_code) ??
    stringValue(record.reason) ??
    stringValue(nested?.reason)
  );
}

export function wireErrReason(body: unknown): string | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const record = body as Record<string, unknown>;
  const nested =
    record.error && typeof record.error === "object"
      ? (record.error as Record<string, unknown>)
      : undefined;
  const details =
    record.details && typeof record.details === "object"
      ? (record.details as Record<string, unknown>)
      : undefined;
  const nestedDetails =
    nested?.details && typeof nested.details === "object"
      ? (nested.details as Record<string, unknown>)
      : undefined;
  return (
    stringValue(record.reason) ??
    stringValue(record.reason_code) ??
    stringValue(record.error_reason) ??
    stringValue(details?.reason) ??
    stringValue(details?.reason_code) ??
    stringValue(nested?.reason) ??
    stringValue(nested?.reason_code) ??
    stringValue(nested?.error_reason) ??
    stringValue(nestedDetails?.reason) ??
    stringValue(nestedDetails?.reason_code)
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

export function plaintextVisibleServiceDeclarations(serviceDids: string[]) {
  return Array.from(
    new Set(serviceDids.map((service) => service.trim()).filter(Boolean)),
  ).map((serviceDid) => ({
    service_did: serviceDid,
    service_type: "principal_server",
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
    default_join_rule?: string;
  },
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const ownerDid =
    data.ownerDid ?? (await currentActorDidApi(request, token, opts));
  const realmId = typedId("realm");
  const createdAt = canonicalTimestamp();
  const plaintextVisibleServiceDids =
    data.plaintext_visible_services ??
    (data.encryption_profile === "mls_rfc9420"
      ? []
      : [solandServiceDid(opts.server), "did:web:soland.local"]);
  const plaintextVisibleServices = plaintextVisibleServiceDeclarations(
    plaintextVisibleServiceDids,
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
          default_join_rule: data.default_join_rule ?? "invite",
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

// join-policy.md §3 — write the per-Realm `realm.join_policy` cell. soland
// carries the candidate join policy inside the active
// `ck.realm.policy_components` event under `components.join_policy`; the
// reducer projects it into
// `ck:cell:ck.component.realm.policy_components.v1:<realm_id>` and reads the
// `join_policy` facet from there.
export async function writeJoinPolicyApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  joinPolicy: Record<string, unknown>,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const actorDid = await currentActorDidApi(request, token, opts);
  const digest = `sha256:${sha256CanonicalJson(joinPolicy)}`;
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.realm.policy_components",
      payload: {
        realm_id: realmId,
        value: {
          components: { join_policy: joinPolicy },
          join_policy: joinPolicy,
        },
      },
    }),
    { server: opts.server, context: `write join policy ${realmId}` },
  );
  return digest;
}

// Grant a realm-scoped `ck.realm.join.review` capability to a subject. Used
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
  const grantId = typedId("grant");
  const issuedAt = canonicalTimestamp();
  const unsignedGrant: Record<string, unknown> = {
    id: grantId,
    grant_id: grantId,
    schema: "ck.schema.capability.v1",
    realm_id: args.realmId,
    issuer: args.ownerDid,
    subject: args.subjectDid,
    actions: ["ck.realm.join.review"],
    resources: [{ kind: "realm", realm_id: args.realmId }],
    issued_at: issuedAt,
  };
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: args.ownerDid,
      realmId: args.realmId,
      kind: "ck.capability.grant",
      createdAt: issuedAt,
      payload: {
        grant_id: grantId,
        grant: {
          ...unsignedGrant,
          proofs: [
            eventProof({ actorDid: args.ownerDid, event: unsignedGrant }),
          ],
        },
      },
    }),
    {
      server: args.server,
      context: `grant ck.realm.join.review to ${args.subjectDid}`,
    },
  );
  return grantId;
}

// Grant a Realm-scoped service delegation capability to a peer service DID.
// sync/federation.md §4.4: the grant subject is a service DID; revoking it
// makes the source Principal Server stop pushing future events to that peer.
export async function grantServiceDelegationApi(
  request: APIRequestContext,
  ownerToken: string,
  args: {
    ownerDid: string;
    realmId: string;
    subjectServiceDid: string;
    action?: string;
    server?: SolandKey;
  },
): Promise<string> {
  const grantId = typedId("grant");
  const issuedAt = canonicalTimestamp();
  const action = args.action ?? "ck.realm.delivery_binding_policy";
  const unsignedGrant: Record<string, unknown> = {
    id: grantId,
    grant_id: grantId,
    schema: "ck.schema.capability.v1",
    realm_id: args.realmId,
    issuer: args.ownerDid,
    subject: args.subjectServiceDid,
    actions: [action],
    resources: [{ kind: "realm", realm_id: args.realmId }],
    issued_at: issuedAt,
  };
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: args.ownerDid,
      realmId: args.realmId,
      kind: "ck.capability.grant",
      createdAt: issuedAt,
      payload: {
        grant_id: grantId,
        grant: {
          ...unsignedGrant,
          proofs: [
            eventProof({ actorDid: args.ownerDid, event: unsignedGrant }),
          ],
        },
      },
    }),
    {
      server: args.server,
      context: `grant ${action} service delegation to ${args.subjectServiceDid}`,
    },
  );
  return grantId;
}

// Mint a realm-scoped `ck.capability.grant` event for an arbitrary action set
// and return BOTH the materialized grant id (`ck:grant:*`) and the carrying
// event id (`ck:event:*`). event-and-patch.md §2.2: a high-tier write that
// references its authorization via the envelope `refs[]` `authorized_by` role
// MUST point at the accepted Event that produced the grant, and soland's
// authorized_by ref resolver requires the `ck:event:` typed id (not the
// `ck:grant:` form). Callers that need the authorized_by ref use the returned
// `eventId`.
export type CapabilityGrantEventArgs = {
  ownerDid: string;
  realmId: string;
  subjectDid: string;
  actions: string[];
  // capabilities.md §8: optional finite validity upper bound. Delegated
  // grants (parentGrantId set) MUST narrow — child effective_expires_at MUST
  // be <= the parent's (§10.1).
  expiresAt?: string;
  // capabilities.md §10: delegation chain anchor. When set the grant is a
  // delegated (child) grant and the reducer enforces the §10.1 narrowing
  // invariants against the referenced parent grant.
  parentGrantId?: string;
  server?: SolandKey;
};

// Build (but do not submit) a signed `ck.capability.grant` envelope. Exposed
// separately from grantCapabilityEventApi so negative suites (delegation
// widening, revoked-parent re-delegation, ...) can submit the same canonical
// envelope shape raw and assert the reducer rejection instead of the 200 the
// happy-path helper pins.
export function buildCapabilityGrantEnvelope(
  args: CapabilityGrantEventArgs,
): { envelope: Record<string, unknown>; grantId: string; eventId: string } {
  const grantId = typedId("grant");
  const eventId = typedId("event");
  const issuedAt = canonicalTimestamp();
  const unsignedGrant: Record<string, unknown> = {
    id: grantId,
    grant_id: grantId,
    schema: "ck.schema.capability.v1",
    realm_id: args.realmId,
    issuer: args.ownerDid,
    subject: args.subjectDid,
    actions: args.actions,
    resources: [{ kind: "realm", realm_id: args.realmId }],
    issued_at: issuedAt,
    ...(args.expiresAt ? { expires_at: args.expiresAt } : {}),
    ...(args.parentGrantId ? { parent_grant_id: args.parentGrantId } : {}),
  };
  const envelope = signedEventEnvelope({
    actorDid: args.ownerDid,
    realmId: args.realmId,
    kind: "ck.capability.grant",
    eventId,
    createdAt: issuedAt,
    // capability_grant_payload (event-payload.schema.json) is closed —
    // parent_grant_id travels inside the grant object, not the payload.
    payload: {
      grant_id: grantId,
      grant: {
        ...unsignedGrant,
        proofs: [
          buildDetachedJwsProof({
            issuerDid: args.ownerDid,
            payload: unsignedGrant,
            createdAt: issuedAt,
          }),
        ],
      },
    },
  });
  return { envelope, grantId, eventId };
}

export async function grantCapabilityEventApi(
  request: APIRequestContext,
  ownerToken: string,
  args: CapabilityGrantEventArgs,
): Promise<{ grantId: string; eventId: string }> {
  const { envelope, grantId, eventId } = buildCapabilityGrantEnvelope(args);
  await submitSignedEventApi(request, ownerToken, envelope, {
    server: args.server,
    context: `grant [${args.actions.join(", ")}] to ${args.subjectDid}`,
  });
  return { grantId, eventId };
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
  return await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: args.ownerDid,
      realmId: args.realmId,
      kind: "ck.capability.revoke",
      payload: {
        grant_id: args.grantId,
        realm_id: args.realmId,
      },
    }),
    { server: args.server, context: `revoke grant ${args.grantId}` },
  );
}

// join-policy.md §7.1 stage 1 — `ck.member.state{membership=knock}`. The
// knock Control Move carries no application body (spec §8 keeps free text out
// of the public knock event).
export async function submitKnockApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  opts: { server?: SolandKey; createdAt?: string } = {},
) {
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.member.state",
      createdAt: opts.createdAt,
      payload: {
        realm_id: realmId,
        actor_id: actorDid,
        membership: "knock",
      },
    }),
    { server: opts.server, context: `knock ${realmId}` },
  );
}

// join-policy.md §7.2 — `member.application` carried as a profile-private
// `application` sub-object on the active `ck.member.state{knock}` event.
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
) {
  const receiptDigest =
    application.receiptDigest ?? `sha256:${sha256CanonicalJson({ realmId, actorDid, answers: application.answers ?? [] })}`;
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.member.state",
      createdAt: opts.createdAt,
      payload: {
        realm_id: realmId,
        actor_id: actorDid,
        membership: "knock",
        application: {
          realm_id: realmId,
          applicant_did: actorDid,
          knock_ref: application.knockRef,
          policy_version_digest: application.policyVersionDigest,
          answers: application.answers ?? [],
          application_receipt_digest: receiptDigest,
        },
      },
    }),
    { server: opts.server, context: `application ${realmId}` },
  );
  return receiptDigest;
}

// join-policy.md §7.3 — `member.application.review`. The reviewer submits a
// `ck.member.state` event targeting the applicant; `accept` keeps the
// applicant in `knock` (the join is later authorised via ck.invite.create),
// `reject` drives the applicant to `leave` and stamps cooldown_after_reject.
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
    grantId?: string;
    reviewReceiptDigest?: string;
  },
  opts: { server?: SolandKey; createdAt?: string } = {},
) {
  const reviewReceiptDigest =
    review.reviewReceiptDigest ??
    `sha256:${sha256CanonicalJson({ realmId, applicantDid, applicationRef: review.applicationRef, decision: review.decision })}`;
  const membership = review.decision === "reject" ? "leave" : "knock";
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: reviewerDid,
      realmId,
      kind: "ck.member.state",
      createdAt: opts.createdAt,
      payload: {
        realm_id: realmId,
        actor_id: applicantDid,
        sender: reviewerDid,
        membership,
        application_review: {
          realm_id: realmId,
          application_ref: review.applicationRef,
          decision: review.decision,
          reason_code: review.reasonCode,
          reason_text: review.reasonText,
          reviewer_did: reviewerDid,
          review_receipt_digest: reviewReceiptDigest,
          reviewer_capability_proof: review.grantId
            ? { grant_id: review.grantId }
            : undefined,
        },
      },
    }),
    {
      server: opts.server,
      context: `review ${review.decision} ${realmId}`,
    },
  );
  return reviewReceiptDigest;
}

// join-policy.md §7.4 — applicant withdraws; drives to leave, no cooldown.
export async function submitApplicationCancelApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  applicationRef: string,
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
        membership: "leave",
        application_cancel: {
          realm_id: realmId,
          application_ref: applicationRef,
          cancelled_by: actorDid,
        },
      },
    }),
    { server: opts.server, context: `cancel application ${realmId}` },
  );
}

// join-policy.md §5 — auto-resolve join: `ck.member.state{membership=join}`
// carrying `gate_proofs[]`. The reducer validates the gates inline.
export async function submitJoinWithProofsApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  gateProofs: Array<Record<string, unknown>>,
  opts: { server?: SolandKey; createdAt?: string } = {},
) {
  return await request.post(
    `${solandBaseUrl(opts.server)}/_cokret/self/events`,
    {
      headers: authHeaders(token),
      data: signedEventEnvelope({
        actorDid,
        realmId,
        kind: "ck.member.state",
        createdAt: opts.createdAt,
        payload: {
          realm_id: realmId,
          actor_id: actorDid,
          membership: "join",
          delivery_status: "unroutable",
          gate_proofs: gateProofs,
        },
      }),
    },
  );
}

// join-policy.md §3.1 `cooldown` gate — applicant leaves the Realm.
export async function submitLeaveApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  opts: { server?: SolandKey; createdAt?: string } = {},
) {
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.member.state",
      createdAt: opts.createdAt,
      payload: {
        realm_id: realmId,
        actor_id: actorDid,
        membership: "leave",
      },
    }),
    { server: opts.server, context: `leave ${realmId}` },
  );
}

// join-policy.md §7.5 — `ck.invite.create` whose
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
  return await request.post(
    `${solandBaseUrl(opts.server)}/_cokret/self/events`,
    {
      headers: authHeaders(token),
      data: signedEventEnvelope({
        actorDid: inviterDid,
        realmId,
        kind: "ck.invite.create",
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
            recipient_service_did: solandServiceDid(opts.server),
          },
          introduction_evidence_digest: `sha256:${sha256CanonicalJson({ inviteId, subjectDid })}`,
          expires_at: expiresAt,
        },
      }),
    },
  );
}

// join-policy.md §9 — list member applications scoped to the caller.
// `member.application` is a spec *candidate* workflow concept
// (`governance/join-policy.md` §7.2) that MUST NOT occupy the `/_cokret/...`
// protocol root before formal registration; soland serves it from the
// product-local `/_soland/self/realms/...` surface (realms.rs `local_router`).
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
    `${solandBaseUrl(opts.server)}/_soland/self/realms/${encodeURIComponent(realmId)}/applications`,
    { headers: authHeaders(token) },
  );
  return await expectJsonOk<{
    applications: Array<Record<string, unknown>>;
    viewer_is_reviewer: boolean;
  }>(response, `list applications ${realmId}`);
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
    id: string;
    realm_id: string;
    invitee?: string;
    state?: string;
    status?: string;
  }>
> {
  const actorDid = await currentActorDidApi(request, token, opts);
  const url = new URL(
    "/_cokret/self/authz/invites",
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
    kind: "ck.message.create",
    actorSeq: opts.actorSeq,
    createdAt: opts.createdAt,
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      content: {
        kind: "ck.content.text",
        body,
        ...(opts.mentions ? { mentions: opts.mentions } : {}),
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
  opts: {
    server?: SolandKey;
    filter?: Record<string, unknown>;
    timeoutMs?: number;
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
    timeoutMs?: number;
  } = {},
): Promise<Array<Record<string, unknown>>> {
  void request;
  const url = new URL(
    `${solandBaseUrl(opts.server)}/_cokret/self/account/subscribe`,
  );
  if (opts.catchup !== false) {
    url.searchParams.set("catchup", "true");
  }
  if (opts.filter) {
    url.searchParams.set("filter", JSON.stringify(opts.filter));
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
      headers: { ...authHeaders(token), accept: "application/x-ndjson" },
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

export async function putAccountDataViaEventApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  key: string,
  body: Record<string, unknown>,
  opts: { server?: SolandKey; context?: string } = {},
) {
  const payloadBody = privateAccountDataKeys.has(key)
    ? encryptedAccountDataMarker(key, body)
    : body;
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
        body: payloadBody,
        updated_at: canonicalTimestamp(),
      },
    }),
    {
      server: opts.server,
      context: opts.context ?? `set account_data ${key}`,
    },
  );
}

const privateAccountDataKeys = new Set([
  "ck.account.blocklist",
  "ck.dnd_schedule",
  "ck.push_rules",
]);

function encryptedAccountDataMarker(
  dataType: string,
  content: Record<string, unknown>,
): Record<string, unknown> {
  const payloadDigest = `sha256:${sha256CanonicalJson({
    data_type: dataType,
    content,
  })}`;
  return {
    client_side_conformance: {
      encrypted_account_data: true,
      profile_id: "ck.profile.e2ee_client.v1",
      payload_digest: payloadDigest,
    },
    content_type: "application/vnd.cokret.account-data+json",
    ciphertext: `opaque-client-account-data:${payloadDigest.slice("sha256:".length)}`,
  };
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
      schema: args.requirementsSchema ?? [
        args.schemaId ?? schemaIdForEventKind(args.kind),
      ],
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

// Generic detached-JWS proof over an arbitrary canonical payload (Seal
// signature, capability grant, identity-link, etc. — NOT the Event-bound
// `eventProof`). The JWS transcript signs the `{payload_digest, did,
// verification_method, created_at}` binding object; the protected header is
// exactly `{"alg":"EdDSA"}` (the SDK verifier deserialises with
// deny-unknown-fields). circle-api.ts and webrtc.ts previously each inlined an
// identical `genericDetachedJwsProof`.
export function buildDetachedJwsProof(args: {
  issuerDid: string;
  payload: Record<string, unknown>;
  createdAt: string;
  verificationMethod?: string;
}): Record<string, unknown> {
  const verificationMethod =
    args.verificationMethod ?? `${args.issuerDid}#device`;
  const payloadDigest = `sha256:${sha256CanonicalJson(args.payload)}`;
  const bindingObject = {
    payload_digest: payloadDigest,
    did: args.issuerDid,
    verification_method: verificationMethod,
    created_at: args.createdAt,
  };
  const protectedHeader = base64urlJsonCanonical({ alg: "EdDSA" });
  const bindingPayload = base64urlJsonCanonical(bindingObject);
  const signature = sign(
    null,
    Buffer.from(`${protectedHeader}.${bindingPayload}`, "utf8"),
    developmentServicePrivateKey(args.issuerDid),
  );
  return {
    kind: "detached_jws",
    alg: "EdDSA",
    verification_method: verificationMethod,
    payload_digest: payloadDigest,
    created_at: args.createdAt,
    jws: `${protectedHeader}..${signature.toString("base64url")}`,
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
    if (
      typeof realm.default_strand_id === "string" &&
      realm.default_strand_id
    ) {
      return realm.default_strand_id;
    }
  }

  // Fallback: discover via the Strand projection's derived is_default marker.
  const flowsResp = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/realms/${encodeURIComponent(realmId)}/strands`,
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
    // Negative-coverage hook: drive the RFC 9421 freshness window past its
    // bound so verify rejects on expiry (federation.md §3.2). The signature
    // itself stays cryptographically valid — only created/expires are stale.
    expireSignature?: boolean;
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
  const headers = signedFederationPushHeaders(sourceDid, destination, url, body, {
    expireSignature: opts.expireSignature,
  });
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
    headers: peerGetHeaders(
      opts.sourceDid,
      solandServiceDid(opts.server),
      targetUri,
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
  const targetUri = `${solandBaseUrl(opts.server)}/_cokret/peer/events/frontier?realm_id=${encodeURIComponent(realmId)}`;
  const response = await request.get(targetUri, {
    headers: peerGetHeaders(
      opts.sourceDid,
      solandServiceDid(opts.server),
      targetUri,
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
const E2E_FIXTURES_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "fixtures",
);

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

function assertPrincipalControlRealmVectors(
  did: string,
  realmId: string,
): void {
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
        throw new Error(
          "principal-control-realm-vectors.json contains an incomplete vector",
        );
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
  if (
    pinned?.principal_control_realm_id &&
    pinned.principal_control_realm_id !== realmId
  ) {
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
    (fixture.vectors ?? []).map((entry) => [
      entry.profile_id,
      entry.expected_digest,
    ]),
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
      throw new Error(
        "reducer-profile-registry contains an incomplete active profile",
      );
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
    developmentServiceHttpPrivateKey(sourceDid),
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
  opts: { expireSignature?: boolean } = {},
): Record<string, string> {
  const bodyBytes = Buffer.from(canonicalJson(body), "utf8");
  const contentDigest = `sha-256=:${createHash("sha256").update(bodyBytes).digest("base64")}:`;
  const requestDigest = `sha256:${createHash("sha256").update(bodyBytes).digest("hex")}`;
  const sourceTrustDomain = trustDomainFromServiceDid(sourceDid);
  const destinationTrustDomain = trustDomainFromServiceDid(destinationDid);
  const nowSeconds = Math.floor(Date.now() / 1000);
  // When asked, push created/expires fully behind the accepted freshness
  // window (federation.md §3.2): expires < now and created beyond the ±30s
  // skew bound. The signature still covers these params, so it verifies — the
  // request is rejected on the freshness check, not on a bad signature.
  const created = opts.expireSignature ? nowSeconds - 600 : nowSeconds;
  const expires = opts.expireSignature ? nowSeconds - 300 : created + 300;
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
    developmentServiceHttpPrivateKey(sourceDid),
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
  // encoding.md §2: the detached-JWS protected header is fixed to
  // {"alg":"EdDSA"} (no kid/typ), and the signed binding object carries the
  // fixed context tag "ck-event-proof-v1" so an Event proof cannot be confused
  // with another proof family's binding.
  const protectedHeader = base64urlJsonCanonical({
    alg: "EdDSA",
  });
  const payload = base64urlJsonCanonical({
    actor_id: args.actorDid,
    context: "ck-event-proof-v1",
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


// FIXTURE ONLY — publicly derivable, MUST NOT be trusted by any non-test code.
// The private key is `sha256("soland:anchorer-ephemeral:" + serviceDid)`, so
// anyone who knows the serviceDid can recompute it. This intentionally mirrors
// soland's *dev* anchorer-ephemeral derivation (soland: federation.rs /
// state.rs) so the mock's federation signatures verify against a dev soland —
// production soland MUST reject keys produced by this convention.
//
// Exported as the single source of truth for the dev actor/anchorer-ephemeral
// key: circle-api.ts and webrtc.ts previously each re-derived this same
// `sha256("soland:anchorer-ephemeral:" + did)` PKCS#8 ed25519 key.
export function developmentServicePrivateKey(serviceDid: string) {
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

// FIXTURE ONLY: mirrors soland development_mode service HTTP signing keys.
function developmentServiceHttpPrivateKey(serviceDid: string) {
  const seed = createHash("sha256")
    .update("soland:notary-ephemeral:")
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
//
// AUTHORITATIVE SOURCE: this is a TS port of the SDK's canonical JSON
// (cokret-rust-sdk/crates/core/src/canonical.rs — RFC 8785 JCS, integer-only
// number profile, UTF-16 key sort, NFC strings). The harness runs on Node and
// cannot call the Rust SDK directly, so this reimplementation MUST stay
// byte-for-byte identical to the SDK; soland verifies the signatures this
// produces using that same SDK. Drift is guarded by the cross-language golden in
// e2e/fixtures/canonical-cross-check.json, asserted by both
// e2e/tests/conformance/canonical-cross-lang.spec.ts (this port) and
// cotest/src/conformance/canonical_cross_lang.rs (the SDK). Keep them in sync.
export function sha256CanonicalJson(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function canonicalJson(value: unknown): string {
  return canonicalJsonValue(value, "$");
}

/// Canonical (JCS key-ordered) JSON serialized to UTF-8 bytes. Authoritative
/// replacement for the per-helper `canonicalBytes` thin wrappers.
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
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
      throw new TypeError(
        `non-canonical JSON value at ${path}: ${typeof value}`,
      );
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

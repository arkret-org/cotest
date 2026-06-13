// Contact-graph protocol-face helpers (`/_cokret/self/contacts/*`,
// `/_cokret/self/direct-conversations/resolve`,
// `/_cokret/self/invite-receive-policy`, and the `consent_grant`-evidence
// invite-delivery path `/_cokret/peer/invites`).
//
// These target the NEW `/_cokret` contract with `requested_scopes:[...]`,
// distinct from the legacy `/_soland/self/contacts/request` + `scope` helper
// used by other specs (helpers/soland-api.ts + consent-grant.spec.ts). Do not
// route new contact-graph coverage through the legacy surface.
//
// Wire shapes mirror cokret-rust-sdk core::http + core::model::invite_addressing
// and soland src/routing/identity/account.rs + src/routing/invites.rs.

import { createHash } from "node:crypto";
import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { type SolandKey, solandBaseUrl, solandServiceDid } from "./env";
import {
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  expectJsonOk,
  signedEventEnvelope,
  submitPeerInviteDeliveryApi,
  submitSignedEventApi,
  typedId,
  type InviteDeliveryRequestBody,
} from "./soland-api";

// ── Contact list / request / respond wire types (subset we assert on). ──

export type ContactState =
  | "pending_outgoing"
  | "pending_incoming"
  | "accepted"
  | "rejected"
  | "tombstoned";

export type DirectConversationSummary = {
  realm_id: string;
  main_flow_id: string;
  binding_event_ref?: string;
  state: string;
};

export type ContactListRow = {
  peer: string;
  state: ContactState;
  request_event_ref?: string;
  response_event_ref?: string;
  tombstone_event_ref?: string;
  granted_by_me: string[];
  granted_to_me: string[];
  bidirectional_scopes: string[];
  effective_scopes?: string[];
  invite_consent_grant_ref?: string;
  direct_conversation?: DirectConversationSummary;
};

export type ContactRequestOutcome = {
  request_event_ref: string;
  requester_consent_refs: string[];
  state: ContactState;
};

export type ContactRespondOutcome = {
  response_event_ref: string;
  consent_grant_refs: string[];
  state: ContactState;
};

export type ContactTombstoneOutcome = {
  tombstone_event_ref: string;
  consent_revoke_refs: string[];
  state: ContactState;
  partial_revoke?: boolean;
};

export type DirectConversationResolveOutcome = {
  state: string;
  realm_id?: string;
  main_flow_id?: string;
  binding_event_ref?: string;
  created?: boolean;
};

export type InviteDeliveryOutcome = {
  status: "accepted" | "duplicate" | "deferred";
  disclosed_outcome?: "delivered" | "blocked" | "quarantined";
  received_at?: string;
  retry_after_ms?: number;
};

// ── Contact request / respond / list / tombstone. ──

export async function requestContactCokret(
  request: APIRequestContext,
  token: string,
  target: string,
  opts: {
    requestedScopes: string[];
    message?: string;
    idempotencyKey?: string;
    server?: SolandKey;
    recipientServiceDid?: string;
  },
): Promise<{ outcome: ContactRequestOutcome; response: APIResponse }> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_cokret/self/contacts/request`,
    {
      headers: authHeaders(token),
      data: {
        target,
        requested_scopes: opts.requestedScopes,
        ...(opts.message !== undefined ? { message: opts.message } : {}),
        ...(opts.idempotencyKey !== undefined
          ? { idempotency_key: opts.idempotencyKey }
          : {}),
        ...(opts.recipientServiceDid !== undefined
          ? { recipient_service_did: opts.recipientServiceDid }
          : {}),
      },
    },
  );
  const outcome = await expectJsonOk<ContactRequestOutcome>(
    response,
    `contact request -> ${target}`,
  );
  return { outcome, response };
}

export async function respondContactCokret(
  request: APIRequestContext,
  token: string,
  opts: {
    requestId: string;
    requester: string;
    action: "accept" | "reject";
    grantedScopes?: string[];
    server?: SolandKey;
    requesterServiceDid?: string;
  },
): Promise<ContactRespondOutcome> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_cokret/self/contacts/respond`,
    {
      headers: authHeaders(token),
      data: {
        request_id: opts.requestId,
        requester: opts.requester,
        action: opts.action,
        ...(opts.grantedScopes ? { granted_scopes: opts.grantedScopes } : {}),
        ...(opts.requesterServiceDid !== undefined
          ? { requester_service_did: opts.requesterServiceDid }
          : {}),
      },
    },
  );
  return await expectJsonOk<ContactRespondOutcome>(
    response,
    `contact respond ${opts.action} <- ${opts.requester}`,
  );
}

export async function listContactsCokret(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<ContactListRow[]> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/contacts`,
    { headers: authHeaders(token) },
  );
  const body = await expectJsonOk<{ contacts?: ContactListRow[] }>(
    response,
    "list contacts",
  );
  return body.contacts ?? [];
}

export async function contactRow(
  request: APIRequestContext,
  token: string,
  peer: string,
  opts: { server?: SolandKey } = {},
): Promise<ContactListRow | undefined> {
  const rows = await listContactsCokret(request, token, opts);
  return rows.find((row) => row.peer === peer);
}

export async function tombstoneContactCokret(
  request: APIRequestContext,
  token: string,
  contact: string,
  opts: {
    revokeScopes?: string[];
    fullPeerRevoke?: boolean;
    blockPeer?: boolean;
    // Cross-PS addressing (spec contact-and-direct-conversation.md §4.1): the
    // peer's home service DID so soland federates the `ck.contact.tombstoned`
    // fact to the peer's Principal Server via `ck.peer.contacts.command.submit`.
    peerServiceDid?: string;
    server?: SolandKey;
  } = {},
): Promise<ContactTombstoneOutcome> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_cokret/self/contacts/tombstone`,
    {
      headers: authHeaders(token),
      data: {
        contact,
        ...(opts.revokeScopes ? { revoke_scopes: opts.revokeScopes } : {}),
        ...(opts.fullPeerRevoke !== undefined
          ? { full_peer_revoke: opts.fullPeerRevoke }
          : {}),
        ...(opts.blockPeer !== undefined ? { block_peer: opts.blockPeer } : {}),
        ...(opts.peerServiceDid !== undefined
          ? { peer_service_did: opts.peerServiceDid }
          : {}),
      },
    },
  );
  return await expectJsonOk<ContactTombstoneOutcome>(
    response,
    `tombstone contact ${contact}`,
  );
}

export async function resolveDirectConversationCokret(
  request: APIRequestContext,
  token: string,
  peer: string,
  opts: { create?: boolean; server?: SolandKey } = {},
): Promise<DirectConversationResolveOutcome> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_cokret/self/direct-conversations/resolve`,
    {
      headers: authHeaders(token),
      data: {
        peer,
        ...(opts.create !== undefined ? { create: opts.create } : {}),
      },
    },
  );
  return await expectJsonOk<DirectConversationResolveOutcome>(
    response,
    `resolve direct conversation with ${peer}`,
  );
}

// ── Invite-receive policy (graded disclosure / blocked subjects). ──

export type InviteReceivePolicy = {
  schema: string;
  subject_id: string;
  allowed_introduction_kinds: string[];
  explicit_address_behavior: "drop" | "quarantine" | "notify";
  unknown_invites: "drop" | "quarantine";
  trusted_realm_ids?: string[];
  trusted_principal_services?: string[];
  blocked_principal_services?: string[];
  blocked_subjects?: string[];
  disclosure?: {
    high_trust?: "opaque" | "outcome";
    low_trust?: "opaque" | "outcome";
  };
};

export async function getInviteReceivePolicyCokret(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<InviteReceivePolicy> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/invite-receive-policy`,
    { headers: authHeaders(token) },
  );
  return await expectJsonOk<InviteReceivePolicy>(
    response,
    "get invite-receive-policy",
  );
}

export async function setInviteReceivePolicyCokret(
  request: APIRequestContext,
  token: string,
  policy: InviteReceivePolicy,
  opts: { server?: SolandKey } = {},
): Promise<InviteReceivePolicy> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_cokret/self/invite-receive-policy`,
    { headers: authHeaders(token), data: policy },
  );
  return await expectJsonOk<InviteReceivePolicy>(
    response,
    "set invite-receive-policy",
  );
}

// ── Realm-pull (consent_grant evidence) invite delivery. ──

export type IntroductionEvidence =
  | { kind: "consent_grant"; consent_grant_ref: string; consent_id?: string }
  | { kind: "explicit_address" }
  | { kind: "same_principal_server" };

// Build a `ck.invite.create` invite event whose payload satisfies soland's
// invite-delivery consistency checks (src/routing/invites.rs
// validate_invite_delivery_consistency + projection required fields):
//   - kind == ck.invite.create
//   - payload.invitee == invite_address.subject_id
//   - payload.invite_delivery_target.recipient_service_did == recipient svc
//   - payload.introduction_evidence_digest == sha256(canonical_json(evidence))
//   - payload carries invite_id + expires_at (schema-required for invite.create)
export function buildInviteCreateEvent(args: {
  inviterDid: string;
  realmId: string;
  inviteeDid: string;
  recipientServiceDid: string;
  evidence: IntroductionEvidence;
  inviteId?: string;
  expiresAt?: string;
}): { event: Record<string, unknown>; inviteId: string } {
  const inviteId = args.inviteId ?? typedId("invite");
  const expiresAt =
    args.expiresAt ??
    canonicalTimestamp(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));
  const evidenceDigest = `sha256:${createHash("sha256")
    .update(canonicalJson(args.evidence))
    .digest("hex")}`;
  const event = signedEventEnvelope({
    actorDid: args.inviterDid,
    realmId: args.realmId,
    kind: "ck.invite.create",
    schemaId: "ck.schema.invite.v1",
    payload: {
      invite_id: inviteId,
      invitee: args.inviteeDid,
      invite_delivery_target: {
        recipient_service_did: args.recipientServiceDid,
        recipient_service_type: "principal_server",
      },
      introduction_evidence_digest: evidenceDigest,
      expires_at: expiresAt,
    },
  });
  return { event, inviteId };
}

// Privately deliver a consent_grant-evidence invite to the subject's principal
// server via `POST /_cokret/peer/invites`. Returns the graded-disclosure
// outcome. `origin` is the inviter's service DID (signs the federation push).
export async function deliverInviteWithConsentGrant(
  request: APIRequestContext,
  args: {
    inviterDid: string;
    realmId: string;
    inviteeDid: string;
    consentGrantRef: string;
    originServer: SolandKey;
    recipientServer: SolandKey;
    idempotencyKey?: string;
  },
): Promise<{ outcome: InviteDeliveryOutcome; inviteId: string }> {
  const recipientServiceDid = solandServiceDid(args.recipientServer);
  const evidence: IntroductionEvidence = {
    kind: "consent_grant",
    consent_grant_ref: args.consentGrantRef,
  };
  const { event, inviteId } = buildInviteCreateEvent({
    inviterDid: args.inviterDid,
    realmId: args.realmId,
    inviteeDid: args.inviteeDid,
    recipientServiceDid,
    evidence,
  });
  const body: InviteDeliveryRequestBody = {
    schema: "ck.schema.invite_delivery_request.v1",
    invite_event: event,
    invite_address: {
      subject_id: args.inviteeDid,
      recipient_service_did: recipientServiceDid,
      recipient_service_type: "principal_server",
    },
    introduction_evidence: evidence,
    idempotency_key:
      args.idempotencyKey ?? `cotest-contact-graph:${inviteId}`,
  };
  const outcome = (await submitPeerInviteDeliveryApi(request, body, {
    origin: solandServiceDid(args.originServer),
    destination: recipientServiceDid,
    server: args.recipientServer,
  })) as unknown as InviteDeliveryOutcome;
  return { outcome, inviteId };
}

// Deliver an explicit-address (low-trust) invite — no consent_grant evidence.
// Used for the stranger / blocked scenarios.
export async function deliverInviteExplicitAddress(
  request: APIRequestContext,
  args: {
    inviterDid: string;
    realmId: string;
    inviteeDid: string;
    originServer: SolandKey;
    recipientServer: SolandKey;
    idempotencyKey?: string;
  },
): Promise<{ outcome: InviteDeliveryOutcome; inviteId: string }> {
  const recipientServiceDid = solandServiceDid(args.recipientServer);
  const evidence: IntroductionEvidence = { kind: "explicit_address" };
  const { event, inviteId } = buildInviteCreateEvent({
    inviterDid: args.inviterDid,
    realmId: args.realmId,
    inviteeDid: args.inviteeDid,
    recipientServiceDid,
    evidence,
  });
  const body: InviteDeliveryRequestBody = {
    schema: "ck.schema.invite_delivery_request.v1",
    invite_event: event,
    invite_address: {
      subject_id: args.inviteeDid,
      recipient_service_did: recipientServiceDid,
      recipient_service_type: "principal_server",
    },
    introduction_evidence: evidence,
    idempotency_key:
      args.idempotencyKey ?? `cotest-contact-graph-explicit:${inviteId}`,
  };
  const outcome = (await submitPeerInviteDeliveryApi(request, body, {
    origin: solandServiceDid(args.originServer),
    destination: recipientServiceDid,
    server: args.recipientServer,
  })) as unknown as InviteDeliveryOutcome;
  return { outcome, inviteId };
}

// List the authenticated actor's pending invites with the canonical wire
// shape. The authz endpoint serializes the SDK `Invite` whose id field is
// `id` (NOT `invite_id`); the shared soland-api.ts `listInvitesApi` mistypes
// it, so contact-graph coverage reads invites through here.
export type AuthzInvite = {
  id: string;
  realm_id: string;
  invitee?: string;
  state?: string;
};

export async function listAuthzInvitesCokret(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<AuthzInvite[]> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/authz/invites`,
    { headers: authHeaders(token) },
  );
  const body = await expectJsonOk<{ invites?: AuthzInvite[] }>(
    response,
    "list authz invites",
  );
  return body.invites ?? [];
}

// Submit `ck.invite.accept` as the invitee to join the realm.
export async function acceptInviteCokret(
  request: APIRequestContext,
  token: string,
  args: { accepterDid: string; realmId: string; inviteId: string; server?: SolandKey },
) {
  return await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: args.accepterDid,
      realmId: args.realmId,
      kind: "ck.invite.accept",
      payload: {
        invitee: args.accepterDid,
        invite_id: args.inviteId,
      },
    }),
    { server: args.server, context: `accept invite ${args.inviteId}` },
  );
}

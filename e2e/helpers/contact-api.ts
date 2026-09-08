// Contact-graph protocol-face helpers (`/_arkret/self/contacts/*`,
// `/_arkret/self/direct-conversations/resolve`,
// `/_arkret/self/invite-receive-policy`, and the private invite-delivery path
// `/_arkret/self/invites/dispatch`, which falls back to `/_arkret/peer/invites`
// only for the cross-server receive-side scenarios).
//
// These target the `/_arkret` contract with `requested_scopes:[...]`, distinct
// from the `/_soland/self/contacts/request` + `scope` helper used by other
// specs (helpers/soland-api.ts + consent-grant.spec.ts). Do not route new
// contact-graph coverage through the `/_soland` surface.
//
// Wire shapes mirror arkret-rust-sdk core::http + core::model::invite_addressing
// and soland src/routing/identity/account.rs + src/routing/invites.rs.

import { createHash } from "node:crypto";
import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { type SolandKey, solandBaseUrl, solandServiceId } from "./env";
import {
  alignSignedEventToActorFrontierApi,
  accountActorId,
  eventPrincipalId,
  acceptInviteApi,
  authHeaders,
  canonicalJson,
  canonicalServiceResolution,
  canonicalTimestamp,
  currentActorIdApi,
  dispatchSelfInviteApi,
  selfInviteDispatchBody,
  expectJsonOk,
  principalControlRealmForId,
  readRealmSealBasis,
  registeredEventSigningSeedB64url,
  registeredEventVerificationMethod,
  retypeEventDerivedId,
  refreshEventEnvelopeProof,
  signWithRegisteredEventSigner,
  signedEventEnvelope,
  submitPeerInviteDeliveryApi,
  submitPrincipalSuccessorSealApi,
  submitSignedEventApi,
  cotestWire,
  type InviteDeliveryOutcomeView,
  type InviteDeliveryRequestBodyBodyBody,
  uuidV7,
} from "./soland-api";
import type { JointUser } from "./users";
import type { ContactPeer, InviteObject } from "./generated/spec-wire-objects";

// ── Contact list / request / respond wire types (subset we assert on). ──
type ContactState =
  | "pending_outgoing"
  | "pending_incoming"
  | "accepted"
  | "rejected"
  | "tombstoned";
type DirectConversationSummary = {
  realm_id: string;
  main_strand_id: string;
  binding_event_ref?: string;
  state: string;
};
type ContactAgentProjection = {
  actor_id: ReturnType<typeof accountActorId> | {
    kind: "service";
    service_id: string;
  };
  controller_account_id: { principal_id: string; station_id: string };
  display_name?: string;
  agent_slug?: string;
  direct_conversation?: DirectConversationSummary;
};

export type ContactListRow = {
  peer: string | Record<string, unknown>;
  peerIdentity: ContactPeer;
  state: ContactState;
  request_event_ref?: string;
  response_event_ref?: string;
  next_prepare_input?: {
    contact_round_id: string;
    version: number;
    predecessor_event_ref: string;
  };
  tombstone_event_ref?: string;
  granted_by_me: string[];
  granted_to_me: string[];
  bidirectional_scopes: string[];
  effective_scopes?: string[];
  direct_conversation?: DirectConversationSummary;
  agents?: ContactAgentProjection[];
  contact_agents?: ContactAgentProjection[];
  request_receipt?: Record<string, unknown>;
};
type ContactRequestOutcome = {
  request_event_ref: string;
  request_acceptance_receipt: Record<string, unknown>;
  state: ContactState;
};
type ContactRespondOutcome = {
  response_event_ref: string;
  acceptance_receipt: Record<string, unknown>;
  state: ContactState;
};
type ContactTombstoneOutcome = {
  tombstone_event_ref: string;
  consent_revoke_refs: string[];
  state: ContactState;
  partial_revoke?: boolean;
};

export type DirectConversationResolveOutcome = {
  state:
    | "creation_required"
    | "creation_blocked"
    | "awaiting_founder"
    | "provisional"
    | "found"
    | "suspended"
    | "temporarily_unavailable";
  next_founding_input?: {
    founding_authority_evidence: Record<string, unknown>;
  };
  coordinates?: Record<string, unknown>;
  blockers?: Array<Record<string, unknown>>;
  send_blockers?: Array<Record<string, unknown>>;
  group_state_ref?: string;
  retry_after_ms?: number;
};

// invite-addressing.md §5.1: `disclosed_outcome` is a closed two-value enum
// (`delivered | blocked`). Quarantine MUST NOT be disclosed at all — it is
// reported as `status="deferred"` with no `disclosed_outcome`.
type InviteDeliveryOutcome = InviteDeliveryOutcomeView;
type InviteConsentGrant = {
  consentId: string;
  eventRef: string;
  dot: string;
};

export async function grantInviteConsentArkret(
  request: APIRequestContext,
  token: string,
  holder: JointUser,
  peerId: string,
  opts: { server?: SolandKey } = {},
): Promise<InviteConsentGrant> {
  const consentId = `ak:consent:${uuidV7()}`;
  const peer = {
    kind: "actor",
    actor_id: accountActorId(peerId, opts.server),
  };
  const envelope = signedEventEnvelope({
    actorId: holder.id,
    realmId: principalControlRealmForId(holder.id),
    kind: "ak.consent.grant",
    server: opts.server,
    payload: {
      consent_id: consentId,
      peer,
      consent_scope: "invite",
      expires_at: canonicalTimestamp(
        new Date(Date.now() + 24 * 60 * 60 * 1000),
      ),
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `grant invite consent to ${peerId}`,
  });
  await submitPrincipalSuccessorSealApi(
    request,
    token,
    holder.id,
    envelope,
    opts,
  );
  const eventRef = String(envelope.event_id);
  const dot = `${eventRef}:0`;
  await expect
    .poll(
      async () => {
        const cellUrl =
          `${solandBaseUrl(opts.server)}/_arkret/self/consent/cell` +
          `?peer=${encodeURIComponent(canonicalJson(peer))}&consent_scope=invite`;
        const response = await request.get(cellUrl, {
          headers: authHeaders(token, "GET", cellUrl),
        });
        if (!response.ok()) return false;
        const body = (await response.json()) as {
          state?: string;
          active_grant_dots?: string[];
        };
        return body.state === "active" && body.active_grant_dots?.includes(dot);
      },
      { timeout: 30_000, intervals: [250, 500, 1_000, 2_000] },
    )
    .toBe(true);
  return { consentId, eventRef, dot };
}

// ── Contact request / respond / list / tombstone. ──

export async function requestContactArkret(
  request: APIRequestContext,
  token: string,
  target: string,
  opts: {
    requestedScopes: string[];
    message?: string;
    idempotencyKey?: string;
    server?: SolandKey;
    recipientServiceId?: string;
    /**
     * Introduction evidence is required for a cross-Station
     * request.  The recipient's default policy quarantines
     * `explicit_address`, so callers exercising a real federation delivery
     * should pass a locator (or another allow-listed evidence kind).
     */
    introductionEvidence?: Record<string, unknown>;
  },
): Promise<{ outcome: ContactRequestOutcome; response: APIResponse }> {
  const nonce = uuidV7();
  const operationId = `ak:operation:contact.request.${nonce}`;
  const idempotencyKey = opts.idempotencyKey ?? nonce;
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/contacts/request`;
  const prepareBody = {
    phase: "prepare",
    operation_id: operationId,
    idempotency_key: idempotencyKey,
    peer: { kind: "human", account_id: accountActorId(target, opts.server, opts.recipientServiceId).account_id },
    granted_to_peer_scopes: opts.requestedScopes,
    introduction_evidence: opts.introductionEvidence ?? {
      kind: "same_station",
    },
    ...(opts.message !== undefined ? { message: opts.message } : {}),
  };
  const preparedResponse = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson(prepareBody),
  });
  const prepared = await expectJsonOk<{
    operation_id: string;
    reservation_handle: string;
    event_draft: { unsigned_event_bytes: string };
  }>(preparedResponse, `prepare contact request -> ${target}`);
  const signedEvent = JSON.parse(
    Buffer.from(
      prepared.event_draft.unsigned_event_bytes,
      "base64url",
    ).toString("utf8"),
  ) as Record<string, unknown>;
  refreshEventEnvelopeProof(signedEvent);
  const response = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({
      phase: "commit",
      operation_id: operationId,
      idempotency_key: idempotencyKey,
      reservation_handle: prepared.reservation_handle,
      signed_event: signedEvent,
    }),
  });
  const accepted = await expectJsonOk<{
    status: "accepted" | "failed";
    reason?: string;
    request_acceptance_receipt?: Record<string, unknown> & {
      core: { request_event_ref: string };
    };
  }>(response, `contact request -> ${target}`);
  if (accepted.status !== "accepted" || !accepted.request_acceptance_receipt) {
    throw new Error(
      `contact request -> ${target} was not accepted: ${JSON.stringify(accepted)}`,
    );
  }
  await submitPrincipalSuccessorSealApi(
    request,
    token,
    eventPrincipalId(signedEvent),
    signedEvent,
    { server: opts.server },
  );
  const outcome: ContactRequestOutcome = {
    request_event_ref:
      accepted.request_acceptance_receipt.core.request_event_ref,
    request_acceptance_receipt: accepted.request_acceptance_receipt,
    state: "pending_outgoing",
  };
  return { outcome, response };
}

/**
 * Resolve a short-lived Principal Locator from a server's public locator
 * endpoint.  The resulting object is suitable for
 * `requestContactArkret(..., { introductionEvidence: { kind: "locator_ref",
 * principal_locator: locator } })` and satisfies the recipient policy's
 * allow-listed `locator_ref` evidence requirement.
 */
export async function resolvePrincipalLocator(
  request: APIRequestContext,
  subjectId: string,
  server: SolandKey,
  sessionToken: string,
): Promise<Record<string, unknown>> {
  const issueUrl = `${solandBaseUrl(server)}/_arkret/self/invite-locators`;
  const issue = await request.post(issueUrl, {
    headers: {
      ...authHeaders(sessionToken, "POST", issueUrl),
      "content-type": "application/json",
    },
    data: canonicalJson({ ttl_seconds: 900 }),
  });
  const issued = await expectJsonOk<{
    locator_token: string;
  }>(issue, `issue principal locator for ${subjectId}`);
  const response = await request.post(
    `${solandBaseUrl(server)}/_arkret/open/invite-locators/resolve`,
    {
      headers: { "content-type": "application/json" },
      data: canonicalJson({ locator_token: issued.locator_token }),
    },
  );
  const locator = await expectJsonOk<Record<string, unknown>>(
    response,
    `resolve principal locator for ${subjectId}`,
  );
  expect(locator.account_id).toEqual(accountActorId(subjectId, server).account_id);
  return locator;
}

export async function respondContactArkret(
  request: APIRequestContext,
  token: string,
  opts: {
    requestId: string;
    requesterId: string;
    action: "accept" | "reject";
    grantedScopes?: string[];
    server?: SolandKey;
    requesterServiceId?: string;
  },
): Promise<ContactRespondOutcome> {
  const rows = await listContactsArkret(request, token, {
    server: opts.server,
  });
  const matches = rows.filter(candidate => candidate.peer === opts.requesterId &&
    (!opts.requesterServiceId || (candidate.peerIdentity.kind === "human" &&
      candidate.peerIdentity.account_id.station_id === opts.requesterServiceId)));
  if (matches.length > 1) throw new Error("Contact response requires an exact AccountId");
  const row = matches[0];
  if (!row?.request_receipt) {
    throw new Error(`contact ${opts.requesterId} exposes no request_receipt`);
  }
  const nonce = uuidV7();
  const operationId = `ak:operation:contact.${opts.action}.${nonce}`;
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/contacts/${opts.action === "accept" ? "respond" : "reject"}`;
  const prepareBody = {
    phase: "prepare",
    operation_id: operationId,
    idempotency_key: nonce,
    request_receipt: row.request_receipt,
    action: opts.action,
    ...(opts.action === "accept"
      ? { granted_to_peer_scopes: opts.grantedScopes ?? [] }
      : {}),
  };
  const preparedResponse = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson(prepareBody),
  });
  const prepared = await expectJsonOk<{
    reservation_handle: string;
    event_draft: { unsigned_event_bytes: string };
  }>(preparedResponse, `prepare contact ${opts.action} <- ${opts.requesterId}`);
  const signedEvent = JSON.parse(
    Buffer.from(
      prepared.event_draft.unsigned_event_bytes,
      "base64url",
    ).toString("utf8"),
  ) as Record<string, unknown>;
  refreshEventEnvelopeProof(signedEvent);
  const response = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({
      phase: "commit",
      operation_id: operationId,
      idempotency_key: nonce,
      reservation_handle: prepared.reservation_handle,
      signed_event: signedEvent,
    }),
  });
  const accepted = await expectJsonOk<Record<string, unknown>>(
    response,
    `contact respond ${opts.action} <- ${opts.requesterId}`,
  );
  await submitPrincipalSuccessorSealApi(
    request,
    token,
    eventPrincipalId(signedEvent),
    signedEvent,
    { server: opts.server },
  );
  const receipt =
    (accepted.normal_response_acceptance_receipt as
      Record<string, unknown> | undefined) ??
    (accepted.reject_acceptance_receipt as Record<string, unknown> | undefined);
  const core = receipt?.core as Record<string, unknown> | undefined;
  return {
    response_event_ref: String(
      core?.response_event_ref ??
        core?.reject_event_ref ??
        signedEvent.event_id,
    ),
    acceptance_receipt: receipt ?? {},
    state: opts.action === "accept" ? "accepted" : "rejected",
  };
}
async function listContactsArkret(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<ContactListRow[]> {
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/contacts`;
  const response = await request.get(url, {
    headers: authHeaders(token, "GET", url),
  });
  const body = await expectJsonOk<{ contacts?: ContactListRow[] }>(
    response,
    "list contacts",
  );
  return (body.contacts ?? []).map((row) => {
    const wire = row as unknown as Record<string, unknown>;
    const peer = wire.peer as ContactPeer;
    const peerId =
      peer?.kind === "human" && typeof peer.account_id?.principal_id === "string"
        ? peer.account_id.principal_id
        : peer?.kind === "agent" && peer.actor_id
          ? eventPrincipalId({ actor_id: peer.actor_id })
          : undefined;
    if (!peerId) {
      throw new Error(`contact row has an invalid canonical peer: ${JSON.stringify(wire.peer)}`);
    }
    return {
      ...row,
      peer: peerId,
      peerIdentity: peer,
      granted_by_me:
        (wire.granted_to_peer_scopes as string[] | undefined) ?? [],
      granted_to_me:
        (wire.granted_by_peer_scopes as string[] | undefined) ?? [],
    };
  });
}

export async function contactRow(
  request: APIRequestContext,
  token: string,
  peer: string,
  opts: { server?: SolandKey } = {},
): Promise<ContactListRow | undefined> {
  const rows = await listContactsArkret(request, token, opts);
  const matches = rows.filter((row) => row.peer === peer);
  if (matches.length > 1) throw new Error("contact principal maps to multiple Station accounts; select a complete peer identity");
  return matches[0];
}

export async function tombstoneContactArkret(
  request: APIRequestContext,
  token: string,
  contact: string,
  opts: {
    revokeScopes?: string[];
    fullPeerRevoke?: boolean;
    blockPeer?: boolean;
    // Cross-PS addressing (spec contact-and-direct-conversation.md §4.1): the
    // peer's home service DID so soland federates the `ak.contact.tombstone`
    // fact to the peer's Station via `ak.peer.contacts.command.submit.v1`.
    peerServiceId?: string;
    server?: SolandKey;
  } = {},
): Promise<ContactTombstoneOutcome> {
  const row = await contactRow(request, token, contact, {
    server: opts.server,
  });
  if (!row) {
    throw new Error(`contact ${contact} is unavailable for tombstone`);
  }
  const next = row.next_prepare_input;
  const contactRoundId = String(next?.contact_round_id ?? "");
  const version = Number(next?.version ?? 0);
  const predecessorEventRef = String(next?.predecessor_event_ref ?? "");
  if (
    !contactRoundId ||
    version < 2 ||
    !predecessorEventRef.startsWith("ak:event:")
  ) {
    throw new Error(`contact ${contact} omits its tombstone lineage`);
  }
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/contacts/tombstone`;
  const nonce = uuidV7();
  const operationId = `ak:operation:contact.tombstone.${nonce}`;
  const prepare = await expectJsonOk<{
    reservation_handle: string;
    event_draft: { unsigned_event_bytes: string };
  }>(
    await request.post(url, {
      headers: {
        ...authHeaders(token, "POST", url),
        "content-type": "application/json",
      },
      data: canonicalJson({
        phase: "prepare",
        operation_id: operationId,
        idempotency_key: nonce,
        peer: row.peerIdentity,
        contact_round_id: contactRoundId,
        version,
        predecessor_event_ref: predecessorEventRef,
        block_peer: opts.blockPeer ?? false,
      }),
    }),
    `prepare tombstone contact ${contact}`,
  );
  const signedEvent = JSON.parse(
    Buffer.from(prepare.event_draft.unsigned_event_bytes, "base64url").toString(
      "utf8",
    ),
  ) as Record<string, unknown>;
  refreshEventEnvelopeProof(signedEvent);
  const response = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({
      phase: "commit",
      operation_id: operationId,
      idempotency_key: nonce,
      reservation_handle: prepare.reservation_handle,
      signed_event: signedEvent,
    }),
  });
  if (response.ok()) {
    await submitPrincipalSuccessorSealApi(
      request,
      token,
      eventPrincipalId(signedEvent),
      signedEvent,
      { server: opts.server },
    );
  }
  const accepted = await expectJsonOk<ContactTombstoneOutcome>(
    response,
    `tombstone contact ${contact}`,
  );
  return { ...accepted, state: "tombstoned" };
}

async function uploadDirectConversationKeyPackage(
  request: APIRequestContext,
  token: string,
  user: JointUser,
  opts: { server?: SolandKey } = {},
): Promise<void> {
  const signingSeedB64url = registeredEventSigningSeedB64url(user.id);
  if (!signingSeedB64url) {
    throw new Error(
      `no accepted device signing seed registered for ${user.id}`,
    );
  }
  const keyPackages = [
    cotestWire<Record<string, unknown>>("mls-keypackage-upload-entry", {
      principal_id: user.id,
      device_id: user.deviceId,
      signing_seed_b64url: signingSeedB64url,
    }),
  ];
  const unsigned = {
    principal_id: user.id,
    device_id: user.deviceId,
    keypackages: keyPackages,
  };
  const signingInput = `ak.self.keys.keypackages.upload.create.v1\n${canonicalJson(unsigned)}`;
  const verificationMethod = registeredEventVerificationMethod(
    user.id,
    user.deviceId,
  );
  if (!verificationMethod) {
    throw new Error(
      `no accepted device verification method registered for ${user.id}`,
    );
  }
  const signature = signWithRegisteredEventSigner(
    user.id,
    verificationMethod,
    signingInput,
  );
  if (!signature) {
    throw new Error(`no accepted device signer registered for ${user.id}`);
  }
  const endpointSignature = {
    kid: verificationMethod,
    signature_algorithm: "Ed25519",
    sig: signature,
  };
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/keys/keypackages/upload`;
  const response = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({
      ...unsigned,
      endpoint_signature: endpointSignature,
    }),
  });
  const body = await expectJsonOk<{
    accepted: number;
    rejections?: Array<Record<string, unknown>>;
  }>(response, `upload direct-conversation KeyPackage ${user.id}`);
  expect(body.accepted).toBe(1);
  expect(body.rejections ?? []).toEqual([]);
}

// ── Invite-receive policy (graded disclosure / blocked subjects). ──

export type InviteReceivePolicy = {
  schema: string;
  account_id: ReturnType<typeof accountActorId>["account_id"];
  holder_allowed_introduction_kinds: string[];
  explicit_address_behavior: "drop" | "quarantine" | "notify";
  unknown_invites: "drop" | "quarantine";
  trusted_realm_ids?: string[];
  trusted_source_ids?: string[];
  denied_source_ids?: string[];
  denied_actor_ids?: Array<ReturnType<typeof accountActorId>>;
  disclosure?: {
    high_trust?: "opaque" | "outcome";
    low_trust?: "opaque" | "outcome";
  };
};

// ── Realm-pull (consent_grant evidence) invite delivery. ──

export type IntroductionEvidence =
  | { kind: "consent_grant"; consent_grant_ref: string; consent_id?: string }
  | { kind: "explicit_address" };

// Build a `ak.invite.create` invite event whose payload satisfies soland's
// invite-delivery consistency checks (src/routing/invites.rs
// validate_invite_delivery_consistency + projection required fields):
//   - kind == ak.invite.create
//   - payload.invitee_id == invite_address.account_id.principal_id
//   - payload.invite_delivery_target.account_id.station_id == recipient svc
//   - payload.introduction_evidence_digest == sha256(canonical_json(evidence))
//   - the invite id is retyped from the create Event id and omitted from payload
function buildInviteCreateEvent(args: {
  inviterId: string;
  realmId: string;
  inviteeId: string;
  recipientServiceId: string;
  recipientServer?: SolandKey;
  evidence: IntroductionEvidence;
  inviteId?: string;
  expiresAt?: string;
}): { event: Record<string, unknown>; inviteId: string } {
  const expiresAt =
    args.expiresAt ??
    canonicalTimestamp(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));
  const evidenceDigest = `sha256:${createHash("sha256")
    .update(canonicalJson(args.evidence))
    .digest("hex")}`;
  const event = signedEventEnvelope({
    actorId: args.inviterId,
    realmId: args.realmId,
    kind: "ak.invite.create",
    schemaId: "ak.schema.invite.v1",
    payload: {
      invitee_account_id: {
          principal_id: args.inviteeId,
          station_id: args.recipientServiceId,
      },
      introduction_evidence_digest: evidenceDigest,
      expires_at: expiresAt,
    },
  });
  const inviteId = retypeEventDerivedId(String(event.event_id), "invite");
  if (args.inviteId !== undefined && args.inviteId !== inviteId) {
    throw new Error(
      "invite id override must equal the create Event-derived id",
    );
  }
  return { event, inviteId };
}

// Persist the durable `ak.invite.create` fact on the inviter's Station
// and then start private delivery for it.
//
// invite-addressing.md §7 splits the two hops by actor: an authenticated CLIENT
// only ever calls `ak.self.invites.command.dispatch.v1` on its own Principal
// Server, and only a Station may speak `ak.peer.invites.command.submit.v1`
// (§7 step 1 binds that surface to verified service-to-service authentication).
// Same-service delivery therefore goes through dispatch, whose local branch
// reruns the very same §7 verification from step 4 and yields the same graded
// disclosure. The cross-server variant still posts to the peer surface: those
// scenarios deliberately exercise the RECEIVING server, standing in for an
// inviter Station whose durable outbox is out of this helper's scope.
async function deliverInvite(
  request: APIRequestContext,
  args: {
    inviterId: string;
    inviterToken: string;
    realmId: string;
    inviteeId: string;
    evidence: IntroductionEvidence;
    originServer: SolandKey;
    recipientServer: SolandKey;
    idempotencyKey?: string;
    idempotencyKeyPrefix: string;
    context: string;
  },
): Promise<{
  outcome: InviteDeliveryOutcome;
  inviteId: string;
  sealBasis: Record<string, unknown>;
}> {
  const recipientServiceId = solandServiceId(args.recipientServer);
  const { event } = buildInviteCreateEvent({
    inviterId: args.inviterId,
    realmId: args.realmId,
    inviteeId: args.inviteeId,
    recipientServiceId,
    recipientServer: args.recipientServer,
    evidence: args.evidence,
  });
  await alignSignedEventToActorFrontierApi(request, args.inviterToken, event, {
    server: args.originServer,
  });
  event.seal_basis = await readRealmSealBasis(
    request,
    args.inviterToken,
    args.realmId,
    args.originServer,
  );
  refreshEventEnvelopeProof(event);
  const sealBasis = event.seal_basis as Record<string, unknown>;
  await submitSignedEventApi(request, args.inviterToken, event, {
    server: args.originServer,
    context: args.context,
  });
  const acceptedEventId = String(event.event_id);
  const inviteId = retypeEventDerivedId(acceptedEventId, "invite");
  const inviteAddress = {
    account_id: {
      principal_id: args.inviteeId,
      station_id: recipientServiceId,
    },
    service_resolution: canonicalServiceResolution(args.recipientServer),
  };
  const idempotencyKey =
    args.idempotencyKey ?? `${args.idempotencyKeyPrefix}:${inviteId}`;

  if (args.originServer === args.recipientServer) {
    const body = selfInviteDispatchBody({
      eventId: acceptedEventId,
      inviteAddress,
      evidence: args.evidence,
      idempotencyKey,
    });
    return {
      outcome: await dispatchSelfInviteApi(request, args.inviterToken, body, {
        server: args.originServer,
      }),
      inviteId,
      sealBasis,
    };
  }

  const body: InviteDeliveryRequestBodyBodyBody = {
    schema: "ak.schema.invite_delivery_request.v1",
    // `signedEventEnvelope` still returns an untyped record — wiring the Event
    // envelope itself to the generated type is the remaining B3 item.
    invite_event: event as InviteDeliveryRequestBodyBodyBody["invite_event"],
    invite_address: inviteAddress,
    introduction_evidence: args.evidence,
    // §7 step 4: the receiver cannot resolve the invite Realm's authority
    // closure itself, so it travels with the request — one bundle per
    // `seal_basis` leaf, read from the inviter side's own accepted Seals.
    idempotency_key: idempotencyKey,
  };
  return {
    outcome: await submitPeerInviteDeliveryApi(request, body, {
      origin: solandServiceId(args.originServer),
      destination: recipientServiceId,
      server: args.recipientServer,
    }),
    inviteId,
    sealBasis,
  };
}

// High-trust `consent_grant` pull: the invitee already issued the inviter an
// active `invite`/`any` grant (§2), so §5.1 lets the outcome be disclosed.
export async function deliverInviteWithConsentGrant(
  request: APIRequestContext,
  args: {
    inviterId: string;
    inviterToken: string;
    realmId: string;
    inviteeId: string;
    consentGrantRef: string;
    originServer: SolandKey;
    recipientServer: SolandKey;
    idempotencyKey?: string;
  },
): Promise<{
  outcome: InviteDeliveryOutcome;
  inviteId: string;
  sealBasis: Record<string, unknown>;
}> {
  return await deliverInvite(request, {
    ...args,
    evidence: {
      kind: "consent_grant",
      consent_grant_ref: args.consentGrantRef,
    },
    idempotencyKeyPrefix: "cotest-contact-graph",
    context: "persist shared consent-grant invite",
  });
}

// List the authenticated actor's pending invites with the canonical wire
// shape. The authz endpoint serializes the SDK `Invite` whose id field is
// `id` (NOT `invite_id`).
type AuthzInvite = InviteObject;

export async function listAuthzInvitesArkret(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<AuthzInvite[]> {
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
  const body = await expectJsonOk<{ invites?: AuthzInvite[] }>(
    response,
    "list authz invites",
  );
  return body.invites ?? [];
}

// Count invites matching (realm, invitee) WITHOUT handing the invite objects to
// a matcher.
//
// R95: `expect(invites.find(...)).toBeFalsy()` makes Playwright serialize the
// whole received object into the failure diff, which lands in
// `error-context.md` and `playwright.stdout.log`. Invite rows carry locator
// secrets, so a failing non-disclosure assertion was itself leaking the secret
// it asserts about. Assert on this count instead: the matcher only ever sees a
// number, and the label carries the diagnosis. Use `expectInviteFields` when a
// test genuinely needs to inspect an invite.
export function countInvitesFor(
  invites: AuthzInvite[],
  realmId: string,
  inviteeId: string,
): number {
  return invites.filter(
    (invite) => invite.realm_id === realmId && invite.invitee_account_id?.principal_id === inviteeId,
  ).length;
}

// Submit `ak.invite.accept` as the invitee to join the realm.
export async function acceptInviteArkret(
  request: APIRequestContext,
  token: string,
  args: {
    accepterId: string;
    realmId: string;
    inviteId: string;
    server?: SolandKey;
    sealBasis?: Record<string, unknown>;
  },
) {
  return await acceptInviteApi(
    request,
    token,
    args.accepterId,
    args.realmId,
    args.inviteId,
    {
      server: args.server,
      sealBasis: args.sealBasis,
    },
  );
}

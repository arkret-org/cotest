// Standard Contact, Direct Conversation, and invite protocol helpers.
// Contact prepare uses the exact peer and request Event reference from the
// Station's pending projection. The Station resolves its retained acceptance
// evidence; clients sign the returned draft with their registered Event signer.

import { createHash } from "node:crypto";
import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { type ColandKey, colandBaseUrl, colandServiceId } from "./env";
import {
  accountActorId,
  eventPrincipalId,
  acceptInviteApi,
  authHeaders,
  canonicalJson,
  canonicalServiceResolution,
  canonicalTimestamp,
  currentActorIdApi,
  originalHumanSignerFactApi,
  dispatchSelfInviteApi,
  selfInviteDispatchBody,
  expectJsonOk,
  principalControlRealmForId,
  principalControlRootAuthorizationRefForId,
  registeredEventSigningSeedB64url,
  registeredEventVerificationMethod,
  retypeEventDerivedId,
  refreshEventEnvelopeProof,
  signWithRegisteredEventSigner,
  signedEventEnvelope,
  sha256CanonicalJson,
  submitPeerInviteDeliveryApi,
  submitSignedEventApi,
  cotestWire,
  type InviteDeliveryResponseBody,
  type InviteDeliveryRequestBody,
  uuidV7,
  wireErrCode,
} from "./coland-api";
import type { JointUser } from "./users";
import { replaceConsentScopeApi } from "./consent-api";
import type {
  ContactPeer, ContactView, ContactOperationResponseBody,
  ContactRequestBody, ContactRespondRequestBody, ContactRejectRequestBody,
  ContactTombstoneRequestBody, InviteObject, KeyPackagesUploadResponseBody,
} from "./generated/spec-wire-objects";

// The extra names below are harness projections, derived from formal wire DTOs.
type ContactState = ContactView["state"];
type ContactRequestPrepare = Extract<ContactRequestBody, { phase: "prepare" }>;
type ContactScope = ContactView["granted_to_peer_scopes"][number];
type ContactTestProjection = Omit<ContactView, "peer"> & {
  peer: string;
  peerIdentity: ContactPeer;
  granted_by_me: ContactScope[];
  granted_to_me: ContactScope[];
};
type ContactRequestSummary = {
  request_event_ref: string;
  request_acceptance_receipt: Extract<ContactOperationResponseBody, { status: "accepted"; operation_kind: "request" }>["request_acceptance_receipt"];
  state: ContactState;
};
type ContactResponseSummary = {
  response_event_ref: string;
  acceptance_receipt: Extract<ContactOperationResponseBody, { status: "accepted"; operation_kind: "response" }>["normal_response_acceptance_receipt"]
    | Extract<ContactOperationResponseBody, { status: "accepted"; operation_kind: "reject" }>["reject_acceptance_receipt"];
  state: ContactState;
};
type ContactTombstoneSummary = { tombstone_event_ref: string; state: "tombstoned" };

function contactScopes(scopes: string[]): ContactScope[] {
  const order: ContactScope[] = ["invite", "direct_message", "voice_call", "video_call", "presence"];
  for (const scope of scopes) {
    if (!order.includes(scope as ContactScope)) throw new Error(`invalid Contact scope ${scope}`);
  }
  return [...new Set(scopes)].sort((a, b) => order.indexOf(a as ContactScope) - order.indexOf(b as ContactScope)) as ContactScope[];
}

type PreparedContact = Extract<ContactOperationResponseBody, { status: "prepared" }>;
function signContactDraft(
  prepared: ContactOperationResponseBody, operationId: string,
  resultKind: PreparedContact["operation_kind"], expectedKind: string,
  actor: ReturnType<typeof accountActorId>, peer: ContactPeer,
): { prepared: PreparedContact; signedEvent: Record<string, unknown> } {
  if (prepared.status !== "prepared" || prepared.operation_kind !== resultKind || prepared.operation_id !== operationId) {
    throw new Error(`Contact prepare did not return its exact operation and branch: ${JSON.stringify(prepared)}`);
  }
  expect(Date.parse(prepared.expires_at)).toBeGreaterThan(Date.now());
  const bytes = Buffer.from(prepared.event_draft.unsigned_event_base64url, "base64url").toString("utf8");
  const signedEvent = JSON.parse(bytes) as Record<string, unknown>;
  expect(canonicalJson(signedEvent)).toBe(bytes);
  expect(`sha256:${sha256CanonicalJson(signedEvent)}`).toBe(prepared.event_draft.event_digest);
  expect(signedEvent.kind).toBe(expectedKind);
  expect(signedEvent.actor_id).toEqual(actor);
  expect(signedEvent.realm_id).toBe(principalControlRealmForId(actor.account_id.principal_id));
  expect(signedEvent.scope_ref).toEqual({ kind: "realm", realm_id: signedEvent.realm_id });
  expect((signedEvent.payload as Record<string, unknown>).peer).toEqual(peer);
  refreshEventEnvelopeProof(signedEvent);
  expect((signedEvent.producer_proof as { event_digest: string }).event_digest).toBe(prepared.event_draft.event_digest);
  return { prepared, signedEvent };
}



// invite-addressing.md §5.1: `disclosed_outcome` is a closed two-value enum
// (`delivered | blocked`). Quarantine MUST NOT be disclosed at all — it is
// reported as `status="deferred"` with no `disclosed_outcome`.
type InviteConsentGrant = { eventRef: string };

export async function grantInviteConsentArkret(
  request: APIRequestContext,
  token: string,
  holder: JointUser,
  peerId: string,
  opts: { server?: ColandKey; peerStationId?: string } = {},
): Promise<InviteConsentGrant> {
  const peer = {
    kind: "actor" as const,
    actor_id: accountActorId(peerId, opts.server, opts.peerStationId),
  };
  const { event } = await replaceConsentScopeApi(request, token, holder.id, peer, "invite", {
    consent_scope: "invite",
    expires_at: canonicalTimestamp(new Date(Date.now() + 24 * 60 * 60 * 1000)),
  }, opts);
  return { eventRef: String(event.event_id) };
}

// ── Contact request / respond / list / tombstone. ──

// contact-and-direct-conversation.md §2: a temporary admission failure is
// not a durable outcome. Replay the same commit, including its signed Event
// and reservation; only the HTTP authentication proof is refreshed.
const contactCommitRetries = new Map<string, number[]>();

async function submitContactCommit(
  request: APIRequestContext,
  token: string,
  url: string,
  body: Record<string, unknown>,
): Promise<APIResponse> {
  const submission = canonicalJson(body);
  const event = body.signed_event as Record<string, unknown>;
  const retryScope = canonicalJson({ actor_id: event.actor_id, endpoint: url });
  const deadline = Date.now() + 30_000;
  for (;;) {
    const response = await request.post(url, {
      headers: {
        ...authHeaders(token, "POST", url),
        "content-type": "application/json",
      },
      data: submission,
      timeout: Math.max(1, deadline - Date.now()),
    });
    if (response.status() !== 503) return response;
    const problem: unknown = await response.json().catch(() => undefined);
    if (wireErrCode(problem) !== "temporarily_unavailable") return response;
    const now = Date.now();
    const retries = (contactCommitRetries.get(retryScope) ?? [])
      .filter((sentAt) => sentAt > now - 300_000);
    contactCommitRetries.set(retryScope, retries);
    if (retries.length >= 5) return response;
    const retryAfter = response.headers()["retry-after"];
    const bodyHint = (problem as Record<string, unknown>).retry_after_ms;
    const hint = retryAfter
      ? /^\d+$/.test(retryAfter)
        ? Number(retryAfter) * 1_000
        : Math.max(0, Date.parse(retryAfter) - Date.now())
      : typeof bodyHint === "number" && bodyHint > 0 ? bodyHint : 0;
    const backoff = Math.min(60_000, 1_000 * 2 ** retries.length);
    const retryDelay = Math.max(
      Number.isFinite(hint) ? hint : 0,
      backoff * (1 + Math.random() * 0.2),
    );
    if (Date.now() + retryDelay >= deadline) return response;
    // Reserve the shared attempt before yielding, including concurrent calls.
    retries.push(now + retryDelay);
    await response.dispose();
    await new Promise((resolve) => setTimeout(resolve, retryDelay));
  }
}

export async function requestContactArkret(
  request: APIRequestContext,
  token: string,
  target: string,
  opts: {
    requestedScopes: string[];
    message?: string;
    idempotencyKey?: string;
    server?: ColandKey;
    recipientServiceId?: string;
    /**
     * Introduction evidence is required for a cross-Station
     * request.  The recipient's default policy quarantines
     * `explicit_address`, so callers exercising a real federation delivery
     * should pass a locator (or another allow-listed evidence kind).
     */
    introductionEvidence?: ContactRequestPrepare["introduction_evidence"];
  },
): Promise<{ outcome: ContactRequestSummary; response: APIResponse }> {
  const nonce = uuidV7();
  const operationId = `ak:operation:contact.request.${nonce}`;
  const idempotencyKey = opts.idempotencyKey ?? nonce;
  const url = `${colandBaseUrl(opts.server)}/_arkret/self/contacts/request`;
  const prepareBody: ContactRequestPrepare = {
    phase: "prepare",
    operation_id: operationId,
    idempotency_key: idempotencyKey,
    peer: { kind: "human", account_id: accountActorId(target, opts.server, opts.recipientServiceId).account_id },
    granted_to_peer_scopes: contactScopes(opts.requestedScopes),
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
  const actor = accountActorId(await currentActorIdApi(request, token, opts), opts.server);
  const { prepared, signedEvent } = signContactDraft(
    await expectJsonOk<ContactOperationResponseBody>(preparedResponse, `prepare contact request -> ${target}`),
    operationId, "request", "ak.contact.requested", actor, prepareBody.peer,
  );
  expect((signedEvent.payload as Record<string, unknown>).granted_to_peer_scopes).toEqual(prepareBody.granted_to_peer_scopes);
  const response = await submitContactCommit(request, token, url, {
    phase: "commit",
    operation_id: operationId,
    idempotency_key: idempotencyKey,
    reservation_handle: prepared.reservation_handle,
    signed_event: signedEvent,
  });
  const accepted = await expectJsonOk<ContactOperationResponseBody>(response, `contact request -> ${target}`);
  if (accepted.status !== "accepted" || accepted.operation_kind !== "request" || accepted.operation_id !== operationId) {
    throw new Error(`Contact request was not accepted for its exact operation: ${JSON.stringify(accepted)}`);
  }
  expect(accepted.request_acceptance_receipt.core.request_event_ref).toBe(signedEvent.event_id);
  expect(accepted.request_acceptance_receipt.core.holder).toEqual({ kind: "human", account_id: actor.account_id });
  expect(accepted.request_acceptance_receipt.core.peer).toEqual(prepareBody.peer);
  const outcome: ContactRequestSummary = {
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
  server: ColandKey,
  sessionToken: string,
): Promise<Extract<ContactRequestPrepare["introduction_evidence"], { kind: "locator_ref" }>["principal_locator"]> {
  const issueUrl = `${colandBaseUrl(server)}/_arkret/self/invite-locators`;
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
    `${colandBaseUrl(server)}/_arkret/open/invite-locators/resolve`,
    {
      headers: { "content-type": "application/json" },
      data: canonicalJson({ locator_token: issued.locator_token }),
    },
  );
  const locator = await expectJsonOk<Extract<ContactRequestPrepare["introduction_evidence"], { kind: "locator_ref" }>["principal_locator"]>(
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
    server?: ColandKey;
    requesterServiceId?: string;
  },
): Promise<ContactResponseSummary> {
  let row: ContactTestProjection | undefined;
  await expect
    .poll(
      async () => {
        const rows = await listContactsArkret(request, token, {
          server: opts.server,
        });
        const matches = rows.filter(
          (candidate) =>
            candidate.peer === opts.requesterId &&
            candidate.request_event_ref === opts.requestId &&
            (!opts.requesterServiceId ||
              (candidate.peerIdentity.kind === "human" &&
                candidate.peerIdentity.account_id.station_id ===
                  opts.requesterServiceId)),
        );
        if (matches.length > 1) {
          throw new Error("Contact response requires an exact AccountId");
        }
        row = matches[0];
        return row?.state === "pending_incoming";
      },
      {
        message: `contact ${opts.requesterId} exposes the exact pending incoming request`,
        timeout: 30_000,
        intervals: [250, 500, 1_000, 2_000],
      },
    )
    .toBe(true);
  if (!row || row.state !== "pending_incoming" || !row.request_event_ref) {
    throw new Error(`contact ${opts.requesterId} exposes no pending incoming request`);
  }
  const nonce = uuidV7();
  const operationId = `ak:operation:contact.${opts.action}.${nonce}`;
  const url = `${colandBaseUrl(opts.server)}/_arkret/self/contacts/${opts.action === "accept" ? "respond" : "reject"}`;
  const common = {
    phase: "prepare" as const, operation_id: operationId, idempotency_key: nonce,
    peer: row.peerIdentity, request_event_ref: row.request_event_ref,
  };
  const prepareBody: ContactRespondRequestBody | ContactRejectRequestBody = opts.action === "accept"
    ? { ...common, action: "accept", granted_to_peer_scopes: contactScopes(opts.grantedScopes ?? []) }
    : { ...common, action: "reject" };
  const preparedResponse = await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson(prepareBody),
  });
  const resultKind = opts.action === "accept" ? "response" : "reject";
  const actor = accountActorId(await currentActorIdApi(request, token, opts), opts.server);
  const { prepared, signedEvent } = signContactDraft(
    await expectJsonOk<ContactOperationResponseBody>(preparedResponse, `prepare contact ${opts.action} <- ${opts.requesterId}`),
    operationId, resultKind, opts.action === "accept" ? "ak.contact.accepted" : "ak.contact.rejected",
    actor, row.peerIdentity,
  );
  expect((signedEvent.payload as Record<string, unknown>).request_event_ref).toBe(row.request_event_ref);
  const response = await submitContactCommit(request, token, url, {
    phase: "commit",
    operation_id: operationId,
    idempotency_key: nonce,
    reservation_handle: prepared.reservation_handle,
    signed_event: signedEvent,
  });
  const accepted = await expectJsonOk<ContactOperationResponseBody>(response, `contact respond ${opts.action} <- ${opts.requesterId}`);
  if (accepted.status !== "accepted" || accepted.operation_id !== operationId ||
      (accepted.operation_kind !== "response" && accepted.operation_kind !== "reject") || accepted.operation_kind !== resultKind) {
    throw new Error(`Contact response was not accepted for its exact operation and branch: ${JSON.stringify(accepted)}`);
  }
  const receipt = accepted.operation_kind === "response"
    ? accepted.normal_response_acceptance_receipt : accepted.reject_acceptance_receipt;
  const eventRef = accepted.operation_kind === "response"
    ? accepted.normal_response_acceptance_receipt.response_event_ref : accepted.reject_acceptance_receipt.reject_event_ref;
  expect(eventRef).toBe(signedEvent.event_id);
  return { response_event_ref: eventRef, acceptance_receipt: receipt,
    state: accepted.operation_kind === "response" ? "accepted" : "rejected" };
}

async function listContactsArkret(
  request: APIRequestContext,
  token: string,
  opts: { server?: ColandKey } = {},
): Promise<ContactTestProjection[]> {
  const url = `${colandBaseUrl(opts.server)}/_arkret/self/contacts`;
  const response = await request.get(url, {
    headers: authHeaders(token, "GET", url),
  });
  const body = await expectJsonOk<{ contacts: ContactView[] }>(
    response,
    "list contacts",
  );
  return body.contacts.map((row) => {
    const peer = row.peer;
    const peerId =
      peer?.kind === "human" && typeof peer.account_id?.principal_id === "string"
        ? peer.account_id.principal_id
        : peer?.kind === "agent" && peer.actor_id
          ? eventPrincipalId({ actor_id: peer.actor_id })
          : undefined;
    if (!peerId) {
      throw new Error(`contact row has an invalid canonical peer: ${JSON.stringify(row.peer)}`);
    }
    return {
      ...row,
      peer: peerId,
      peerIdentity: peer,
      granted_by_me: row.granted_to_peer_scopes,
      granted_to_me: row.granted_by_peer_scopes,
    };
  });
}

export async function contactRow(
  request: APIRequestContext,
  token: string,
  peer: string,
  opts: { server?: ColandKey } = {},
): Promise<ContactTestProjection | undefined> {
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
    blockPeer?: boolean;
    // Cross-PS addressing (spec contact-and-direct-conversation.md §4.1): the
    // peer's home service DID so coland federates the `ak.contact.tombstone`
    // fact to the peer's Station via `ak.peer.contacts.command.submit.v1`.
    peerServiceId?: string;
    server?: ColandKey;
  } = {},
): Promise<ContactTombstoneSummary> {
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
  const url = `${colandBaseUrl(opts.server)}/_arkret/self/contacts/tombstone`;
  const nonce = uuidV7();
  const operationId = `ak:operation:contact.tombstone.${nonce}`;
  const prepareBody: Extract<ContactTombstoneRequestBody, { phase: "prepare" }> = {
    phase: "prepare", operation_id: operationId, idempotency_key: nonce,
    peer: row.peerIdentity, contact_round_id: contactRoundId, version,
    predecessor_event_ref: predecessorEventRef, block_peer: opts.blockPeer ?? false,
  };
  const preparedResponse = await request.post(url, {
    headers: { ...authHeaders(token, "POST", url), "content-type": "application/json" },
    data: canonicalJson(prepareBody),
  });
  const actor = accountActorId(await currentActorIdApi(request, token, opts), opts.server);
  const { prepared, signedEvent } = signContactDraft(
    await expectJsonOk<ContactOperationResponseBody>(preparedResponse, `prepare tombstone contact ${contact}`),
    operationId, "tombstone", "ak.contact.tombstone", actor, row.peerIdentity,
  );
  const payload = signedEvent.payload as Record<string, unknown>;
  expect(payload.contact_round_id).toBe(contactRoundId);
  expect(payload.version).toBe(version);
  expect(payload.predecessor_event_ref).toBe(predecessorEventRef);
  const response = await submitContactCommit(request, token, url, {
    phase: "commit",
    operation_id: operationId,
    idempotency_key: nonce,
    reservation_handle: prepared.reservation_handle,
    signed_event: signedEvent,
  });
  const accepted = await expectJsonOk<ContactOperationResponseBody>(response, `tombstone contact ${contact}`);
  if (accepted.status !== "accepted" || accepted.operation_kind !== "tombstone" || accepted.operation_id !== operationId) {
    throw new Error(`Contact tombstone was not accepted for its exact operation: ${JSON.stringify(accepted)}`);
  }
  expect(accepted.lineage.event_ref).toBe(signedEvent.event_id);
  expect(accepted.lineage.peer).toEqual(row.peerIdentity);
  expect(accepted.lineage.contact_round_id).toBe(contactRoundId);
  return { tombstone_event_ref: accepted.lineage.event_ref, state: "tombstoned" };
}

async function uploadDirectConversationKeyPackage(
  request: APIRequestContext,
  token: string,
  user: JointUser,
  opts: { server?: ColandKey } = {},
): Promise<void> {
  const signingSeedB64url = registeredEventSigningSeedB64url(user.id);
  if (!signingSeedB64url) {
    throw new Error(
      `no accepted device signing seed registered for ${user.id}`,
    );
  }
  const actorId = accountActorId(user.id, opts.server);
  const keyPackages = [
    cotestWire<Record<string, unknown>>("mls-keypackage-upload-entry", {
      actor_id: actorId,
      device_id: user.deviceId,
      signing_seed_b64url: signingSeedB64url,
    }),
  ];
  const unsigned = {
    actor_id: actorId,
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
    signature: signature,
  };
  const url = `${colandBaseUrl(opts.server)}/_arkret/self/keys/keypackages/upload`;
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
  const body = await expectJsonOk<KeyPackagesUploadResponseBody>(response, `upload direct-conversation KeyPackage ${user.id}`);
  expect(body.accepted_count).toBe(1);
  expect(body.rejections ?? []).toEqual([]);
}


// ── Realm-pull (consent_grant evidence) invite delivery. ──

export type IntroductionEvidence = Extract<
  InviteDeliveryRequestBody["introduction_evidence"],
  { kind: "consent_grant" | "explicit_address" }
>;

// Build a `ak.invite.create` invite event whose payload satisfies coland's
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
  recipientServer?: ColandKey;
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
    originServer: ColandKey;
    recipientServer: ColandKey;
    idempotencyKey?: string;
    idempotencyKeyPrefix: string;
    context: string;
  },
): Promise<{
  outcome: InviteDeliveryResponseBody;
  inviteId: string;
}> {
  const recipientServiceId = colandServiceId(args.recipientServer);
  const { event } = buildInviteCreateEvent({
    inviterId: args.inviterId,
    realmId: args.realmId,
    inviteeId: args.inviteeId,
    recipientServiceId,
    recipientServer: args.recipientServer,
    evidence: args.evidence,
  });
  refreshEventEnvelopeProof(event);
  // The Station answers submission with the RealmCommit that covers the Event.
  // That commit is what the recipient Station verifies the delivery against,
  // so it travels with the request instead of a Seal basis.
  const submitOutcome = await submitSignedEventApi(request, args.inviterToken, event, {
    server: args.originServer,
    context: args.context,
  });
  const inviteCommit = (submitOutcome as Record<string, unknown>).commit as
    InviteDeliveryRequestBody["invite_commit"];
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
    };
  }

  const body: InviteDeliveryRequestBody = {
    schema: "ak.schema.invite_delivery_request.v1",
    // `signedEventEnvelope` still returns an untyped record — wiring the Event
    // envelope itself to the generated type is the remaining B3 item.
    invite_event: event as InviteDeliveryRequestBody["invite_event"],
    // §7 step 4: the receiver cannot resolve the invite Realm's authority
    // itself, so the covering RealmCommit and the locator hints that reach the
    // inviter's Station travel with the request.
    invite_commit: inviteCommit,
    producer_signer_fact: await originalHumanSignerFactApi(
      request, args.inviterToken,
      event as InviteDeliveryRequestBody["invite_event"], inviteCommit,
      { server: args.originServer },
    ),
    authority_locator_hints: [
      {
        service_kind: "station",
        service_id: colandServiceId(args.originServer),
        source: "invite",
      },
    ],
    invite_address: inviteAddress,
    introduction_evidence: args.evidence,
    idempotency_key: idempotencyKey,
  };
  return {
    outcome: await submitPeerInviteDeliveryApi(request, body, {
      origin: colandServiceId(args.originServer),
      destination: recipientServiceId,
      server: args.recipientServer,
    }),
    inviteId,
  };
}

// High-trust `consent_grant` pull: the invitee already issued the inviter an
// current explicit `invite` permission (§2), so §5.1 lets the outcome be disclosed.
export async function deliverInviteWithConsentGrant(
  request: APIRequestContext,
  args: {
    inviterId: string;
    inviterToken: string;
    realmId: string;
    inviteeId: string;
    consentGrantRef: Extract<IntroductionEvidence, { kind: "consent_grant" }>["consent_grant_ref"];
    originServer: ColandKey;
    recipientServer: ColandKey;
    idempotencyKey?: string;
  },
): Promise<{
  outcome: InviteDeliveryResponseBody;
  inviteId: string;
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

export async function listAuthzInvitesArkret(
  request: APIRequestContext,
  token: string,
  opts: { server?: ColandKey } = {},
): Promise<InviteObject[]> {
  const url = new URL(
    "/_arkret/self/authz/invites",
    colandBaseUrl(opts.server),
  );
  const response = await request.get(url.toString(), {
    headers: {
      ...authHeaders(token, "GET", url.toString()),
      "Arkret-Operation": "ak.self.authz.invites.read.list.v1",
    },
  });
  const body = await expectJsonOk<{ invites?: InviteObject[] }>(
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
  invites: InviteObject[],
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
    server?: ColandKey;
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
    },
  );
}

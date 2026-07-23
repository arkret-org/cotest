// Contact-graph protocol-face helpers (`/_arkret/self/contacts/*`,
// `/_arkret/self/direct-conversations/resolve`,
// `/_arkret/self/invite-receive-policy`, and the `consent_grant`-evidence
// invite-delivery path `/_arkret/peer/invites`).
//
// These target the NEW `/_arkret` contract with `requested_scopes:[...]`,
// distinct from the legacy `/_soland/self/contacts/request` + `scope` helper
// used by other specs (helpers/soland-api.ts + consent-grant.spec.ts). Do not
// route new contact-graph coverage through the legacy surface.
//
// Wire shapes mirror arkret-rust-sdk core::http + core::model::invite_addressing
// and soland src/routing/identity/account.rs + src/routing/invites.rs.

import {
  createHash,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";
import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { type SolandKey, solandBaseUrl, solandServiceId } from "./env";
import {
  alignSignedEventToActorFrontierApi,
  authHeaders,
  b64url,
  canonicalJson,
  canonicalTimestamp,
  currentActorDidApi,
  expectJsonOk,
  principalControlRealmForDid,
  registerEventSigner,
  signedEventEnvelope,
  submitPeerInviteDeliveryApi,
  submitSignedEventApi,
  typedId,
  type InviteDeliveryRequestBody,
} from "./soland-api";
import type { JointUser } from "./users";
import { ed25519PrivateKeySeedB64url } from "./encoding";
import {
  buildCrossSigningPublishPayload,
  buildDeviceCrossSigningBinding,
  buildDevicePossessionSignature,
  generateCrossSigningKey,
  TEST_DEVICE_ALGORITHMS,
  type CrossSigningIdentity,
  type CrossSigningKey,
} from "./cross-signing-harness";
import {
  buildPrincipalGenesisEntry,
  generateWebvhKey,
  submitPrincipalGenesisEntry,
} from "./webvh-api";

export type Ed25519FixtureKey = {
  privateKey: KeyObject;
  rawPublicKey: Buffer;
  publicKeyMultibase: string;
};

export type PreparedDirectConversationIdentity = {
  user: JointUser;
  principalSigningKey: Ed25519FixtureKey;
};

// ── Contact list / request / respond wire types (subset we assert on). ──

export type ContactState =
  | "pending_outgoing"
  | "pending_incoming"
  | "accepted"
  | "rejected"
  | "tombstoned";

export type DirectConversationSummary = {
  realm_id: string;
  main_strand_id: string;
  binding_event_ref?: string;
  state: string;
};

export type ContactAgentProjection = {
  agent_id: string;
  controller_id: string;
  display_name?: string;
  agent_slug?: string;
  direct_conversation?: DirectConversationSummary;
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
  agents?: ContactAgentProjection[];
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
  state:
    | "found"
    | "authoring_required"
    | "not_found"
    | "retired"
    | "non_canonical";
  realm_id?: string;
  main_strand_id?: string;
  binding_event_ref?: string;
  created?: boolean;
  authoring_kind?:
    | "remote_keypackage_claim"
    | "direct_conversation_materialization";
  claim_authorization_draft?: Record<string, unknown>;
  materialization_draft?: Record<string, unknown>;
};

export type InviteDeliveryOutcome = {
  status: "accepted" | "duplicate" | "deferred";
  disclosed_outcome?: "delivered" | "blocked" | "quarantined";
  received_at?: string;
  retry_after_ms?: number;
};

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
     * Introduction evidence is required for a cross-Principal-Server
     * request.  The recipient's default policy quarantines
     * `explicit_address`, so callers exercising a real federation delivery
     * should pass a locator (or another allow-listed evidence kind).
     */
    introductionEvidence?: Record<string, unknown>;
  },
): Promise<{ outcome: ContactRequestOutcome; response: APIResponse }> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_arkret/self/contacts/request`,
    {
      headers: authHeaders(token),
      data: {
        target,
        requested_scopes: opts.requestedScopes,
        ...(opts.message !== undefined ? { message: opts.message } : {}),
        ...(opts.idempotencyKey !== undefined
          ? { idempotency_key: opts.idempotencyKey }
          : {}),
        ...(opts.recipientServiceId !== undefined
          ? { recipient_service_id: opts.recipientServiceId }
          : {}),
        ...(opts.introductionEvidence !== undefined
          ? { introduction_evidence: opts.introductionEvidence }
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

/**
 * Resolve a short-lived Principal Locator from a server's public locator
 * endpoint.  The resulting object is suitable for
 * `requestContactArkret(..., { introductionEvidence: { kind: "locator_ref",
 * principal_locator: locator } })` and satisfies the recipient policy's
 * allow-listed `locator_ref` evidence requirement.
 */
export async function resolvePrincipalLocator(
  request: APIRequestContext,
  subjectDid: string,
  server: SolandKey,
  sessionToken: string,
): Promise<Record<string, unknown>> {
  const issue = await request.post(
    `${solandBaseUrl(server)}/_arkret/self/invite-locators`,
    {
      headers: authHeaders(sessionToken),
      data: { ttl_seconds: 900 },
    },
  );
  const issued = await expectJsonOk<{
    locator_token: string;
  }>(issue, `issue principal locator for ${subjectDid}`);
  const response = await request.post(
    `${solandBaseUrl(server)}/_arkret/open/invite-locators/resolve`,
    { data: { locator_token: issued.locator_token } },
  );
  const locator = await expectJsonOk<Record<string, unknown>>(
    response,
    `resolve principal locator for ${subjectDid}`,
  );
  expect(locator.subject_id).toBe(subjectDid);
  return locator;
}

export async function respondContactArkret(
  request: APIRequestContext,
  token: string,
  opts: {
    requestId: string;
    requester: string;
    action: "accept" | "reject";
    grantedScopes?: string[];
    server?: SolandKey;
    requesterServiceId?: string;
  },
): Promise<ContactRespondOutcome> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_arkret/self/contacts/respond`,
    {
      headers: authHeaders(token),
      data: {
        request_id: opts.requestId,
        requester: opts.requester,
        action: opts.action,
        ...(opts.grantedScopes ? { granted_scopes: opts.grantedScopes } : {}),
        ...(opts.requesterServiceId !== undefined
          ? { requester_service_id: opts.requesterServiceId }
          : {}),
      },
    },
  );
  return await expectJsonOk<ContactRespondOutcome>(
    response,
    `contact respond ${opts.action} <- ${opts.requester}`,
  );
}

export async function listContactsArkret(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<ContactListRow[]> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_arkret/self/contacts`,
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
  const rows = await listContactsArkret(request, token, opts);
  return rows.find((row) => row.peer === peer);
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
    // peer's home service DID so soland federates the `ak.contact.tombstoned`
    // fact to the peer's Principal Server via `ak.peer.contacts.command.submit`.
    peerServiceId?: string;
    server?: SolandKey;
  } = {},
): Promise<ContactTombstoneOutcome> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_arkret/self/contacts/tombstone`,
    {
      headers: authHeaders(token),
      data: {
        contact,
        ...(opts.revokeScopes ? { revoke_scopes: opts.revokeScopes } : {}),
        ...(opts.fullPeerRevoke !== undefined
          ? { full_peer_revoke: opts.fullPeerRevoke }
          : {}),
        ...(opts.blockPeer !== undefined ? { block_peer: opts.blockPeer } : {}),
        ...(opts.peerServiceId !== undefined
          ? { peer_service_id: opts.peerServiceId }
          : {}),
      },
    },
  );
  return await expectJsonOk<ContactTombstoneOutcome>(
    response,
    `tombstone contact ${contact}`,
  );
}

export async function resolveDirectConversationArkret(
  request: APIRequestContext,
  token: string,
  peer: string,
  opts: { create?: boolean; server?: SolandKey } = {},
): Promise<DirectConversationResolveOutcome> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_arkret/self/direct-conversations/resolve`,
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

export async function prepareDirectConversationIdentityArkret(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey } = {},
): Promise<PreparedDirectConversationIdentity> {
  const principalSigningKey = generateWebvhKey();
  const built = buildPrincipalGenesisEntry({
    baseUrl: solandBaseUrl(opts.server),
    localId: user.name,
    rootKey: generateWebvhKey(),
    nextRootKey: generateWebvhKey(),
    principalSigningKey,
    enrollmentKey: generateWebvhKey(),
    serviceEndpoint: solandBaseUrl(opts.server),
  });
  await submitPrincipalGenesisEntry(
    request,
    solandBaseUrl(opts.server),
    built,
  );
  registerEventSigner({
    actorDid: built.did,
    deviceId: user.deviceId,
    verificationMethod: `${built.did}#principal-signing-key`,
    signingSeedB64url: ed25519PrivateKeySeedB64url(principalSigningKey.privateKey),
  });
  return {
    user: { ...user, did: built.did },
    principalSigningKey: {
      privateKey: principalSigningKey.privateKey,
      rawPublicKey: principalSigningKey.publicKey,
      publicKeyMultibase: principalSigningKey.multibase,
    },
  };
}

export async function seedDirectConversationIdentityArkret(
  request: APIRequestContext,
  token: string,
  user: JointUser,
  opts: { principalSigningKey: Ed25519FixtureKey; server?: SolandKey },
): Promise<void> {
  const psk = opts.principalSigningKey;
  const ssk = generateCrossSigningKey();
  const usk = generateCrossSigningKey();
  const pskKid = `${user.did}#principal-signing-key`;
  const sskKid = `${user.did}#ak_self_signing_v1`;
  const uskKid = `${user.did}#ak_user_signing_v1`;
  const trustDomain = await solandTrustDomain(request, opts);
  const generation = 1;
  const identity: CrossSigningIdentity = {
    principalId: user.did,
    trustDomain,
    generation,
    psk: fixtureCrossSigningKey(psk, pskKid),
    ssk: { ...ssk, verificationMethod: sskKid },
    usk: { ...usk, verificationMethod: uskKid },
  };

  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: user.did,
      realmId: principalControlRealmForDid(user.did),
      kind: "ak.cross_signing.publish",
      payload: buildCrossSigningPublishPayload(identity),
    }),
    { server: opts.server, context: `publish cross-signing ${user.did}` },
  );

  const deviceKey = generateCrossSigningKey();
  const hpkeKeyMultibase = "z6LSCotestE2eDeviceHpkeKey";
  const notBefore = canonicalTimestamp();
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: user.did,
      realmId: principalControlRealmForDid(user.did),
      kind: "ak.device.authorize",
      payload: {
        principal_id: user.did,
        device_id: user.deviceId,
        device_public_key: deviceKey.multibase,
        hpke_key: hpkeKeyMultibase,
        algorithms: TEST_DEVICE_ALGORITHMS,
        device_key_algorithm: "EdDSA",
        device_signature: {
          kid: `${user.did}#${user.deviceId}`,
          alg: "EdDSA",
          sig: buildDevicePossessionSignature({
            identity,
            deviceId: user.deviceId,
            devicePublicKeyMultibase: deviceKey.multibase,
            hpkeKeyMultibase,
            algorithms: TEST_DEVICE_ALGORITHMS,
            deviceKeyAlgorithm: "EdDSA",
            authorizedBy: user.deviceId,
            notBefore,
            privateKey: deviceKey.privateKey,
          }),
        },
        authorized_by: user.deviceId,
        not_before: notBefore,
        cross_signing_binding: buildDeviceCrossSigningBinding({
          identity,
          deviceId: user.deviceId,
          devicePublicKeyMultibase: deviceKey.multibase,
          hpkeKeyMultibase,
          algorithms: TEST_DEVICE_ALGORITHMS,
        }),
      },
    }),
    { server: opts.server, context: `authorize device ${user.deviceId}` },
  );

  await uploadDirectConversationKeyPackage(
    request,
    token,
    user,
    deviceKey.privateKey,
    opts,
  );
}

function fixtureCrossSigningKey(
  key: Ed25519FixtureKey,
  verificationMethod: string,
): CrossSigningKey {
  return {
    privateKey: key.privateKey,
    rawPublicKey: key.rawPublicKey,
    multibase: key.publicKeyMultibase,
    didKey: `did:key:${key.publicKeyMultibase}`,
    verificationMethod,
  };
}

async function solandTrustDomain(
  request: APIRequestContext,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const response = await request.get(`${solandBaseUrl(opts.server)}/_arkret/describe`);
  const body = await expectJsonOk<{ trust_domain?: string }>(
    response,
    "describe trust_domain",
  );
  return body.trust_domain ?? "ak:trust_domain:soland.joint-e2e.local";
}

async function uploadDirectConversationKeyPackage(
  request: APIRequestContext,
  token: string,
  user: JointUser,
  devicePrivateKey: KeyObject,
  opts: { server?: SolandKey } = {},
): Promise<void> {
  const stamp = `${Date.now()}-${Math.random()}`;
  const keypackageId = typedId("mls_keypackage");
  const keyPackage = b64url(`direct-conversation-keypackage-${stamp}`);
  const keypackageDigest = `sha256:${createHash("sha256")
    .update(Buffer.from(keyPackage, "base64url"))
    .digest("hex")}`;
  const keyPackages = [
    {
      keypackage_id: keypackageId,
      keypackage_ref: keypackageDigest,
      key_package: keyPackage,
      keypackage_digest: keypackageDigest,
      cipher_suites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
      capabilities: ["ak.mls.rfc9420", "ak.mls.profile.full"],
      created_at: canonicalTimestamp(),
      expires_at: canonicalTimestamp(new Date(Date.now() + 60 * 60 * 1000)),
    },
  ];
  const unsigned = {
    principal_id: user.did,
    device_id: user.deviceId,
    key_packages: keyPackages,
  };
  const deviceSignature = {
    kid: `${user.did}#${user.deviceId}`,
    alg: "EdDSA",
    sig: nodeSign(
      null,
      Buffer.concat([
        Buffer.from("ak.self.keys.keypackages.upload.create\n", "utf8"),
        Buffer.from(canonicalJson(unsigned), "utf8"),
      ]),
      devicePrivateKey,
    ).toString("base64url"),
  };
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_arkret/self/keys/keypackages/upload`,
    {
      headers: authHeaders(token),
      data: {
        ...unsigned,
        device_signature: deviceSignature,
      },
    },
  );
  const body = await expectJsonOk<{
    accepted: number;
    rejected?: Array<Record<string, unknown>>;
  }>(response, `upload direct-conversation KeyPackage ${user.did}`);
  expect(body.accepted).toBe(1);
  expect(body.rejected ?? []).toEqual([]);
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

export async function getInviteReceivePolicyArkret(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<InviteReceivePolicy> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_arkret/self/invite-receive-policy`,
    { headers: authHeaders(token) },
  );
  return await expectJsonOk<InviteReceivePolicy>(
    response,
    "get invite-receive-policy",
  );
}

export async function setInviteReceivePolicyArkret(
  request: APIRequestContext,
  token: string,
  policy: InviteReceivePolicy,
  opts: { server?: SolandKey } = {},
): Promise<InviteReceivePolicy> {
  const response = await request.put(
    `${solandBaseUrl(opts.server)}/_arkret/self/invite-receive-policy`,
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

// Build a `ak.invite.create` invite event whose payload satisfies soland's
// invite-delivery consistency checks (src/routing/invites.rs
// validate_invite_delivery_consistency + projection required fields):
//   - kind == ak.invite.create
//   - payload.invitee == invite_address.subject_id
//   - payload.invite_delivery_target.recipient_service_id == recipient svc
//   - payload.introduction_evidence_digest == sha256(canonical_json(evidence))
//   - payload carries invite_id + expires_at (schema-required for invite.create)
export function buildInviteCreateEvent(args: {
  inviterDid: string;
  realmId: string;
  inviteeDid: string;
  recipientServiceId: string;
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
    kind: "ak.invite.create",
    schemaId: "ak.schema.invite.v1",
    payload: {
      invite_id: inviteId,
      invitee: args.inviteeDid,
      invite_delivery_target: {
        recipient_service_id: args.recipientServiceId,
        recipient_service_type: "principal_server",
      },
      introduction_evidence_digest: evidenceDigest,
      expires_at: expiresAt,
    },
  });
  return { event, inviteId };
}

// Privately deliver a consent_grant-evidence invite to the subject's principal
// server via `POST /_arkret/peer/invites`. Returns the graded-disclosure
// outcome. `origin` is the inviter's service DID (signs the federation push).
export async function deliverInviteWithConsentGrant(
  request: APIRequestContext,
  args: {
    inviterDid: string;
    inviterToken: string;
    realmId: string;
    inviteeDid: string;
    consentGrantRef: string;
    originServer: SolandKey;
    recipientServer: SolandKey;
    idempotencyKey?: string;
  },
): Promise<{ outcome: InviteDeliveryOutcome; inviteId: string }> {
  const recipientServiceId = solandServiceId(args.recipientServer);
  const evidence: IntroductionEvidence = {
    kind: "consent_grant",
    consent_grant_ref: args.consentGrantRef,
  };
  const { event, inviteId } = buildInviteCreateEvent({
    inviterDid: args.inviterDid,
    realmId: args.realmId,
    inviteeDid: args.inviteeDid,
    recipientServiceId,
    evidence,
  });
  await alignSignedEventToActorFrontierApi(
    request,
    args.inviterToken,
    event,
    { server: args.originServer },
  );
  const body: InviteDeliveryRequestBody = {
    schema: "ak.schema.invite_delivery_request.v1",
    invite_event: event,
    invite_address: {
      subject_id: args.inviteeDid,
      recipient_service_id: recipientServiceId,
      recipient_service_type: "principal_server",
    },
    introduction_evidence: evidence,
    idempotency_key:
      args.idempotencyKey ?? `cotest-contact-graph:${inviteId}`,
  };
  const outcome = (await submitPeerInviteDeliveryApi(request, body, {
    origin: solandServiceId(args.originServer),
    destination: recipientServiceId,
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
    inviterToken: string;
    realmId: string;
    inviteeDid: string;
    originServer: SolandKey;
    recipientServer: SolandKey;
    idempotencyKey?: string;
  },
): Promise<{ outcome: InviteDeliveryOutcome; inviteId: string }> {
  const recipientServiceId = solandServiceId(args.recipientServer);
  const evidence: IntroductionEvidence = { kind: "explicit_address" };
  const { event, inviteId } = buildInviteCreateEvent({
    inviterDid: args.inviterDid,
    realmId: args.realmId,
    inviteeDid: args.inviteeDid,
    recipientServiceId,
    evidence,
  });
  await alignSignedEventToActorFrontierApi(
    request,
    args.inviterToken,
    event,
    { server: args.originServer },
  );
  const body: InviteDeliveryRequestBody = {
    schema: "ak.schema.invite_delivery_request.v1",
    invite_event: event,
    invite_address: {
      subject_id: args.inviteeDid,
      recipient_service_id: recipientServiceId,
      recipient_service_type: "principal_server",
    },
    introduction_evidence: evidence,
    idempotency_key:
      args.idempotencyKey ?? `cotest-contact-graph-explicit:${inviteId}`,
  };
  const outcome = (await submitPeerInviteDeliveryApi(request, body, {
    origin: solandServiceId(args.originServer),
    destination: recipientServiceId,
    server: args.recipientServer,
  })) as unknown as InviteDeliveryOutcome;
  return { outcome, inviteId };
}

// List the authenticated actor's pending invites with the canonical wire
// shape. The authz endpoint serializes the SDK `Invite` whose id field is
// `id` (NOT `invite_id`).
export type AuthzInvite = {
  id: string;
  realm_id: string;
  invitee?: string;
  state?: string;
};

export async function listAuthzInvitesArkret(
  request: APIRequestContext,
  token: string,
  opts: { server?: SolandKey } = {},
): Promise<AuthzInvite[]> {
  const actorDid = await currentActorDidApi(request, token, opts);
  const url = new URL("/_arkret/self/authz/invites", solandBaseUrl(opts.server));
  url.searchParams.set("subject", actorDid);
  const response = await request.get(
    url.toString(),
    { headers: authHeaders(token) },
  );
  const body = await expectJsonOk<{ invites?: AuthzInvite[] }>(
    response,
    "list authz invites",
  );
  return body.invites ?? [];
}

// Submit `ak.invite.accept` as the invitee to join the realm.
export async function acceptInviteArkret(
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
      kind: "ak.invite.accept",
      payload: {
        invitee: args.accepterDid,
        invite_id: args.inviteId,
      },
    }),
    { server: args.server, context: `accept invite ${args.inviteId}` },
  );
}

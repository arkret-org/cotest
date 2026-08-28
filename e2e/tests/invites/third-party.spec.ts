// Third-party invite (email -> token commitment -> binding proof -> claim)
// Contract: e2e/scenarios/invites/third-party.md
// Spec: sync/third-party-invites.md section 3-4

import { createHash, randomUUID } from "node:crypto";
import { expect, test } from "../../helpers/arkret-test";
import type { APIRequestContext } from "../../helpers/arkret-test";
import { mockEmailBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  alignSignedEventToActorFrontierApi,
  authHeaders,
  requireDidCoreId,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  expectJsonOk,
  nextJoinPolicyRevision,
  prepareSignedEventCbaApi,
  projectDidToCoreId,
  registerEventSigner,
  retypeEventDerivedId,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";
import {
  buildClaimPayload,
  buildThirdPartyInvitePayload,
  generateDidKeyIdentity,
  signBindingProof,
  signSubjectProof,
  type DidKeyIdentity,
  type ThirdPartyInviteCell,
} from "../../helpers/third-party-invite";
import { ed25519PrivateKeySeedB64url } from "../../helpers/encoding";
import {
  buildWebvhGenesisEntry,
  generateWebvhKey,
  submitPrincipalGenesisEntry,
} from "../../helpers/webvh-api";

// Mint a fresh did:key-backed claimant. did:key DIDs are self-resolving, so the
// subject_proof Ed25519 key verifies against the SDK DidKeyResolver without any
// DID-document seeding against the joint harness.
function didKeyUser(prefix: string, identity: DidKeyIdentity): JointUser {
  const stamp = randomUUID();
  const deviceSuffix = stamp.replace(/-/g, "").slice(0, 12);
  return {
    name: `${prefix}-${stamp}`.toLowerCase(),
    id: projectDidToCoreId(identity.did),
    did: identity.did,
    deviceId: `ak:device:01904100-0000-7000-8000-${deviceSuffix}`,
    handle: `@${prefix}-${stamp}`.toLowerCase(),
    displayName: `${prefix} ${stamp}`,
  };
}

async function createVerificationService(
  request: APIRequestContext,
  seed: string,
): Promise<DidKeyIdentity> {
  const signingKey = generateWebvhKey();
  const built = buildWebvhGenesisEntry({
    baseUrl: solandBaseUrl(),
    localId: `invite-verifier-${seed}-${randomUUID()}`,
    rootKey: generateWebvhKey(),
    nextRootKey: generateWebvhKey(),
    document: (did) => {
      const verificationMethod = `${did}#invite-verification`;
      return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        id: did,
        verificationMethod: [
          {
            id: verificationMethod,
            type: "Multikey",
            controller: did,
            publicKeyMultibase: signingKey.multibase,
          },
        ],
        assertionMethod: [verificationMethod],
      };
    },
  });
  await submitPrincipalGenesisEntry(request, solandBaseUrl(), built);
  return {
    did: built.did,
    verificationMethod: `${built.did}#invite-verification`,
    publicKeyMultibase: signingKey.multibase,
    signingSeedB64url: ed25519PrivateKeySeedB64url(signingKey.privateKey),
    privateKey: signingKey.privateKey,
  };
}

function tokenCommitment(seed: string): string {
  // sha256:<hex> over an opaque per-invite secret. The plaintext 3PID never
  // appears anywhere in the event chain — only this salted commitment does.
  return `sha256:${createHash("sha256")
    .update(`cotest:3pid-invite:${seed}`)
    .digest("hex")}`;
}

type SelfEventsOutcome = {
  status: number;
  accepted: string[];
  rejected: Array<{ id?: string; reason_code?: string; detail?: string }>;
  rejectReason?: string;
  body: Record<string, unknown>;
};

// `/_arkret/self/events` is a batch endpoint: a reducer rejection comes back as
// HTTP 200 with `status:"partial"` and the failure in `rejected[].reason_code`,
// NOT as a 4xx. Submit one envelope and surface that outcome uniformly.
async function submitSelfEvent(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
  opts: { alignFrontier?: boolean } = {},
): Promise<SelfEventsOutcome> {
  // This setup creates a real Realm, so bind the Event to its authoritative
  // frontier. A synthetic conformance basis would inject non-Event digests
  // into the real Seal DAG and poison every later control-seal pass.
  await prepareSignedEventCbaApi(request, token, envelope);
  if (opts.alignFrontier !== false) {
    await alignSignedEventToActorFrontierApi(request, token, envelope);
  }
  const response = await request.post(
    `${solandBaseUrl()}/_arkret/self/events`,
    {
      headers: { ...authHeaders(token), "content-type": "application/json" },
      data: canonicalJson(envelope),
    },
  );
  const text = await response.text();
  let body: Record<string, unknown> = {};
  try {
    body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    body = { raw: text };
  }
  const accepted = Array.isArray(body.accepted)
    ? (body.accepted as string[])
    : [];
  const rawRejected = Array.isArray(body.rejected)
    ? (body.rejected as Array<{ reason_code?: string; detail?: string }>)
    : [];
  const topLevelReason = wireErrCode(body);
  const topLevelError =
    body.error && typeof body.error === "object"
      ? (body.error as Record<string, unknown>)
      : undefined;
  const topLevelDetail =
    typeof topLevelError?.detail === "string"
      ? topLevelError.detail
      : typeof topLevelError?.message === "string"
        ? topLevelError.message
        : typeof body.detail === "string"
          ? body.detail
          : typeof body.message === "string"
            ? body.message
            : undefined;
  const rejected =
    rawRejected.length > 0
      ? rawRejected
      : topLevelReason
        ? [{ reason_code: topLevelReason, detail: topLevelDetail }]
        : [];
  const rejectReason = rejected[0]?.reason_code;
  return {
    status: response.status(),
    accepted,
    rejected,
    rejectReason,
    body,
  };
}

// Seed the Realm policy components cell with the verification-service allowlist
// the reducer re-checks (third-party-invites.md §2.1 Allowlist MUST). The
// allowlist entries are did_core_id and compared byte-for-byte against the
// payload's verification_id, so the DID is projected first. The
// createRealmApi genesis already occupies policy_revision 1.
async function allowlistVerificationService(
  request: APIRequestContext,
  token: string,
  ownerId: string,
  realmId: string,
  serviceId: string,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId: ownerId,
      realmId,
      kind: "ak.realm.policy_bundle",
      payload: {
        policy_revision: nextJoinPolicyRevision(undefined, realmId),
        allowed_third_party_invite_verification_ids: [
          projectDidToCoreId(serviceId),
        ],
      },
    }),
    { context: `allowlist verification service ${serviceId}` },
  );
}

async function submitThirdPartyInvite(
  request: APIRequestContext,
  token: string,
  ownerId: string,
  cell: ThirdPartyInviteCell,
  payload: Record<string, unknown>,
): Promise<SelfEventsOutcome> {
  const envelope = signedEventEnvelope({
    actorId: ownerId,
    realmId: cell.realmId,
    kind: "ak.invite.third_party",
    schemaId: "ak.schema.event.v1",
    payload,
  });
  const outcome = await submitSelfEvent(request, token, envelope);
  if (outcome.accepted.length > 0) {
    // Event-derived-id contract: the Invite id is a retype of the accepted
    // Event id (apply_invites.rs InviteId::from_event_id) and is never
    // carried in the payload, so the cell learns it only now.
    cell.inviteId = retypeEventDerivedId(outcome.accepted[0], "invite");
  }
  return outcome;
}

// Submit a `ak.invite.claim` directly to the reducer (the spec source of truth,
// third-party-invites.md §4.3).
async function submitClaim(
  request: APIRequestContext,
  bobToken: string,
  claimant: JointUser,
  cell: ThirdPartyInviteCell,
  claimPayload: Record<string, unknown>,
): Promise<SelfEventsOutcome> {
  return await submitSelfEvent(
    request,
    bobToken,
    signedEventEnvelope({
      actorId: claimant.id,
      realmId: cell.realmId,
      kind: "ak.invite.claim",
      actorSeq: 0,
      prevRefs: [],
      schemaId: "ak.schema.event.v1",
      payload: claimPayload,
    }),
    { alignFrontier: false },
  );
}

test.describe.configure({ mode: "serial" });

test.describe("third-party invite", () => {
  // Shared Phase-A/B/C setup: alice creates an `invite` Realm, allowlists a
  // resolvable did:webvh verification service, and submits a pending `ak.invite.third_party`
  // whose `third_party_invite` the test controls so the claim transcripts can be
  // reconstructed byte-for-byte.
  async function setupPendingInvite(
    request: APIRequestContext,
    opts: {
      fixtureNonce: string;
      expiresInMs?: number;
      allowlistService?: boolean;
    },
  ) {
    const alice = uniqueUser(`${opts.fixtureNonce}-alice`);
    const bobIdentity = generateDidKeyIdentity();
    const bob = didKeyUser(`${opts.fixtureNonce}-bob`, bobIdentity);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    // dev-login auto-provisions the did:key account for bob.
    const bobToken = await issueDevSession(request, bob);
    registerEventSigner({
      actorId: bob.id,
      deviceId: bob.deviceId,
      verificationMethod: bobIdentity.verificationMethod,
      signingSeedB64url: bobIdentity.signingSeedB64url,
    });
    const realmId = await createRealmApi(request, aliceToken, {
      title: `3PID invite reducer ${opts.fixtureNonce}`,
      ownerId: alice.id,
    });

    const verificationService = await createVerificationService(
      request,
      opts.fixtureNonce,
    );
    if (opts.allowlistService !== false) {
      await allowlistVerificationService(
        request,
        aliceToken,
        alice.id,
        realmId,
        verificationService.did,
      );
    }

    const expiresAt = canonicalTimestamp(
      new Date(Date.now() + (opts.expiresInMs ?? 60 * 60_000)),
    );
    const { payload, cell } = buildThirdPartyInvitePayload({
      realmId,
      verificationService,
      tokenCommitment: tokenCommitment(`${opts.fixtureNonce}-${alice.id}`),
      expiresAt,
      displayNameHint: "external invite",
    });

    return {
      alice,
      aliceToken,
      bob,
      bobIdentity,
      bobToken,
      realmId,
      verificationService,
      cell,
      invitePayload: payload,
    };
  }

  test("alice issues ak.invite.third_party with token_commitment; plaintext email never leaves client", async ({
    request,
  }) => {
    // third-party-invites.md §3.1 — the durable Event carries only the salted
    // token_commitment; the plaintext 3PID never enters the event chain.
    const ctx = await setupPendingInvite(request, {
      fixtureNonce: "s3-issue",
      allowlistService: false,
    });
    const outcome = await submitThirdPartyInvite(
      request,
      ctx.aliceToken,
      ctx.alice.id,
      ctx.cell,
      ctx.invitePayload,
    );
    expect(
      outcome.rejected,
      `ak.invite.third_party rejected: ${JSON.stringify(outcome.rejected)}`,
    ).toHaveLength(0);
    expect(outcome.accepted.length).toBeGreaterThan(0);

    // Privacy invariant: the submitted durable payload exposes only the
    // commitment + service binding, never plaintext email/phone/token.
    const serialized = JSON.stringify(ctx.invitePayload);
    expect(serialized).toContain(ctx.cell.tokenCommitment);
    expect(serialized).not.toMatch(/@example\.com/);
    for (const forbidden of [
      'token_salt"',
      "plaintext",
      '"email"',
      '"phone"',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  test("mock verification service receives invite token via email and atomically consumes it on claim", async ({
    request,
  }) => {
    // third-party-invites.md §3.2 + §4.1 — the email/verification broker
    // delivers the invite token out-of-band and atomically consumes it when
    // the registered DID presents it (harness: cotest mock-email service).
    const mockEmail = mockEmailBaseUrl();
    test.skip(!mockEmail, "mock-email service not provisioned by the harness");
    const recipient = `bob-${randomUUID()}@example.com`;
    const inviteToken = `invtok-${randomUUID().replace(/-/g, "")}${randomUUID().replace(/-/g, "")}`;
    const bobIdentity = generateDidKeyIdentity();

    // §3.2 — deliver the token to the 3PID via the email broker.
    const send = await request.post(
      `${mockEmail}/mock/email/verification/send`,
      { data: { to: recipient, token: inviteToken } },
    );
    const sent = await expectJsonOk<{ message_id?: string }>(
      send,
      "mock email send",
    );
    expect(sent.message_id).toBeTruthy();

    // §3.2 — bob sees the token-bearing message in his inbox.
    const inboxResp = await request.get(
      `${mockEmail}/mock/email/verification/inbox?to=${encodeURIComponent(recipient)}`,
    );
    const inbox = await expectJsonOk<{
      messages?: Array<{ token?: string }>;
    }>(inboxResp, "mock email inbox");
    expect(
      (inbox.messages ?? []).some((m) => m.token === inviteToken),
    ).toBeTruthy();

    // §4.1 — bob presents the token + his registered DID; the service
    // atomically consumes it and returns a binding artifact.
    const claim = await request.post(
      `${mockEmail}/mock/email/verification/claim`,
      { data: { token: inviteToken, did: bobIdentity.did } },
    );
    const claimed = await expectJsonOk<{
      binding_proof?: string;
      token_commitment?: string;
    }>(claim, "mock email claim");
    expect(claimed.binding_proof).toBeTruthy();
    expect(claimed.token_commitment).toBeTruthy();

    // §4.1 — the token is single-use; a second claim is rejected (consumed).
    const replay = await request.post(
      `${mockEmail}/mock/email/verification/claim`,
      { data: { token: inviteToken, did: bobIdentity.did } },
    );
    expect(replay.status()).toBe(409);
  });

  // Live since 2026-08-06. The canonical allowlist carrier landed in spec + SDK
  // (2026-08-02, `allowed_third_party_invite_verification_ids`) and in
  // soland's reducer (`apply_invites.rs` reads that top-level component only).
  // Former blocker, now resolved:
  // arkret-work/review/spec-done/2026-08-01-third-party-invite-verification-service-allowlist-has-no-carrier.md
  test("bob submits ak.invite.claim with binding_proof + subject_proof; reducer accepts and converts to membership", async ({
    request,
  }) => {
    // third-party-invites.md §4.1-4.3 — happy path. The did:webvh verification
    // service signs the binding_proof; bob signs the subject_proof; the
    // reducer verifies both, flips pending -> claimed, and seeds an invite
    // membership proposal for bob.
    const ctx = await setupPendingInvite(request, {
      fixtureNonce: "s3-claim",
    });
    const issued = await submitThirdPartyInvite(
      request,
      ctx.aliceToken,
      ctx.alice.id,
      ctx.cell,
      ctx.invitePayload,
    );
    expect(issued.rejected).toHaveLength(0);

    const claimNonce = `claim-${randomUUID()}`;
    const bindingExpiresAt = ctx.cell.expiresAt;
    const bindingProof = signBindingProof({
      cell: ctx.cell,
      verificationService: ctx.verificationService,
      subjectId: ctx.bob.id,
      claimNonce,
      bindingExpiresAt,
    });
    const subjectProof = signSubjectProof({
      cell: ctx.cell,
      subject: ctx.bobIdentity,
      verificationServiceDid: ctx.verificationService.did,
      bindingProof,
      claimNonce,
    });
    const claimPayload = buildClaimPayload({
      cell: ctx.cell,
      subjectId: ctx.bob.id,
      claimNonce,
      bindingProof,
      subjectProof,
    });

    const claim = await submitClaim(
      request,
      ctx.bobToken,
      ctx.bob,
      ctx.cell,
      claimPayload,
    );
    expect(
      claim.rejected,
      `claim rejected: ${JSON.stringify(claim.rejected)}`,
    ).toHaveLength(0);
    expect(claim.accepted.length).toBeGreaterThan(0);

    // Reducer effect: bob is now an invite-membership proposal in the Realm.
    const invitesResp = await request.get(
      `${solandBaseUrl()}/_arkret/self/authz/invites?subject=${encodeURIComponent(ctx.bob.id)}&realm_id=${encodeURIComponent(ctx.realmId)}`,
      {
        headers: {
          ...authHeaders(ctx.bobToken),
          "Arkret-Operation": "ak.self.authz.invites.read.list.v1",
        },
      },
    );
    const invitesBody = await expectJsonOk<{
      invites?: Array<{
        id?: string;
        realm_id?: string;
        invitee?: string;
        state?: string;
        status?: string;
      }>;
    }>(invitesResp, "list claimed invites");
    const claimed = (invitesBody.invites ?? []).find(
      (invite) =>
        invite.realm_id === ctx.realmId && invite.invitee === ctx.bob.id,
    );
    expect(claimed, `claimed invite for ${ctx.bob.id}`).toBeTruthy();
  });

  // Live since 2026-08-06. The canonical allowlist carrier landed in spec + SDK
  // (2026-08-02, `allowed_third_party_invite_verification_ids`) and in
  // soland's reducer (`apply_invites.rs` reads that top-level component only).
  // Former blocker, now resolved:
  // arkret-work/review/spec-done/2026-08-01-third-party-invite-verification-service-allowlist-has-no-carrier.md
  test("E3.1 expired token: reducer rejects claim with expired_invite_token", async ({
    request,
  }) => {
    // third-party-invites.md §4.3 step 2 / §6.1 — an invite past expires_at
    // is force-expired and any claim is refused.
    const ctx = await setupPendingInvite(request, {
      fixtureNonce: "s3-expired",
      expiresInMs: 4_000,
    });
    const issued = await submitThirdPartyInvite(
      request,
      ctx.aliceToken,
      ctx.alice.id,
      ctx.cell,
      ctx.invitePayload,
    );
    expect(issued.rejected).toHaveLength(0);

    // Let the invite cross expires_at before claiming. The reducer
    // force-expires the cell (third-party-invites.md §4.3 step 2) before any
    // binding/subject proof is even inspected.
    await new Promise((resolve) => setTimeout(resolve, 6_000));

    const claimNonce = `claim-${randomUUID()}`;
    const bindingProof = signBindingProof({
      cell: ctx.cell,
      verificationService: ctx.verificationService,
      subjectId: ctx.bob.id,
      claimNonce,
      bindingExpiresAt: ctx.cell.expiresAt,
    });
    const subjectProof = signSubjectProof({
      cell: ctx.cell,
      subject: ctx.bobIdentity,
      verificationServiceDid: ctx.verificationService.did,
      bindingProof,
      claimNonce,
    });
    const claim = await submitClaim(
      request,
      ctx.bobToken,
      ctx.bob,
      ctx.cell,
      buildClaimPayload({
        cell: ctx.cell,
        subjectId: ctx.bob.id,
        claimNonce,
        bindingProof,
        subjectProof,
      }),
    );
    expect(claim.accepted).toHaveLength(0);
    expect(claim.rejectReason).toBe("expired_invite_token");
  });

  // Live since 2026-08-06. The canonical allowlist carrier landed in spec + SDK
  // (2026-08-02, `allowed_third_party_invite_verification_ids`) and in
  // soland's reducer (`apply_invites.rs` reads that top-level component only).
  // Former blocker, now resolved:
  // arkret-work/review/spec-done/2026-08-01-third-party-invite-verification-service-allowlist-has-no-carrier.md
  test("E3.2 wrong DID claim (subject_proof != binding_proof.subject) rejected", async ({
    request,
  }) => {
    // third-party-invites.md §4.3 step 5 — mallory holds the token but the
    // binding_proof names bob. mallory must submit subject_id == her own DID,
    // so binding_proof.subject_id (bob) no longer matches and the reducer
    // refuses to bind the token to the attacker DID.
    const ctx = await setupPendingInvite(request, {
      fixtureNonce: "s3-wrongdid",
    });
    const issued = await submitThirdPartyInvite(
      request,
      ctx.aliceToken,
      ctx.alice.id,
      ctx.cell,
      ctx.invitePayload,
    );
    expect(issued.rejected).toHaveLength(0);

    const malloryIdentity = generateDidKeyIdentity();
    const mallory = didKeyUser("s3-mallory", malloryIdentity);
    const malloryToken = await issueDevSession(request, mallory);
    registerEventSigner({
      actorId: mallory.id,
      deviceId: mallory.deviceId,
      verificationMethod: malloryIdentity.verificationMethod,
      signingSeedB64url: malloryIdentity.signingSeedB64url,
    });

    const claimNonce = `claim-${randomUUID()}`;
    // Verification service still signs a binding_proof for the legitimate
    // subject bob (it never met mallory).
    const bindingProof = signBindingProof({
      cell: ctx.cell,
      verificationService: ctx.verificationService,
      subjectId: ctx.bob.id,
      claimNonce,
      bindingExpiresAt: ctx.cell.expiresAt,
    });
    // mallory signs a subject_proof with HER key and submits as herself.
    const subjectProof = signSubjectProof({
      cell: ctx.cell,
      subject: malloryIdentity,
      verificationServiceDid: ctx.verificationService.did,
      bindingProof,
      claimNonce,
    });
    const claim = await submitClaim(
      request,
      malloryToken,
      mallory,
      ctx.cell,
      buildClaimPayload({
        cell: ctx.cell,
        subjectId: mallory.id,
        claimNonce,
        bindingProof,
        subjectProof,
      }),
    );
    expect(claim.accepted).toHaveLength(0);
    // The binding_proof names bob but mallory submits subject_id == her own
    // DID, so the claim payload fails the subject/binding consistency gate
    // before the token can ever be bound to the attacker DID. soland surfaces
    // this as `schema_violation` with a subject-mismatch detail.
    expect(claim.rejectReason).toBe("schema_violation");
    const detail = claim.rejected[0]?.detail ?? "";
    expect(detail).toContain("subject_id");
  });

  // Live since 2026-08-06. The canonical allowlist carrier landed in spec + SDK
  // (2026-08-02, `allowed_third_party_invite_verification_ids`) and in
  // soland's reducer (`apply_invites.rs` reads that top-level component only).
  // Former blocker, now resolved:
  // arkret-work/review/spec-done/2026-08-01-third-party-invite-verification-service-allowlist-has-no-carrier.md
  test("E3.3 double-claim: second claim of same token rejected (token consumed)", async ({
    request,
  }) => {
    // third-party-invites.md §4.3 step 6 / §6.1 — once a token is claimed the
    // invite is `claimed`; a second claim is refused with duplicate_conflict.
    const ctx = await setupPendingInvite(request, {
      fixtureNonce: "s3-double",
    });
    const issued = await submitThirdPartyInvite(
      request,
      ctx.aliceToken,
      ctx.alice.id,
      ctx.cell,
      ctx.invitePayload,
    );
    expect(issued.rejected).toHaveLength(0);

    const firstNonce = `claim-${randomUUID()}`;
    const firstBinding = signBindingProof({
      cell: ctx.cell,
      verificationService: ctx.verificationService,
      subjectId: ctx.bob.id,
      claimNonce: firstNonce,
      bindingExpiresAt: ctx.cell.expiresAt,
    });
    const firstSubject = signSubjectProof({
      cell: ctx.cell,
      subject: ctx.bobIdentity,
      verificationServiceDid: ctx.verificationService.did,
      bindingProof: firstBinding,
      claimNonce: firstNonce,
    });
    const firstClaim = await submitClaim(
      request,
      ctx.bobToken,
      ctx.bob,
      ctx.cell,
      buildClaimPayload({
        cell: ctx.cell,
        subjectId: ctx.bob.id,
        claimNonce: firstNonce,
        bindingProof: firstBinding,
        subjectProof: firstSubject,
      }),
    );
    expect(
      firstClaim.rejected,
      `first claim rejected: ${JSON.stringify(firstClaim.rejected)}`,
    ).toHaveLength(0);

    // Second claim of the same already-consumed token (fresh nonce) — the
    // invite cell is now `claimed`, so the reducer refuses re-claim.
    const secondNonce = `claim-${randomUUID()}`;
    const secondBinding = signBindingProof({
      cell: ctx.cell,
      verificationService: ctx.verificationService,
      subjectId: ctx.bob.id,
      claimNonce: secondNonce,
      bindingExpiresAt: ctx.cell.expiresAt,
    });
    const secondSubject = signSubjectProof({
      cell: ctx.cell,
      subject: ctx.bobIdentity,
      verificationServiceDid: ctx.verificationService.did,
      bindingProof: secondBinding,
      claimNonce: secondNonce,
    });
    const secondClaim = await submitClaim(
      request,
      ctx.bobToken,
      ctx.bob,
      ctx.cell,
      buildClaimPayload({
        cell: ctx.cell,
        subjectId: ctx.bob.id,
        claimNonce: secondNonce,
        bindingProof: secondBinding,
        subjectProof: secondSubject,
      }),
    );
    expect(secondClaim.accepted).toHaveLength(0);
    expect(secondClaim.rejectReason).toBe("duplicate_conflict");
  });
});

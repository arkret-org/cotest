// Third-party invite (email -> token commitment -> binding proof -> claim)
// Contract: e2e/scenarios/invites/third-party.md
// Spec: sync/third-party-invites.md section 3-4

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { expect, test } from "../../helpers/arkret-test";
import type { APIRequestContext } from "../../helpers/arkret-test";
import {
  mockEmailBaseUrl,
  colandBaseUrl,
  colandServiceId,
  colandServiceResolution,
} from "../../helpers/env";
import {
  authHeaders,
  accountActorId,
  acceptInviteApi,
  requireDidCoreId,
  canonicalJson,
  canonicalTimestamp,
  cotestWire,
  registeredEventSigningSeedB64url,
  registeredEventVerificationMethod,
  createRealmApi,
  expectJsonOk,
  projectDidToCoreId,
  readCurrentRealmPolicyBundleApi,
  retypeEventDerivedId,
  signedEventEnvelope,
  assertAuthoritySubmitOutcome,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/coland-api";
import {
  ensureRegistered,
  issueUserSession,
  registeredPrincipalControlIdentity,
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
import { sdkInviteSubjectProof } from "../../helpers/coland-api/wire-client";
import { ed25519PrivateKeySeedB64url } from "../../helpers/encoding";
import {
  buildWebvhGenesisEntry,
  generateWebvhKey,
  submitPrincipalGenesisEntry,
} from "../../helpers/webvh-api";

async function createVerificationService(
  request: APIRequestContext,
  seed: string,
): Promise<DidKeyIdentity> {
  const signingKey = generateWebvhKey();
  const built = buildWebvhGenesisEntry({
    baseUrl: colandBaseUrl(),
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
  await submitPrincipalGenesisEntry(request, colandBaseUrl(), built);
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

// Single self submissions return the exact accepted RealmCommit. Rejections
// use the registered Problem response; accepted/rejected below are fixture views.
async function submitSelfEvent(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
): Promise<SelfEventsOutcome> {
  const response = await request.post(
    `${colandBaseUrl()}/_arkret/self/events`,
    {
      headers: { ...authHeaders(token, "POST", `${colandBaseUrl()}/_arkret/self/events`), "content-type": "application/json" },
      data: canonicalJson({ event: envelope }),
    },
  );
  const text = await response.text();
  const body = JSON.parse(text) as Record<string, unknown>;
  const accepted: string[] = [];
  const rejected: SelfEventsOutcome["rejected"] = [];
  if ([200, 201].includes(response.status())) {
    assertAuthoritySubmitOutcome(body, envelope, "3PID single self submission");
    accepted.push(String((body.commit as Record<string, unknown>).event_ref));
  } else {
    const reason = wireErrCode(body);
    expect(reason, `3PID submission has no registered Problem type: ${text}`)
      .toBeDefined();
    rejected.push({
      reason_code: reason,
      detail: typeof body.detail === "string" ? body.detail : undefined,
    });
  }
  const rejectReason = rejected[0]?.reason_code;
  return {
    status: response.status(),
    accepted,
    rejected,
    rejectReason,
    body,
  };
}

// Restate the current Realm policy bundle with the verification-service
// allowlist the reducer re-checks (third-party-invites.md §2.1 Allowlist MUST,
// §4.3 step 4 reads it from the `realm_policy_bundle` typed current result).
// The allowlist entries are did_core_id and compared byte-for-byte against the
// payload's verification_id, so the DID is projected first.
async function allowlistVerificationService(
  request: APIRequestContext,
  token: string,
  ownerId: string,
  realmId: string,
  serviceId: string,
) {
  const currentPolicy = await readCurrentRealmPolicyBundleApi(request, token, realmId);
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId: ownerId,
      realmId,
      kind: "ak.realm.policy_bundle",
      payload: {
        ...currentPolicy,
        policy_revision: Number(currentPolicy.policy_revision) + 1,
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
  claimantToken: string,
  claimant: JointUser,
  cell: ThirdPartyInviteCell,
  claimPayload: Record<string, unknown>,
): Promise<SelfEventsOutcome> {
  // The claimant presents the out-of-band claim; its Account Station binds
  // fresh producer evidence without a membership-private frontier read.
  return await submitSelfEvent(
    request,
    claimantToken,
    signedEventEnvelope({
      actorId: claimant.id,
      realmId: cell.realmId,
      kind: "ak.invite.claim",
      payload: claimPayload,
    }),
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
    const bob = uniqueUser(`${opts.fixtureNonce}-bob`);
    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    const bobSubjectIdentity = await registeredPrincipalControlIdentity(request, bob);
    const aliceToken = await issueUserSession(request, alice);
    const bobToken = await issueUserSession(request, bob);
    // The Event keeps its accepted PCR device producer. Its subject proof
    // instead proves native DID control from the registration's update key.
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
      bobIdentity: bobSubjectIdentity,
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
    // third-party-invites.md §2.1 Allowlist (MUST): a verification service
    // outside the current policy bundle's
    // `allowed_third_party_invite_verification_ids` MUST NOT be bound by an
    // invite, so the same payload is refused until the owner allowlists it.
    const unlisted = await submitThirdPartyInvite(
      request,
      ctx.aliceToken,
      ctx.alice.id,
      ctx.cell,
      ctx.invitePayload,
    );
    expect(unlisted.accepted).toHaveLength(0);
    expect(unlisted.rejectReason).toBe("capability_denied");
    await allowlistVerificationService(
      request,
      ctx.aliceToken,
      ctx.alice.id,
      ctx.realmId,
      ctx.verificationService.did,
    );
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
  // coland's reducer (`apply_invites.rs` reads that top-level component only).
  // Former blocker and current live-verification owner:
  // arkret-work/tasks/impl-tailin/2026-08-02-account-status-allowlist-and-personal-blocklist-downstream.md
  test("bob submits ak.invite.claim with binding_proof + subject_proof; reducer accepts and records claimed lifecycle", async ({
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

    const deviceMethod = registeredEventVerificationMethod(ctx.bob.id, ctx.bob.deviceId);
    const deviceSeed = registeredEventSigningSeedB64url(ctx.bob.id);
    expect(Boolean(deviceMethod && deviceSeed), "negative proof uses the accepted PCR device key").toBe(true);
    const deviceSubjectProof = sdkInviteSubjectProof({
      subjectAccountId: { principal_id: ctx.bob.id, station_id: colandServiceId() },
      inviteId: ctx.cell.inviteId!, realmId: ctx.cell.realmId,
      tokenCommitment: ctx.cell.tokenCommitment, claimNonce,
      verificationId: projectDidToCoreId(ctx.verificationService.did), bindingProof,
      verificationMethod: deviceMethod!, subjectDid: ctx.bobIdentity.did,
      rootPublicKeyMultibase: ctx.bobIdentity.rootPublicKeyMultibase,
      recoveryKey: ctx.bobIdentity.recoveryKey,
      negativeDeviceSigningSeedB64url: deviceSeed!,
    });
    const deviceClaim = await submitClaim(request, ctx.bobToken,
      ctx.bob, ctx.cell, { ...claimPayload, subject_proof: deviceSubjectProof });
    expect(deviceClaim.accepted).toHaveLength(0);
    expect(deviceClaim.rejected, "PCR device proof cannot replace DID subject authority").toHaveLength(1);

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

    // Claim creates a subject-bound proposal, not a directed private delivery
    // or joined membership. Verify its accepted source and typed lifecycle
    // through Alice's already-authorized Realm view.
    const acceptedCommit = claim.body.commit as Record<string, unknown>;
    const acceptedUrl = `${colandBaseUrl()}/_arkret/self/committed-events/${claim.accepted[0]}`;
    const accepted = await expectJsonOk<Record<string, any>>(
      await request.get(acceptedUrl, {
        headers: authHeaders(ctx.aliceToken, "GET", acceptedUrl),
      }),
      "read the exact accepted third-party claim",
    );
    expect(accepted.commit).toEqual(acceptedCommit);
    expect(accepted.event.kind).toBe("ak.invite.claim");
    expect(accepted.event.event_id).toBe(claim.accepted[0]);
    expect(accepted.event.payload).toEqual(claimPayload);
    expect(accepted.event.payload.subject_account_id).toEqual({
      principal_id: ctx.bob.id,
      station_id: colandServiceId(),
    });
    const readVerifiedSnapshot = async () => {
      const snapshotUrl = `${colandBaseUrl()}/_arkret/self/realm-state-snapshot/head?realm_id=${encodeURIComponent(ctx.realmId)}`;
      const snapshot = await expectJsonOk<Record<string, any>>(
        await request.get(snapshotUrl, {
          headers: authHeaders(ctx.aliceToken, "GET", snapshotUrl),
        }),
        "read third-party claim lifecycle at the accepted Realm cut",
      );
      const authorityRequest = { realm_id: ctx.realmId, nonce: randomBytes(32).toString("base64url") };
      const authorityResponse = await request.post(`${colandBaseUrl()}/_arkret/open/realm-authority/bundle`, {
        headers: { "content-type": "application/json" }, data: canonicalJson(authorityRequest),
      });
      const authorityBundle = await expectJsonOk(authorityResponse, "claim Realm authority");
      const serviceResolution = await expectJsonOk(
        await request.get(colandServiceResolution().resolution_url), "governing Station resolution",
      );
      expect(cotestWire("verify-realm-state-snapshot", {
        snapshot, expected_snapshot_id: snapshot.snapshot_id,
        authority_request: authorityRequest, authority_bundle: authorityBundle,
        trusted_service_id: colandServiceId(), service_resolution: serviceResolution,
      })).toEqual({ verified: true });
      return snapshot;
    };
    const snapshot = await readVerifiedSnapshot();
    const lifecycle = snapshot.current_state_entries.filter((row: Record<string, any>) =>
      row.selector.kind === "invite_lifecycle" && row.selector.invite_id === ctx.cell.inviteId);
    expect(lifecycle).toHaveLength(1);
    expect(lifecycle[0].value).toBe("claimed");
    expect(lifecycle[0].source_stream_ref).toEqual(acceptedCommit.stream_ref);
    expect(lifecycle[0].revision).toEqual({
      commit_id: acceptedCommit.commit_id, stream_position: acceptedCommit.stream_position,
    });

    // Holder-private authz listing requires a directed delivery. A claimed
    // placeholder must not fabricate that independent notification state.
    const invitesResp = await request.get(
      `${colandBaseUrl()}/_arkret/self/authz/invites?realm_id=${encodeURIComponent(ctx.realmId)}`,
      {
        headers: {
          ...authHeaders(ctx.bobToken, "GET", `${colandBaseUrl()}/_arkret/self/authz/invites?realm_id=${encodeURIComponent(ctx.realmId)}`),
          "Arkret-Operation": "ak.self.authz.invites.read.list.v1",
        },
      },
    );
    const invitesBody = await expectJsonOk<{
      invites?: Array<{
        id?: string;
        realm_id?: string;
        invitee_account_id?: {
          principal_id?: string;
          station_id?: string;
        };
        state?: string;
      }>;
    }>(invitesResp, "list claimed invites");
    expect((invitesBody.invites ?? []).filter((invite) => invite.id === ctx.cell.inviteId))
      .toHaveLength(0);

    // Membership is a separate explicit acceptance after the claimed proposal.
    const acceptance = await acceptInviteApi(request, ctx.bobToken, ctx.bob.id,
      ctx.realmId, ctx.cell.inviteId!, { previousState: "claimed", directed: false });
    const acceptanceCommit = acceptance.commit as Record<string, unknown>;
    expect(acceptanceCommit.event_ref).toBeTruthy();
    const joinedSnapshot = await readVerifiedSnapshot();
    const joinedLifecycle = joinedSnapshot.current_state_entries.filter((row: Record<string, any>) =>
      row.selector.kind === "invite_lifecycle" && row.selector.invite_id === ctx.cell.inviteId);
    expect(joinedLifecycle).toHaveLength(1);
    expect(joinedLifecycle[0].value).toBe("accepted");
    expect(joinedLifecycle[0].source_stream_ref).toEqual(acceptanceCommit.stream_ref);
    expect(joinedLifecycle[0].revision).toEqual({
      commit_id: acceptanceCommit.commit_id, stream_position: acceptanceCommit.stream_position,
    });
    // governance-objects.md section 5.3: one acceptance atomically writes
    // the accepted invite lifecycle and the full subject Actor's join.
    const joinedMember = joinedSnapshot.current_state_entries.filter((row: Record<string, any>) =>
      row.selector.kind === "member_state" &&
      canonicalJson(row.selector.actor_id) === canonicalJson(accountActorId(ctx.bob.id)));
    expect(joinedMember).toHaveLength(1);
    expect(joinedMember[0].value.membership).toBe("join");
    expect(joinedMember[0].source_stream_ref).toEqual(acceptanceCommit.stream_ref);
    expect(joinedMember[0].revision).toEqual({
      commit_id: acceptanceCommit.commit_id, stream_position: acceptanceCommit.stream_position,
    });
  });

  // Live since 2026-08-06. The canonical allowlist carrier landed in spec + SDK
  // (2026-08-02, `allowed_third_party_invite_verification_ids`) and in
  // coland's reducer (`apply_invites.rs` reads that top-level component only).
  // Former blocker and current live-verification owner:
  // arkret-work/tasks/impl-tailin/2026-08-02-account-status-allowlist-and-personal-blocklist-downstream.md
  test("E3.1 expired token: claim failure is wire-indistinguishable", async ({
    request,
  }) => {
    // third-party-invites.md §4.3 step 2 / §6.1: a claim signed after
    // expires_at is refused without changing shared invite state.
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

    // Sign the claim after expires_at. The reducer compares the signed Event
    // timestamp, not its local receive time, before binding/subject proofs.
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
    expect(claim.rejectReason).toBe("not_found");
  });

  // Live since 2026-08-06. The canonical allowlist carrier landed in spec + SDK
  // (2026-08-02, `allowed_third_party_invite_verification_ids`) and in
  // coland's reducer (`apply_invites.rs` reads that top-level component only).
  // Former blocker and current live-verification owner:
  // arkret-work/tasks/impl-tailin/2026-08-02-account-status-allowlist-and-personal-blocklist-downstream.md
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

    const mallory = uniqueUser("s3-mallory");
    await ensureRegistered(request, mallory);
    const mallorySubjectIdentity = await registeredPrincipalControlIdentity(request, mallory);
    const malloryToken = await issueUserSession(request, mallory);

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
      subject: mallorySubjectIdentity,
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
    // The binding_proof names Bob's AccountId while Mallory submits her own
    // subject_account_id, so the consistency gate must reject the claim before
    // the token can be bound to the attacker. Keep the externally visible
    // detail non-enumerating as required by third-party-invites.md section 6.
    expect(claim.rejectReason).toBe("schema_violation");
    const detail = claim.rejected[0]?.detail ?? "";
    expect(detail).not.toContain(ctx.bob.id);
    expect(detail).not.toContain(mallory.id);
    expect(detail).not.toContain(ctx.cell.tokenCommitment);
  });

  // Live since 2026-08-06. The canonical allowlist carrier landed in spec + SDK
  // (2026-08-02, `allowed_third_party_invite_verification_ids`) and in
  // coland's reducer (`apply_invites.rs` reads that top-level component only).
  // Former blocker and current live-verification owner:
  // arkret-work/tasks/impl-tailin/2026-08-02-account-status-allowlist-and-personal-blocklist-downstream.md
  test("E3.3 double-claim: second claim of same token is wire-indistinguishable", async ({
    request,
  }) => {
    // third-party-invites.md §4.3 step 6 / §6.1 — once a token is claimed the
    // invite is `claimed`, and a second claim is refused.
    //
    // conformance-vectors.md §9.7.1 fixes what the claimant may learn: the
    // reducer's own reason for case 7 (claim nonce / token replay) is
    // `duplicate_conflict`, but "所有失败通过外部 claim surface 返回不可枚举
    // `not_found` 或同形态响应；具体 reason 只进入 audit / per-event rejected
    // diagnostics". Asserting the internal reason here would require the claim
    // surface to be an enumeration oracle that distinguishes "already claimed"
    // from "no such invite" — exactly what that clause forbids, and what E3.1
    // already pins for the expired-token case.
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
    expect(firstClaim.accepted, "the first claim must actually be accepted").toHaveLength(1);

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
    expect(secondClaim.rejectReason).toBe("not_found");
  });
});

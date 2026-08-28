// Contact graph (same principal server): add-friend / direct conversation /
// realm-pull via consent_grant evidence / graded disclosure / block.
//
// Protocol face: `/_arkret/self/contacts/*`,
// `/_arkret/self/direct-conversations/resolve`,
// `/_arkret/self/invite-receive-policy`, `/_arkret/peer/invites`.
// Spec refs: contact-and-direct-conversation.md §3-§4, invite-addressing.md
// §2/§5/§5.1, consent-model.md §2-§3.
//
// Uses the `requested_scopes:[...]` contract (NOT the `/_soland` + `scope`
// surface that consent-grant.spec.ts exercises).

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import { expectStructurallyIdentical } from "../../helpers/secret-safe";
import { createDpopUserSession } from "../../helpers/users";
import { authHeaders, createRealmApi } from "../../helpers/soland-api";
import {
  acceptInviteArkret,
  contactRow,
  countInvitesFor,
  deliverInviteExplicitAddress,
  deliverInviteWithConsentGrant,
  grantInviteConsentArkret,
  getInviteReceivePolicyArkret,
  listAuthzInvitesArkret,
  requestContactArkret,
  prepareDirectConversationIdentityArkret,
  resolveDirectConversationArkret,
  respondContactArkret,
  revokeInviteConsentArkret,
  seedDirectConversationIdentityArkret,
  setInviteReceivePolicyArkret,
  tombstoneContactArkret,
} from "../../helpers/contact-api";

// Each test provisions fresh DIDs, so parallel execution is safe.

async function activeContactUser(request: APIRequestContext, prefix: string) {
  const session = await createDpopUserSession(request, prefix);
  if (!session) {
    throw new Error("contact graph requires the joint Coauth stack");
  }
  return { user: session.user, token: session.grantJwt };
}

test.describe("contact graph (same principal server)", () => {
  // S1: Contact facts and receipts establish the bidirectional projection.
  // Consent is a separate holder-private component and is not synthesized by
  // Contact admission.
  test("S1 add friend with greeting + invite scope, accept -> bidirectional projection", async ({
    request,
  }) => {
    const [aliceSession, bobSession] = await Promise.all([
      activeContactUser(request, "cg-s1-alice"),
      activeContactUser(request, "cg-s1-bob"),
    ]);
    const { user: alice, token: aliceToken } = aliceSession;
    const { user: bob, token: bobToken } = bobSession;

    const greeting = `hello bob, let's connect ${Date.now()}`;
    const { outcome: reqOutcome } = await requestContactArkret(
      request,
      aliceToken,
      bob.id,
      { requestedScopes: ["invite"], message: greeting },
    );
    expect(reqOutcome.state).toBe("pending_outgoing");
    expect(reqOutcome.request_event_ref).toMatch(/^ak:event:/);
    expect(reqOutcome.request_acceptance_receipt.core).toBeTruthy();

    // Bob sees the incoming request.
    const bobIncoming = await contactRow(request, bobToken, alice.id);
    expect(bobIncoming?.state).toBe("pending_incoming");

    const respondOutcome = await respondContactArkret(request, bobToken, {
      requestId: reqOutcome.request_event_ref,
      requesterId: alice.id,
      action: "accept",
      grantedScopes: ["invite"],
    });
    expect(respondOutcome.state).toBe("accepted");
    expect(respondOutcome.response_event_ref).toMatch(/^ak:event:/);
    expect(respondOutcome.acceptance_receipt).toBeTruthy();

    // Both sides now list each other as accepted.
    const aliceRow = await contactRow(request, aliceToken, bob.id);
    const bobRow = await contactRow(request, bobToken, alice.id);
    expect(aliceRow?.state).toBe("accepted");
    expect(bobRow?.state).toBe("accepted");

    // Bidirectional invite scope (both granted invite to each other).
    expect(aliceRow?.bidirectional_scopes).toContain("invite");
    expect(bobRow?.bidirectional_scopes).toContain("invite");

    expect(aliceRow?.next_prepare_input).toBeTruthy();
    expect(bobRow?.next_prepare_input).toBeTruthy();
  });

  // S2: add friend -> reject -> state=rejected, no consent written.
  test("S2 add friend, reject -> rejected, no bidirectional consent", async ({
    request,
  }) => {
    const [aliceSession, bobSession] = await Promise.all([
      activeContactUser(request, "cg-s2-alice"),
      activeContactUser(request, "cg-s2-bob"),
    ]);
    const { user: alice, token: aliceToken } = aliceSession;
    const { user: bob, token: bobToken } = bobSession;

    const { outcome } = await requestContactArkret(
      request,
      aliceToken,
      bob.id,
      { requestedScopes: ["invite"] },
    );
    const reject = await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requesterId: alice.id,
      action: "reject",
    });
    expect(reject.state).toBe("rejected");
    // Reject grants no scopes: bob did not grant alice anything.
    const bobRow = await contactRow(request, bobToken, alice.id);
    expect(bobRow?.state).toBe("rejected");
    expect(bobRow?.granted_by_me ?? []).not.toContain("invite");
    expect(bobRow?.bidirectional_scopes ?? []).toHaveLength(0);
  });

  // S3: resolve is query-only. It returns only the exact founding authority
  // evidence the derived founder needs; it never allocates coordinates or
  // returns unsigned Event/MLS materialization drafts.
  test("S3 friends via direct_message -> founder authority input", async ({
    request,
  }) => {
    const [aliceSession, bobSession] = await Promise.all([
      activeContactUser(request, "cg-s3-alice"),
      activeContactUser(request, "cg-s3-bob"),
    ]);
    const { user: alice, token: aliceToken } = aliceSession;
    const { user: bob, token: bobToken } = bobSession;
    await Promise.all([
      seedDirectConversationIdentityArkret(request, aliceToken, alice),
      seedDirectConversationIdentityArkret(request, bobToken, bob),
    ]);

    // Establish a bidirectional direct_message contact. direct conversation
    // resolve requires (1) accepted contact for the pair and (2) the PEER
    // granted the resolver direct_message consent. Make both directions grant
    // direct_message so either side can resolve.
    const { outcome } = await requestContactArkret(
      request,
      aliceToken,
      bob.id,
      { requestedScopes: ["direct_message"] },
    );
    await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requesterId: alice.id,
      action: "accept",
      grantedScopes: ["direct_message"],
    });
    await expect
      .poll(async () => (await contactRow(request, aliceToken, bob.id))?.state, {
        timeout: 30_000,
        intervals: [100, 250, 500, 1_000],
      })
      .toBe("accepted");
    await expect
      .poll(async () => (await contactRow(request, bobToken, alice.id))?.state, {
        timeout: 30_000,
        intervals: [100, 250, 500, 1_000],
      })
      .toBe("accepted");

    // The normal Contact branch assigns founding authority to the responder.
    // Alice is therefore required to wait; this state never transfers
    // authority by timeout or recovery policy.
    const waiting = await resolveDirectConversationArkret(
      request,
      aliceToken,
      bob.id,
    );
    expect(waiting.state).toBe("awaiting_founder");

    const resolved = await resolveDirectConversationArkret(
      request,
      bobToken,
      alice.id,
    );
    expect(resolved.state).toBe("creation_required");
    expect(
      resolved.next_founding_input?.founding_authority_evidence,
    ).toBeTruthy();
    expect(resolved).not.toHaveProperty("realm_id");
    expect(resolved).not.toHaveProperty("main_strand_id");
    expect(resolved).not.toHaveProperty("materialization_draft");

    const retry = await resolveDirectConversationArkret(
      request,
      bobToken,
      alice.id,
    );
    expectStructurallyIdentical(
      retry.next_founding_input,
      resolved.next_founding_input,
      "direct-conversation founding input must be deterministic across retries",
    );
  });

  // S4 (core closed loop): already friends (invite scope) -> use
  // invite_consent_grant_ref as consent_grant evidence to pull the peer into a
  // NEW realm (no locator) -> private delivery high-trust outcome -> peer lists
  // it in authz/invites -> peer ak.invite.accept -> peer is a realm member.
  test("S4 consent_grant evidence pulls friend into a new realm (closed loop)", async ({
    request,
  }) => {
    const [aliceSession, bobSession] = await Promise.all([
      activeContactUser(request, "cg-s4-alice"),
      activeContactUser(request, "cg-s4-bob"),
    ]);
    const { user: alice, token: aliceToken } = aliceSession;
    const { user: bob, token: bobToken } = bobSession;

    // Contact admission and holder-private Consent are separate protocols.
    const { outcome } = await requestContactArkret(
      request,
      aliceToken,
      bob.id,
      { requestedScopes: ["invite"] },
    );
    await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requesterId: alice.id,
      action: "accept",
      grantedScopes: ["invite"],
    });

    const consent = await grantInviteConsentArkret(
      request,
      bobToken,
      bob,
      alice.id,
    );
    const grantRef = consent.eventRef;

    // alice creates a NEW realm and pulls bob in using the consent_grant ref.
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S4 pull realm ${Date.now()}`,
      ownerId: alice.id,
    });

    const {
      outcome: delivery,
      inviteId,
      sealBasis,
    } = await deliverInviteWithConsentGrant(request, {
      inviterId: alice.id,
      inviterToken: aliceToken,
      realmId,
      inviteeId: bob.id,
      consentGrantRef: grantRef!,
      originServer: "default",
      recipientServer: "default",
    });
    // High-trust consent_grant: accepted + disclosed_outcome=delivered.
    expect(delivery.status).toBe("accepted");
    expect(delivery.disclosed_outcome).toBe("delivered");

    // bob lists the pending invite.
    const invites = await listAuthzInvitesArkret(request, bobToken);
    const invite = invites.find(
      (i) => i.realm_id === realmId && i.invitee_id === bob.id,
    );
    expect(invite, "bob pending invite for the new realm").toBeTruthy();
    expect(invite!.id).toBe(inviteId);

    // bob accepts -> becomes a realm member.
    await acceptInviteArkret(request, bobToken, {
      accepterId: bob.id,
      realmId,
      inviteId: invite!.id,
      sealBasis,
    });
    await expect
      .poll(
        async () => {
          const realmUrl = `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
          const resp = await request.get(realmUrl, {
            headers: authHeaders(bobToken, "GET", realmUrl),
          });
          if (!resp.ok()) return false;
          const realm = await resp.json();
          return (
            Array.isArray(realm.members) && realm.members.includes(bob.id)
          );
        },
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBeTruthy();
  });

  // S5: stranger pulls via explicit_address only -> opaque outcome (no
  // disclosed_outcome), quarantined/dropped, recipient is not a member.
  test("S5 stranger explicit_address pull -> opaque + not a member", async ({
    request,
  }) => {
    const [mallorySession, victimSession] = await Promise.all([
      activeContactUser(request, "cg-s5-mallory"),
      activeContactUser(request, "cg-s5-victim"),
    ]);
    const { user: mallory, token: malloryToken } = mallorySession;
    const { user: victim, token: victimToken } = victimSession;

    const realmId = await createRealmApi(request, malloryToken, {
      title: `S5 stranger realm ${Date.now()}`,
      ownerId: mallory.id,
    });

    const { outcome } = await deliverInviteExplicitAddress(request, {
      inviterId: mallory.id,
      inviterToken: malloryToken,
      realmId,
      inviteeId: victim.id,
      originServer: "default",
      recipientServer: "default",
    });
    // Default policy quarantines explicit_address; low-trust disclosure is
    // opaque (no disclosed_outcome).
    expect(outcome.status).toBe("deferred");
    expect(outcome.disclosed_outcome).toBeUndefined();

    // Victim has no pending invite (quarantined, not notified).
    const invites = await listAuthzInvitesArkret(request, victimToken);
    expect(
      countInvitesFor(invites, realmId, victim.id),
      "quarantined explicit_address invite must not surface to the invitee",
    ).toBe(0);
  });

  // S6: block (tombstone block_peer=true) -> peer pulls via any evidence ->
  // drop + opaque.
  test("S6 block_peer then pull -> dropped + opaque", async ({ request }) => {
    const [aliceSession, bobSession] = await Promise.all([
      activeContactUser(request, "cg-s6-alice"),
      activeContactUser(request, "cg-s6-bob"),
    ]);
    const { user: alice, token: aliceToken } = aliceSession;
    const { user: bob, token: bobToken } = bobSession;

    // Establish the Contact, then separately grant holder-private invite
    // consent from alice to bob.
    const { outcome } = await requestContactArkret(
      request,
      bobToken,
      alice.id,
      { requestedScopes: ["invite"] },
    );
    await respondContactArkret(request, aliceToken, {
      requestId: outcome.request_event_ref,
      requesterId: bob.id,
      action: "accept",
      grantedScopes: ["invite"],
    });
    await expect
      .poll(async () => (await contactRow(request, aliceToken, bob.id))?.state, {
        timeout: 30_000,
        intervals: [100, 250, 500, 1_000],
      })
      .toBe("accepted");
    const consent = await grantInviteConsentArkret(
      request,
      aliceToken,
      alice,
      bob.id,
    );
    const grantRef = consent.eventRef;

    // alice blocks bob.
    const tomb = await tombstoneContactArkret(request, aliceToken, bob.id, {
      blockPeer: true,
    });
    expect(tomb.state).toBe("tombstoned");
    const policy = await getInviteReceivePolicyArkret(request, aliceToken);
    expect(policy.denied_subject_ids ?? []).toContain(bob.id);

    // bob tries to pull alice into a realm with the (now revoked) consent_grant.
    const realmId = await createRealmApi(request, bobToken, {
      title: `S6 blocked realm ${Date.now()}`,
      ownerId: bob.id,
    });
    const { outcome: delivery } = await deliverInviteWithConsentGrant(request, {
      inviterId: bob.id,
      inviterToken: bobToken,
      realmId,
      inviteeId: alice.id,
      consentGrantRef: grantRef!,
      originServer: "default",
      recipientServer: "default",
    });
    // denied_subject_ids hit: drop + opaque (no disclosed_outcome leak).
    expect(delivery.status).toBe("deferred");
    expect(delivery.disclosed_outcome).toBeUndefined();

    const invites = await listAuthzInvitesArkret(request, aliceToken);
    expect(
      countInvitesFor(invites, realmId, alice.id),
      "denied_subject_ids invite must be dropped, not delivered to the invitee",
    ).toBe(0);
  });

  // S7: revoked consent evidence is downgraded to explicit-address trust.
  // Quarantine remains holder-private even when low-trust outcome disclosure
  // is requested, so the sender receives only the deferred status.
  test("S7 revoked invite consent is downgraded and quarantine remains opaque", async ({
    request,
  }) => {
    const [aliceSession, bobSession] = await Promise.all([
      activeContactUser(request, "cg-s7-alice"),
      activeContactUser(request, "cg-s7-bob"),
    ]);
    const { user: alice, token: aliceToken } = aliceSession;
    const { user: bob, token: bobToken } = bobSession;

    // Contact admission does not synthesize Consent. Alice separately grants
    // bob an invite consent dot and later revokes that exact dot.
    const { outcome } = await requestContactArkret(
      request,
      bobToken,
      alice.id,
      { requestedScopes: ["invite"] },
    );
    await respondContactArkret(request, aliceToken, {
      requestId: outcome.request_event_ref,
      requesterId: bob.id,
      action: "accept",
      grantedScopes: ["invite"],
    });
    const consent = await grantInviteConsentArkret(
      request,
      aliceToken,
      alice,
      bob.id,
    );
    const grantRef = consent.eventRef;

    await revokeInviteConsentArkret(request, aliceToken, alice, consent);

    // bob pulls alice using the now-revoked consent_grant ref. The grant fails
    // to verify and is downgraded to explicit_address (low trust). Default
    // policy quarantines explicit_address. Because the subject (alice) did NOT
    // block bob, low_trust disclosure default is opaque -> no disclosed_outcome.
    // We assert the delivery is deferred and the peer is not notified; the
    // explicit-feedback variant requires the subject to opt low_trust=outcome.
    const realmId = await createRealmApi(request, bobToken, {
      title: `S7 revoked realm ${Date.now()}`,
      ownerId: bob.id,
    });

    // Opt alice into low-trust outcome disclosure. Quarantine remains an
    // intentional exception: it is holder-private consent state and therefore
    // never discloses whether the holder retained the invite.
    const policy = await getInviteReceivePolicyArkret(request, aliceToken);
    await setInviteReceivePolicyArkret(request, aliceToken, {
      ...policy,
      disclosure: { high_trust: "outcome", low_trust: "outcome" },
    });

    const { outcome: delivery } = await deliverInviteWithConsentGrant(request, {
      inviterId: bob.id,
      inviterToken: bobToken,
      realmId,
      inviteeId: alice.id,
      consentGrantRef: grantRef!,
      originServer: "default",
      recipientServer: "default",
    });
    expect(delivery.status).toBe("deferred");
    expect(delivery.disclosed_outcome).toBeUndefined();

    // alice is not actually a member.
    const invites = await listAuthzInvitesArkret(request, aliceToken);
    expect(
      countInvitesFor(invites, realmId, alice.id),
      "revoked-consent invite must stay quarantined and holder-private",
    ).toBe(0);
  });

  // S8: realm member pulled into a Circle without consent. Now implemented and
  // run for real in `identity/circle-member.spec.ts` (soland ships the
  // `/_arkret/self/circles/*` admin surface — AKP-0007). Kept here as a
  // pointer so the contact-graph table stays self-documenting.
  test("S8 circle member manage without consent", async ({ request }) => {
    test.skip(
      true,
      "moved to identity/circle-member.spec.ts (real run): admin one-way pull into a Circle, pulled actor does zero operations",
    );
    void request;
  });
});

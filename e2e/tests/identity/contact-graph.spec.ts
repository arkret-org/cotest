// Contact graph (same principal server): add-friend / direct conversation /
// realm-pull via consent_grant evidence / graded disclosure / block.
//
// Protocol face: `/_arkret/self/contacts/*`,
// `/_arkret/self/direct-conversations/resolve`,
// `/_arkret/self/invite-receive-policy`, `/_arkret/peer/invites`.
// Spec refs: contact-and-direct-conversation.md §3-§4, invite-addressing.md
// §2/§5/§5.1, consent-model.md §2-§3.
//
// New `requested_scopes:[...]` contract (NOT the legacy `/_soland` + `scope`
// surface that consent-grant.spec.ts exercises).

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { expectStructurallyIdentical } from "../../helpers/secret-safe";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import { authHeaders, createRealmApi } from "../../helpers/soland-api";
import {
  acceptInviteArkret,
  contactRow,
  countInvitesFor,
  deliverInviteExplicitAddress,
  deliverInviteWithConsentGrant,
  getInviteReceivePolicyArkret,
  listAuthzInvitesArkret,
  requestContactArkret,
  prepareDirectConversationIdentityArkret,
  resolveDirectConversationArkret,
  respondContactArkret,
  seedDirectConversationIdentityArkret,
  setInviteReceivePolicyArkret,
  tombstoneContactArkret,
} from "../../helpers/contact-api";

// Each test provisions fresh DIDs, so parallel execution is safe.

test.describe("contact graph (same principal server)", () => {
  // S1: add friend with greeting + invite scope -> accept -> both accepted,
  // message passthrough, bidirectional scope, holder row carries a legal
  // ak:event invite_consent_grant_ref.
  test("S1 add friend with greeting + invite scope, accept -> bidirectional + invite_consent_grant_ref", async ({
    request,
  }) => {
    const alice = uniqueUser("cg-s1-alice");
    const bob = uniqueUser("cg-s1-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);

    const greeting = `hello bob, let's connect ${Date.now()}`;
    const { outcome: reqOutcome } = await requestContactArkret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["invite"], message: greeting },
    );
    expect(reqOutcome.state).toBe("pending_outgoing");
    expect(reqOutcome.request_event_ref).toMatch(/^ak:event:/);
    // The requester-side contact-managed grant is event-backed.
    expect(reqOutcome.requester_consent_refs.length).toBeGreaterThan(0);
    expect(reqOutcome.requester_consent_refs[0]).toMatch(/^ak:event:/);

    // Bob sees the incoming request.
    const bobIncoming = await contactRow(request, bobToken, alice.did);
    expect(bobIncoming?.state).toBe("pending_incoming");

    const respondOutcome = await respondContactArkret(request, bobToken, {
      requestId: reqOutcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["invite"],
    });
    expect(respondOutcome.state).toBe("accepted");
    expect(respondOutcome.consent_grant_refs.length).toBeGreaterThan(0);
    expect(respondOutcome.consent_grant_refs[0]).toMatch(/^ak:event:/);

    // Both sides now list each other as accepted.
    const aliceRow = await contactRow(request, aliceToken, bob.did);
    const bobRow = await contactRow(request, bobToken, alice.did);
    expect(aliceRow?.state).toBe("accepted");
    expect(bobRow?.state).toBe("accepted");

    // Bidirectional invite scope (both granted invite to each other).
    expect(aliceRow?.bidirectional_scopes).toContain("invite");
    expect(bobRow?.bidirectional_scopes).toContain("invite");

    // Holder (alice) row carries a legal ak:event invite_consent_grant_ref:
    // bob granted alice an active invite consent, so alice's row surfaces it.
    expect(aliceRow?.invite_consent_grant_ref).toMatch(/^ak:event:/);
  });

  // S2: add friend -> reject -> state=rejected, no consent written.
  test("S2 add friend, reject -> rejected, no bidirectional consent", async ({
    request,
  }) => {
    const alice = uniqueUser("cg-s2-alice");
    const bob = uniqueUser("cg-s2-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);

    const { outcome } = await requestContactArkret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["invite"] },
    );
    const reject = await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "reject",
    });
    expect(reject.state).toBe("rejected");
    // Reject grants no scopes: bob did not grant alice anything.
    const bobRow = await contactRow(request, bobToken, alice.did);
    expect(bobRow?.state).toBe("rejected");
    expect(bobRow?.granted_by_me ?? []).not.toContain("invite");
    expect(bobRow?.bidirectional_scopes ?? []).toHaveLength(0);
  });

  // S3: the API resolver reserves one immutable authoring plan. A headless
  // API test must not fake RFC 9420 ciphertext or treat authoring_required as
  // success; Inkson owns participant signing and MLS materialization.
  test("S3 friends via direct_message -> immutable participant-authoring plan", async ({
    request,
  }) => {
    const [aliceIdentity, bobIdentity] = await Promise.all([
      prepareDirectConversationIdentityArkret(
        request,
        uniqueUser("cg-s3-alice"),
      ),
      prepareDirectConversationIdentityArkret(request, uniqueUser("cg-s3-bob")),
    ]);
    const alice = aliceIdentity.user;
    const bob = bobIdentity.user;
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
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
      bob.did,
      { requestedScopes: ["direct_message"] },
    );
    await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["direct_message"],
    });

    // Alice resolves: requires bob -> alice direct_message consent (granted on
    // accept above).
    const resolved = await resolveDirectConversationArkret(
      request,
      aliceToken,
      bob.did,
      { create: true },
    );
    expect(resolved.state).toBe("authoring_required");
    expect(resolved.created).toBe(false);
    expect(resolved.authoring_kind).toBe("direct_conversation_materialization");
    expect(resolved.realm_id).toMatch(/^ak:realm:/);
    expect(resolved.main_strand_id).toMatch(/^ak:strand:/);
    const draft = resolved.materialization_draft as Record<string, any>;
    expect(draft).toBeTruthy();
    expect(draft.realm_event?.proofs).toEqual([]);
    expect(draft.creator_member_event?.proofs).toEqual([]);
    expect(draft.peer_member_event?.proofs).toEqual([]);
    expect(draft.main_strand_event?.proofs).toEqual([]);
    expect(draft.binding_event?.proofs).toEqual([]);
    expect(draft.binding_event?.payload?.realm_id).toBe(resolved.realm_id);
    expect(draft.binding_event?.payload?.main_strand_id).toBe(
      resolved.main_strand_id,
    );
    expect(draft.binding_event?.payload?.mls_group_id).toBe(draft.mls_group_id);

    const retry = await resolveDirectConversationArkret(
      request,
      aliceToken,
      bob.did,
      { create: true },
    );
    // The draft carries MLS group state and the unsigned founding Events, so
    // handing it to `toEqual` would publish the whole object into stdout and
    // error-context.md on any drift. The determinism claim only needs the two
    // drafts to be the same structure.
    expectStructurallyIdentical(
      retry.materialization_draft,
      resolved.materialization_draft,
      "direct-conversation materialization draft must be deterministic across retries",
    );
  });

  // S4 (core closed loop): already friends (invite scope) -> use
  // invite_consent_grant_ref as consent_grant evidence to pull the peer into a
  // NEW realm (no locator) -> private delivery high-trust outcome -> peer lists
  // it in authz/invites -> peer ak.invite.accept -> peer is a realm member.
  test("S4 consent_grant evidence pulls friend into a new realm (closed loop)", async ({
    request,
  }) => {
    const alice = uniqueUser("cg-s4-alice");
    const bob = uniqueUser("cg-s4-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);

    // alice requests invite-scope contact; bob accepts granting invite. After
    // accept, bob has granted alice an active invite consent — so alice's
    // contact row surfaces invite_consent_grant_ref (bob -> alice grant).
    const { outcome } = await requestContactArkret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["invite"] },
    );
    await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["invite"],
    });

    const aliceRow = await contactRow(request, aliceToken, bob.did);
    const grantRef = aliceRow?.invite_consent_grant_ref;
    expect(grantRef, "alice row invite_consent_grant_ref").toMatch(
      /^ak:event:/,
    );

    // alice creates a NEW realm and pulls bob in using the consent_grant ref.
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S4 pull realm ${Date.now()}`,
      ownerDid: alice.did,
    });

    const { outcome: delivery, inviteId } = await deliverInviteWithConsentGrant(
      request,
      {
        inviterDid: alice.did,
        inviterToken: aliceToken,
        realmId,
        inviteeDid: bob.did,
        consentGrantRef: grantRef!,
        originServer: "default",
        recipientServer: "default",
      },
    );
    // High-trust consent_grant: accepted + disclosed_outcome=delivered.
    expect(delivery.status).toBe("accepted");
    expect(delivery.disclosed_outcome).toBe("delivered");

    // bob lists the pending invite.
    const invites = await listAuthzInvitesArkret(request, bobToken);
    const invite = invites.find(
      (i) => i.realm_id === realmId && i.invitee === bob.did,
    );
    expect(invite, "bob pending invite for the new realm").toBeTruthy();
    expect(invite!.id).toBe(inviteId);

    // bob accepts -> becomes a realm member.
    await acceptInviteArkret(request, bobToken, {
      accepterDid: bob.did,
      realmId,
      inviteId: invite!.id,
    });
    await expect
      .poll(
        async () => {
          const resp = await request.get(
            `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
            { headers: authHeaders(bobToken) },
          );
          if (!resp.ok()) return false;
          const realm = await resp.json();
          return (
            Array.isArray(realm.members) && realm.members.includes(bob.did)
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
    const mallory = uniqueUser("cg-s5-mallory");
    const victim = uniqueUser("cg-s5-victim");
    await Promise.all([
      ensureRegistered(request, mallory),
      ensureRegistered(request, victim),
    ]);
    const [malloryToken, victimToken] = await Promise.all([
      issueDevSession(request, mallory),
      issueDevSession(request, victim),
    ]);

    const realmId = await createRealmApi(request, malloryToken, {
      title: `S5 stranger realm ${Date.now()}`,
      ownerDid: mallory.did,
    });

    const { outcome } = await deliverInviteExplicitAddress(request, {
      inviterDid: mallory.did,
      inviterToken: malloryToken,
      realmId,
      inviteeDid: victim.did,
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
      countInvitesFor(invites, realmId, victim.did),
      "quarantined explicit_address invite must not surface to the invitee",
    ).toBe(0);
  });

  // S6: block (tombstone block_peer=true) -> peer pulls via any evidence ->
  // drop + opaque.
  test("S6 block_peer then pull -> dropped + opaque", async ({ request }) => {
    const alice = uniqueUser("cg-s6-alice");
    const bob = uniqueUser("cg-s6-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);

    // Establish invite-scope friendship so bob has a consent_grant ref to try.
    const { outcome } = await requestContactArkret(
      request,
      bobToken,
      alice.did,
      { requestedScopes: ["invite"] },
    );
    await respondContactArkret(request, aliceToken, {
      requestId: outcome.request_event_ref,
      requester: bob.did,
      action: "accept",
      grantedScopes: ["invite"],
    });
    const bobRow = await contactRow(request, bobToken, alice.did);
    const grantRef = bobRow?.invite_consent_grant_ref;
    expect(grantRef).toMatch(/^ak:event:/);

    // alice blocks bob.
    const tomb = await tombstoneContactArkret(request, aliceToken, bob.did, {
      blockPeer: true,
    });
    expect(tomb.state).toBe("tombstoned");
    const policy = await getInviteReceivePolicyArkret(request, aliceToken);
    expect(policy.denied_subjects ?? []).toContain(bob.did);

    // bob tries to pull alice into a realm with the (now revoked) consent_grant.
    const realmId = await createRealmApi(request, bobToken, {
      title: `S6 blocked realm ${Date.now()}`,
      ownerDid: bob.did,
    });
    const { outcome: delivery } = await deliverInviteWithConsentGrant(request, {
      inviterDid: bob.did,
      inviterToken: bobToken,
      realmId,
      inviteeDid: alice.did,
      consentGrantRef: grantRef!,
      originServer: "default",
      recipientServer: "default",
    });
    // denied_subjects hit: drop + opaque (no disclosed_outcome leak).
    expect(delivery.status).toBe("deferred");
    expect(delivery.disclosed_outcome).toBeUndefined();

    const invites = await listAuthzInvitesArkret(request, aliceToken);
    expect(
      countInvitesFor(invites, realmId, alice.did),
      "denied_subjects invite must be dropped, not delivered to the invitee",
    ).toBe(0);
  });

  // S7: revoked consent evidence is downgraded to explicit-address trust.
  // Quarantine remains holder-private even when low-trust outcome disclosure
  // is requested, so the sender receives only the deferred status.
  test("S7 revoked invite consent is downgraded and quarantine remains opaque", async ({
    request,
  }) => {
    const alice = uniqueUser("cg-s7-alice");
    const bob = uniqueUser("cg-s7-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);

    // bob asks alice; alice accepts granting invite -> alice gave bob invite
    // consent (alice=holder, bob=peer). bob's row surfaces the grant ref.
    const { outcome } = await requestContactArkret(
      request,
      bobToken,
      alice.did,
      { requestedScopes: ["invite"] },
    );
    await respondContactArkret(request, aliceToken, {
      requestId: outcome.request_event_ref,
      requester: bob.did,
      action: "accept",
      grantedScopes: ["invite"],
    });
    const bobRow = await contactRow(request, bobToken, alice.did);
    const grantRef = bobRow?.invite_consent_grant_ref;
    expect(grantRef).toMatch(/^ak:event:/);

    // alice revokes the invite consent (tombstone with revoke_scopes=[invite],
    // NO block). This revokes alice->bob invite grant so the consent_grant
    // evidence no longer verifies.
    const tomb = await tombstoneContactArkret(request, aliceToken, bob.did, {
      revokeScopes: ["invite"],
    });
    expect(tomb.state).toBe("tombstoned");

    // bob pulls alice using the now-revoked consent_grant ref. The grant fails
    // to verify and is downgraded to explicit_address (low trust). Default
    // policy quarantines explicit_address. Because the subject (alice) did NOT
    // block bob, low_trust disclosure default is opaque -> no disclosed_outcome.
    // We assert the delivery is deferred and the peer is not notified; the
    // explicit-feedback variant requires the subject to opt low_trust=outcome.
    const realmId = await createRealmApi(request, bobToken, {
      title: `S7 revoked realm ${Date.now()}`,
      ownerDid: bob.did,
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
      inviterDid: bob.did,
      inviterToken: bobToken,
      realmId,
      inviteeDid: alice.did,
      consentGrantRef: grantRef!,
      originServer: "default",
      recipientServer: "default",
    });
    expect(delivery.status).toBe("deferred");
    expect(delivery.disclosed_outcome).toBeUndefined();

    // alice is not actually a member.
    const invites = await listAuthzInvitesArkret(request, aliceToken);
    expect(
      countInvitesFor(invites, realmId, alice.did),
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

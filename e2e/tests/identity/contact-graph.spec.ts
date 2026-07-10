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

import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import {
  authHeaders,
  canonicalJson,
  createRealmApi,
  queryRealmEventsApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import {
  acceptInviteCokret,
  contactRow,
  deliverInviteExplicitAddress,
  deliverInviteWithConsentGrant,
  getInviteReceivePolicyCokret,
  listAuthzInvitesCokret,
  requestContactCokret,
  resolveDirectConversationCokret,
  respondContactCokret,
  seedDirectConversationIdentityCokret,
  setInviteReceivePolicyCokret,
  tombstoneContactCokret,
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
    const { outcome: reqOutcome } = await requestContactCokret(
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

    const respondOutcome = await respondContactCokret(request, bobToken, {
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

    const { outcome } = await requestContactCokret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["invite"] },
    );
    const reject = await respondContactCokret(request, bobToken, {
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

  // S3: already friends (direct_message) -> resolve direct conversation
  // (create=true) -> realm_id + main_strand_id -> exchange a message.
  test("S3 friends via direct_message -> resolve direct conversation (realm_id + main_strand_id, both sides converge)", async ({
    request,
  }) => {
    const alice = uniqueUser("cg-s3-alice");
    const bob = uniqueUser("cg-s3-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    await Promise.all([
      seedDirectConversationIdentityCokret(request, aliceToken, alice),
      seedDirectConversationIdentityCokret(request, bobToken, bob),
    ]);

    // Establish a bidirectional direct_message contact. direct conversation
    // resolve requires (1) accepted contact for the pair and (2) the PEER
    // granted the resolver direct_message consent. Make both directions grant
    // direct_message so either side can resolve.
    const { outcome } = await requestContactCokret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["direct_message"] },
    );
    await respondContactCokret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["direct_message"],
    });

    // Alice resolves: requires bob -> alice direct_message consent (granted on
    // accept above).
    const resolved = await resolveDirectConversationCokret(
      request,
      aliceToken,
      bob.did,
      { create: true },
    );
    expect(["created", "found"]).toContain(resolved.state);
    expect(resolved.realm_id).toMatch(/^ak:realm:/);
    expect(resolved.main_strand_id).toMatch(/^ak:strand:/);
    const realmId = resolved.realm_id!;

    // Both sides converge on the same canonical 1:1 binding (same realm_id +
    // main_strand_id), and the binding is surfaced on each contact row's
    // direct_conversation summary.
    const bobResolved = await resolveDirectConversationCokret(
      request,
      bobToken,
      alice.did,
      { create: true },
    );
    expect(bobResolved.realm_id).toBe(realmId);
    expect(bobResolved.main_strand_id).toBe(resolved.main_strand_id);

    const aliceRow = await contactRow(request, aliceToken, bob.did);
    expect(aliceRow?.direct_conversation?.realm_id).toBe(realmId);
    expect(aliceRow?.direct_conversation?.state).toBe("active");

    // Message leg (live): direct conversations are private Realms, so message
    // content must be carried as encrypted_content unless the Realm explicitly
    // lists a plaintext-visible service. The peer still reads the canonical
    // event envelope and ciphertext through the standard event API.
    const plaintext = `dm body ${Date.now()}`;
    const ciphertext = Buffer.from(
      `opaque-direct-ciphertext-${Date.now()}`,
      "utf8",
    ).toString("base64url");
    const envelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: resolved.main_strand_id!,
        track_name: "discussion",
        encrypted_content: encryptedEnvelope(ciphertext, realmId),
      },
    });
    await submitSignedEventApi(
      request,
      aliceToken,
      envelope,
      { context: "dm message into direct realm" },
    );
    // The peer (bob) reads the message back through the bound realm: a real
    // bidirectional round-trip through the canonical 1:1 direct conversation.
    const events = await queryRealmEventsApi(request, bobToken, realmId, {
      limit: 50,
    });
    const serverView = JSON.stringify(events);
    expect(serverView).toContain(String(envelope.event_id));
    expect(serverView).toContain("encrypted_content");
    expect(serverView).toContain("payload_digest");
    expect(serverView).toContain(ciphertext);
    expect(serverView).not.toContain(plaintext);
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
    const { outcome } = await requestContactCokret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["invite"] },
    );
    await respondContactCokret(request, bobToken, {
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

    const { outcome: delivery, inviteId } =
      await deliverInviteWithConsentGrant(request, {
        inviterDid: alice.did,
        realmId,
        inviteeDid: bob.did,
        consentGrantRef: grantRef!,
        originServer: "default",
        recipientServer: "default",
      });
    // High-trust consent_grant: accepted + disclosed_outcome=delivered.
    expect(delivery.status).toBe("accepted");
    expect(delivery.disclosed_outcome).toBe("delivered");

    // bob lists the pending invite.
    const invites = await listAuthzInvitesCokret(request, bobToken);
    const invite = invites.find(
      (i) => i.realm_id === realmId && i.invitee === bob.did,
    );
    expect(invite, "bob pending invite for the new realm").toBeTruthy();
    expect(invite!.id).toBe(inviteId);

    // bob accepts -> becomes a realm member.
    await acceptInviteCokret(request, bobToken, {
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
    const invites = await listAuthzInvitesCokret(request, victimToken);
    expect(
      invites.find((i) => i.realm_id === realmId && i.invitee === victim.did),
    ).toBeFalsy();
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
    const { outcome } = await requestContactCokret(
      request,
      bobToken,
      alice.did,
      { requestedScopes: ["invite"] },
    );
    await respondContactCokret(request, aliceToken, {
      requestId: outcome.request_event_ref,
      requester: bob.did,
      action: "accept",
      grantedScopes: ["invite"],
    });
    const bobRow = await contactRow(request, bobToken, alice.did);
    const grantRef = bobRow?.invite_consent_grant_ref;
    expect(grantRef).toMatch(/^ak:event:/);

    // alice blocks bob.
    const tomb = await tombstoneContactCokret(request, aliceToken, bob.did, {
      blockPeer: true,
    });
    expect(tomb.state).toBe("tombstoned");
    const policy = await getInviteReceivePolicyCokret(request, aliceToken);
    expect(policy.blocked_subjects ?? []).toContain(bob.did);

    // bob tries to pull alice into a realm with the (now revoked) consent_grant.
    const realmId = await createRealmApi(request, bobToken, {
      title: `S6 blocked realm ${Date.now()}`,
      ownerDid: bob.did,
    });
    const { outcome: delivery } = await deliverInviteWithConsentGrant(request, {
      inviterDid: bob.did,
      realmId,
      inviteeDid: alice.did,
      consentGrantRef: grantRef!,
      originServer: "default",
      recipientServer: "default",
    });
    // blocked_subjects hit: drop + opaque (no disclosed_outcome leak).
    expect(delivery.status).toBe("deferred");
    expect(delivery.disclosed_outcome).toBeUndefined();

    const invites = await listAuthzInvitesCokret(request, aliceToken);
    expect(
      invites.find((i) => i.realm_id === realmId && i.invitee === alice.did),
    ).toBeFalsy();
  });

  // S7: contact but holder revoked invite consent (consent revoke via
  // tombstone, NOT block) -> peer pulls -> high-trust tier returns
  // disclosed_outcome=blocked/quarantined (explicit feedback because the
  // downgraded evidence is no longer high-trust, but the subject is not
  // blocked so disclosure is not forced opaque).
  test("S7 revoked invite consent -> high-trust pull returns explicit disclosed_outcome", async ({
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
    const { outcome } = await requestContactCokret(
      request,
      bobToken,
      alice.did,
      { requestedScopes: ["invite"] },
    );
    await respondContactCokret(request, aliceToken, {
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
    const tomb = await tombstoneContactCokret(request, aliceToken, bob.did, {
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

    // Opt alice into explicit low-trust feedback so the revoked-grant pull
    // returns an explicit disclosed_outcome (spec §5.1 graded disclosure with
    // low_trust=outcome).
    const policy = await getInviteReceivePolicyCokret(request, aliceToken);
    await setInviteReceivePolicyCokret(request, aliceToken, {
      ...policy,
      disclosure: { high_trust: "outcome", low_trust: "outcome" },
    });

    const { outcome: delivery } = await deliverInviteWithConsentGrant(request, {
      inviterDid: bob.did,
      realmId,
      inviteeDid: alice.did,
      consentGrantRef: grantRef!,
      originServer: "default",
      recipientServer: "default",
    });
    expect(delivery.status).toBe("deferred");
    // With low_trust=outcome and explicit_address quarantine behavior, the
    // explicit feedback is "quarantined" (or "blocked" if dropped).
    expect(["quarantined", "blocked"]).toContain(delivery.disclosed_outcome);

    // alice is not actually a member.
    const invites = await listAuthzInvitesCokret(request, aliceToken);
    expect(
      invites.find((i) => i.realm_id === realmId && i.invitee === alice.did),
    ).toBeFalsy();
  });

  // S8: realm member pulled into a Circle without consent. Now implemented and
  // run for real in `identity/circle-member.spec.ts` (soland ships the
  // `/_arkret/self/circles/*` admin surface — CKP-0007). Kept here as a
  // pointer so the contact-graph table stays self-documenting.
  test("S8 circle member manage without consent", async ({ request }) => {
    test.skip(
      true,
      "moved to identity/circle-member.spec.ts (real run): admin one-way pull into a Circle, pulled actor does zero operations",
    );
    void request;
  });
});

function encryptedEnvelope(
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  const aad = { realm_id: realmId, event_kind: "ak.message.create" };
  const payloadMetadata = {
    scheme: "mls-rfc9420",
    version: "1.0",
    group_id: "mls_test",
    epoch: 1,
    content_type: "application/vnd.arkret.message+json",
    aad_visibility_event_id: "hidden",
    aad,
    key_ref: {
      algorithm: "MLS",
      group_state_ref:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
  return {
    ...payloadMetadata,
    ciphertext,
    aad_digest: sha256Digest(canonicalJson(aad)),
    payload_digest: encryptedPayloadDigest(payloadMetadata, ciphertext),
  };
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function encryptedPayloadDigest(
  metadata: Record<string, unknown>,
  ciphertext: string,
): string {
  const hash = createHash("sha256");
  hash.update(Buffer.from(canonicalJson(metadata), "utf8"));
  hash.update(Buffer.from(ciphertext, "base64url"));
  return `sha256:${hash.digest("hex")}`;
}

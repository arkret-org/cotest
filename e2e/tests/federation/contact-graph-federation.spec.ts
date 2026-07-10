// Contact graph across principal servers (α/β federation).
//
// Gated on hasDualSoland(): pass -DualSoland to scripts/run-joint-e2e.ps1.
//
// Protocol face: `/_arkret/self/contacts/*`,
// `/_arkret/self/direct-conversations/resolve`, `/_arkret/peer/invites`.
// Spec refs: contact-and-direct-conversation.md §3-§4, invite-addressing.md
// §2/§5 (cross-domain private delivery), §5.1 graded disclosure.
//
// Cross-PS contact federation (spec contact-and-direct-conversation.md §2/§4.1):
// the contact request/respond protocol face delivers signed `ck.contact.*`
// facts to the target holder's home PS via `ck.peer.contacts.command.submit`
// (`POST /_arkret/peer/contacts`) over the durable federation outbox. The
// requester addresses the remote target with `recipient_service_did`; the
// responder addresses the remote requester with `requester_service_did`
// (principal DIDs do not embed their home PS).
//
// What ALSO crosses a PS boundary is the consent_grant-evidence invite delivery
// (`POST /_arkret/peer/invites`): the recipient PS verifies the grant against
// its OWN consent cells. S4-fed exercises that real cross-PS path end to end.

import { expect, test } from "@playwright/test";
import {
  assertDualSolandNotRequired,
  hasDualSoland,
  solandBaseUrl,
  solandServiceDid,
} from "../../helpers/env";
import {
  authHeaders,
  createRealmApi,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import {
  acceptInviteCokret,
  contactRow,
  deliverInviteWithConsentGrant,
  listAuthzInvitesCokret,
  requestContactCokret,
  respondContactCokret,
  tombstoneContactCokret,
} from "../../helpers/contact-api";

test.describe.configure({ mode: "serial" });

test.beforeEach(() => {
  if (!hasDualSoland()) {
    assertDualSolandNotRequired("contact graph federation");
    test.skip(
      true,
      "contact-graph federation requires dual soland topology — pass -DualSoland to scripts/run-joint-e2e.ps1",
    );
  }
});

test.describe("contact graph federation (α/β)", () => {
  // S1-fed: cross-PS add friend (alice@α <-> bob@β), full positive handshake.
  //
  // alice@α requests bob@β with recipient_service_did=β -> the signed
  // ak.contact.requested fact federates to β over the outbox -> bob@β sees
  // pending_incoming -> bob accepts with requester_service_did=α -> the
  // ak.contact.accepted fact federates back to α -> alice@α sees accepted +
  // invite_consent_grant_ref (bob -> alice invite grant projected on α).
  test("S1-fed cross-PS add friend federates request + accept and converges both sides", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`cgf-s1-alice-${stamp}`);
    const bob = uniqueUser(`cgf-s1-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "alpha",
    });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });

    const { outcome } = await requestContactCokret(
      request,
      aliceToken,
      bob.did,
      {
        requestedScopes: ["invite"],
        server: "alpha",
        recipientServiceDid: solandServiceDid("beta"),
      },
    );
    // alice's local view: a pending outgoing request exists on α.
    expect(outcome.state).toBe("pending_outgoing");

    // The signed ak.contact.requested fact federates to β; bob@β sees the
    // incoming request once the outbox dispatcher drains (poll for delivery).
    await expect
      .poll(
        async () => {
          const row = await contactRow(request, bobToken, alice.did, {
            server: "beta",
          });
          return row?.state;
        },
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("pending_incoming");

    // bob accepts on β granting invite, addressing the remote requester (α).
    const respondOutcome = await respondContactCokret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["invite"],
      server: "beta",
      requesterServiceDid: solandServiceDid("alpha"),
    });
    expect(respondOutcome.state).toBe("accepted");

    // The ak.contact.accepted fact federates back to α; alice@α converges to
    // accepted, with bob -> alice invite grant surfaced as
    // invite_consent_grant_ref on her row.
    await expect
      .poll(
        async () => {
          const row = await contactRow(request, aliceToken, bob.did, {
            server: "alpha",
          });
          return row?.state;
        },
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("accepted");
    const aliceRow = await contactRow(request, aliceToken, bob.did, {
      server: "alpha",
    });
    expect(aliceRow?.invite_consent_grant_ref).toMatch(/^ak:event:/);
  });

  // S3-fed: cross-PS direct conversation resolve (binding leg).
  //
  // The cross-PS contact handshake (S1-fed) federates the accept fact back to
  // α, where projecting it ALSO writes the bob -> alice direct_message consent
  // grant locally on α. That gives α's resolver both preconditions it needs:
  // an accepted contact for the pair AND a peer-granted direct_message
  // consent. So alice@α can resolve a canonical DM binding (realm_id +
  // main_strand_id) without any further cross-PS plumbing.
  //
  // Scope note (honest): the resulting DM Realm is materialized locally on α
  // (alice's home PS) with bob added as a member there. A true symmetric
  // cross-PS DM Realm — where bob@β projects the same realm/strand and the
  // message timeline replicates both ways — requires cross-PS realm + MLS
  // group replication, which is out of scope here. This test pins the binding
  // leg (resolve converges to a canonical realm_id/main_strand_id on α); the
  // cross-PS message round-trip is documented as out of scope, not asserted.
  test("S3-fed cross-PS direct conversation resolves a binding on α after federated accept", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`cgf-s3-alice-${stamp}`);
    const bob = uniqueUser(`cgf-s3-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "alpha",
    });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });

    // Federated direct_message contact handshake (same path as S1-fed, but with
    // direct_message scope so the resolver's consent precondition is met).
    const { outcome } = await requestContactCokret(request, aliceToken, bob.did, {
      requestedScopes: ["direct_message"],
      server: "alpha",
      recipientServiceDid: solandServiceDid("beta"),
    });
    await expect
      .poll(
        async () =>
          (await contactRow(request, bobToken, alice.did, { server: "beta" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("pending_incoming");
    await respondContactCokret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["direct_message"],
      server: "beta",
      requesterServiceDid: solandServiceDid("alpha"),
    });
    // α converges to accepted once the accept fact federates back.
    await expect
      .poll(
        async () =>
          (await contactRow(request, aliceToken, bob.did, { server: "alpha" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("accepted");

    // alice@α resolves the canonical 1:1 DM binding. Preconditions are met on
    // α: accepted contact + bob -> alice direct_message consent (both projected
    // from the federated accept fact).
    const resolved = await request.post(
      `${solandBaseUrl("alpha")}/_arkret/self/direct-conversations/resolve`,
      {
        headers: authHeaders(aliceToken),
        data: { peer: bob.did, create: true },
      },
    );
    expect(resolved.ok()).toBeTruthy();
    const body = await resolved.json();
    expect(["created", "found"]).toContain(body.state);
    expect(body.realm_id).toMatch(/^ak:realm:/);
    expect(body.main_strand_id).toMatch(/^ak:strand:/);
    // The cross-PS message round-trip (bob@β reading alice's DM message) is out
    // of scope: the DM Realm lives on α and is not replicated to β. Documented,
    // not asserted.
    test.info().annotations.push({
      type: "scope",
      description:
        "Cross-PS DM Realm replication (symmetric realm/MLS group + two-way message timeline) is out of scope; this pins the binding leg only.",
    });
  });

  // S4-fed (core cross-PS closed loop): alice@α pulls bob@β into a realm using
  // a consent_grant whose grant the RECIPIENT server (β) can verify against its
  // own consent cells. The consent setup is done locally on β (alice + bob both
  // registered on β so bob can grant alice an invite consent there); the cross
  // boundary is the private `POST /_arkret/peer/invites` delivery from α to β.
  test("S4-fed consent_grant evidence delivers cross-PS to β and bob joins", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`cgf-s4-alice-${stamp}`);
    const bob = uniqueUser(`cgf-s4-bob-${stamp}`);

    // bob lives on β. alice is registered on BOTH α (her home, where she signs
    // the realm + delivery) AND β (so the bob->alice invite consent cell, which
    // β verifies the evidence against, can be created on β).
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, alice, { server: "beta" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceTokenAlpha = await issueDevSession(request, alice, {
      server: "alpha",
    });
    const aliceTokenBeta = await issueDevSession(request, alice, {
      server: "beta",
    });
    const bobTokenBeta = await issueDevSession(request, bob, { server: "beta" });

    // On β: alice requests bob (invite scope); bob accepts granting invite.
    // bob's accept mints a contact-managed grant holder=bob, peer=alice,
    // scope=invite on β. bob's contact row then surfaces the ref alice needs.
    const { outcome } = await requestContactCokret(
      request,
      aliceTokenBeta,
      bob.did,
      { requestedScopes: ["invite"], server: "beta" },
    );
    await respondContactCokret(request, bobTokenBeta, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["invite"],
      server: "beta",
    });
    // bob's accept minted a grant holder=bob, peer=alice (bob -> alice invite).
    // That surfaces on ALICE's contact row (actor=alice, peer=bob), whose
    // invite_consent_grant_ref resolves the bob->alice grant — exactly the ref
    // β's `has_active_consent_grant_evidence(subject=bob, inviter=alice)`
    // verifies. (Reading bob's own row would surface the inverse alice->bob
    // grant and fail verification.)
    const aliceRowBeta = await contactRow(request, aliceTokenBeta, bob.did, {
      server: "beta",
    });
    const grantRef = aliceRowBeta?.invite_consent_grant_ref;
    expect(
      grantRef,
      "alice@β row invite_consent_grant_ref (bob -> alice invite grant)",
    ).toMatch(/^ak:event:/);

    // On α: alice creates the realm she wants to pull bob into.
    const realmId = await createRealmApi(
      request,
      aliceTokenAlpha,
      { title: `S4-fed pull ${stamp}`, ownerDid: alice.did },
      { server: "alpha" },
    );

    // Cross-PS private delivery: α signs, β receives + verifies the grant
    // against ITS consent cells (subject=bob gave inviter=alice invite).
    const { outcome: delivery, inviteId } = await deliverInviteWithConsentGrant(
      request,
      {
        inviterDid: alice.did,
        realmId,
        inviteeDid: bob.did,
        consentGrantRef: grantRef!,
        originServer: "alpha",
        recipientServer: "beta",
      },
    );
    expect(delivery.status).toBe("accepted");
    expect(delivery.disclosed_outcome).toBe("delivered");

    // bob@β lists the pending invite and accepts -> becomes a member on β.
    const invites = await listAuthzInvitesCokret(request, bobTokenBeta, {
      server: "beta",
    });
    const invite = invites.find(
      (i) => i.realm_id === realmId && i.invitee === bob.did,
    );
    expect(invite, "bob@β pending invite for the α realm").toBeTruthy();
    expect(invite!.id).toBe(inviteId);

    await acceptInviteCokret(request, bobTokenBeta, {
      accepterDid: bob.did,
      realmId,
      inviteId: invite!.id,
      server: "beta",
    });
    await expect
      .poll(
        async () => {
          const resp = await request.get(
            `${solandBaseUrl("beta")}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
            { headers: authHeaders(bobTokenBeta) },
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

  // Tombstone-fed: cross-PS contact tombstone federates a `ck.contact.tombstoned`
  // fact to the peer's home Principal Server.
  //
  // alice@α and bob@β first become accepted contacts (same federated handshake
  // as S1-fed). Then alice@α tombstones bob with block_peer=true and addresses
  // bob's home PS via peer_service_did=β. soland's contact_tombstone handler
  // federates `ck.contact.tombstoned` over the durable outbox; β's
  // peer_contacts_submit downgrades its mirrored alice row to `tombstoned`.
  // Spec contact-and-direct-conversation.md §2/§4.1.
  test("tombstone-fed cross-PS tombstone downgrades the peer's mirrored row to tombstoned", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`cgf-tomb-alice-${stamp}`);
    const bob = uniqueUser(`cgf-tomb-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "alpha",
    });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });

    // Federated accepted handshake (reuse S1-fed path).
    const { outcome } = await requestContactCokret(request, aliceToken, bob.did, {
      requestedScopes: ["invite"],
      server: "alpha",
      recipientServiceDid: solandServiceDid("beta"),
    });
    await expect
      .poll(
        async () =>
          (await contactRow(request, bobToken, alice.did, { server: "beta" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("pending_incoming");
    await respondContactCokret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["invite"],
      server: "beta",
      requesterServiceDid: solandServiceDid("alpha"),
    });
    await expect
      .poll(
        async () =>
          (await contactRow(request, aliceToken, bob.did, { server: "alpha" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("accepted");

    // alice@α tombstones bob, addressing bob's home PS (β) and hard-blocking.
    const tomb = await tombstoneContactCokret(request, aliceToken, bob.did, {
      blockPeer: true,
      peerServiceDid: solandServiceDid("beta"),
      server: "alpha",
    });
    expect(tomb.state).toBe("tombstoned");

    // The `ck.contact.tombstoned` fact federates to β; bob@β's mirrored alice
    // row downgrades to `tombstoned` once the outbox dispatcher drains.
    await expect
      .poll(
        async () =>
          (await contactRow(request, bobToken, alice.did, { server: "beta" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("tombstoned");
  });
});

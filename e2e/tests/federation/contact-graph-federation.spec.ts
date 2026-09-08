// Contact graph across Stations (server1/server2 federation).
//
// Gated on hasServerCount(2): pass -ServerCount 2 to scripts/run-joint-e2e.ps1.
//
// Protocol face: `/_arkret/self/contacts/*`,
// `/_arkret/self/direct-conversations/resolve`, `/_arkret/peer/invites`.
// Spec refs: contact-and-direct-conversation.md §3-§4, invite-addressing.md
// §2/§5 (cross-domain private delivery), §5.1 graded disclosure.
//
// Cross-PS contact federation (spec contact-and-direct-conversation.md §2/§4.1):
// the contact request/respond protocol face delivers signed `ak.contact.*`
// facts to the target holder's home PS via `ak.peer.contacts.command.submit.v1`
// (`POST /_arkret/peer/contacts`) over the durable federation outbox. The
// requester addresses the remote target with `recipient_id`; the
// responder addresses the remote requester with `requester_id`
// (principal DIDs do not embed their home PS).
//
// What ALSO crosses a PS boundary is the consent_grant-evidence invite delivery
// (`POST /_arkret/peer/invites`): the recipient PS verifies the grant against
// its OWN consent cells. S4-fed exercises that real cross-PS path end to end.

import { expect, test } from "../../helpers/arkret-test";
import {
  assertServerCountNotRequired,
  hasServerCount,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import {
  authHeaders,
  createRealmApi,
  readRealmSealBasis,
  accountActorId,
  canonicalJson,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";
import {
  acceptInviteArkret,
  contactRow,
  deliverInviteWithConsentGrant,
  grantInviteConsentArkret,
  listAuthzInvitesArkret,
  requestContactArkret,
  resolvePrincipalLocator,
  respondContactArkret,
  tombstoneContactArkret,
} from "../../helpers/contact-api";

test.describe.configure({ mode: "serial" });

test.beforeEach(() => {
  if (!hasServerCount(2)) {
    assertServerCountNotRequired("contact graph federation", 2);
    test.skip(
      true,
      "contact-graph federation requires two-server topology — pass -ServerCount 2 to scripts/run-joint-e2e.ps1",
    );
  }
});

test.describe("contact graph federation (server1/server2)", () => {
  // S1-fed: cross-PS add friend (alice@server1 <-> bob@server2), full positive handshake.
  //
  // alice@server1 requests bob@server2 with recipient_id=server2 -> the signed
  // ak.contact.requested fact federates to server2 over the outbox -> bob@server2 sees
  // pending_incoming -> bob accepts with requester_id=server1 -> the
  // ak.contact.accepted fact federates back to server1 -> alice@server1 sees accepted +
  // invite_consent_grant_ref (bob -> alice invite grant projected on server1).
  test("S1-fed cross-PS add friend federates request + accept and converges both sides", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`cgf-s1-alice-${stamp}`);
    const bob = uniqueUser(`cgf-s1-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueDevSession(request, bob, { server: "server2" });
    // The server2 default invite/contact policy quarantines explicit-address
    // requests. Resolve a signed principal locator so the peer can notify and
    // project the pending_incoming row (invite-addressing.md Â§5).
    const bobLocator = await resolvePrincipalLocator(request, bob.id, "server2", bobToken);

    const { outcome } = await requestContactArkret(
      request,
      aliceToken,
      bob.id,
      {
        requestedScopes: ["invite"],
        server: "server1",
        recipientServiceId: solandServiceId("server2"),
        introductionEvidence: {
          kind: "locator_ref",
          principal_locator: bobLocator,
        },
      },
    );
    // alice's local view: a pending outgoing request exists on server1.
    expect(outcome.state).toBe("pending_outgoing");

    // The signed ak.contact.requested fact federates to server2; bob@server2 sees the
    // incoming request once the outbox dispatcher drains (poll for delivery).
    await expect
      .poll(
        async () => {
          const row = await contactRow(request, bobToken, alice.id, {
            server: "server2",
          });
          return row?.state;
        },
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("pending_incoming");

    // bob accepts on server2 granting invite, addressing the remote requester (server1).
    const respondOutcome = await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requesterId: alice.id,
      action: "accept",
      grantedScopes: ["invite"],
      server: "server2",
      requesterServiceId: solandServiceId("server1"),
    });
    expect(respondOutcome.state).toBe("accepted");

    // The ak.contact.accepted fact federates back to server1.
    await expect
      .poll(
        async () => {
          const row = await contactRow(request, aliceToken, bob.id, {
            server: "server1",
          });
          return row?.state;
        },
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("accepted");
    const aliceRow = await contactRow(request, aliceToken, bob.id, {
      server: "server1",
    });
    expect(aliceRow?.next_prepare_input).toBeTruthy();
  });

  // S3-fed: a normal Contact round selects its responder as founder. Resolving
  // either side is read-only and cannot allocate a Realm or replace that founder.
  test("S3-fed cross-PS resolver gives only the responder founding authority", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`cgf-s3-alice-${stamp}`);
    const bob = uniqueUser(`cgf-s3-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueDevSession(request, bob, { server: "server2" });
    const bobLocator = await resolvePrincipalLocator(request, bob.id, "server2", bobToken);

    // Federated direct_message contact handshake (same path as S1-fed, but with
    // direct_message scope so the resolver's consent precondition is met).
    const { outcome } = await requestContactArkret(request, aliceToken, bob.id, {
      requestedScopes: ["direct_message"],
      server: "server1",
      recipientServiceId: solandServiceId("server2"),
      introductionEvidence: {
        kind: "locator_ref",
        principal_locator: bobLocator,
      },
    });
    await expect
      .poll(
        async () =>
          (await contactRow(request, bobToken, alice.id, { server: "server2" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("pending_incoming");
    await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requesterId: alice.id,
      action: "accept",
      grantedScopes: ["direct_message"],
      server: "server2",
      requesterServiceId: solandServiceId("server1"),
    });
    // server1 converges to accepted once the accept fact federates back.
    await expect
      .poll(
        async () =>
          (await contactRow(request, aliceToken, bob.id, { server: "server1" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("accepted");

    const resolved = await request.post(
      `${solandBaseUrl("server1")}/_arkret/self/direct-conversations/resolve`,
      {
        headers: { ...authHeaders(aliceToken), "content-type": "application/json" },
        data: canonicalJson({
          peer: {
            kind: "human",
            account_id: { principal_id: bob.id, station_id: solandServiceId("server2") },
          },
        }),
      },
    );
    expect(resolved.ok(), await resolved.text()).toBeTruthy();
    const body = await resolved.json();
    expect(body.state).toBe("awaiting_founder");
    expect(body.coordinates).toBeUndefined();
    expect(body.next_founding_input).toBeUndefined();

    const founderRequest = {
      headers: { ...authHeaders(bobToken), "content-type": "application/json" },
      data: canonicalJson({
        peer: {
          kind: "human",
          account_id: { principal_id: alice.id, station_id: solandServiceId("server1") },
        },
      }),
    };
    const founderResolved = await request.post(
      `${solandBaseUrl("server2")}/_arkret/self/direct-conversations/resolve`,
      founderRequest,
    );
    expect(founderResolved.ok(), await founderResolved.text()).toBeTruthy();
    const founderBody = await founderResolved.json();
    expect(founderBody.state).toBe("creation_required");
    expect(founderBody.coordinates).toBeUndefined();
    const evidence = founderBody.next_founding_input.founding_authority_evidence;
    expect(evidence.kind).toBe("human");
    expect(evidence.contact_round_evidence.current_proofs).toHaveLength(2);
    expect(evidence.contact_round_evidence.normal_response_receipt).toBeTruthy();

    const retry = await request.post(
      `${solandBaseUrl("server2")}/_arkret/self/direct-conversations/resolve`,
      founderRequest,
    );
    expect(retry.ok(), await retry.text()).toBeTruthy();
    const retried = await retry.json();
    expect(retried.state).toBe("creation_required");
    expect(retried.coordinates).toBeUndefined();
    expect(retried.next_founding_input.founding_authority_evidence.contact_round_evidence.contact_round_id)
      .toBe(evidence.contact_round_evidence.contact_round_id);
  });

  test("S3-live cross-PS Inkson materializes one MLS Realm and exchanges encrypted messages", async ({
    browser,
    request,
  }) => {
    test.setTimeout(480_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, `cgf-live-alice-${stamp}`, {
        server: "server1",
      }),
      openDpopUserPage(browser, request, `cgf-live-bob-${stamp}`, {
        server: "server2",
      }),
    ]);
    test.skip(
      !aliceFlow || !bobFlow,
      "coauth DPoP session-grant login is unavailable",
    );
    if (!aliceFlow || !bobFlow) {
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice, { server: "server1" }),
      issueDevSession(request, bob, { server: "server2" }),
    ]);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    try {
      await Promise.all([alicePage.gotoHome(), bobPage.gotoHome()]);
      const bobLocator = await resolvePrincipalLocator(
        request,
        bob.id,
        "server2",
        bobToken,
      );
      const { outcome } = await requestContactArkret(
        request,
        aliceToken,
        bob.id,
        {
          requestedScopes: ["direct_message"],
          server: "server1",
          recipientServiceId: solandServiceId("server2"),
          introductionEvidence: {
            kind: "locator_ref",
            principal_locator: bobLocator,
          },
        },
      );
      await expect
        .poll(
          async () =>
            (
              await contactRow(
                request,
                bobToken,
                alice.id,
                { server: "server2" },
              )
            )?.state,
          { timeout: 30_000, intervals: [500, 1_000, 2_000] },
        )
        .toBe("pending_incoming");
      await respondContactArkret(request, bobToken, {
        requestId: outcome.request_event_ref,
        requesterId: alice.id,
        action: "accept",
        grantedScopes: ["direct_message"],
        server: "server2",
        requesterServiceId: solandServiceId("server1"),
      });
      await expect
        .poll(
          async () =>
            (
              await contactRow(
                request,
                aliceToken,
                bob.id,
                { server: "server1" },
              )
            )?.state,
          { timeout: 30_000, intervals: [500, 1_000, 2_000] },
        )
        .toBe("accepted");

      await alicePage.gotoHome();
      await alicePage.page.getByTestId("realm-sidebar-tab-direct").click();
      await alicePage.page
        .locator(
          `[data-testid="direct-conversation-row"][data-peer=${JSON.stringify(canonicalJson(accountActorId(bob.id, "server2")))}]`,
        )
        .click();
      await expect(alicePage.page).toHaveURL(/\/direct\/ak:realm:.*\/ak:strand:/, {
        timeout: 180_000,
      });
      const alicePath = new URL(alicePage.page.url()).pathname;
      const [, , encodedRealmId, encodedStrandId] = alicePath.split("/");
      const realmId = decodeURIComponent(encodedRealmId);
      const strandId = decodeURIComponent(encodedStrandId);

      await expect
        .poll(
          async () => {
            const row = await contactRow(
              request,
              bobToken,
              alice.id,
              { server: "server2" },
            );
            return row?.direct_conversation;
          },
          { timeout: 90_000, intervals: [500, 1_000, 2_000, 5_000] },
        )
        .toMatchObject({ realm_id: realmId, main_strand_id: strandId });

      await bobPage.gotoHome();
      await bobPage.page.getByTestId("realm-sidebar-tab-direct").click();
      await bobPage.page
        .locator(
          `[data-testid="direct-conversation-row"][data-peer=${JSON.stringify(canonicalJson(accountActorId(alice.id, "server1")))}]`,
        )
        .click();
      await expect
        .poll(() => decodeURIComponent(new URL(bobPage.page.url()).pathname), {
          timeout: 120_000,
          intervals: [500, 1_000, 2_000],
        })
        .toBe(`/direct/${realmId}/${strandId}`);

      const aliceMessage = `cross-ps alice ${Date.now()}`;
      await alicePage.page.getByTestId("chat-input").fill(aliceMessage);
      await alicePage.page.getByTestId("send-chat-button").click();
      await expect(
        bobPage.page.getByTestId("chat-message").filter({ hasText: aliceMessage }),
      ).toBeVisible({ timeout: 90_000 });

      const bobMessage = `cross-ps bob ${Date.now()}`;
      await bobPage.page.getByTestId("chat-input").fill(bobMessage);
      await bobPage.page.getByTestId("send-chat-button").click();
      await expect(
        alicePage.page.getByTestId("chat-message").filter({ hasText: bobMessage }),
      ).toBeVisible({ timeout: 90_000 });

      await Promise.all([alicePage.page.reload(), bobPage.page.reload()]);
      await expect(
        alicePage.page.getByTestId("chat-message").filter({ hasText: bobMessage }),
      ).toBeVisible({ timeout: 90_000 });
      await expect(
        bobPage.page.getByTestId("chat-message").filter({ hasText: aliceMessage }),
      ).toBeVisible({ timeout: 90_000 });
    } finally {
      await Promise.allSettled([alicePage.close(), bobPage.close()]);
    }
  });

  // S4-fed: Alice's Server1 Account invites Bob's Server2 Account with Bob's private consent.
  test("S4-fed consent_grant evidence delivers cross-PS to server2 and bob joins", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`cgf-s4-alice-${stamp}`, "server1");
    const bob = uniqueUser(`cgf-s4-bob-${stamp}`, "server2");

    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceTokenServer1 = await issueDevSession(request, alice, { server: "server1" });
    const bobTokenServer2 = await issueDevSession(request, bob, { server: "server2" });
    const locator = await resolvePrincipalLocator(request, bob.id, "server2", bobTokenServer2);
    const { outcome } = await requestContactArkret(request, aliceTokenServer1, bob.id, {
      requestedScopes: ["invite"], server: "server1", recipientServiceId: solandServiceId("server2"),
      introductionEvidence: { kind: "locator_ref", principal_locator: locator },
    });
    await expect.poll(async () => (await contactRow(request, bobTokenServer2, alice.id, { server: "server2" }))?.state,
      { timeout: 30_000 }).toBe("pending_incoming");
    await respondContactArkret(request, bobTokenServer2, {
      requestId: outcome.request_event_ref, requesterId: alice.id, action: "accept",
      grantedScopes: ["invite"], server: "server2", requesterServiceId: solandServiceId("server1"),
    });
    const consent = await grantInviteConsentArkret(request, bobTokenServer2, bob, alice.id, { server: "server2" });
    const grantRef = consent.eventRef;

    // On server1: alice creates the realm she wants to pull bob into.
    const realmId = await createRealmApi(
      request,
      aliceTokenServer1,
      {
        title: `S4-fed pull ${stamp}`,
        ownerId: alice.id,
        creator_id: solandServiceId("server1"),
        plaintext_visible_services: [
          solandServiceId("server1"),
          solandServiceId("server2"),
        ],
      },
      { server: "server1" },
    );
    // Cross-PS private delivery: server1 signs, server2 receives + verifies the grant
    // against ITS consent cells (subject=bob gave inviter=alice invite).
    const { outcome: delivery, inviteId } = await deliverInviteWithConsentGrant(
      request,
      {
        inviterId: alice.id,
        inviterToken: aliceTokenServer1,
        realmId,
        inviteeId: bob.id,
        consentGrantRef: grantRef!,
        originServer: "server1",
        recipientServer: "server2",
      },
    );
    expect(delivery.status).toBe("accepted");
    expect(delivery.disclosed_outcome).toBe("delivered");

    // bob@server2 lists the pending invite and accepts -> becomes a member on server2.
    const invites = await listAuthzInvitesArkret(request, bobTokenServer2, {
      server: "server2",
    });
    const invite = invites.find(
      (i) => i.realm_id === realmId && i.invitee_account_id?.principal_id === bob.id && i.invitee_account_id.station_id === solandServiceId("server2"),
    );
    expect(invite, "bob@server2 pending invite for the server1 realm").toBeTruthy();
    expect(invite!.id).toBe(inviteId);

    await acceptInviteArkret(request, bobTokenServer2, {
      accepterId: bob.id,
      realmId,
      inviteId: invite!.id,
      server: "server2",
      sealBasis: await readRealmSealBasis(request, aliceTokenServer1, realmId, "server1"),
    });
    await expect
      .poll(
        async () => {
          const resp = await request.get(
            `${solandBaseUrl("server2")}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
            { headers: authHeaders(bobTokenServer2) },
          );
          if (!resp.ok()) return false;
          const realm = await resp.json();
          return (
            Array.isArray(realm.member_ids) && realm.member_ids.some((member: unknown) => JSON.stringify(member) === JSON.stringify(accountActorId(bob.id, "server2")))
          );
        },
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBeTruthy();
  });

  // Tombstone-fed: cross-PS contact tombstone federates an `ak.contact.tombstone`
  // fact to the peer's home Station.
  //
  // alice@server1 and bob@server2 first become accepted contacts (same federated handshake
  // as S1-fed). Then alice@server1 tombstones bob with block_peer=true and addresses
  // bob's home PS via peer_id=server2. soland's contact_tombstone handler
  // federates `ak.contact.tombstone` over the durable outbox; server2's
  // peer_contacts_submit downgrades its mirrored alice row to `tombstoned`.
  // Spec contact-and-direct-conversation.md §2/§4.1.
  test("tombstone-fed cross-PS tombstone downgrades the peer's mirrored row to tombstoned", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`cgf-tomb-alice-${stamp}`);
    const bob = uniqueUser(`cgf-tomb-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueDevSession(request, bob, { server: "server2" });
    const bobLocator = await resolvePrincipalLocator(request, bob.id, "server2", bobToken);

    // Federated accepted handshake (reuse S1-fed path).
    const { outcome } = await requestContactArkret(request, aliceToken, bob.id, {
      requestedScopes: ["invite"],
      server: "server1",
      recipientServiceId: solandServiceId("server2"),
      introductionEvidence: {
        kind: "locator_ref",
        principal_locator: bobLocator,
      },
    });
    await expect
      .poll(
        async () =>
          (await contactRow(request, bobToken, alice.id, { server: "server2" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("pending_incoming");
    await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requesterId: alice.id,
      action: "accept",
      grantedScopes: ["invite"],
      server: "server2",
      requesterServiceId: solandServiceId("server1"),
    });
    await expect
      .poll(
        async () =>
          (await contactRow(request, aliceToken, bob.id, { server: "server1" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("accepted");

    // alice@server1 tombstones bob, addressing bob's home PS (server2) and hard-blocking.
    const tomb = await tombstoneContactArkret(request, aliceToken, bob.id, {
      blockPeer: true,
      peerServiceId: solandServiceId("server2"),
      server: "server1",
    });
    expect(tomb.state).toBe("tombstoned");

    // The `ak.contact.tombstone` fact federates to server2; bob@server2's mirrored alice
    // row downgrades to `tombstoned` once the outbox dispatcher drains.
    await expect
      .poll(
        async () =>
          (await contactRow(request, bobToken, alice.id, { server: "server2" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("tombstoned");
  });
});

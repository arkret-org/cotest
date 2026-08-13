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
// the contact request/respond protocol face delivers signed `ak.contact.*`
// facts to the target holder's home PS via `ak.peer.contacts.command.submit`
// (`POST /_arkret/peer/contacts`) over the durable federation outbox. The
// requester addresses the remote target with `recipient_service_id`; the
// responder addresses the remote requester with `requester_service_id`
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
  solandServiceId,
} from "../../helpers/env";
import {
  authHeaders,
  createRealmApi,
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
  listAuthzInvitesArkret,
  requestContactArkret,
  resolvePrincipalLocator,
  respondContactArkret,
  tombstoneContactArkret,
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
  // alice@α requests bob@β with recipient_service_id=β -> the signed
  // ak.contact.requested fact federates to β over the outbox -> bob@β sees
  // pending_incoming -> bob accepts with requester_service_id=α -> the
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
    // The beta default invite/contact policy quarantines explicit-address
    // requests. Resolve a signed principal locator so the peer can notify and
    // project the pending_incoming row (invite-addressing.md Â§5).
    const bobLocator = await resolvePrincipalLocator(request, bob.did, "beta", bobToken);

    const { outcome } = await requestContactArkret(
      request,
      aliceToken,
      bob.did,
      {
        requestedScopes: ["invite"],
        server: "alpha",
        recipientServiceId: solandServiceId("beta"),
        introductionEvidence: {
          kind: "locator_ref",
          principal_locator: bobLocator,
        },
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
    const respondOutcome = await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["invite"],
      server: "beta",
      requesterServiceId: solandServiceId("alpha"),
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

  // S3-fed: cross-PS creation begins with an immutable participant-authorized
  // remote KeyPackage claim draft. The server must not claim a package or
  // materialize a one-sided Realm before the client signs this draft.
  test("S3-fed cross-PS direct conversation returns remote KeyPackage claim authoring", async ({
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
    const bobLocator = await resolvePrincipalLocator(request, bob.did, "beta", bobToken);

    // Federated direct_message contact handshake (same path as S1-fed, but with
    // direct_message scope so the resolver's consent precondition is met).
    const { outcome } = await requestContactArkret(request, aliceToken, bob.did, {
      requestedScopes: ["direct_message"],
      server: "alpha",
      recipientServiceId: solandServiceId("beta"),
      introductionEvidence: {
        kind: "locator_ref",
        principal_locator: bobLocator,
      },
    });
    await expect
      .poll(
        async () =>
          (await contactRow(request, bobToken, alice.did, { server: "beta" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("pending_incoming");
    await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["direct_message"],
      server: "beta",
      requesterServiceId: solandServiceId("alpha"),
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

    const resolved = await request.post(
      `${solandBaseUrl("alpha")}/_arkret/self/direct-conversations/resolve`,
      {
        headers: authHeaders(aliceToken),
        data: { peer: bob.did, create: true },
      },
    );
    expect(resolved.ok()).toBeTruthy();
    const body = await resolved.json();
    expect(body.state).toBe("authoring_required");
    expect(body.created).toBe(false);
    expect(body.authoring_kind).toBe("remote_keypackage_claim");
    expect(body.realm_id).toMatch(/^ak:realm:/);
    expect(body.main_strand_id).toMatch(/^ak:strand:/);
    expect(body.materialization_draft).toBeUndefined();
    const draft = body.claim_authorization_draft;
    expect(draft?.request?.requester).toBe(alice.did);
    expect(draft?.request?.target_principal_id).toBe(bob.did);
    expect(draft?.request?.intended_realm_id).toBe(body.realm_id);
    expect(draft?.request?.strand_id).toBe(body.main_strand_id);
    expect(draft?.request?.claim_purpose).toBe("direct_conversation");
    expect(draft?.transport_binding?.source_service_id).toBe(
      solandServiceId("alpha"),
    );
    expect(draft?.transport_binding?.destination_service_id).toBe(
      bobLocator.recipient_service_id,
    );

    const retry = await request.post(
      `${solandBaseUrl("alpha")}/_arkret/self/direct-conversations/resolve`,
      {
        headers: authHeaders(aliceToken),
        data: { peer: bob.did, create: true },
      },
    );
    expect(retry.ok()).toBeTruthy();
    expect((await retry.json()).claim_authorization_draft).toEqual(draft);
  });

  test("S3-live cross-PS Inkson materializes one MLS Realm and exchanges encrypted messages", async ({
    browser,
    request,
  }) => {
    test.setTimeout(480_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, `cgf-live-alice-${stamp}`, {
        server: "alpha",
      }),
      openDpopUserPage(browser, request, `cgf-live-bob-${stamp}`, {
        server: "beta",
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
      issueDevSession(request, alice, { server: "alpha" }),
      issueDevSession(request, bob, { server: "beta" }),
    ]);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    try {
      await Promise.all([alicePage.gotoHome(), bobPage.gotoHome()]);
      const bobLocator = await resolvePrincipalLocator(
        request,
        bob.did,
        "beta",
        bobToken,
      );
      const { outcome } = await requestContactArkret(
        request,
        aliceToken,
        bob.did,
        {
          requestedScopes: ["direct_message"],
          server: "alpha",
          recipientServiceId: solandServiceId("beta"),
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
                alice.did,
                { server: "beta" },
              )
            )?.state,
          { timeout: 30_000, intervals: [500, 1_000, 2_000] },
        )
        .toBe("pending_incoming");
      await respondContactArkret(request, bobToken, {
        requestId: outcome.request_event_ref,
        requester: alice.did,
        action: "accept",
        grantedScopes: ["direct_message"],
        server: "beta",
        requesterServiceId: solandServiceId("alpha"),
      });
      await expect
        .poll(
          async () =>
            (
              await contactRow(
                request,
                aliceToken,
                bob.did,
                { server: "alpha" },
              )
            )?.state,
          { timeout: 30_000, intervals: [500, 1_000, 2_000] },
        )
        .toBe("accepted");

      await alicePage.gotoHome();
      await alicePage.page.getByTestId("realm-sidebar-tab-direct").click();
      await alicePage.page
        .locator(
          `[data-testid="direct-conversation-row"][data-peer="${bob.did}"]`,
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
              alice.did,
              { server: "beta" },
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
          `[data-testid="direct-conversation-row"][data-peer="${alice.did}"]`,
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

  // S4-fed (core cross-PS closed loop): alice@α pulls bob@β into a realm using
  // a consent_grant whose grant the RECIPIENT server (β) can verify against its
  // own consent cells. The consent setup is done locally on β (alice + bob both
  // registered on β so bob can grant alice an invite consent there); the cross
  // boundary is the private `POST /_arkret/peer/invites` delivery from α to β.
  test("S4-fed consent_grant evidence delivers cross-PS to β and bob joins", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`cgf-s4-alice-${stamp}`, "alpha");
    const bob = uniqueUser(`cgf-s4-bob-${stamp}`, "beta");

    // bob lives on β. alice is registered on BOTH α (her home, where she signs
    // the realm + delivery) AND β (so the bob->alice invite consent cell, which
    // β verifies the evidence against, can be created on β).
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, alice, { server: "beta" });
    await ensureRegistered(request, bob, { server: "beta" });
    // A join candidate authenticates the signing principal independently of
    // Bob's home Principal Server. The harness obtains a candidate-scoped
    // session on α, while Bob's account-private inbox and delivery binding
    // remain on β.
    await ensureRegistered(request, bob, { server: "alpha" });
    const aliceTokenAlpha = await issueDevSession(request, alice, {
      server: "alpha",
    });
    const aliceTokenBeta = await issueDevSession(request, alice, {
      server: "beta",
    });
    const bobTokenBeta = await issueDevSession(request, bob, { server: "beta" });
    const bobTokenAlpha = await issueDevSession(request, bob, {
      server: "alpha",
    });

    // On β: alice requests bob (invite scope); bob accepts granting invite.
    // bob's accept mints a contact-managed grant holder=bob, peer=alice,
    // scope=invite on β. bob's contact row then surfaces the ref alice needs.
    const { outcome } = await requestContactArkret(
      request,
      aliceTokenBeta,
      bob.did,
      { requestedScopes: ["invite"], server: "beta" },
    );
    await respondContactArkret(request, bobTokenBeta, {
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
      {
        title: `S4-fed pull ${stamp}`,
        ownerDid: alice.did,
        creator_service_id: solandServiceId("alpha"),
        plaintext_visible_services: [
          solandServiceId("alpha"),
          solandServiceId("beta"),
        ],
      },
      { server: "alpha" },
    );
    // Cross-PS private delivery: α signs, β receives + verifies the grant
    // against ITS consent cells (subject=bob gave inviter=alice invite).
    const { outcome: delivery, inviteId } = await deliverInviteWithConsentGrant(
      request,
      {
        inviterDid: alice.did,
        inviterToken: aliceTokenAlpha,
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
    const invites = await listAuthzInvitesArkret(request, bobTokenBeta, {
      server: "beta",
    });
    const invite = invites.find(
      (i) => i.realm_id === realmId && i.invitee === bob.did,
    );
    expect(invite, "bob@β pending invite for the α realm").toBeTruthy();
    expect(invite!.id).toBe(inviteId);

    await acceptInviteArkret(request, bobTokenBeta, {
      accepterDid: bob.did,
      realmId,
      inviteId: invite!.id,
      server: "beta",
      candidateTokens: { alpha: bobTokenAlpha },
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

  // Tombstone-fed: cross-PS contact tombstone federates a `ak.contact.tombstoned`
  // fact to the peer's home Principal Server.
  //
  // alice@α and bob@β first become accepted contacts (same federated handshake
  // as S1-fed). Then alice@α tombstones bob with block_peer=true and addresses
  // bob's home PS via peer_service_id=β. soland's contact_tombstone handler
  // federates `ak.contact.tombstoned` over the durable outbox; β's
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
    const bobLocator = await resolvePrincipalLocator(request, bob.did, "beta", bobToken);

    // Federated accepted handshake (reuse S1-fed path).
    const { outcome } = await requestContactArkret(request, aliceToken, bob.did, {
      requestedScopes: ["invite"],
      server: "alpha",
      recipientServiceId: solandServiceId("beta"),
      introductionEvidence: {
        kind: "locator_ref",
        principal_locator: bobLocator,
      },
    });
    await expect
      .poll(
        async () =>
          (await contactRow(request, bobToken, alice.did, { server: "beta" }))
            ?.state,
        { timeout: 30_000, intervals: [500, 1000, 2000] },
      )
      .toBe("pending_incoming");
    await respondContactArkret(request, bobToken, {
      requestId: outcome.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["invite"],
      server: "beta",
      requesterServiceId: solandServiceId("alpha"),
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
    const tomb = await tombstoneContactArkret(request, aliceToken, bob.did, {
      blockPeer: true,
      peerServiceId: solandServiceId("beta"),
      server: "alpha",
    });
    expect(tomb.state).toBe("tombstoned");

    // The `ak.contact.tombstoned` fact federates to β; bob@β's mirrored alice
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

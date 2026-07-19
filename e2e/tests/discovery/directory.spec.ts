// Discovery (directory search / contacts / profile / presence / organization)
// Contract: e2e/scenarios/discovery/directory.md
// Spec: discovery/discovery-directory.md, discovery/profiles-presence.md, identity/identity-handles.md

import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import { cssStringEscape } from "../../helpers/dom";
import { solandBaseUrl } from "../../helpers/env";
import {
  requestContactArkret,
  respondContactArkret,
} from "../../helpers/contact-api";
import { stepShot } from "../../helpers/screenshots";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  selfPathHeadersForDpopSession,
  uniqueUser,
} from "../../helpers/users";
import { canonicalJson, createRealmApi } from "../../helpers/soland-api";

test.describe.configure({ mode: "serial" });

test.describe("discovery", () => {
  test("alice and bob complete the contact request → accept → list → directory-visible strand", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const [aliceSession, bobSession] = await Promise.all([
      openDpopUserPage(browser, request, `s24-alice-${stamp}`),
      openDpopUserPage(browser, request, `s24-bob-${stamp}`),
    ]);
    if (!aliceSession || !bobSession) {
      assertJointStackNotRequired("directory contact browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceSession.user;
    const alicePage = aliceSession.page;
    const bob = bobSession.user;
    const bobPage = bobSession.page;

    try {
      // Pre-contact: directory search for bob from alice returns empty.
      await alicePage.gotoDirectory();
      await alicePage.clickWithPassivePromptRetry(
        alicePage.page.getByTestId("tab-actors"),
      );
      await alicePage.fillWithPassivePromptRetry(
        alicePage.page.getByTestId("directory-search-input"),
        bob.did,
      );
      await alicePage.clickWithPassivePromptRetry(
        alicePage.page.getByTestId("directory-search-button"),
      );
      await expect(alicePage.page.getByTestId("directory-panel")).toContainText(
        /No actors found/,
        {
          timeout: 30_000,
        },
      );

      // alice requests contact via directory contact tools.
      const aliceContact = alicePage.page.getByTestId(
        "directory-contact-tools",
      );
      await alicePage.fillWithPassivePromptRetry(
        aliceContact.getByTestId("contact-target-did-input"),
        bob.did,
      );
      await alicePage.clickWithPassivePromptRetry(
        aliceContact.getByTestId("request-contact-button"),
      );
      await expect(aliceContact).toContainText(/pending/i, { timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "contact-pending");

      // bob accepts via directory contact tools.
      await bobPage.gotoDirectory();
      const bobContact = bobPage.page.getByTestId("directory-contact-tools");
      await bobPage.clickWithPassivePromptRetry(
        bobContact.getByTestId("list-contacts-button"),
      );
      await expect(bobContact).toContainText(alice.did, { timeout: 30_000 });
      await expect(bobContact).toContainText(/pending/i, { timeout: 30_000 });
      await bobPage.fillWithPassivePromptRetry(
        bobContact.getByTestId("contact-requester-did-input"),
        alice.did,
      );
      await bobPage.clickWithPassivePromptRetry(
        bobContact.getByTestId("accept-contact-button"),
      );
      await expect(bobContact).toContainText(/accepted/i, { timeout: 30_000 });

      // bob lists; alice should appear with count 1.
      await bobPage.clickWithPassivePromptRetry(
        bobContact.getByTestId("list-contacts-button"),
      );
      await expect(bobContact).toContainText(alice.did);
      await expect(bobContact).toContainText(/contacts 1/i);

      // The accepted edge must project symmetrically before Directory uses
      // Alice's local contact index as the DID-disclosure basis.
      const aliceContactsUrl = `${solandBaseUrl()}/_arkret/self/contacts`;
      const aliceContacts = await request.get(aliceContactsUrl, {
        headers: selfPathHeadersForDpopSession(
          aliceSession.session,
          "GET",
          aliceContactsUrl,
        ),
      });
      const aliceContactsText = await aliceContacts.text();
      expect(aliceContacts.status(), aliceContactsText).toBe(200);
      const aliceContactsBody = JSON.parse(aliceContactsText) as {
        contacts?: Array<{ peer?: string; state?: string }>;
      };
      expect(aliceContactsBody.contacts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ peer: bob.did, state: "accepted" }),
        ]),
      );

      const searchActorsUrl = `${solandBaseUrl()}/_arkret/find/directory/search-actors`;
      const searchActors = await request.post(searchActorsUrl, {
        headers: selfPathHeadersForDpopSession(
          aliceSession.session,
          "POST",
          searchActorsUrl,
        ),
        data: { query: bob.did },
      });
      const searchActorsText = await searchActors.text();
      expect(searchActors.status(), searchActorsText).toBe(200);
      const searchActorsBody = JSON.parse(searchActorsText) as {
        actors?: Array<{ actor_id?: string; did?: string }>;
      };
      expect(searchActorsBody.actors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ actor_id: bob.did }),
        ]),
      );

      // Post-contact: alice's directory search now sees bob.
      await alicePage.gotoDirectory();
      await alicePage.clickWithPassivePromptRetry(
        alicePage.page.getByTestId("tab-actors"),
      );
      await alicePage.fillWithPassivePromptRetry(
        alicePage.page.getByTestId("directory-search-input"),
        bob.did,
      );
      await alicePage.clickWithPassivePromptRetry(
        alicePage.page.getByTestId("directory-search-button"),
      );
      await expect(
        alicePage.page.locator(
          `[data-testid="actor-result-did"][title="${cssStringEscape(bob.did)}"]`,
        ),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "post-contact-visible");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("profile update stays on the canonical account surface without implying directory disclosure", async ({
    request,
  }) => {
    // Account profile updates do not implicitly announce a discoverable
    // Directory projection. The canonical profile is read back from the
    // account surface, while an unrelated actor must not gain visibility.
    const stamp = Date.now();
    const alice = uniqueUser(`s24-profile-alice-${stamp}`);
    const bob = uniqueUser(`s24-profile-bob-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    const newDisplay = `Bob Renamed ${stamp}`;
    const newBio = `Engineer doing E2E work · ${stamp}`;

    const update = await request.post(
      `${solandBaseUrl()}/_arkret/self/account/profile`,
      {
        headers: { authorization: `Bearer ${bobToken}` },
        data: {
          patch: {
            display_name: { $op: "set", value: newDisplay },
            "profile_fields.bio": { $op: "set", value: newBio },
          },
        },
      },
    );
    expect(update.status()).toBe(200);
    const updateBody = await update.json();
    expect(updateBody.profile?.display_name).toBe(newDisplay);
    expect(updateBody.profile?.profile_fields?.bio).toBe(newBio);

    // A profile write is not an implicit Directory announce. Alice has no
    // contact or other disclosure relationship with Bob, so searching by the
    // new display name must not surface Bob or his private biography.
    const search = await request.post(
      `${solandBaseUrl()}/_arkret/find/directory/search-actors`,
      {
        headers: { authorization: `Bearer ${aliceToken}` },
        data: { query: newDisplay },
      },
    );
    expect(search.status()).toBe(200);
    const body = await search.json();
    const actors = (body.actors ?? []) as Array<{ actor_id?: string }>;
    expect(actors.some((actor) => actor.actor_id === bob.did)).toBe(false);
    expect(JSON.stringify(actors)).not.toContain(newBio);

    // /account/viewer reflects new fields on the canonical account surface.
    const me = await request.get(
      `${solandBaseUrl()}/_arkret/self/account/viewer`,
      {
        headers: { authorization: `Bearer ${bobToken}` },
      },
    );
    expect(me.ok()).toBeTruthy();
    const meBody = await me.json();
    expect(meBody.profile?.display_name).toBe(newDisplay);
    expect(meBody.profile?.profile_fields?.bio).toBe(newBio);
  });

  test("presence: bob closes tab → alice's directory shows presence-offline; bob reopens → presence-online within 5s", async ({
    request,
  }) => {
    // spec: profiles-presence.md §3 — presence is ephemeral and projects into
    // the directory actor row. A client signals `online` while its tab is open
    // by broadcasting `ak.presence` on `POST /_arkret/self/ephemeral`;
    // closing the tab stops the refresh and the row decays to `offline`
    // (mirroring the Sync presence projection's stale-online TTL). Reopening
    // re-asserts `online`. We drive this through the API rather than the inkson
    // UI because the directory's presence projection — not the renderer — is
    // what this scenario pins.
    const stamp = Date.now();
    const alice = uniqueUser(`s24-presence-alice-${stamp}`);
    const bob = uniqueUser(`s24-presence-bob-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const presenceRealmId = await createRealmApi(request, bobToken, {
      title: `S24 Presence ${stamp}`,
      discoverability: "unlisted",
      history_visibility: "joined",
      encryption_profile: "none",
    });

    // Directory search filters actors to the caller's accepted contacts;
    // establish the contact edge so alice can see bob's row at all.
    const { outcome: aliceReq } = await requestContactArkret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["direct_message"] },
    );
    expect(aliceReq.state).toBe("pending_outgoing");
    const bobAccept = await respondContactArkret(request, bobToken, {
      requestId: aliceReq.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["direct_message"],
    });
    expect(bobAccept.state).toBe("accepted");

    const bobPresenceFromSearch = async (): Promise<string | undefined> => {
      const search = await request.post(
        `${solandBaseUrl()}/_arkret/find/directory/search-actors`,
        {
          headers: { authorization: `Bearer ${aliceToken}` },
          data: { query: bob.did },
        },
      );
      expect(search.status()).toBe(200);
      const body = await search.json();
      const row = (
        body.actors as Array<{
          actor_id?: string;
          preview?: { did?: string; presence?: { status?: string } };
        }>
      ).find((r) => r.actor_id === bob.did || r.preview?.did === bob.did);
      return row?.preview?.presence?.status;
    };

    const broadcastBobPresence = async (state: "online" | "offline") => {
      const response = await request.post(
        `${solandBaseUrl()}/_arkret/self/ephemeral`,
        {
          headers: { authorization: `Bearer ${bobToken}` },
          data: presenceEnvelope(bob.did, bob.deviceId, presenceRealmId, state),
        },
      );
      const text = await response.text();
      expect(
        response.ok(),
        `presence ${state} returned ${response.status()}: ${text}`,
      ).toBeTruthy();
    };

    // bob's tab is open → presence refreshed to online.
    await broadcastBobPresence("online");
    await expect
      .poll(bobPresenceFromSearch, { timeout: 10_000, intervals: [500] })
      .toBe("online");

    // bob closes the tab → presence refresh stops. We model the closed tab by
    // explicitly flipping presence offline (the same wire the client emits on
    // teardown); the directory row MUST reflect offline.
    await broadcastBobPresence("offline");
    await expect
      .poll(bobPresenceFromSearch, { timeout: 10_000, intervals: [500] })
      .toBe("offline");

    // bob reopens → presence-online MUST surface within 5s.
    await broadcastBobPresence("online");
    await expect
      .poll(bobPresenceFromSearch, { timeout: 5_000, intervals: [500] })
      .toBe("online");
  });

  test("E24.2 reject contact: alice's request rejected by bob → status=rejected; alice cannot re-request until cooldown", async ({
    request,
  }) => {
    // spec: identity/account-lifecycle.md (contacts) — once a contact request
    // is rejected, alice's subsequent `POST /_arkret/self/contacts/request` for the
    // same target MUST NOT open a fresh pending row. The server's cooldown
    // implementation today is "return the existing rejected record" rather
    // than a fresh 4xx — that satisfies the spec invariant (no new pending
    // state surfaces to bob) while leaving room for a stricter timed
    // cooldown later.
    const stamp = Date.now();
    const alice = uniqueUser(`s24-rj-alice-${stamp}`);
    const bob = uniqueUser(`s24-rj-bob-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    // alice requests contact with bob.
    const { outcome: aliceReqBody } = await requestContactArkret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["direct_message"] },
    );
    expect(aliceReqBody.state).toBe("pending_outgoing");

    // bob rejects the request.
    const bobBody = await respondContactArkret(request, bobToken, {
      requestId: aliceReqBody.request_event_ref,
      requester: alice.did,
      action: "reject",
    });
    expect(bobBody.state).toBe("rejected");

    // alice retries her contact request — must NOT open a fresh pending row.
    // The server returns the same record with status=rejected (cooldown).
    const { outcome: retryBody } = await requestContactArkret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["direct_message"] },
    );
    expect(retryBody.state).toBe("rejected");
  });

  test("organization search: tab-organizations returns at least one organization with display_name + freshness", async ({
    browser,
    request,
  }) => {
    // spec: discovery/discovery-directory.md §2 — directory exposes the
    // organization axis; the demo deployment seeds a `ak:org:demo`
    // organization that MUST surface in `tab-organizations` results with
    // stable display metadata and freshness fields.
    const stamp = Date.now();
    const alice = uniqueUser(`s24-org-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    // API surface check — inkson renders the same response payload.
    const orgResp = await request.post(
      `${solandBaseUrl()}/_arkret/find/directory/search-organizations`,
      {
        headers: { authorization: `Bearer ${aliceToken}` },
        data: { query: "Arkret" },
      },
    );
    expect(orgResp.status()).toBe(200);
    const body = await orgResp.json();
    expect(Array.isArray(body.organizations)).toBe(true);
    expect(body.organizations.length).toBeGreaterThanOrEqual(1);
    const demoEnvelope = body.organizations.find(
      (r: {
        organization_did?: string;
        handle?: string;
        display_name?: string;
        source_refs?: string[];
        policy_revision?: string;
      }) =>
        r.handle === "@arkret-demo" ||
        r.display_name === "Arkret Demo Organization",
    );
    const demo = demoEnvelope;
    expect(
      demo,
      "demo organization must appear in search results",
    ).toBeTruthy();
    expect(demo!.display_name).toBe("Arkret Demo Organization");
    expect(Array.isArray(demo!.source_refs)).toBe(true);
    expect(demo!.source_refs!.length).toBeGreaterThan(0);
    expect(typeof demo!.policy_revision).toBe("string");

    // UI smoke — the Organizations tab renders the result row.
    const aliceSession = await openDpopUserPage(
      browser,
      request,
      `s24-org-ui-${stamp}`,
    );
    if (!aliceSession) {
      assertJointStackNotRequired("directory organization browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceSession.page;
    try {
      await alicePage.gotoDirectory();
      await alicePage.clickWithPassivePromptRetry(
        alicePage.page.getByTestId("tab-organizations"),
      );
      await alicePage.fillWithPassivePromptRetry(
        alicePage.page.getByTestId("directory-search-input"),
        "Arkret",
      );
      await alicePage.clickWithPassivePromptRetry(
        alicePage.page.getByTestId("directory-search-button"),
      );
      await expect(alicePage.page.getByTestId("org-result")).toBeVisible({
        timeout: 30_000,
      });
      await expect(alicePage.page.getByTestId("org-result")).toContainText(
        "Arkret Demo",
      );
    } finally {
      await alicePage.close();
    }
  });
});

function presenceEnvelope(
  actorDid: string,
  deviceId: string,
  realmId: string,
  state: "online" | "offline",
): Record<string, unknown> {
  const sentAt = new Date();
  const expiresAt = new Date(sentAt.getTime() + 30_000);
  const envelope: Record<string, unknown> = {
    kind: "ak.presence",
    realm_id: realmId,
    actor_id: actorDid,
    device_id: deviceId,
    sent_at: sentAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    payload: { state },
  };
  const eventDigest = `sha256:${createHash("sha256")
    .update(canonicalJson(envelope))
    .digest("hex")}`;
  envelope.proof = {
    kind: "detached_jws",
    alg: "EdDSA",
    verification_method: `${actorDid}#${deviceId}`,
    event_digest: eventDigest,
    created_at: sentAt.toISOString(),
    jws: "eyJhbGciOiJFZERTQSJ9..c2ln",
  };
  return envelope;
}

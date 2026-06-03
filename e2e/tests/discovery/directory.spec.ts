// Discovery (directory search / contacts / profile / presence / organization)
// Contract: e2e/scenarios/discovery/directory.md
// Spec: discovery/discovery-directory.md, discovery/profiles-presence.md, identity/identity-handles.md

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("discovery", () => {
  test("alice and bob complete the contact request → accept → list → directory-visible flow", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s24-alice-${stamp}`);
    const bob = uniqueUser(`s24-bob-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

    try {
      // Pre-contact: directory search for bob from alice returns empty.
      await alicePage.gotoDirectory();
      await alicePage.page.getByTestId("tab-actors").click();
      await alicePage.page.getByTestId("directory-search-input").fill(bob.handle);
      await alicePage.page.getByTestId("directory-search-button").click();
      await expect(alicePage.page.getByTestId("directory-panel")).toContainText(/No actors found/, {
        timeout: 30_000,
      });

      // alice requests contact via directory contact tools.
      const aliceContact = alicePage.page.getByTestId("directory-contact-tools");
      await aliceContact.getByTestId("contact-target-did-input").fill(bob.did);
      await aliceContact.getByTestId("request-contact-button").click();
      await expect(aliceContact).toContainText(/pending/, { timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "contact-pending");

      // bob accepts via directory contact tools.
      await bobPage.gotoDirectory();
      const bobContact = bobPage.page.getByTestId("directory-contact-tools");
      await bobContact.getByTestId("contact-requester-did-input").fill(alice.did);
      await bobContact.getByTestId("accept-contact-button").click();
      await expect(bobContact).toContainText(/accepted/, { timeout: 30_000 });

      // bob lists; alice should appear with count 1.
      await bobContact.getByTestId("list-contacts-button").click();
      await expect(bobContact).toContainText(alice.did);
      await expect(bobContact).toContainText(/contacts 1/);

      // Post-contact: alice's directory search now sees bob.
      await alicePage.gotoDirectory();
      await alicePage.page.getByTestId("tab-actors").click();
      await alicePage.page.getByTestId("directory-search-input").fill(bob.handle);
      await alicePage.page.getByTestId("directory-search-button").click();
      await expect(alicePage.page.getByTestId("actor-result")).toContainText(bob.did, {
        timeout: 30_000,
      });
      await stepShot(alicePage.page, testInfo, "post-contact-visible");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("bob updates profile (display_name/bio/avatar); alice sees the change in directory results within 30s", async ({
    request,
  }) => {
    // spec: discovery/profiles-presence.md §2 — actor profile updates
    // fan out through the directory's actor projection. We assert via
    // `POST /api/v1/directory/search-actors` (the same endpoint yougen's
    // tab-actors hits) rather than driving the yougen profile-edit UI
    // because the yougen profile form is not in scope here.
    const stamp = Date.now();
    const alice = uniqueUser(`s24-profile-alice-${stamp}`);
    const bob = uniqueUser(`s24-profile-bob-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    const newDisplay = `Bob Renamed ${stamp}`;
    const newBio = `Engineer doing E2E work · ${stamp}`;
    const newAvatar = `https://avatars.example/bob-${stamp}.png`;

    const update = await request.post(`${solandBaseUrl()}/api/v1/account/profile`, {
      headers: { authorization: `Bearer ${bobToken}` },
      data: { display_name: newDisplay, bio: newBio, avatar_url: newAvatar },
    });
    expect(update.status()).toBe(200);
    const updateBody = await update.json();
    expect(updateBody.display_name).toBe(newDisplay);
    expect(updateBody.bio).toBe(newBio);
    expect(updateBody.avatar_url).toBe(newAvatar);

    // Directory search filters actors to the caller's accepted contacts
    // (or self) — establish a contact relationship so alice can see bob.
    const aliceReq = await request.post(`${solandBaseUrl()}/api/v1/contacts/request`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { target: bob.did },
    });
    expect([200, 201]).toContain(aliceReq.status());
    const bobAccept = await request.post(`${solandBaseUrl()}/api/v1/contacts/respond`, {
      headers: { authorization: `Bearer ${bobToken}` },
      data: { requester: alice.did, action: "accept" },
    });
    expect(bobAccept.status()).toBe(200);

    // alice searches actors — bob's directory row carries the new fields.
    const search = await request.post(`${solandBaseUrl()}/api/v1/directory/search-actors`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { query: newDisplay },
    });
    expect(search.status()).toBe(200);
    const body = await search.json();
    const bobRow = (body.results as Array<{ did: string }>).find((r) => r.did === bob.did);
    expect(bobRow, "bob must appear in directory search results").toBeTruthy();
    expect((bobRow as { display_name: string }).display_name).toBe(newDisplay);
    expect((bobRow as { bio?: string }).bio).toBe(newBio);
    expect((bobRow as { avatar_url?: string }).avatar_url).toBe(newAvatar);

    // /account/me reflects new fields.
    const me = await request.get(`${solandBaseUrl()}/api/v1/account/me`, {
      headers: { authorization: `Bearer ${bobToken}` },
    });
    expect(me.ok()).toBeTruthy();
    const meBody = await me.json();
    expect(meBody.display_name).toBe(newDisplay);
  });

  test.fixme(
    // @blocking-on: soland#discovery-directory-gap
    // @user-promise: e2e/scenarios/discovery/directory.md
    // @expected-live-by: 2026Q3
    "presence: bob closes tab → alice's directory shows presence-offline; bob reopens → presence-online within 5s",
    async () => {
      // spec: profiles-presence.md §3
    },
  );

  test("E24.2 reject contact: alice's request rejected by bob → status=rejected; alice cannot re-request until cooldown", async ({
    request,
  }) => {
    // spec: identity/account-lifecycle.md (contacts) — once a contact request
    // is rejected, alice's subsequent `POST /api/v1/contacts/request` for the
    // same target MUST NOT open a fresh pending row. The server's cooldown
    // implementation today is "return the existing rejected record" rather
    // than a fresh 4xx — that satisfies the spec invariant (no new pending
    // state surfaces to bob) while leaving room for a stricter timed
    // cooldown later.
    const stamp = Date.now();
    const alice = uniqueUser(`s24-rj-alice-${stamp}`);
    const bob = uniqueUser(`s24-rj-bob-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    // alice requests contact with bob.
    const aliceReq = await request.post(`${solandBaseUrl()}/api/v1/contacts/request`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { target: bob.did },
    });
    expect([200, 201]).toContain(aliceReq.status());
    const aliceReqBody = await aliceReq.json();
    expect(aliceReqBody.status ?? aliceReqBody.contact?.status).toBe("pending");

    // bob rejects the request.
    const bobResp = await request.post(`${solandBaseUrl()}/api/v1/contacts/respond`, {
      headers: { authorization: `Bearer ${bobToken}` },
      data: { requester: alice.did, action: "reject" },
    });
    expect(bobResp.status()).toBe(200);
    const bobBody = await bobResp.json();
    expect(bobBody.status ?? bobBody.contact?.status).toBe("rejected");

    // alice retries her contact request — must NOT open a fresh pending row.
    // The server returns the same record with status=rejected (cooldown).
    const aliceRetry = await request.post(`${solandBaseUrl()}/api/v1/contacts/request`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { target: bob.did },
    });
    expect([200, 201]).toContain(aliceRetry.status());
    const retryBody = await aliceRetry.json();
    expect(retryBody.status ?? retryBody.contact?.status).toBe("rejected");
  });

  test("organization search: tab-organizations returns at least one organization with name + member count", async ({
    browser,
    request,
  }) => {
    // spec: discovery/discovery-directory.md §2 — directory exposes the
    // organization axis; the demo deployment seeds a `ck:org:demo`
    // organization that MUST surface in `tab-organizations` results with
    // a stable name and an actor_count member figure.
    const stamp = Date.now();
    const alice = uniqueUser(`s24-org-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    // API surface check — yougen renders the same response payload.
    const orgResp = await request.post(`${solandBaseUrl()}/api/v1/directory/search-organizations`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { query: "Cokret" },
    });
    expect(orgResp.status()).toBe(200);
    const body = await orgResp.json();
    expect(Array.isArray(body.results)).toBe(true);
    expect(body.results.length).toBeGreaterThanOrEqual(1);
    const demo = body.results.find(
      (r: { organization_id?: string; handle?: string }) =>
        r.organization_id === "ck:org:demo" || r.handle === "@cokret-demo",
    );
    expect(demo, "demo organization must appear in search results").toBeTruthy();
    expect(typeof demo.name).toBe("string");
    expect(demo.name.length).toBeGreaterThan(0);
    expect(typeof demo.actor_count).toBe("number");

    // UI smoke — the Organizations tab renders the result row.
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    try {
      await alicePage.gotoDirectory();
      await alicePage.page.getByTestId("tab-organizations").click();
      await alicePage.page.getByTestId("directory-search-input").fill("Cokret");
      await alicePage.page.getByTestId("directory-search-button").click();
      await expect(alicePage.page.getByTestId("org-result")).toBeVisible({ timeout: 30_000 });
      await expect(alicePage.page.getByTestId("org-result")).toContainText("Cokret Demo");
    } finally {
      await alicePage.close();
    }
  });
});

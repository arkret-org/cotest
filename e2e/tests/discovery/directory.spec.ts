// Discovery (directory search / contacts / profile / presence / organization)
// Contract: e2e/scenarios/discovery/directory.md
// Spec: discovery/discovery-directory.md, discovery/profiles-presence.md, identity/identity-handles.md

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  requestContactCokret,
  respondContactCokret,
} from "../../helpers/contact-api";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("discovery", () => {
  test("alice and bob complete the contact request → accept → list → directory-visible strand", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s24-alice-${stamp}`);
    const bob = uniqueUser(`s24-bob-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });
    const bobPage = await openUserPage(browser, bob, {
      sessionCredential: bobToken,
    });

    try {
      // Pre-contact: directory search for bob from alice returns empty.
      await alicePage.gotoDirectory();
      await alicePage.page.getByTestId("tab-actors").click();
      await alicePage.page
        .getByTestId("directory-search-input")
        .fill(bob.handle);
      await alicePage.page.getByTestId("directory-search-button").click();
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
      await aliceContact.getByTestId("contact-target-did-input").fill(bob.did);
      await aliceContact.getByTestId("request-contact-button").click();
      await expect(aliceContact).toContainText(/pending/i, { timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "contact-pending");

      // bob accepts via directory contact tools.
      await bobPage.gotoDirectory();
      const bobContact = bobPage.page.getByTestId("directory-contact-tools");
      await bobContact.getByTestId("list-contacts-button").click();
      await expect(bobContact).toContainText(alice.did, { timeout: 30_000 });
      await expect(bobContact).toContainText(/pending/i, { timeout: 30_000 });
      await bobContact
        .getByTestId("contact-requester-did-input")
        .fill(alice.did);
      await bobContact.getByTestId("accept-contact-button").click();
      await expect(bobContact).toContainText(/accepted/i, { timeout: 30_000 });

      // bob lists; alice should appear with count 1.
      await bobContact.getByTestId("list-contacts-button").click();
      await expect(bobContact).toContainText(alice.did);
      await expect(bobContact).toContainText(/contacts 1/i);

      // Post-contact: alice's directory search now sees bob.
      await alicePage.gotoDirectory();
      await alicePage.page.getByTestId("tab-actors").click();
      await alicePage.page
        .getByTestId("directory-search-input")
        .fill(bob.handle);
      await alicePage.page.getByTestId("directory-search-button").click();
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

  test("bob updates profile (display_name/bio); alice sees the change in directory results within 30s", async ({
    request,
  }) => {
    // spec: discovery/profiles-presence.md §2 — actor profile updates
    // fan out through the directory's actor projection. We assert via
    // `POST /_cokret/find/directory/search-actors` (the same endpoint yougen's
    // tab-actors hits) rather than driving the yougen profile-edit UI
    // because the yougen profile form is not in scope here.
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
      `${solandBaseUrl()}/_cokret/self/account/profile`,
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

    // Directory search filters actors to the caller's accepted contacts
    // (or self) — establish a contact relationship so alice can see bob.
    const { outcome: aliceReq } = await requestContactCokret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["direct_message"] },
    );
    expect(aliceReq.state).toBe("pending_outgoing");
    const bobAccept = await respondContactCokret(request, bobToken, {
      requestId: aliceReq.request_event_ref,
      requester: alice.did,
      action: "accept",
      grantedScopes: ["direct_message"],
    });
    expect(bobAccept.state).toBe("accepted");

    // alice searches actors — bob's directory row carries the new fields.
    const search = await request.post(
      `${solandBaseUrl()}/_cokret/find/directory/search-actors`,
      {
        headers: { authorization: `Bearer ${aliceToken}` },
        data: { query: newDisplay },
      },
    );
    expect(search.status()).toBe(200);
    const body = await search.json();
    const bobEnvelope = (
      body.actors as Array<{
        actor_id?: string;
        display_name?: string;
        preview?: { did?: string; display_name?: string; bio?: string };
      }>
    ).find((r) => r.actor_id === bob.did || r.preview?.did === bob.did);
    const bobRow = bobEnvelope?.preview ?? bobEnvelope;
    expect(bobRow, "bob must appear in directory search results").toBeTruthy();
    expect((bobRow as { display_name: string }).display_name).toBe(newDisplay);
    expect((bobRow as { bio?: string }).bio).toBe(newBio);

    // /account/viewer reflects new fields on the canonical account surface.
    const me = await request.get(
      `${solandBaseUrl()}/_cokret/self/account/viewer`,
      {
        headers: { authorization: `Bearer ${bobToken}` },
      },
    );
    expect(me.ok()).toBeTruthy();
    const meBody = await me.json();
    expect(meBody.profile?.display_name).toBe(newDisplay);
  });

  test.fixme(// @blocking-on: soland#discovery-directory-gap
  // @user-promise: e2e/scenarios/discovery/directory.md
  // @expected-live-by: 2026Q3
  "presence: bob closes tab → alice's directory shows presence-offline; bob reopens → presence-online within 5s", async () => {
    // spec: profiles-presence.md §3
  });

  test("E24.2 reject contact: alice's request rejected by bob → status=rejected; alice cannot re-request until cooldown", async ({
    request,
  }) => {
    // spec: identity/account-lifecycle.md (contacts) — once a contact request
    // is rejected, alice's subsequent `POST /_cokret/self/contacts/request` for the
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
    const { outcome: aliceReqBody } = await requestContactCokret(
      request,
      aliceToken,
      bob.did,
      { requestedScopes: ["direct_message"] },
    );
    expect(aliceReqBody.state).toBe("pending_outgoing");

    // bob rejects the request.
    const bobBody = await respondContactCokret(request, bobToken, {
      requestId: aliceReqBody.request_event_ref,
      requester: alice.did,
      action: "reject",
    });
    expect(bobBody.state).toBe("rejected");

    // alice retries her contact request — must NOT open a fresh pending row.
    // The server returns the same record with status=rejected (cooldown).
    const { outcome: retryBody } = await requestContactCokret(
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
    // organization axis; the demo deployment seeds a `ck:org:demo`
    // organization that MUST surface in `tab-organizations` results with
    // stable display metadata and freshness fields.
    const stamp = Date.now();
    const alice = uniqueUser(`s24-org-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    // API surface check — yougen renders the same response payload.
    const orgResp = await request.post(
      `${solandBaseUrl()}/_cokret/find/directory/search-organizations`,
      {
        headers: { authorization: `Bearer ${aliceToken}` },
        data: { query: "Cokret" },
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
        r.handle === "@cokret-demo" ||
        r.display_name === "Cokret Demo Organization",
    );
    const demo = demoEnvelope;
    expect(
      demo,
      "demo organization must appear in search results",
    ).toBeTruthy();
    expect(demo!.display_name).toBe("Cokret Demo Organization");
    expect(Array.isArray(demo!.source_refs)).toBe(true);
    expect(demo!.source_refs!.length).toBeGreaterThan(0);
    expect(typeof demo!.policy_revision).toBe("string");

    // UI smoke — the Organizations tab renders the result row.
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });
    try {
      await alicePage.gotoDirectory();
      await alicePage.page.getByTestId("tab-organizations").click();
      await alicePage.page.getByTestId("directory-search-input").fill("Cokret");
      await alicePage.page.getByTestId("directory-search-button").click();
      await expect(alicePage.page.getByTestId("org-result")).toBeVisible({
        timeout: 30_000,
      });
      await expect(alicePage.page.getByTestId("org-result")).toContainText(
        "Cokret Demo",
      );
    } finally {
      await alicePage.close();
    }
  });
});

function cssStringEscape(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

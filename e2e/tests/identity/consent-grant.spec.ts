// Consent grant flow
// Contract: e2e/scenarios/identity/consent-grant.md
// Spec: identity/consent-model.md §2-§4

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

async function requestContact(
  actor: Awaited<ReturnType<typeof openUserPage>>,
  targetDid: string,
  scope: "invite" | "message" | "call",
) {
  await actor.page.goto("/contacts/new", { waitUntil: "domcontentloaded" });
  await expect(actor.page.getByTestId("contact-request-panel")).toBeVisible({
    timeout: 120_000,
  });
  await actor.page.getByTestId("contact-target-input").fill(targetDid);
  await actor.page.getByTestId("contact-scope-select").selectOption(scope);
  await actor.page.getByTestId("send-contact-request-button").click();
  return actor.page.getByTestId("contact-request-status");
}

async function gotoConsentSettings(actor: Awaited<ReturnType<typeof openUserPage>>) {
  await actor.page.goto("/settings/consent", { waitUntil: "domcontentloaded" });
  await expect(actor.page.getByTestId("consent-settings-panel")).toBeVisible({
    timeout: 120_000,
  });
}

async function expectConsentCell(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  holderDid: string,
  peerDid: string,
  scope: string,
  expectedState: "granted" | "revoked" | "expired" | "pending",
) {
  const cell = await request.get(
    `${solandBaseUrl()}/api/v1/consent/cells/${encodeURIComponent(holderDid)}` +
      `?peer=${encodeURIComponent(peerDid)}&scope=${encodeURIComponent(scope)}`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  expect(cell.status()).toBe(200);
  const body = await cell.json();
  expect(JSON.stringify(body)).toContain(peerDid);
  expect(JSON.stringify(body)).toContain(scope);
  expect(JSON.stringify(body)).toContain(expectedState);
}

test.describe("consent grant", () => {
  test.fixme(
    "alice grants consent and bob can establish contact (full lifecycle)",
    async ({ browser, request }, testInfo) => {
      // spec: identity/consent-model.md §2-§4.
      // soland gap: cx.consent.* reducer/projection 未实现.
      // yougen gap: /contacts/new and /settings/consent consent UI 未实现.
      const stamp = Date.now();
      const alice = uniqueUser("consent-alice");
      const bob = uniqueUser("consent-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        await alicePage.gotoHome();
        await bobPage.gotoHome();

        const pendingStatus = await requestContact(bobPage, alice.did, "invite");
        await expect(pendingStatus).toContainText(/pending/i, { timeout: 30_000 });
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "pending");
        await stepShot(bobPage.page, testInfo, "A-bob-pending-consent");

        await gotoConsentSettings(alicePage);
        const pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
          hasText: bob.did,
        });
        await expect(pendingRow).toBeVisible({ timeout: 30_000 });
        await pendingRow.getByTestId("consent-detail-button").click();
        const detail = alicePage.page.getByTestId("consent-pending-detail");
        await expect(detail).toContainText(bob.did);
        await detail.getByTestId("consent-scope-select").selectOption("invite");
        await detail.getByTestId("consent-valid-until-input").fill(
          new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        );
        await detail.getByTestId("grant-consent-button").click();
        await expect(alicePage.page.getByTestId("write-status")).toContainText(/granted/i, {
          timeout: 30_000,
        });
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "granted");
        await stepShot(alicePage.page, testInfo, "B-alice-granted-consent");

        await bobPage.page.reload({ waitUntil: "domcontentloaded" });
        await expect(bobPage.page.getByTestId("contact-request-status")).toContainText(
          /accepted|granted/i,
          { timeout: 30_000 },
        );

        const retryStatus = await requestContact(bobPage, alice.did, "invite");
        await expect(retryStatus).toContainText(/accepted|already connected/i, {
          timeout: 30_000,
        });
        await alicePage.page.goto("/contacts", { waitUntil: "domcontentloaded" });
        await expect(alicePage.page.getByTestId("contact-row").filter({ hasText: bob.did })).toBeVisible({
          timeout: 30_000,
        });
        await stepShot(alicePage.page, testInfo, "C-contact-established");
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test.fixme(
    "E1.1 time-windowed consent expires after valid_until elapses",
    async ({ browser, request }, testInfo) => {
      /* spec: identity/consent-model.md §2. soland gap: cx.consent.* reducer 未实现 */
      const alice = uniqueUser("consent-window-alice");
      const bob = uniqueUser("consent-window-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        await requestContact(bobPage, alice.did, "invite");
        await gotoConsentSettings(alicePage);
        const pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
          hasText: bob.did,
        });
        await pendingRow.getByTestId("consent-detail-button").click();
        const detail = alicePage.page.getByTestId("consent-pending-detail");
        await detail.getByTestId("consent-valid-until-input").fill(
          new Date(Date.now() + 5_000).toISOString(),
        );
        await detail.getByTestId("grant-consent-button").click();
        await expect(alicePage.page.getByTestId("write-status")).toContainText(/granted/i);
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "granted");

        await expect(await requestContact(bobPage, alice.did, "invite")).toContainText(
          /accepted|already connected/i,
          { timeout: 30_000 },
        );
        await bobPage.page.waitForTimeout(6_000);
        const expiredStatus = await requestContact(bobPage, alice.did, "invite");
        await expect(expiredStatus).toContainText(/pending|expired/i, { timeout: 30_000 });
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "expired");
        await stepShot(bobPage.page, testInfo, "time-window-expired");
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test.fixme("E1.2 revoke then re-grant lifecycle", async ({ browser, request }, testInfo) => {
    /* spec: identity/consent-model.md §3. soland gap: cx.consent.* reducer 未实现 */
    const alice = uniqueUser("consent-regrant-alice");
    const bob = uniqueUser("consent-regrant-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

    try {
      await requestContact(bobPage, alice.did, "message");
      await gotoConsentSettings(alicePage);
      let pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
        hasText: bob.did,
      });
      await pendingRow.getByTestId("consent-detail-button").click();
      await alicePage.page.getByTestId("consent-pending-detail").getByTestId("grant-consent-button").click();
      await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "granted");

      const grantedRow = alicePage.page.getByTestId("consent-granted-row").filter({
        hasText: bob.did,
      });
      await expect(grantedRow).toBeVisible({ timeout: 30_000 });
      await grantedRow.getByTestId("revoke-consent-button").click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(/revoked/i, {
        timeout: 30_000,
      });
      await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "revoked");

      await expect(await requestContact(bobPage, alice.did, "message")).toContainText(/pending/i, {
        timeout: 30_000,
      });
      await alicePage.page.reload({ waitUntil: "domcontentloaded" });
      pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
        hasText: bob.did,
      });
      await pendingRow.getByTestId("consent-detail-button").click();
      await alicePage.page.getByTestId("consent-pending-detail").getByTestId("grant-consent-button").click();
      await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "granted");
      await expect(await requestContact(bobPage, alice.did, "message")).toContainText(
        /accepted|already connected/i,
        { timeout: 30_000 },
      );
      await stepShot(alicePage.page, testInfo, "revoke-then-regrant");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test.fixme(
    "E1.3 scope-granularity: invite-scope consent does not allow call",
    async ({ browser, request }, testInfo) => {
      /* spec: identity/consent-model.md §2. soland gap: cx.consent.* reducer 未实现 */
      const alice = uniqueUser("consent-scope-alice");
      const bob = uniqueUser("consent-scope-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        await requestContact(bobPage, alice.did, "invite");
        await gotoConsentSettings(alicePage);
        const inviteRow = alicePage.page.getByTestId("consent-pending-row").filter({
          hasText: bob.did,
        });
        await inviteRow.getByTestId("consent-detail-button").click();
        const detail = alicePage.page.getByTestId("consent-pending-detail");
        await detail.getByTestId("consent-scope-select").selectOption("invite");
        await detail.getByTestId("grant-consent-button").click();
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "granted");

        await expect(await requestContact(bobPage, alice.did, "invite")).toContainText(
          /accepted|already connected/i,
          { timeout: 30_000 },
        );
        await expect(await requestContact(bobPage, alice.did, "call")).toContainText(/pending/i, {
          timeout: 30_000,
        });
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "call", "pending");
        await stepShot(bobPage.page, testInfo, "scope-granularity-call-pending");
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test.fixme(
    "E1.4 pairwise DID consent isolates contact channels",
    async ({ browser, request }, testInfo) => {
      /* spec: identity/consent-model.md §4. soland gap: cx.consent.* reducer 未实现 */
      const alice = uniqueUser("consent-pairwise-alice");
      const bob = uniqueUser("consent-pairwise-bob");
      const bobPairwise = {
        ...bob,
        did: `did:peer:${Date.now()}bob-consent-pairwise`,
        handle: `${bob.handle}-pairwise`,
      };
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, bob),
        ensureRegistered(request, bobPairwise),
      ]);
      const [aliceToken, pairwiseToken, rootToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bobPairwise),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const pairwisePage = await openUserPage(browser, bobPairwise, { sessionToken: pairwiseToken });
      const rootPage = await openUserPage(browser, bob, { sessionToken: rootToken });

      try {
        await requestContact(pairwisePage, alice.did, "message");
        await gotoConsentSettings(alicePage);
        const pairwiseRow = alicePage.page.getByTestId("consent-pending-row").filter({
          hasText: bobPairwise.did,
        });
        await pairwiseRow.getByTestId("consent-detail-button").click();
        await alicePage.page.getByTestId("consent-pending-detail").getByTestId("grant-consent-button").click();
        await expectConsentCell(
          request,
          aliceToken,
          alice.did,
          bobPairwise.did,
          "message",
          "granted",
        );

        await expect(await requestContact(pairwisePage, alice.did, "message")).toContainText(
          /accepted|already connected/i,
          { timeout: 30_000 },
        );
        await expect(await requestContact(rootPage, alice.did, "message")).toContainText(
          /pending|needs consent/i,
          { timeout: 30_000 },
        );
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "pending");
        await stepShot(alicePage.page, testInfo, "pairwise-isolated");
      } finally {
        await Promise.allSettled([
          rootPage.close(),
          pairwisePage.close(),
          alicePage.close(),
        ]);
      }
    },
  );
});

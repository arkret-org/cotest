// Cross-member encrypted kanban
// Contract: e2e/scenarios/kanban/cross-member-encrypted.md
// Spec refs:
//   - crypto-media/encryption-and-audit.md §2.2-§2.4 (Welcome/Commit, envelope, sync)
//   - models/realm-and-space.md §2.2 encryption_profile, §3.7.2 E2EE Realm
//   - models/strand-and-message.md §2-§3 (Strand private `body` content path)
//
// WHY THIS EXISTS
// ---------------
// The suite already proves two adjacent things, but NOT the one that breaks most
// in real usage:
//   - kanban/end-to-end.spec.ts: a member encrypts card content on the SAME
//     device that created the Realm (creator-device round-trip only).
//   - encryption/mls-group.spec.ts "joined member decrypts E2EE timeline
//     messages": a DIFFERENT member decrypts, but only for CHAT messages.
//   - encryption/mls-group.spec.ts "fresh device ... refuses": a second device
//     of the SAME account, and it asserts a REFUSAL, not a successful decrypt.
//
// The untested gap — and the single most-recurring real-world failure — is a
// DIFFERENT member opening another member's ENCRYPTED KANBAN CARD and actually
// DECRYPTING its private content. Every historically-recurring bug in this area
// lives here: "invitee sees 0 cards", "the other member's board flashes then
// disappears", "card stuck Restoring", "body locked / can't decrypt",
// pre-join history, MLS policy_root drift. This test is the missing main chain.
//
// FALSE-GREEN PROOFS (this test is written to be un-cheatable)
//   1. Card TITLE is plaintext container metadata, so bob seeing the title only
//      proves cross-member PROJECTION/SYNC, not decryption. Decryption is proven
//      separately: bob must read the private DESCRIPTION body, and
//      `card-detail-body-locked` must NOT be present.
//   2. `kanban-card-redacted` (the withdrawn-content placeholder) must be absent
//      for the target card — a card that failed to decrypt/hydrate must not pass.
//   3. The description must NOT appear verbatim on alice's submit wire (proves the
//      realm was actually encrypted, not a false-green on a plaintext realm).
//   4. After bob RELOADS, the card and its decrypted body must still be present —
//      catching the "flash then live-refresh clobbers the backfill" regression.

import { expect, test, type Page } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import { selfPathGrantHeaders } from "../../helpers/session-grant-dpop";
import {
  assertJointStackNotRequired,
  createDpopUserSession,
  openUserPage,
  type JointUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

// Build an encrypted board + one list + one card (title only) and return the
// board's ck:space: id so the invitee can deep-link straight to it. Mirrors the
// proven flow in kanban/end-to-end.spec.ts and mls-group.spec.ts.
async function buildEncryptedBoardListCard(
  page: Page,
  realmId: string,
  boardTitle: string,
  listTitle: string,
  cardTitle: string,
): Promise<string> {
  await page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
  await page.getByTestId("new-board-toggle").click();
  await page.getByTestId("new-board-title-input").fill(boardTitle);
  await page.getByTestId("create-board-space-button").click();
  await expect(page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
    timeout: 45_000,
  });
  await expect.poll(() => page.url(), { timeout: 30_000 }).toContain("/board/ck:space:");
  const boardId = decodeURIComponent(
    new URL(page.url()).pathname.split("/board/")[1]?.split("/")[0] ?? "",
  );
  expect(boardId, `board id from url ${page.url()}`).toMatch(/^ck:space:/);

  await page.getByTestId("new-column-input").fill(listTitle);
  await page.getByTestId("add-column-button").click();
  const column = page.getByTestId("kanban-column").filter({ hasText: listTitle }).first();
  await expect(column).toBeVisible({ timeout: 45_000 });
  await column.getByTestId("add-card-button").click();
  await column.getByTestId("new-card-title-input").fill(cardTitle);
  await column.getByTestId("save-card-button").click();
  await expect(
    column.getByTestId("kanban-card").filter({ hasText: cardTitle }),
  ).toBeVisible({ timeout: 45_000 });
  return boardId;
}

// Add an encrypted private description to a card through the UI and assert the
// ck.strand.update was accepted AND actually encrypted (description never
// appears verbatim on the wire). Mirrors kanban/end-to-end.spec.ts.
async function addEncryptedDescription(
  page: Page,
  cardTitle: string,
  description: string,
): Promise<void> {
  await page.getByTestId("kanban-card").filter({ hasText: cardTitle }).first().click();
  await expect(page.getByTestId("card-detail-modal")).toBeVisible({ timeout: 45_000 });
  await page.getByTestId("card-detail-tab-description").click();
  await page.getByTestId("card-detail-add-description-button").click();

  const editor = page.getByTestId("card-detail-description-input");
  await expect(editor).toBeAttached({ timeout: 45_000 });
  await editor.evaluate((node, value) => {
    const textarea = node as HTMLTextAreaElement;
    textarea.value = value;
    textarea.dispatchEvent(
      new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }),
    );
  }, description);

  const strandUpdate = page.waitForResponse(
    (response) =>
      response.url().includes("/_cokret/self/events") &&
      response.request().method() === "POST" &&
      (response.request().postData() ?? "").includes("ck.strand.update"),
    { timeout: 60_000 },
  );
  await page.getByTestId("card-detail-save-button").click();

  const response = await strandUpdate;
  const body = await response.text();
  expect(
    body.includes("content_encryption_floor_violation"),
    `description ck.strand.update hit the content-encryption floor — client shipped plaintext to an encrypted realm: ${response.status()} ${body.slice(0, 500)}`,
  ).toBe(false);
  expect(response.status(), `ck.strand.update should be accepted; body=${body.slice(0, 500)}`).toBeLessThan(400);
  expect(
    (response.request().postData() ?? "").includes(description),
    "description leaked as plaintext into the ck.strand.update wire — realm not actually encrypted",
  ).toBe(false);

  await expect(page.getByTestId("card-description-panel")).toContainText(description, {
    timeout: 120_000,
  });
  // Close the modal so the invitee-side assertions start from the board.
  await page.getByTestId("card-detail-close-button").click();
}

// Open the target card as the reader and PROVE decryption: the private body is
// visible in plaintext and NO `card-detail-body-locked` affordance is shown.
async function assertCardDecrypts(
  reader: JointUserPage,
  cardTitle: string,
  expectedDescription: string,
): Promise<void> {
  const card = reader.page.getByTestId("kanban-card").filter({ hasText: cardTitle }).first();
  await expect(card, `${reader.user.name} must see the card (cross-member projection)`).toBeVisible({
    timeout: 90_000,
  });
  // The card must be the real, hydrated card — never the withdrawn-content
  // placeholder that a decrypt/hydration failure renders.
  await expect(
    reader.page.getByTestId("kanban-card-redacted").filter({ hasText: cardTitle }),
  ).toHaveCount(0);

  await card.click();
  await expect(reader.page.getByTestId("card-detail-modal")).toBeVisible({ timeout: 45_000 });
  await reader.page.getByTestId("card-detail-tab-description").click();

  // The decryption proof: the private body renders in plaintext...
  await expect(reader.page.getByTestId("card-description-panel")).toContainText(
    expectedDescription,
    { timeout: 120_000 },
  );
  // ...and the "locked / cannot decrypt" affordance is NOT shown.
  await expect(reader.page.getByTestId("card-detail-body-locked")).toHaveCount(0);
  await reader.page.getByTestId("card-detail-close-button").click();
}

test.describe("cross-member encrypted kanban", () => {
  test("bob joins an MLS-encrypted realm and decrypts alice's encrypted card content; survives reload; bob's own card projects back to alice", async ({
    browser,
    request,
  }, testInfo) => {
    // The full two-browser MLS flow (recovery-key setup, create, board+card,
    // encrypt, invite, Welcome, join, cross-member decrypt, reload, reverse
    // direction) does not fit the 180s default — mirror the sibling MLS browser
    // budget so it does not time out mid-flow.
    test.setTimeout(360_000);

    const stamp = Date.now();
    const [aliceSession, bobSession] = await Promise.all([
      createDpopUserSession(request, "xmenc-alice"),
      createDpopUserSession(request, "xmenc-bob"),
    ]);
    if (!aliceSession || !bobSession) {
      // Do not silently green-skip the crown-jewel cross-member decrypt path on
      // the joint harness; fail loud when the stack is declared present.
      assertJointStackNotRequired(
        "cross-member encrypted kanban requires coauth DPoP session-grant login",
      );
      test.skip(true, "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages");
      return;
    }

    const alice = aliceSession.user;
    const bob = bobSession.user;
    const [alicePage, bobPage] = await Promise.all([
      openUserPage(browser, alice, {
        grantJwt: aliceSession.grantJwt,
        dpopSeedB64url: aliceSession.dpopSeedB64url,
        grantId: aliceSession.grantId,
        grantAudience: aliceSession.grantAudience,
      }),
      openUserPage(browser, bob, {
        grantJwt: bobSession.grantJwt,
        dpopSeedB64url: bobSession.dpopSeedB64url,
        grantId: bobSession.grantId,
        grantAudience: bobSession.grantAudience,
      }),
    ]);

    const boardTitle = `Enc XM Board ${stamp}`;
    const listTitle = `Todo-${stamp}`;
    const aliceCard = `Alice secret card ${stamp}`;
    const aliceDescription = `Alice private detail ${stamp}`;
    const bobCard = `Bob reply card ${stamp}`;

    try {
      await Promise.all([alicePage.gotoHome(), bobPage.gotoHome()]);
      await Promise.all([
        alicePage.completeRecoveryKeySetupIfPrompted(),
        bobPage.completeRecoveryKeySetupIfPrompted(),
      ]);
      await Promise.all([
        alicePage.acknowledgeRecommendedEncryptionPromptIfVisible(),
        bobPage.acknowledgeRecommendedEncryptionPromptIfVisible(),
      ]);

      // 1) Alice creates an MLS-encrypted realm with an encrypted card.
      const realmId = await alicePage.createRealm({
        title: `Encrypted XM Kanban ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });
      const boardId = await buildEncryptedBoardListCard(
        alicePage.page,
        realmId,
        boardTitle,
        listTitle,
        aliceCard,
      );
      await addEncryptedDescription(alicePage.page, aliceCard, aliceDescription);
      await stepShot(alicePage.page, testInfo, "A-alice-encrypted-card");

      // 2) Alice invites bob → MLS Welcome must be queued (KeyPackage claimed).
      const inviteStatus = await alicePage.inviteFromAdmin(realmId, bob.did);
      expect(
        inviteStatus,
        "inviting a member of an MLS realm must queue a Welcome (KeyPackage claimed)",
      ).toContain("MLS Welcome queued");

      // 3) Bob accepts and opens the board. Route-context bootstrap is where his
      //    client applies the pending MLS Welcome and hydrates realm state.
      await bobPage.acceptInvite(realmId);
      await bobPage.page.goto(`/kanban/${realmId}/board/${boardId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(bobPage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });

      // 4) THE CORE ASSERTION: bob decrypts alice's private card content.
      await assertCardDecrypts(bobPage, aliceCard, aliceDescription);
      await stepShot(bobPage.page, testInfo, "B-bob-decrypted-card");

      // 5) Reload survival: the decrypted card must not flash-then-vanish when
      //    the live refresh clobbers the bootstrap backfill.
      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expect(bobPage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await assertCardDecrypts(bobPage, aliceCard, aliceDescription);
      await stepShot(bobPage.page, testInfo, "C-bob-card-survives-reload");

      // 6) Reverse direction: bob adds his own card; it must project back to
      //    alice (the admission fork historically broke BOTH directions).
      const bobColumn = bobPage.page.getByTestId("kanban-column").filter({ hasText: listTitle }).first();
      await bobColumn.getByTestId("add-card-button").click();
      await bobColumn.getByTestId("new-card-title-input").fill(bobCard);
      await bobColumn.getByTestId("save-card-button").click();
      await expect(bobColumn.getByTestId("kanban-card").filter({ hasText: bobCard })).toBeVisible({
        timeout: 45_000,
      });

      await alicePage.page.goto(`/kanban/${realmId}/board/${boardId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(alicePage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await expect(
        alicePage.page.getByTestId("kanban-card").filter({ hasText: bobCard }),
        "bob's card must project back to alice (reverse cross-member sync)",
      ).toBeVisible({ timeout: 90_000 });
      await expect(
        alicePage.page.getByTestId("kanban-card-redacted").filter({ hasText: bobCard }),
      ).toHaveCount(0);
      await stepShot(alicePage.page, testInfo, "D-alice-sees-bob-card");

      // 7) Raw wire stays ciphertext for the private body: the encrypted realm
      //    must never expose alice's description verbatim in the event log.
      const rawEventsUrl = `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=200`;
      const rawEvents = await request.get(rawEventsUrl, {
        headers: selfPathGrantHeaders({
          deviceKey: aliceSession.deviceKey,
          grantJwt: aliceSession.grantJwt,
          method: "GET",
          url: rawEventsUrl,
        }),
      });
      expect(rawEvents.status()).toBe(200);
      expect(JSON.stringify(await rawEvents.json())).not.toContain(aliceDescription);
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });
});

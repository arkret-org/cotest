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
// pre-join history, MLS Security Frontier drift. This test is the missing main chain.
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

import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import { canonicalJson } from "../../helpers/soland-api";
import { grantInviteConsentArkret } from "../../helpers/contact-api";
import { stepShot } from "../../helpers/screenshots";
import { selfPathGrantHeaders } from "../../helpers/session-grant-dpop";
import { installMlsOutboundFault } from "../../helpers/mls-outbound-fault";
import {
  assertJointStackNotRequired,
  createDpopUserSession,
  issueInviteLocatorToken,
  openDpopUserPageFromSession,
  openUserPage,
  type DpopUserSession,
  type JointUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type E2eeStorageEvidence = {
  secureEntryKeys: string[];
  localStorageE2eeKeys: string[];
  localStoragePlaintextMatches: string[];
  indexedDbPlaintextMatches: string[];
  encryptedSecureEntryCount: number;
  wrappingKeyExtractable: boolean | null;
};

// The Welcome is a recipient delivery, not a shared Event. Wait for the
// accepted member-add Commit before the recipient reload/decrypt assertions.
async function waitForMlsCommit(
  request: APIRequestContext,
  session: DpopUserSession,
  realmId: string,
  recipientId: string,
): Promise<void> {
  await expect
    .poll(
      async () => {
        const url = `${solandBaseUrl()}/_arkret/self/streams/scan`;
        const response = await request.fetch(url, {
          method: "POST",
          data: canonicalJson({
            realm_id: realmId,
            stream_ref: { kind: "realm", realm_id: realmId },
            after_position: null,
            limit: 500,
          }),
          headers: {
            "content-type": "application/json",
            ...selfPathGrantHeaders({
              deviceKey: session.deviceKey,
              grantJwt: session.grantJwt,
              method: "POST",
              url,
            }),
          },
        });
        if (response.status() !== 200) {
          return `status ${response.status()}: ${await response.text()}`;
        }
        const body = await response.json();
        return (body.committed_events ?? []).some(
          (item: { event?: Record<string, any> }) =>
            item.event?.kind === "ak.mls.commit",
        );
      },
      {
        timeout: 120_000,
        intervals: [1_000, 2_000, 5_000],
        message: `MLS member-add Commit for ${recipientId} was not accepted in ${realmId}`,
      },
    )
    .toBe(true);
}

// Inspect only the raw persistence representation. This deliberately does not
// decrypt the secure entry: the acceptance boundary is that localStorage has no
// E2EE mirror, IndexedDB contains only IV+ciphertext records, and its wrapping
// CryptoKey remains non-extractable.
async function readE2eeStorageEvidence(
  page: Page,
  plaintextMarkers: string[],
): Promise<E2eeStorageEvidence> {
  return page.evaluate(async (markers) => {
    const prefix = "inkson.e2ee_plaintext_cache.v1.";
    const localStorageKeys: string[] = [];
    const localStorageValues: string[] = [];
    for (let index = 0; index < window.localStorage.length; index += 1) {
      const key = window.localStorage.key(index);
      if (!key) continue;
      localStorageKeys.push(key);
      localStorageValues.push(window.localStorage.getItem(key) ?? "");
    }

    const requestResult = (request: IDBRequest): Promise<unknown> =>
      new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
          reject(request.error ?? new Error("IndexedDB request failed"));
      });
    const openRequest = window.indexedDB.open("inkson.secret.inkson", 1);
    const db = (await requestResult(openRequest)) as IDBDatabase;
    try {
      const entriesTx = db.transaction("entries", "readonly");
      const entries = entriesTx.objectStore("entries");
      const [keysResult, valuesResult] = await Promise.all([
        requestResult(entries.getAllKeys()),
        requestResult(entries.getAll()),
      ]);
      const keys = (keysResult as IDBValidKey[]).map(String);
      const values = valuesResult as Array<{ iv?: unknown; ct?: unknown }>;
      const secureEntryIndexes = keys
        .map((key, index) => (key.startsWith(prefix) ? index : -1))
        .filter((index) => index >= 0);
      const toBytes = (value: unknown): Uint8Array => {
        if (value instanceof Uint8Array) return value;
        if (value instanceof ArrayBuffer) return new Uint8Array(value);
        return new Uint8Array();
      };
      const rawIndexedDbText = values
        .flatMap((value) => [toBytes(value.iv), toBytes(value.ct)])
        .map((bytes) => new TextDecoder().decode(bytes))
        .join("\n");
      const encryptedSecureEntryCount = secureEntryIndexes.filter((index) => {
        const value = values[index];
        return (
          toBytes(value?.iv).byteLength === 12 &&
          toBytes(value?.ct).byteLength > 16
        );
      }).length;

      const wrappingTx = db.transaction("wrapping_keys", "readonly");
      const wrappingKey = (await requestResult(
        wrappingTx.objectStore("wrapping_keys").get("primary"),
      )) as CryptoKey | undefined;

      return {
        secureEntryKeys: secureEntryIndexes.map((index) => keys[index]),
        localStorageE2eeKeys: localStorageKeys.filter((key) =>
          key.includes(prefix),
        ),
        localStoragePlaintextMatches: markers.filter((marker) =>
          localStorageValues.some((value) => value.includes(marker)),
        ),
        indexedDbPlaintextMatches: markers.filter((marker) =>
          rawIndexedDbText.includes(marker),
        ),
        encryptedSecureEntryCount,
        wrappingKeyExtractable:
          typeof wrappingKey?.extractable === "boolean"
            ? wrappingKey.extractable
            : null,
      };
    } finally {
      db.close();
    }
  }, plaintextMarkers);
}

async function assertE2eeStorageIsHardened(
  page: Page,
  plaintextMarkers: string[],
): Promise<void> {
  await expect
    .poll(() => readE2eeStorageEvidence(page, plaintextMarkers), {
      timeout: 30_000,
      intervals: [250, 500, 1_000],
      message: "account-scoped E2EE secure cache never reached IndexedDB",
    })
    .toMatchObject({
      localStorageE2eeKeys: [],
      localStoragePlaintextMatches: [],
      indexedDbPlaintextMatches: [],
      wrappingKeyExtractable: false,
    });

  const persisted = await readE2eeStorageEvidence(page, plaintextMarkers);
  expect(persisted.secureEntryKeys).toHaveLength(1);
  expect(persisted.encryptedSecureEntryCount).toBe(1);
}

// Build an encrypted board + one list + one card (title only) and return the
// board's ak:space: id so the invitee can deep-link straight to it. Mirrors the
// proven flow in kanban/end-to-end.spec.ts and mls-group.spec.ts.
async function buildEncryptedBoardListCard(
  page: Page,
  realmId: string,
  boardTitle: string,
  listTitle: string,
  cardTitle: string,
): Promise<string> {
  await page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible({
    timeout: 120_000,
  });
  await page.getByTestId("new-board-toggle").click();
  await page.getByTestId("new-board-title-input").fill(boardTitle);
  await page.getByTestId("create-board-space-button").click();
  await expect(page.getByTestId("kanban-empty-board")).toContainText(
    /No lists yet/,
    {
      timeout: 45_000,
    },
  );
  await expect
    .poll(() => page.url(), { timeout: 30_000 })
    .toContain("/board/ak:space:");
  const boardId = decodeURIComponent(
    new URL(page.url()).pathname.split("/board/")[1]?.split("/")[0] ?? "",
  );
  expect(boardId, `board id from url ${page.url()}`).toMatch(/^ak:space:/);

  await page.getByTestId("new-column-input").fill(listTitle);
  await page.getByTestId("add-column-button").click();
  const column = page
    .getByTestId("kanban-column")
    .filter({ hasText: listTitle })
    .first();
  await expect(column).toBeVisible({ timeout: 45_000 });
  await column.getByTestId("add-card-button").click();
  await column.getByTestId("new-card-title-input").fill(cardTitle);
  await column.getByTestId("save-card-button").click();
  const createdCard = column.getByTestId("kanban-card").filter({ hasText: cardTitle });
  await expect(createdCard).toBeVisible({ timeout: 45_000 });
  // A visible optimistic draft does not yet name an accepted Strand. Editing
  // its private tracks requires the confirmed object identity.
  await expect(createdCard).toHaveAttribute("data-card-draft", "false", {
    timeout: 120_000,
  });
  return boardId;
}

// Add an encrypted private description to a card through the UI and assert the
// ak.strand.update was accepted AND actually encrypted (description never
// appears verbatim on the wire). Mirrors kanban/end-to-end.spec.ts.
async function addEncryptedDescription(
  page: Page,
  cardTitle: string,
  description: string,
): Promise<void> {
  await page
    .getByTestId("kanban-card")
    .filter({ hasText: cardTitle })
    .first()
    .click();
  await expect(page.getByTestId("card-detail-modal")).toBeVisible({
    timeout: 45_000,
  });
  await page.getByTestId("card-detail-tab-description").click();
  await page.getByTestId("card-detail-edit-description-button").click();

  const editor = page.getByTestId("card-detail-description-input");
  await expect(editor).toBeAttached({ timeout: 45_000 });
  await editor.evaluate((node, value) => {
    const textarea = node as HTMLTextAreaElement;
    textarea.value = value;
    textarea.dispatchEvent(
      new InputEvent("input", {
        bubbles: true,
        inputType: "insertText",
        data: value,
      }),
    );
  }, description);

  const responseDeadline = Date.now() + 120_000;
  let response: Awaited<ReturnType<Page["waitForResponse"]>> | undefined;
  // Keep one observer through checkpoint recovery so an asynchronous save
  // cannot fall between short-lived response listeners.
  const strandUpdate = page.waitForResponse(
    (candidate) =>
      candidate.url().includes("/_arkret/self/events") &&
      candidate.request().method() === "POST" &&
      (candidate.request().postData() ?? "").includes("ak.strand.update"),
    { timeout: 120_000 },
  ).catch(() => undefined);
  await page.getByTestId("card-detail-save-button").click();
  while (Date.now() < responseDeadline) {
    response = await Promise.race([
      strandUpdate,
      page.waitForTimeout(Math.min(10_000, responseDeadline - Date.now())).then(() => undefined),
    ]);
    if (response) break;

    const status =
      (
        await page.getByTestId("card-detail-edit-status").textContent()
      )?.trim() ?? "";
    expect(
      status,
      "description save produced neither ak.strand.update nor a visible failure status",
    ).not.toBe("");
    expect(
      status.includes("encryption_transition_pending")
        || status === "Restoring encrypted Realm state before saving...",
      `description save failed before submission: ${status}`,
    ).toBe(true);
    if (status.includes("encryption_transition_pending") && Date.now() < responseDeadline) {
      await page.getByTestId("card-detail-save-button").click();
    }
  }
  expect(
    response,
    "description remained encryption_transition_pending after the MLS admission convergence deadline",
  ).toBeDefined();

  const acceptedResponse = response!;
  const body = await acceptedResponse.text();
  expect(
    body.includes("content_encryption_floor_violation"),
    `description ak.strand.update hit the content-encryption floor — client shipped plaintext to an encrypted realm: ${acceptedResponse.status()} ${body.slice(0, 500)}`,
  ).toBe(false);
  expect(
    acceptedResponse.status(),
    `ak.strand.update should be accepted; body=${body.slice(0, 500)}`,
  ).toBeLessThan(400);
  expect(
    (acceptedResponse.request().postData() ?? "").includes(description),
    "description leaked as plaintext into the ak.strand.update wire — realm not actually encrypted",
  ).toBe(false);

  await expect(page.getByTestId("card-description-panel")).toContainText(
    description,
    {
      timeout: 120_000,
    },
  );
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
  const card = reader.page
    .getByTestId("kanban-card")
    .filter({ hasText: cardTitle })
    .first();
  await expect(
    card,
    `${reader.user.name} must see the card (cross-member projection)`,
  ).toBeVisible({
    timeout: 90_000,
  });
  // The card must be the real, hydrated card — never the withdrawn-content
  // placeholder that a decrypt/hydration failure renders.
  await expect(
    reader.page
      .getByTestId("kanban-card-redacted")
      .filter({ hasText: cardTitle }),
  ).toHaveCount(0);

  // The recovery/backup nag modal can re-pop and its backdrop intercepts the
  // card click; dismiss it then open the card, retrying past a late modal.
  const detailModal = reader.page.getByTestId("card-detail-modal");
  await expect
    .poll(
      async () => {
        if (await detailModal.isVisible().catch(() => false)) return true;
        await dismissRecoveryNags(reader);
        await card.click({ timeout: 3_000 }).catch(() => {});
        return detailModal.isVisible().catch(() => false);
      },
      {
        timeout: 60_000,
        intervals: [1_000, 2_000],
        message: `${reader.user.name} could not open the card detail (nag modal blocking?)`,
      },
    )
    .toBe(true);
  await dismissRecoveryNags(reader);
  await reader.page.getByTestId("card-detail-tab-description").click();

  // The decryption proof: the private body renders in plaintext...
  await expect(reader.page.getByTestId("card-description-panel")).toContainText(
    expectedDescription,
    { timeout: 120_000 },
  );
  // ...and the "locked / cannot decrypt" affordance is NOT shown.
  await expect(reader.page.getByTestId("card-detail-body-locked")).toHaveCount(
    0,
  );
  await reader.page.getByTestId("card-detail-close-button").click();
}

// A member who has not set up encrypted-history recovery (every invitee, and
// any creator until they save a Recovery Key) is nagged by modal prompts — the
// "Protect your encrypted history" backup modal and the MLS recovery/unlock
// modals — whose dialog backdrop blocks board interaction and which re-appear on
// navigation. Dismiss whichever is currently up. Best-effort; never throws.
async function dismissRecoveryNags(reader: JointUserPage): Promise<void> {
  const page = reader.page;
  // The "Set up your 24-word Recovery Key" modal (required before encryption) has
  // NO dismiss affordance — it must be COMPLETED (save the generated key + confirm
  // it back). An invitee hits it the moment they touch encrypted content.
  await reader.completeRecoveryKeySetupIfPrompted(500).catch(() => undefined);
  for (const testId of [
    "mls-backup-dismiss",
    "mls-recovery-missing-dismiss",
    "mls-unlock-dismiss",
  ]) {
    const btn = page.getByTestId(testId).last();
    if (await btn.isVisible({ timeout: 300 }).catch(() => false)) {
      await btn.click({ timeout: 3_000 }).catch(() => {});
    }
  }
}

// Get a member's already-loaded kanban route into a readable board state:
// dismiss the recovery nags, then EXPLICITLY select the board so its lists/cards
// project into view — the deep-link `/board/<id>` route alone leaves the
// board-space selector unset ("Select an option"), so no lists render. If the
// member's projection never received the board space, the option never appears
// and this throws — which is itself the cross-member-projection bug this test
// hunts. Forces past the board-toolbar button overlap and retries the open with
// nag-dismissal in case a late modal intercepts.
async function readyReaderBoard(
  reader: JointUserPage,
  boardId: string,
): Promise<void> {
  const page = reader.page;
  await expect(page.getByTestId("kanban-panel")).toBeVisible({
    timeout: 120_000,
  });
  // Clear the recovery/backup nags whose modal backdrop blocks board interaction
  // and which re-appear on navigation.
  for (let i = 0; i < 5; i += 1) {
    await dismissRecoveryNags(reader);
    await page.waitForTimeout(400);
  }
  // Best-effort: explicitly select alice's board so the right board's lists
  // render. The deep-link `/board/<id>` route + first-board auto-select usually
  // already select it once the board Space projects into the switcher (that
  // projection is the actual thing under test), so a hiccup opening the dxc
  // Select here is NOT fatal — assertCardDecrypts (a 90s poll for the decrypted
  // card) is the real gate.
  const selectScope = page.getByTestId("board-space-select");
  const trigger = selectScope
    .locator('button[aria-haspopup="listbox"]')
    .first();
  const quoted = boardId.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const option = selectScope.locator(`[role="option"][data-value="${quoted}"]`);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    await dismissRecoveryNags(reader);
    if (
      (await trigger.getAttribute("aria-expanded").catch(() => null)) !== "true"
    ) {
      await trigger.click({ force: true, timeout: 3_000 }).catch(() => {});
    }
    if (await option.isVisible({ timeout: 1_500 }).catch(() => false)) {
      await option.click({ force: true }).catch(() => {});
      break;
    }
  }
  if (
    (await trigger.getAttribute("aria-expanded").catch(() => null)) === "true"
  ) {
    await trigger.press("Escape").catch(() => {});
  }
}

async function openReaderBoard(
  reader: JointUserPage,
  realmId: string,
  boardId: string,
): Promise<void> {
  await reader.page.goto(`/kanban/${realmId}/board/${boardId}`, {
    waitUntil: "domcontentloaded",
  });
  await readyReaderBoard(reader, boardId);
}

test.describe("cross-member encrypted kanban @fully-implemented", () => {
  test("creator E2EE plaintext cache is encrypted in IndexedDB and survives reload", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(240_000);

    const stamp = Date.now();
    const creatorSession = await createDpopUserSession(
      request,
      "e2ee-cache-creator",
    );
    if (!creatorSession) {
      assertJointStackNotRequired(
        "E2EE secure-cache browser acceptance requires coauth DPoP session-grant login",
      );
      test.skip(
        true,
        "coauth DPoP session-grant login is required for MLS encryption",
      );
      return;
    }

    const creator = await openUserPage(browser, creatorSession.user, {
      grantJwt: creatorSession.grantJwt,
      dpopSeedB64url: creatorSession.dpopSeedB64url,
      eventSigningSeedB64url: creatorSession.eventSigningSeedB64url,
      grantId: creatorSession.grantId,
      accountId: creatorSession.accountId,
      principalControlRealmId: creatorSession.principalControlRealmId,
      grantAudience: creatorSession.grantAudience,
      recoveryKey: creatorSession.recoveryKey,
      recoveryMaterialEvidence: creatorSession.recoveryMaterialEvidence,
    });
    const boardTitle = `Secure cache board ${stamp}`;
    const listTitle = `Secure cache list ${stamp}`;
    const cardTitle = `Secure cache card ${stamp}`;
    const privateDescription = `Secure cache private description ${stamp}`;

    try {
      await creator.gotoHome();
      await creator.completeRecoveryKeySetupIfPrompted();
      await creator.acknowledgeRecommendedEncryptionPromptIfVisible();

      const realmId = await creator.createRealm({
        title: `Secure cache realm ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        mlsActivated: true,
      });
      const boardId = await buildEncryptedBoardListCard(
        creator.page,
        realmId,
        boardTitle,
        listTitle,
        cardTitle,
      );
      await addEncryptedDescription(
        creator.page,
        cardTitle,
        privateDescription,
      );

      await assertE2eeStorageIsHardened(creator.page, [privateDescription]);
      await stepShot(creator.page, testInfo, "A-secure-cache-before-reload");

      await creator.page.reload({ waitUntil: "domcontentloaded" });
      await readyReaderBoard(creator, boardId);
      await assertCardDecrypts(creator, cardTitle, privateDescription);
      await assertE2eeStorageIsHardened(creator.page, [privateDescription]);
      await stepShot(creator.page, testInfo, "B-secure-cache-after-reload");
    } finally {
      await creator.close();
    }
  });

  for (const fault of [undefined, "commit-response-lost", "welcome-before-durable", "welcome-response-lost"] as const) {
    test("bob joins an MLS-encrypted realm and decrypts alice's encrypted card content; survives reload; bob's own card projects back to alice" + (fault ? `; recovers ${fault}` : ""), async ({
      browser,
      request,
    }, testInfo) => {
      // The full two-browser MLS flow (recovery-key setup, create, board+card,
      // encrypt, invite, Welcome, join, cross-member decrypt, reload, reverse
      // direction) does not fit the 180s default — mirror the sibling MLS browser
      // budget so it does not time out mid-flow.
      test.setTimeout(fault ? 600_000 : 360_000);

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
        test.skip(
          true,
          "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
        );
        return;
      }

      const alice = aliceSession.user;
      const bob = bobSession.user;
      const aliceFlow = await openDpopUserPageFromSession(browser, aliceSession);
      expect(aliceFlow).toBeTruthy();
      const alicePage = aliceFlow!.page;
      let bobPage: JointUserPage | undefined;
      let outboundFault: Awaited<ReturnType<typeof installMlsOutboundFault>> | undefined;

      const boardTitle = `Enc XM Board ${stamp}`;
      const listTitle = `Todo-${stamp}`;
      const aliceCard = `Alice secret card ${stamp}`;
      const aliceDescription = `Alice private detail ${stamp}`;
      const bobCard = `Bob reply card ${stamp}`;
      const bobDescription = `Bob private reply ${stamp}`;

      try {
        await alicePage.gotoHome();
        await alicePage.completeRecoveryKeySetupIfPrompted();
        await alicePage.acknowledgeRecommendedEncryptionPromptIfVisible();

        // 1) Alice creates an EMPTY MLS-encrypted realm.
        const realmId = await alicePage.createRealm({
          title: `Encrypted XM Kanban ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          historyAccess: "since_join",
          mlsActivated: true,
        });
        await grantInviteConsentArkret(
          request,
          bobSession.grantJwt,
          bob,
          alice.id,
        );

        // 2) Invite Bob before his browser has completed the founding-device
        // bootstrap or published a KeyPackage. The invite must persist even
        // though immediate MLS admission is deferred.
        // Bob has not published a receive policy yet. His deliberately shared
        // locator supplies the high-trust introduction the default requires;
        // a bare address would correctly enter quarantine even with consent.
        const bobLocatorToken = await issueInviteLocatorToken(request, bobSession.grantJwt);
        const inviteStatus = await alicePage.inviteFromAdmin(
          realmId,
          bob.id,
          bob.id,
          { token: bobLocatorToken },
        );
        expect(
          inviteStatus,
          "the Realm invite must persist while Bob has no claimable KeyPackage",
        ).toContain("invited");
        expect(inviteStatus).not.toContain("MLS Welcome queued");

        // Bob now completes the atomic PCR create + founding-device authorization.
        // This publishes his real event-signer KeyPackage after the invite already
        // exists, exercising the deferred Welcome reconciliation path.
        const bobFlow = await openDpopUserPageFromSession(browser, bobSession);
        expect(bobFlow).toBeTruthy();
        bobPage = bobFlow!.page;
        await bobPage.gotoHome();
        await bobPage.completeRecoveryKeySetupIfPrompted();
        await bobPage.acknowledgeRecommendedEncryptionPromptIfVisible();

        // 3) Bob JOINS before any board content exists. This matters twice over:
        //    under history_access=since_join, soland crops pre-join events from
        //    bob's view; and under MLS forward secrecy, bob has no key for epochs
        //    that predate his membership. So content alice creates AFTER this point
        //    is the content bob can legitimately both see and decrypt. (Pre-join
        //    history sharing is a separate, optional capability — not the core
        //    cross-member collaboration path this test exercises.)
        if (fault) {
          outboundFault = await installMlsOutboundFault(alicePage.page, realmId, fault);
        }
        await bobPage.acceptInvite(realmId);
        if (outboundFault) {
          await outboundFault.waitForCut();
          // Destroy the sender's wasm runtime while the real transport remains
          // cut. Recovery must reload the original durable saga and signed IDs.
          await alicePage.page.reload({ waitUntil: "domcontentloaded" });
          await outboundFault.restore();
        }
        await bobPage.gotoTimelineRealm(realmId);
        await waitForMlsCommit(request, aliceSession, realmId, bob.id);
        await bobPage.page.reload({ waitUntil: "domcontentloaded" });
        await bobPage.completeRecoveryKeySetupIfPrompted();

        // 4) Alice builds the board + encrypted card AFTER bob is a member, so it is
        //    post-join shared content for bob.
        const boardId = await buildEncryptedBoardListCard(
          alicePage.page,
          realmId,
          boardTitle,
          listTitle,
          aliceCard,
        );
        await addEncryptedDescription(
          alicePage.page,
          aliceCard,
          aliceDescription,
        );
        await stepShot(alicePage.page, testInfo, "A-alice-encrypted-card");

        // 4b) Cross-member DELIVERY gate (isolates soland delivery from inkson
        //     projection): soland MUST surface alice's post-join board Space create
        //     on bob's own realm events feed — the same feed the kanban backfill
        //     ingests. If the board id is absent here, the bug is soland-side
        //     Space delivery/visibility; if present but the board never appears in
        //     bob's UI below, the bug is inkson's board projection.
        await expect
          .poll(
            async () => {
              const url = `${solandBaseUrl()}/_arkret/self/streams/scan`;
              const resp = await request.fetch(url, {
                method: "POST",
                data: canonicalJson({
                  realm_id: realmId,
                  stream_ref: { kind: "realm", realm_id: realmId },
                  after_position: null,
                  limit: 500,
                }),
                headers: {
                  "content-type": "application/json",
                  ...selfPathGrantHeaders({
                    deviceKey: bobSession.deviceKey,
                    grantJwt: bobSession.grantJwt,
                    method: "POST",
                    url,
                  }),
                },
              });
              if (resp.status() !== 200) return `status ${resp.status()}`;
              return JSON.stringify(await resp.json());
            },
            {
              timeout: 60_000,
              intervals: [1_000, 2_000, 5_000],
              message: `soland never delivered alice's board Space (${boardId}) to bob's realm events feed — cross-member Space delivery/visibility gap (not a inkson projection issue)`,
            },
          )
          .toContain(boardId);

        // 5) THE CORE ASSERTION: bob opens the board and decrypts alice's private
        //    card content.
        await openReaderBoard(bobPage, realmId, boardId);
        await assertCardDecrypts(bobPage, aliceCard, aliceDescription);
        await assertE2eeStorageIsHardened(bobPage.page, [aliceDescription]);
        await stepShot(bobPage.page, testInfo, "B-bob-decrypted-card");

        // 5) Reload survival: the decrypted card must not flash-then-vanish when
        //    the live refresh clobbers the bootstrap backfill.
        await bobPage.page.reload({ waitUntil: "domcontentloaded" });
        await readyReaderBoard(bobPage, boardId);
        await assertCardDecrypts(bobPage, aliceCard, aliceDescription);
        await assertE2eeStorageIsHardened(bobPage.page, [aliceDescription]);
        await stepShot(bobPage.page, testInfo, "C-bob-card-survives-reload");

        // 6) Reverse direction: bob adds his own card; it must project back to
        //    alice (the admission fork historically broke BOTH directions).
        const bobColumn = bobPage.page
          .getByTestId("kanban-column")
          .filter({ hasText: listTitle })
          .first();
        await bobColumn.getByTestId("add-card-button").click();
        await bobColumn.getByTestId("new-card-title-input").fill(bobCard);
        await bobColumn.getByTestId("save-card-button").click();
        await expect(
          bobColumn.getByTestId("kanban-card").filter({ hasText: bobCard }),
        ).toBeVisible({
          timeout: 45_000,
        });
        await expect(
          bobColumn.getByTestId("kanban-card").filter({ hasText: bobCard }),
        ).toHaveAttribute("data-card-draft", "false", { timeout: 120_000 });
        await addEncryptedDescription(bobPage.page, bobCard, bobDescription);

        await openReaderBoard(alicePage, realmId, boardId);
        await expect(
          alicePage.page.getByTestId("kanban-card").filter({ hasText: bobCard }),
          "bob's card must project back to alice (reverse cross-member sync)",
        ).toBeVisible({ timeout: 90_000 });
        await expect(
          alicePage.page
            .getByTestId("kanban-card-redacted")
            .filter({ hasText: bobCard }),
        ).toHaveCount(0);
        await assertCardDecrypts(alicePage, bobCard, bobDescription);
        await assertE2eeStorageIsHardened(alicePage.page, [bobDescription]);
        await stepShot(alicePage.page, testInfo, "D-alice-sees-bob-card");

        // 7) Raw wire stays ciphertext for the private body: the encrypted realm
        //    must never expose alice's description verbatim in the event log.
        const rawEventsUrl = `${solandBaseUrl()}/_arkret/self/events`;
        const rawEvents = await request.fetch(rawEventsUrl, {
          method: "QUERY",
          data: canonicalJson({ realm_ids: [realmId], limit: 200 }),
          headers: {
            "content-type": "application/json",
            ...selfPathGrantHeaders({
              deviceKey: aliceSession.deviceKey,
              grantJwt: aliceSession.grantJwt,
              method: "QUERY",
              url: rawEventsUrl,
            }),
          },
        });
        expect(rawEvents.status()).toBe(200);
        const rawEventBody = JSON.stringify(await rawEvents.json());
        expect(rawEventBody).not.toContain(aliceDescription);
        expect(rawEventBody).not.toContain(bobDescription);
        outboundFault?.assertExactReplay();
      } finally {
        await outboundFault?.dispose();
        await Promise.allSettled([
          bobPage?.close() ?? Promise.resolve(),
          alicePage.close(),
        ]);
      }
    });
  }

  test("bob joins a shared-history MLS realm after alice's encrypted card and decrypts the pre-join card content", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);

    const stamp = Date.now();
    const [aliceSession, bobSession] = await Promise.all([
      createDpopUserSession(request, "xmhist-alice"),
      createDpopUserSession(request, "xmhist-bob"),
    ]);
    if (!aliceSession || !bobSession) {
      assertJointStackNotRequired(
        "shared-history encrypted kanban requires coauth DPoP session-grant login",
      );
      test.skip(
        true,
        "coauth DPoP session-grant login is required for MLS history sharing",
      );
      return;
    }

    const alice = aliceSession.user;
    const bob = bobSession.user;
    const aliceFlow = await openDpopUserPageFromSession(browser, aliceSession);
    expect(aliceFlow).toBeTruthy();
    const alicePage = aliceFlow!.page;
    let bobPage: JointUserPage | undefined;

    const boardTitle = `Shared History Board ${stamp}`;
    const listTitle = `Before-join-${stamp}`;
    const aliceCard = `Pre-join encrypted card ${stamp}`;
    const aliceDescription = `Pre-join private detail ${stamp}`;

    try {
      await alicePage.gotoHome();
      await alicePage.completeRecoveryKeySetupIfPrompted();
      await alicePage.acknowledgeRecommendedEncryptionPromptIfVisible();

      // 1) Alice creates a shared-history MLS realm. For this visibility the
      // card events are visible to a later joined member, but the private body
      // still requires the private history-key request/response mailbox flow
      // path before Bob may render plaintext.
      const realmId = await alicePage.createRealm({
        title: `Shared-history MLS Kanban ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "all_history_for_current_members",
        mlsActivated: true,
      });
      await grantInviteConsentArkret(
        request,
        bobSession.grantJwt,
        bob,
        alice.id,
      );

      // 2) Alice writes the board/list/card and encrypted private description
      // BEFORE Bob joins. This is the regression path: Bob's projection can see
      // activity/history, but the description used to stay locked without the
      // shared-history key exchange.
      const boardId = await buildEncryptedBoardListCard(
        alicePage.page,
        realmId,
        boardTitle,
        listTitle,
        aliceCard,
      );
      await addEncryptedDescription(
        alicePage.page,
        aliceCard,
        aliceDescription,
      );
      await stepShot(
        alicePage.page,
        testInfo,
        "A-alice-prejoin-encrypted-card",
      );

      // 3) Alice invites Bob only after the encrypted content already exists,
      // while Bob still has no browser-published KeyPackage.
      // Present holder-issued introduction evidence: a raw address remains
      // low-trust even when a separate consent grant exists in Bob's PCR.
      const bobLocatorToken = await issueInviteLocatorToken(request, bobSession.grantJwt);
      const inviteStatus = await alicePage.inviteFromAdmin(
        realmId,
        bob.id,
        undefined,
        { token: bobLocatorToken },
      );
      expect(inviteStatus).toContain("invited");
      expect(inviteStatus).not.toContain("MLS Welcome queued");

      const bobFlow = await openDpopUserPageFromSession(browser, bobSession);
      expect(bobFlow).toBeTruthy();
      bobPage = bobFlow!.page;
      await bobPage.gotoHome();
      await bobPage.completeRecoveryKeySetupIfPrompted();
      await bobPage.acknowledgeRecommendedEncryptionPromptIfVisible();
      await bobPage.acceptInvite(realmId);
      await bobPage.gotoTimelineRealm(realmId);
      await waitForMlsCommit(request, aliceSession, realmId, bob.id);
      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await bobPage.completeRecoveryKeySetupIfPrompted();

      // Server-side visibility gate: Bob's event feed must include the pre-join
      // board Space. If this fails, the bug is not the MLS key-share path.
      await expect
        .poll(
          async () => {
            const url = `${solandBaseUrl()}/_arkret/self/streams/scan`;
            const resp = await request.fetch(url, {
              method: "POST",
              data: canonicalJson({
                realm_id: realmId,
                stream_ref: { kind: "realm", realm_id: realmId },
                after_position: null,
                limit: 500,
              }),
              headers: {
                "content-type": "application/json",
                ...selfPathGrantHeaders({
                  deviceKey: bobSession.deviceKey,
                  grantJwt: bobSession.grantJwt,
                  method: "POST",
                  url,
                }),
              },
            });
            if (resp.status() !== 200) return `status ${resp.status()}`;
            return JSON.stringify(await resp.json());
          },
          {
            timeout: 60_000,
            intervals: [1_000, 2_000, 5_000],
            message: `shared-history realm did not expose alice's pre-join board Space (${boardId}) to Bob`,
          },
        )
        .toContain(boardId);

      // End-to-end history sharing proof: Bob must request/install the missing
      // epoch history_secret and decrypt Alice's private card description.
      await openReaderBoard(bobPage, realmId, boardId);
      await assertCardDecrypts(bobPage, aliceCard, aliceDescription);
      await stepShot(bobPage.page, testInfo, "B-bob-decrypted-prejoin-card");

      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await readyReaderBoard(bobPage, boardId);
      await assertCardDecrypts(bobPage, aliceCard, aliceDescription);
      await stepShot(
        bobPage.page,
        testInfo,
        "C-bob-prejoin-card-survives-reload",
      );

      const rawEventsUrl = `${solandBaseUrl()}/_arkret/self/streams/scan`;
      const rawEvents = await request.fetch(rawEventsUrl, {
        method: "POST",
        data: canonicalJson({
          realm_id: realmId,
          stream_ref: { kind: "realm", realm_id: realmId },
          after_position: null,
          limit: 200,
        }),
        headers: {
          "content-type": "application/json",
          ...selfPathGrantHeaders({
            deviceKey: aliceSession.deviceKey,
            grantJwt: aliceSession.grantJwt,
            method: "POST",
            url: rawEventsUrl,
          }),
        },
      });
      expect(rawEvents.status()).toBe(200);
      expect(JSON.stringify(await rawEvents.json())).not.toContain(
        aliceDescription,
      );
    } finally {
      await Promise.allSettled([
        bobPage?.close() ?? Promise.resolve(),
        alicePage.close(),
      ]);
    }
  });
});

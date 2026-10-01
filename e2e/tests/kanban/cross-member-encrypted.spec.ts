// Cross-member encrypted kanban
// Contract: e2e/scenarios/kanban/cross-member-encrypted.md
// Spec refs:
//   - crypto-media/encryption-and-audit.md §2.2-§2.4 (Welcome/Commit, envelope, sync)
//   - models/realm-and-space.md §2.2 accepted MLS Genesis and since-join history
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
// pre-join history, accepted MLS epoch drift. This test is the missing main chain.
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
import { assertAuthoritySubmitOutcome, canonicalJson, grantCapabilityEventApi } from "../../helpers/soland-api";
import { grantInviteConsentArkret } from "../../helpers/contact-api";
import { stepShot } from "../../helpers/screenshots";
import { selfPathGrantHeaders } from "../../helpers/session-grant-dpop";
import { installMlsOutboundFault } from "../../helpers/mls-outbound-fault";
import { selectDxcOption } from "../../helpers/dxc-select";
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

// Read only the holder's outbound vault, using its non-extractable wrapping
// key. This is a local persistence assertion, never authority evidence.
async function readCreatorRecords(page: Page): Promise<Record<string, any>[]> {
  return page.evaluate(async () => {
    const result = <T>(request: IDBRequest<T>): Promise<T> => new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const db = await result(indexedDB.open("inkson.secret.inkson", 1));
    try {
      const tx = db.transaction(["entries", "wrapping_keys"], "readonly");
      const entries = tx.objectStore("entries");
      const [key, names, encrypted] = await Promise.all([
        result(tx.objectStore("wrapping_keys").get("primary")) as Promise<CryptoKey>,
        result(entries.getAllKeys()),
        result(entries.getAll()),
      ]);
      if (!key || key.extractable) throw new Error("creator vault has no non-extractable wrapping key");
      const records: Record<string, any>[] = [];
      for (let index = 0; index < names.length; index += 1) {
        const name = String(names[index]);
        if (!name.startsWith("inkson.outbound.v1::") || !name.endsWith(".standard")) continue;
        const entry = encrypted[index] as { iv: Uint8Array; ct: Uint8Array };
        const plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: Uint8Array.from(entry.iv).buffer }, key, Uint8Array.from(entry.ct).buffer,
        );
        const state = JSON.parse(new TextDecoder().decode(plaintext));
        records.push(...(state.creator_bootstrap_records ?? []));
      }
      return records;
    } finally {
      db.close();
    }
  });
}

async function readCreatorIntents(page: Page): Promise<Record<string, any>[]> {
  return (await readCreatorRecords(page)).map((record) => record.intent);
}

// The Welcome is a recipient delivery, not a shared Event. Wait for the
// accepted member-add Commit before the recipient reload/decrypt assertions.
async function waitForMlsCommit(
  request: APIRequestContext,
  session: DpopUserSession,
  realmId: string,
  recipientId: string,
  minimumEpoch = 1,
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
            item.event?.kind === "ak.mls.commit" && Number(item.event.payload?.next_epoch) >= minimumEpoch,
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
  await expect
    .poll(() => decodeURIComponent(new URL(page.url()).pathname), { timeout: 15_000 })
    .toContain("/task/ak:strand:");
  const taskId = decodeURIComponent(
    new URL(page.url()).pathname.split("/task/")[1]?.split("/")[0] ?? "",
  );
  expect(taskId, `card detail route for ${cardTitle}`).toMatch(/^ak:strand:/);
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
  const submitted = JSON.parse(acceptedResponse.request().postData() ?? "{}") as {
    event?: Record<string, unknown>;
  };
  expect(submitted.event?.kind).toBe("ak.strand.update");
  if (!submitted.event) {
    throw new Error("description edit did not submit an Event envelope");
  }
  expect((submitted.event.payload as Record<string, unknown>)?.target_ref).toBe(taskId);
  const outcome = JSON.parse(body) as Record<string, unknown>;
  expect(outcome.status, "a new description edit must commit").toBe("committed");
  assertAuthoritySubmitOutcome(
    outcome,
    submitted.event,
    `encrypted description edit for ${cardTitle}`,
  );
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

async function openPendingTimeline(reader: JointUserPage, realmId: string): Promise<void> {
  await reader.page.goto(`/chat/${encodeURIComponent(realmId)}`, { waitUntil: "domcontentloaded" });
  await expect(reader.page.getByTestId("chat-panel")).toBeVisible({ timeout: 120_000 });
  await expect(reader.page.getByTestId("message-list")).toBeVisible({ timeout: 120_000 });
  await expect(reader.page.getByTestId("chat-panel")).toHaveAttribute("data-initial-sync", "pending");
}

test.describe("cross-member encrypted kanban @fully-implemented", () => {
  for (const loseCreateResponse of [false, true]) {
  test("creator E2EE plaintext cache is encrypted in IndexedDB and survives reload" +
    (loseCreateResponse ? "; recovers accepted-create response loss before epoch zero" : ""), async ({
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
    const submittedCreateIds = new Set<string>();
    const submittedGenesisIds = new Set<string>();
    let frozenCreateBytes: string | undefined;
    let cutRealmId: string | undefined;
    let intentAtCut: Record<string, any> | undefined;
    let cutActive = loseCreateResponse;
    await creator.page.route(/\/_arkret\/self\/events(?:\?.*)?$/, async (route) => {
      const payload = route.request().postDataJSON() as Record<string, any>;
      const create = payload.events?.[0]?.event;
      if (payload.event?.kind === "ak.mls.genesis"
        && submittedCreateIds.has(payload.event.realm_id.replace("ak:realm:", "ak:event:"))) {
        const record = (await readCreatorRecords(creator.page)).find(
          (value) => value.intent.effective_scope.realm_id === payload.event.realm_id,
        );
        expect(record, "Genesis submission must retain its formal durable creator record").toBeDefined();
        expect(record!.state).toBe("realm_accepted");
        expect(record!.accepted_create.accepted_event).toEqual(record!.intent.signed_scope_create_unit.events[0].event);
        expect(record!.accepted_create.covering_commit.event_ref).toBe(record!.intent.scope_create_event_id);
        expect(record!.genesis_absence.realm_id).toBe(payload.event.realm_id);
        expect(record!.genesis_absence.visible_stream_heads.some(
          (head: Record<string, any>) => head.stream_ref.kind === "realm" && head.stream_ref.realm_id === payload.event.realm_id,
        )).toBe(true);
        expect(record!.genesis_absence.current_state_entries.some(
          (entry: Record<string, any>) => entry.selector?.kind === "mls_group" && entry.selector.scope_ref.realm_id === payload.event.realm_id,
        )).toBe(false);
      }
      if (payload.event?.kind === "ak.mls.genesis" && payload.event.realm_id === cutRealmId) {
        submittedGenesisIds.add(payload.event.event_id);
      }
      if (create?.kind === "ak.realm.create") {
        const intents = await readCreatorIntents(creator.page);
        const intent = intents.find((value) => value.scope_create_event_id === create.event_id);
        expect(intent, "the closed MLS intent must be durable before the first create request").toBeDefined();
        expect(intent!.owner_actor_id).toEqual(create.actor_id);
        expect(intent!.effective_scope).toEqual({ kind: "realm", realm_id: create.event_id.replace("ak:event:", "ak:realm:") });
        expect(intent!.creator_signer_method).toBe(create.producer_proof.verification_method);
        expect(intent!.signed_scope_create_unit).toEqual(payload);
        submittedCreateIds.add(create.event_id);
        frozenCreateBytes ??= route.request().postData()!;
        expect(route.request().postData(), "create recovery must retain the original signed request bytes").toBe(frozenCreateBytes);
        if (cutActive) {
          if (!cutRealmId) {
            const response = await route.fetch();
            expect(response.ok(), "the real authority must accept the create before response loss").toBe(true);
            const outcome = await response.json();
            expect(outcome.unit_kind).toBe("ordinary_realm_bootstrap");
            expect(outcome.status).toMatch(/^(committed|duplicate)$/);
            expect(outcome.commits).toHaveLength(payload.events.length);
            payload.events.forEach((submission: Record<string, any>, index: number) => {
              assertAuthoritySubmitOutcome({ status: outcome.status, commit: outcome.commits[index] },
                submission.event, "accepted create response loss");
            });
            intentAtCut = intent;
            cutRealmId = intent!.effective_scope.realm_id;
          }
          await route.abort("connectionfailed");
          return;
        }
      }
      await route.continue();
    });

    try {
      await creator.gotoHome();
      await creator.completeRecoveryKeySetupIfPrompted();
      await creator.acknowledgeRecommendedEncryptionPromptIfVisible();

      const createOptions = {
        title: `Secure cache realm ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join" as const,
        mlsActivated: true,
      };
      let realmId: string;
      if (loseCreateResponse) {
        // Submit through the real wizard, then destroy its runtime before an
        // accepted response can release foreground epoch-zero authoring.
        await creator.gotoSetup();
        const wizard = creator.page.getByTestId("realm-lifecycle-strand").last();
        const title = wizard.getByTestId("realm-title-input");
        if (!(await title.isVisible().catch(() => false))) {
          await wizard.getByRole("button", { name: /^Basics/ }).first().click();
        }
        await title.fill(createOptions.title);
        await wizard.getByTestId("new-realm-next-button").first().click();
        await selectDxcOption(wizard.getByTestId("realm-discoverability-input"), createOptions.discoverability);
        await selectDxcOption(wizard.getByTestId("realm-policy-join-rule-input"), createOptions.joinRule);
        await selectDxcOption(wizard.getByTestId("realm-policy-history-access-input"), createOptions.historyAccess);
        await selectDxcOption(wizard.getByTestId("realm-mls-activation-input"), "after_create");
        await wizard.getByTestId("new-realm-next-button").first().click();
        await wizard.getByTestId("create-realm-button").click();
        await expect.poll(() => cutRealmId, { timeout: 120_000 }).toBeTruthy();
        expect(submittedGenesisIds.size, "the crash cut precedes every Genesis submission").toBe(0);
        realmId = cutRealmId!;
        await stepShot(creator.page, testInfo, "A-accepted-create-response-lost");
        await creator.page.goto(`/chat/${encodeURIComponent(realmId)}`, { waitUntil: "domcontentloaded" });
        cutActive = false;
      } else {
        realmId = await creator.createRealm(createOptions);
      }
      expect(submittedCreateIds.size).toBe(1);
      const intentBeforeReload = (await readCreatorIntents(creator.page)).find(
        (intent) => intent.effective_scope.realm_id === realmId,
      );
      expect(intentBeforeReload).toBeDefined();
      if (loseCreateResponse) expect(intentBeforeReload).toEqual(intentAtCut);
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
      if (loseCreateResponse) {
        expect(submittedGenesisIds.size, "background recovery must author one Genesis for the original scope").toBe(1);
        expect(submittedCreateIds.size).toBe(1);
      }

      await assertE2eeStorageIsHardened(creator.page, [privateDescription]);
      await stepShot(creator.page, testInfo, "A-secure-cache-before-reload");

      await creator.page.reload({ waitUntil: "domcontentloaded" });
      await readyReaderBoard(creator, boardId);
      expect((await readCreatorIntents(creator.page)).find(
        (intent) => intent.effective_scope.realm_id === realmId,
      )).toEqual(intentBeforeReload);
      expect(submittedCreateIds.size).toBe(1);
      await assertCardDecrypts(creator, cardTitle, privateDescription);
      await assertE2eeStorageIsHardened(creator.page, [privateDescription]);
      await stepShot(creator.page, testInfo, "B-secure-cache-after-reload");
    } finally {
      await creator.close();
    }
  });
  }

  for (const fault of [undefined, "commit-response-lost", "welcome-before-durable", "welcome-response-lost", "retryable-unavailable", "private-state-blocked", "late-transition-tail"] as const) {
    test("bob joins an MLS-encrypted realm and decrypts alice's encrypted card content; survives reload; bob's own card projects back to alice" + (fault ? `; recovers ${fault}` : ""), async ({
      browser,
      request,
    }, testInfo) => {
      // The full two-browser MLS flow (recovery-key setup, create, board+card,
      // encrypt, invite, Welcome, join, cross-member decrypt, reload, reverse
      // direction) does not fit the 180s default — mirror the sibling MLS browser
      // budget so it does not time out mid-flow.
      test.setTimeout(600_000);

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
      let carolPage: JointUserPage | undefined;
      let outboundFault: Awaited<ReturnType<typeof installMlsOutboundFault>> | undefined;
      const privateClaimQuery = /\/_arkret\/self\/keys\/keypackages\/claims\/query(?:\?.*)?$/;
      let holdPrivateState = fault === "private-state-blocked";
      let privateReadCuts = 0;

      const boardTitle = `Enc XM Board ${stamp}`;
      const listTitle = `Todo-${stamp}`;
      const aliceCard = `Alice secret card ${stamp}`;
      const aliceDescription = `Alice private detail ${stamp}`;
      const bobCard = `Bob reply card ${stamp}`;
      const bobDescription = `Bob private reply ${stamp}`;
      const bobEditOfAliceCard = `Bob edited Alice card ${stamp}`;
      const aliceEditOfBobCard = `Alice edited Bob card ${stamp}`;

      try {
        await alicePage.gotoHome();
        await alicePage.completeRecoveryKeySetupIfPrompted();
        await alicePage.acknowledgeRecommendedEncryptionPromptIfVisible();

        // 1) Alice creates an EMPTY realm, then activates it with accepted MLS Genesis.
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
        if (fault === "commit-response-lost" || fault === "welcome-before-durable" || fault === "welcome-response-lost" || fault === "retryable-unavailable") {
          outboundFault = await installMlsOutboundFault(alicePage.page, realmId, fault);
        }
        if (holdPrivateState) {
          await bobPage.page.route(privateClaimQuery, async (route) => {
            if (holdPrivateState) {
              privateReadCuts += 1;
              await route.abort("failed");
            } else {
              await route.continue();
            }
          });
        }
        await bobPage.acceptInvite(realmId);
        if (outboundFault) {
          await outboundFault.waitForCut();
          if (fault === "retryable-unavailable") await alicePage.page.waitForTimeout(1_500);
          // Destroy the sender's wasm runtime while the real transport remains
          // cut. Recovery must reload the original durable saga and signed IDs.
          await alicePage.page.reload({ waitUntil: "domcontentloaded" });
          await outboundFault.restore();
        }
        if (holdPrivateState) {
          await openPendingTimeline(bobPage, realmId);
        } else {
          await bobPage.gotoTimelineRealm(realmId);
        }
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
        if (holdPrivateState) {
          await expect.poll(() => privateReadCuts, { timeout: 90_000 }).toBeGreaterThan(0);
          const committedList = bobPage.page.getByTestId("kanban-column").filter({ hasText: listTitle }).first();
          await expect(committedList).toBeVisible({ timeout: 90_000 });
          await expect(committedList).toHaveAttribute("data-column-draft", "false");
          await expect(committedList.getByTestId("add-card-button")).toBeDisabled();
          await openPendingTimeline(bobPage, realmId);
          await expect(bobPage.page.getByTestId("chat-panel")).toHaveAttribute("data-initial-sync", "pending");
          holdPrivateState = false;
          await bobPage.page.unroute(privateClaimQuery);
          await expect(bobPage.page.getByTestId("chat-panel")).toHaveAttribute("data-initial-sync", "complete", { timeout: 120_000 });
          await openReaderBoard(bobPage, realmId, boardId);
        }
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

        if (fault === "late-transition-tail") {
          const carolSession = await createDpopUserSession(request, "xmenc-carol");
          expect(carolSession).toBeTruthy();
          const carol = carolSession!.user;
          await grantInviteConsentArkret(request, carolSession!.grantJwt, carol, alice.id);
          const locator = await issueInviteLocatorToken(request, carolSession!.grantJwt);
          expect(await alicePage.inviteFromAdmin(realmId, carol.id, carol.id, { token: locator })).toContain("invited");
          const flow = await openDpopUserPageFromSession(browser, carolSession!);
          expect(flow).toBeTruthy();
          carolPage = flow!.page;
          await carolPage.gotoHome();
          await carolPage.completeRecoveryKeySetupIfPrompted();
          await carolPage.acknowledgeRecommendedEncryptionPromptIfVisible();
          await carolPage.acceptInvite(realmId);
          await waitForMlsCommit(request, aliceSession, realmId, carol.id, 2);
          await carolPage.gotoTimelineRealm(realmId);
          // Bob was not a new recipient of this Welcome. His durable epoch-one
          // group must apply the accepted tail, rather than borrow Carol's secret.
          await bobPage.page.reload({ waitUntil: "domcontentloaded" });
          await readyReaderBoard(bobPage, boardId);
          await assertCardDecrypts(bobPage, aliceCard, aliceDescription);
          await stepShot(bobPage.page, testInfo, "C2-bob-after-next-accepted-commit");
        }

        // Joining grants visibility, not collaboration authority. The owner
        // explicitly permits card creation/placement and Description editing;
        // the field constraint does not grant Synthesis or metadata editing.
        await grantCapabilityEventApi(request, aliceSession.grantJwt, {
          ownerId: alice.id,
          realmId,
          subjectId: bob.id,
          actions: ["ak.strand.create", "ak.strand.move"],
        });
        await grantCapabilityEventApi(request, aliceSession.grantJwt, {
          ownerId: alice.id,
          realmId,
          subjectId: bob.id,
          actions: ["ak.strand.update"],
          constraints: [{
            constraint_kind: "field_access",
            effect: "allow",
            evaluation_class: "stateless",
            allowed_write_fields: ["content", "encrypted_content"],
          }],
        });

        if (!fault || fault === "late-transition-tail") {
          // Both members must be able to edit the same accepted encrypted
          // Strand, rather than merely decrypt each other's own cards.
          await addEncryptedDescription(bobPage.page, aliceCard, bobEditOfAliceCard);
          await openReaderBoard(alicePage, realmId, boardId);
          await assertCardDecrypts(alicePage, aliceCard, bobEditOfAliceCard);
          await alicePage.page.reload({ waitUntil: "domcontentloaded" });
          await readyReaderBoard(alicePage, boardId);
          await assertCardDecrypts(alicePage, aliceCard, bobEditOfAliceCard);
        }

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

        if (!fault) {
          await alicePage.page.reload({ waitUntil: "domcontentloaded" });
          await readyReaderBoard(alicePage, boardId);
          await assertCardDecrypts(alicePage, bobCard, bobDescription);
          await addEncryptedDescription(alicePage.page, bobCard, aliceEditOfBobCard);
          await bobPage.page.reload({ waitUntil: "domcontentloaded" });
          await readyReaderBoard(bobPage, boardId);
          await assertCardDecrypts(bobPage, bobCard, aliceEditOfBobCard);
        }

        // 7) Raw wire stays ciphertext for the private body: the encrypted realm
        //    must never expose alice's description verbatim in the event log.
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
        const rawEventBody = JSON.stringify(await rawEvents.json());
        expect(rawEventBody).not.toContain(aliceDescription);
        expect(rawEventBody).not.toContain(bobDescription);
        expect(rawEventBody).not.toContain(bobEditOfAliceCard);
        expect(rawEventBody).not.toContain(aliceEditOfBobCard);
        outboundFault?.assertExactReplay();
      } finally {
        holdPrivateState = false;
        await bobPage?.page.unroute(privateClaimQuery);
        await outboundFault?.dispose();
        await Promise.allSettled([
          bobPage?.close() ?? Promise.resolve(),
          carolPage?.close() ?? Promise.resolve(),
          alicePage.close(),
        ]);
      }
    });
  }

});

import { readCreatorRecords } from "../../helpers/creator-bootstrap";
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
//   1. Card title and DESCRIPTION use distinct encrypted metadata/body carriers.
//      Seeing the title does not prove private body decryption: bob must read
//      the private DESCRIPTION body, and
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
import { assertAuthoritySubmitOutcome, canonicalJson, grantCapabilityEventApi, queryRealmEventsApi } from "../../helpers/soland-api";
import { grantInviteConsentArkret } from "../../helpers/contact-api";
import { stepShot } from "../../helpers/screenshots";
import { selfPathGrantHeaders } from "../../helpers/session-grant-dpop";
import { activateRealmMlsApi, readScopeMlsGroupCurrentApi } from "../../helpers/soland-api/mls";
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
// Damage authenticated local recovery data, never wire authority evidence.
// Encryption uses the actual non-extractable holder key and replacement uses
// a readwrite transaction comparing the committed ciphertext.
async function damageCreatorVault(page: Page, realmId: string, cut: string): Promise<Record<string, any>> {
  return page.evaluate(async ({ realmId, cut }) => {
    const result = <T>(request: IDBRequest<T>): Promise<T> => new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const db = await result(indexedDB.open("inkson.secret.inkson", 1));
    try {
      const tx = db.transaction(["entries", "wrapping_keys"], "readonly");
      const [key, names, encrypted] = await Promise.all([
        result(tx.objectStore("wrapping_keys").get("primary")) as Promise<CryptoKey>,
        result(tx.objectStore("entries").getAllKeys()), result(tx.objectStore("entries").getAll()),
      ]);
      for (let index = 0; index < names.length; index += 1) {
        const name = String(names[index]);
        if (!name.startsWith("inkson.outbound.v1::") || !name.endsWith(".standard")) continue;
        const entry = encrypted[index] as { iv: Uint8Array; ct: Uint8Array };
        const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Uint8Array.from(entry.iv).buffer }, key, Uint8Array.from(entry.ct).buffer);
        const state = JSON.parse(new TextDecoder().decode(plain));
        const record = state.creator_bootstrap_records?.find((record: Record<string, any>) => record.intent.effective_scope.realm_id === realmId);
        if (!record) continue;
        if (record.state !== "ready") throw new Error("local inconsistency cut requires the real ready state");
        if (cut === "quarantine_record") record.epoch_zero.encrypted_private_state = { retained_damage: [1, 2, 3] };
        else if (cut === "quarantine_private" || cut === "quarantine_write_failure") {
          const envelope = JSON.parse(new TextDecoder().decode(Uint8Array.from(record.epoch_zero.encrypted_private_state)));
          const ciphertext = String(envelope.ciphertext_hex);
          if (!/^[0-9a-f]{34,}$/.test(ciphertext)) throw new Error("the fixture needs the original valid private AEAD envelope");
          envelope.ciphertext_hex = (ciphertext[0] === "0" ? "1" : "0") + ciphertext.slice(1);
          record.epoch_zero.encrypted_private_state = Array.from(new TextEncoder().encode(JSON.stringify(envelope)));
          if (!record.artifacts.private_state_binding.startsWith("sha256:")) throw new Error("the fixture requires its declared SHA-256 material suite");
          const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(record.epoch_zero.encrypted_private_state)));
          // Keep the saved byte binding coherent so only the actual original
          // private restore can detect this cut, not the SDK shape validator.
          record.artifacts.private_state_binding = `sha256:${Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("")}`;
        }
        else if (cut === "quarantine_queue") {
          const queue = state.items.find((item: Record<string, any>) => item.submission.event_id === record.queued_genesis.outbound_queue_item_id);
          queue.submission.request.event.created_at = "2026-01-01T00:00:00.000Z";
        } else if (cut === "quarantine_index") state.creator_ready_index = state.creator_ready_index.filter((receipt: Record<string, any>) => receipt.effective_scope.realm_id !== realmId);
        else throw new Error(`unknown creator inconsistency cut ${cut}`);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(state))));
        await new Promise<void>((resolve, reject) => {
          const write = db.transaction("entries", "readwrite");
          const entries = write.objectStore("entries");
          const current = entries.get(name);
          current.onsuccess = () => {
            const old = current.result as { iv: Uint8Array; ct: Uint8Array };
            if (!old || old.ct.length !== entry.ct.length || old.iv.length !== entry.iv.length
              || old.ct.some((byte, index) => byte !== entry.ct[index]) || old.iv.some((byte, index) => byte !== entry.iv[index])) { write.abort(); return; }
            entries.put({ iv, ct }, name);
          };
          write.oncomplete = () => resolve();
          write.onabort = () => reject(write.error ?? new Error("creator vault changed during the local fault cut"));
          write.onerror = () => reject(write.error);
        });
        return record;
      }
      throw new Error("creator ready vault not found");
    } finally { db.close(); }
  }, { realmId, cut });
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
  createCard = true,
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
  if (!createCard) return boardId;
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
  for (const cut of ["none", "create_response_loss", "device_evidence_unavailable", "public_blob_response_loss", "genesis_response_loss", "artifact_install_failure", "ready_publish_failure", "genesis_superseded", "genesis_rejected", "genesis_rejected_winner", "genesis_rejected_accepted", "quarantine_record", "quarantine_private", "quarantine_queue", "quarantine_index", "quarantine_write_failure"] as const) {
  const quarantineCut = cut.startsWith("quarantine_");
  const loseCreateResponse = cut === "create_response_loss";
  const loseDeviceEvidence = cut === "device_evidence_unavailable";
  const loseBlobResponse = cut === "public_blob_response_loss";
  const loseGenesisResponse = cut === "genesis_response_loss";
  const failArtifactInstall = cut === "artifact_install_failure";
  const failReadyPublish = cut === "ready_publish_failure";
  const failLocalPublication = failArtifactInstall || failReadyPublish;
  const winnerAfterRejection = cut === "genesis_rejected_winner";
  const competingGenesisWins = cut === "genesis_superseded" || winnerAfterRejection;
  const rejectedOriginalAccepted = cut === "genesis_rejected_accepted";
  const rejectGenesis = cut === "genesis_rejected" || rejectedOriginalAccepted;
  test("creator E2EE plaintext cache is encrypted in IndexedDB and survives reload" +
    (loseCreateResponse ? "; recovers accepted-create response loss before epoch zero" : "") +
    (loseDeviceEvidence ? "; Device evidence unavailable keeps acceptance before randomness" : "") +
    (loseBlobResponse ? "; restores epoch-zero unit after public blob response loss" : "") +
    (loseGenesisResponse ? "; reconciles exact accepted Genesis after response loss and unavailable query" : "") +
    (failArtifactInstall ? "; retries the whole accepted artifact install after durable write failure" : "") +
    (failReadyPublish ? "; publishes ready and its send-gate index atomically after durable write failure" : "") +
    (competingGenesisWins ? "; stops the losing queue after a distinct accepted Genesis wins" : "") +
    (rejectGenesis ? "; retains a terminal rejection and explicitly opens a new verified attempt" : "") +
    (winnerAfterRejection ? "; preserves a real Station rejection before resolving its winner" : "") +
    (rejectedOriginalAccepted ? "; quarantines a rejected original independently proved accepted" : "") +
    (quarantineCut ? `; quarantines ${cut.replace("quarantine_", "")} inconsistency without erasing recovery material` : ""), async ({
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
    let deviceCutActive = loseDeviceEvidence;
    let deviceCutSeen = false;
    let blobCutActive = loseBlobResponse;
    let epochUnitAtCut: Record<string, any> | undefined;
    let genesisCutActive = loseGenesisResponse;
    let acceptedGenesisAtCut: Record<string, any> | undefined;
    let signedGenesisAtCut: Record<string, any> | undefined;
    let competingWinnerId: string | undefined;
    let rejectionActive = rejectGenesis;
    let closedRejection: Record<string, any> | undefined;
    await creator.page.route(/\/_arkret\/self\/streams\/scan(?:\?.*)?$/, async (route) => {
      if (genesisCutActive && acceptedGenesisAtCut) {
        await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({
          error: { code: "temporarily_unavailable", message: "creator exact query cut" },
        }) });
        return;
      }
      await route.continue();
    });
    await creator.page.route(/\/_arkret\/self\/keys\/query(?:\?.*)?$/, async (route) => {
      if (deviceCutActive && deviceCutSeen) {
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
          device_keys: [], device_generations: [], failures: [],
        }) });
        return;
      }
      if (deviceCutActive) {
        const record = (await readCreatorRecords(creator.page)).find((value) =>
          value.state === "realm_accepted" && submittedCreateIds.has(value.intent.scope_create_event_id));
        if (record) {
          deviceCutSeen = true;
          cutRealmId = record.intent.effective_scope.realm_id;
          intentAtCut = record.intent;
          await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
            device_keys: [], device_generations: [], failures: [],
          }) });
          return;
        }
      }
      await route.continue();
    });
    await creator.page.route(/\/_arkret\/self\/blob\/upload(?:\?.*)?$/, async (route) => {
      if (blobCutActive && epochUnitAtCut) {
        await route.abort("connectionfailed");
        return;
      }
      const record = (await readCreatorRecords(creator.page)).find((value) =>
        value.epoch_zero && submittedCreateIds.has(value.intent.scope_create_event_id));
      const body = route.request().postDataBuffer();
      if (!record || !body || (!body.includes(Buffer.from(record.epoch_zero.group_info_bytes)) && !body.includes(Buffer.from(record.epoch_zero.ratchet_tree_bytes)))) {
        await route.continue();
        return;
      }
      expect(record.state, "the complete recovery unit must precede public blob observability").toMatch(/^(epoch0_state_persisted|genesis_queued|genesis_accepted|artifacts_converged|ready)$/);
      expect(record.epoch_zero.encrypted_private_state.length).toBeGreaterThan(0);
      if (blobCutActive) {
        if (!epochUnitAtCut) {
          const response = await route.fetch();
          expect(response.ok(), "the real blob store must persist material before response loss").toBe(true);
          const outcome = await response.json();
          expect([record.epoch_zero.unsigned_genesis.event.payload.group_info_ref,
            record.epoch_zero.unsigned_genesis.event.payload.ratchet_tree_ref]).toContain(outcome.blob_ref);
          epochUnitAtCut = record.epoch_zero;
          intentAtCut = record.intent;
          cutRealmId = record.intent.effective_scope.realm_id;
        }
        await route.abort("connectionfailed");
        return;
      }
      if (epochUnitAtCut) expect(record.epoch_zero).toEqual(epochUnitAtCut);
      await route.continue();
    });
    await creator.page.route(/\/_arkret\/self\/events(?:\?.*)?$/, async (route) => {
      const payload = route.request().postDataJSON() as Record<string, any>;
      const create = payload.events?.[0]?.event;
      if (payload.event?.kind === "ak.mls.genesis"
        && submittedCreateIds.has(payload.event.realm_id.replace("ak:realm:", "ak:event:"))) {
        const record = (await readCreatorRecords(creator.page)).find(
          (value) => value.intent.effective_scope.realm_id === payload.event.realm_id,
        );
        expect(record, "Genesis submission must retain its formal durable creator record").toBeDefined();
        submittedGenesisIds.add(payload.event.event_id);
        expect(record!.state).toBe("genesis_queued");
        const unsigned = { ...payload.event };
        delete unsigned.producer_proof;
        expect(record!.epoch_zero.unsigned_genesis.event).toEqual(unsigned);
        expect(record!.epoch_zero.unsigned_genesis.event.created_at).toBe(payload.event.payload.created_at);
        expect(record!.queued_genesis.signed_genesis.event).toEqual(payload.event);
        expect(record!.queued_genesis.canonical_signed_bytes).toEqual(Array.from(new TextEncoder().encode(canonicalJson(payload.event))));
        expect(record!.queued_genesis.outbound_queue_item_id).toBe(payload.event.event_id);
        expect(record!.queue_items.find((item: Record<string, any>) => item.submission.event_id === payload.event.event_id).submission.request).toEqual(payload);
        if (epochUnitAtCut) expect(record!.epoch_zero).toEqual(epochUnitAtCut);
        const pin = record!.governance_evidence;
        expect(pin.accepted_create.accepted_event).toEqual(record!.accepted_create.accepted_event);
        expect(pin.governance_binding).toEqual(record!.intent.proposed_group_genesis_binding.proposed_group_genesis_binding);
        expect(pin.canonical_proposal_bytes).toEqual(Array.from(new TextEncoder().encode(canonicalJson(record!.intent.proposed_group_genesis_binding))));
        expect(pin.creator_device_authority.account_id).toEqual(record!.intent.owner_actor_id.account_id);
        expect(pin.creator_device_authority.device_id).toBe(record!.intent.creator_device_id);
        expect(pin.creator_device_authority.projection.authorized_generation_ref).toBe(pin.creator_device_authority.generation.current_device_generation_ref);
        expect(pin.genesis_absence.current_state_entries.some(
          (entry: Record<string, any>) => entry.selector?.kind === "mls_group" && entry.selector.scope_ref.realm_id === payload.event.realm_id,
        )).toBe(false);
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
      if (rejectionActive && payload.event?.kind === "ak.mls.genesis"
        && submittedCreateIds.has(payload.event.realm_id.replace("ak:realm:", "ak:event:"))) {
        const record = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === payload.event.realm_id)!;
        cutRealmId = payload.event.realm_id;
        intentAtCut = record.intent;
        epochUnitAtCut = record.epoch_zero;
        signedGenesisAtCut = record.queued_genesis;
        // Fixture-only ordinary Event admission refusal. Production owns the
        // durable cut and obtains fresh authenticated absence on explicit retry.
        await route.fulfill({ status: 403, contentType: "application/problem+json", body: JSON.stringify({
          type: "https://arkret.org/problems/capability_denied", title: "Capability denied",
          status: 403, detail: "creator terminal rejection fixture",
        }) });
        return;
      }
      if (competingGenesisWins && payload.event?.kind === "ak.mls.genesis"
        && submittedCreateIds.has(payload.event.realm_id.replace("ak:realm:", "ak:event:"))) {
        const record = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === payload.event.realm_id)!;
        cutRealmId = payload.event.realm_id;
        intentAtCut = record.intent;
        epochUnitAtCut = record.epoch_zero;
        signedGenesisAtCut = record.queued_genesis;
        if (!competingWinnerId) {
          // A separate fixture client wins the real Station CAS. It never
          // installs its private material into the losing browser vault.
          competingWinnerId = await activateRealmMlsApi(request, {
            id: creatorSession.user.id, deviceId: creatorSession.user.deviceId,
            token: creatorSession.grantJwt,
          }, cutRealmId!, { stationId: creatorSession.accountId.station_id });
          expect(competingWinnerId).not.toBe(payload.event.event_id);
        }
        if (winnerAfterRejection) { await route.continue(); }
        else { await route.abort("connectionfailed"); }
        return;
      }
      if (genesisCutActive && payload.event?.kind === "ak.mls.genesis"
        && submittedCreateIds.has(payload.event.realm_id.replace("ak:realm:", "ak:event:"))) {
        submittedGenesisIds.add(payload.event.event_id);
        if (!acceptedGenesisAtCut) {
          const record = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === payload.event.realm_id)!;
          const response = await route.fetch();
          expect(response.ok()).toBe(true);
          acceptedGenesisAtCut = await response.json();
          assertAuthoritySubmitOutcome(acceptedGenesisAtCut!, payload.event, "accepted Genesis response loss");
          cutRealmId = payload.event.realm_id;
          intentAtCut = record.intent;
          epochUnitAtCut = record.epoch_zero;
          signedGenesisAtCut = record.queued_genesis;
        }
        await route.abort("connectionfailed");
        return;
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
      if (failLocalPublication) {
        await creator.page.evaluate((targetState) => {
          const original = SubtleCrypto.prototype.encrypt;
          SubtleCrypto.prototype.encrypt = async function(algorithm, key, data) {
            const bytes = ArrayBuffer.isView(data)
              ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
              : new Uint8Array(data);
            let state: Record<string, any> | undefined;
            try { state = JSON.parse(new TextDecoder().decode(bytes)); } catch { /* unrelated encryption */ }
            const record = state?.creator_bootstrap_records?.find((value: Record<string, any>) => value.state === targetState);
            if (record) {
              (window as any).__creatorPublicationCut = record;
              throw new DOMException("creator durable publication cut", "OperationError");
            }
            return original.call(this, algorithm, key, data);
          };
        }, failArtifactInstall ? "artifacts_converged" : "ready");
      }
      if (loseCreateResponse || loseDeviceEvidence || loseBlobResponse || loseGenesisResponse || failLocalPublication || competingGenesisWins || rejectGenesis) {
        // Submit through the real wizard, then destroy its runtime at the
        // accepted-create response or current Device evidence boundary.
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
        if (failLocalPublication) {
          await expect.poll(() => creator.page.evaluate(() => (window as any).__creatorPublicationCut?.intent.effective_scope.realm_id), { timeout: 120_000 }).toBeTruthy();
          cutRealmId = await creator.page.evaluate(() => (window as any).__creatorPublicationCut.intent.effective_scope.realm_id);
          const before = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          expect(before.state).toBe(failArtifactInstall ? "genesis_accepted" : "artifacts_converged");
          expect(before.ready_receipt).toBeUndefined();
          expect(before.ready_index.filter((receipt: Record<string, any>) => receipt.effective_scope.realm_id === cutRealmId)).toHaveLength(0);
          expect(before.accepted_genesis.accepted.event).toEqual(before.queued_genesis.signed_genesis.event);
          expect(Boolean(before.artifacts)).toBe(failReadyPublish);
          intentAtCut = before.intent;
          epochUnitAtCut = before.epoch_zero;
          signedGenesisAtCut = before.queued_genesis;
          acceptedGenesisAtCut = before.accepted_genesis.accepted;
          await creator.page.waitForTimeout(500);
          const still = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          expect(still.state).toBe(before.state);
          expect(still.epoch_zero).toEqual(epochUnitAtCut);
        }
        let resumedBeforeGenesisCut = false;
        await expect.poll(async () => {
          if (!cutRealmId && !resumedBeforeGenesisCut && (loseGenesisResponse || competingGenesisWins || rejectGenesis)) {
            const openRealm = wizard.getByTestId("realm-setup-done").getByRole("link", { name: /Open (?:Realm|workspace)/i });
            if (await openRealm.isVisible().catch(() => false)) {
              // A real unavailable snapshot can stop setup before our target
              // cut. Re-enter its accepted Realm and resume the same record.
              resumedBeforeGenesisCut = true;
              await openRealm.click();
            }
          }
          return cutRealmId;
        }, { timeout: 120_000 }).toBeTruthy();
        if (competingGenesisWins) {
          await expect.poll(() => competingWinnerId, { timeout: 60_000 }).toBeTruthy();
          if (winnerAfterRejection) {
            await expect.poll(async () => (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)?.state,
              { timeout: 60_000 }).toBe("rejected");
            const refused = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
            expect(refused.rejection.reason_code).toBe("mls_activation_irreversible");
            expect(refused.rejection.authority_problem.status).toBe(409);
            expect(refused.queue_items.find((item: Record<string, any>) => item.submission.event_id === refused.rejection.event_id).status).toBe("failed");
            await creator.page.goto(`/chat/${encodeURIComponent(cutRealmId!)}`, { waitUntil: "domcontentloaded" });
            await expect(creator.page.getByTestId("creator-mls-retry-button")).toBeVisible({ timeout: 60_000 });
            expect((await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!.rejection).toEqual(refused.rejection);
            let unavailableDecisions = 0;
            const captureUnavailable = async (response: import("@playwright/test").Response) => {
              if (!response.url().includes("/_arkret/self/realm-state-snapshot/head") || response.status() !== 503) return;
              const problem = await response.json().catch(() => undefined);
              if (problem?.type === "https://arkret.org/problems/realm_state_snapshot_unavailable") unavailableDecisions += 1;
            };
            creator.page.on("response", captureUnavailable);
            try {
              for (let attempt = 0; attempt < 3; attempt += 1) {
                const beforeUnavailable = unavailableDecisions;
                const retry = creator.page.getByTestId("creator-mls-retry-button");
                await expect(retry).toBeEnabled();
                await retry.click();
                await expect.poll(async () => {
                  const record = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
                  if (record.state === "superseded") return true;
                  return unavailableDecisions > beforeUnavailable && await retry.isEnabled().catch(() => false)
                    && (await creator.page.getByTestId("creator-mls-retry").textContent())?.includes("realm_state_snapshot_unavailable");
                }, { timeout: 60_000 }).toBeTruthy();
                const afterRetry = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
                if (afterRetry.state === "superseded") break;
                // A real issuance-cut change leaves the exact rejection intact.
                // A second explicit product action repeats the verified query.
                expect(afterRetry.state).toBe("rejected");
                expect(afterRetry.rejection).toEqual(refused.rejection);
                expect(afterRetry.intent).toEqual(refused.intent);
                expect(afterRetry.rejected_record).toEqual(refused.rejected_record);
                expect(afterRetry.queue_items).toEqual(refused.queue_items);
                expect(afterRetry.ready_index).toHaveLength(0);
                expect(submittedGenesisIds.size).toBe(1);
              }
            } finally { creator.page.off("response", captureUnavailable); }
          }
          await expect.poll(async () => (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)?.state, { timeout: 60_000 }).toBe("superseded");
          const terminal = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          expect(terminal.intent).toEqual(intentAtCut);
          expect(terminal.winner.accepted.event.event_id).toBe(competingWinnerId);
          const losingAttempt = terminal.loser_record.rejected_record ?? terminal.loser_record;
          expect(losingAttempt.epoch_zero).toEqual(epochUnitAtCut);
          expect(losingAttempt.queued_genesis).toEqual(signedGenesisAtCut);
          expect(terminal.loser_genesis).toEqual([signedGenesisAtCut!.outbound_queue_item_id, signedGenesisAtCut!.canonical_bytes_digest]);
          expect(terminal.queue_items.some((item: Record<string, any>) => item.submission.event_id === terminal.loser_genesis[0])).toBe(false);
          expect(terminal.ready_index).toHaveLength(0);
          expect(terminal.ready_receipt).toBeUndefined();
          const current = await readScopeMlsGroupCurrentApi(request, creatorSession.grantJwt, cutRealmId!);
          expect(current!.genesis_event_ref).toBe(competingWinnerId);
          expect(current!.public_tree_ref).toBe(terminal.winner.accepted.event.payload.ratchet_tree_ref);
          const historyBefore = await queryRealmEventsApi(request, creatorSession.grantJwt, cutRealmId!);
          // Space titles are encrypted metadata too. A losing private group
          // cannot author even a Board until lawful winner material is acquired.
          const assertBoardCreateBlocked = async () => {
            await expect(creator.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 60_000 });
            await creator.page.getByTestId("new-board-toggle").click();
            await creator.page.getByTestId("new-board-title-input").fill(boardTitle);
            await expect(creator.page.getByTestId("create-board-space-button")).toBeDisabled();
          };
          await creator.page.goto(`/kanban/${cutRealmId!}`, { waitUntil: "domcontentloaded" });
          await assertBoardCreateBlocked();
          const afterNavigation = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          expect(afterNavigation.state).toBe("superseded");
          expect(afterNavigation.winner).toEqual(terminal.winner);
          expect(afterNavigation.loser_record).toEqual(terminal.loser_record);
          expect(submittedGenesisIds.size).toBe(1);
          await creator.page.reload({ waitUntil: "domcontentloaded" });
          await assertBoardCreateBlocked();
          const afterReload = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          expect(afterReload.state).toBe("superseded");
          expect(afterReload.winner).toEqual(terminal.winner);
          expect(afterReload.loser_record).toEqual(terminal.loser_record);
          expect(afterReload.queue_items.some((item: Record<string, any>) => item.submission.event_id === terminal.loser_genesis[0])).toBe(false);
          expect(afterReload.ready_index).toHaveLength(0);
          expect(submittedGenesisIds.size).toBe(1);
          expect(submittedCreateIds.size).toBe(1);
          expect(await queryRealmEventsApi(request, creatorSession.grantJwt, cutRealmId!)).toEqual(historyBefore);
          await stepShot(creator.page, testInfo, "A-superseded-loser-stays-unwritable-after-reload");
          return;
        }
        if (rejectGenesis) {
          await expect.poll(async () => (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)?.state,
            { timeout: 60_000 }).toBe("rejected");
          const terminal = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          closedRejection = terminal.rejection;
          expect(terminal.intent).toEqual(intentAtCut);
          expect(terminal.rejected_record.epoch_zero).toEqual(epochUnitAtCut);
          expect(terminal.rejected_record.queued_genesis).toEqual(signedGenesisAtCut);
          expect(closedRejection!.event_id).toBe(signedGenesisAtCut!.outbound_queue_item_id);
          expect(closedRejection!.canonical_bytes_digest).toBe(signedGenesisAtCut!.canonical_bytes_digest);
          expect(closedRejection!.reason_code).toBe("capability_denied");
          expect(closedRejection!.stage).toBe("authority_submit");
          expect(closedRejection!.authority_problem.status).toBe(403);
          expect(closedRejection!.last_verified.current_snapshot.realm_id).toBe(cutRealmId);
          const stopped = terminal.queue_items.find((item: Record<string, any>) => item.submission.event_id === closedRejection!.event_id);
          expect(stopped.status).toBe("failed");
          expect(stopped.last_problem).toEqual(closedRejection!.authority_problem);
          expect(stopped.settled_at).toBeTruthy();
          expect(terminal.ready_index).toHaveLength(0);
          if (rejectedOriginalAccepted) {
            const url = `${solandBaseUrl()}/_arkret/self/events`;
            const response = await request.post(url, {
              data: canonicalJson(stopped.submission.request),
              headers: { "content-type": "application/json", ...selfPathGrantHeaders({
                deviceKey: creatorSession.deviceKey, grantJwt: creatorSession.grantJwt, method: "POST", url,
              }) },
            });
            expect(response.ok(), "the actual Station accepts the exact previously rejected original fixture").toBe(true);
            const outcome = await response.json();
            assertAuthoritySubmitOutcome(outcome, stopped.submission.request.event, "accepted original contradicting local rejection");
            rejectionActive = false;
            await creator.page.goto(`/chat/${encodeURIComponent(cutRealmId!)}`, { waitUntil: "domcontentloaded" });
            for (let retry = 0; retry < 3; retry += 1) {
              await expect(creator.page.getByTestId("creator-mls-retry-button").first()).toBeEnabled({ timeout: 60_000 });
              await creator.page.getByTestId("creator-mls-retry-button").first().click();
              await expect.poll(async () => {
                const current = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
                if (current.state === "quarantined") return "quarantined";
                if (await creator.page.getByTestId("creator-mls-retry").filter({ hasText: "realm_state_snapshot_unavailable" }).count()) return "retryable_unavailable";
                return "pending";
              }, { timeout: 60_000 }).not.toBe("pending");
              const current = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
              if (current.state === "quarantined") break;
              expect(current.state).toBe("rejected");
              expect(current.rejection).toEqual(terminal.rejection);
              expect(current.rejected_record).toEqual(terminal.rejected_record);
              expect(current.queue_items).toEqual(terminal.queue_items);
            }
            const quarantined = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
            expect(quarantined.state).toBe("quarantined");
            expect(quarantined.intent).toEqual(terminal.intent);
            expect(quarantined.diagnostic.last_state).toBe("rejected");
            expect(quarantined.diagnostic.invariant).toBe("accepted_result");
            expect(quarantined.diagnostic.event_id).toBe(closedRejection!.event_id);
            expect(quarantined.diagnostic.accepted_winner.kind).toBe("winner");
            expect(quarantined.diagnostic.accepted_winner.winner.accepted.event).toEqual(stopped.submission.request.event);
            expect(quarantined.diagnostic.recovery_record.rejection).toEqual(terminal.rejection);
            expect(quarantined.diagnostic.recovery_record.rejected_record).toEqual(terminal.rejected_record);
            expect(quarantined.ready_index).toHaveLength(0);
            await expect(creator.page.getByTestId("creator-mls-quarantined").first()).toBeVisible({ timeout: 60_000 });
            await expect(creator.page.getByTestId("creator-mls-retry-button")).toHaveCount(0);
            await creator.page.reload({ waitUntil: "domcontentloaded" });
            await expect(creator.page.getByTestId("creator-mls-quarantined").first()).toBeVisible({ timeout: 60_000 });
            const reopened = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
            expect(reopened.diagnostic).toEqual(quarantined.diagnostic);
            expect(reopened.intent).toEqual(terminal.intent);
            expect(submittedGenesisIds.size).toBe(1);
            expect(submittedCreateIds.size).toBe(1);
            await stepShot(creator.page, testInfo, "A-rejected-original-accepted-conflict-stays-quarantined");
            return;
          }
          await creator.page.goto(`/chat/${encodeURIComponent(cutRealmId!)}`, { waitUntil: "domcontentloaded" });
          await expect(creator.page.getByTestId("creator-mls-retry-button")).toBeVisible({ timeout: 60_000 });
          const afterReentry = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          expect(afterReentry.state).toBe("rejected");
          expect(afterReentry.rejection).toEqual(closedRejection);
          expect(submittedGenesisIds.size).toBe(1);
          let holdRetryAbsence = true;
          let retryAbsenceCuts = 0;
          await creator.page.route(/\/_arkret\/self\/streams\/scan(?:\?.*)?$/, async (route) => {
            const query = route.request().postDataJSON() as Record<string, any>;
            if (holdRetryAbsence && query.realm_id === cutRealmId) {
              retryAbsenceCuts += 1;
              await route.fulfill({ status: 503, contentType: "application/problem+json", body: JSON.stringify({
                type: "https://arkret.org/problems/temporarily_unavailable", title: "Temporarily unavailable",
                status: 503, detail: "creator new-attempt absence cut",
              }) });
            } else { await route.fallback(); }
          });
          await creator.page.getByTestId("creator-mls-retry-button").click();
          await expect.poll(() => retryAbsenceCuts, { timeout: 60_000 }).toBeGreaterThan(0);
          await expect(creator.page.getByTestId("creator-mls-retry-button")).toBeEnabled({ timeout: 60_000 });
          const blocked = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          expect(blocked.state).toBe("rejected");
          expect(blocked.rejection).toEqual(closedRejection);
          expect(submittedGenesisIds.size).toBe(1);
          holdRetryAbsence = false;
          rejectionActive = false;
          epochUnitAtCut = undefined;
          signedGenesisAtCut = undefined;
          await creator.page.getByTestId("creator-mls-retry-button").click();
          await expect.poll(async () => (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)?.state,
            { timeout: 90_000 }).toBe("ready");
          const retried = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          expect(retried.intent).toEqual(intentAtCut);
          expect(retried.closed_attempts).toEqual([closedRejection]);
          expect(retried.queue_items.some((item: Record<string, any>) => item.submission.event_id === closedRejection!.event_id)).toBe(false);
          expect(retried.queued_genesis.outbound_queue_item_id).not.toBe(closedRejection!.event_id);
          const freshCut = retried.governance_evidence.accepted_create.authority_root;
          const rejectedCut = closedRejection!.last_verified.accepted_create.authority_root;
          for (const basis of [freshCut, rejectedCut]) {
            expect(basis.account_id).toEqual(creatorSession.accountId);
            expect(basis.session_grant_id).toBe(creatorSession.grantId);
            expect(basis.snapshot.realm_id).toBe(cutRealmId);
            expect(Number.isSafeInteger(basis.request_sequence)).toBe(true);
          }
          expect(freshCut.session_epoch).toBe(rejectedCut.session_epoch);
          // The sequence is consumer-local, not a cross-client clock.
          // SDK same_read compares this exact holder/session/read binding.
          expect(freshCut.request_sequence).not.toBe(rejectedCut.request_sequence);
          expect(submittedGenesisIds.size).toBe(2);
          epochUnitAtCut = undefined;
          signedGenesisAtCut = undefined;
        }
        if (loseDeviceEvidence) {
          expect(deviceCutSeen).toBe(true);
          const before = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId);
          expect(before!.state).toBe("realm_accepted");
          expect(before!.governance_evidence).toBeUndefined();
        }
        if (loseBlobResponse) {
          const before = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId);
          expect(before!.state).toBe("epoch0_state_persisted");
          expect(before!.queued_genesis).toBeUndefined();
          expect(before!.epoch_zero).toEqual(epochUnitAtCut);
        }
        if (loseGenesisResponse) {
          const before = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === cutRealmId)!;
          expect(before.state).toBe("genesis_queued");
          expect(before.accepted_genesis, "HTTP acceptance cannot bypass the unavailable exact query").toBeUndefined();
          expect(before.epoch_zero).toEqual(epochUnitAtCut);
          expect(before.queued_genesis).toEqual(signedGenesisAtCut);
        } else if (!failLocalPublication && !rejectGenesis) {
          expect(submittedGenesisIds.size, "the crash cut precedes every Genesis submission").toBe(0);
        }
        realmId = cutRealmId!;
        await stepShot(creator.page, testInfo, loseGenesisResponse ? "A-genesis-response-and-query-lost" : loseBlobResponse ? "A-public-blob-response-lost" : loseDeviceEvidence ? "A-device-evidence-unavailable" : "A-accepted-create-response-lost");
        await creator.page.goto(`/chat/${encodeURIComponent(realmId)}`, { waitUntil: "domcontentloaded" });
        cutActive = false;
        deviceCutActive = false;
        blobCutActive = false;
        genesisCutActive = false;
      } else {
        realmId = await creator.createRealm(createOptions);
      }
      expect(submittedCreateIds.size).toBe(1);
      const intentBeforeReload = (await readCreatorIntents(creator.page)).find(
        (intent) => intent.effective_scope.realm_id === realmId,
      );
      expect(intentBeforeReload).toBeDefined();
      if (loseCreateResponse || loseDeviceEvidence || loseBlobResponse || loseGenesisResponse || failLocalPublication) expect(intentBeforeReload).toEqual(intentAtCut);
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
      if (loseCreateResponse || loseDeviceEvidence || loseBlobResponse || loseGenesisResponse || failLocalPublication) {
        expect(submittedGenesisIds.size, "background recovery must author one Genesis for the original scope").toBe(1);
        expect(submittedCreateIds.size).toBe(1);
      }

      await assertE2eeStorageIsHardened(creator.page, [privateDescription]);
      const recordBeforeReload = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === realmId)!;
      const pinBeforeReload = recordBeforeReload.governance_evidence;
      if (rejectGenesis) expect(recordBeforeReload.closed_attempts).toEqual([closedRejection]);
      expect(recordBeforeReload.state).toBe("ready");
      const readyReceipt = recordBeforeReload.ready_receipt;
      expect(readyReceipt.accepted_genesis_event_id).toBe(recordBeforeReload.accepted_genesis.accepted.event.event_id);
      expect(readyReceipt.accepted_genesis_digest).toBe(recordBeforeReload.accepted_genesis.accepted_bytes_digest);
      expect(readyReceipt.immutable_genesis_binding).toEqual(recordBeforeReload.governance_evidence.governance_binding);
      expect(readyReceipt.accepted_artifact_ref).toBe(readyReceipt.accepted_genesis_event_id);
      expect(readyReceipt.ready_commit_position).toBeGreaterThan(0);
      expect(readyReceipt.ready_commit_position).toBeLessThanOrEqual(recordBeforeReload.vault_commit_position);
      expect(recordBeforeReload.ready_index.filter((receipt: Record<string, any>) => receipt.effective_scope.realm_id === realmId)).toEqual([readyReceipt]);
      expect(recordBeforeReload.artifacts.accepted_artifact_ref).toBe(readyReceipt.accepted_artifact_ref);
      expect(recordBeforeReload.artifacts.consistency_checks.group_info_bytes).toEqual(recordBeforeReload.epoch_zero.group_info_bytes);
      expect(recordBeforeReload.artifacts.consistency_checks.ratchet_tree_bytes).toEqual(recordBeforeReload.epoch_zero.ratchet_tree_bytes);
      const accepted = recordBeforeReload.accepted_genesis;
      expect(accepted.accepted.event).toEqual(recordBeforeReload.queued_genesis.signed_genesis.event);
      expect(accepted.canonical_accepted_bytes).toEqual(recordBeforeReload.queued_genesis.canonical_signed_bytes);
      expect(accepted.accepted_bytes_digest).toBe(recordBeforeReload.queued_genesis.canonical_bytes_digest);
      const ledger = recordBeforeReload.queue_items.find((item: Record<string, any>) => item.submission.event_id === accepted.accepted.event.event_id);
      expect(ledger.status).toBe("committed");
      expect(ledger.submission.state.commit).toEqual(accepted.accepted.commit);
      expect(ledger.settled_at).toBeTruthy();
      if (acceptedGenesisAtCut) expect(accepted.accepted.commit).toEqual(acceptedGenesisAtCut.commit);
      if (signedGenesisAtCut) expect(recordBeforeReload.queued_genesis).toEqual(signedGenesisAtCut);
      expect(recordBeforeReload.epoch_zero).toBeDefined();
      expect(recordBeforeReload.queued_genesis).toBeDefined();
      if (epochUnitAtCut) expect(recordBeforeReload.epoch_zero).toEqual(epochUnitAtCut);
      expect(pinBeforeReload).toBeDefined();
      await stepShot(creator.page, testInfo, "A-secure-cache-before-reload");

      await creator.page.reload({ waitUntil: "domcontentloaded" });
      await readyReaderBoard(creator, boardId);
      expect((await readCreatorIntents(creator.page)).find(
        (intent) => intent.effective_scope.realm_id === realmId,
      )).toEqual(intentBeforeReload);
      expect(submittedCreateIds.size).toBe(1);
      expect((await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === realmId)!.governance_evidence).toEqual(pinBeforeReload);
      const recordAfterReload = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === realmId)!;
      expect(recordAfterReload.state).toBe("ready");
      if (rejectGenesis) {
        expect(recordAfterReload.closed_attempts).toEqual([closedRejection]);
        expect(submittedGenesisIds.size).toBe(2);
        expect(recordAfterReload.queue_items.some((item: Record<string, any>) => item.submission.event_id === closedRejection!.event_id)).toBe(false);
      }
      expect(recordAfterReload.ready_receipt).toEqual(readyReceipt);
      expect(recordAfterReload.artifacts).toEqual(recordBeforeReload.artifacts);
      expect(recordAfterReload.ready_index.filter((receipt: Record<string, any>) => receipt.effective_scope.realm_id === realmId)).toEqual([readyReceipt]);
      expect(recordAfterReload.accepted_genesis).toEqual(recordBeforeReload.accepted_genesis);
      expect(recordAfterReload.epoch_zero).toEqual(recordBeforeReload.epoch_zero);
      expect(recordAfterReload.queued_genesis).toEqual(recordBeforeReload.queued_genesis);
      await assertCardDecrypts(creator, cardTitle, privateDescription);
      await assertE2eeStorageIsHardened(creator.page, [privateDescription]);
      await stepShot(creator.page, testInfo, "B-secure-cache-after-reload");
      if (quarantineCut) {
        const damaged = await damageCreatorVault(creator.page, realmId, cut);
        const genesisCount = submittedGenesisIds.size;
        const genesisId = damaged.queued_genesis.outbound_queue_item_id;
        const boardUrl = `/kanban/${realmId}/board/${boardId}`;
        if (cut === "quarantine_write_failure") {
          await creator.page.addInitScript(() => {
            if (!new URL(location.href).searchParams.has("creator-vault-write-cut")) return;
            const original = SubtleCrypto.prototype.encrypt;
            SubtleCrypto.prototype.encrypt = async function(algorithm, key, data) {
              const bytes = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);
              let value: Record<string, any> | undefined;
              try { value = JSON.parse(new TextDecoder().decode(bytes)); } catch { /* unrelated encryption */ }
              if (value?.creator_bootstrap_records?.some((record: Record<string, any>) => record.state === "quarantined")) {
                (window as any).__creatorQuarantineWriteFailed = true;
                throw new DOMException("creator quarantine durable write cut", "OperationError");
              }
              return original.call(this, algorithm, key, data);
            };
          });
          await creator.page.goto(`${boardUrl}?creator-vault-write-cut=1`, { waitUntil: "domcontentloaded" });
          await expect.poll(() => creator.page.evaluate(() => Boolean((window as any).__creatorQuarantineWriteFailed)), { timeout: 60_000 }).toBe(true);
          const pending = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === realmId)!;
          const { queue_items, ready_index, vault_commit_position, ...pendingRecord } = pending;
          expect(pendingRecord, "failed quarantine publication must retain the entire prior durable record").toEqual(damaged);
          expect(ready_index.filter((receipt: Record<string, any>) => receipt.effective_scope.realm_id === realmId)).toEqual([readyReceipt]);
          await expect(creator.page.getByTestId("creator-mls-quarantined")).toHaveCount(0);
        }
        await creator.page.goto(boardUrl, { waitUntil: "domcontentloaded" });
        await expect.poll(async () => (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === realmId)?.state, { timeout: 60_000 }).toBe("quarantined");
        const terminal = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === realmId)!;
        expect(terminal.intent).toEqual(damaged.intent);
        expect(terminal.diagnostic.last_state).toBe("ready");
        expect(terminal.diagnostic.invariant).toBeTruthy();
        if (cut === "quarantine_private" || cut === "quarantine_write_failure") expect(terminal.diagnostic.invariant).toBe("private_material");
        expect(terminal.diagnostic.invariant_detail).toBeTruthy();
        expect(terminal.diagnostic.reason_code).toMatch(/^creator_.+_mismatch$/);
        expect(terminal.diagnostic.detected_at).toBeTruthy();
        expect(terminal.diagnostic.event_id).toBe(genesisId);
        expect(terminal.diagnostic.canonical_bytes_digest).toBe(damaged.queued_genesis.canonical_bytes_digest);
        expect(terminal.diagnostic.outbound_queue_item_id).toBe(genesisId);
        expect(terminal.diagnostic.recovery_record).toEqual(damaged);
        expect(terminal.diagnostic.accepted_winner).toEqual({ kind: "original", acceptance: damaged.accepted_genesis });
        expect(terminal.diagnostic.recovery_queue_items.some((item: Record<string, any>) => item.submission.event_id === genesisId)).toBe(true);
        expect(terminal.ready_index.filter((receipt: Record<string, any>) => receipt.effective_scope.realm_id === realmId)).toHaveLength(0);
        expect(terminal.ready_receipt).toBeUndefined();
        await expect(creator.page.getByTestId("creator-mls-quarantined").first()).toBeVisible({ timeout: 60_000 });
        await expect(creator.page.getByTestId("creator-mls-retry-button")).toHaveCount(0);
        await expect(creator.page.getByTestId("kanban-column").filter({ hasText: listTitle }).first().getByTestId("add-card-button")).toBeDisabled();
        const createCount = submittedCreateIds.size;
        await creator.page.reload({ waitUntil: "domcontentloaded" });
        await expect(creator.page.getByTestId("creator-mls-quarantined").first()).toBeVisible({ timeout: 60_000 });
        const reopened = (await readCreatorRecords(creator.page)).find((value) => value.intent.effective_scope.realm_id === realmId)!;
        expect(reopened.diagnostic).toEqual(terminal.diagnostic);
        expect(reopened.intent).toEqual(terminal.intent);
        expect(reopened.ready_index.filter((receipt: Record<string, any>) => receipt.effective_scope.realm_id === realmId)).toHaveLength(0);
        await expect(creator.page.getByTestId("kanban-column").filter({ hasText: listTitle }).first().getByTestId("add-card-button")).toBeDisabled();
        expect(submittedCreateIds.size).toBe(createCount);
        expect(submittedGenesisIds.size).toBe(genesisCount);
        await stepShot(creator.page, testInfo, "C-quarantined-original-survives-reload-with-closed-send-gate");
      }
    } catch (error) {
      const records = await readCreatorRecords(creator.page, true).catch(() => []);
      const retryStatus = await creator.page.getByTestId("creator-mls-retry").allTextContents().catch(() => []);
      const safeStatus = retryStatus.filter((text) =>
        !/bearer |recovery_key|mnemonic|access_token|dpop:|eyJ[A-Za-z0-9_-]+\./i.test(text));
      await testInfo.attach("safe-creator-failure-coordinates", { contentType: "application/json",
        body: JSON.stringify({ cut, retryStatus: safeStatus, records: records.map((record) => ({
          scope: record.intent.effective_scope, state: record.state,
          rejectionReason: record.rejection?.reason_code,
          quarantineReason: record.diagnostic?.reason_code,
          accepted: record.accepted_genesis?.accepted.event.event_id,
          winner: record.winner?.accepted.event.event_id,
          checkpoints: record.checkpoint_coordinates,
          queue: (record.queue_items ?? []).map((item: Record<string, any>) => ({
            kind: item.submission.request.event?.kind, status: item.status,
          })),
        })) }, null, 2) });
      throw error;
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
        // The session opener already bootstraps Home. A second hard navigation
        // interrupts its first backup publication before this flow has begun.
        await alicePage.completeRecoveryKeySetupIfPrompted();
        await alicePage.acknowledgeRecommendedEncryptionPromptIfVisible();
        expect(Boolean(aliceSession.recoveryKey), "Alice retains her confirmed account Recovery Key").toBe(true);
        await alicePage.completeMlsAccountRecoveryIfPrompted(aliceSession.recoveryKey!);

        // 1) Alice creates an EMPTY realm, then activates it with accepted MLS Genesis.
        const realmId = await alicePage.createRealm({
          title: `Encrypted XM Kanban ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          historyAccess: "since_join",
          mlsActivated: true,
        });
        // First MLS use can require the already confirmed account Recovery
        // Key to seal its new checkpoint secret. Complete the real backup,
        // rather than hiding a modal or treating an optimistic Realm as ready.
        await alicePage.completeMlsAccountRecoveryIfPrompted(aliceSession.recoveryKey!);
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
        await bobPage.completeRecoveryKeySetupIfPrompted();
        await bobPage.acknowledgeRecommendedEncryptionPromptIfVisible();
        expect(Boolean(bobSession.recoveryKey), "Bob retains his confirmed account Recovery Key").toBe(true);
        await bobPage.completeMlsAccountRecoveryIfPrompted(bobSession.recoveryKey!);

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
        await bobPage.completeMlsAccountRecoveryIfPrompted(bobSession.recoveryKey!);
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
          // The List structure is accepted, but its title is encrypted metadata
          // and must remain undisclosed while the private Welcome state is cut.
          const committedList = bobPage.page.getByTestId("kanban-column");
          await expect(committedList).toHaveCount(1, { timeout: 90_000 });
          await expect(committedList).toBeVisible({ timeout: 90_000 });
          await expect(committedList).toHaveAttribute("data-column-draft", "false");
          await expect(committedList).not.toContainText(listTitle);
          await expect(bobPage.page.getByTestId("kanban-panel")).not.toContainText(boardTitle);
          await expect(bobPage.page.getByTestId("kanban-panel")).not.toContainText(aliceCard);
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
      } catch (error) {
        const records = await readCreatorRecords(alicePage.page, true).catch(() => []);
        const privateFailure = (detail: unknown) => {
          if (detail === "creator private cache has another Genesis ref") return "cache-genesis-ref";
          if (detail === "creator durable private cache differs from the winning unit") return "cache-private-unit";
          if (detail === "creator durable artifact/private state mismatch") return "artifact-private-mismatch";
          return "other-private-invariant";
        };
        await testInfo.attach("safe-creator-cross-member-failure-coordinates", {
          contentType: "application/json",
          body: JSON.stringify({ fault: fault ?? "ordinary", records: records.map(record => ({
            scope: record.intent.effective_scope, state: record.state,
            quarantineReason: record.diagnostic?.reason_code,
            invariant: record.diagnostic?.invariant,
            privateFailure: record.diagnostic ? privateFailure(record.diagnostic.invariant_detail) : undefined,
            lastState: record.diagnostic?.last_state,
            accepted: record.accepted_genesis?.accepted.event.event_id,
            checkpoints: record.checkpoint_coordinates,
          })) }, null, 2),
        });
        throw error;
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

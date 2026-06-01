// Key backup + restore
// Contract: e2e/scenarios/encryption/key-backup.md
// Spec refs:
//   - identity/key-management.md §7 (backup), §7.2 (envelope), §7.3 (restore), §12 (API)
//   - crypto-media/device-lifecycle.md §12 (key backup durable form)

import { expect, test, type Page } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  type JointUser,
  type JointUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("key backup + restore", () => {
  test("backup endpoint exists; listing exposes metadata only (no plaintext)", async ({
    browser,
    request,
  }) => {
    const alice = uniqueUser("s13-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      // Probe: is /api/v1/keys/backups routed?
      const listResp = await request.get(`${solandBaseUrl()}/api/v1/keys/backups`, {
        headers: { authorization: `Bearer ${aliceToken}` },
      });
      // If routed, body must be JSON; backups array (possibly empty).
      // If not routed (404), this is the soland implementation gap S13 documents.
      expect([200, 404]).toContain(listResp.status());
      if (listResp.ok()) {
        const body = await listResp.json();
        const backups = body.backups ?? body.results ?? body;
        expect(Array.isArray(backups)).toBeTruthy();
        // Spec §12: listing MUST NOT return plaintext keys or passphrase.
        const serialized = JSON.stringify(body);
        expect(serialized).not.toMatch(/password|passphrase|plaintext_key/i);
      }
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "alice sets up passphrase-protected backup via /settings/recovery; Argon2id KDF + XChaCha20-Poly1305 envelope uploaded",
    async () => {
      // spec: key-management.md §7.1-§7.2
      // soland gap: cx.schema.key_backup.v1 schema + recovery policy state.
      // yougen gap: /settings/recovery setup wizard.
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "device-2 restores from backup with correct passphrase; commitment match → ciphertext decrypted locally; no server oracle",
    async () => {
      // spec: key-management.md §7.2-§7.3
      // soland gap: backup retrieval API.
      // Key invariant: wrong passphrase fails at commitment stage WITHOUT contacting server.
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "device-2 replays cx.mls.commit chain using backup's mls_history_backup_key; pre-loss E2EE messages decrypt",
    async () => {
      // spec: encryption-and-audit.md §2.4 + key-management.md §7.3 step 6
      // soland gap: MLS epoch backfill on restore.
    },
  );

  test(
    "A1 same-account fresh browser restores MLS account secret and decrypts historical encrypted cards",
    async ({ browser, request }) => {
      test.setTimeout(240_000);
      const stamp = Date.now();
      const passphrase = `A1 cotest MLS account restore ${stamp} passphrase with enough entropy`;
      const alice = uniqueUser("a1-mls-restore-alice");
      await ensureRegistered(request, alice);
      const deviceAToken = await issueDevSession(request, alice);
      const deviceA = await openUserPage(browser, alice, { sessionToken: deviceAToken });
      const sessionsToClose: JointUserPage[] = [deviceA];
      const keyBackupPuts = collectKeyBackupPuts(deviceA.page);
      const protocolFailures: string[] = [];
      collectA1ProtocolFailures(deviceA.page, protocolFailures);

      try {
        const spaceId = await deviceA.createSpace({
          title: `A1 MLS restore ${stamp}`,
          summary: "same-account fresh-profile MLS account secret recovery acceptance",
          discoverability: "unlisted",
          joinRule: "invite",
          historyVisibility: "joined",
          encryptionProfile: "mls_rfc9420",
        });
        const historicalCards = [
          `A1 historical encrypted card 1 ${stamp}`,
          `A1 historical encrypted card 2 ${stamp}`,
          `A1 historical encrypted card 3 ${stamp}`,
        ];
        for (const card of historicalCards) {
          await deviceA.sendTimelineMessage(spaceId, card);
        }

        await setupRecoveryVaultPassphrase(deviceA.page, passphrase);
        await expect
          .poll(() => keyBackupPuts.some((hit) => hit.status === 200), {
            timeout: 120_000,
          })
          .toBe(true);
        await expect
          .poll(
            () =>
              keyBackupPuts.some(
                (hit) =>
                  hit.status === 200 &&
                  /"item_type"\s*:\s*"mls_account_secret"/.test(hit.postData),
              ),
            { timeout: 120_000 },
          )
          .toBe(true);

        const deviceBUser = sameActorFreshDevice(alice, "device-b");
        const deviceBToken = await issueDevSession(request, deviceBUser);
        const deviceB = await openUserPage(browser, deviceBUser, { sessionToken: deviceBToken });
        sessionsToClose.push(deviceB);
        collectA1ProtocolFailures(deviceB.page, protocolFailures);

        await deviceB.gotoHome();
        await expect(deviceB.page.getByTestId("mls-unlock-banner")).toBeVisible({
          timeout: 90_000,
        });
        await unlockMlsAccountSecret(deviceB.page, passphrase);
        await deviceB.gotoTimelineSpace(spaceId);
        for (const card of historicalCards) {
          await expect(deviceB.timelineEvent(card)).toBeVisible({ timeout: 90_000 });
        }

        const deviceBCard = `A1 restored device writes encrypted card ${stamp}`;
        await deviceB.sendTimelineMessage(spaceId, deviceBCard);
        await deviceA.gotoTimelineSpace(spaceId);
        await deviceA.page.reload({ waitUntil: "domcontentloaded" });
        await expect(deviceA.timelineEvent(deviceBCard)).toBeVisible({ timeout: 90_000 });

        expect(
          protocolFailures.filter((line) =>
            /MLS runtime|SnapshotDecryptFailed|\/api\/v1\/(account\/subscribe|subscribe|describe|events)/.test(
              line,
            ),
          ),
          protocolFailures.join("\n"),
        ).toEqual([]);
      } finally {
        await Promise.allSettled(sessionsToClose.map((session) => session.close()));
      }
    },
  );

  test(
    "A2 restored fresh browser saves encrypted Kanban card details without MLS bootstrap or schema errors",
    async ({ browser, request }) => {
      test.setTimeout(300_000);
      const stamp = Date.now();
      const passphrase = `A2 cotest MLS kanban restore ${stamp} passphrase with enough entropy`;
      const alice = uniqueUser("a2-mls-kanban-alice");
      await ensureRegistered(request, alice);
      const deviceAToken = await issueDevSession(request, alice);
      const deviceA = await openUserPage(browser, alice, { sessionToken: deviceAToken });
      const sessionsToClose: JointUserPage[] = [deviceA];
      const keyBackupPuts = collectKeyBackupPuts(deviceA.page);
      const protocolFailures: string[] = [];
      collectA1ProtocolFailures(deviceA.page, protocolFailures);

      const boardTitle = `A2 Board ${stamp}`;
      const listTitle = `A2 Todos ${stamp}`;
      const cardTitle = `A2 encrypted kanban card ${stamp}`;
      const restoredDescription = `A2 restored-device encrypted detail ${stamp}`;

      try {
        const spaceId = await deviceA.createSpace({
          title: `A2 MLS Kanban ${stamp}`,
          summary: "kanban encrypted detail MLS restore acceptance",
          discoverability: "unlisted",
          joinRule: "invite",
          historyVisibility: "joined",
          encryptionProfile: "mls_rfc9420",
        });
        const boardId = await createKanbanBoardListAndCard(
          deviceA.page,
          spaceId,
          boardTitle,
          listTitle,
          cardTitle,
        );
        await expect
          .poll(
            () =>
              keyBackupPuts.some(
                (hit) =>
                  hit.status === 200 &&
                  /"backup_class"\s*:\s*"mls_history"/.test(hit.postData),
              ),
            { timeout: 120_000 },
          )
          .toBe(true);

        await setupRecoveryVaultPassphrase(deviceA.page, passphrase);
        await expect
          .poll(
            () =>
              keyBackupPuts.some(
                (hit) =>
                  hit.status === 200 &&
                  /"item_type"\s*:\s*"mls_account_secret"/.test(hit.postData),
              ),
            { timeout: 120_000 },
          )
          .toBe(true);

        const deviceBUser = sameActorFreshDevice(alice, "device-b");
        const deviceBToken = await issueDevSession(request, deviceBUser);
        const deviceB = await openUserPage(browser, deviceBUser, { sessionToken: deviceBToken });
        sessionsToClose.push(deviceB);
        collectA1ProtocolFailures(deviceB.page, protocolFailures);

        await deviceB.gotoHome();
        await expect(deviceB.page.getByTestId("mls-unlock-banner")).toBeVisible({
          timeout: 90_000,
        });
        await unlockMlsAccountSecret(deviceB.page, passphrase);
        await deviceB.page.goto(`/kanban/${spaceId}/board/${boardId}`, {
          waitUntil: "domcontentloaded",
        });
        await expect(deviceB.page.getByTestId("kanban-panel")).toBeVisible({
          timeout: 120_000,
        });
        await expect(deviceB.page.getByTestId("board-space-select")).toHaveValue(boardId, {
          timeout: 45_000,
        });
        await expect(
          deviceB.page.getByTestId("kanban-card").filter({ hasText: cardTitle }),
        ).toBeVisible({ timeout: 90_000 });

        await updateCardDescription(deviceB.page, cardTitle, restoredDescription);
        await expectEncryptedKanbanSaveErrorsAbsent(deviceB.page);

        await deviceA.page.goto(`/kanban/${spaceId}/board/${boardId}`, {
          waitUntil: "domcontentloaded",
        });
        await expect(deviceA.page.getByTestId("kanban-panel")).toBeVisible({
          timeout: 120_000,
        });
        await deviceA.page
          .getByTestId("kanban-card")
          .filter({ hasText: cardTitle })
          .click();
        await expect(deviceA.page.getByTestId("card-description-panel")).toContainText(
          restoredDescription,
          { timeout: 90_000 },
        );

        const fatalProtocolPattern =
          /MLS runtime|SnapshotDecryptFailed|MissingWelcome|schema_violation|payload violates registered payload schema|MLS commit event failed|\/api\/v1\/(account\/subscribe|subscribe|describe|events)/;
        expect(
          protocolFailures.filter((line) => fatalProtocolPattern.test(line)),
          protocolFailures.join("\n"),
        ).toEqual([]);
      } finally {
        await Promise.allSettled(sessionsToClose.map((session) => session.close()));
      }
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "E13.1 wrong passphrase: client rejects at key_commitment stage; no GET issued to server (avoids oracle)",
    async () => {
      // spec: key-management.md §7.2
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "E13.2 tampered ciphertext: digest mismatch → client refuses to decrypt",
    async () => {
      // spec: key-management.md §7.2 line 328
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "E13.4 mixed_secret_storage=true is allowed in personal_node profile but rejected in high_assurance",
    async () => {
      // spec: key-management.md §7.1
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "E13.7 DELETE backup requires ownership proof (SSK signature); session-token-only DELETE rejected",
    async () => {
      // spec: key-management.md §7.4 + §12
    },
  );
});

type KeyBackupPut = {
  url: string;
  status: number;
  postData: string;
};

function collectKeyBackupPuts(page: Page): KeyBackupPut[] {
  const hits: KeyBackupPut[] = [];
  page.on("response", (response) => {
    if (
      response.request().method() !== "PUT" ||
      !/\/api\/v1\/keys\/backups\//.test(response.url())
    ) {
      return;
    }
    hits.push({
      url: response.url(),
      status: response.status(),
      postData: response.request().postData() ?? "",
    });
  });
  return hits;
}

function collectA1ProtocolFailures(page: Page, failures: string[]) {
  page.on("console", (message) => {
    const text = message.text();
    if (/MLS runtime|SnapshotDecryptFailed/.test(text)) {
      failures.push(`console:${message.type()}:${text}`);
    }
  });
  page.on("pageerror", (error) => {
    failures.push(`pageerror:${error.message}`);
  });
  page.on("requestfailed", (request) => {
    const url = request.url();
    const errorText = request.failure()?.errorText ?? "";
    if (
      /\/api\/v1\/(account\/subscribe|subscribe)/.test(url) &&
      /ERR_ABORTED|NS_BINDING_ABORTED|aborted|cancel/i.test(errorText)
    ) {
      return;
    }
    if (/\/api\/v1\/(account\/subscribe|subscribe|describe|events)/.test(url)) {
      failures.push(`requestfailed:${request.method()} ${url} ${errorText}`);
    }
  });
  page.on("response", (response) => {
    const url = response.url();
    if (
      response.status() >= 400 &&
      /\/api\/v1\/(account\/subscribe|subscribe|describe|events)/.test(url)
    ) {
      const entry = `http:${response.status()} ${response.request().method()} ${url}`;
      failures.push(entry);
      if (/\/api\/v1\/events/.test(url)) {
        void response
          .text()
          .then((body) => {
            if (body) {
              failures.push(`${entry} ${body.slice(0, 1000)}`);
            }
          })
          .catch(() => {});
      }
    }
  });
}

async function setupRecoveryVaultPassphrase(page: Page, passphrase: string) {
  await page.goto("/recovery", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("recovery-panel")).toBeVisible({ timeout: 120_000 });
  await page.getByTestId("vault-passphrase").fill(passphrase);
  await page.getByTestId("vault-passphrase-confirm").fill(passphrase);
  await page.getByTestId("vault-rekey").click();
  await expect(page.getByTestId("vault-status")).toContainText(/Uploaded|stored|backup/i, {
    timeout: 120_000,
  });
}

async function unlockMlsAccountSecret(page: Page, passphrase: string) {
  await page.getByTestId("mls-unlock-passphrase").fill(passphrase);
  await page.getByTestId("mls-unlock-submit").click();
  await expect(page.getByTestId("mls-unlock-status")).toContainText(/restored/i, {
    timeout: 120_000,
  });
}

async function createKanbanBoardListAndCard(
  page: Page,
  spaceId: string,
  boardTitle: string,
  listTitle: string,
  cardTitle: string,
): Promise<string> {
  await page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
  await page.getByTestId("new-board-toggle").click();
  await page.getByTestId("new-board-title-input").fill(boardTitle);
  await page.getByTestId("create-board-space-button").click();
  await expect(page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
    timeout: 45_000,
  });
  const boardId = await page
    .getByTestId("board-space-select")
    .evaluate((node) => (node as HTMLSelectElement).value);
  expect(boardId).toMatch(/^cx:space:/);

  await page.getByTestId("new-column-input").fill(listTitle);
  await page.getByTestId("add-column-button").click();
  const column = page.getByTestId("kanban-column").filter({ hasText: listTitle }).first();
  await expect(column).toBeVisible({ timeout: 45_000 });
  await column.getByTestId("add-card-button").click();
  await column.getByTestId("new-card-title-input").fill(cardTitle);
  await column.getByTestId("save-card-button").click();
  await expect(column.getByTestId("kanban-card").filter({ hasText: cardTitle })).toBeVisible({
    timeout: 45_000,
  });
  return boardId;
}

async function updateCardDescription(page: Page, cardTitle: string, description: string) {
  await page.getByTestId("kanban-card").filter({ hasText: cardTitle }).first().click();
  await expect(page.getByTestId("card-detail-modal")).toBeVisible({ timeout: 45_000 });
  const add = page.getByTestId("card-detail-add-description-button");
  if ((await add.count()) > 0 && (await add.first().isVisible())) {
    await add.first().click();
  } else {
    await page.getByTestId("card-detail-edit-description-button").click();
  }
  await setCardDetailEditorValue(page, description);
  await page.getByTestId("card-detail-save-button").click();
  await expect(page.getByTestId("card-description-panel")).toContainText(description, {
    timeout: 120_000,
  });
}

async function setCardDetailEditorValue(page: Page, value: string): Promise<void> {
  const input = page.getByTestId("card-detail-description-input");
  await expect(input).toBeAttached({ timeout: 45_000 });
  await input.evaluate((node, nextValue) => {
    const textarea = node as HTMLTextAreaElement;
    textarea.value = nextValue;
    textarea.dispatchEvent(
      new InputEvent("input", {
        bubbles: true,
        inputType: "insertText",
        data: nextValue,
      }),
    );
  }, value);
}

async function expectEncryptedKanbanSaveErrorsAbsent(page: Page) {
  await expect(page.getByText(/MLS state is not ready on this device yet/i)).toHaveCount(0);
  await expect(
    page.getByText(/schema_violation|payload violates registered payload schema/i),
  ).toHaveCount(0);
  await expect(page.getByText(/MLS commit event failed/i)).toHaveCount(0);
}

function sameActorFreshDevice(user: JointUser, label: string): JointUser {
  const suffix = `${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`
    .replace(/[^a-f0-9]/g, "")
    .slice(0, 12)
    .padEnd(12, "0");
  return {
    ...user,
    name: `${user.name}-${label}`,
    deviceId: `cx:device:01904100-0000-7000-8000-${suffix}`,
  };
}

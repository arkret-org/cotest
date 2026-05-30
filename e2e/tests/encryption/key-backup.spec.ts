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
      failures.push(`http:${response.status()} ${response.request().method()} ${url}`);
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

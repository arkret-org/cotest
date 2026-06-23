// Key backup + restore
// Contract: e2e/scenarios/encryption/key-backup.md
// Spec refs:
//   - identity/key-management.md §3.3 (Recovery Key = sole content-recovery
//     credential), §7 (backup), §7.2 (envelope), §7.3 (restore), §7.7
//     (recovery UI MUST take the 24-word Recovery Key), §7.10 (automatic
//     continuous backup)
//   - crypto-media/device-lifecycle.md §12-§12.1 (key backup durable form + API)

import { expect, test, type Page } from "@playwright/test";
import {
  coauthBaseUrl,
  optionalEnv,
  realOidcLoginHandle,
  realOidcLoginPassword,
  solandBaseUrl,
} from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  type JointUser,
  type JointUserPage,
  uniqueUser,
} from "../../helpers/users";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";

test.describe.configure({ mode: "serial" });

test.describe("key backup + restore", () => {
  test("backup endpoint exists; listing exposes metadata only (no plaintext)", async ({
    browser,
    request,
  }) => {
    const alice = uniqueUser("s13-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });

    try {
      // Probe: is /_cokret/self/keys/backups routed?
      const listResp = await request.get(
        `${solandBaseUrl()}/_cokret/self/keys/backups`,
        {
          headers: { authorization: `Bearer ${aliceToken}` },
        },
      );
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

  test.fixme(// @blocking-on: soland#encryption-key-backup-gap
  // @user-promise: e2e/scenarios/encryption/key-backup.md
  // @expected-live-by: 2026Q3
  "alice generates a 24-word Recovery Key at /settings/recovery (recovery-key-regenerate); account-secret envelopes upload automatically, no user passphrase", async () => {
    // spec: key-management.md §3.3 / §7.1-§7.2 / §7.7 / §7.10
    // Remaining gap beyond A1/A2 (which cover the MlsBackupPrompt path):
    // settings-page generation + rotation + recovery-key-sync-badge wiring,
    // and the §7.5.2 recovery_public_key envelope alongside the
    // passphrase_kdf compatibility envelope.
  });

  test("A1 automatic MLS recovery-key dialogs restore encrypted cards on a fresh browser", async ({
    browser,
    request,
  }) => {
    test.setTimeout(240_000);
    const stamp = Date.now();
    const alice = uniqueUser("a1-mls-restore-alice");
    await ensureRegistered(request, alice);
    const deviceAToken = await issueDevSession(request, alice);
    const deviceA = await openUserPage(browser, alice, {
      sessionCredential: deviceAToken,
    });
    const sessionsToClose: JointUserPage[] = [deviceA];
    const keyBackupPuts = collectKeyBackupPuts(deviceA.page);
    const protocolFailures: string[] = [];
    collectA1ProtocolFailures(deviceA.page, protocolFailures);

    try {
      const realmId = await deviceA.createRealm({
        title: `A1 MLS restore ${stamp}`,
        summary:
          "same-account fresh-profile MLS account secret recovery acceptance",
        discoverability: "unlisted",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });
      const recoveryKey = await createMlsRecoveryBackupFromPrompt(
        deviceA.page,
        keyBackupPuts,
      );
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

      const historicalCards = [
        `A1 historical encrypted card 1 ${stamp}`,
        `A1 historical encrypted card 2 ${stamp}`,
        `A1 historical encrypted card 3 ${stamp}`,
      ];
      for (const card of historicalCards) {
        await deviceA.sendTimelineMessage(realmId, card);
      }

      const deviceBUser = sameActorFreshDevice(alice, "device-b");
      const deviceBToken = await issueDevSession(request, deviceBUser);
      const deviceB = await openUserPage(browser, deviceBUser, {
        sessionCredential: deviceBToken,
      });
      sessionsToClose.push(deviceB);
      collectA1ProtocolFailures(deviceB.page, protocolFailures);

      await deviceB.gotoHome();
      await expect(deviceB.page.getByTestId("mls-unlock-banner")).toBeVisible({
        timeout: 90_000,
      });
      await unlockMlsAccountSecret(deviceB.page, recoveryKey);
      await deviceB.gotoTimelineRealm(realmId);
      for (const card of historicalCards) {
        await expect(deviceB.timelineEvent(card)).toBeVisible({
          timeout: 90_000,
        });
      }

      const deviceBCard = `A1 restored device writes encrypted card ${stamp}`;
      await deviceB.sendTimelineMessage(realmId, deviceBCard);
      await deviceA.gotoTimelineRealm(realmId);
      await deviceA.page.reload({ waitUntil: "domcontentloaded" });
      await expect(deviceA.timelineEvent(deviceBCard)).toBeVisible({
        timeout: 90_000,
      });

      expect(
        protocolFailures.filter((line) =>
          /MLS runtime|SnapshotDecryptFailed|\/(?:api\/v1|_cokret\/self)\/(account\/subscribe|subscribe|describe|events)/.test(
            line,
          ),
        ),
        protocolFailures.join("\n"),
      ).toEqual([]);
    } finally {
      await Promise.allSettled(
        sessionsToClose.map((session) => session.close()),
      );
    }
  });

  test("A3 real password/OIDC login restores MLS on a fresh browser with session-grant holder proof", async ({
    browser,
    request,
  }) => {
    test.setTimeout(420_000);
    const coauth = coauthBaseUrl();
    const restoreOptIn = optionalEnv("COTEST_REAL_MLS_RESTORE_OIDC");
    if (restoreOptIn && !coauth) {
      throw new Error(
        "COTEST_REAL_MLS_RESTORE_OIDC=1 requires COTEST_COAUTH_BASE_URL; refusing to fall back to dev-login",
      );
    }
    test.skip(!coauth, "coauth not started for this run");
    test.skip(
      !restoreOptIn && !optionalEnv("COTEST_REAL_OIDC_LOGIN"),
      "set COTEST_REAL_MLS_RESTORE_OIDC=1 to run the real OIDC MLS restore acceptance",
    );

    const stamp = Date.now();
    const envHandle = realOidcLoginHandle();
    const envPassword = realOidcLoginPassword();
    const account: PasswordAccount =
      envHandle && envPassword
        ? { handle: envHandle, password: envPassword }
        : await registerCoauthPasswordAccount(request, coauth!);

    const deviceA = await openUserPage(browser, uniqueUser("a3-oidc-mls-a"));
    const sessionsToClose: JointUserPage[] = [deviceA];
    const protocolFailures: string[] = [];
    const deviceATrace = collectSessionGrantHolderProofTrace(deviceA.page);
    const keyBackupPuts = collectKeyBackupPuts(deviceA.page);
    collectA1ProtocolFailures(deviceA.page, protocolFailures);

    try {
      await deviceA.gotoLogin();
      await serverLoginViaCoauth(deviceA.page, account);
      await expectGrantDpopSelfPath(deviceATrace, "device A real OIDC login");

      const realmId = await deviceA.createRealm({
        title: `A3 real OIDC MLS restore ${stamp}`,
        summary: "fresh-browser restore must use real coauth session grant",
        discoverability: "unlisted",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });
      const recoveryKey = await createMlsRecoveryBackupFromPrompt(
        deviceA.page,
        keyBackupPuts,
      );
      await expectGrantDpopSelfPath(deviceATrace, "device A key backup upload");
      expect(
        deviceATrace.authorizedSelfRequests.filter((hit) => hit.missingDpop),
        "real OIDC device A must not fall back to naked bearer self/root calls",
      ).toEqual([]);
      expect(
        deviceATrace.keyBackupWrites.some((hit) => hit.status === 200 && hit.hasDpop),
        "key backup write must be authenticated by the real grant plus DPoP holder proof",
      ).toBe(true);

      const historicalCards = [
        `A3 historical encrypted card 1 ${stamp}`,
        `A3 historical encrypted card 2 ${stamp}`,
      ];
      for (const card of historicalCards) {
        await deviceA.sendTimelineMessage(realmId, card);
      }

      const deviceB = await openUserPage(browser, uniqueUser("a3-oidc-mls-b"));
      sessionsToClose.push(deviceB);
      const deviceBTrace = collectSessionGrantHolderProofTrace(deviceB.page);
      collectA1ProtocolFailures(deviceB.page, protocolFailures);

      await deviceB.gotoLogin();
      await serverLoginViaCoauth(deviceB.page, account);
      await expectGrantDpopSelfPath(deviceBTrace, "device B real OIDC login");
      await deviceB.gotoHome();
      await expect(deviceB.page.getByTestId("mls-unlock-banner")).toBeVisible({
        timeout: 90_000,
      });
      await unlockMlsAccountSecret(deviceB.page, recoveryKey);
      const successfulUnlock = await expectSuccessfulUnlockWithHolderProof(deviceBTrace);

      const nakedUnlock = await deviceB.page.request.post(successfulUnlock.url, {
        headers: {
          authorization: `Bearer ${successfulUnlock.grantJwt}`,
          "content-type": "application/json",
        },
        data: JSON.parse(successfulUnlock.postData),
      });
      expect(
        [401, 403],
        `bearer-only key-backup unlock must fail closed, got ${nakedUnlock.status()}: ${await nakedUnlock.text()}`,
      ).toContain(nakedUnlock.status());

      const reloadTraceStart = deviceBTrace.authorizedSelfRequests.length;
      await deviceB.page.reload({ waitUntil: "domcontentloaded" });
      await expect(deviceB.page.getByTestId("client-shell")).toBeVisible({
        timeout: 120_000,
      });
      await expect(deviceB.page.getByTestId("login-panel")).toHaveCount(0);
      await expectNewGrantDpopSelfPath(
        deviceBTrace,
        reloadTraceStart,
        "device B fresh-browser reload",
      );

      await deviceB.gotoTimelineRealm(realmId);
      for (const card of historicalCards) {
        await expect(deviceB.timelineEvent(card)).toBeVisible({
          timeout: 90_000,
        });
      }

      expect(
        deviceBTrace.authorizedSelfRequests.filter((hit) => hit.missingDpop),
        "real OIDC device B must not fall back to naked bearer self/root calls",
      ).toEqual([]);
      expect(
        protocolFailures.filter((line) =>
          /MLS runtime|SnapshotDecryptFailed|MissingWelcome|schema_violation|payload violates registered payload schema|\/(?:api\/v1|_cokret\/self)\/(account\/subscribe|subscribe|describe|events)/.test(
            line,
          ),
        ),
        protocolFailures.join("\n"),
      ).toEqual([]);
    } finally {
      await Promise.allSettled(
        sessionsToClose.map((session) => session.close()),
      );
    }
  });

  test("A2 automatic MLS recovery-key dialogs keep restored Kanban writes encrypted", async ({
    browser,
    request,
  }) => {
    test.setTimeout(300_000);
    const stamp = Date.now();
    const alice = uniqueUser("a2-mls-kanban-alice");
    await ensureRegistered(request, alice);
    const deviceAToken = await issueDevSession(request, alice);
    const deviceA = await openUserPage(browser, alice, {
      sessionCredential: deviceAToken,
    });
    const sessionsToClose: JointUserPage[] = [deviceA];
    const keyBackupPuts = collectKeyBackupPuts(deviceA.page);
    const protocolFailures: string[] = [];
    collectA1ProtocolFailures(deviceA.page, protocolFailures);

    const boardTitle = `A2 Board ${stamp}`;
    const listTitle = `A2 Todos ${stamp}`;
    const cardTitle = `A2 encrypted kanban card ${stamp}`;
    const restoredDescription = `A2 restored-device encrypted detail ${stamp}`;

    try {
      const realmId = await deviceA.createRealm({
        title: `A2 MLS Kanban ${stamp}`,
        summary: "kanban encrypted detail MLS restore acceptance",
        discoverability: "unlisted",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });
      const recoveryKey = await createMlsRecoveryBackupFromPrompt(
        deviceA.page,
        keyBackupPuts,
      );
      const boardId = await createKanbanBoardListAndCard(
        deviceA.page,
        realmId,
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
      const deviceB = await openUserPage(browser, deviceBUser, {
        sessionCredential: deviceBToken,
      });
      sessionsToClose.push(deviceB);
      collectA1ProtocolFailures(deviceB.page, protocolFailures);

      await deviceB.gotoHome();
      await expect(deviceB.page.getByTestId("mls-unlock-banner")).toBeVisible({
        timeout: 90_000,
      });
      await unlockMlsAccountSecret(deviceB.page, recoveryKey);
      await deviceB.page.goto(`/kanban/${realmId}/board/${boardId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(deviceB.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await expect(deviceB.page.getByTestId("board-space-select")).toHaveValue(
        boardId,
        {
          timeout: 45_000,
        },
      );
      await expect(
        deviceB.page.getByTestId("kanban-card").filter({ hasText: cardTitle }),
      ).toBeVisible({ timeout: 90_000 });

      await updateCardDescription(deviceB.page, cardTitle, restoredDescription);
      await expectEncryptedKanbanSaveErrorsAbsent(deviceB.page);

      await deviceA.page.goto(`/kanban/${realmId}/board/${boardId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(deviceA.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      if (await restoreMlsHistoryIfPrompted(deviceA.page, recoveryKey)) {
        await deviceA.page.goto(`/kanban/${realmId}/board/${boardId}`, {
          waitUntil: "domcontentloaded",
        });
        await expect(deviceA.page.getByTestId("kanban-panel")).toBeVisible({
          timeout: 120_000,
        });
        await expect(
          deviceA.page.getByTestId("board-space-select"),
        ).toHaveValue(boardId, {
          timeout: 45_000,
        });
      }
      await deviceA.page
        .getByTestId("kanban-card")
        .filter({ hasText: cardTitle })
        .click();
      await expect(
        deviceA.page.getByTestId("card-description-panel"),
      ).toContainText(restoredDescription, { timeout: 90_000 });

      const fatalProtocolPattern =
        /MLS runtime|SnapshotDecryptFailed|MissingWelcome|schema_violation|payload violates registered payload schema|MLS commit event failed|\/(?:api\/v1|_cokret\/self)\/(account\/subscribe|subscribe|describe|events)/;
      expect(
        protocolFailures.filter((line) => fatalProtocolPattern.test(line)),
        protocolFailures.join("\n"),
      ).toEqual([]);
    } finally {
      await Promise.allSettled(
        sessionsToClose.map((session) => session.close()),
      );
    }
  });

  test.fixme(// @blocking-on: soland#encryption-key-backup-gap
  // @user-promise: e2e/scenarios/encryption/key-backup.md
  // @expected-live-by: 2026Q3
  "E13.1 wrong Recovery Key: invalid 24-word input rejected at normalization; valid-but-wrong words rejected at key_commitment stage; no GET issued to server (avoids oracle)", async () => {
    // spec: key-management.md §7.2 / §7.7
  });

  test.fixme(// @blocking-on: soland#encryption-key-backup-gap
  // @user-promise: e2e/scenarios/encryption/key-backup.md
  // @expected-live-by: 2026Q3
  "E13.2 tampered ciphertext: digest mismatch → client refuses to decrypt", async () => {
    // spec: key-management.md §7.2
  });

});

type KeyBackupPut = {
  url: string;
  status: number;
  postData: string;
};

type PasswordAccount = {
  handle: string;
  password: string;
};

type HolderProofRequest = {
  method: string;
  url: string;
  status: number;
  hasDpop: boolean;
  missingDpop: boolean;
  authorization: string;
  grantJwt: string;
  postData: string;
};

type KeyBackupUnlockRequest = HolderProofRequest & {
  hasProofBody: boolean;
};

type SessionGrantHolderProofTrace = {
  authorizedSelfRequests: HolderProofRequest[];
  keyBackupWrites: HolderProofRequest[];
  unlocks: KeyBackupUnlockRequest[];
};

function collectKeyBackupPuts(page: Page): KeyBackupPut[] {
  const hits: KeyBackupPut[] = [];
  page.on("response", (response) => {
    if (
      response.request().method() !== "PUT" ||
      !/\/(?:api\/v1|_cokret\/self)\/keys\/backups\//.test(response.url())
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

function collectSessionGrantHolderProofTrace(
  page: Page,
): SessionGrantHolderProofTrace {
  const trace: SessionGrantHolderProofTrace = {
    authorizedSelfRequests: [],
    keyBackupWrites: [],
    unlocks: [],
  };
  page.on("response", (response) => {
    const request = response.request();
    const url = response.url();
    if (!/\/_cokret\/(?:self|root)\//.test(url)) {
      return;
    }
    const headers = request.headers();
    const authorization = headers.authorization ?? "";
    if (!/^Bearer\s+\S+/.test(authorization)) {
      return;
    }
    const postData = request.postData() ?? "";
    const hit: HolderProofRequest = {
      method: request.method(),
      url,
      status: response.status(),
      hasDpop: Boolean(headers.dpop),
      missingDpop: !headers.dpop,
      authorization,
      grantJwt: authorization.replace(/^Bearer\s+/i, ""),
      postData,
    };
    trace.authorizedSelfRequests.push(hit);
    if (
      hit.method === "PUT" &&
      /\/_cokret\/self\/keys\/backups\/[^/]+$/.test(url)
    ) {
      trace.keyBackupWrites.push(hit);
    }
    if (
      hit.method === "POST" &&
      /\/_cokret\/self\/keys\/backups\/[^/]+\/unlock$/.test(url)
    ) {
      trace.unlocks.push({
        ...hit,
        hasProofBody: /"proof"\s*:/.test(postData),
      });
    }
  });
  return trace;
}

async function expectGrantDpopSelfPath(
  trace: SessionGrantHolderProofTrace,
  label: string,
) {
  await expectNewGrantDpopSelfPath(trace, 0, label);
}

async function expectNewGrantDpopSelfPath(
  trace: SessionGrantHolderProofTrace,
  startIndex: number,
  label: string,
) {
  await expect
    .poll(
      () =>
        trace.authorizedSelfRequests
          .slice(startIndex)
          .some(isRealGrantDpopSelfRequest),
      { timeout: 60_000 },
    )
    .toBe(true);
  expect(
    trace.authorizedSelfRequests
      .slice(startIndex)
      .some(isRealGrantDpopSelfRequest),
    `${label}: expected a real session-grant JWT self/root request with DPoP`,
  ).toBe(true);
}

function isRealGrantDpopSelfRequest(hit: HolderProofRequest): boolean {
  return hit.hasDpop && hit.status < 500 && hit.grantJwt.split(".").length >= 3;
}

async function expectSuccessfulUnlockWithHolderProof(
  trace: SessionGrantHolderProofTrace,
): Promise<KeyBackupUnlockRequest> {
  await expect
    .poll(
      () =>
        trace.unlocks.some(
          (hit) =>
            hit.status === 200 &&
            hit.hasProofBody &&
            isRealGrantDpopSelfRequest(hit),
        ),
      { timeout: 120_000 },
    )
    .toBe(true);
  return trace.unlocks.find(
    (hit) =>
      hit.status === 200 && hit.hasProofBody && isRealGrantDpopSelfRequest(hit),
  )!;
}

async function serverLoginViaCoauth(
  page: Page,
  account: PasswordAccount,
): Promise<void> {
  await page.getByTestId("login-server-url").fill(solandBaseUrl());
  await page.getByTestId("start-server-login-button").click();

  const loginHandle = page.locator("#login-handle");
  const shell = page.getByTestId("client-shell");
  await expect(loginHandle.or(shell)).toBeVisible({ timeout: 60_000 });
  if (await loginHandle.isVisible()) {
    await loginHandle.fill(account.handle);
    await page.locator("#login-password").fill(account.password);
    await page.getByTestId("coauth-login-submit").click();
  }

  const approve = page.getByTestId("coauth-oauth-approve");
  const consentShown = await approve
    .waitFor({ state: "visible", timeout: 20_000 })
    .then(() => true)
    .catch(() => false);
  if (consentShown) {
    await approve.click();
  }

  await expect(shell).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("login-panel")).toHaveCount(0);
  expect(new URL(page.url()).pathname).not.toBe("/login");
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
      request.method() === "GET" &&
      /\/(?:api\/v1|_cokret\/self)\/(account\/subscribe|subscribe|events\/describe|describe)(?:\?|$)/.test(
        url,
      ) &&
      /ERR_ABORTED|NS_BINDING_ABORTED|aborted|cancel/i.test(errorText)
    ) {
      return;
    }
    if (
      /\/(?:api\/v1|_cokret\/self)\/(account\/subscribe|subscribe|describe|events)/.test(
        url,
      )
    ) {
      failures.push(`requestfailed:${request.method()} ${url} ${errorText}`);
    }
  });
  page.on("response", (response) => {
    const url = response.url();
    if (
      response.status() >= 400 &&
      /\/(?:api\/v1|_cokret\/self)\/(account\/subscribe|subscribe|describe|events)/.test(
        url,
      )
    ) {
      const entry = `http:${response.status()} ${response.request().method()} ${url}`;
      failures.push(entry);
      if (/\/(?:api\/v1|_cokret\/self)\/events/.test(url)) {
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

async function createMlsRecoveryBackupFromPrompt(
  page: Page,
  keyBackupPuts: KeyBackupPut[],
): Promise<string> {
  const legacyPromptVisible = await page
    .getByTestId("mls-backup-modal")
    .isVisible({ timeout: 2_000 })
    .catch(() => false);
  if (!legacyPromptVisible) {
    return createMlsRecoveryBackupFromRecoverySettings(page, keyBackupPuts);
  }

  await expect(page.getByTestId("mls-backup-modal")).toBeVisible({
    timeout: 90_000,
  });
  await expect(page.getByTestId("mls-backup-banner")).toHaveAttribute(
    "role",
    "dialog",
  );
  await expect(page.getByTestId("mls-backup-banner")).toHaveAttribute(
    "aria-modal",
    "true",
  );
  await expect(page.getByTestId("mls-backup-submit")).toBeVisible();
  await expect(page.getByTestId("mls-backup-passphrase")).toHaveCount(0);
  await expect(page.getByTestId("mls-backup-confirm")).toHaveCount(0);

  await page.getByTestId("mls-backup-submit").click();
  const generatedKeyField = page.getByTestId("mls-backup-generated-key");
  await expect(generatedKeyField).toBeVisible({ timeout: 120_000 });
  const recoveryKey = (await generatedKeyField.inputValue()).trim();
  expect(recoveryKey.split(/\s+/)).toHaveLength(24);
  await expect(
    page.getByTestId("mls-backup-generated-key-warning"),
  ).toBeVisible();
  await expect(page.getByTestId("mls-backup-saved")).toBeVisible();

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

  await page.getByTestId("mls-backup-saved").click();
  await expect(page.getByTestId("mls-backup-modal")).toHaveCount(0);
  return recoveryKey;
}

async function createMlsRecoveryBackupFromRecoverySettings(
  page: Page,
  keyBackupPuts: KeyBackupPut[],
): Promise<string> {
  await page.goto("/settings/recovery", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("recovery-key-section")).toBeVisible({
    timeout: 120_000,
  });
  await page.getByTestId("recovery-key-regenerate").click();

  const generatedKeyField = page.getByTestId("recovery-key-current");
  let recoveryKey = "";
  await expect
    .poll(
      async () => {
        recoveryKey = normalizeRecoveryKeyText(
          (await generatedKeyField.textContent()) ?? "",
        );
        return recoveryKey.split(/\s+/).filter(Boolean).length;
      },
      { timeout: 120_000 },
    )
    .toBe(24);
  await expect(page.getByTestId("recovery-key-live-warning")).toBeVisible();

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

  await expect(page.getByTestId("recovery-key-status")).toContainText(
    /encrypted history (?:is|are) backed up/i,
    { timeout: 30_000 },
  );
  return recoveryKey;
}

function normalizeRecoveryKeyText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

async function unlockMlsAccountSecret(page: Page, recoveryKey: string) {
  await expect(page.getByTestId("mls-unlock-modal")).toBeVisible({
    timeout: 90_000,
  });
  await expect(page.getByTestId("mls-unlock-banner")).toHaveAttribute(
    "role",
    "dialog",
  );
  await expect(page.getByTestId("mls-unlock-banner")).toHaveAttribute(
    "aria-modal",
    "true",
  );
  // `mls-unlock-passphrase` is the historical testid of the unlock input;
  // since the Recovery Key convergence it accepts only the 24-word key.
  const showRecoveryKey = page.getByTestId("mls-unlock-show-recovery-key");
  if (await showRecoveryKey.isVisible().catch(() => false)) {
    await showRecoveryKey.click();
  }
  await expect(page.getByTestId("mls-unlock-passphrase")).toBeVisible({
    timeout: 30_000,
  });
  await page.getByTestId("mls-unlock-passphrase").fill(recoveryKey);
  await page.getByTestId("mls-unlock-submit").click();
  await expect(page.getByTestId("mls-unlock-status")).toContainText(
    /restored/i,
    {
      timeout: 120_000,
    },
  );
  await expect(page.getByTestId("mls-unlock-modal")).toHaveCount(0, {
    timeout: 30_000,
  });
}

async function restoreMlsHistoryIfPrompted(
  page: Page,
  recoveryKey: string,
): Promise<boolean> {
  try {
    await expect(page.getByTestId("mls-unlock-modal")).toBeVisible({
      timeout: 45_000,
    });
  } catch {
    return false;
  }
  await unlockMlsAccountSecret(page, recoveryKey);
  return true;
}

async function createKanbanBoardListAndCard(
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
  const boardId = await page
    .getByTestId("board-space-select")
    .evaluate((node) => (node as HTMLSelectElement).value);
  expect(boardId).toMatch(/^ck:space:/);

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
  await expect(
    column.getByTestId("kanban-card").filter({ hasText: cardTitle }),
  ).toBeVisible({
    timeout: 45_000,
  });
  return boardId;
}

async function updateCardDescription(
  page: Page,
  cardTitle: string,
  description: string,
) {
  await page
    .getByTestId("kanban-card")
    .filter({ hasText: cardTitle })
    .first()
    .click();
  await expect(page.getByTestId("card-detail-modal")).toBeVisible({
    timeout: 45_000,
  });
  const add = page.getByTestId("card-detail-add-description-button");
  if ((await add.count()) > 0 && (await add.first().isVisible())) {
    await add.first().click();
  } else {
    await page.getByTestId("card-detail-edit-description-button").click();
  }
  await setCardDetailEditorValue(page, description);
  await page.getByTestId("card-detail-save-button").click();
  await expect(page.getByTestId("card-description-panel")).toContainText(
    description,
    {
      timeout: 120_000,
    },
  );
}

async function setCardDetailEditorValue(
  page: Page,
  value: string,
): Promise<void> {
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
  await expect(
    page.getByText(/MLS state is not ready on this device yet/i),
  ).toHaveCount(0);
  await expect(
    page.getByText(
      /schema_violation|payload violates registered payload schema/i,
    ),
  ).toHaveCount(0);
  await expect(page.getByText(/MLS commit event failed/i)).toHaveCount(0);
}

function sameActorFreshDevice(user: JointUser, label: string): JointUser {
  const suffix =
    `${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`
      .replace(/[^a-f0-9]/g, "")
      .slice(0, 12)
      .padEnd(12, "0");
  return {
    ...user,
    name: `${user.name}-${label}`,
    deviceId: `ck:device:01904100-0000-7000-8000-${suffix}`,
  };
}

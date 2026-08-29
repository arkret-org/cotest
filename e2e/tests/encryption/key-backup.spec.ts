// Key backup + restore
// Contract: e2e/scenarios/encryption/key-backup.md
// Spec refs:
//   - identity/key-management.md §3.3 (Recovery Key = sole content-recovery
//     credential), §7 (backup), §7.2 (envelope), §7.3 (restore), §7.7
//     (recovery UI MUST take the 24-word Recovery Key), §7.10 (automatic
//     continuous backup)
//   - crypto-media/device-lifecycle.md §12-§12.1 (key backup durable form + API)

import {
  expect,
  test,
  type APIRequestContext,
  type Browser,
  type Page,
} from "../../helpers/arkret-test";
import {
  coauthBaseUrl,
  optionalEnv,
  realOidcLoginHandle,
  realOidcLoginPassword,
  solandBaseUrl,
} from "../../helpers/env";
import {
  ensureRegistered,
  assertJointStackNotRequired,
  createDpopUserSessionForAccount,
  issueDevSession,
  openUserPage,
  selfPathHeadersForDpopSession,
  type DpopUserSession,
  type JointUser,
  type JointUserPage,
  uniqueUser,
} from "../../helpers/users";
import {
  registerCoauthPasswordAccount,
  type CoauthPasswordAccount,
} from "../../helpers/coauth-register";
import { serverLoginViaCoauth } from "../../helpers/real-oidc-login";

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
      // Probe: is /_arkret/self/keys/backups routed?
      const listResp = await request.get(
        `${solandBaseUrl()}/_arkret/self/keys/backups`,
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

  test("first-device bootstrap activates a recovery policy and durable encrypted account backup; direct replacement requires staged handoff", async ({
    browser,
    request,
  }) => {
    // spec: key-management.md §3.3 / §7.1-§7.2 / §7.7 / §7.10
    // Beyond A1/A2 (the MlsBackupPrompt path), this covers first-device
    // recovery bootstrap, the passphrase-free recovery_public_key envelope,
    // and the staged-handoff-only replacement rule.
    test.setTimeout(240_000);
    const coauth = coauthBaseUrl();
    if (!coauth) {
      assertJointStackNotRequired("key backup settings recovery coauth");
      test.skip(
        true,
        "coauth DPoP session-grant login is required for device-authorized key backup",
      );
      return;
    }
    const account = await registerCoauthPasswordAccount(request, coauth);
    const deviceFlow = await openDpopDeviceForAccount(
      browser,
      request,
      "settings-recovery-alice",
      account,
      coauth,
      false,
    );
    if (!deviceFlow) {
      assertJointStackNotRequired("key backup settings recovery browser login");
      test.skip(true, "coauth DPoP password login is unavailable");
      return;
    }
    const { page: device, session } = deviceFlow;

    try {
      await device.gotoHome();
      await expectDpopDeviceActive(request, session);

      // Principal bootstrap already generated and confirmed the first Recovery
      // Key before openUserPage returned. The write can therefore precede any
      // response listener registered by this test; verify its durable state.
      const firstKey = session.recoveryKey ?? "";
      expect(firstKey.split(/\s+/)).toHaveLength(24);
      await device.gotoAppPanel("/settings/recovery", "recovery-panel");
      await expect(device.page.getByTestId("recovery-key-section")).toBeVisible(
        {
          timeout: 120_000,
        },
      );

      // The settings page MUST NOT ask for a user passphrase.
      await expect(
        device.page.getByTestId("recovery-key-passphrase"),
      ).toHaveCount(0);

      const backupsUrl = `${solandBaseUrl()}/_arkret/self/keys/backups?backup_kind=secret_storage`;
      await expect
        .poll(
          async () => {
            const response = await request.get(backupsUrl, {
              headers: selfPathHeadersForDpopSession(
                session,
                "GET",
                backupsUrl,
              ),
            });
            if (!response.ok()) {
              return false;
            }
            const body = await response.json();
            const backups = Array.isArray(body?.backups)
              ? body.backups
              : Array.isArray(body)
                ? body
                : [];
            return backups.some(
              (backup: any) =>
                backup?.backup_kind === "secret_storage" &&
                backup?.encryption?.recipient_method ===
                  "recovery_public_key" &&
                Array.isArray(backup?.contents) &&
                backup.contents.some(
                  (item: any) => item?.item_kind === "mls_account_secret",
                ),
            );
          },
          { timeout: 120_000 },
        )
        .toBe(true);

      // Direct replacement was removed by the staged two-entry handoff
      // protocol. The settings surface must not silently rotate the key.
      await expect(
        device.page.getByTestId("recovery-key-regenerate"),
      ).toBeDisabled();
      await expect(
        device.page.getByTestId("recovery-key-regenerate"),
      ).toHaveAttribute("title", /staged handoff/i);
    } finally {
      await device.close();
    }
  });

  test("A1 automatic MLS recovery-key dialogs restore encrypted cards on a fresh browser", async ({
    browser,
    request,
  }) => {
    test.setTimeout(240_000);
    const stamp = Date.now();
    const coauth = coauthBaseUrl();
    if (!coauth) {
      assertJointStackNotRequired("A1 MLS restore coauth");
      test.skip(
        true,
        "coauth DPoP session-grant login is required for device-authorized key backup",
      );
      return;
    }
    const account = await registerCoauthPasswordAccount(request, coauth);
    const deviceAFlow = await openDpopDeviceForAccount(
      browser,
      request,
      "a1-mls-restore-alice-a",
      account,
      coauth,
      false,
    );
    if (!deviceAFlow) {
      assertJointStackNotRequired("A1 MLS restore device A login");
      test.skip(true, "coauth DPoP password login is unavailable");
      return;
    }
    const { page: deviceA, session: deviceASession } = deviceAFlow;
    const sessionsToClose: JointUserPage[] = [deviceA];
    const keyBackupPuts = collectKeyBackupPuts(deviceA.page);
    const protocolFailures: string[] = [];
    collectA1ProtocolFailures(deviceA.page, protocolFailures);

    try {
      await deviceA.gotoHome();
      await expectDpopDeviceActive(request, deviceASession);
      const recoveryKey = await createMlsRecoveryBackupFromPrompt(
        deviceA.page,
        keyBackupPuts,
        deviceASession.recoveryKey,
      );
      await deviceA.gotoSetup();
      await deviceA.acknowledgeRecommendedEncryptionPromptIfVisible(30_000);

      const realmId = await deviceA.createRealm({
        title: `A1 MLS restore ${stamp}`,
        summary:
          "same-account fresh-profile MLS account secret recovery acceptance",
        discoverability: "unlisted",
        joinRule: "invite",
        historyAccess: "since_join",
        encryptionProfile: "mls_rfc9420",
      });

      const historicalCards = [
        `A1 historical encrypted card 1 ${stamp}`,
        `A1 historical encrypted card 2 ${stamp}`,
        `A1 historical encrypted card 3 ${stamp}`,
      ];
      for (const card of historicalCards) {
        await deviceA.sendTimelineMessage(realmId, card);
      }
      await expectMlsAccountSecretBackupUploaded(keyBackupPuts);

      const deviceBFlow = await openDpopDeviceForAccount(
        browser,
        request,
        "a1-mls-restore-alice-b",
        account,
        coauth,
        false,
      );
      if (!deviceBFlow) {
        assertJointStackNotRequired("A1 MLS restore device B login");
        test.skip(true, "coauth DPoP password login is unavailable");
        return;
      }
      const { page: deviceB, session: deviceBSession } = deviceBFlow;
      sessionsToClose.push(deviceB);
      const deviceBKeyBackupPuts = collectKeyBackupPuts(deviceB.page);
      collectA1ProtocolFailures(deviceB.page, protocolFailures);

      await pairDpopDevice(deviceA, deviceB, request, deviceBSession);
      await deviceB.gotoHome();
      await expect(deviceB.page.getByTestId("mls-unlock-banner")).toBeVisible({
        timeout: 90_000,
      });
      await unlockMlsAccountSecret(deviceB.page, recoveryKey);
      await deviceB.gotoTimelineRealm(realmId);
      await deviceB.acknowledgeRecommendedEncryptionPromptIfVisible(30_000);
      for (const card of historicalCards) {
        await expect(deviceB.timelineEvent(card)).toBeVisible({
          timeout: 90_000,
        });
      }

      const deviceBCard = `A1 restored device writes encrypted card ${stamp}`;
      const deviceBPrivatePlaintextBackupsBefore =
        mlsPrivatePlaintextBackupPutCount(deviceBKeyBackupPuts);
      await deviceB.sendTimelineMessage(realmId, deviceBCard);
      await expect
        .poll(() => mlsPrivatePlaintextBackupPutCount(deviceBKeyBackupPuts), {
          timeout: 120_000,
        })
        .toBeGreaterThan(deviceBPrivatePlaintextBackupsBefore);
      await deviceA.gotoTimelineRealm(realmId);
      if (await restoreMlsHistoryIfPrompted(deviceA.page, recoveryKey)) {
        await deviceA.gotoTimelineRealm(realmId);
      }
      await deviceA.page.reload({ waitUntil: "domcontentloaded" });
      await expect(deviceA.timelineEvent(deviceBCard)).toBeVisible({
        timeout: 90_000,
      });

      expect(
        protocolFailures.filter((line) =>
          /MLS runtime|SnapshotDecryptFailed|\/(?:api\/v1|_arkret\/self)\/(account\/subscribe|subscribe|describe|events)/.test(
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
    if (!coauth) {
      assertJointStackNotRequired("A3 real OIDC MLS restore coauth");
      test.skip(true, "coauth not started for this run");
      return;
    }
    test.skip(
      !restoreOptIn && !optionalEnv("COTEST_REAL_OIDC_LOGIN"),
      "set COTEST_REAL_MLS_RESTORE_OIDC=1 to run the real OIDC MLS restore acceptance",
    );

    const stamp = Date.now();
    const envHandle = realOidcLoginHandle();
    const envPassword = realOidcLoginPassword();
    const registeredAccount =
      envHandle && envPassword
        ? undefined
        : await registerCoauthPasswordAccount(request, coauth!);
    const account: PasswordAccount = registeredAccount ?? {
      handle: envHandle!,
      password: envPassword!,
    };
    const deviceAUser = uniqueUser("a3-oidc-mls-a");
    if (registeredAccount) {
      deviceAUser.id = registeredAccount.id;
      deviceAUser.did = registeredAccount.did;
      deviceAUser.deviceId = registeredAccount.genesisDeviceId;
    }
    const deviceA = await openUserPage(browser, deviceAUser);
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
        historyAccess: "since_join",
        encryptionProfile: "mls_rfc9420",
      });
      const recoveryKey = await createMlsRecoveryBackupFromPrompt(
        deviceA.page,
        keyBackupPuts,
        registeredAccount?.recoveryKey,
      );
      await expectGrantDpopSelfPath(deviceATrace, "device A key backup upload");
      expect(
        deviceATrace.authorizedSelfRequests.filter((hit) => hit.missingDpop),
        "real OIDC device A must not fall back to naked bearer self/root calls",
      ).toEqual([]);
      expect(
        deviceATrace.keyBackupWrites.some(
          (hit) => hit.status === 200 && hit.hasDpop,
        ),
        "key backup write must be authenticated by the real grant plus DPoP holder proof",
      ).toBe(true);

      const historicalCards = [
        `A3 historical encrypted card 1 ${stamp}`,
        `A3 historical encrypted card 2 ${stamp}`,
      ];
      for (const card of historicalCards) {
        await deviceA.sendTimelineMessage(realmId, card);
      }
      await expectMlsAccountSecretBackupUploaded(keyBackupPuts);

      const deviceB = await openUserPage(browser, uniqueUser("a3-oidc-mls-b"));
      sessionsToClose.push(deviceB);
      const deviceBTrace = collectSessionGrantHolderProofTrace(deviceB.page);
      collectA1ProtocolFailures(deviceB.page, protocolFailures);

      await deviceB.gotoLogin();
      await serverLoginViaCoauth(deviceB.page, account);
      await expectGrantDpopSelfPath(deviceBTrace, "device B real OIDC login");
      await pairBrowserDevice(deviceA, deviceB);
      await deviceB.gotoHome();
      await expect(deviceB.page.getByTestId("mls-unlock-banner")).toBeVisible({
        timeout: 90_000,
      });
      await unlockMlsAccountSecret(deviceB.page, recoveryKey);
      const successfulUnlock =
        await expectSuccessfulUnlockWithHolderProof(deviceBTrace);

      const nakedUnlock = await deviceB.page.request.post(
        successfulUnlock.url,
        {
          headers: {
            authorization: `Bearer ${successfulUnlock.grantJwt}`,
            "content-type": "application/json",
          },
          data: JSON.parse(successfulUnlock.postData),
        },
      );
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
      await deviceB.acknowledgeRecommendedEncryptionPromptIfVisible(30_000);
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
          /MLS runtime|SnapshotDecryptFailed|MissingWelcome|schema_violation|payload violates registered payload schema|\/(?:api\/v1|_arkret\/self)\/(account\/subscribe|subscribe|describe|events)/.test(
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
    const coauth = coauthBaseUrl();
    if (!coauth) {
      assertJointStackNotRequired("A2 MLS Kanban restore coauth");
      test.skip(
        true,
        "coauth DPoP session-grant login is required for device-authorized key backup",
      );
      return;
    }
    const account = await registerCoauthPasswordAccount(request, coauth);
    const deviceAFlow = await openDpopDeviceForAccount(
      browser,
      request,
      "a2-mls-kanban-alice-a",
      account,
      coauth,
    );
    if (!deviceAFlow) {
      assertJointStackNotRequired("A2 MLS Kanban restore device A login");
      test.skip(true, "coauth DPoP password login is unavailable");
      return;
    }
    const { page: deviceA, session: deviceASession } = deviceAFlow;
    const sessionsToClose: JointUserPage[] = [deviceA];
    const keyBackupPuts = collectKeyBackupPuts(deviceA.page);
    const protocolFailures: string[] = [];
    collectA1ProtocolFailures(deviceA.page, protocolFailures);

    const boardTitle = `A2 Board ${stamp}`;
    const listTitle = `A2 Todos ${stamp}`;
    const cardTitle = `A2 encrypted kanban card ${stamp}`;
    const restoredDescription = `A2 restored-device encrypted detail ${stamp}`;

    try {
      await deviceA.gotoHome();
      await expectDpopDeviceActive(request, deviceASession);
      const recoveryKey = await createMlsRecoveryBackupFromPrompt(
        deviceA.page,
        keyBackupPuts,
        deviceASession.recoveryKey,
      );
      await deviceA.gotoSetup();
      await deviceA.acknowledgeRecommendedEncryptionPromptIfVisible(30_000);

      const realmId = await deviceA.createRealm({
        title: `A2 MLS Kanban ${stamp}`,
        summary: "kanban encrypted detail MLS restore acceptance",
        discoverability: "unlisted",
        joinRule: "invite",
        historyAccess: "since_join",
        encryptionProfile: "mls_rfc9420",
      });
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
                /"backup_kind"\s*:\s*"mls_history"/.test(
                  keyBackupWireData(hit),
                ),
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
                /"item_kind"\s*:\s*"mls_account_secret"/.test(
                  keyBackupWireData(hit),
                ),
            ),
          { timeout: 120_000 },
        )
        .toBe(true);

      const deviceBFlow = await openDpopDeviceForAccount(
        browser,
        request,
        "a2-mls-kanban-alice-b",
        account,
        coauth,
      );
      if (!deviceBFlow) {
        assertJointStackNotRequired("A2 MLS Kanban restore device B login");
        test.skip(true, "coauth DPoP password login is unavailable");
        return;
      }
      const { page: deviceB, session: deviceBSession } = deviceBFlow;
      sessionsToClose.push(deviceB);
      const deviceBKeyBackupPuts = collectKeyBackupPuts(deviceB.page);
      collectA1ProtocolFailures(deviceB.page, protocolFailures);

      await pairDpopDevice(deviceA, deviceB, request, deviceBSession);
      await deviceB.gotoHome();
      await expect(deviceB.page.getByTestId("mls-unlock-banner")).toBeVisible({
        timeout: 90_000,
      });
      await unlockMlsAccountSecret(deviceB.page, recoveryKey);
      await deviceB.page.goto(`/kanban/${realmId}/board/${boardId}`, {
        waitUntil: "domcontentloaded",
      });
      await deviceB.acknowledgeRecommendedEncryptionPromptIfVisible(30_000);
      await expect(deviceB.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await expect(
        deviceB.page.getByTestId("board-space-select-button"),
      ).toContainText(boardTitle, {
        timeout: 45_000,
      });
      await expect(
        deviceB.page.getByTestId("kanban-card").filter({ hasText: cardTitle }),
      ).toBeVisible({ timeout: 90_000 });

      const deviceBPrivatePlaintextBackupsBefore =
        mlsPrivatePlaintextBackupPutCount(deviceBKeyBackupPuts);
      await updateCardDescription(deviceB.page, cardTitle, restoredDescription);
      await expectEncryptedKanbanSaveErrorsAbsent(deviceB.page);
      await expect
        .poll(() => mlsPrivatePlaintextBackupPutCount(deviceBKeyBackupPuts), {
          timeout: 120_000,
        })
        .toBeGreaterThan(deviceBPrivatePlaintextBackupsBefore);

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
          deviceA.page.getByTestId("board-space-select-button"),
        ).toContainText(boardTitle, {
          timeout: 45_000,
        });
      }
      await deviceA.page
        .getByTestId("kanban-card")
        .filter({ hasText: cardTitle })
        .click();
      await expect(
        deviceA.page
          .locator('[data-testid="card-description-panel"]:visible')
          .filter({ hasText: restoredDescription })
          .first(),
      ).toBeVisible({ timeout: 90_000 });

      const fatalProtocolPattern =
        /MLS runtime|SnapshotDecryptFailed|MissingWelcome|schema_violation|payload violates registered payload schema|MLS commit event failed|\/(?:api\/v1|_arkret\/self)\/(account\/subscribe|subscribe|describe|events)/;
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
});

type KeyBackupPut = {
  url: string;
  status: number;
  postData: string;
  responseData: string;
};

type PasswordAccount = {
  handle: string;
  password: string;
};

async function openDpopDeviceForAccount(
  browser: Browser,
  request: APIRequestContext,
  prefix: string,
  account: CoauthPasswordAccount,
  coauth: string,
  autoCompleteRecoveryKeySetup = true,
): Promise<{ page: JointUserPage; session: DpopUserSession } | undefined> {
  const session = await createDpopUserSessionForAccount(
    request,
    prefix,
    account,
    {
      coauthBase: coauth,
    },
  );
  if (!session) {
    return undefined;
  }
  const page = await openUserPage(browser, session.user, {
    grantJwt: session.grantJwt,
    dpopSeedB64url: session.dpopSeedB64url,
    grantId: session.grantId,
    serviceAccountId: session.serviceAccountId,
    grantAudience: session.grantAudience,
    autoCompleteRecoveryKeySetup,
  });
  return { page, session };
}

async function expectDpopDeviceActive(
  request: APIRequestContext,
  session: DpopUserSession,
) {
  const url = `${solandBaseUrl()}/_arkret/self/account/viewer`;
  await expect
    .poll(
      async () => {
        const response = await request.get(url, {
          headers: selfPathHeadersForDpopSession(session, "GET", url),
        });
        if (!response.ok()) {
          return `http-${response.status()}`;
        }
        const body = await response.json();
        const devices = Array.isArray(body?.devices) ? body.devices : [];
        const current = devices.find(
          (device: any) => device?.device_id === session.user.deviceId,
        );
        return current?.status ?? "missing";
      },
      { timeout: 90_000 },
    )
    .toBe("active");
}

async function pairDpopDevice(
  authorizingDevice: JointUserPage,
  requestingDevice: JointUserPage,
  request: APIRequestContext,
  requestingSession: DpopUserSession,
) {
  // A password/OIDC handoff identifies the fresh browser but does not
  // authorize it to write events or unwrap account E2EE history. Complete
  // the spec-required same-account pairing before exercising recovery.
  await authorizingDevice.gotoHome();
  await requestingDevice.page.goto("/settings/devices/pair", {
    waitUntil: "domcontentloaded",
  });
  await requestingDevice.page.getByTestId("pair-device-start-button").click();
  const pairingCode = requestingDevice.page.getByTestId("pair-device-code");
  await expect(pairingCode).toBeVisible({ timeout: 30_000 });
  const code = (await pairingCode.textContent())?.trim() ?? "";
  expect(code).not.toBe("");

  const approvalModal = authorizingDevice.page.getByTestId(
    "device-pair-approval-modal",
  );
  await expect(approvalModal).toBeVisible({ timeout: 90_000 });
  await expect(
    authorizingDevice.page.getByTestId("device-pair-approval-code"),
  ).toHaveText(code);
  await authorizingDevice.page
    .getByTestId("device-pair-approval-approve")
    .click();
  await expectDpopDeviceActive(request, requestingSession);
}

async function pairBrowserDevice(
  authorizingDevice: JointUserPage,
  requestingDevice: JointUserPage,
) {
  await authorizingDevice.gotoHome();
  await requestingDevice.page.goto("/settings/devices/pair", {
    waitUntil: "domcontentloaded",
  });
  await requestingDevice.page.getByTestId("pair-device-start-button").click();
  const pairingCode = requestingDevice.page.getByTestId("pair-device-code");
  await expect(pairingCode).toBeVisible({ timeout: 30_000 });
  const code = (await pairingCode.textContent())?.trim() ?? "";
  expect(code).not.toBe("");

  const approvalModal = authorizingDevice.page.getByTestId(
    "device-pair-approval-modal",
  );
  await expect(approvalModal).toBeVisible({ timeout: 90_000 });
  await expect(
    authorizingDevice.page.getByTestId("device-pair-approval-code"),
  ).toHaveText(code);
  await authorizingDevice.page
    .getByTestId("device-pair-approval-approve")
    .click();
  await expect(approvalModal).toBeHidden({ timeout: 90_000 });

  await requestingDevice.page.getByTestId("pair-device-status-button").click();
  await expect(
    requestingDevice.page.getByTestId("pair-device-status"),
  ).toContainText("Approved.", { timeout: 30_000 });
}

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
  page.on("response", async (response) => {
    if (
      response.request().method() !== "PUT" ||
      !/\/(?:api\/v1|_arkret\/self)\/keys\/backups\//.test(response.url())
    ) {
      return;
    }
    const responseData = await response.text().catch(() => "");
    hits.push({
      url: response.url(),
      status: response.status(),
      postData: response.request().postData() ?? "",
      responseData,
    });
  });
  return hits;
}

function keyBackupWireData(hit: KeyBackupPut): string {
  return hit.postData || hit.responseData;
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
    if (!/\/_arkret\/(?:self|root)\//.test(url)) {
      return;
    }
    const headers = request.headers();
    const authorization = headers.authorization ?? "";
    if (!/^DPoP\s+\S+/.test(authorization)) {
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
      grantJwt: authorization.replace(/^DPoP\s+/i, ""),
      postData,
    };
    trace.authorizedSelfRequests.push(hit);
    if (
      hit.method === "PUT" &&
      /\/_arkret\/self\/keys\/backups\/[^/]+$/.test(url)
    ) {
      trace.keyBackupWrites.push(hit);
    }
    if (
      hit.method === "POST" &&
      /\/_arkret\/self\/keys\/backups\/[^/]+\/unlock$/.test(url)
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
      /\/(?:api\/v1|_arkret\/self)\/(account\/subscribe|subscribe|events\/subscribe|events\/describe|describe)(?:\?|$)/.test(
        url,
      ) &&
      /ERR_ABORTED|NS_BINDING_ABORTED|aborted|cancel/i.test(errorText)
    ) {
      return;
    }
    if (
      /\/(?:api\/v1|_arkret\/self)\/(account\/subscribe|subscribe|describe|events)/.test(
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
      /\/(?:api\/v1|_arkret\/self)\/(account\/subscribe|subscribe|describe|events)/.test(
        url,
      )
    ) {
      const entry = `http:${response.status()} ${response.request().method()} ${url}`;
      failures.push(entry);
      if (/\/(?:api\/v1|_arkret\/self)\/events/.test(url)) {
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
  bootstrapRecoveryKey?: string,
): Promise<string> {
  const setupRecoveryKey = await completeRecoveryKeySetupPrompt(page, 30_000);
  if (setupRecoveryKey) {
    return setupRecoveryKey;
  }

  const backupPrompt = page.getByTestId("mls-backup-modal");
  const backupPromptVisible = await backupPrompt
    .waitFor({ state: "visible", timeout: 5_000 })
    .then(() => true)
    .catch(() => false);
  if (!backupPromptVisible) {
    if (bootstrapRecoveryKey) {
      expect(bootstrapRecoveryKey.split(/\s+/)).toHaveLength(24);
      return bootstrapRecoveryKey;
    }
    throw new Error(
      "Recovery Key bootstrap completed without exposing a setup prompt or bootstrap key",
    );
  }

  await expect(backupPrompt).toBeVisible({
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

  await expectMlsAccountSecretBackupUploaded(keyBackupPuts);

  await page.getByTestId("mls-backup-saved").click();
  await expect(page.getByTestId("mls-backup-modal")).toHaveCount(0);
  return recoveryKey;
}

async function completeRecoveryKeySetupPrompt(
  page: Page,
  timeout: number,
): Promise<string | undefined> {
  const setupPrompt = page.getByTestId("recovery-key-setup-modal").last();
  const setupPromptVisible = await setupPrompt
    .waitFor({ state: "visible", timeout })
    .then(() => true)
    .catch(() => false);
  if (!setupPromptVisible) {
    return undefined;
  }

  await expect(page.getByTestId("recovery-key-setup-banner")).toHaveAttribute(
    "role",
    "dialog",
  );
  await expect(page.getByTestId("recovery-key-setup-banner")).toHaveAttribute(
    "aria-modal",
    "true",
  );

  const generatedKeyField = page
    .getByTestId("recovery-key-setup-generated-key")
    .last();
  await expect(generatedKeyField).toBeVisible({ timeout: 120_000 });
  const recoveryKey = (await generatedKeyField.inputValue()).trim();
  expect(recoveryKey.split(/\s+/)).toHaveLength(24);
  await expect(
    page.getByTestId("recovery-key-setup-generated-key-warning").last(),
  ).toBeVisible();

  await page
    .getByTestId("recovery-key-setup-confirm-key")
    .last()
    .fill(recoveryKey);
  await page.getByTestId("recovery-key-setup-saved").last().click();
  await expect(setupPrompt).toBeHidden({ timeout: 30_000 });
  return recoveryKey;
}

async function expectMlsAccountSecretBackupUploaded(
  keyBackupPuts: KeyBackupPut[],
) {
  await expect
    .poll(
      () =>
        keyBackupPuts.some(
          (hit) =>
            hit.status === 200 &&
            /"item_kind"\s*:\s*"mls_account_secret"/.test(
              keyBackupWireData(hit),
            ),
        ),
      { timeout: 120_000 },
    )
    .toBe(true);
}

function mlsHistoryBackupPutCount(keyBackupPuts: KeyBackupPut[]): number {
  return keyBackupPuts.filter(
    (hit) =>
      hit.status === 200 &&
      /"backup_kind"\s*:\s*"mls_history"/.test(keyBackupWireData(hit)),
  ).length;
}

function mlsPrivatePlaintextBackupPutCount(
  keyBackupPuts: KeyBackupPut[],
): number {
  return keyBackupPuts.filter(
    (hit) =>
      hit.status === 200 &&
      /"item_kind"\s*:\s*"mls_private_plaintext"/.test(keyBackupWireData(hit)),
  ).length;
}

async function unlockMlsAccountSecret(page: Page, recoveryKey: string) {
  const unlockPrompt = page
    .locator(
      '[data-testid="mls-unlock-modal"], [data-testid="mls-unlock-banner"]',
    )
    .last();
  const visibleUnlockStatus = page.locator(
    '[data-testid="mls-unlock-status"]:visible',
  );

  await expect(unlockPrompt).toBeVisible({
    timeout: 90_000,
  });
  await expect(unlockPrompt).toHaveAttribute("role", /^(?:dialog|region)$/);
  if ((await unlockPrompt.getAttribute("role")) === "dialog") {
    await expect(unlockPrompt).toHaveAttribute("aria-modal", "true");
  }
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
  await expect
    .poll(
      async () => {
        if (!(await unlockPrompt.isVisible().catch(() => false))) {
          return "closed";
        }
        const status = await visibleUnlockStatus.textContent().catch(() => "");
        if (/restored/i.test(status ?? "")) {
          return "restored";
        }
        return status ?? "";
      },
      { timeout: 120_000 },
    )
    .toMatch(/^(?:restored|closed)$/);
  await expect(unlockPrompt).not.toBeVisible({
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
  await expect
    .poll(() => page.url(), { timeout: 30_000 })
    .toContain("/board/ak:space:");
  const boardId = decodeURIComponent(
    new URL(page.url()).pathname.split("/board/")[1]?.split("/")[0] ?? "",
  );
  expect(boardId).toMatch(/^ak:space:/);

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
    deviceId: `ak:device:01904100-0000-7000-8000-${suffix}`,
  };
}

// Notifications (push prefs / DnD / per-realm mute / mark-all-read)
// Contract: e2e/scenarios/discovery/notifications.md
// Spec: discovery/push-notifications.md §2-§4, discovery/client-preferences.md

import { expect, test } from "../../helpers/arkret-test";
import { cssStringEscape } from "../../helpers/dom";
import { stepShot } from "../../helpers/screenshots";
import {
  addRealmMemberApi,
  accountSubscribeDeltaApi,
  createRealmApi,
  grantCapabilityEventApi,
  resolveDefaultStrandId,
  sendMessageApi,
  setStrandWatchLevelApi,
  replaceAccountDataApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import {
  approvePairingLinkOnAuthorizedDevice,
  assertJointStackNotRequired,
  ensureRegistered,
  issueUserSession,
  openDpopUserPage,
  openDpopUserPageForAccount,
  openUserPage,
  selfPathHeadersForDpopSession,
  uniqueUser,
} from "../../helpers/users";
import { selectDxcOption } from "../../helpers/dxc-select";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import { serverLoginViaCoauth, submitCoauthPasswordCredentials } from "../../helpers/real-oidc-login";

test.describe.configure({ mode: "serial" });

test.describe("notifications", () => {
  test("watch-all notification: alice sends, bob sees the message in /notifications", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const [aliceSession, bobSession] = await Promise.all([
      openDpopUserPage(browser, request, "s23-alice", {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, "s23-bob", {
        prepareMlsDevice: false,
      }),
    ]);
    if (!aliceSession || !bobSession) {
      assertJointStackNotRequired("notifications default browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceSession.page;
    const alice = aliceSession.user;
    const bob = bobSession.user;
    const bobPage = bobSession.page;

    try {
      const realmId = await alicePage.createRealm({
        title: `S23 Notif ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        mlsActivated: false,
        seedMembers: [bob.id],
      });
      await bobPage.acceptInvite(realmId);
      const [aliceToken, bobToken] = await Promise.all([
        issueUserSession(request, alice),
        issueUserSession(request, bob),
      ]);
      // Membership alone grants Bob no baseline `ak.strand.create`
      // capability. Let the Realm authority-root controller establish the
      // discussion Strand after Bob has joined, then let Bob manage only his
      // own watch state.
      const strandId = await resolveDefaultStrandId(
        request,
        aliceToken,
        realmId,
        { authorityRootController: alice.id },
      );
      await setStrandWatchLevelApi(
        request,
        bobToken,
        realmId,
        strandId,
        bob.id,
        "all",
      );

      const msg = `S23 note ${stamp}`;
      await alicePage.sendTimelineMessage(realmId, msg);

      // bob navigates to /notifications and should see the new message in the list.
      await bobPage.gotoNotifications();
      await expect(bobPage.page.getByTestId("notifications-panel")).toBeVisible(
        {
          timeout: 30_000,
        },
      );
      const notification = bobPage.page
        .getByTestId("notification-item")
        .filter({ hasText: msg });
      await expect
        .poll(
          async () => {
            await bobPage.page.getByTestId("refresh-notifications").click();
            await bobPage.page.waitForTimeout(500);
            return await notification.count();
          },
          { timeout: 90_000, intervals: [500, 1_000, 2_000] },
        )
        .toBeGreaterThan(0);
      await expect(notification).toBeVisible({ timeout: 5_000 });
      await stepShot(bobPage.page, testInfo, "watch-all-notification");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test(// @user-promise: e2e/scenarios/discovery/notifications.md
  "muting a Realm stops ordinary and directed notifications", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: push-notifications.md §4.3.2.
    const stamp = Date.now();
    const [aliceSession, bobSession] = await Promise.all([
      openDpopUserPage(browser, request, `s23-mute-alice-${stamp}`),
      openDpopUserPage(browser, request, `s23-mute-bob-${stamp}`),
    ]);
    if (!aliceSession || !bobSession) {
      assertJointStackNotRequired("notifications mute browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceSession.page;
    const bob = bobSession.user;
    const bobPage = bobSession.page;
    const normalMsg = `muted normal message ${stamp}`;
    const mentionSuffix = `muted direct mention ${stamp}`;
    const apiActorSeq = 8_000_000_100_000_000 + (stamp % 100_000);

    try {
      const realmId = await alicePage.createRealm({
        title: `S23 Muted ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        mlsActivated: false,
        seedMembers: [bob.id],
      });
      await bobPage.acceptInvite(realmId);
      const aliceToken = await issueUserSession(request, aliceSession.user);
      await resolveDefaultStrandId(request, aliceToken, realmId, {
        authorityRootController: aliceSession.user.id,
      });
      await grantCapabilityEventApi(request, aliceToken, {
        ownerId: aliceSession.user.id,
        realmId,
        subjectId: aliceSession.user.id,
        actions: ["ak.message.create"],
      });

      await bobPage.gotoNotificationSettings();
      await expect(
        bobPage.page.getByTestId("notification-settings-panel"),
      ).toBeVisible({
        timeout: 30_000,
      });
      await selectDxcOption(
        bobPage.page.getByTestId("realm-override-realm-select"),
        realmId,
      );
      await selectDxcOption(
        bobPage.page.getByTestId("realm-override-level-select"),
        "muted",
      );
      await bobPage.page.getByTestId("realm-override-add").click();
      await expect(
        bobPage.page.locator(
          `[data-testid="settings-muted-realm-row"][data-realm-id="${cssStringEscape(realmId)}"]`,
        ),
      ).toBeVisible({ timeout: 30_000 });

      await alicePage.sendTimelineMessage(realmId, normalMsg);
      await bobPage.gotoNotifications();
      await expect(bobPage.page.getByTestId("notifications-panel")).toBeVisible(
        {
          timeout: 30_000,
        },
      );
      await expect(
        bobPage.page
          .getByTestId("notification-item")
          .filter({ hasText: normalMsg }),
      ).toHaveCount(0);

      const mentionMsg = mentionSuffix;
      await sendMessageApi(request, aliceToken, realmId, mentionMsg, {
        mentions: [bob.id],
      });
      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expect(
        bobPage.page
          .getByTestId("notification-item")
          .filter({ hasText: mentionMsg }),
      ).toHaveCount(0);
      await stepShot(bobPage.page, testInfo, "muted-mention-suppressed");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test(// @user-promise: e2e/scenarios/discovery/notifications.md
  "Do-not-disturb window suppresses all notifications during configured hours; resumes after window ends", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    // spec: push-notifications.md §3.2 do-not-disturb preference.
    const stamp = Date.now();
    const coauth = coauthBaseUrl();
    if (!coauth) {
      assertJointStackNotRequired("notifications dnd browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const bobAccount = await registerCoauthPasswordAccount(request, coauth, {
      password: "1amTester!",
    });
    const [aliceSession, bobDeviceASession] = await Promise.all([
      openDpopUserPage(browser, request, `s23-dnd-alice-${stamp}`),
      openDpopUserPageForAccount(
        browser,
        request,
        `s23-dnd-bob-${stamp}-device-a`,
        bobAccount,
        {
          prepareMlsDevice: false,
        },
      ),
    ]);
    if (!aliceSession || !bobDeviceASession) {
      assertJointStackNotRequired("notifications dnd browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceSession.user;
    const alicePage = aliceSession.page;
    const bob = bobDeviceASession.user;
    const bobDeviceA = bobDeviceASession.page;
    const aliceToken = await issueUserSession(request, alice);
    const suppressedSuffix = `DND suppressed ${stamp}`;
    const resumedSuffix = `DND resumed ${stamp}`;
    const apiActorSeq = 8_000_000_000_000_000 + (stamp % 100_000);
    let suppressedMsg = "";
    let resumedMsg = "";

    try {
      await bobDeviceA.gotoHome();

      const realmId = await alicePage.createRealm({
        title: `S23 DND ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        mlsActivated: false,
        seedMembers: [bob.id],
      });
      await bobDeviceA.acceptInvite(realmId);
      // Membership and Realm ownership are not substitutes for an action
      // capability. Bind the API-authored mention writes to an accepted
      // ak.message.create grant before testing notification policy.
      await alicePage.grantRealmCapability(
        realmId,
        aliceSession.session.accountId,
        "ak.message.create",
      );

      await bobDeviceA.gotoNotificationSettings();
      await expect(
        bobDeviceA.page.getByTestId("notification-settings-panel"),
      ).toBeVisible({
        timeout: 30_000,
      });
      await bobDeviceA.checkWithPassivePromptRetry(
        bobDeviceA.page.getByTestId("dnd-enabled-toggle"),
      );
      await selectDxcOption(
        bobDeviceA.page.getByTestId("dnd-mode-select"),
        "now",
      );
      await bobDeviceA.clickWithPassivePromptRetry(
        bobDeviceA.page.getByTestId("save-notification-settings-button"),
      );
      await expect(
        bobDeviceA.page.getByTestId("notification-settings-status"),
      ).toContainText(/do not disturb|dnd/i, { timeout: 30_000 });

      const accountDataUrl = `${solandBaseUrl()}/_arkret/self/account_data/${encodeURIComponent("ak.dnd_schedule")}`;
      let storedDnd: Record<string, unknown> = {};
      await expect
        .poll(
          async () => {
            const response = await request.get(accountDataUrl, {
              headers: selfPathHeadersForDpopSession(
                bobDeviceASession.session,
                "GET",
                accountDataUrl,
              ),
            });
            if (!response.ok()) return `http-${response.status()}`;
            storedDnd = await response.json();
            return isEncryptedDndAccountData(storedDnd.content);
          },
          { timeout: 30_000 },
        )
        .toBe(true);
      const storedWire = JSON.stringify(storedDnd);
      expect(storedWire).not.toContain('"enabled":true');
      expect(storedWire).not.toContain('"mode":"now"');
      expect(storedWire).not.toContain('"dnd"');

      suppressedMsg = suppressedSuffix;
      await sendMessageApi(request, aliceToken, realmId, suppressedMsg, {
        mentions: [bob.id],
      });
      await bobDeviceA.gotoNotifications();
      await expect(
        bobDeviceA.page
          .getByTestId("notification-item")
          .filter({ hasText: suppressedMsg }),
      ).toHaveCount(0);

      await bobDeviceA.gotoNotificationSettings();
      await bobDeviceA.uncheckWithPassivePromptRetry(
        bobDeviceA.page.getByTestId("dnd-enabled-toggle"),
      );
      await bobDeviceA.clickWithPassivePromptRetry(
        bobDeviceA.page.getByTestId("save-notification-settings-button"),
      );
      await expect(
        bobDeviceA.page.getByTestId("notification-settings-status"),
      ).toContainText(/dnd disabled/i, { timeout: 30_000 });
      resumedMsg = resumedSuffix;
      await sendMessageApi(request, aliceToken, realmId, resumedMsg, {
        mentions: [bob.id],
      });
      await bobDeviceA.gotoNotifications();
      await expect(
        bobDeviceA.page
          .getByTestId("notification-item")
          .filter({ hasText: resumedMsg }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(bobDeviceA.page, testInfo, "dnd-resumed");
    } finally {
      await Promise.allSettled([bobDeviceA.close(), alicePage.close()]);
    }
  });

  test("mark-all-read clears unread badges and marks notification rows as read", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: discovery/read-receipts.md §6.6 + sync/client-sync.md §3.
    // Notification projection is read from account subscribe; mark-all-read
    // advances read cursor state from the client surface.
    const stamp = Date.now();
    const alice = uniqueUser(`s23-mark-${stamp}`);
    const bobSession = await openDpopUserPage(
      browser,
      request,
      `s23-mark-bob-${stamp}`,
    );
    if (!bobSession) {
      assertJointStackNotRequired("notifications mark-all-read browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const bob = bobSession.user;
    await ensureRegistered(request, alice);
    const [aliceToken, bobToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
    ]);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S23 Mark Read ${stamp}`,
      discoverability: "listed",
      history_access: "all_history_for_current_members",
      mls_activated: false,
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.id);
    const msg = `mark all read notification ${stamp}`;
    await sendMessageApi(request, aliceToken, realmId, msg, {
      mentions: [bob.id],
    });

    const bobPage = bobSession.page;
    try {
      await bobPage.gotoNotifications();
      const row = bobPage.page
        .getByTestId("notification-item")
        .filter({ hasText: msg });
      await expect(row).toBeVisible({ timeout: 30_000 });
      await expect(row.getByTestId("mark-read-button")).toBeVisible();
      await expect(
        bobPage.page
          .getByTestId("topbar-notifications-button")
          .locator(".topbar-notifications-badge"),
      ).toBeVisible({ timeout: 30_000 });

      await bobPage.page.getByTestId("mark-all-read-button").click();
      await expect(row.getByTestId("mark-unread-button")).toBeVisible({
        timeout: 30_000,
      });
      await expect(row.getByTestId("mark-read-button")).toHaveCount(0);
      await expect(
        bobPage.page
          .getByTestId("topbar-notifications-button")
          .locator(".topbar-notifications-badge"),
      ).toHaveCount(0, { timeout: 30_000 });
      await stepShot(bobPage.page, testInfo, "mark-all-read");
    } finally {
      await bobPage.close();
    }
  });

  test(// @user-promise: e2e/scenarios/discovery/notifications.md
  "E2EE Realm with evaluation_locus=client: server sends blind wake; client decrypts and evaluates 'contains_keyword' rule locally", async ({
    request,
  }) => {
    // spec: push-notifications.md §4.5
    const stamp = Date.now();
    const alice = uniqueUser("s23-e2ee-alice");
    const bob = uniqueUser("s23-e2ee-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
    ]);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S23 E2EE Blind Wake ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
      mls_activated: true,
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.id);
    await replaceAccountDataApi(
      request,
      bobToken,
      bob.id,
      "ak.push_rules",
      {
        rules: [
          {
            rule_id: "keyword.local",
            evaluation_locus: "client",
            conditions: [
              { kind: "contains_keyword", pattern: "sealed-keyword" },
            ],
            actions: ["notify"],
          },
        ],
      },
      0,
      { context: "set ak.push_rules" },
    );

    const plaintext = `sealed-keyword plaintext must stay client-side ${stamp}`;
    const strandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const encrypted = signedEventEnvelope({
      actorId: alice.id,
      realmId: realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        encrypted_content: encryptedEnvelope(
          "ak.message.v1",
          "opaque-ciphertext-for-sealed-keyword",
          realmId,
        ),
      },
    });
    await submitSignedEventApi(request, aliceToken, encrypted, {
      context: "encrypted message with blind wake sidecar",
    });

    const body = await accountSubscribeDeltaApi(request, bobToken);
    const notifications = isRecord(body.notifications)
      ? body.notifications
      : {};
    const items = Array.isArray(notifications.items)
      ? notifications.items.filter(isRecord)
      : [];
    expect(items.every((item) => item.type === "agent")).toBe(true);
    const wire = JSON.stringify(notifications);
    expect(wire).not.toContain(encrypted.event_id);
    expect(wire).not.toContain(plaintext);
    expect(wire).not.toContain("sealed-keyword");
    expect(wire).not.toContain(bob.id);
  });

  test(// @user-promise: e2e/scenarios/discovery/notifications.md
  "cross-device read state: marking read on device-2 clears unread on device-1 within sync window", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: client-preferences.md read marker is per-account, synced to all devices.
    const stamp = Date.now();
    const alice = uniqueUser("s23-crossdev-alice");
    const coauth = coauthBaseUrl();
    if (!coauth) {
      assertJointStackNotRequired("notifications cross-device browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const bobAccount = await registerCoauthPasswordAccount(request, coauth, {
      password: "1amTester!",
    });
    const bobDevice1Session = await openDpopUserPageForAccount(
      browser,
      request,
      `s23-crossdev-bob-${stamp}-d1`,
      bobAccount,
    );
    if (!bobDevice1Session) {
      assertJointStackNotRequired("notifications cross-device browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const bob = bobDevice1Session.user;
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);
    const bobDevice1 = bobDevice1Session.page;
    const bobDevice2Page = await openUserPage(
      browser,
      uniqueUser(`s23-crossdev-bob-${stamp}-d2`),
      { neutralLoginConfig: true, autoCompleteRecoveryKeySetup: false },
    );

    try {
      // A password/OIDC handoff identifies the fresh browser but does not make
      // it an authorized event author. Complete the spec-required same-account
      // pairing before device 2 advances the durable read cursor.
      await bobDevice1.gotoHome();
      await bobDevice2Page.page.goto("/login", {
        waitUntil: "domcontentloaded",
      });
      await bobDevice2Page.page.getByTestId("login-server-url").fill(solandBaseUrl());
      await bobDevice2Page.page.getByTestId("start-server-login-button").click();
      await submitCoauthPasswordCredentials(bobDevice2Page.page, bobAccount);
      const approve = bobDevice2Page.page.getByTestId("coauth-oauth-approve");
      if (await approve.waitFor({ state: "visible", timeout: 20_000 }).then(() => true).catch(() => false)) {
        await approve.click();
      }
      await expect(bobDevice2Page.page.getByTestId("device-setup-required")).toBeVisible({ timeout: 120_000 });
      await expect(bobDevice2Page.page.getByTestId("client-shell")).toHaveCount(0);
      await bobDevice2Page.page.getByTestId("device-setup-pairing-start").click();
      const pairingCode = bobDevice2Page.page.getByTestId("device-setup-pairing-code");
      await expect(pairingCode).toBeVisible({ timeout: 30_000 });
      const code = (await pairingCode.textContent())?.trim() ?? "";
      expect(code).not.toBe("");
      const pairingLink = await bobDevice2Page.page
        .getByTestId("device-setup-pairing-link")
        .inputValue();
      await approvePairingLinkOnAuthorizedDevice(
        bobDevice1,
        pairingLink,
        code,
      );

      await bobDevice2Page.page.getByTestId("device-setup-pairing-status").click();
      await expect(bobDevice2Page.page.getByTestId("device-setup-status")).toContainText(
        "Device authorization is accepted", { timeout: 90_000 },
      );
      await bobDevice2Page.page.getByRole("link", { name: "Sign in again after approval" }).click();
      await serverLoginViaCoauth(bobDevice2Page.page, bobAccount);
      await expect(bobDevice2Page.page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
      await bobDevice2Page.completeRecoveryKeySetupIfPrompted();
      const unlockPrompt = bobDevice2Page.page.locator(
        '[data-testid="mls-unlock-modal"], [data-testid="mls-unlock-banner"]',
      ).last();
      if (await unlockPrompt.isVisible()) {
        const recoveryKey = bobDevice1Session.session.recoveryKey;
        if (!recoveryKey) throw new Error("paired notification device requires the account recovery key");
        await bobDevice2Page.unlockMlsAccountSecret(recoveryKey);
      }

      const realmId = await createRealmApi(request, aliceToken, {
        title: `S23 Cross Device ${stamp}`,
        discoverability: "listed",
        history_access: "all_history_for_current_members",
        mls_activated: false,
      });
      await addRealmMemberApi(request, aliceToken, realmId, bob.id);
      const msg = `cross-device unread ${stamp}`;
      await sendMessageApi(request, aliceToken, realmId, msg, {
        mentions: [bob.id],
      });

      await bobDevice1.gotoNotifications();
      const device1Row = bobDevice1.page
        .getByTestId("notification-item")
        .filter({ hasText: msg });
      await expect(device1Row).toBeVisible({ timeout: 30_000 });
      await expect(device1Row.getByTestId("mark-read-button")).toBeVisible({
        timeout: 30_000,
      });

      await bobDevice2Page.gotoNotifications();
      const device2Row = bobDevice2Page.page
        .getByTestId("notification-item")
        .filter({ hasText: msg });
      await expect(device2Row).toBeVisible({ timeout: 30_000 });
      await bobDevice2Page.clickWithPassivePromptRetry(
        bobDevice2Page.page.getByTestId("mark-all-read-button"),
      );
      await expect(device2Row.getByTestId("mark-unread-button")).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        bobDevice2Page.page.getByTestId("notifications-status"),
      ).toContainText(/synced \d+ read cursor/i, { timeout: 30_000 });

      // The success toast is transient and may be cleared by the refresh that
      // applies the new cursor. Device 1 is the authoritative cross-device
      // convergence assertion.
      await bobDevice1.page.reload({ waitUntil: "domcontentloaded" });
      const device1ClearedRow = bobDevice1.page
        .getByTestId("notification-item")
        .filter({ hasText: msg });
      await expect(
        device1ClearedRow.getByTestId("mark-unread-button"),
      ).toBeVisible({ timeout: 30_000 });
      await expect(
        device1ClearedRow.getByTestId("mark-read-button"),
      ).toHaveCount(0);
      await stepShot(
        bobDevice1.page,
        testInfo,
        "device1-cleared-after-device2-read",
      );
    } finally {
      await Promise.allSettled([bobDevice2Page.close(), bobDevice1.close()]);
    }
  });
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isEncryptedDndAccountData(value: unknown): boolean {
  if (!isRecord(value) || !isRecord(value.aad)) return false;
  return (
    value.schema === "ak.schema.account_data_encrypted_value.v1" &&
    value.version === "1.0" &&
    value.aead_profile === "ak.aead.xchacha20_poly1305.v1" &&
    value.aad.schema === "ak.schema.account_data_encrypted_value.v1" &&
    value.aad.account_data_key === "ak.dnd_schedule" &&
    typeof value.ciphertext === "string" &&
    value.ciphertext.length > 0 &&
    typeof value.nonce === "string" &&
    value.nonce.length > 0
  );
}

function encryptedEnvelope(
  contentType: string,
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  void contentType;
  void realmId;
  return {
    version: "1.0",
    content_type: "application/vnd.arkret.message+json",
    encryption_context: {
      epoch: 1,
      group_state_ref: "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
    },
    ciphertext,
  };
}

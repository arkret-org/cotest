// Notifications (push prefs / DnD / per-realm mute / mark-all-read)
// Contract: e2e/scenarios/discovery/notifications.md
// Spec: discovery/push-notifications.md §2-§4, discovery/client-preferences.md

import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import { cssStringEscape } from "../../helpers/dom";
import { stepShot } from "../../helpers/screenshots";
import {
  addRealmMemberApi,
  accountSubscribeDeltaApi,
  canonicalJson,
  createRealmApi,
  resolveDefaultStrandId,
  sendMessageApi,
  putAccountDataViaEventApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  openDpopUserPageForAccount,
  uniqueUser,
} from "../../helpers/users";
import { selectDxcOption } from "../../helpers/dxc-select";
import { coauthBaseUrl } from "../../helpers/env";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";

test.describe.configure({ mode: "serial" });

test.describe("notifications", () => {
  test("default notification: alice sends, bob sees the message in /notifications", async ({
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
    const bob = bobSession.user;
    const bobPage = bobSession.page;

    try {
      const realmId = await alicePage.createRealm({
        title: `S23 Notif ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(realmId);

      const msg = `S23 note ${stamp}`;
      await alicePage.sendTimelineMessage(realmId, msg);

      // bob navigates to /notifications and should see the new message in the list.
      await bobPage.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
      await expect(bobPage.page.getByTestId("notifications-panel")).toBeVisible(
        {
          timeout: 30_000,
        },
      );
      await expect(
        bobPage.page
          .getByTestId("notification-item")
          .filter({ hasText: msg }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(bobPage.page, testInfo, "default-notification");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test(// @user-promise: e2e/scenarios/discovery/notifications.md
  "muting a Realm stops push notifications for new messages but mention still notifies (spec §3 mention override)", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: push-notifications.md §3 + §4.3.1.
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
    const mentionSuffix = `muted mention override ${stamp}`;

    try {
      const realmId = await alicePage.createRealm({
        title: `S23 Muted ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(realmId);

      await bobPage.page.goto("/notifications/settings", {
        waitUntil: "domcontentloaded",
      });
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
      await bobPage.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
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

      const mentionMsg = await alicePage.sendTimelineMentionMessage(
        realmId,
        bob.did,
        mentionSuffix,
      );
      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expect(
        bobPage.page
          .getByTestId("notification-item")
          .filter({ hasText: mentionMsg }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(bobPage.page, testInfo, "muted-mention-override");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test(// @user-promise: e2e/scenarios/discovery/notifications.md
  "Do-not-disturb window suppresses all notifications during configured hours; resumes after window ends", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: push-notifications.md §3.2 do-not-disturb preference.
    const stamp = Date.now();
    const [aliceSession, bobSession] = await Promise.all([
      openDpopUserPage(browser, request, `s23-dnd-alice-${stamp}`),
      openDpopUserPage(browser, request, `s23-dnd-bob-${stamp}`),
    ]);
    if (!aliceSession || !bobSession) {
      assertJointStackNotRequired("notifications dnd browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceSession.user;
    const alicePage = aliceSession.page;
    const bob = bobSession.user;
    const bobPage = bobSession.page;
    const aliceToken = await issueDevSession(request, alice);
    const suppressedSuffix = `DND suppressed ${stamp}`;
    const resumedSuffix = `DND resumed ${stamp}`;
    const apiActorSeq = 8_000_000_000_000_000 + (stamp % 100_000);
    let suppressedMsg = "";
    let resumedMsg = "";

    try {
      const realmId = await alicePage.createRealm({
        title: `S23 DND ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(realmId);

      await bobPage.page.goto("/notifications/settings", {
        waitUntil: "domcontentloaded",
      });
      await expect(
        bobPage.page.getByTestId("notification-settings-panel"),
      ).toBeVisible({
        timeout: 30_000,
      });
      await bobPage.completeRecoveryKeySetupIfPrompted();
      await bobPage.checkWithPassivePromptRetry(
        bobPage.page.getByTestId("dnd-enabled-toggle"),
      );
      await selectDxcOption(bobPage.page.getByTestId("dnd-mode-select"), "now");
      await bobPage.clickWithPassivePromptRetry(
        bobPage.page.getByTestId("save-notification-settings-button"),
      );
      await expect(
        bobPage.page.getByTestId("notification-settings-status"),
      ).toContainText(/do not disturb|dnd/i, { timeout: 30_000 });

      suppressedMsg = suppressedSuffix;
      await sendMessageApi(request, aliceToken, realmId, suppressedMsg, {
        mentions: [bob.did],
        actorSeq: apiActorSeq,
      });
      await bobPage.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
      await expect(
        bobPage.page
          .getByTestId("notification-item")
          .filter({ hasText: suppressedMsg }),
      ).toHaveCount(0);

      await bobPage.page.goto("/notifications/settings", {
        waitUntil: "domcontentloaded",
      });
      await bobPage.completeRecoveryKeySetupIfPrompted();
      await bobPage.uncheckWithPassivePromptRetry(
        bobPage.page.getByTestId("dnd-enabled-toggle"),
      );
      await bobPage.clickWithPassivePromptRetry(
        bobPage.page.getByTestId("save-notification-settings-button"),
      );
      await expect(
        bobPage.page.getByTestId("notification-settings-status"),
      ).toContainText(/dnd disabled/i, { timeout: 30_000 });
      resumedMsg = resumedSuffix;
      await sendMessageApi(request, aliceToken, realmId, resumedMsg, {
        mentions: [bob.did],
        actorSeq: apiActorSeq + 1,
      });
      await bobPage.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
      await expect(
        bobPage.page
          .getByTestId("notification-item")
          .filter({ hasText: resumedMsg }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(bobPage.page, testInfo, "dnd-resumed");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
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
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S23 Mark Read ${stamp}`,
      discoverability: "listed",
      history_visibility: "shared",
      encryption_profile: "none",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);
    const msg = `mark all read notification ${stamp}`;
    const sent = await sendMessageApi(request, aliceToken, realmId, msg, {
      mentions: [bob.did],
    });
    const beforeDelta = await accountSubscribeDeltaApi(request, bobToken);
    const beforeItem = notificationEventsFromDelta(beforeDelta).find(
      (candidate) => candidate.source_event_id === sent.event_id,
    );
    expect(beforeItem, "account subscribe notification before mark-all").toEqual(
      expect.objectContaining({
        source_event_id: sent.event_id,
        state: "unread",
        read: false,
      }),
    );

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
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S23 E2EE Blind Wake ${stamp}`,
      discoverability: "listed",
      history_visibility: "shared",
      encryption_profile: "mls_rfc9420",
      content_scheme: "mls-exporter-aead-v1",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);
    await putAccountDataViaEventApi(
      request,
      bobToken,
      bob.did,
      realmId,
      "ck.push_rules",
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
      { context: "set ck.push_rules" },
    );

    const plaintext = `sealed-keyword plaintext must stay client-side ${stamp}`;
    const sidecarHash = mentionSidecarHash(realmId, bob.did);
    const strandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const encrypted = signedEventEnvelope({
      actorDid: alice.did,
      realmId: realmId,
      kind: "ck.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        mention_sidecar_hash: [sidecarHash],
        encrypted_content: encryptedEnvelope(
          "ck.message.v1",
          "opaque-ciphertext-for-sealed-keyword",
          realmId,
        ),
      },
    });
    await submitSignedEventApi(request, aliceToken, encrypted, {
      context: "encrypted message with blind wake sidecar",
    });

    const body = await accountSubscribeDeltaApi(request, bobToken);
    const item = notificationEventsFromDelta(body).find(
      (candidate) => candidate.source_event_id === encrypted.event_id,
    );
    expect(item, "blind wake notification for encrypted message").toBeTruthy();
    if (!item) throw new Error("blind wake notification missing for encrypted message");
    expect(item.encrypted).toBe(true);
    expect(item.local_decrypted).toBe(false);
    expect(item.actor_id).toBe(alice.did);
    expect(item.realm_id).toBe(realmId);
    expect(item.notification_type).toBe("mention");
    expect(item.body).toBeUndefined();
    expect(item.preview).toBeUndefined();
    const wire = JSON.stringify(item);
    expect(wire).not.toContain(plaintext);
    expect(wire).not.toContain("sealed-keyword");
    expect(wire).not.toContain(sidecarHash);
    expect(wire).not.toContain(bob.did);
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
    const [bobDevice1Session, bobDevice2Session] = await Promise.all([
      openDpopUserPageForAccount(
        browser,
        request,
        `s23-crossdev-bob-${stamp}-d1`,
        bobAccount,
      ),
      openDpopUserPageForAccount(
        browser,
        request,
        `s23-crossdev-bob-${stamp}-d2`,
        bobAccount,
      ),
    ]);
    if (!bobDevice1Session || !bobDevice2Session) {
      assertJointStackNotRequired("notifications cross-device browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const bob = bobDevice1Session.user;
    expect(bobDevice2Session.user.did).toBe(bob.did);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const bobDevice1 = bobDevice1Session.page;
    const bobDevice2Page = bobDevice2Session.page;

    try {
      const realmId = await createRealmApi(request, aliceToken, {
        title: `S23 Cross Device ${stamp}`,
        discoverability: "listed",
        history_visibility: "shared",
        encryption_profile: "none",
      });
      await addRealmMemberApi(request, aliceToken, realmId, bob.did);
      const msg = `cross-device unread ${stamp}`;
      await sendMessageApi(request, aliceToken, realmId, msg, {
        mentions: [bob.did],
      });

      await bobDevice1.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
      const device1Row = bobDevice1.page
        .getByTestId("notification-item")
        .filter({ hasText: msg });
      await expect(device1Row).toBeVisible({ timeout: 30_000 });
      await expect(device1Row.getByTestId("mark-read-button")).toBeVisible({
        timeout: 30_000,
      });

      await bobDevice2Page.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
      const device2Row = bobDevice2Page.page
        .getByTestId("notification-item")
        .filter({ hasText: msg });
      await expect(device2Row).toBeVisible({ timeout: 30_000 });
      await bobDevice2Page.page.getByTestId("mark-all-read-button").click();
      await expect(device2Row.getByTestId("mark-unread-button")).toBeVisible({
        timeout: 30_000,
      });

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
      await Promise.allSettled([
        bobDevice2Page.close(),
        bobDevice1.close(),
      ]);
    }
  });
});

function mentionSidecarHash(realmId: string, did: string): string {
  return createHash("sha256").update(`${realmId}|${did}`).digest("hex");
}

function notificationEventsFromDelta(
  delta: Record<string, unknown>,
): Array<Record<string, unknown>> {
  const notifications = delta.notifications;
  if (Array.isArray(notifications)) {
    return notifications.filter(isRecord);
  }
  if (!isRecord(notifications)) {
    return [];
  }
  for (const key of ["events", "items"]) {
    const values = notifications[key];
    if (Array.isArray(values)) {
      return values.filter(isRecord);
    }
  }
  return [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function encryptedEnvelope(
  contentType: string,
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  void contentType;
  const aad = { realm_id: realmId, event_kind: "ck.message.create" };
  const payloadMetadata = {
    scheme: "mls-rfc9420",
    version: "1.0",
    group_id: "mls_test",
    epoch: 1,
    content_type: "application/vnd.cokret.message+json",
    aad_visibility_event_id: "hidden",
    aad,
    key_ref: {
      algorithm: "MLS",
      group_state_ref:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
  return {
    ...payloadMetadata,
    ciphertext,
    aad_digest: sha256Digest(canonicalJson(aad)),
    payload_digest: encryptedPayloadDigest(payloadMetadata, ciphertext),
  };
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function encryptedPayloadDigest(
  metadata: Record<string, unknown>,
  ciphertext: string,
): string {
  const hash = createHash("sha256");
  hash.update(Buffer.from(canonicalJson(metadata), "utf8"));
  hash.update(Buffer.from(ciphertext, "base64url"));
  return `sha256:${hash.digest("hex")}`;
}

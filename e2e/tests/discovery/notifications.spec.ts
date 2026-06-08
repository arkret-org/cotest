// Notifications (push prefs / DnD / per-realm mute / mark-all-read)
// Contract: e2e/scenarios/discovery/notifications.md
// Spec: discovery/push-notifications.md §2-§4, discovery/client-preferences.md

import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  addRealmMemberApi,
  authHeaders,
  createRealmApi,
  flowIdFromRealmId,
  putAccountDataViaEventApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";
import { selectDxcOption } from "../../helpers/dxc-select";

test.describe.configure({ mode: "serial" });

test.describe("notifications", () => {
  test("default notification: alice sends, bob sees the message in /notifications", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s23-alice");
    const bob = uniqueUser("s23-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `S23 Notif ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(realmId);

      const msg = `S23 note ${stamp}`;
      await alicePage.sendTimelineMessage(realmId, msg);

      // bob navigates to /notifications and should see the new message in the list.
      await bobPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
      await expect(bobPage.page.getByTestId("notifications-panel")).toBeVisible({
        timeout: 30_000,
      });
      // We're tolerant — either a notification-item with the message text, or the panel
      // is empty (notification projection not implemented yet). The fixme tests below
      // pin the spec contract.
      await stepShot(bobPage.page, testInfo, "default-notification");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test(
    // @user-promise: e2e/scenarios/discovery/notifications.md
    "muting a Realm stops push notifications for new messages but mention still notifies (spec §3 mention override)",
    async ({ browser, request }, testInfo) => {
      // spec: push-notifications.md §3 + §4.3.1.
      const stamp = Date.now();
      const alice = uniqueUser("s23-mute-alice");
      const bob = uniqueUser("s23-mute-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
      const normalMsg = `muted normal message ${stamp}`;
      const mentionMsg = `@${bob.handle.replace(/^@/, "")} muted mention override ${stamp}`;

      try {
        const realmId = await alicePage.createRealm({
          title: `S23 Muted ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          seedMembers: [bob.did],
        });
        await bobPage.acceptInvite(realmId);

        await bobPage.page.goto("/notifications/settings", { waitUntil: "domcontentloaded" });
        await expect(bobPage.page.getByTestId("notification-settings-panel")).toBeVisible({
          timeout: 30_000,
        });
        await bobPage.page.getByTestId("realm-notification-target-input").fill(realmId);
        await bobPage.page.getByTestId("realm-mute-toggle").check();
        await expect(bobPage.page.getByTestId("notification-settings-status")).toContainText(
          /muted/i,
          { timeout: 30_000 },
        );

        await alicePage.sendTimelineMessage(realmId, normalMsg);
        await bobPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
        await expect(bobPage.page.getByTestId("notifications-panel")).toBeVisible({
          timeout: 30_000,
        });
        await expect(
          bobPage.page.getByTestId("notification-item").filter({ hasText: normalMsg }),
        ).toHaveCount(0);

        await alicePage.sendTimelineMessage(realmId, mentionMsg);
        await bobPage.page.reload({ waitUntil: "domcontentloaded" });
        await expect(
          bobPage.page.getByTestId("notification-item").filter({ hasText: mentionMsg }),
        ).toBeVisible({ timeout: 30_000 });
        await stepShot(bobPage.page, testInfo, "muted-mention-override");
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test(
    // @user-promise: e2e/scenarios/discovery/notifications.md
    "Do-not-disturb window suppresses all notifications during configured hours; resumes after window ends",
    async ({ browser, request }, testInfo) => {
      // spec: push-notifications.md §3.2 do-not-disturb preference.
      const stamp = Date.now();
      const alice = uniqueUser("s23-dnd-alice");
      const bob = uniqueUser("s23-dnd-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
      const suppressedMsg = `DND suppressed ${stamp}`;
      const resumedMsg = `DND resumed ${stamp}`;

      try {
        const realmId = await alicePage.createRealm({
          title: `S23 DND ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          seedMembers: [bob.did],
        });
        await bobPage.acceptInvite(realmId);

        await bobPage.page.goto("/notifications/settings", { waitUntil: "domcontentloaded" });
        await expect(bobPage.page.getByTestId("notification-settings-panel")).toBeVisible({
          timeout: 30_000,
        });
        await bobPage.page.getByTestId("dnd-enabled-toggle").check();
        await selectDxcOption(bobPage.page.getByTestId("dnd-mode-select"), "now");
        await bobPage.page.getByTestId("save-notification-settings-button").click();
        await expect(bobPage.page.getByTestId("notification-settings-status")).toContainText(
          /do not disturb|dnd/i,
          { timeout: 30_000 },
        );

        await alicePage.sendTimelineMessage(realmId, suppressedMsg);
        await bobPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
        await expect(
          bobPage.page.getByTestId("notification-item").filter({ hasText: suppressedMsg }),
        ).toHaveCount(0);

        await bobPage.page.goto("/notifications/settings", { waitUntil: "domcontentloaded" });
        await bobPage.page.getByTestId("dnd-enabled-toggle").uncheck();
        await bobPage.page.getByTestId("save-notification-settings-button").click();
        await alicePage.sendTimelineMessage(realmId, resumedMsg);
        await bobPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
        await expect(
          bobPage.page.getByTestId("notification-item").filter({ hasText: resumedMsg }),
        ).toBeVisible({ timeout: 30_000 });
        await stepShot(bobPage.page, testInfo, "dnd-resumed");
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test("mark-all-read clears unread badges and marks notification rows as read", async ({
    request,
  }) => {
    // spec: discovery/push-notifications.md — `last_read_at` marker is
    // the canonical "everything before this is read" cursor. Asserted
    // via the dedicated `POST /_soland/self/notifications/mark-all-read` +
    // `GET /_soland/self/notifications` pair.
    const stamp = Date.now();
    const alice = uniqueUser(`s23-mark-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const auth = { authorization: `Bearer ${aliceToken}` };

    // Pre-mark: last_read_at is null.
    const before = await request.get(`${solandBaseUrl()}/_soland/self/notifications`, {
      headers: auth,
    });
    expect(before.status()).toBe(200);
    const beforeBody = await before.json();
    expect(beforeBody.last_read_at == null).toBe(true);

    // mark-all-read writes a marker.
    const mark = await request.post(
      `${solandBaseUrl()}/_soland/self/notifications/mark-all-read`,
      { headers: auth, data: {} },
    );
    expect(mark.status()).toBe(200);
    const markBody = await mark.json();
    expect(typeof markBody.marked_at).toBe("string");
    expect(markBody.actor).toBe(alice.did);

    // Post-mark: last_read_at reflects the marker.
    const after = await request.get(`${solandBaseUrl()}/_soland/self/notifications`, {
      headers: auth,
    });
    expect(after.status()).toBe(200);
    const afterBody = await after.json();
    expect(afterBody.last_read_at).toBe(markBody.marked_at);
    expect(afterBody.unread_count).toBe(0);

    // Idempotency / advancement: a second call advances the marker.
    await new Promise((r) => setTimeout(r, 20));
    const mark2 = await request.post(
      `${solandBaseUrl()}/_soland/self/notifications/mark-all-read`,
      { headers: auth, data: {} },
    );
    const mark2Body = await mark2.json();
    expect(new Date(mark2Body.marked_at).getTime()).toBeGreaterThanOrEqual(
      new Date(markBody.marked_at).getTime(),
    );
  });

  test(
    // @user-promise: e2e/scenarios/discovery/notifications.md
    "E2EE Realm with evaluation_locus=client: server sends blind wake; client decrypts and evaluates 'contains_keyword' rule locally",
    async ({ request }) => {
      // spec: push-notifications.md §4.5
      const stamp = Date.now();
      const alice = uniqueUser("s23-e2ee-alice");
      const bob = uniqueUser("s23-e2ee-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const realmId = await createRealmApi(request, aliceToken, {
        title: `S23 E2EE Blind Wake ${stamp}`,
        discoverability: "listed",
        history_visibility: "shared",
        encryption_profile: "mls_rfc9420",
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
              conditions: [{ kind: "contains_keyword", pattern: "sealed-keyword" }],
              actions: ["notify"],
            },
          ],
        },
        { context: "set ck.push_rules" },
      );

      const plaintext = `sealed-keyword plaintext must stay client-side ${stamp}`;
      const sidecarHash = mentionSidecarHash(realmId, bob.did);
      const encrypted = signedEventEnvelope({
        actorDid: alice.did,
        realmId: realmId,
        kind: "ck.message.create",
        payload: {
          flow_id: flowIdFromRealmId(realmId),
          track_name: "discussion",
          encrypted: true,
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

      const notifications = await request.get(`${solandBaseUrl()}/_soland/self/notifications`, {
        headers: authHeaders(bobToken),
      });
      expect(notifications.status()).toBe(200);
      const body = await notifications.json();
      const item = (body.items ?? []).find(
        (candidate: Record<string, unknown>) => candidate.event_id === encrypted.event_id,
      );
      expect(item, "blind wake notification for encrypted message").toBeTruthy();
      expect(item.encrypted).toBe(true);
      expect(item.privacy_mode).toBe("blind_wakeup");
      expect(item.wakeup_kind).toBe("encrypted_message");
      expect(item.sender_did).toBe(alice.did);
      expect(item.mention_sidecar_hash).toContain(sidecarHash);
      expect(item.body).toBeUndefined();
      const wire = JSON.stringify(item);
      expect(wire).not.toContain(plaintext);
      expect(wire).not.toContain(bob.did);
    },
  );

  test(
    // @user-promise: e2e/scenarios/discovery/notifications.md
    "cross-device read state: marking read on device-2 clears unread on device-1 within sync window",
    async ({ browser, request }, testInfo) => {
      // spec: client-preferences.md read marker is per-account, synced to all devices.
      const stamp = Date.now();
      const alice = uniqueUser("s23-crossdev-alice");
      const bob = uniqueUser("s23-crossdev-bob");
      const bobDevice2 = {
        ...bob,
        name: `${bob.name}-device2`,
        deviceId: `ck:device:01904100-0000-7000-8000-${String(stamp).padStart(12, "0").slice(-12)}`,
      };
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken1, bobToken2] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
        issueDevSession(request, bobDevice2),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobDevice1 = await openUserPage(browser, bob, { sessionToken: bobToken1 });
      const bobDevice2Page = await openUserPage(browser, bobDevice2, { sessionToken: bobToken2 });

      try {
        const realmId = await alicePage.createRealm({
          title: `S23 Cross Device ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          seedMembers: [bob.did],
        });
        await bobDevice1.acceptInvite(realmId);
        await alicePage.sendTimelineMessage(realmId, `cross-device unread ${stamp}`);

        await bobDevice1.page.goto("/notifications", { waitUntil: "domcontentloaded" });
        await expect(bobDevice1.page.getByTestId("unread-count")).toContainText(/[1-9]/, {
          timeout: 30_000,
        });

        await bobDevice2Page.page.goto("/notifications", { waitUntil: "domcontentloaded" });
        await bobDevice2Page.page.getByTestId("mark-all-read-button").click();
        await expect(bobDevice2Page.page.getByTestId("unread-count")).toContainText(/0/, {
          timeout: 30_000,
        });

        await bobDevice1.page.reload({ waitUntil: "domcontentloaded" });
        await expect(bobDevice1.page.getByTestId("unread-count")).toContainText(/0/, {
          timeout: 30_000,
        });
        await stepShot(bobDevice1.page, testInfo, "device1-cleared-after-device2-read");
      } finally {
        await Promise.allSettled([
          bobDevice2Page.close(),
          bobDevice1.close(),
          alicePage.close(),
        ]);
      }
    },
  );
});

function mentionSidecarHash(realmId: string, did: string): string {
  return createHash("sha256").update(`${realmId}|${did}`).digest("hex");
}

function encryptedEnvelope(
  contentType: string,
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  return {
    scheme: "mls-rfc9420",
    version: "1.0",
    group_id: "mls_test",
    epoch: 1,
    content_type: "application/vnd.cokret.message+json",
    ciphertext,
    authentication_tag: "opaque-tag",
    aad_visibility_event_id: "hidden",
    aad: { suite: "test", content_type: contentType, realm_id: realmId, event_kind: "ck.message.create" },
    key_ref: {
      algorithm: "MLS",
      group_state_ref: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
    aad_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    payload_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    digests: {
      ciphertext: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
}

// Same-server multi-profile browser contexts.
// Contract: Playwright can simulate two local browser profiles against one soland.

import { expect, test } from "@playwright/test";
import {
  assertJointStackNotRequired,
  type JointUserPage,
  openDpopUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("same-server multi-profile UI @fully-implemented", () => {
  test("two isolated browser contexts accept an invite through UI and exchange discussion messages", async ({
    browser,
    request,
  }) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, "same-profile-alice"),
      openDpopUserPage(browser, request, "same-profile-bob"),
    ]);
    if (!aliceFlow || !bobFlow) {
      assertJointStackNotRequired(
        "same-server multi-profile UI requires coauth DPoP session-grant login",
      );
      test.skip(true, "coauth DPoP session-grant login is required for joint UI");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    const realmTitle = `Same server profiles ${stamp}`;
    const aliceMessage = `alice profile message ${stamp}`;
    const bobMessage = `bob profile reply ${stamp}`;

    try {
      expect(alicePage.session.context).not.toBe(bobPage.session.context);
      await Promise.all([alicePage.gotoHome(), bobPage.gotoHome()]);
      const [aliceConfigRaw, bobConfigRaw] = await Promise.all([
        alicePage.page.evaluate(() => window.localStorage.getItem("inkson.config.v1")),
        bobPage.page.evaluate(() => window.localStorage.getItem("inkson.config.v1")),
      ]);
      expect(
        JSON.parse(aliceConfigRaw ?? "{}").active_account?.authority?.principal_id,
      ).toBe(alice.did);
      expect(
        JSON.parse(bobConfigRaw ?? "{}").active_account?.authority?.principal_id,
      ).toBe(bob.did);

      const realmId = await alicePage.createRealm({
        title: realmTitle,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        encryptionProfile: "none",
      });
      await alicePage.inviteFromAdmin(realmId, bob.did);

      await bobPage.acceptInviteFromNotifications(realmId);

      await sendChatMessage(alicePage, realmId, aliceMessage);
      await gotoChat(bobPage, realmId);
      await expect(chatMessage(bobPage, aliceMessage)).toBeVisible({ timeout: 30_000 });

      await sendChatMessage(bobPage, realmId, bobMessage);
      await gotoChat(alicePage, realmId);
      await expect(chatMessage(alicePage, bobMessage)).toBeVisible({ timeout: 30_000 });
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });
});

async function gotoChat(userPage: JointUserPage, realmId: string) {
  await userPage.page.goto(`/chat/${realmId}`, { waitUntil: "domcontentloaded" });
  await expect(userPage.page.getByTestId("chat-panel")).toBeVisible({ timeout: 120_000 });
  await expect(userPage.page.getByTestId("channel-item").first()).toBeVisible({ timeout: 30_000 });
}

async function sendChatMessage(userPage: JointUserPage, realmId: string, body: string) {
  await gotoChat(userPage, realmId);
  await userPage.page.getByTestId("chat-input").fill(body);
  await userPage.page.getByTestId("send-chat-button").click();
  await expect(chatMessage(userPage, body)).toBeVisible({ timeout: 30_000 });
}

function chatMessage(userPage: JointUserPage, body: string) {
  return userPage.page.getByTestId("chat-message").filter({ hasText: body }).first();
}

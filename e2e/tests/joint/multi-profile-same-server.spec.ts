// Same-server multi-profile browser contexts.
// Contract: Playwright can simulate two local browser profiles against one soland.

import { expect, test } from "@playwright/test";
import {
  ensureRegistered,
  issueDevSession,
  type JointUserPage,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("same-server multi-profile UI @fully-implemented", () => {
  test("two isolated browser contexts accept an invite through UI and exchange discussion messages", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("same-profile-alice");
    const bob = uniqueUser("same-profile-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const [alicePage, bobPage] = await Promise.all([
      openUserPage(browser, alice, { sessionCredential: aliceToken }),
      openUserPage(browser, bob, { sessionCredential: bobToken }),
    ]);

    const realmTitle = `Same server profiles ${stamp}`;
    const aliceMessage = `alice profile message ${stamp}`;
    const bobMessage = `bob profile reply ${stamp}`;

    try {
      expect(alicePage.session.context).not.toBe(bobPage.session.context);
      await Promise.all([alicePage.gotoHome(), bobPage.gotoHome()]);
      const [aliceConfigRaw, bobConfigRaw] = await Promise.all([
        alicePage.page.evaluate(() => window.localStorage.getItem("yougen.config.v1")),
        bobPage.page.evaluate(() => window.localStorage.getItem("yougen.config.v1")),
      ]);
      expect(JSON.parse(aliceConfigRaw ?? "{}").account_did).toBe(alice.did);
      expect(JSON.parse(bobConfigRaw ?? "{}").account_did).toBe(bob.did);

      const realmId = await alicePage.createRealm({
        title: realmTitle,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
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

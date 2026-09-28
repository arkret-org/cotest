// Same-server multi-profile browser contexts.
// Contract: Playwright can simulate two local browser profiles against one soland.

import { expect, test } from "../../helpers/arkret-test";
import {
  assertJointStackNotRequired,
  type JointUserPage,
  openDpopUserPage,
} from "../../helpers/users";
import {
  grantCapabilityEventApi,
  resolveDefaultStrandId,
} from "../../helpers/soland-api";

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
      ).toBe(alice.id);
      expect(
        JSON.parse(bobConfigRaw ?? "{}").active_account?.authority?.principal_id,
      ).toBe(bob.id);

      const realmId = await alicePage.createRealm({
        title: realmTitle,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        mlsActivated: false,
      });
      // Ordinary Realm bootstrap intentionally has no implicit discussion
      // Strand. Author the two explicit Events required by the spec before
      // exercising the chat surface.
      await resolveDefaultStrandId(
        request,
        aliceFlow.session.grantJwt,
        realmId,
        { authorityRootController: alice.id },
      );
      await alicePage.inviteFromAdmin(realmId, bob.id);

      await bobPage.acceptInviteFromNotifications(realmId);
      // Membership and message authority are intentionally independent.
      await grantCapabilityEventApi(
        request,
        aliceFlow.session.grantJwt,
        {
          ownerId: alice.id,
          realmId,
          subjectId: bob.id,
          actions: ["ak.message.create"],
        },
      );

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
  // Keep the authenticated shell mounted. A browser-generated back/forward
  // transition emits the native popstate that Dioxus consumes; directly
  // constructing PopStateEvent does not exercise the browser history source.
  await userPage.page.evaluate(async (nextPath) => {
    const nextPop = () =>
      new Promise<void>((resolve) =>
        window.addEventListener("popstate", () => resolve(), { once: true }),
      );
    window.history.pushState({}, "", nextPath);
    const back = nextPop();
    window.history.back();
    await back;
    const forward = nextPop();
    window.history.forward();
    await forward;
  }, `/chat/${realmId}`);
  await expect(userPage.page.getByTestId("chat-panel")).toBeVisible({ timeout: 120_000 });
  await expect(userPage.page.getByTestId("channel-item").first()).toBeVisible({ timeout: 30_000 });
}

async function sendChatMessage(userPage: JointUserPage, realmId: string, body: string) {
  await gotoChat(userPage, realmId);
  // The recipient initially sees the fail-closed encrypted composer while its
  // verified Realm current is still loading. Wait for the plaintext policy
  // selected by this scenario before authoring a message.
  await expect(userPage.page.getByTestId("send-e2ee-move-button")).toBeVisible({ timeout: 30_000 });
  await userPage.page.getByTestId("chat-input").fill(body);
  await userPage.page.getByTestId("send-chat-button").click();
  await expect(chatMessage(userPage, body)).toBeVisible({ timeout: 30_000 });
}

function chatMessage(userPage: JointUserPage, body: string) {
  return userPage.page.getByTestId("chat-message").filter({ hasText: body }).first();
}

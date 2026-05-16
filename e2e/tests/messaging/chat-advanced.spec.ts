// Chat advanced (reactions/replies/mentions/polls/typing/presence)
// Contract: e2e/scenarios/messaging/chat-advanced.md
// Spec refs:
//   - models/flow-and-message.md §4.3, §8
//   - models/content-types.md §4.1 (mentions), §4.9 (polls)
//   - discovery/profiles-presence.md §3
//   - discovery/push-notifications.md §4.3.1, §4.5

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
  type JointUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

async function gotoChat(page: JointUserPage, spaceId: string) {
  if (!page.page.url().includes(`/chat/${spaceId}`)) {
    await page.page.goto(`/chat/${spaceId}`, { waitUntil: "domcontentloaded" });
  }
  await expect(page.page.getByTestId("chat-panel")).toBeVisible({ timeout: 120_000 });
  // Wait for the discussion list to populate at least one channel — yougen's
  // send-chat-button silently no-ops if no selected_channel matches a known
  // channel (chat.rs:2186-2189). Sync hydrates the channel list after mount.
  await expect(page.page.getByTestId("channel-item").first()).toBeVisible({ timeout: 30_000 });
}

async function sendChat(page: JointUserPage, spaceId: string, body: string) {
  await gotoChat(page, spaceId);
  await page.page.getByTestId("chat-input").fill(body);
  await page.page.getByTestId("send-chat-button").click();
  await expect(
    page.page.getByTestId("chat-message").filter({ hasText: body }),
  ).toBeVisible({ timeout: 30_000 });
}

test.describe("chat advanced", () => {
  // yougen gap: ChatPanel's channel list (`channel-item`) doesn't hydrate
  // from sync.spaces flows on first /chat/<id> mount in a fresh browser
  // context; the panel renders but no channels appear. Since the send
  // button no-ops without a selected_channel (chat.rs:2186-2189), every
  // chat-advanced step blocks until yougen ships the initial chat sync.
  test.fixme(
    "reactions converge (OR-Set) and replies render with reply indicator",
    async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s14-alice");
    const bob = uniqueUser("s14-bob");
    const carol = uniqueUser("s14-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const [aliceToken, bobToken, carolToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
      issueDevSession(request, carol),
    ]);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
    const carolPage = await openUserPage(browser, carol, { sessionToken: carolToken });

    const m1 = `S14 ship it ${stamp}`;
    const m2 = `S14 yes ship ${stamp}`;

    try {
      const spaceId = await alicePage.createSpace({
        title: `S14 Chat ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did, carol.did],
      });
      await bobPage.acceptInvite(spaceId);
      await carolPage.acceptInvite(spaceId);

      await sendChat(alicePage, spaceId, m1);

      await gotoChat(bobPage, spaceId);
      const bobOnM1 = bobPage.page.getByTestId("chat-message").filter({ hasText: m1 }).first();
      await expect(bobOnM1).toBeVisible({ timeout: 30_000 });
      await bobOnM1.getByTestId("chat-react-button").click();
      const bobPicker = bobPage.page.getByTestId("chat-reaction-picker");
      await expect(bobPicker).toBeVisible();
      await bobPicker.getByRole("button").first().click();
      await expect(bobOnM1.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });

      await gotoChat(carolPage, spaceId);
      const carolOnM1 = carolPage.page.getByTestId("chat-message").filter({ hasText: m1 }).first();
      await expect(carolOnM1).toBeVisible({ timeout: 30_000 });
      await carolOnM1.getByTestId("chat-react-button").click();
      await carolPage.page.getByTestId("chat-reaction-picker").getByRole("button").first().click();
      await expect(carolOnM1.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });

      await gotoChat(alicePage, spaceId);
      const aliceOnM1 = alicePage.page.getByTestId("chat-message").filter({ hasText: m1 }).first();
      await expect(aliceOnM1.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "reactions-converged");

      await gotoChat(bobPage, spaceId);
      const bobOnM1Reload = bobPage.page.getByTestId("chat-message").filter({ hasText: m1 }).first();
      await bobOnM1Reload.getByTestId("chat-reply-button").click();
      await expect(bobPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await sendChat(bobPage, spaceId, m2);
      const bobOnM2 = bobPage.page.getByTestId("chat-message").filter({ hasText: m2 }).first();
      await expect(bobOnM2.getByTestId("chat-reply-indicator")).toBeVisible();
      await stepShot(bobPage.page, testInfo, "reply-chain");
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  },
  );

  test.fixme("E14.D mentions route notifications only to the mentioned actor", async () => {
    // spec: discovery/push-notifications.md §4.3.1 mention_routing_hint
  });

  test.fixme("E14.E poll create + vote + close (vote replacement per actor)", async () => {
    // spec: models/content-types.md §4.9 polls
  });

  test.fixme(
    "E14.F typing indicator (cx.typing ephemeral) appears in peer view within 1s and clears after ttl_ms=5000",
    async () => {
      // spec: profiles-presence.md §3.5
    },
  );

  test.fixme(
    "E14.G presence state propagates online/offline within 1s after page open/close",
    async () => {
      // spec: profiles-presence.md §3.2-§3.4
    },
  );

  test.fixme(
    "E14.2 mention in E2EE space uses sidecar hash; server log does not contain mentionee.did plaintext",
    async () => {
      // spec: push-notifications.md §4.5 evaluation_locus + mention sidecar hash
    },
  );
});

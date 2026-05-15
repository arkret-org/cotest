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
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("chat advanced", () => {
  test("reactions converge (OR-Set) and replies render with reply indicator", async ({
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

      // Reactions (OR-Set)
      await alicePage.sendTimelineMessage(spaceId, m1);
      await bobPage.gotoTimelineSpace(spaceId);
      await carolPage.gotoTimelineSpace(spaceId);

      const bobOnM1 = bobPage.timelineEvent(m1);
      await bobOnM1.getByTestId("chat-react-button").click();
      const picker = bobPage.page.getByTestId("chat-reaction-picker");
      await expect(picker).toBeVisible();
      await picker.getByRole("button").first().click();
      await expect(bobOnM1.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });

      const carolOnM1 = carolPage.timelineEvent(m1);
      await carolOnM1.getByTestId("chat-react-button").click();
      await carolPage.page.getByTestId("chat-reaction-picker").getByRole("button").first().click();
      await expect(carolOnM1.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });

      // alice should see both reactions (OR-Set convergence)
      await alicePage.gotoTimelineSpace(spaceId);
      const aliceOnM1 = alicePage.timelineEvent(m1);
      await expect(aliceOnM1.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "reactions-converged");

      // Reply chain
      await bobOnM1.getByTestId("chat-reply-button").click();
      await expect(bobPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await bobPage.sendTimelineMessage(spaceId, m2);
      const bobOnM2 = bobPage.timelineEvent(m2);
      await expect(bobOnM2.getByTestId("chat-reply-indicator")).toBeVisible();
      await stepShot(bobPage.page, testInfo, "reply-chain");
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  });

  test.fixme("E14.D mentions route notifications only to the mentioned actor", async () => {
    // spec: discovery/push-notifications.md §4.3.1 mention_routing_hint
    // soland gap: mention routing + notification queue projection.
  });

  test.fixme("E14.E poll create + vote + close (vote replacement per actor)", async () => {
    // spec: models/content-types.md §4.9 polls
    // soland gap: cx.content.poll{,.response} reducer.
  });

  test.fixme("E14.F typing indicator (cx.typing ephemeral) appears in peer view within 1s and clears after ttl_ms=5000", async () => {
    // spec: profiles-presence.md §3.5
    // soland gap: ephemeral cx.typing signal routing through Sync Service.
  });

  test.fixme("E14.G presence state propagates online/offline within 1s after page open/close", async () => {
    // spec: profiles-presence.md §3.2-§3.4
    // soland gap: cx.presence ephemeral channel.
  });

  test.fixme("E14.2 mention in E2EE space uses sidecar hash; server log does not contain mentionee.did plaintext", async () => {
    // spec: push-notifications.md §4.5 evaluation_locus + mention sidecar hash
    // soland gap: E2EE mention routing.
  });
});

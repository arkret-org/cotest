// Team onboarding workflow — Mei welcomes new hire Yuki
// Contract: e2e/scenarios/workflows/team-onboarding.md
// Spec refs:
//   - models/realm-and-space.md §2-§3 (Space + Join Policy)
//   - models/strand-and-message.md §8 (reply/edit)
//
// Realistic story: Manager Mei creates a welcome space, seeds Yuki, exchanges
// a reply + edit timeline thread, and wraps the day with a short reply.
// Kept timeline-only to stay aligned with feature surface that's solid;
// kanban-driven onboarding tasks live in workflows/kanban-week.

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import { openDpopUserPage } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: team onboarding", () => {
  test("mei seeds yuki into welcome space, exchanges reply + edit + wrap-up", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const [meiFlow, yukiFlow] = await Promise.all([
      openDpopUserPage(browser, request, "wf-onboard-mei"),
      openDpopUserPage(browser, request, "wf-onboard-yuki"),
    ]);
    test.skip(
      !meiFlow || !yukiFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!meiFlow || !yukiFlow) {
      return;
    }
    const yuki = yukiFlow.user;
    const meiPage = meiFlow.page;
    const yukiPage = yukiFlow.page;

    const welcome = `Hi Yuki, welcome aboard! Ping me if anything blocks you. ${stamp}`;
    const welcomeEdited = `${welcome} (Onboarding hub: https://corp.example/onboarding)`;
    const yukiThanks = `Thanks Mei — happy to be here. ${stamp}`;
    const wrap = `Great progress today — see you tomorrow ${stamp}`;
    const yukiWrap = `Will do, see you tomorrow! ${stamp}`;

    try {
      // Phase A — welcome space + seed invite.
      const realmId = await meiPage.createRealm({
        title: `Welcome to the team ${stamp}`,
        summary: "Day-1 onboarding hub",
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
        seedMembers: [yuki.did],
      });
      await yukiPage.acceptInvite(realmId);
      await meiPage.sendTimelineMessage(realmId, welcome);
      await stepShot(meiPage.page, testInfo, "A-welcome");

      // Phase B — Yuki picks up the welcome and replies.
      await yukiPage.gotoTimelineRealm(realmId);
      await expect(yukiPage.page.getByTestId("message-list")).toContainText(welcome, {
        timeout: 30_000,
      });
      await yukiPage.clickTimelineReply(welcome);
      await expect(yukiPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await yukiPage.sendTimelineMessage(realmId, yukiThanks);
      await expect(yukiPage.timelineEvent(yukiThanks)).toBeVisible({ timeout: 30_000 });
      await expect(
        yukiPage.timelineEvent(yukiThanks).getByTestId("chat-reply-indicator"),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(yukiPage.page, testInfo, "B-yuki-replied");

      // Phase C — Mei edits the welcome in place; Yuki sees the patched copy.
      await meiPage.gotoTimelineRealm(realmId);
      await expect(meiPage.timelineEvent(welcome)).toBeVisible({ timeout: 30_000 });
      await meiPage.clickTimelineEdit(welcome);
      await meiPage.page.getByTestId("chat-edit-composer").locator("textarea").fill(welcomeEdited);
      await meiPage.page.getByTestId("chat-save-edit-button").click();
      await meiPage.waitForTimelineEventSettled(welcomeEdited);
      await expect(meiPage.page.getByTestId("chat-status")).toContainText(/Message updated/i);
      await yukiPage.gotoTimelineRealm(realmId);
      await expect(yukiPage.timelineEvent(welcomeEdited)).toBeVisible({ timeout: 30_000 });
      await stepShot(meiPage.page, testInfo, "C-welcome-edited");

      // Phase D — close the day with a small back-and-forth.
      await meiPage.sendTimelineMessage(realmId, wrap);
      await yukiPage.gotoTimelineRealm(realmId);
      await expect(yukiPage.timelineEvent(wrap)).toBeVisible({ timeout: 30_000 });
      await yukiPage.sendTimelineMessage(realmId, yukiWrap);
      await meiPage.gotoTimelineRealm(realmId);
      await expect(meiPage.timelineEvent(yukiWrap)).toBeVisible({ timeout: 30_000 });
      await stepShot(meiPage.page, testInfo, "D-wrap-up");
    } finally {
      await Promise.allSettled([yukiPage.close(), meiPage.close()]);
    }
  });

  test.fixme(
    // @blocking-on: soland#workflows-team-onboarding-gap
    // @user-promise: e2e/scenarios/workflows/team-onboarding.md
    // @expected-live-by: 2026Q3
    "E-onboarding.1 mei pins the welcome message so yuki keeps seeing it at the top",
    async () => {
      // yougen gap: pinned-message UI; spec models/strand-and-message.md §8.6.
    },
  );

  test.fixme(
    // @blocking-on: soland#workflows-team-onboarding-gap
    // @user-promise: e2e/scenarios/workflows/team-onboarding.md
    // @expected-live-by: 2026Q3
    "E-onboarding.2 mei edits welcome twice; write-status reflects revision count",
    async () => {
      // yougen gap: write-status reports `revised` but not a numeric counter.
    },
  );
});

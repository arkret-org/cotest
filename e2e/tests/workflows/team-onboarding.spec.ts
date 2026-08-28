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

import { expect, test } from "../../helpers/arkret-test";
import { stepShot } from "../../helpers/screenshots";
import { openDpopUserPage } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: team onboarding", () => {
  test("mei seeds yuki into welcome space, exchanges reply + edit + wrap-up", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(300_000);
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
        seedMembers: [yuki.id],
      });
      await yukiPage.acceptInvite(realmId);
      await meiPage.grantRealmCapability(
        realmId,
        yuki.id,
        "ak.message.create",
      );
      await meiPage.sendTimelineMessage(realmId, welcome);
      await stepShot(meiPage.page, testInfo, "A-welcome");

      // Phase B — Yuki picks up the welcome and replies.
      await yukiPage.gotoTimelineRealm(realmId);
      await expect(yukiPage.page.getByTestId("message-list")).toContainText(
        welcome,
        {
          timeout: 30_000,
        },
      );
      await yukiPage.clickTimelineReply(welcome);
      await expect(
        yukiPage.page.getByTestId("chat-reply-banner"),
      ).toBeVisible();
      await yukiPage.sendTimelineMessage(realmId, yukiThanks);
      await expect(yukiPage.timelineEvent(yukiThanks)).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        yukiPage.timelineEvent(yukiThanks).getByTestId("chat-reply-indicator"),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(yukiPage.page, testInfo, "B-yuki-replied");

      // Phase C — Mei edits the welcome in place; Yuki sees the patched copy.
      await meiPage.gotoTimelineRealm(realmId);
      await expect(meiPage.timelineEvent(welcome)).toBeVisible({
        timeout: 30_000,
      });
      await meiPage.clickTimelineEdit(welcome);
      await meiPage.page
        .getByTestId("chat-edit-composer")
        .locator("textarea")
        .fill(welcomeEdited);
      await meiPage.page.getByTestId("chat-save-edit-button").click();
      await meiPage.waitForTimelineEventSettled(welcomeEdited);
      await expect(meiPage.page.getByTestId("chat-status")).toContainText(
        /Message updated/i,
      );
      await yukiPage.gotoTimelineRealm(realmId);
      await expect(yukiPage.timelineEvent(welcomeEdited)).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(meiPage.page, testInfo, "C-welcome-edited");

      // Phase D — close the day with a small back-and-forth.
      await meiPage.sendTimelineMessage(realmId, wrap);
      await yukiPage.gotoTimelineRealm(realmId);
      await expect(yukiPage.timelineEvent(wrap)).toBeVisible({
        timeout: 30_000,
      });
      await yukiPage.sendTimelineMessage(realmId, yukiWrap);
      await meiPage.gotoTimelineRealm(realmId);
      await expect(meiPage.timelineEvent(yukiWrap)).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(meiPage.page, testInfo, "D-wrap-up");
    } finally {
      await Promise.allSettled([yukiPage.close(), meiPage.close()]);
    }
  });

  test("E-onboarding.1 mei pins the welcome message so yuki keeps seeing it at the top", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(300_000);
    const stamp = Date.now();
    const [meiFlow, yukiFlow] = await Promise.all([
      openDpopUserPage(browser, request, "wf-onboard-pin-mei"),
      openDpopUserPage(browser, request, "wf-onboard-pin-yuki"),
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
    const welcome = `Pinned welcome — read me first, Yuki! ${stamp}`;

    try {
      const realmId = await meiPage.createRealm({
        title: `Pinned welcome space ${stamp}`,
        summary: "Day-1 onboarding hub with a pinned welcome",
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
        seedMembers: [yuki.id],
      });
      await yukiPage.acceptInvite(realmId);
      await meiPage.sendTimelineMessage(realmId, welcome);

      // Mei pins the welcome via the message context menu. The
      // pinned-message bar at the top of the feed then surfaces it. Spec:
      // models/pins.md (`ak.pin.add` shared event).
      const meiMessage = meiPage.timelineEvent(welcome);
      await expect(meiMessage).toBeVisible({ timeout: 30_000 });
      await meiMessage.hover();
      await meiMessage.getByTestId("chat-message-menu-button").click();
      const pinButton = meiMessage.getByTestId("message-shared-pin-button");
      await expect(pinButton).toBeVisible({ timeout: 30_000 });
      await pinButton.click();

      const meiPinnedBar = meiPage.page.getByTestId("pinned-bar");
      await expect(meiPinnedBar.getByTestId("pinned-bar-item")).toContainText(
        welcome.slice(0, 40),
        { timeout: 30_000 },
      );
      await stepShot(meiPage.page, testInfo, "E1-mei-pinned");

      // Yuki keeps seeing the welcome at the top: the shared pin projects
      // into Yuki's pinned bar once the `ak.pin.add` event syncs.
      await yukiPage.gotoTimelineRealm(realmId);
      await expect(yukiPage.page.getByTestId("message-list")).toContainText(
        welcome,
        {
          timeout: 30_000,
        },
      );
      const yukiPinnedItem = yukiPage.page
        .getByTestId("pinned-bar")
        .getByTestId("pinned-bar-item");
      await expect(yukiPinnedItem).toContainText(welcome.slice(0, 40), {
        timeout: 60_000,
      });
      await stepShot(yukiPage.page, testInfo, "E1-yuki-sees-pin");
    } finally {
      await Promise.allSettled([yukiPage.close(), meiPage.close()]);
    }
  });

  test("E-onboarding.2 mei edits welcome twice; write-status reflects revision count", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(300_000);
    const stamp = Date.now();
    const meiFlow = await openDpopUserPage(
      browser,
      request,
      "wf-onboard-rev-mei",
    );
    test.skip(
      !meiFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!meiFlow) {
      return;
    }
    const meiPage = meiFlow.page;
    const welcome = `Welcome v1 ${stamp}`;
    const welcomeV2 = `Welcome v2 — added onboarding hub ${stamp}`;
    const welcomeV3 = `Welcome v3 — added benefits portal ${stamp}`;

    try {
      const realmId = await meiPage.createRealm({
        title: `Revision counter space ${stamp}`,
        summary: "Edit the welcome twice; assert the numeric write-status",
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
      });
      await meiPage.sendTimelineMessage(realmId, welcome);

      // First edit -> revision count 1.
      await meiPage.clickTimelineEdit(welcome);
      await meiPage.page
        .getByTestId("chat-edit-composer")
        .locator("textarea")
        .fill(welcomeV2);
      await meiPage.page.getByTestId("chat-save-edit-button").click();
      await meiPage.waitForTimelineEventSettled(welcomeV2);
      const afterFirst = meiPage
        .timelineEvent(welcomeV2)
        .getByTestId("message-write-status");
      await expect(afterFirst).toBeVisible({ timeout: 30_000 });
      await expect(afterFirst).toHaveAttribute("data-revision-count", "1");

      // Second edit -> revision count 2.
      await meiPage.clickTimelineEdit(welcomeV2);
      await meiPage.page
        .getByTestId("chat-edit-composer")
        .locator("textarea")
        .fill(welcomeV3);
      await meiPage.page.getByTestId("chat-save-edit-button").click();
      await meiPage.waitForTimelineEventSettled(welcomeV3);
      const afterSecond = meiPage
        .timelineEvent(welcomeV3)
        .getByTestId("message-write-status");
      await expect(afterSecond).toBeVisible({ timeout: 30_000 });
      await expect(afterSecond).toHaveAttribute("data-revision-count", "2");
      await expect(afterSecond).toContainText("2");
      await stepShot(meiPage.page, testInfo, "E2-revision-count");
    } finally {
      await meiPage.close();
    }
  });
});

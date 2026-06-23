// Async daily standup workflow — three engineers post + cross-unblock
// Contract: e2e/scenarios/workflows/daily-standup.md
// Spec refs:
//   - models/strand-and-message.md §8 (reply / edit)
//
// Realistic story: Three engineers each post their Yesterday/Today/Blockers
// in a shared standup space. Lin replies to unblock Pat's PR review ask, and
// Pat edits the ETA on a reply (after realising EOD was wrong).

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import { openDpopUserPage } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: async daily standup", () => {
  test("lin/pat/quincy each post standup; lin unblocks pat by reply; pat edits an ETA", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const encryptedSyncTimeout = 90_000;
    const [linFlow, patFlow, quincyFlow] = await Promise.all([
      openDpopUserPage(browser, request, "wf-standup-lin"),
      openDpopUserPage(browser, request, "wf-standup-pat"),
      openDpopUserPage(browser, request, "wf-standup-quincy"),
    ]);
    test.skip(
      !linFlow || !patFlow || !quincyFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!linFlow || !patFlow || !quincyFlow) {
      return;
    }
    const pat = patFlow.user;
    const quincy = quincyFlow.user;
    const linPage = linFlow.page;
    const patPage = patFlow.page;
    const quincyPage = quincyFlow.page;

    const linStandup = `[Standup] Yesterday: shipped onboarding. Today: code review. Blockers: none. ${stamp}`;
    const patStandup = `[Standup] Yesterday: kanban bug. Today: deploy fix. Blockers: need Lin's review on PR #88. ${stamp}`;
    const quincyStandup = `[Standup] Yesterday: design draft. Today: write tests. Blockers: ETA on test infra? ${stamp}`;
    const linUnblockPat = `Reviewing PR #88 now, ack in 30min. ${stamp}`;
    const linUnblockPatFixed = `Reviewing PR #88 now — actually ack in 1h, sorry. ${stamp}`;

    try {
      // Phase A — standup space (today's edition).
      const realmId = await linPage.createRealm({
        title: `Team Daily ${stamp}`,
        summary: "Async standup channel",
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [pat.did, quincy.did],
      });
      await Promise.all([
        patPage.acceptInvite(realmId),
        quincyPage.acceptInvite(realmId),
      ]);
      await Promise.all([
        patPage.gotoTimelineRealm(realmId),
        quincyPage.gotoTimelineRealm(realmId),
      ]);

      // Phase B — three standups land.
      await linPage.sendTimelineMessage(realmId, linStandup);
      await patPage.sendTimelineMessage(realmId, patStandup);
      await quincyPage.sendTimelineMessage(realmId, quincyStandup);

      for (const actor of [linPage, patPage, quincyPage]) {
        await actor.gotoTimelineRealm(realmId);
        for (const body of [linStandup, patStandup, quincyStandup]) {
          await expect(actor.page.getByTestId("message-list")).toContainText(
            body,
            {
              timeout: encryptedSyncTimeout,
            },
          );
        }
      }
      await stepShot(linPage.page, testInfo, "B-three-standups");

      // Phase C — Lin replies on Pat's standup to unblock the PR review.
      await linPage.gotoTimelineRealm(realmId);
      await expect(linPage.page.getByTestId("message-list")).toContainText(
        patStandup,
        {
          timeout: encryptedSyncTimeout,
        },
      );
      await linPage.clickTimelineReply(patStandup);
      await expect(linPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await linPage.sendTimelineMessage(realmId, linUnblockPat);
      await expect(linPage.timelineEvent(linUnblockPat)).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await expect(
        linPage
          .timelineEvent(linUnblockPat)
          .getByTestId("chat-reply-indicator"),
      ).toBeVisible({ timeout: encryptedSyncTimeout });

      await patPage.gotoTimelineRealm(realmId);
      await expect(patPage.timelineEvent(linUnblockPat)).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await stepShot(patPage.page, testInfo, "C-unblock-landed");

      // Phase D — Lin realises 30min is wrong and edits the reply.
      await linPage.gotoTimelineRealm(realmId);
      await expect(linPage.timelineEvent(linUnblockPat)).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await linPage.clickTimelineEdit(linUnblockPat);
      await linPage.page
        .getByTestId("chat-edit-composer")
        .locator("textarea")
        .fill(linUnblockPatFixed);
      await linPage.page.getByTestId("chat-save-edit-button").click();
      await expect(linPage.timelineEvent(linUnblockPatFixed)).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await expect(linPage.page.getByTestId("chat-status")).toContainText(
        /Message updated/i,
      );
      await patPage.gotoTimelineRealm(realmId);
      await expect(patPage.timelineEvent(linUnblockPatFixed)).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await stepShot(patPage.page, testInfo, "D-eta-corrected");
    } finally {
      await Promise.allSettled([
        quincyPage.close(),
        patPage.close(),
        linPage.close(),
      ]);
    }
  });

  test.fixme(// @blocking-on: soland#workflows-daily-standup-gap
  // @user-promise: e2e/scenarios/workflows/daily-standup.md
  // @expected-live-by: 2026Q3
  "E-standup.offline pat is offline mid-post; reconnect flushes the outbox", async () => {
    // yougen gap: outbox UX + offline persistence (sync/offline-conflict).
  });

  test.fixme(// @blocking-on: soland#workflows-daily-standup-gap
  // @user-promise: e2e/scenarios/workflows/daily-standup.md
  // @expected-live-by: 2026Q3
  "E-standup.redact lin redacts their own standup after spotting a wrong template", async () => {
    // Same redact pattern as triad — pulled out here for the standup story.
  });
});

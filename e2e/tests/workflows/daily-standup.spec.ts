// Async daily standup workflow — three engineers post + cross-unblock
// Contract: e2e/scenarios/workflows/daily-standup.md
// Spec refs:
//   - models/flow-and-message.md §8 (reply / edit)
//
// Realistic story: Three engineers each post their Yesterday/Today/Blockers
// in a shared standup space. Lin replies to unblock Pat's PR review ask, and
// Pat edits the ETA on a reply (after realising EOD was wrong).

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: async daily standup", () => {
  test("lin/pat/quincy each post standup; lin unblocks pat by reply; pat edits an ETA", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const lin = uniqueUser("wf-standup-lin");
    const pat = uniqueUser("wf-standup-pat");
    const quincy = uniqueUser("wf-standup-quincy");
    await Promise.all([
      ensureRegistered(request, lin),
      ensureRegistered(request, pat),
      ensureRegistered(request, quincy),
    ]);
    const [linToken, patToken, quincyToken] = await Promise.all([
      issueDevSession(request, lin),
      issueDevSession(request, pat),
      issueDevSession(request, quincy),
    ]);
    const linPage = await openUserPage(browser, lin, { sessionToken: linToken });
    const patPage = await openUserPage(browser, pat, { sessionToken: patToken });
    const quincyPage = await openUserPage(browser, quincy, { sessionToken: quincyToken });

    const linStandup = `[Standup] Yesterday: shipped onboarding. Today: code review. Blockers: none. ${stamp}`;
    const patStandup = `[Standup] Yesterday: kanban bug. Today: deploy fix. Blockers: need Lin's review on PR #88. ${stamp}`;
    const quincyStandup = `[Standup] Yesterday: design draft. Today: write tests. Blockers: ETA on test infra? ${stamp}`;
    const linUnblockPat = `Reviewing PR #88 now, ack in 30min. ${stamp}`;
    const linUnblockPatFixed = `Reviewing PR #88 now — actually ack in 1h, sorry. ${stamp}`;

    try {
      // Phase A — standup space (today's edition).
      const spaceId = await linPage.createRealm({
        title: `Team Daily ${stamp}`,
        summary: "Async standup channel",
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [pat.did, quincy.did],
      });
      await Promise.all([patPage.acceptInvite(spaceId), quincyPage.acceptInvite(spaceId)]);

      // Phase B — three standups land.
      await linPage.sendTimelineMessage(spaceId, linStandup);
      await patPage.sendTimelineMessage(spaceId, patStandup);
      await quincyPage.sendTimelineMessage(spaceId, quincyStandup);

      for (const actor of [linPage, patPage, quincyPage]) {
        await actor.gotoTimelineRealm(spaceId);
        for (const body of [linStandup, patStandup, quincyStandup]) {
          await expect(actor.page.getByTestId("timeline")).toContainText(body, {
            timeout: 30_000,
          });
        }
      }
      await stepShot(linPage.page, testInfo, "B-three-standups");

      // Phase C — Lin replies on Pat's standup to unblock the PR review.
      await linPage.gotoTimelineRealm(spaceId);
      await expect(linPage.page.getByTestId("timeline")).toContainText(patStandup, {
        timeout: 30_000,
      });
      await linPage.timelineEvent(patStandup).getByTestId("reply-button").click();
      await expect(linPage.page.getByTestId("reply-to-banner")).toBeVisible();
      await linPage.sendTimelineMessage(spaceId, linUnblockPat);
      await expect(linPage.timelineEvent(linUnblockPat)).toBeVisible({ timeout: 30_000 });
      await expect(
        linPage.timelineEvent(linUnblockPat).getByTestId("reply-indicator"),
      ).toBeVisible({ timeout: 30_000 });

      await patPage.gotoTimelineRealm(spaceId);
      await expect(patPage.timelineEvent(linUnblockPat)).toBeVisible({ timeout: 30_000 });
      await stepShot(patPage.page, testInfo, "C-unblock-landed");

      // Phase D — Lin realises 30min is wrong and edits the reply.
      await linPage.gotoTimelineRealm(spaceId);
      await expect(linPage.timelineEvent(linUnblockPat)).toBeVisible({ timeout: 30_000 });
      await linPage.timelineEvent(linUnblockPat).getByTestId("edit-button").click();
      await linPage.page.getByTestId("edit-composer").locator("textarea").fill(linUnblockPatFixed);
      await linPage.page.getByTestId("save-edit-button").click();
      await expect(linPage.timelineEvent(linUnblockPatFixed)).toBeVisible({ timeout: 30_000 });
      await expect(linPage.page.getByTestId("write-status")).toContainText(/revised/);
      await patPage.gotoTimelineRealm(spaceId);
      await expect(patPage.timelineEvent(linUnblockPatFixed)).toBeVisible({ timeout: 30_000 });
      await stepShot(patPage.page, testInfo, "D-eta-corrected");
    } finally {
      await Promise.allSettled([quincyPage.close(), patPage.close(), linPage.close()]);
    }
  });

  test.fixme(
    // @blocking-on: soland#workflows-daily-standup-gap
    // @user-promise: e2e/scenarios/workflows/daily-standup.md
    // @expected-live-by: 2026Q3
    "E-standup.offline pat is offline mid-post; reconnect flushes the outbox",
    async () => {
      // yougen gap: outbox UX + offline persistence (sync/offline-conflict).
    },
  );

  test.fixme(
    // @blocking-on: soland#workflows-daily-standup-gap
    // @user-promise: e2e/scenarios/workflows/daily-standup.md
    // @expected-live-by: 2026Q3
    "E-standup.redact lin redacts their own standup after spotting a wrong template",
    async () => {
      // Same redact pattern as triad — pulled out here for the standup story.
    },
  );
});

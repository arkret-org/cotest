// Sprint planning workflow — tech lead + two engineers commit to stories
// Contract: e2e/scenarios/workflows/sprint-planning.md
// Spec refs:
//   - models/space-and-place.md §2-§4 (Space + Board + List)
//   - models/flow-and-message.md §8 (reply chain)
//
// Realistic story: Tech-lead Mei kicks off a sprint, two engineers reply
// claiming user stories. The kanban side of sprint planning (multi-card +
// promote Backlog→Todo) needs cross-user kanban sync and a non-draft state
// — both fixme'd until soland + yougen close those gaps.

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: sprint planning", () => {
  test("mei kicks off sprint, bob + carol claim their stories via reply chain", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const mei = uniqueUser("wf-sprint-mei");
    const bob = uniqueUser("wf-sprint-bob");
    const carol = uniqueUser("wf-sprint-carol");
    await Promise.all([
      ensureRegistered(request, mei),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const [meiToken, bobToken, carolToken] = await Promise.all([
      issueDevSession(request, mei),
      issueDevSession(request, bob),
      issueDevSession(request, carol),
    ]);
    const meiPage = await openUserPage(browser, mei, { sessionToken: meiToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
    const carolPage = await openUserPage(browser, carol, { sessionToken: carolToken });

    const kickoff = `Sprint 24 kickoff — Story A (auth), Story B (payments), Story C (analytics). Reply with your pick. ${stamp}`;
    const bobClaim = `I'll take Story A. ${stamp}`;
    const carolClaim = `I'll grab Story B. ${stamp}`;
    const meiClose = `Thanks both — I'll cover Story C. Regroup Friday. ${stamp}`;

    try {
      // Phase A — Mei spins up the sprint space with both engineers seeded.
      const spaceId = await meiPage.createSpace({
        title: `Sprint 24 ${stamp}`,
        summary: "Sprint planning + claims",
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did, carol.did],
      });
      await Promise.all([bobPage.acceptInvite(spaceId), carolPage.acceptInvite(spaceId)]);
      await meiPage.sendTimelineMessage(spaceId, kickoff);
      await stepShot(meiPage.page, testInfo, "A-kickoff");

      // Phase B — both engineers receive the kickoff and reply with claims.
      await bobPage.gotoTimelineSpace(spaceId);
      await expect(bobPage.page.getByTestId("timeline")).toContainText(kickoff, {
        timeout: 30_000,
      });
      await bobPage.timelineEvent(kickoff).getByTestId("reply-button").click();
      await expect(bobPage.page.getByTestId("reply-to-banner")).toBeVisible();
      await bobPage.sendTimelineMessage(spaceId, bobClaim);
      await expect(bobPage.timelineEvent(bobClaim)).toBeVisible({ timeout: 30_000 });
      await expect(bobPage.timelineEvent(bobClaim).getByTestId("reply-indicator")).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(bobPage.page, testInfo, "B-bob-claimed");

      await carolPage.gotoTimelineSpace(spaceId);
      await expect(carolPage.page.getByTestId("timeline")).toContainText(kickoff, {
        timeout: 30_000,
      });
      await carolPage.timelineEvent(kickoff).getByTestId("reply-button").click();
      await expect(carolPage.page.getByTestId("reply-to-banner")).toBeVisible();
      await carolPage.sendTimelineMessage(spaceId, carolClaim);
      await expect(carolPage.timelineEvent(carolClaim)).toBeVisible({ timeout: 30_000 });
      await expect(carolPage.timelineEvent(carolClaim).getByTestId("reply-indicator")).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(carolPage.page, testInfo, "B-carol-claimed");

      // Phase C — Mei closes the loop after seeing both claims arrive.
      await meiPage.gotoTimelineSpace(spaceId);
      await expect(meiPage.timelineEvent(bobClaim)).toBeVisible({ timeout: 30_000 });
      await expect(meiPage.timelineEvent(carolClaim)).toBeVisible({ timeout: 30_000 });
      await meiPage.sendTimelineMessage(spaceId, meiClose);
      await stepShot(meiPage.page, testInfo, "C-loop-closed");

      // Both engineers see Mei's wrap-up.
      for (const eng of [bobPage, carolPage]) {
        await eng.gotoTimelineSpace(spaceId);
        await expect(eng.timelineEvent(meiClose)).toBeVisible({ timeout: 30_000 });
      }
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), meiPage.close()]);
    }
  });

  test.fixme(
    // @blocking-on: soland#workflows-sprint-planning-gap
    // @user-promise: e2e/scenarios/workflows/sprint-planning.md
    // @expected-live-by: 2026Q3
    "E-sprint.kanban mei builds a Backlog + Todo + Doing + Done kanban and promotes 3 stories",
    async () => {
      // Multi-card kanban (5+ cards in one column) currently keeps cards in
      // draft/queued state, which blocks archive. Needs soland to ack the
      // batch faster or yougen to surface draft-state independently.
    },
  );

  test.fixme(
    // @blocking-on: soland#workflows-sprint-planning-gap
    // @user-promise: e2e/scenarios/workflows/sprint-planning.md
    // @expected-live-by: 2026Q3
    "E-sprint.crossuser bob + carol see the same kanban as mei after she edits the board",
    async () => {
      // yougen gap: kanban state is local per-context, not synced via /sync.
    },
  );

  test.fixme(
    // @blocking-on: soland#workflows-sprint-planning-gap
    // @user-promise: e2e/scenarios/workflows/sprint-planning.md
    // @expected-live-by: 2026Q3
    "E-sprint.archiveboard mei archives the entire sprint board at end of week",
    async () => {
      // yougen gap: bulk board archive button; needs cascade behavior per spec.
    },
  );
});

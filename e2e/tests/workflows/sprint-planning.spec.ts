// Sprint planning workflow — tech lead + two engineers commit to stories
// Contract: e2e/scenarios/workflows/sprint-planning.md
// Spec refs:
//   - models/space-and-place.md §2-§4 (Space + Board + List)
//   - models/flow-and-message.md §8 (reply chain)
//
// Realistic story: Tech-lead Mei kicks off a sprint, two engineers reply
// claiming user stories. The kanban cross-user hydration path is live;
// multi-card promote Backlog→Todo remains fixme'd until the move UI is
// stable enough for the full scenario.

import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
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

  test("E-sprint.crossuser bob + carol see the same kanban as mei after she edits the board", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const mei = uniqueUser("wf-sprint-kanban-mei");
    const bob = uniqueUser("wf-sprint-kanban-bob");
    const carol = uniqueUser("wf-sprint-kanban-carol");
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

    const backlog = `Backlog-${stamp}`;
    const todo = `Todo-${stamp}`;
    const doing = `Doing-${stamp}`;
    const done = `Done-${stamp}`;
    const stories = [
      `Story A: User auth flow ${stamp}`,
      `Story B: Payment gateway integration ${stamp}`,
      `Story C: Analytics dashboard ${stamp}`,
    ];
    const detailDescription = `Remote description update from Mei ${stamp}`;
    const synthesisNote = `Remote synthesis note from Mei ${stamp}`;

    try {
      const spaceId = await meiPage.createSpace({
        title: `Sprint board ${stamp}`,
        summary: "Cross-user kanban hydration",
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did, carol.did],
      });
      await Promise.all([bobPage.acceptInvite(spaceId), carolPage.acceptInvite(spaceId)]);

      await meiPage.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
      await expect(meiPage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await meiPage.page.getByTestId("new-board-toggle").click();
      await meiPage.page.getByTestId("new-board-title-input").fill(`Sprint Board ${stamp}`);
      await meiPage.page.getByTestId("create-board-space-button").click();
      await expect(meiPage.page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
        timeout: 30_000,
      });
      const boardId = await meiPage.page
        .getByTestId("board-space-select")
        .evaluate((node) => (node as HTMLSelectElement).value);
      expect(boardId).toMatch(/^ck:space:/);

      for (const columnName of [backlog, todo, doing, done]) {
        await meiPage.page.getByTestId("new-column-input").fill(columnName);
        await meiPage.page.getByTestId("add-column-button").click();
        await expect(
          meiPage.page.getByTestId("kanban-column").filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }

      await bobPage.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
      await expect(bobPage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await expect(bobPage.page.getByTestId("board-space-select")).toHaveValue(boardId, {
        timeout: 30_000,
      });
      await expect(
        bobPage.page.getByTestId("kanban-column").filter({ hasText: backlog }),
      ).toBeVisible({ timeout: 30_000 });

      const backlogColumn = meiPage.page.getByTestId("kanban-column").filter({ hasText: backlog });
      const liveStory = stories[0];
      await backlogColumn.getByTestId("add-card-button").click();
      await backlogColumn.getByTestId("new-card-title-input").fill(liveStory);
      await backlogColumn.getByTestId("save-card-button").click();
      await expect(
        backlogColumn.getByTestId("kanban-card").filter({ hasText: liveStory }),
      ).toBeVisible({ timeout: 30_000 });
      await expect(
        bobPage.page
          .getByTestId("kanban-column")
          .filter({ hasText: backlog })
          .getByTestId("kanban-card")
          .filter({ hasText: liveStory }),
      ).toBeVisible({ timeout: 45_000 });

      const bobLiveCard = bobPage.page
        .getByTestId("kanban-column")
        .filter({ hasText: backlog })
        .getByTestId("kanban-card")
        .filter({ hasText: liveStory });
      await bobLiveCard.click();
      await expect(bobPage.page.getByTestId("card-detail-modal")).toBeVisible({
        timeout: 30_000,
      });

      const meiLiveCard = backlogColumn.getByTestId("kanban-card").filter({ hasText: liveStory });
      await meiLiveCard.click();
      await expect(meiPage.page.getByTestId("card-detail-modal")).toBeVisible({
        timeout: 30_000,
      });
      await meiPage.page.getByTestId("card-detail-add-description-button").click();
      await setCardDetailEditorValue(meiPage.page, detailDescription);
      await meiPage.page.getByTestId("card-detail-save-button").click();
      await expect(meiPage.page.getByTestId("card-description-panel")).toContainText(
        detailDescription,
        { timeout: 30_000 },
      );
      await expect(bobPage.page.getByTestId("card-description-panel")).toContainText(
        detailDescription,
        { timeout: 60_000 },
      );

      await meiPage.page.getByTestId("card-detail-tab-synthesis").click();
      await meiPage.page.getByTestId("card-detail-new-synthesis-button").click();
      await setCardDetailEditorValue(meiPage.page, synthesisNote);
      await meiPage.page.getByTestId("card-detail-save-button").click();
      await expect(meiPage.page.getByTestId("card-synthesis-panel")).toContainText(synthesisNote, {
        timeout: 30_000,
      });
      await bobPage.page.getByTestId("card-detail-tab-synthesis").click();
      await expect(bobPage.page.getByTestId("card-synthesis-panel")).toContainText(synthesisNote, {
        timeout: 60_000,
      });

      await bobPage.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
      await expect(bobPage.page.getByTestId("board-space-select")).toHaveValue(boardId, {
        timeout: 30_000,
      });
      await bobPage.page
        .getByTestId("kanban-column")
        .filter({ hasText: backlog })
        .getByTestId("kanban-card")
        .filter({ hasText: liveStory })
        .click();
      await expect(bobPage.page.getByTestId("card-description-panel")).toContainText(
        detailDescription,
        { timeout: 60_000 },
      );
      await bobPage.page.getByTestId("card-detail-tab-synthesis").click();
      await expect(bobPage.page.getByTestId("card-synthesis-panel")).toContainText(synthesisNote, {
        timeout: 60_000,
      });
      await meiPage.page.getByTestId("card-detail-close-button").click();
      await expect(meiPage.page.getByTestId("card-detail-modal")).toBeHidden({
        timeout: 30_000,
      });

      for (const story of stories.slice(1)) {
        await backlogColumn.getByTestId("add-card-button").click();
        await backlogColumn.getByTestId("new-card-title-input").fill(story);
        await backlogColumn.getByTestId("save-card-button").click();
        await expect(
          backlogColumn.getByTestId("kanban-card").filter({ hasText: story }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await expect
        .poll(async () => flowTitlesForBoard(request, spaceId, meiToken, boardId), {
          timeout: 30_000,
        })
        .toEqual(expect.arrayContaining(stories));
      await stepShot(meiPage.page, testInfo, "D-mei-board-ready");

      for (const [actor, token] of [
        [bobPage, bobToken],
        [carolPage, carolToken],
      ] as const) {
        await actor.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
        await expect(actor.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
        await expect(actor.page.getByTestId("board-space-select")).toHaveValue(boardId, {
          timeout: 30_000,
        });
        for (const columnName of [backlog, todo, doing, done]) {
          await expect(
            actor.page.getByTestId("kanban-column").filter({ hasText: columnName }),
          ).toBeVisible({ timeout: 30_000 });
        }
        const hydratedBacklog = actor.page
          .getByTestId("kanban-column")
          .filter({ hasText: backlog });
        for (const story of stories) {
          await expect(
            hydratedBacklog.getByTestId("kanban-card").filter({ hasText: story }),
          ).toBeVisible({ timeout: 30_000 });
        }
        await expect
          .poll(async () => flowTitlesForBoard(request, spaceId, token, boardId), {
            timeout: 30_000,
          })
          .toEqual(expect.arrayContaining(stories));
      }
      await stepShot(bobPage.page, testInfo, "D-bob-board-hydrated");
      await stepShot(carolPage.page, testInfo, "D-carol-board-hydrated");
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), meiPage.close()]);
    }
  });

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

async function flowTitlesForBoard(
  request: APIRequestContext,
  spaceId: string,
  token: string,
  boardId: string,
): Promise<string[]> {
  const resp = await request.get(
    `${solandBaseUrl()}/_cokret/self/projection/flows?realm_id=${encodeURIComponent(spaceId)}`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  if (resp.status() !== 200) {
    return [];
  }
  const body = await resp.json();
  const flows = Array.isArray(body.flows)
    ? body.flows
    : Array.isArray(body.items)
      ? body.items
      : [];
  return flows
    .filter((flow: { board_space_id?: string }) => flow.board_space_id === boardId)
    .map((flow: { title?: string }) => flow.title)
    .filter((title: unknown): title is string => typeof title === "string")
    .sort();
}

async function setCardDetailEditorValue(page: Page, value: string): Promise<void> {
  const input = page.getByTestId("card-detail-description-input");
  await expect(input).toBeAttached({ timeout: 30_000 });
  await input.evaluate((node, nextValue) => {
    const textarea = node as HTMLTextAreaElement;
    textarea.value = nextValue;
    textarea.dispatchEvent(
      new InputEvent("input", {
        bubbles: true,
        inputType: "insertText",
        data: nextValue,
      }),
    );
  }, value);
}

// Sprint planning workflow — tech lead + two engineers commit to stories
// Contract: e2e/scenarios/workflows/sprint-planning.md
// Spec refs:
//   - models/realm-and-space.md §2-§4 (Space + Board + List)
//   - models/strand-and-message.md §8 (reply chain)
//
// Realistic story: Tech-lead Mei kicks off a sprint, two engineers reply
// claiming user stories. The kanban cross-user hydration path is live;
// multi-card promote Backlog→Todo remains fixme'd until the move UI is
// stable enough for the full scenario.

import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import { grantInviteConsentArkret } from "../../helpers/contact-api";
import { stepShot } from "../../helpers/screenshots";
import {
  openDpopUserPage,
  selfPathHeadersForDpopSession,
  type DpopUserSession,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: sprint planning", () => {
  test("mei kicks off sprint, bob + carol claim their stories via reply chain", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const encryptedSyncTimeout = 90_000;
    const [meiFlow, bobFlow, carolFlow] = await Promise.all([
      openDpopUserPage(browser, request, "wf-sprint-mei"),
      openDpopUserPage(browser, request, "wf-sprint-bob"),
      openDpopUserPage(browser, request, "wf-sprint-carol"),
    ]);
    test.skip(
      !meiFlow || !bobFlow || !carolFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!meiFlow || !bobFlow || !carolFlow) {
      return;
    }
    const bob = bobFlow.user;
    const carol = carolFlow.user;
    const meiPage = meiFlow.page;
    const bobPage = bobFlow.page;
    const carolPage = carolFlow.page;

    const kickoff = `Sprint 24 kickoff — Story A (auth), Story B (payments), Story C (analytics). Reply with your pick. ${stamp}`;
    const bobClaim = `I'll take Story A. ${stamp}`;
    const carolClaim = `I'll grab Story B. ${stamp}`;
    const meiClose = `Thanks both — I'll cover Story C. Regroup Friday. ${stamp}`;

    try {
      await Promise.all([
        grantInviteConsentArkret(
          request,
          bobFlow.session.grantJwt,
          bob,
          meiFlow.user.id,
        ),
        grantInviteConsentArkret(
          request,
          carolFlow.session.grantJwt,
          carol,
          meiFlow.user.id,
        ),
      ]);
      // Phase A — Mei spins up the sprint space with both engineers seeded.
      const realmId = await meiPage.createRealm({
        title: `Sprint 24 ${stamp}`,
        summary: "Sprint planning + claims",
        discoverability: "listed",
        joinRule: "invite",
        mlsActivated: false,
        seedMembers: [bob.id, carol.id],
      });
      await Promise.all([
        bobPage.acceptInvite(realmId),
        carolPage.acceptInvite(realmId),
      ]);
      await meiPage.grantRealmCapability(
        realmId,
        bobFlow.session.accountId,
        "ak.message.create",
      );
      await meiPage.grantRealmCapability(
        realmId,
        carolFlow.session.accountId,
        "ak.message.create",
      );
      await Promise.all([
        bobPage.gotoTimelineRealm(realmId),
        carolPage.gotoTimelineRealm(realmId),
      ]);
      await meiPage.sendTimelineMessage(realmId, kickoff);
      await stepShot(meiPage.page, testInfo, "A-kickoff");

      // Phase B — both engineers receive the kickoff and reply with claims.
      await bobPage.gotoTimelineRealm(realmId);
      await expect(bobPage.page.getByTestId("message-list")).toContainText(
        kickoff,
        {
          timeout: encryptedSyncTimeout,
        },
      );
      await bobPage.clickTimelineReply(kickoff);
      await expect(bobPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await bobPage.sendTimelineMessage(realmId, bobClaim);
      await expect(bobPage.timelineEvent(bobClaim)).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await expect(
        bobPage.timelineEvent(bobClaim).getByTestId("chat-reply-indicator"),
      ).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await stepShot(bobPage.page, testInfo, "B-bob-claimed");

      await carolPage.gotoTimelineRealm(realmId);
      await expect(carolPage.page.getByTestId("message-list")).toContainText(
        kickoff,
        {
          timeout: encryptedSyncTimeout,
        },
      );
      await carolPage.clickTimelineReply(kickoff);
      await expect(
        carolPage.page.getByTestId("chat-reply-banner"),
      ).toBeVisible();
      await carolPage.sendTimelineMessage(realmId, carolClaim);
      await expect(carolPage.timelineEvent(carolClaim)).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await expect(
        carolPage.timelineEvent(carolClaim).getByTestId("chat-reply-indicator"),
      ).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await stepShot(carolPage.page, testInfo, "B-carol-claimed");

      // Phase C — Mei closes the loop after seeing both claims arrive.
      await meiPage.gotoTimelineRealm(realmId);
      await expect(meiPage.timelineEvent(bobClaim)).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await expect(meiPage.timelineEvent(carolClaim)).toBeVisible({
        timeout: encryptedSyncTimeout,
      });
      await meiPage.sendTimelineMessage(realmId, meiClose);
      await stepShot(meiPage.page, testInfo, "C-loop-closed");

      // Both engineers see Mei's wrap-up.
      for (const eng of [bobPage, carolPage]) {
        await eng.gotoTimelineRealm(realmId);
        await expect(eng.timelineEvent(meiClose)).toBeVisible({
          timeout: encryptedSyncTimeout,
        });
      }
    } finally {
      await Promise.allSettled([
        carolPage.close(),
        bobPage.close(),
        meiPage.close(),
      ]);
    }
  });

  test("E-sprint.kanban mei builds a Backlog + Todo + Doing + Done kanban and promotes 3 stories", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const meiFlow = await openDpopUserPage(
      browser,
      request,
      "wf-sprint-batch-mei",
      { prepareMlsDevice: false },
    );
    test.skip(
      !meiFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!meiFlow) {
      return;
    }
    const meiPage = meiFlow.page;
    const backlog = `Backlog-${stamp}`;
    const todo = `Todo-${stamp}`;
    const doing = `Doing-${stamp}`;
    const done = `Done-${stamp}`;
    const boardTitle = `Sprint Batch Board ${stamp}`;
    // 5+ cards in one column — exercises the batch-ack draft-state path.
    const stories = Array.from(
      { length: 5 },
      (_, i) => `Story ${i + 1} (${stamp})`,
    );

    try {
      const realmId = await meiPage.createRealm({
        title: `Sprint batch ${stamp}`,
        summary: "Multi-card draft-state batch",
        discoverability: "listed",
        joinRule: "invite",
        mlsActivated: false,
      });

      await meiPage.page.goto(`/kanban/${realmId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(meiPage.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await meiPage.page.getByTestId("new-board-toggle").click();
      await meiPage.page.getByTestId("new-board-title-input").fill(boardTitle);
      await meiPage.page.getByTestId("create-board-space-button").click();
      await expect(
        meiPage.page.getByTestId("board-space-select-button"),
      ).toContainText(boardTitle, { timeout: 45_000 });

      for (const columnName of [backlog, todo, doing, done]) {
        await meiPage.page.getByTestId("new-column-input").fill(columnName);
        await meiPage.page.getByTestId("add-column-button").click();
        await expect(
          meiPage.page
            .getByTestId("kanban-column")
            .filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }

      const backlogColumn = meiPage.page
        .getByTestId("kanban-column")
        .filter({ hasText: backlog });

      // Add 5 cards back-to-back. inkson surfaces each card's draft-state
      // independently (data-card-draft) so the batch is observable even
      // before every create event acks. The composer intentionally stays open
      // after Save so consecutive cards can be entered without reopening it.
      await backlogColumn.getByTestId("add-card-button").click();
      for (const story of stories) {
        await backlogColumn.getByTestId("new-card-title-input").fill(story);
        await backlogColumn.getByTestId("save-card-button").click();
        await expect(
          backlogColumn.getByTestId("kanban-card").filter({ hasText: story }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await stepShot(meiPage.page, testInfo, "batch-A-queued");

      // Every card eventually settles out of draft (the batch acks). Each
      // card exposes its own `data-card-draft="false"` so the promote /
      // archive flow can act on the whole column once it settles.
      for (const story of stories) {
        const card = backlogColumn
          .getByTestId("kanban-card")
          .filter({ hasText: story });
        await expect(card).toHaveAttribute("data-card-draft", "false", {
          timeout: 90_000,
        });
      }
      await stepShot(meiPage.page, testInfo, "batch-B-settled");
    } finally {
      await meiPage.close();
    }
  });

  test("E-sprint.crossuser bob + carol see the same kanban as mei after she edits the board", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [meiFlow, bobFlow, carolFlow] = await Promise.all([
      openDpopUserPage(browser, request, "wf-sprint-kanban-mei"),
      openDpopUserPage(browser, request, "wf-sprint-kanban-bob"),
      openDpopUserPage(browser, request, "wf-sprint-kanban-carol"),
    ]);
    test.skip(
      !meiFlow || !bobFlow || !carolFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!meiFlow || !bobFlow || !carolFlow) {
      return;
    }
    const bob = bobFlow.user;
    const carol = carolFlow.user;
    const meiPage = meiFlow.page;
    const bobPage = bobFlow.page;
    const carolPage = carolFlow.page;

    const backlog = `Backlog-${stamp}`;
    const todo = `Todo-${stamp}`;
    const doing = `Doing-${stamp}`;
    const done = `Done-${stamp}`;
    const boardTitle = `Sprint Board ${stamp}`;
    const stories = [
      `Story A: User auth strand ${stamp}`,
      `Story B: Payment gateway integration ${stamp}`,
      `Story C: Analytics dashboard ${stamp}`,
    ];
    const detailDescription = `Remote description update from Mei ${stamp}`;
    const synthesisNote = `Remote synthesis note from Mei ${stamp}`;

    try {
      const realmId = await meiPage.createRealm({
        title: `Sprint board ${stamp}`,
        summary: "Cross-user kanban hydration",
        discoverability: "listed",
        joinRule: "invite",
        mlsActivated: false,
        seedMembers: [bob.id, carol.id],
      });
      await Promise.all([
        bobPage.acceptInvite(realmId),
        carolPage.acceptInvite(realmId),
      ]);
      await Promise.all([
        bobPage.gotoTimelineRealm(realmId),
        carolPage.gotoTimelineRealm(realmId),
      ]);

      await meiPage.page.goto(`/kanban/${realmId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(meiPage.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await meiPage.page.getByTestId("new-board-toggle").click();
      await meiPage.page.getByTestId("new-board-title-input").fill(boardTitle);
      await meiPage.page.getByTestId("create-board-space-button").click();
      await expect(
        meiPage.page.getByTestId("kanban-empty-board"),
      ).toContainText(/No lists yet/, {
        timeout: 30_000,
      });
      await expect
        .poll(
          async () =>
            boardSpaceIdByTitle(request, realmId, meiFlow.session, boardTitle),
          {
            timeout: 45_000,
          },
        )
        .toMatch(/^ak:space:/);
      const boardId = await boardSpaceIdByTitle(
        request,
        realmId,
        meiFlow.session,
        boardTitle,
      );
      expect(boardId).toMatch(/^ak:space:/);
      await expect(
        meiPage.page.getByTestId("board-space-select-button"),
      ).toContainText(boardTitle, {
        timeout: 30_000,
      });

      for (const columnName of [backlog, todo, doing, done]) {
        await meiPage.page.getByTestId("new-column-input").fill(columnName);
        await meiPage.page.getByTestId("add-column-button").click();
        await expect(
          meiPage.page
            .getByTestId("kanban-column")
            .filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }

      await bobPage.page.goto(`/kanban/${realmId}/board/${boardId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(bobPage.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await expect(
        bobPage.page.getByTestId("board-space-select-button"),
      ).toContainText(boardTitle, {
        timeout: 30_000,
      });
      await expect(
        bobPage.page.getByTestId("kanban-column").filter({ hasText: backlog }),
      ).toBeVisible({ timeout: 30_000 });

      const backlogColumn = meiPage.page
        .getByTestId("kanban-column")
        .filter({ hasText: backlog });
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
      await bobPage.clickWithPassivePromptRetry(bobLiveCard);
      await expect(bobPage.page.getByTestId("card-detail-modal")).toBeVisible({
        timeout: 30_000,
      });

      const meiLiveCard = backlogColumn
        .getByTestId("kanban-card")
        .filter({ hasText: liveStory });
      await meiPage.clickWithPassivePromptRetry(meiLiveCard);
      await expect(meiPage.page.getByTestId("card-detail-modal")).toBeVisible({
        timeout: 30_000,
      });
      await meiPage.page
        .getByTestId("card-detail-edit-description-button")
        .click();
      await setCardDetailEditorValue(meiPage.page, detailDescription);
      await meiPage.page.getByTestId("card-detail-save-button").click();
      await expect(
        meiPage.page.getByTestId("card-description-panel"),
      ).toContainText(detailDescription, { timeout: 30_000 });
      await expect(
        bobPage.page.getByTestId("card-description-panel"),
      ).toContainText(detailDescription, { timeout: 60_000 });

      await meiPage.page.getByTestId("card-detail-tab-synthesis").click();
      await meiPage.page
        .getByTestId("card-detail-new-synthesis-button")
        .click();
      await setCardDetailEditorValue(meiPage.page, synthesisNote);
      await meiPage.page.getByTestId("card-detail-save-button").click();
      await expect(
        meiPage.page.getByTestId("card-synthesis-panel"),
      ).toContainText(synthesisNote, {
        timeout: 30_000,
      });
      await bobPage.page.getByTestId("card-detail-tab-synthesis").click();
      await expect(
        bobPage.page.getByTestId("card-synthesis-panel"),
      ).toContainText(synthesisNote, {
        timeout: 60_000,
      });

      await bobPage.page.goto(`/kanban/${realmId}/board/${boardId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(
        bobPage.page.getByTestId("board-space-select-button"),
      ).toContainText(boardTitle, {
        timeout: 30_000,
      });
      await bobPage.page
        .getByTestId("kanban-column")
        .filter({ hasText: backlog })
        .getByTestId("kanban-card")
        .filter({ hasText: liveStory })
        .click();
      await expect(
        bobPage.page.getByTestId("card-description-panel"),
      ).toContainText(detailDescription, { timeout: 60_000 });
      await bobPage.page.getByTestId("card-detail-tab-synthesis").click();
      await expect(
        bobPage.page.getByTestId("card-synthesis-panel"),
      ).toContainText(synthesisNote, {
        timeout: 60_000,
      });
      await meiPage.page.getByTestId("card-detail-close-button").click();
      await expect(meiPage.page.getByTestId("card-detail-modal")).toBeHidden({
        timeout: 30_000,
      });

      // M1 continuous create keeps the cleared composer open until Cancel.
      // Opening card details must not discard that existing creation flow.
      await expect(backlogColumn.getByTestId("new-card-title-input")).toBeVisible();
      for (const story of stories.slice(1)) {
        await backlogColumn.getByTestId("new-card-title-input").fill(story);
        await backlogColumn.getByTestId("save-card-button").click();
        await expect(
          backlogColumn.getByTestId("kanban-card").filter({ hasText: story }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await expect
        .poll(
          async () =>
            strandTitlesForBoard(request, realmId, meiFlow.session, boardId),
          {
            timeout: 30_000,
          },
        )
        .toEqual(expect.arrayContaining(stories));
      await stepShot(meiPage.page, testInfo, "D-mei-board-ready");

      for (const [actor, token] of [
        [bobPage, bobFlow.session],
        [carolPage, carolFlow.session],
      ] as const) {
        await actor.page.goto(`/kanban/${realmId}/board/${boardId}`, {
          waitUntil: "domcontentloaded",
        });
        await expect(actor.page.getByTestId("kanban-panel")).toBeVisible({
          timeout: 120_000,
        });
        await expect(
          actor.page.getByTestId("board-space-select-button"),
        ).toContainText(boardTitle, {
          timeout: 30_000,
        });
        for (const columnName of [backlog, todo, doing, done]) {
          await expect(
            actor.page
              .getByTestId("kanban-column")
              .filter({ hasText: columnName }),
          ).toBeVisible({ timeout: 30_000 });
        }
        const hydratedBacklog = actor.page
          .getByTestId("kanban-column")
          .filter({ hasText: backlog });
        for (const story of stories) {
          await expect(
            hydratedBacklog
              .getByTestId("kanban-card")
              .filter({ hasText: story }),
          ).toBeVisible({ timeout: 30_000 });
        }
        await expect
          .poll(
            async () => strandTitlesForBoard(request, realmId, token, boardId),
            {
              timeout: 30_000,
            },
          )
          .toEqual(expect.arrayContaining(stories));
      }
      await stepShot(bobPage.page, testInfo, "D-bob-board-hydrated");
      await stepShot(carolPage.page, testInfo, "D-carol-board-hydrated");
    } finally {
      await Promise.allSettled([
        carolPage.close(),
        bobPage.close(),
        meiPage.close(),
      ]);
    }
  });

  test("E-sprint.archiveboard mei archives the entire sprint board at end of week", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const meiFlow = await openDpopUserPage(
      browser,
      request,
      "wf-sprint-archive-mei",
    );
    test.skip(
      !meiFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!meiFlow) {
      return;
    }
    const meiPage = meiFlow.page;
    const column = `Backlog-${stamp}`;
    const boardTitle = `Closeout Board ${stamp}`;
    const cards = [`Story A ${stamp}`, `Story B ${stamp}`];

    try {
      const realmId = await meiPage.createRealm({
        title: `Sprint archive ${stamp}`,
        summary: "End-of-week bulk archive + cascade",
        discoverability: "listed",
        joinRule: "invite",
        mlsActivated: false,
      });

      await meiPage.page.goto(`/kanban/${realmId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(meiPage.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await meiPage.page.getByTestId("new-board-toggle").click();
      await meiPage.page.getByTestId("new-board-title-input").fill(boardTitle);
      await meiPage.page.getByTestId("create-board-space-button").click();
      await expect(
        meiPage.page.getByTestId("board-space-select-button"),
      ).toContainText(boardTitle, { timeout: 45_000 });

      await meiPage.page.getByTestId("new-column-input").fill(column);
      await meiPage.page.getByTestId("add-column-button").click();
      const backlogColumn = meiPage.page
        .getByTestId("kanban-column")
        .filter({ hasText: column });
      await expect(backlogColumn).toBeVisible({ timeout: 30_000 });

      await backlogColumn.getByTestId("add-card-button").click();
      const cardTitleInput = backlogColumn.getByTestId("new-card-title-input");
      // M1 continuous create retains the composer and clears it after Save.
      for (const card of cards) {
        await expect(cardTitleInput).toBeVisible();
        await cardTitleInput.fill(card);
        await backlogColumn.getByTestId("save-card-button").click();
        await expect(cardTitleInput).toHaveValue("");
        const cardLocator = backlogColumn
          .getByTestId("kanban-card")
          .filter({ hasText: card });
        await expect(cardLocator).toBeVisible({ timeout: 30_000 });
        await expect(cardLocator).toHaveAttribute("data-card-draft", "false", {
          timeout: 90_000,
        });
      }
      await stepShot(meiPage.page, testInfo, "archiveboard-A-ready");

      // Bulk archive the whole board: cascade-archive every active card +
      // list, then the board Space itself. The button opens a confirmation
      // dialog first; the cascade only fires from the confirm button.
      await meiPage.page.getByTestId("archive-board-button").click();
      await meiPage.page.getByTestId("archive-board-confirm-button").click();

      // Cascade: cards and the column drop out of the active board view.
      for (const card of cards) {
        await expect(
          meiPage.page.getByTestId("kanban-card").filter({ hasText: card }),
        ).toHaveCount(0, { timeout: 90_000 });
      }
      await expect(
        meiPage.page.getByTestId("kanban-column").filter({ hasText: column }),
      ).toHaveCount(0, { timeout: 90_000 });
      await stepShot(meiPage.page, testInfo, "archiveboard-B-cascaded");
    } finally {
      await meiPage.close();
    }
  });
});

async function boardSpaceIdByTitle(
  request: APIRequestContext,
  realmId: string,
  session: DpopUserSession,
  title: string,
): Promise<string> {
  const url = `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/spaces`;
  const resp = await request.get(url, {
    headers: selfPathHeadersForDpopSession(session, "GET", url),
  });
  if (resp.status() !== 200) {
    return "";
  }
  const body = await resp.json();
  const spaces = body.spaces ?? [];
  const board = spaces.find(
    (space: { kind?: string; space_id?: string; title?: string }) =>
      space.kind === "board" && space.title === title,
  );
  return typeof board?.space_id === "string" ? board.space_id : "";
}

async function strandTitlesForBoard(
  request: APIRequestContext,
  realmId: string,
  session: DpopUserSession,
  boardId: string,
): Promise<string[]> {
  const url = `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/strands`;
  const resp = await request.get(url, {
    headers: selfPathHeadersForDpopSession(session, "GET", url),
  });
  if (resp.status() !== 200) {
    return [];
  }
  const body = await resp.json();
  const strands = body.strands ?? [];
  return strands
    .filter(
      (strand: { board_space_id?: string }) =>
        strand.board_space_id === boardId,
    )
    .map((strand: { title?: string }) => strand.title)
    .filter((title: unknown): title is string => typeof title === "string")
    .sort();
}

async function setCardDetailEditorValue(
  page: Page,
  value: string,
): Promise<void> {
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

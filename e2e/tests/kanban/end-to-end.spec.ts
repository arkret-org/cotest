// Kanban end-to-end
// Contract: e2e/scenarios/kanban/end-to-end.md
// Spec refs:
//   - models/space-and-place.md §4 (Place), §4.5-§4.6 (cas-register basis), §4.7 (Board/List)
//   - models/flow-and-message.md §2-§3 (Flow), §4.3 (discussion track)
//   - models/relation.md §3.2 (contains)

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("kanban end-to-end", () => {
  test("alice builds Board → 3 Lists → 2 Cards → drags Card to In Progress → archives → comments", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s15-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const spaceId = await alicePage.createSpace({
        title: `S15 Kanban ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      // Phase B — build Board (route is yougen's kanban view; testid 探查)
      await alicePage.page.goto(`/kanban`, { waitUntil: "domcontentloaded" });
      // 兜底:某些 yougen 部署 /kanban 是 space-scoped。如果首页没有 new-board-button,
      // 试 space-scoped 路径。
      const newBoardButton = alicePage.page.getByTestId("new-board-button");
      if ((await newBoardButton.count()) === 0) {
        await alicePage.page.goto(`/spaces/${spaceId}/kanban`, { waitUntil: "domcontentloaded" });
      }
      await alicePage.page.getByTestId("new-board-button").click();
      await alicePage.page.getByTestId("board-title-input").fill(`Sprint ${stamp}`);
      await alicePage.page.getByTestId("create-board-button").click();
      const boardCard = alicePage.page.getByTestId("board-card").filter({ hasText: `Sprint ${stamp}` }).first();
      await expect(boardCard).toBeVisible({ timeout: 30_000 });
      await boardCard.click();
      await stepShot(alicePage.page, testInfo, "B-board-open");

      // Phase C — add three Lists
      for (const listName of ["Todo", "In Progress", "Done"]) {
        await alicePage.page.getByTestId("add-list-button").click();
        await alicePage.page.getByTestId("list-title-input").fill(listName);
        await alicePage.page.getByTestId("create-list-button").click();
        await expect(
          alicePage.page.getByTestId("list-column").filter({ hasText: listName }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await stepShot(alicePage.page, testInfo, "C-three-lists");

      // Phase D — add two Cards in Todo
      const todoColumn = alicePage.page.getByTestId("list-column").filter({ hasText: "Todo" }).first();
      for (const cardName of ["Card A", "Card B"]) {
        await todoColumn.getByTestId("add-card-button").click();
        await alicePage.page.getByTestId("card-title-input").fill(cardName);
        await alicePage.page.getByTestId("create-card-button").click();
        await expect(todoColumn.getByTestId("flow-card").filter({ hasText: cardName })).toBeVisible({
          timeout: 30_000,
        });
      }

      // Phase E — drag Card A to In Progress
      const cardA = todoColumn.getByTestId("flow-card").filter({ hasText: "Card A" }).first();
      const inProgressColumn = alicePage.page
        .getByTestId("list-column")
        .filter({ hasText: "In Progress" })
        .first();
      await cardA.dragTo(inProgressColumn);
      await expect(inProgressColumn.getByTestId("flow-card").filter({ hasText: "Card A" })).toBeVisible({
        timeout: 30_000,
      });
      await expect(todoColumn.getByTestId("flow-card").filter({ hasText: "Card A" })).toHaveCount(0);
      await stepShot(alicePage.page, testInfo, "E-card-dragged");

      // Phase F — comment on Card A
      await inProgressColumn.getByTestId("flow-card").filter({ hasText: "Card A" }).first().click();
      await alicePage.page.getByTestId("discussion-composer-input").fill(`started this morning ${stamp}`);
      await alicePage.page.getByTestId("discussion-send-button").click();
      await expect(
        alicePage.page.getByTestId("discussion-message").filter({ hasText: `started this morning ${stamp}` }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "F-comment-added");

      // Phase G — archive Card A
      await alicePage.page.getByTestId("archive-card-button").click();
      await alicePage.page.getByTestId("confirm-archive-button").click();
      // back to board; Card A should be gone from main view
      await alicePage.page.goBack();
      await expect(inProgressColumn.getByTestId("flow-card").filter({ hasText: "Card A" })).toHaveCount(0);
      await stepShot(alicePage.page, testInfo, "G-card-archived");
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(
    "E15.1 concurrent cross-list move: cas-register accepts one winner, rejects the other with cas_register_conflict",
    async () => {
      // spec: space-and-place.md §4.6 cx.flow.move cas-register basis
      // soland gap: cas-register conflict resolution + ordered-log child_order projection.
    },
  );

  test.fixme(
    "E15.2 cross-space contains relation rejected with reason=cross_space_structural_relation",
    async () => {
      // spec: models/relation.md §3.2
    },
  );

  test.fixme(
    "E15.5 commenting on an archived flow is rejected by reducer (no writes on archived Flow)",
    async () => {
      // spec: space-and-place.md §4.6 archived state write constraints
    },
  );

  test.fixme("E15.H reordering lists (drag column) updates board's child_order cell", async () => {
    // spec: space-and-place.md §4.5 cas-register basis
  });
});

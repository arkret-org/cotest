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
  test("alice opens kanban, adds 3 columns, adds 2 cards in Todo, archives Card A, restores it", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("kanban-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    const cardA = `Card A ${stamp}`;
    const cardB = `Card B ${stamp}`;

    try {
      // Create a space so the kanban view has a selected_space context.
      const spaceId = await alicePage.createSpace({
        title: `Kanban Space ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });
      // Kanban scopes writes to selected_space; navigate with the explicit
      // space_id so the route resolves to the freshly-created space (plain
      // `/kanban` falls back to the first preview, which on a fresh session
      // is the hardcoded demo space the test user is NOT a member of, and
      // every cx.flow.* event would 403 with capability_denied).
      await alicePage.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await stepShot(alicePage.page, testInfo, "A-kanban-open");

      // Add three columns (lists).
      for (const columnName of [`Todo-${stamp}`, `InProgress-${stamp}`, `Done-${stamp}`]) {
        await alicePage.page.getByTestId("new-column-input").fill(columnName);
        await alicePage.page.getByTestId("add-column-button").click();
        await expect(
          alicePage.page.getByTestId("kanban-column").filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await stepShot(alicePage.page, testInfo, "B-three-columns");

      const todoColumn = alicePage.page
        .getByTestId("kanban-column")
        .filter({ hasText: `Todo-${stamp}` })
        .first();

      // Add two cards in Todo. Each "add-card-button" click reveals the
      // new-card-title-input; fill + save.
      for (const cardName of [cardA, cardB]) {
        await todoColumn.getByTestId("add-card-button").click();
        await todoColumn.getByTestId("new-card-title-input").fill(cardName);
        await todoColumn.getByTestId("save-card-button").click();
        await expect(
          todoColumn.getByTestId("kanban-card").filter({ hasText: cardName }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await stepShot(alicePage.page, testInfo, "C-two-cards");

      // Archive Card A → it should disappear from the active column.
      await todoColumn
        .getByTestId("kanban-card")
        .filter({ hasText: cardA })
        .first()
        .getByTestId("card-archive-button")
        .click();
      await expect(todoColumn.getByTestId("kanban-card").filter({ hasText: cardA })).toHaveCount(0, {
        timeout: 30_000,
      });
      // Card A appears in archived list.
      await expect(
        alicePage.page.getByTestId("kanban-archived-card-row").filter({ hasText: cardA }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "D-card-archived");

      // Restore Card A from archive — it should reappear on the board.
      const archivedRow = alicePage.page
        .getByTestId("kanban-archived-card-row")
        .filter({ hasText: cardA })
        .first();
      await archivedRow.getByTestId("card-restore-button").click();
      await expect(
        alicePage.page.getByTestId("kanban-card").filter({ hasText: cardA }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "E-card-restored");
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(
    "concurrent cross-list move: cas-register accepts one winner, rejects the other with cas_register_conflict",
    async () => {
      // spec: space-and-place.md §4.6 cx.flow.move cas-register basis
    },
  );

  test.fixme(
    "cross-space contains relation rejected with reason=cross_space_structural_relation",
    async () => {
      // spec: models/relation.md §3.2
    },
  );

  test.fixme(
    "commenting on an archived flow is rejected by reducer (no writes on archived Flow)",
    async () => {
      // spec: space-and-place.md §4.6 archived state write constraints
    },
  );

  test.fixme("reordering lists (drag column) updates board's child_order cell", async () => {
    // spec: space-and-place.md §4.5 cas-register basis
  });
});

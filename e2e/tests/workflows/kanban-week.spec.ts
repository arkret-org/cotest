// Kanban week-in-review workflow — single user runs a day on the board
// Contract: e2e/scenarios/workflows/kanban-week.md
// Spec refs:
//   - models/space-and-place.md §4 (Place / Board / List)
//   - models/space-and-place.md §4.4 (lifecycle / archive cascade)
//
// Realistic story: PM Pat plans their day on the kanban: four tasks in
// Today, archives two as done, then restores one that was archived by
// mistake. Single-user to stay on the proven kanban CRUD surface; cross-
// user kanban sync lives in workflows/sprint-planning fixme'd cases.

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: kanban week-in-review", () => {
  test("pat plans 4 tasks, archives 2 as done, restores 1 that was archived by mistake", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const pat = uniqueUser("wf-kanban-pat");
    await ensureRegistered(request, pat);
    const patToken = await issueDevSession(request, pat);
    const patPage = await openUserPage(browser, pat, { sessionToken: patToken });

    const todayList = `Today-${stamp}`;
    const doingList = `Doing-${stamp}`;
    const doneList = `Done-${stamp}`;
    const triageTask = `Triage support inbox ${stamp}`;
    const prTask = `Review PR backlog ${stamp}`;
    const specTask = `Spec the Q4 roadmap doc ${stamp}`;
    const planTask = `Plan tomorrow's standup agenda ${stamp}`;

    try {
      // Phase A — kanban opens against a fresh space. Navigate with the
      // explicit space_id so writes route to this space; plain `/kanban`
      // falls back to the hardcoded demo space the test user is not a
      // member of, and every cx.flow.* event would 403.
      const spaceId = await patPage.createSpace({
        title: `Week 21 ops ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });
      await patPage.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
      await expect(patPage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });

      for (const columnName of [todayList, doingList, doneList]) {
        await patPage.page.getByTestId("new-column-input").fill(columnName);
        await patPage.page.getByTestId("add-column-button").click();
        await expect(
          patPage.page.getByTestId("kanban-column").filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await stepShot(patPage.page, testInfo, "A-board-ready");

      // Phase B — load Today with four real tasks.
      const today = patPage.page
        .getByTestId("kanban-column")
        .filter({ hasText: todayList })
        .first();
      for (const task of [triageTask, prTask, specTask, planTask]) {
        await today.getByTestId("add-card-button").click();
        await today.getByTestId("new-card-title-input").fill(task);
        await today.getByTestId("save-card-button").click();
        await expect(today.getByTestId("kanban-card").filter({ hasText: task })).toBeVisible({
          timeout: 30_000,
        });
      }
      await stepShot(patPage.page, testInfo, "B-four-tasks");

      // Phase C — archive two finished tasks.
      for (const finished of [triageTask, planTask]) {
        await today
          .getByTestId("kanban-card")
          .filter({ hasText: finished })
          .first()
          .getByTestId("card-archive-button")
          .click();
        await expect(today.getByTestId("kanban-card").filter({ hasText: finished })).toHaveCount(
          0,
          { timeout: 30_000 },
        );
        await expect(
          patPage.page.getByTestId("kanban-archived-card-row").filter({ hasText: finished }),
        ).toBeVisible({ timeout: 30_000 });
      }
      // Today should still hold the two real-work tasks.
      await expect(today.getByTestId("kanban-card").filter({ hasText: prTask })).toBeVisible({
        timeout: 30_000,
      });
      await expect(today.getByTestId("kanban-card").filter({ hasText: specTask })).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(patPage.page, testInfo, "C-two-done");

      // Phase D — Pat archives prTask by mistake, then restores it.
      await today
        .getByTestId("kanban-card")
        .filter({ hasText: prTask })
        .first()
        .getByTestId("card-archive-button")
        .click();
      await expect(today.getByTestId("kanban-card").filter({ hasText: prTask })).toHaveCount(0, {
        timeout: 30_000,
      });
      const archivedRow = patPage.page
        .getByTestId("kanban-archived-card-row")
        .filter({ hasText: prTask })
        .first();
      await archivedRow.getByTestId("card-restore-button").click();
      await expect(
        patPage.page.getByTestId("kanban-card").filter({ hasText: prTask }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(patPage.page, testInfo, "D-restored");
    } finally {
      await patPage.close();
    }
  });

  test.fixme(
    // @blocking-on: soland#workflows-kanban-week-gap
    // @user-promise: e2e/scenarios/workflows/kanban-week.md
    // @expected-live-by: 2026Q3
    "E-kanbanweek.1 restored card lands at the end of its original column, preserving rank",
    async () => {
      // yougen behavior: card-restore-button currently puts the card back in
      // its column but rank ordering after restore needs verification.
    },
  );

  test.fixme(
    // @blocking-on: soland#workflows-kanban-week-gap
    // @user-promise: e2e/scenarios/workflows/kanban-week.md
    // @expected-live-by: 2026Q3
    "E-kanbanweek.2 archive an entire list (column-level archive button)",
    async () => {
      // list-archive-button exists in yougen but its UX semantics + cascade
      // to contained cards isn't covered by an existing test.
    },
  );
});

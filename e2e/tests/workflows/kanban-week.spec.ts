// Kanban week-in-review workflow — single user runs a day on the board
// Contract: e2e/scenarios/workflows/kanban-week.md
// Spec refs:
//   - models/realm-and-space.md §3 (Space containers / Board / List)
//   - common-fields.md §5.1 (lifecycle / archive cascade)
//
// Realistic story: PM Pat plans their day on the kanban: four tasks in
// Today, archives two as done, then restores one that was archived by
// mistake. Single-user to stay on the proven kanban CRUD surface; cross-
// user kanban sync lives in workflows/sprint-planning fixme'd cases.

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
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
      // Phase A — kanban opens against a fresh Realm. Navigate with the
      // explicit realm_id so writes route to this Realm; plain `/kanban`
      // falls back to the hardcoded demo Realm the test user is not a
      // member of, and every ck.strand.* event would 403.
      const realmId = await patPage.createRealm({
        title: `Week 21 ops ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });
      await patPage.page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
      await expect(patPage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await patPage.page.getByTestId("new-board-toggle").click();
      await patPage.page
        .getByTestId("new-board-title-input")
        .fill(`Week 21 board ${stamp}`);
      await patPage.page.getByTestId("create-board-space-button").click();
      await expect(patPage.page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
        timeout: 30_000,
      });

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
      const prStrandId = await today
        .getByTestId("kanban-card")
        .filter({ hasText: prTask })
        .first()
        .getByTestId("card-archive-button")
        .getAttribute("data-strand-id");
      const specStrandId = await today
        .getByTestId("kanban-card")
        .filter({ hasText: specTask })
        .first()
        .getByTestId("card-archive-button")
        .getAttribute("data-strand-id");
      const prStrandIdValue = prStrandId ?? "";
      const specStrandIdValue = specStrandId ?? "";
      expect(prStrandIdValue).toMatch(/^ck:strand:/);
      expect(specStrandIdValue).toMatch(/^ck:strand:/);
      await stepShot(patPage.page, testInfo, "B-four-tasks");

      // Phase C — archive two finished tasks.
      // The card-archive-button is hover-revealed (hidden until the user
      // hovers the parent .board-card), so hover the card first before
      // clicking the now-actionable button.
      for (const finished of [triageTask, planTask]) {
        const finishedCard = today
          .getByTestId("kanban-card")
          .filter({ hasText: finished })
          .first();
        await finishedCard.hover();
        await finishedCard.getByTestId("card-archive-button").click();
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
      const prCard = today
        .getByTestId("kanban-card")
        .filter({ hasText: prTask })
        .first();
      await prCard.hover();
      await prCard.getByTestId("card-archive-button").click();
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
      const restoredTitles = await today.getByTestId("kanban-card").allTextContents();
      const restoredPrIndex = restoredTitles.findIndex((title) => title.includes(prTask));
      const restoredSpecIndex = restoredTitles.findIndex((title) => title.includes(specTask));
      expect(restoredPrIndex).toBeGreaterThanOrEqual(0);
      expect(restoredSpecIndex).toBeGreaterThanOrEqual(0);
      expect(restoredPrIndex).toBeLessThan(restoredSpecIndex);
      await stepShot(patPage.page, testInfo, "D-restored");

      // Phase E — archive an entire list and verify soland cascades the card
      // lifecycle while preserving the original card rank for restore.
      const todayListId = await today
        .getByTestId("list-archive-button")
        .getAttribute("data-space-container-id");
      expect(todayListId ?? "").toMatch(/^ck:space:/);
      await expect
        .poll(async () => strandState(request, realmId, patToken, prStrandIdValue))
        .toBe("active");
      await expect
        .poll(async () => strandState(request, realmId, patToken, specStrandIdValue))
        .toBe("active");

      // list-archive-button is hover-revealed on the column header — hover
      // the column itself first so the button becomes actionable.
      await today.hover();
      await today.getByTestId("list-archive-button").click();
      const archivedLists = patPage.page.getByTestId("kanban-archived-lists");
      await archivedLists.locator("summary").click();
      await expect(
        patPage.page.getByTestId("kanban-archived-list-row").filter({ hasText: todayList }),
      ).toBeVisible({ timeout: 30_000 });
      await expect
        .poll(async () => strandState(request, realmId, patToken, prStrandIdValue), {
          timeout: 30_000,
        })
        .toBe("archived");
      await expect
        .poll(async () => strandState(request, realmId, patToken, specStrandIdValue), {
          timeout: 30_000,
        })
        .toBe("archived");

      await archivedLists
        .getByTestId("kanban-archived-list-row")
        .filter({ hasText: todayList })
        .first()
        .getByTestId("list-restore-button")
        .click();
      await expect(
        patPage.page.getByTestId("kanban-column").filter({ hasText: todayList }),
      ).toBeVisible({ timeout: 30_000 });
      await expect
        .poll(async () => strandState(request, realmId, patToken, prStrandIdValue), {
          timeout: 30_000,
        })
        .toBe("active");
      await expect
        .poll(async () => strandState(request, realmId, patToken, specStrandIdValue), {
          timeout: 30_000,
        })
        .toBe("active");
      await stepShot(patPage.page, testInfo, "E-list-restored");
    } finally {
      await patPage.close();
    }
  });
});

async function strandState(
  request: APIRequestContext,
  realmId: string,
  token: string,
  strandId: string,
): Promise<string | undefined> {
  const resp = await request.get(
    `${solandBaseUrl()}/_cokret/self/projection/strands?realm_id=${encodeURIComponent(realmId)}&include_terminal=true`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  if (resp.status() !== 200) {
    return undefined;
  }
  const body = await resp.json();
  const strands = Array.isArray(body.strands) ? body.strands : Array.isArray(body.items) ? body.items : [];
  return strands.find((strand: { strand_id?: string }) => strand.strand_id === strandId)?.state;
}

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

import {
  expect,
  test,
  type APIRequestContext,
  type Locator,
} from "../../helpers/arkret-test";
import { createRealmViaApi } from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import { canonicalJson } from "../../helpers/soland-api";
import {
  openDpopUserPage,
  selfPathHeadersForDpopSession,
  type DpopUserSession,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

async function readRealmEvents(
  request: APIRequestContext,
  realmId: string,
  session: DpopUserSession,
): Promise<Array<Record<string, unknown>>> {
  const url = `${solandBaseUrl()}/_arkret/self/events`;
  const response = await request.fetch(url, {
    method: "QUERY",
    headers: {
      ...selfPathHeadersForDpopSession(session, "QUERY", url),
      "content-type": "application/json",
    },
    data: canonicalJson({ limit: 256, realms: [realmId] }),
  });
  expect(response.status(), await response.text()).toBe(200);
  const body = (await response.json()) as {
    events?: Array<Record<string, unknown>>;
  };
  return (body.events ?? []).map((row) => {
    const event = row.event;
    return event && typeof event === "object"
      ? (event as Record<string, unknown>)
      : row;
  });
}

async function addCardThroughColumn(column: Locator, title: string): Promise<void> {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const titleInput = column.getByTestId("new-card-title-input").last();
    if (!(await titleInput.isVisible({ timeout: 250 }).catch(() => false))) {
      const addButton = column.getByTestId("add-card-button").last();
      await expect(addButton).toBeVisible({ timeout: 30_000 });
      await addButton.click({ timeout: 5_000 }).catch(async (error) => {
        if (!(await titleInput.isVisible({ timeout: 500 }).catch(() => false))) {
          throw error;
        }
      });
    }
    await expect(titleInput).toBeVisible({ timeout: 30_000 });
    await titleInput.fill(title);
    const saveButton = column.getByTestId("save-card-button").last();
    if (await saveButton.isEnabled({ timeout: 2_000 }).catch(() => false)) {
      try {
        await saveButton.evaluate((button: HTMLButtonElement) => button.click());
        return;
      } catch (error) {
        if (await column.getByText(title, { exact: true }).isVisible({ timeout: 500 }).catch(() => false)) {
          return;
        }
        if (attempt === 3) {
          throw error;
        }
      }
    }
  }
  throw new Error(`card editor was repeatedly replaced before saving ${title}`);
}

async function waitForCanonicalStrandId(
  request: APIRequestContext,
  realmId: string,
  session: DpopUserSession,
  card: Locator,
  title: string,
): Promise<string> {
  let strandId = "";
  await expect
    .poll(
      async () => {
        const event = (await readRealmEvents(request, realmId, session)).find(
          (candidate) => {
            if (candidate.kind !== "ak.strand.create") {
              return false;
            }
            const payload = candidate.payload as
              | { object?: { metadata?: { title?: unknown } } }
              | undefined;
            return payload?.object?.metadata?.title === title;
          },
        );
        const eventId = typeof event?.event_id === "string" ? event.event_id : "";
        strandId = eventId.startsWith("ak:event:")
          ? `ak:strand:${eventId.slice("ak:event:".length)}`
          : "";
        return strandId;
      },
      { timeout: 120_000 },
    )
    .toMatch(/^ak:strand:/);
  await expect
    .poll(
      () =>
        card
          .getByTestId("card-archive-button")
          .getAttribute("data-strand-id"),
      { timeout: 120_000 },
    )
    .toBe(strandId);
  return strandId;
}

test.describe("workflow: kanban week-in-review", () => {
  test("pat plans 4 tasks, archives 2 as done, restores 1 that was archived by mistake", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const patFlow = await openDpopUserPage(browser, request, "wf-kanban-pat", {
      prepareMlsDevice: false,
    });
    test.skip(
      !patFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!patFlow) {
      return;
    }
    const patPage = patFlow.page;

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
      // member of, and every ak.strand.* event would 403.
      const realmId = await createRealmViaApi(request, patFlow.session.grantJwt, {
        title: `Week 21 ops ${stamp}`,
        discoverability: "listed",
        encryptionProfile: "none",
        ownerDid: patFlow.user.did,
      });
      await patPage.page.evaluate((path) => {
        window.history.pushState({}, "", path);
        window.dispatchEvent(new PopStateEvent("popstate"));
      }, `/kanban/${realmId}`);
      await expect(patPage.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await patPage.page
        .getByTestId("new-board-toggle")
        .evaluate((button: HTMLButtonElement) => button.click());
      await patPage.page
        .getByTestId("new-board-title-input")
        .fill(`Week 21 board ${stamp}`);
      await patPage.page.getByTestId("create-board-space-button").click();
      await expect(patPage.page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
        timeout: 30_000,
      });
      await expect(patPage.page.getByTestId("add-column-button")).toBeEnabled({
        timeout: 120_000,
      });
      let boardCreate: Record<string, unknown> | undefined;
      await expect
        .poll(async () => {
          const events = await readRealmEvents(request, realmId, patFlow.session);
          boardCreate = events.find((event) => event.kind === "ak.space.create");
          return boardCreate !== undefined;
        })
        .toBe(true);
      expect(boardCreate?.seal_ref, "Board create is a Data Event").toEqual(
        expect.stringMatching(/^ak:seal:/),
      );
      expect(boardCreate?.auth_context, "Board create carries Data Event auth context").toEqual(
        expect.any(Object),
      );
      expect(boardCreate?.seal_basis, "Board create never enters Control Move shape").toBeUndefined();

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
        await addCardThroughColumn(today, task);
        await expect(today.getByTestId("kanban-card").filter({ hasText: task })).toBeVisible({
          timeout: 30_000,
        });
      }
      for (const task of [triageTask, prTask, specTask, planTask]) {
        const card = today.getByTestId("kanban-card").filter({ hasText: task }).first();
        await waitForCanonicalStrandId(
          request,
          realmId,
          patFlow.session,
          card,
          task,
        );
      }
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
      expect(todayListId ?? "").toMatch(/^ak:space:/);

      // list-archive-button is hover-revealed on the column header — hover
      // the column itself first so the button becomes actionable. Clicking
      // it opens a confirmation dialog; the archive submits from confirm.
      await today.hover();
      await today.getByTestId("list-archive-button").click();
      await patPage.page.getByTestId("list-archive-confirm-button").click();
      const archivedLists = patPage.page.getByTestId("kanban-archived-lists");
      await archivedLists.locator("summary").click();
      await expect(
        patPage.page.getByTestId("kanban-archived-list-row").filter({ hasText: todayList }),
      ).toBeVisible({ timeout: 30_000 });
      await expect
        .poll(async () => {
          const events = await readRealmEvents(request, realmId, patFlow.session);
          return events.some((event) => event.kind === "ak.space.archive");
        }, {
          timeout: 30_000,
        })
        .toBe(true);

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
        .poll(async () => {
          const events = await readRealmEvents(request, realmId, patFlow.session);
          return events.some((event) => event.kind === "ak.space.restore");
        }, {
          timeout: 30_000,
        })
        .toBe(true);
      const controlMove = (await readRealmEvents(request, realmId, patFlow.session)).find(
        (event) => event.kind === "ak.space.archive" || event.kind === "ak.strand.archive",
      );
      expect(controlMove, "workflow emitted a real Control Move comparison event").toBeDefined();
      expect(controlMove?.seal_basis, "Control Move carries seal_basis").toEqual(
        expect.any(Object),
      );
      expect(controlMove?.seal_ref, "Control Move has no Data Event seal_ref").toBeUndefined();
      expect(controlMove?.auth_context, "Control Move has no Data Event auth context").toBeUndefined();
      await stepShot(patPage.page, testInfo, "E-list-restored");
    } finally {
      await patPage.close();
    }
  });
});

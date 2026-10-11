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
import { stepShot } from "../../helpers/screenshots";
import { decodeIngressEvents } from "../../helpers/event-ingress";
import { scanRealmStreamApi } from "../../helpers/coland-api";
import {
  openDpopUserPage,
  type DpopUserSession,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

async function readRealmEvents(
  request: APIRequestContext,
  realmId: string,
  session: DpopUserSession,
): Promise<Array<Record<string, unknown>>> {
  const scan = await scanRealmStreamApi(request, session.grantJwt, realmId, {
    limit: 256,
  });
  return scan.events;
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
        await saveButton.click({ timeout: 30_000 });
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
        mlsActivated: false,
        ownerId: patFlow.user.id,
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
        }, { timeout: 90_000 })
        .toBe(true);
      expect(boardCreate?.event_id, "Board create is an accepted Event").toMatch(/^ak:event:/);
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
          timeout: 90_000,
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

      // Phase E — archive an entire List and restore it. realm-and-space.md
      // section 3.4: Space archive moves only the List's own lifecycle; its
      // cards keep their state and placement, so restore brings them back.
      const todayListId = await today
        .getByTestId("list-archive-button")
        .getAttribute("data-space-container-id");
      expect(todayListId ?? "").toMatch(/^ak:space:/);

      // list-archive-button is hover-revealed on the column header — hover
      // the column itself first so the button becomes actionable. Clicking
      // it opens a confirmation dialog; the archive submits from confirm.
      await today.hover();
      await today.getByTestId("list-archive-button").click();
      const archiveWrite = patPage.page.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === "/_arkret/self/events" &&
          response.request().method() === "POST" &&
          decodeIngressEvents(response.request().postData()).some(
            (event) => event.kind === "ak.space.archive",
          ),
        { timeout: 90_000 },
      );
      await patPage.page.getByTestId("list-archive-confirm-button").click();
      const archiveResponse = await archiveWrite;
      expect(archiveResponse.status(), await archiveResponse.text()).toBeLessThan(400);
      const archivedLists = patPage.page.getByTestId("kanban-archived-lists");
      await archivedLists.locator("summary").click();
      await expect(
        patPage.page.getByTestId("kanban-archived-list-row").filter({ hasText: todayList }),
      ).toBeVisible({ timeout: 30_000 });
      const restoreWrite = patPage.page.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === "/_arkret/self/events" &&
          response.request().method() === "POST" &&
          decodeIngressEvents(response.request().postData()).some(
            (event) => event.kind === "ak.space.restore",
          ),
        { timeout: 90_000 },
      );
      await archivedLists
        .getByTestId("kanban-archived-list-row")
        .filter({ hasText: todayList })
        .first()
        .getByTestId("list-restore-button")
        .click();
      const restoreResponse = await restoreWrite;
      expect(restoreResponse.status(), await restoreResponse.text()).toBeLessThan(400);
      await expect(
        patPage.page.getByTestId("kanban-column").filter({ hasText: todayList }),
      ).toBeVisible({ timeout: 30_000 });
      // event-envelope.schema.json is closed: the archive is an ordinary
      // producer-signed Event whose payload names only the Space
      // (space_state_transition_payload); it carries no seal or auth basis.
      const archiveEvent = decodeIngressEvents(
        archiveResponse.request().postData(),
      ).find((event) => event.kind === "ak.space.archive");
      expect(archiveEvent, "workflow emitted the List archive Event").toBeDefined();
      expect(archiveEvent?.payload).toEqual({ space_id: todayListId });
      expect(archiveEvent?.seal_basis).toBeUndefined();
      expect(archiveEvent?.auth_context).toBeUndefined();
      await stepShot(patPage.page, testInfo, "E-list-restored");
    } finally {
      await patPage.close();
    }
  });
});

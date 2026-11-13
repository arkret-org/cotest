import { newBoardTrigger, addBoardList, submitBoardCardDraft } from "../../helpers/kanban-product-ui";
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
import { assertAuthoritySubmitOutcome, scanRealmStreamApi, sdkEventDerivedObjectId } from "../../helpers/coland-api";
import { waitForDurableCurrentCut } from "../../helpers/durable-current-cut";
import type { CommitStreamHead } from "../../helpers/generated/spec-wire-objects";
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
  await submitBoardCardDraft(column, title);
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
        strandId = event ? sdkEventDerivedObjectId(event) : "";
        return strandId;
      },
      { timeout: 120_000 },
    )
    .toMatch(/^ak:strand:/);
  const page = card.page();
  const boardPath = new URL(page.url()).pathname;
  await card.click();
  await expect.poll(() => decodeURIComponent(new URL(page.url()).pathname).endsWith(`/task/${strandId}`))
    .toBe(true);
  await page.locator(".card-detail-close-button").click();
  await expect.poll(() => new URL(page.url()).pathname).toBe(boardPath);
  await expect(card).toBeVisible();
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
      await patPage.page.goto(`/kanban/${encodeURIComponent(realmId)}`, { waitUntil: "domcontentloaded" });
      await expect(patPage.page.locator(".kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await patPage.clickWithPassivePromptRetry(newBoardTrigger(patPage.page));
      await patPage.page
        .locator(".new-board-title-input input, .new-board-title-input textarea")
        .fill(`Week 21 board ${stamp}`);
      await patPage.page.locator(".create-board-space-button").click();
      await expect(patPage.page.locator(".kanban-empty-board")).toContainText(/No lists yet/, {
        timeout: 30_000,
      });
      await expect(patPage.page.locator(".add-column-button")).toBeEnabled({
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
        await addBoardList(patPage.page, columnName);
        await expect(
          patPage.page.locator(".kanban-column").filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await stepShot(patPage.page, testInfo, "A-board-ready");

      // Phase B — load Today with four real tasks.
      const today = patPage.page
        .locator(".kanban-column")
        .filter({ hasText: todayList })
        .first();
      for (const task of [triageTask, prTask, specTask, planTask]) {
        await addCardThroughColumn(today, task);
        await expect(today.locator(".kanban-card").filter({ hasText: task })).toBeVisible({
          timeout: 90_000,
        });
      }
      for (const task of [triageTask, prTask, specTask, planTask]) {
        const card = today.locator(".kanban-card").filter({ hasText: task }).first();
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
          .locator(".kanban-card")
          .filter({ hasText: finished })
          .first();
        await finishedCard.hover();
        await finishedCard.locator(".card-archive-button").click();
        await expect(today.locator(".kanban-card").filter({ hasText: finished })).toHaveCount(
          0,
          { timeout: 30_000 },
        );
        await expect(
          patPage.page.locator(".kanban-archived-card-row").filter({ hasText: finished }),
        ).toBeVisible({ timeout: 30_000 });
      }
      // Today should still hold the two real-work tasks.
      await expect(today.locator(".kanban-card").filter({ hasText: prTask })).toBeVisible({
        timeout: 30_000,
      });
      await expect(today.locator(".kanban-card").filter({ hasText: specTask })).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(patPage.page, testInfo, "C-two-done");

      // Phase D — Pat archives prTask by mistake, then restores it.
      const prCard = today
        .locator(".kanban-card")
        .filter({ hasText: prTask })
        .first();
      await prCard.hover();
      await prCard.locator(".card-archive-button").click();
      await expect(today.locator(".kanban-card").filter({ hasText: prTask })).toHaveCount(0, {
        timeout: 30_000,
      });
      const archivedRow = patPage.page
        .locator(".kanban-archived-card-row")
        .filter({ hasText: prTask })
        .first();
      await archivedRow.locator(".card-restore-button").click();
      await expect(
        patPage.page.locator(".kanban-card").filter({ hasText: prTask }),
      ).toBeVisible({ timeout: 30_000 });
      const restoredTitles = await today.locator(".kanban-card").allTextContents();
      const restoredPrIndex = restoredTitles.findIndex((title) => title.includes(prTask));
      const restoredSpecIndex = restoredTitles.findIndex((title) => title.includes(specTask));
      expect(restoredPrIndex).toBeGreaterThanOrEqual(0);
      expect(restoredSpecIndex).toBeGreaterThanOrEqual(0);
      expect(restoredPrIndex).toBeLessThan(restoredSpecIndex);
      await stepShot(patPage.page, testInfo, "D-restored");

      // Phase E — archive an entire List and restore it. realm-and-space.md
      // section 3.4: Space archive moves only the List's own lifecycle; its
      // cards keep their state and placement, so restore brings them back.
      const acceptedLists = (await readRealmEvents(request, realmId, patFlow.session)).filter(event => {
        const object = (event.payload as { object?: { kind?: string; title?: string } } | undefined)?.object;
        return event.kind === "ak.space.create" && object?.kind === "list" && object.title === todayList;
      });
      expect(acceptedLists).toHaveLength(1);
      const todayListId = sdkEventDerivedObjectId(acceptedLists[0]);
      expect(todayListId ?? "").toMatch(/^ak:space:/);

      // list-archive-button is hover-revealed on the column header — hover
      // the column itself first so the button becomes actionable. Clicking
      // it opens a confirmation dialog; the archive submits from confirm.
      await today.hover();
      await today.locator(".list-archive-button").click();
      const archiveWrite = patPage.page.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === "/_arkret/self/events" &&
          response.request().method() === "POST" &&
          decodeIngressEvents(response.request().postData()).some(
            (event) => event.kind === "ak.space.archive",
          ),
        { timeout: 90_000 },
      );
      await patPage.page.locator(".list-archive-confirm-button").click();
      const archiveResponse = await archiveWrite;
      expect(archiveResponse.status(), await archiveResponse.text()).toBeLessThan(400);
      const archiveEvent = decodeIngressEvents(
        archiveResponse.request().postData(),
      ).find((event) => event.kind === "ak.space.archive");
      expect(archiveEvent, "workflow emitted the List archive Event").toBeDefined();
      const archiveOutcome = await archiveResponse.json();
      assertAuthoritySubmitOutcome(archiveOutcome, archiveEvent!, "week-in-review List archive");
      await waitForDurableCurrentCut(patPage.page, archiveOutcome.commit as CommitStreamHead);
      const archivedLists = patPage.page.locator(".kanban-archived-lists");
      // Durable installation can precede the maintenance view's next render.
      // Open the accepted List's disclosure, rather than the retiring zero row.
      const archiveViewDeadline = Date.now() + 30_000;
      const archiveToggle = archivedLists.getByRole("button", { name: "Archived lists (1)", exact: true });
      await expect(archiveToggle).toBeVisible({ timeout: Math.max(1, archiveViewDeadline - Date.now()) });
      await archiveToggle.click({ timeout: Math.max(1, archiveViewDeadline - Date.now()) });
      const archivedList = archivedLists.locator(".kanban-archived-list-row").filter({ hasText: todayList });
      await expect(archivedList).toBeVisible({ timeout: Math.max(1, archiveViewDeadline - Date.now()) });
      const [restoreResponse] = await Promise.all([
        patPage.page.waitForResponse((response) =>
          new URL(response.url()).pathname === "/_arkret/self/events" &&
          response.request().method() === "POST" &&
          decodeIngressEvents(response.request().postData()).some(
            (event) => event.kind === "ak.space.restore",
          ),
        { timeout: 90_000 }),
        archivedList.getByRole("button", { name: "Restore", exact: true }).click(),
      ]);
      expect(restoreResponse.status(), await restoreResponse.text()).toBeLessThan(400);
      await expect(
        patPage.page.locator(".kanban-column").filter({ hasText: todayList }),
      ).toBeVisible({ timeout: 30_000 });
      // event-envelope.schema.json is closed: the archive is an ordinary
      // producer-signed Event whose payload names only the Space
      // (space_state_transition_payload); it carries no seal or auth basis.
      expect(archiveEvent?.payload).toEqual({ space_id: todayListId });
      expect(archiveEvent?.seal_basis).toBeUndefined();
      expect(archiveEvent?.auth_context).toBeUndefined();
      await stepShot(patPage.page, testInfo, "E-list-restored");
    } finally {
      await patPage.close();
    }
  });
});

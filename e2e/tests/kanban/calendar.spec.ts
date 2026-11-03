// Calendar schedule and RSVP through the Inkson card detail surface.
// Contract: e2e/scenarios/kanban/calendar.md
// Spec: models/calendar-event.md, models/strand-and-message.md

import { addBoardList } from "../../helpers/kanban-product-ui";
import {
  expect,
  test,
  type Locator,
  type Response,
} from "../../helpers/arkret-test";
import { selectProductOptionByLabel } from "../../helpers/product-select";
import {
  assertJointStackNotRequired,
  openDpopUserPage,
} from "../../helpers/users";

async function addCard(column: Locator, title: string): Promise<void> {
  await column.locator(".add-card-button").click();
  await column.locator(".new-card-title-input").fill(title);
  await column.locator(".save-card-button").click();
  await expect(column.locator(".kanban-card").filter({ hasText: title }).first()).not.toHaveClass(/\bis-draft\b/, { timeout: 45_000 });
}

test("@fully-implemented calendar schedule and RSVP survive the canonical Strand event flow", async ({
  browser,
  request,
}) => {
  test.setTimeout(360_000);
  const stamp = Date.now();
  const flow = await openDpopUserPage(
    browser,
    request,
    `calendar-ui-${stamp}`,
    { refreshGrantBeforeUse: true },
  );
  if (!flow) {
    assertJointStackNotRequired("calendar UI DPoP login");
    test.skip(true, "coauth DPoP session-grant login is unavailable");
    return;
  }

  const { page, session } = flow;
  const cardTitle = `Planning session ${stamp}`;
  const start = "2026-10-05T09:00:00";
  const end = "2026-10-05T10:30:00";
  const timezone = "Asia/Shanghai";
  const location = `Room ${stamp}`;

  try {
    await page.waitForSessionGrantRefresh();
    const realmId = await page.createRealm({
      title: `Calendar Realm ${stamp}`,
      discoverability: "listed",
      joinRule: "invite",
    });
    await page.grantRealmCapability(
      realmId,
      session.accountId,
      "ak.rsvp.set",
    );
    await page.page.goto(`/kanban/${realmId}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(page.page.locator(".kanban-panel")).toBeVisible({
      timeout: 120_000,
    });

    await page.page.locator(".new-board-toggle").click();
    await page.page
      .locator(".new-board-title-input input, .new-board-title-input textarea")
      .fill(`Calendar Board ${stamp}`);
    await page.page.locator(".create-board-space-button").click();
    await expect(page.page.locator(".kanban-empty-board")).toBeVisible({
      timeout: 45_000,
    });
    await expect(page.page).toHaveURL(url => decodeURIComponent(url.pathname)
      .startsWith(`/kanban/${realmId}/board/ak:space:`), { timeout: 120_000 });

    const columnTitle = `Upcoming ${stamp}`;
    const column = await addBoardList(page.page, columnTitle);
    await addCard(column, cardTitle);

    const detail = page.page.locator(".card-detail-modal");
    // Creating a card may select it immediately. Avoid clicking through an
    // already-open detail overlay, which correctly intercepts board input.
    if (!(await detail.isVisible({ timeout: 1_000 }).catch(() => false))) {
      await column
        .locator(".kanban-card")
        .filter({ hasText: cardTitle })
        .first()
        .click();
    }
    await expect(detail).toBeVisible({ timeout: 45_000 });
    const calendar = detail.locator(".card-detail-calendar");
    await calendar.locator(".card-detail-calendar-edit").click();
    const editor = page.page.locator(".card-detail-calendar-editor-dialog");
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await editor.locator(".card-detail-calendar-start-input").locator("input, textarea").fill(start);
    await editor.locator(".card-detail-calendar-end-input").locator("input, textarea").fill(end);
    await editor
      .locator(".card-detail-calendar-timezone-input").locator("input, textarea")
      .fill(timezone);
    await editor
      .locator(".card-detail-calendar-location-input").locator("input, textarea")
      .fill(location);
    await selectProductOptionByLabel(
      editor.locator(".card-detail-calendar-recurrence-select"),
      "Weekly",
    );

    const schedulePredicate = (response: Response) =>
      response.url().includes("/_arkret/self/events") &&
      response.request().method() === "POST" &&
      (response.request().postData() ?? "").includes("ak.strand.update");
    // Saving queues the write and closes the editor before encrypted submission
    // necessarily reaches the network. Observe that one write instead of
    // clicking an already-closed editor again after a short response timeout.
    const scheduleWrite = page.page
      .waitForResponse(schedulePredicate, { timeout: 90_000 })
      .catch(() => undefined);
    await editor.locator(".card-detail-save-button").click();
    const scheduled = await scheduleWrite;
    const scheduleStatus = await editor
      .locator(".card-detail-edit-status")
      .textContent({ timeout: 1_000 })
      .catch(() => "schedule write was not emitted");
    expect(scheduled, scheduleStatus ?? "schedule write was not emitted").toBeTruthy();
    const scheduledResponse = scheduled!;
    const scheduledText = await scheduledResponse.text();
    const scheduleWire = scheduledResponse.request().postData() ?? "";
    expect(
      scheduledResponse.status(),
      scheduledText,
    ).toBeLessThan(400);
    expect(scheduleWire).toContain("ak.schema.calendar_event.v1");
    expect(scheduleWire).not.toContain(timezone);
    expect(scheduleWire).not.toContain(start);
    expect(scheduleWire).not.toContain(end);
    expect(scheduleWire).not.toContain(location);
    const scheduleEvent = JSON.parse(scheduleWire).event;
    const metadataEnvelope = scheduleEvent?.payload?.patch?.encrypted_metadata?.value;
    expect(metadataEnvelope?.content_type).toBe("application/json");
    expect(metadataEnvelope?.ciphertext).toBeTruthy();
    expect(scheduleEvent?.payload?.patch?.metadata).toBeUndefined();
    await expect(editor).toBeHidden({ timeout: 45_000 });

    await expect(calendar).toContainText(timezone, { timeout: 60_000 });
    await expect(calendar).toContainText(location);
    await expect(calendar).toContainText(/Weekly/i);

    // Reload through the canonical projection before responding.  RSVP basis
    // refs must come from an observed schedule frontier, not solely from the
    // optimistic local card overlay used immediately after saving.
    await page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.page.locator(".kanban-panel")).toBeVisible({
      timeout: 120_000,
    });
    // The canonical card route may restore the selected Strand after the board
    // itself becomes visible. Close that late overlay before selecting the
    // projected card again; otherwise it correctly intercepts board input.
    const restoredOverlay = page.page.locator(".card-detail-overlay");
    if (
      await restoredOverlay
        .waitFor({ state: "visible", timeout: 30_000 })
        .then(() => true)
        .catch(() => false)
    ) {
      await restoredOverlay.locator(".card-detail-close-button").click();
      await expect(restoredOverlay).toBeHidden({ timeout: 30_000 });
    }
    const reloadedCard = page.page
      .locator(".kanban-card")
      .filter({ hasText: cardTitle })
      .first();
    await expect(reloadedCard).toBeVisible({ timeout: 90_000 });
    await reloadedCard.click();
    await expect(detail).toBeVisible({ timeout: 45_000 });
    await expect(
      calendar.locator(".card-detail-calendar-agenda-unresolved"),
    ).toHaveCount(0, { timeout: 90_000 });

    await calendar.getByRole("button", { name: "Entire series", exact: true }).click();
    const rsvpWrite = page.page.waitForResponse(
      (response) =>
        response.url().includes("/_arkret/self/events") &&
        response.request().method() === "POST" &&
        (response.request().postData() ?? "").includes("ak.rsvp.set"),
      { timeout: 90_000 },
    );
    await calendar.locator(".card-detail-rsvp-accepted").click();
    const accepted = await rsvpWrite;
    const acceptedText = await accepted.text();
    expect(accepted.status(), acceptedText).toBeLessThan(400);
    const acceptedWire = JSON.parse(accepted.request().postData() ?? "{}");
    const encryptedResponse = acceptedWire.event?.payload?.entry?.encrypted_response;
    expect(encryptedResponse?.content_type).toBe(
      "application/vnd.arkret.calendar-rsvp-response+json",
    );
    expect(encryptedResponse?.ciphertext).toBeTruthy();
    await expect(calendar.locator(".card-detail-rsvp-own")).toHaveText(
      "You: accepted",
      { timeout: 90_000 },
    );
    await expect(calendar.locator(".card-detail-rsvp-counts")).toContainText(
      "1 yes",
    );

    await calendar.locator(".card-detail-calendar-edit").click();
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await expect(
      editor.locator(".card-detail-calendar-start-input").locator("input, textarea"),
    ).toHaveValue(start);
    await expect(
      editor.locator(".card-detail-calendar-end-input").locator("input, textarea"),
    ).toHaveValue(end);
    await expect(
      editor.locator(".card-detail-calendar-timezone-input").locator("input, textarea"),
    ).toHaveValue(timezone);
    await expect(
      editor.locator(".card-detail-calendar-location-input").locator("input, textarea"),
    ).toHaveValue(location);
  } finally {
    await page.close();
  }
});

// Calendar schedule and RSVP through the Inkson card detail surface.
// Contract: e2e/scenarios/kanban/calendar.md
// Spec: models/calendar-event.md, models/strand-and-message.md

import {
  expect,
  test,
  type Locator,
  type Response,
} from "../../helpers/arkret-test";
import { selectDxcOption } from "../../helpers/dxc-select";
import {
  assertJointStackNotRequired,
  openDpopUserPage,
} from "../../helpers/users";

async function addCard(column: Locator, title: string): Promise<void> {
  await column.getByTestId("add-card-button").click();
  await column.getByTestId("new-card-title-input").fill(title);
  await column.getByTestId("save-card-button").click();
  await expect(
    column.getByTestId("kanban-card").filter({ hasText: title }).first(),
  ).toBeVisible({ timeout: 45_000 });
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
    await expect(page.page.getByTestId("kanban-panel")).toBeVisible({
      timeout: 120_000,
    });

    await page.page.getByTestId("new-board-toggle").click();
    await page.page
      .getByTestId("new-board-title-input")
      .fill(`Calendar Board ${stamp}`);
    await page.page.getByTestId("create-board-space-button").click();
    await expect(page.page.getByTestId("kanban-empty-board")).toBeVisible({
      timeout: 45_000,
    });

    const columnTitle = `Upcoming ${stamp}`;
    await page.page.getByTestId("new-column-input").fill(columnTitle);
    await page.page.getByTestId("add-column-button").click();
    const column = page.page
      .getByTestId("kanban-column")
      .filter({ hasText: columnTitle })
      .first();
    await expect(column).toBeVisible({ timeout: 45_000 });
    await addCard(column, cardTitle);

    const detail = page.page.getByTestId("card-detail-modal");
    // Creating a card may select it immediately. Avoid clicking through an
    // already-open detail overlay, which correctly intercepts board input.
    if (!(await detail.isVisible({ timeout: 1_000 }).catch(() => false))) {
      await column
        .getByTestId("kanban-card")
        .filter({ hasText: cardTitle })
        .first()
        .click();
    }
    await expect(detail).toBeVisible({ timeout: 45_000 });
    const calendar = detail.getByTestId("card-detail-calendar");
    await calendar.getByTestId("card-detail-edit-calendar-button").click();
    const editor = page.page.getByTestId("card-detail-calendar-editor-dialog");
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await editor.getByTestId("card-detail-calendar-start-input").fill(start);
    await editor.getByTestId("card-detail-calendar-end-input").fill(end);
    await editor
      .getByTestId("card-detail-calendar-timezone-input")
      .fill(timezone);
    await editor
      .getByTestId("card-detail-calendar-location-input")
      .fill(location);
    await selectDxcOption(
      editor.getByTestId("card-detail-calendar-recurrence-select"),
      "weekly",
    );

    const schedulePredicate = (response: Response) =>
      response.url().includes("/_arkret/self/events") &&
      response.request().method() === "POST" &&
      (response.request().postData() ?? "").includes("ak.strand.update");
    let scheduled: Response | undefined;
    for (let attempt = 0; attempt < 18 && !scheduled; attempt += 1) {
      const scheduleWrite = page.page
        .waitForResponse(schedulePredicate, { timeout: 5_000 })
        .catch(() => undefined);
      await editor.getByTestId("card-detail-save-button").click();
      scheduled = await scheduleWrite;
      if (!scheduled) {
        await page.page.waitForTimeout(1_000);
      }
    }
    const scheduleStatus = await editor
      .getByTestId("card-detail-edit-status")
      .textContent({ timeout: 1_000 })
      .catch(() => "schedule write was not emitted");
    expect(scheduled, scheduleStatus ?? "schedule write was not emitted").toBeTruthy();
    const scheduledResponse = scheduled!;
    const scheduledText = await scheduledResponse.text();
    const scheduleWire = scheduledResponse.request().postData() ?? "";
    expect(
      scheduledResponse.status(),
      `${scheduledText}\nrequest=${scheduleWire}`,
    ).toBeLessThan(400);
    expect(scheduleWire).toContain("ak.schema.calendar_event.v1");
    expect(scheduleWire).toContain(timezone);
    expect(scheduleWire).not.toContain(location);
    expect(scheduleWire).toContain('"content_type":"application/vnd.arkret.strand.patch-value+json"');
    await expect(editor).toBeHidden({ timeout: 45_000 });

    await expect(calendar).toContainText(timezone, { timeout: 60_000 });
    await expect(calendar).toContainText(location);
    await expect(calendar).toContainText(/Weekly/i);

    // Reload through the canonical projection before responding.  RSVP basis
    // refs must come from an observed schedule frontier, not solely from the
    // optimistic local card overlay used immediately after saving.
    await page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.page.getByTestId("kanban-panel")).toBeVisible({
      timeout: 120_000,
    });
    // The canonical card route may restore the selected Strand after the board
    // itself becomes visible. Close that late overlay before selecting the
    // projected card again; otherwise it correctly intercepts board input.
    const restoredOverlay = page.page.getByTestId("card-detail-overlay");
    if (
      await restoredOverlay
        .waitFor({ state: "visible", timeout: 30_000 })
        .then(() => true)
        .catch(() => false)
    ) {
      await restoredOverlay.getByTestId("card-detail-close-button").click();
      await expect(restoredOverlay).toBeHidden({ timeout: 30_000 });
    }
    const reloadedCard = page.page
      .getByTestId("kanban-card")
      .filter({ hasText: cardTitle })
      .first();
    await expect(reloadedCard).toBeVisible({ timeout: 90_000 });
    await reloadedCard.click();
    await expect(detail).toBeVisible({ timeout: 45_000 });
    await expect(
      calendar.getByTestId("card-detail-calendar-agenda-unresolved"),
    ).toHaveCount(0, { timeout: 90_000 });

    await calendar.getByRole("button", { name: "Series", exact: true }).click();
    const rsvpWrite = page.page.waitForResponse(
      (response) =>
        response.url().includes("/_arkret/self/events") &&
        response.request().method() === "POST" &&
        (response.request().postData() ?? "").includes("ak.rsvp.set"),
      { timeout: 90_000 },
    );
    await calendar.getByTestId("card-detail-rsvp-accepted").click();
    const accepted = await rsvpWrite;
    const acceptedText = await accepted.text();
    expect(
      accepted.status(),
      `${acceptedText}\nrequest=${accepted.request().postData() ?? ""}`,
    ).toBeLessThan(400);
    expect(accepted.request().postData() ?? "").toContain('"status":"accepted"');
    await expect(calendar.getByTestId("card-detail-rsvp-own")).toHaveText(
      "You: accepted",
      { timeout: 90_000 },
    );
    await expect(calendar.getByTestId("card-detail-rsvp-counts")).toContainText(
      "1 yes",
    );

    await calendar.getByTestId("card-detail-edit-calendar-button").click();
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await expect(
      editor.getByTestId("card-detail-calendar-start-input"),
    ).toHaveValue(start);
    await expect(
      editor.getByTestId("card-detail-calendar-end-input"),
    ).toHaveValue(end);
    await expect(
      editor.getByTestId("card-detail-calendar-timezone-input"),
    ).toHaveValue(timezone);
    await expect(
      editor.getByTestId("card-detail-calendar-location-input"),
    ).toHaveValue(location);
  } finally {
    await page.close();
  }
});

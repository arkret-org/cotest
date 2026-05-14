import { expect, test } from "@playwright/test";
import { stepShot } from "../helpers/screenshots";
import { ensureRegistered, issueDevSession, openUserPage, uniqueUser } from "../helpers/users";

test.describe.configure({ mode: "serial" });

test("notifications panel renders toolbar, grouping segments, and mark-all-read status", async ({
  browser,
  request,
}, testInfo) => {
  const user = uniqueUser("notifications");
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);

  try {
    await actor.page.goto("/notifications", { waitUntil: "domcontentloaded" });
    await expect(actor.page.getByTestId("notifications-panel")).toBeVisible({ timeout: 120_000 });

    const grouping = actor.page.getByRole("tablist", { name: "Notification grouping" });
    await expect(grouping).toBeVisible();
    for (const label of ["Space", "Type", "Time", "All"]) {
      const segment = grouping.getByRole("button", { name: label });
      await segment.click();
      await expect(segment).toHaveClass(/active/);
    }
    await stepShot(actor.page, testInfo, "01-grouping-cycled");

    await actor.page.getByTestId("toggle-archived").click();
    await actor.page.getByTestId("refresh-notifications").click();
    await stepShot(actor.page, testInfo, "02-refresh-clicked");

    await actor.page.getByTestId("mark-all-read").click();
    const status = actor.page.getByTestId("notifications-status");
    await expect(status).toContainText(/All visible notifications marked read|locally\./i, {
      timeout: 30_000,
    });
    await stepShot(actor.page, testInfo, "03-mark-all-read-status");

    const itemCount = await actor.page.getByTestId("notification-item").count();
    if (itemCount === 0) {
      const empty = actor.page.getByTestId("notifications-muted-empty");
      const fallback = actor.page.getByTestId("notifications-panel").locator(".event").last();
      const hasEmptyTestid = (await empty.count()) > 0;
      const hasFallback = (await fallback.count()) > 0;
      expect(hasEmptyTestid || hasFallback).toBeTruthy();
      await stepShot(actor.page, testInfo, "04-empty-state");
    } else {
      await stepShot(actor.page, testInfo, "04-items-visible");
    }
  } finally {
    await actor.close();
  }
});

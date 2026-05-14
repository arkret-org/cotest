import { expect, test } from "@playwright/test";
import { stepShot } from "../helpers/screenshots";
import { ensureRegistered, issueDevSession, openUserPage, uniqueUser } from "../helpers/users";

test.describe.configure({ mode: "serial" });

test("quarantine panel renders, refresh exposes status, empty list reports empty hint", async ({
  browser,
  request,
}, testInfo) => {
  const user = uniqueUser("quarantine");
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);

  try {
    await actor.page.goto("/quarantine", { waitUntil: "domcontentloaded" });
    await expect(actor.page.getByTestId("quarantine-panel")).toBeVisible({ timeout: 120_000 });
    await expect(actor.page.getByTestId("quarantine-header")).toBeVisible();
    await expect(actor.page.getByTestId("quarantine-empty")).toBeVisible();
    await stepShot(actor.page, testInfo, "01-quarantine-initial");

    await actor.page.getByTestId("quarantine-refresh-button").click();
    const status = actor.page.getByTestId("quarantine-status");
    await expect
      .poll(async () => ((await status.count()) > 0 ? await status.innerText() : ""), { timeout: 30_000 })
      .toMatch(/loaded \d+ entries|quarantine fetch failed|invalid coauth URL/i);
    await stepShot(actor.page, testInfo, "02-quarantine-refreshed");

    await actor.page.getByTestId("quarantine-reject-reason-input").fill("e2e default reject reason");
    await expect(actor.page.getByTestId("quarantine-reject-reason-input")).toHaveValue(
      "e2e default reject reason",
    );
    await stepShot(actor.page, testInfo, "03-reject-reason-filled");
  } finally {
    await actor.close();
  }
});

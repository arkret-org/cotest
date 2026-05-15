import { expect, test } from "@playwright/test";
import { stepShot } from "../helpers/screenshots";
import { ensureRegistered, issueDevSession, openUserPage, uniqueUser } from "../helpers/users";

test.describe.configure({ mode: "serial" });

test("consent grant + revoke demo card validates input and surfaces a Move status", async ({
  browser,
  request,
}, testInfo) => {
  const user = uniqueUser("consent");
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);

  try {
    const spaceId = await actor.createSpace({
      title: `Consent Demo Space ${Date.now()}`,
      summary: "consent move PoC",
      discoverability: "public",
    });
    await stepShot(actor.page, testInfo, "01-space-ready");

    await actor.page.goto("/settings/privacy", { waitUntil: "domcontentloaded" });
    const card = actor.page.getByTestId("consent-grant-demo");
    await expect(card).toBeVisible({ timeout: 120_000 });
    await stepShot(actor.page, testInfo, "02-consent-card-visible");

    await card.getByTestId("consent-grant-submit").click();
    await expect(card.getByTestId("consent-grant-status")).toContainText(/Fill space_id/i);
    await stepShot(actor.page, testInfo, "03-empty-validation");

    await card.getByTestId("consent-grant-space-id").fill(spaceId);
    await card.getByTestId("consent-grant-consent-id").fill("cnt.e2e-01");
    await card.getByTestId("consent-grant-tag").fill("scope:contacts");
    await card.getByTestId("consent-grant-submit").click();

    const status = card.getByTestId("consent-grant-status");
    await expect(status).toContainText(/Move cx:move:sha256:|submit_move.*failed:|Identity unavailable|Build move failed/i, {
      timeout: 30_000,
    });
    await expect(card.getByTestId("consent-grant-last-move-id")).toContainText(/cx:move:sha256:/);
    await stepShot(actor.page, testInfo, "04-grant-submitted");

    await card.getByTestId("consent-revoke-submit").click();
    await expect(status).toContainText(/Move cx:move:sha256:|submit_move \(revoke\).*failed:|Build revoke move failed/i, {
      timeout: 30_000,
    });
    await stepShot(actor.page, testInfo, "05-revoke-submitted");
  } finally {
    await actor.close();
  }
});

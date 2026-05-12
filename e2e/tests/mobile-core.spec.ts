import { expect, test, type Page } from "@playwright/test";
import { stepShot } from "../helpers/screenshots";
import { bob, ensureRegistered, issueDevSession, openUserPage, uniqueUser } from "../helpers/users";

test("mobile core path: login, navigation, timeline, message, and space admin screenshots @mobile", async ({
  browser,
  request,
}, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-chrome", "mobile project only");

  const user = uniqueUser("mobile-user");
  await ensureRegistered(request, user);
  await ensureRegistered(request, bob);

  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);
  const page = actor.page;
  const stamp = Date.now();
  const title = `Mobile Core Space ${stamp}`;
  const message = `mobile core message ${stamp}`;

  try {
    await actor.gotoHome();
    await expect(page.getByTestId("mobile-shellbar")).toBeVisible();
    await expect(page.getByTestId("sidebar")).toBeHidden();

    await page.getByTestId("mobile-nav-toggle").click();
    await expect(page.getByTestId("mobile-nav-drawer")).toBeVisible();
    await stepShot(page, testInfo, "01-mobile-nav-open");

    await page.getByTestId("mobile-connect-button").click();
    await expect(page.getByTestId("mobile-status-label")).toContainText(
      /Connected|Online|Empty|authenticated|principal_server/,
    );
    await stepShot(page, testInfo, "02-mobile-authenticated");

    await page.getByTestId("mobile-product-nav-button").click();
    await expect(page.getByTestId("product-panel")).toBeVisible();
    const spaceFlow = page.getByTestId("space-lifecycle-flow").first();
    await spaceFlow.getByTestId("space-title-input").fill(title);
    await spaceFlow.getByTestId("space-summary-input").fill("mobile core coverage");
    await spaceFlow.getByTestId("space-discoverability-input").fill("public");
    await spaceFlow.getByTestId("member-did-input").fill(bob.did);
    await spaceFlow.getByTestId("create-space-button").click();
    await expect(spaceFlow).toContainText(/created cx:space:/);
    const spaceId = await extractCreatedSpaceId(page);
    await stepShot(page, testInfo, "03-mobile-space-created");

    await page.getByTestId("mobile-nav-toggle").click();
    await page.getByTestId("mobile-timeline-nav-button").click();
    await expect(page.getByTestId("timeline")).toBeVisible();
    await page.goto(`/timeline/${spaceId}`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("timeline")).toBeVisible({ timeout: 120_000 });
    await page.getByTestId("composer-input").fill(message);
    await page.getByTestId("send-button").click();
    await expect(page.getByTestId("timeline")).toContainText(message);
    await expect(page.getByTestId("write-status")).toContainText(/persisted/);
    await stepShot(page, testInfo, "04-mobile-timeline-message-sent");

    await page.goto(`/space/${spaceId}/admin`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("space-admin-panel")).toBeVisible({ timeout: 120_000 });
    await expect(page.getByTestId("space-metadata")).toContainText(spaceId);
    await stepShot(page, testInfo, "05-mobile-space-admin");
  } finally {
    await actor.close();
  }
});

async function extractCreatedSpaceId(page: Page): Promise<string> {
  const text = await page.getByTestId("space-lifecycle-flow").first().innerText();
  const match = text.match(/created (cx:space:[^\s]+)/);
  expect(match, `created space id in: ${text}`).not.toBeNull();
  return match![1];
}

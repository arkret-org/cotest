import { expect, test, type Page } from "@playwright/test";
import { solandBaseUrl } from "../helpers/env";
import { visualBaselineShot } from "../helpers/visual-baseline";
import { bob, ensureRegistered, issueDevSession, openUserPage, type JointUser } from "../helpers/users";

const visualOwner: JointUser = {
  name: "visual-owner",
  did: "did:web:visual-owner.example",
  deviceId: "cx:device:01904100-0000-7000-8000-000000000201",
  handle: "@visual-owner-e2e",
  displayName: "Visual Owner",
};

const visualOutsider: JointUser = {
  name: "visual-outsider",
  did: "did:web:visual-outsider.example",
  deviceId: "cx:device:01904100-0000-7000-8000-000000000202",
  handle: "@visual-outsider-e2e",
  displayName: "Visual Outsider",
};

test("controlled desktop visual baselines for login, timeline, permission, and space admin @visual", async ({
  browser,
  request,
}, testInfo) => {
  await ensureRegistered(request, visualOwner);
  await ensureRegistered(request, visualOutsider);
  await ensureRegistered(request, bob);

  const guest = await openUserPage(browser, visualOwner);
  try {
    await guest.gotoLogin();
    await expect(guest.page.getByTestId("login-panel")).toBeVisible();
    await visualBaselineShot(guest.page, testInfo, "login-panel", guest.page.getByTestId("login-panel"));
  } finally {
    await guest.close();
  }

  const ownerToken = await issueDevSession(request, visualOwner);
  const outsiderToken = await issueDevSession(request, visualOutsider);
  const owner = await openUserPage(browser, visualOwner, ownerToken);
  const outsider = await openUserPage(browser, visualOutsider, outsiderToken);

  try {
    await owner.gotoProduct();
    const spaceFlow = owner.page.getByTestId("space-lifecycle-flow").first();
    await spaceFlow.getByTestId("space-title-input").fill("Visual Baseline Space");
    await spaceFlow.getByTestId("space-summary-input").fill("Stable visual baseline coverage");
    await spaceFlow.getByTestId("space-discoverability-input").fill("public");
    await spaceFlow.getByTestId("member-did-input").fill(bob.did);
    await spaceFlow.getByTestId("create-space-button").click();
    await expect(spaceFlow).toContainText(/created cx:space:/);
    const spaceId = await extractCreatedSpaceId(owner.page);

    await owner.page.goto(`/timeline/${spaceId}`, { waitUntil: "domcontentloaded" });
    await expect(owner.page.getByTestId("timeline")).toBeVisible({ timeout: 120_000 });
    await owner.page.getByTestId("composer-input").fill("Visual baseline message");
    await owner.page.getByTestId("send-button").click();
    await expect(owner.page.getByTestId("timeline")).toContainText("Visual baseline message");
    await expect(owner.page.getByTestId("write-status")).toContainText(/persisted/);
    await visualBaselineShot(owner.page, testInfo, "timeline-message", owner.page.getByTestId("timeline"));

    await outsider.gotoProduct();
    const outsiderSpaceFlow = outsider.page.getByTestId("space-lifecycle-flow").first();
    await outsiderSpaceFlow.getByTestId("selected-space-id-input").fill(spaceId);
    await outsiderSpaceFlow.getByTestId("space-title-input").fill("Visual Baseline Denied");
    await outsiderSpaceFlow.getByTestId("update-space-button").click();
    await expect(outsiderSpaceFlow).toContainText(/update failed:.*(403|owner|policy_denied)/);
    await visualBaselineShot(outsider.page, testInfo, "permission-denied", outsiderSpaceFlow);

    await owner.page.goto(`/space/${spaceId}/admin`, { waitUntil: "domcontentloaded" });
    await expect(owner.page.getByTestId("space-admin-panel")).toBeVisible({ timeout: 120_000 });
    await expect(owner.page.getByTestId("space-metadata")).toContainText("Space Metadata");
    await visualBaselineShot(owner.page, testInfo, "space-admin", owner.page.getByTestId("space-admin-panel"));

    const ownerSearch = await request.post(`${solandBaseUrl()}/api/v1/directory/search-spaces`, {
      headers: { authorization: `Bearer ${ownerToken}` },
      data: { query: "Visual Baseline Space" },
    });
    expect(ownerSearch.status()).toBe(200);
  } finally {
    await outsider.close();
    await owner.close();
  }
});

async function extractCreatedSpaceId(page: Page): Promise<string> {
  const text = await page.getByTestId("space-lifecycle-flow").first().innerText();
  const match = text.match(/created (cx:space:[^\s]+)/);
  expect(match, `created space id in: ${text}`).not.toBeNull();
  return match![1];
}

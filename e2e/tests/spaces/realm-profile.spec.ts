// Realm profile editing through the Inkson administration surface.
// Contract: e2e/scenarios/spaces/realm-profile.md
// Spec: models/realm-and-space.md, models/event-and-patch.md

import { expect, test } from "../../helpers/arkret-test";
import {
  assertJointStackNotRequired,
  openDpopUserPage,
} from "../../helpers/users";

test("@fully-implemented Realm owner changes title and summary, then explicitly unsets summary", async ({
  browser,
  request,
}) => {
  test.setTimeout(300_000);
  const stamp = Date.now();
  const flow = await openDpopUserPage(
    browser,
    request,
    `realm-profile-${stamp}`,
  );
  if (!flow) {
    assertJointStackNotRequired("Realm profile settings DPoP login");
    test.skip(true, "coauth DPoP session-grant login is unavailable");
    return;
  }

  const { page } = flow;
  const title = `Realm Profile ${stamp}`;
  const updatedTitle = `${title} Updated`;
  const summary = `Joint E2E metadata ${stamp}`;

  try {
    const realmId = await page.createRealm({
      title,
      discoverability: "listed",
      joinRule: "invite",
    });
    await page.gotoRealmAdminSection(realmId, "profile");
    const profile = page.page.locator(".realm-profile");
    await expect(profile).toBeVisible({ timeout: 60_000 });
    await profile.locator(".realm-name-input input, .realm-name-input textarea").fill(updatedTitle);
    await profile.locator(".realm-summary-input").locator("input, textarea").fill(summary);

    const metadataWrite = page.page.waitForResponse(
      (response) =>
        response.url().includes("/_arkret/self/events") &&
        response.request().method() === "POST" &&
        (response.request().postData() ?? "").includes("ak.realm.profile"),
      { timeout: 90_000 },
    );
    await profile.locator(".update-metadata-button").click();
    const written = await metadataWrite;
    const writtenText = await written.text();
    expect(written.status(), writtenText).toBeLessThan(400);
    expect(written.request().postData() ?? "").toContain(updatedTitle);
    expect(written.request().postData() ?? "").toContain(summary);
    await expect(page.page.locator(".realm-settings .write-status")).toContainText(
      /profile updated/i,
      { timeout: 60_000 },
    );

    await page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(profile).toBeVisible({ timeout: 60_000 });
    await expect(profile.locator(".realm-name-input input, .realm-name-input textarea")).toHaveValue(
      updatedTitle,
    );
    await expect(profile.locator(".realm-summary-input").locator("input, textarea")).toHaveValue(
      summary,
    );

    await profile.locator(".realm-summary-input").locator("input, textarea").fill("");
    const clearWrite = page.page.waitForResponse(
      (response) =>
        response.url().includes("/_arkret/self/events") &&
        response.request().method() === "POST" &&
        (response.request().postData() ?? "").includes("ak.realm.profile"),
      { timeout: 90_000 },
    );
    await profile.locator(".update-metadata-button").click();
    const cleared = await clearWrite;
    const clearedText = await cleared.text();
    expect(cleared.status(), clearedText).toBeLessThan(400);
    const clearedWire = JSON.parse(cleared.request().postData() ?? "{}") as {
      event?: {
        payload?: { title?: string; summary?: string };
      };
    };
    expect(clearedWire.event?.payload?.summary).toBeUndefined();
    expect(clearedWire.event?.payload?.title).toBe(updatedTitle);
    await page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(profile).toBeVisible({ timeout: 60_000 });
    await expect(profile.locator(".realm-name-input input, .realm-name-input textarea")).toHaveValue(
      updatedTitle,
    );
    await expect(profile.locator(".realm-summary-input").locator("input, textarea")).toHaveValue("");
  } finally {
    await page.close();
  }
});

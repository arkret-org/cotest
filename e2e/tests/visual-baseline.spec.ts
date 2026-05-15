import { expect, test } from "@playwright/test";
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

test.describe.configure({ mode: "serial" });

test("controlled desktop visual baselines for login, timeline, permission, and space admin @visual", async ({
  browser,
  request,
}, testInfo) => {
  await ensureRegistered(request, visualOwner);
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
  const owner = await openUserPage(browser, visualOwner, ownerToken);

  try {
    const spaceId = await owner.createSpace({
      title: "Visual Baseline Space",
      summary: "Stable visual baseline coverage",
      discoverability: "public",
      seedMembers: [bob.did],
    });

    await owner.page.goto(`/timeline/${spaceId}`, { waitUntil: "domcontentloaded" });
    await expect(owner.page.getByTestId("timeline")).toBeVisible({ timeout: 120_000 });
    await owner.page.getByTestId("composer-input").fill("Visual baseline message");
    await owner.page.getByTestId("send-button").click();
    await expect(owner.page.getByTestId("timeline")).toContainText("Visual baseline message");
    await expect(owner.page.getByTestId("write-status")).toContainText(/persisted/);
    await visualBaselineShot(owner.page, testInfo, "timeline-message", owner.page.getByTestId("timeline"));

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
    await owner.close();
  }
});

test("controlled desktop visual baselines for dashboard, directory, settings, and notifications @visual", async ({
  browser,
  request,
}, testInfo) => {
  const user: JointUser = {
    name: "visual-shell",
    did: "did:web:visual-shell.example",
    deviceId: "cx:device:01904100-0000-7000-8000-000000000203",
    handle: "@visual-shell-e2e",
    displayName: "Visual Shell",
  };
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);

  try {
    await actor.gotoHome();
    await expect(actor.page.getByTestId("dashboard-panel")).toBeVisible({ timeout: 120_000 });
    await visualBaselineShot(actor.page, testInfo, "dashboard-panel", actor.page.getByTestId("dashboard-panel"));

    await actor.gotoDirectory();
    await visualBaselineShot(actor.page, testInfo, "directory-panel", actor.page.getByTestId("directory-panel"));

    await actor.gotoSettings();
    await visualBaselineShot(actor.page, testInfo, "settings-panel", actor.page.getByTestId("settings-panel"));

    await actor.page.goto("/notifications", { waitUntil: "domcontentloaded" });
    await expect(actor.page.getByTestId("notifications-panel")).toBeVisible({ timeout: 120_000 });
    await visualBaselineShot(
      actor.page,
      testInfo,
      "notifications-panel",
      actor.page.getByTestId("notifications-panel"),
    );
  } finally {
    await actor.close();
  }
});

test("controlled mobile visual baselines for shellbar and nav drawer @visual @mobile", async ({
  browser,
  request,
}, testInfo) => {
  test.skip(testInfo.project.name !== "visual-chrome", "visual project only");

  const user: JointUser = {
    name: "visual-mobile",
    did: "did:web:visual-mobile.example",
    deviceId: "cx:device:01904100-0000-7000-8000-000000000204",
    handle: "@visual-mobile-e2e",
    displayName: "Visual Mobile",
  };
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);

  try {
    await actor.page.setViewportSize({ width: 390, height: 844 });
    await actor.gotoHome();
    await expect(actor.page.getByTestId("mobile-shellbar")).toBeVisible({ timeout: 120_000 });
    await visualBaselineShot(actor.page, testInfo, "mobile-shellbar", actor.page.getByTestId("mobile-shellbar"));

    await actor.page.getByTestId("mobile-nav-toggle").click();
    await expect(actor.page.getByTestId("mobile-nav-drawer")).toBeVisible();
    await visualBaselineShot(
      actor.page,
      testInfo,
      "mobile-nav-drawer",
      actor.page.getByTestId("mobile-nav-drawer"),
    );
  } finally {
    await actor.close();
  }
});

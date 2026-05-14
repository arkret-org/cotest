import { expect, test } from "@playwright/test";
import { stepShot } from "../helpers/screenshots";
import { ensureRegistered, issueDevSession, openUserPage, uniqueUser } from "../helpers/users";

test.describe.configure({ mode: "serial" });

test("onboarding stepper walks DID method, handle, device, and recovery to the dashboard", async ({
  browser,
  request,
}, testInfo) => {
  const user = uniqueUser("onboarding");
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);

  try {
    await actor.page.goto("/onboarding", { waitUntil: "domcontentloaded" });
    await expect(actor.page.getByTestId("onboarding-panel")).toBeVisible({ timeout: 120_000 });
    await expect(actor.page.getByTestId("onboarding-header")).toContainText("step 1 / 4");
    await expect(actor.page.getByTestId("onboarding-step-did")).toBeVisible();
    await stepShot(actor.page, testInfo, "01-step-did");

    await actor.page.getByTestId("did-method-webvh").click();
    await expect(actor.page.getByTestId("did-method-webvh")).toHaveClass(/primary/);
    await stepShot(actor.page, testInfo, "02-did-webvh-selected");

    await actor.page.getByTestId("next-handle").click();
    await expect(actor.page.getByTestId("onboarding-header")).toContainText("step 2 / 4");
    await expect(actor.page.getByTestId("onboarding-step-handle")).toBeVisible();
    await actor.page.getByTestId("handle-local-input").fill("e2e-handle");
    await actor.page.getByTestId("handle-domain-input").fill("users.joint-e2e.local");
    await stepShot(actor.page, testInfo, "03-step-handle-filled");

    await actor.page.getByTestId("next-device").click();
    await expect(actor.page.getByTestId("onboarding-header")).toContainText("step 3 / 4");
    await expect(actor.page.getByTestId("onboarding-step-device")).toBeVisible();
    await stepShot(actor.page, testInfo, "04-step-device");

    await actor.page.getByTestId("next-recovery").click();
    await expect(actor.page.getByTestId("onboarding-header")).toContainText("step 4 / 4");
    await expect(actor.page.getByTestId("onboarding-step-recovery")).toBeVisible();

    await actor.page.getByTestId("recovery-social").click();
    await expect(actor.page.getByTestId("recovery-social")).toHaveClass(/primary/);
    await actor.page.getByTestId("recovery-key").click();
    await expect(actor.page.getByTestId("recovery-key")).toHaveClass(/primary/);
    await actor.page.getByTestId("recovery-vault").click();
    await expect(actor.page.getByTestId("recovery-vault")).toHaveClass(/primary/);
    await stepShot(actor.page, testInfo, "05-recovery-choices");

    const progressTabs = actor.page.getByTestId("onboarding-progress").getByRole("tab");
    await expect(progressTabs).toHaveCount(4);
    await progressTabs.first().click();
    await expect(actor.page.getByTestId("onboarding-step-did")).toBeVisible();
    await progressTabs.last().click();
    await expect(actor.page.getByTestId("onboarding-step-recovery")).toBeVisible();
    await stepShot(actor.page, testInfo, "06-progress-rewind");

    await actor.page.getByTestId("onboarding-finish").click();
    await expect(actor.page).toHaveURL(/\/$|\/dashboard/);
    await expect(actor.page.getByTestId("dashboard-panel")).toBeVisible({ timeout: 120_000 });
    await stepShot(actor.page, testInfo, "07-onboarding-finished");
  } finally {
    await actor.close();
  }
});

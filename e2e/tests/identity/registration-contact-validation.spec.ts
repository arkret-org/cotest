import { expect, test } from "../../helpers/arkret-test";
import { coauthBaseUrl, colandBaseUrl } from "../../helpers/env";

test("registration explains its supported required contact methods @fully-implemented", async ({ page }) => {
  test.skip(!coauthBaseUrl(), "Coauth is required for registration validation");
  await page.goto("/register");
  await page.getByLabel("Station", { exact: true }).fill(colandBaseUrl());
  const providersResponse = page.waitForResponse(response =>
    new URL(response.url()).pathname === "/_coauth/account/auth/providers"
    && response.request().method() === "GET");
  await page.locator(".registration-panel").getByRole("button", { name: "Continue", exact: true }).click();
  const response = await providersResponse;
  expect(response.status()).toBe(200);
  const policy = await response.json();
  expect(policy.password_registration_contact_required).toBe(true);
  expect(typeof policy.phone_verification_enabled).toBe("boolean");
  const phoneEnabled = policy.phone_verification_enabled === true;
  let registrationSubmissions = 0;
  page.on("request", request => {
    if (new URL(request.url()).pathname === "/_coauth/account/auth/register"
      && request.method() === "POST") registrationSubmissions += 1;
  });
  await page.getByLabel("Username", { exact: true }).fill(`contact-required-${Date.now()}`);
  await page.getByLabel("New password", { exact: true }).fill("1amTester!");
  await page.getByLabel("Confirm password", { exact: true }).fill("1amTester!");
  await page.getByRole("button", { name: /^Create account$/i }).click();
  const error = page.getByRole("alert");
  await expect(error).toContainText(phoneEnabled ? /email.*phone|phone.*email/i : /email address/i,
    { timeout: 30_000 });
  await expect(error).not.toContainText("email_or_phone_required");
  await expect(page.getByLabel("Email address", { exact: true })).toBeVisible();
  if (phoneEnabled) {
    await expect(page.getByLabel("Phone (optional)", { exact: true })).toBeVisible();
  } else {
    await expect(error).not.toContainText(/phone/i);
    await expect(page.getByLabel("Phone (optional)", { exact: true })).toHaveCount(0);
  }
  expect(registrationSubmissions, "missing supported contact is explained before submission").toBe(0);
});

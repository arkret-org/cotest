import { expect, test } from "../../helpers/arkret-test";
import { coauthBaseUrl, colandBaseUrl } from "../../helpers/env";

test("registration explains the missing email-or-phone requirement @fully-implemented", async ({ page }) => {
  test.skip(!coauthBaseUrl(), "Coauth is required for registration validation");
  await page.goto("/register");
  await page.getByTestId("register-server").fill(colandBaseUrl());
  await page.getByTestId("register-open-account-authority").click();
  await page.locator('input[autocomplete="username"]').fill(`contact-required-${Date.now()}`);
  await page.locator("#new-password").fill("1amTester!");
  await page.locator("#confirm-new-password").fill("1amTester!");
  await page.getByRole("button", { name: /^Create account$/i }).click();
  const error = page.getByRole("alert");
  await expect(error).toContainText(/email.*phone|phone.*email/i, { timeout: 30_000 });
  await expect(error).not.toContainText("email_or_phone_required");
  await expect(page.locator('input[autocomplete="email"]')).toBeVisible();
  await expect(page.locator('input[autocomplete="tel"]')).toBeVisible();
});

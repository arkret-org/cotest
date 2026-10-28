import { randomUUID } from "node:crypto";

import { expect, test, type Page } from "../../helpers/arkret-test";
import { coauthBaseUrl } from "../../helpers/env";
import { registrationEmailCode } from "../../helpers/coauth-register";
import { submitCoauthPasswordCredentials } from "../../helpers/real-oidc-login";

const registrationPath = "/_coauth/account/auth/register";
const password = "1amTester!";

test.use({ locale: "en-US" });

function authority(): string {
  const base = coauthBaseUrl();
  if (!base) throw new Error("The Coauth handle boundary requires a real Coauth service");
  return base.replace(/\/$/, "");
}

function asciiHandle(length: number): string {
  return `u${randomUUID().replaceAll("-", "")}`.padEnd(length, "a");
}

function astralHandle(): string {
  const unique = [...randomUUID().replaceAll("-", "").slice(0, 8)]
    .map(digit => String.fromCodePoint(0x20000 + Number.parseInt(digit, 16))).join("");
  return `${unique}${String.fromCodePoint(0x20000).repeat(120)}`;
}

async function fillRegistration(page: Page, handle: string, email: string): Promise<void> {
  await page.goto(`${authority()}/register`);
  const username = page.locator('input[autocomplete="username"]');
  await username.fill(handle);
  await expect(username).toHaveValue(handle);
  await page.locator('input[autocomplete="email"]').fill(email);
  await page.locator("#new-password").fill(password);
  await page.locator("#confirm-new-password").fill(password);
}

async function signedInAccount(page: Page, handle: string): Promise<string> {
  const viewerResponse = page.waitForResponse(response =>
    new URL(response.url()).pathname === "/_coauth/self/viewer"
    && response.request().method() === "GET" && response.status() === 200);
  await page.goto(`${authority()}/`);
  const body = await (await viewerResponse).json();
  expect(body.viewer).toMatchObject({ __typename: "User", username: handle, has_password: true });
  await expect(page.getByRole("link", { name: "Settings", exact: true })).toBeVisible();
  expect(typeof body.viewer.id).toBe("string");
  return body.viewer.id;
}

for (const boundary of [64, 65, 128, "astral-128"] as const) {
  test(`Coauth persists and reauthenticates ${boundary} character usernames @fully-implemented @coauth-handle-boundary`, async ({ browser, request }) => {
    test.setTimeout(180_000);
    const handle = boundary === "astral-128" ? astralHandle() : asciiHandle(boundary);
    expect([...handle]).toHaveLength(boundary === "astral-128" ? 128 : boundary);
    if (boundary === "astral-128") expect(Buffer.byteLength(handle, "utf8")).toBe(512);
    const email = `handle-${randomUUID()}@example.test`;
    const context = await browser.newContext({ locale: "en-US" });
    try {
      const page = await context.newPage();
      await fillRegistration(page, handle, email);
      const begin = page.waitForResponse(response =>
        new URL(response.url()).pathname === registrationPath && response.request().method() === "POST");
      await page.getByRole("button", { name: /^create account$/i }).click();
      const started = await begin;
      expect(started.status()).toBe(200);
      expect(await started.json()).toMatchObject({ status: "success", next_step: "verify_email" });
      const code = await registrationEmailCode(request, email);
      const codeInput = page.locator('input[autocomplete="one-time-code"]');
      await expect(codeInput).toBeVisible();
      await expect.poll(async () => {
        if (!(await codeInput.isVisible())) return true;
        await codeInput.fill(code);
        await page.getByRole("button", { name: /^verify$/i }).click();
        return !(await codeInput.isVisible());
      }, { timeout: 60_000, intervals: [500] }).toBe(true);
      await page.locator('input[autocomplete="name"]').fill(`Boundary ${boundary}`);
      const finish = page.waitForResponse(response =>
        new RegExp(`^${registrationPath}/[^/]+/finish$`).test(new URL(response.url()).pathname)
        && response.request().method() === "POST", { timeout: 60_000 });
      await page.getByRole("button", { name: /^continue$/i }).click();
      const manualFinish = page.getByRole("button", { name: /^create account$/i });
      await expect(manualFinish.or(page.getByRole("link", { name: "Settings", exact: true }))
        .or(page.locator(".alert-critical"))).toBeVisible({ timeout: 60_000 });
      if (await manualFinish.isVisible()) await manualFinish.click();
      const completed = await finish;
      expect(completed.status(), "a valid prepared handle completes persistence").toBe(200);
      expect(await completed.json()).toMatchObject({ status: "success" });
      const accountId = await signedInAccount(page, handle);
      await page.reload();
      await expect(page.getByRole("link", { name: "Settings", exact: true })).toBeVisible();

      // A fresh cookie jar must authenticate the complete username, rather
      // than inheriting the registration browser's accepted session.
      const returning = await browser.newContext({ locale: "en-US" });
      try {
        const loginPage = await returning.newPage();
        const providers = loginPage.waitForResponse(response =>
          new URL(response.url()).pathname === "/_coauth/account/auth/providers"
          && response.request().method() === "GET");
        await loginPage.goto(`${authority()}/login`);
        expect((await (await providers).json()).current_account ?? null).toBeNull();
        const login = loginPage.waitForResponse(response =>
          new URL(response.url()).pathname === "/_coauth/account/auth/login"
          && response.request().method() === "POST");
        await submitCoauthPasswordCredentials(loginPage, { handle, password });
        const signedIn = await login;
        expect(signedIn.status()).toBe(200);
        expect(await signedIn.json()).toMatchObject({ status: "success" });
        expect(await signedInAccount(loginPage, handle)).toBe(accountId);
      } finally { await returning.close(); }
    } finally { await context.close(); }
  });
}

test("Coauth rejects 129 character usernames without a persistence error @fully-implemented @coauth-handle-boundary", async ({ page }) => {
  const handle = asciiHandle(129);
  await fillRegistration(page, handle, `invalid-${randomUUID()}@example.test`);
  const response = page.waitForResponse(response =>
    new URL(response.url()).pathname === registrationPath && response.request().method() === "POST");
  await page.getByRole("button", { name: /^create account$/i }).click();
  const rejected = await response;
  expect(rejected.status()).toBe(200);
  expect(await rejected.json()).toMatchObject({ status: "error", error: "handle_invalid" });
  await expect(page.getByRole("alert")).toContainText(/128/);
  await expect(page.getByRole("alert")).not.toContainText(/handle_invalid|internal_error/);
  await expect(page.locator('input[autocomplete="username"]')).toHaveValue(handle);
});

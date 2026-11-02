import { randomUUID } from "node:crypto";

import { expect, test, type CDPSession, type Page } from "../../helpers/arkret-test";
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
  const username = page.getByLabel("Username", { exact: true });
  await username.fill(handle);
  await expect(username).toHaveValue(handle);
  await page.getByLabel("Email address", { exact: true }).fill(email);
  await page.getByLabel("New password", { exact: true }).fill(password);
  await page.getByLabel("Confirm password", { exact: true }).fill(password);
}

async function signedInAccount(page: Page, handle: string): Promise<string> {
  await expect(page.getByRole("link", { name: "Settings", exact: true })).toBeVisible();
  await page.waitForLoadState("load");
  const [response] = await Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === "/_coauth/self/viewer"
      && response.request().method() === "GET"),
    page.reload({ waitUntil: "domcontentloaded" }),
  ]);
  expect(response.status(), "an unbound account can read its own Coauth viewer").toBe(200);
  const body = await response.json();
  expect(body.viewer).toMatchObject({ __typename: "User", username: handle, has_password: true });
  expect(body.viewer.principal_id ?? null, "account registration must not invent a published principal").toBeNull();
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
    let responseBodies: CDPSession | undefined;
    try {
      const page = await context.newPage();
      responseBodies = await context.newCDPSession(page);
      // Observe the original browser response across Coauth document navigation.
      await responseBodies.send("Network.configureDurableMessages", {
        maxTotalBufferSize: 4 * 1024 * 1024,
        maxResourceBufferSize: 1024 * 1024,
      });
      await fillRegistration(page, handle, email);
      const begin = page.waitForResponse(response =>
        new URL(response.url()).pathname === registrationPath && response.request().method() === "POST")
        .then(async response => ({ response, body: await response.json() }));
      await page.getByRole("button", { name: /^create account$/i }).click();
      const { response: started, body: startedBody } = await begin;
      expect(started.status()).toBe(200);
      expect(startedBody).toMatchObject({ status: "success", next_step: "verify_email" });
      const code = await registrationEmailCode(request, email);
      const codeInput = page.getByLabel("Verification code", { exact: true });
      await expect(codeInput).toBeVisible();
      await expect.poll(async () => {
        if (!(await codeInput.isVisible())) return true;
        await codeInput.fill(code);
        await page.getByRole("button", { name: /^verify$/i }).click();
        return !(await codeInput.isVisible());
      }, { timeout: 60_000, intervals: [500] }).toBe(true);
      await page.getByLabel(/^display name$/i).fill(`Boundary ${boundary}`);
      const finish = page.waitForResponse(response =>
        new RegExp(`^${registrationPath}/[^/]+/finish$`).test(new URL(response.url()).pathname)
        && response.request().method() === "POST", { timeout: 60_000 })
        .then(async response => ({ response, body: await response.json() }));
      await page.getByRole("button", { name: /^continue$/i }).click();
      const manualFinish = page.getByRole("button", { name: /^create account$/i });
      await expect(manualFinish.or(page.getByRole("link", { name: "Settings", exact: true }))
        .or(page.locator(".alert-critical"))).toBeVisible({ timeout: 60_000 });
      if (await manualFinish.isVisible()) await manualFinish.click();
      const { response: completed, body: completedBody } = await finish;
      expect(completed.status(), "a valid prepared handle completes persistence").toBe(200);
      expect(completedBody).toMatchObject({ status: "success" });
      const accountId = await signedInAccount(page, handle);
      await page.reload();
      await expect(page.getByRole("link", { name: "Settings", exact: true })).toBeVisible();

      // A fresh cookie jar must authenticate the complete username, rather
      // than inheriting the registration browser's accepted session.
      const returning = await browser.newContext({ locale: "en-US" });
      let returningResponseBodies: CDPSession | undefined;
      try {
        const loginPage = await returning.newPage();
        returningResponseBodies = await returning.newCDPSession(loginPage);
        await returningResponseBodies.send("Network.configureDurableMessages", {
          maxTotalBufferSize: 4 * 1024 * 1024,
          maxResourceBufferSize: 1024 * 1024,
        });
        const providers = loginPage.waitForResponse(response =>
          new URL(response.url()).pathname === "/_coauth/account/auth/providers"
          && response.request().method() === "GET");
        await loginPage.goto(`${authority()}/login`);
        expect((await (await providers).json()).current_account ?? null).toBeNull();
        const login = loginPage.waitForResponse(response =>
          new URL(response.url()).pathname === "/_coauth/account/auth/login"
          && response.request().method() === "POST")
          .then(async response => ({ response, body: await response.json() }));
        await submitCoauthPasswordCredentials(loginPage, { handle, password });
        const { response: signedIn, body: signedInBody } = await login;
        expect(signedIn.status()).toBe(200);
        expect(signedInBody).toMatchObject({ status: "success" });
        expect(await signedInAccount(loginPage, handle)).toBe(accountId);
      } finally {
        try { await returningResponseBodies?.detach(); }
        finally { await returning.close(); }
      }
    } finally {
      try { await responseBodies?.detach(); }
      finally { await context.close(); }
    }
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
  await expect(page.getByLabel("Username", { exact: true })).toHaveValue(handle);
});

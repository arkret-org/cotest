import { expect, type Page } from "@playwright/test";
import { solandBaseUrl } from "./env";
import { type JointUserPage } from "./users";

export type RealOidcAccount = { handle: string; password: string };

export async function submitCoauthPasswordCredentials(
  page: Page,
  account: RealOidcAccount,
): Promise<void> {
  const loginHandle = page.locator("#login-handle");
  const loginPassword = page.locator("#login-password");
  const shell = page.getByTestId("client-shell");

  await expect(loginHandle.or(loginPassword).or(shell)).toBeVisible({ timeout: 60_000 });
  if (await shell.isVisible()) {
    return;
  }

  if (await loginHandle.isVisible()) {
    const identifier = account.handle.trim();
    expect(identifier, "real OIDC login handle must not be empty").not.toBe("");
    await loginHandle.click();
    await loginHandle.fill(identifier);
    await expect(loginHandle).toHaveValue(identifier, { timeout: 5_000 });
    const next = page.getByTestId("coauth-login-identifier-submit");
    if (await next.isVisible()) {
      await next.click();
    }
  }

  await expect(loginPassword.or(shell)).toBeVisible({ timeout: 60_000 });
  if (await shell.isVisible()) {
    return;
  }

  await loginPassword.fill(account.password);
  await page.getByTestId("coauth-login-submit").click();
}

// Drive inkson's server-login button through coauth and back to the signed-in
// app. Robust to both paths: a fresh coauth session shows credentials +
// consent; a returning coauth browser session may bounce straight back.
export async function serverLoginViaCoauth(
  page: Page,
  account: RealOidcAccount,
): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await page.getByTestId("login-server-url").fill(solandBaseUrl());
    await page.getByTestId("start-server-login-button").click();

    await submitCoauthPasswordCredentials(page, account);

    const approve = page.getByTestId("coauth-oauth-approve");
    const consentShown = await approve
      .waitFor({ state: "visible", timeout: 20_000 })
      .then(() => true)
      .catch(() => false);
    if (consentShown) {
      await approve.click();
    }

    const shell = page.getByTestId("client-shell");
    const authenticated = await expect(shell)
      .toBeVisible({ timeout: 60_000 })
      .then(() => true)
      .catch(() => false);
    if (authenticated) {
      await expect(page.getByTestId("login-panel")).toHaveCount(0);
      return;
    }

    if (attempt === 0) {
      // Coauth can return to Inkson before a transient session-grant exchange
      // failure has restored the login panel. Reloading the local route clears
      // callback-only UI state; the second authorization ceremony remains a
      // complete, independently verified login.
      await page.goto(`${new URL(page.url()).origin}/login`, {
        waitUntil: "domcontentloaded",
      });
      await expect(page.getByTestId("login-panel")).toBeVisible({
        timeout: 30_000,
      });
    }
  }
  throw new Error(
    `coauth login returned without an active session grant: ${page.url()}`,
  );
}

export async function hardLogoutViaAccountMenu(
  jointPage: JointUserPage,
): Promise<void> {
  const page = jointPage.page;
  await page.getByTestId("account-menu-button").click();
  await page.getByTestId("account-menu-session-logout").click();
  await expect(page.getByTestId("login-panel")).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("client-shell")).toHaveCount(0);
}

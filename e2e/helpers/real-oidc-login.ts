import {
  expect,
  type Page,
  type Browser,
  type APIRequestContext,
} from "@playwright/test";
import { colandBaseUrl } from "./env";
import {
  createDpopUserSessionForAccount,
  openDpopUserPageFromSession,
  type JointUserPage,
} from "./users";
import type { CoauthPasswordAccount } from "./coauth-register";

export type RealOidcAccount = { handle: string; password: string };

export async function submitCoauthPasswordCredentials(
  page: Page,
  account: RealOidcAccount,
): Promise<void> {
  const loginHandle = page.getByLabel("Username", { exact: true });
  const loginPassword = page.getByLabel("Password", { exact: true });
  const shell = page.locator("html[data-inkson-app-shell] .shell.app");

  await expect(loginHandle.or(loginPassword).or(shell)).toBeVisible({
    timeout: 60_000,
  });
  if (await shell.isVisible()) {
    return;
  }

  if (await loginHandle.isVisible()) {
    const identifier = account.handle.trim();
    expect(identifier, "real OIDC login handle must not be empty").not.toBe("");
    await loginHandle.click();
    await loginHandle.fill(identifier);
    await expect(loginHandle).toHaveValue(identifier, { timeout: 5_000 });
    const next = page.locator(".login-container").getByRole("button", { name: "Continue", exact: true });
    if (await next.isVisible()) {
      await next.click();
    }
  }

  await expect(loginPassword.or(shell)).toBeVisible({ timeout: 60_000 });
  if (await shell.isVisible()) {
    return;
  }

  await loginPassword.fill(account.password);
  await page.locator(".login-container").getByRole("button", { name: "Sign in", exact: true }).click();
}

// Drive inkson's server-login button through coauth and back to the signed-in
// app. Robust to both paths: a fresh coauth session shows credentials +
// consent; a returning coauth browser session may bounce straight back.
export async function serverLoginViaCoauth(
  page: Page,
  account: RealOidcAccount,
): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await page.getByLabel("Sign-in server URL", { exact: true }).fill(colandBaseUrl());
    await page.locator(".auth-panel:not(.registration-panel)").getByRole("button", { name: "Sign in to this server", exact: true }).click();

    await submitCoauthPasswordCredentials(page, account);

    const approve = page.locator(".login-container").getByRole("button", { name: "Allow", exact: true });
    const consentShown = await approve
      .waitFor({ state: "visible", timeout: 20_000 })
      .then(() => true)
      .catch(() => false);
    if (consentShown) {
      await approve.click();
    }

    const shell = page.locator("html[data-inkson-app-shell] .shell.app");
    const authenticated = await expect(shell)
      .toBeVisible({ timeout: 60_000 })
      .then(() => true)
      .catch(() => false);
    if (authenticated) {
      await expect(page.locator(".auth-panel:not(.registration-panel)")).toHaveCount(0);
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
      await expect(page.locator(".auth-panel:not(.registration-panel)")).toBeVisible({
        timeout: 30_000,
      });
    }
  }
  const status = await page
    .locator(".auth-panel .auth-status")
    .textContent()
    .catch(() => null);
  // Read only the dedicated status element, never the page or recovery words.
  const safeStatus = status
    ?.replace(/[A-Za-z0-9_-]{32,}/g, "[redacted]")
    .slice(0, 600);
  throw new Error(
    `coauth login did not reach the authenticated shell: ${new URL(page.url()).pathname}; status=${safeStatus ?? "unavailable"}`,
  );
}

export async function hardLogoutViaAccountMenu(
  jointPage: JointUserPage,
): Promise<void> {
  const page = jointPage.page;
  await page.getByRole("button", { name: "Account menu", exact: true }).click();
  await page.locator(".account-menu").getByRole("button", { name: "Sign out of this account", exact: true }).click();
  await expect(page.locator(".auth-panel:not(.registration-panel)")).toBeVisible({
    timeout: 60_000,
  });
  await expect(page.locator("html[data-inkson-app-shell] .shell.app")).toHaveCount(0);
}

// A bound account's first browser session is already a returning-device flow.
// Install only the exact signer and receipt produced by canonical registration,
// then log out before driving OIDC. Copying its public DID into a fresh browser
// cannot prove possession of its accepted device key (device-lifecycle section 3).
export async function openAcceptedDeviceForOidcLogin(
  browser: Browser,
  request: APIRequestContext,
  account: CoauthPasswordAccount,
  prefix: string,
): Promise<JointUserPage> {
  return (
    await prepareAcceptedDeviceForOidcLogin(
      browser,
      request,
      account,
      prefix,
      false,
    )
  ).page;
}

export async function openAcceptedDeviceWithRecoveryKeyForOidcLogin(
  browser: Browser,
  request: APIRequestContext,
  account: CoauthPasswordAccount,
  prefix: string,
): Promise<{ page: JointUserPage; recoveryKey: string }> {
  const prepared = await prepareAcceptedDeviceForOidcLogin(
    browser,
    request,
    account,
    prefix,
    true,
  );
  return {
    page: prepared.page,
    recoveryKey: prepared.recoveryKey ?? account.recoveryKey,
  };
}

async function prepareAcceptedDeviceForOidcLogin(
  browser: Browser,
  request: APIRequestContext,
  account: CoauthPasswordAccount,
  prefix: string,
  establishRecoveryKey: boolean,
): Promise<{ page: JointUserPage; recoveryKey?: string }> {
  const session = await createDpopUserSessionForAccount(
    request,
    prefix,
    account,
  );
  const flow = await openDpopUserPageFromSession(browser, session, {
    prepareMlsDevice: false,
    autoCompleteRecoveryKeySetup: false,
  });
  if (!flow)
    throw new Error("canonical accepted-device fixture is unavailable");
  try {
    const recoveryKey = establishRecoveryKey
      ? await flow.page.completeRecoveryKeySetupIfPrompted(30_000)
      : undefined;
    await hardLogoutViaAccountMenu(flow.page);
    return { page: flow.page, recoveryKey };
  } catch (error) {
    await flow.page.close();
    throw error;
  }
}

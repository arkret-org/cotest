import { expect, test, type Page } from "../../helpers/arkret-test";
import { coauthBaseUrl, colandBaseUrl, inksonBaseUrl, optionalEnv } from "../../helpers/env";
import { registerUnboundCoauthPasswordAccount } from "../../helpers/coauth-register";
import { submitCoauthPasswordCredentials, type RealOidcAccount } from "../../helpers/real-oidc-login";
import { assertJointStackNotRequired } from "../../helpers/users";

// These scenarios handle recovery material. Never persist UI traces or captures.
test.use({ trace: "off", video: "off", screenshot: "off" });

type SavedAccount = {
  profile_id: string;
  authority: { principal_id: string; station_id: string };
  device_id: string;
  server_url: string;
};

async function currentAccount(page: Page): Promise<SavedAccount> {
  return page.evaluate(() => {
    const config = JSON.parse(localStorage.getItem("inkson.config.v1") ?? "{}");
    if (!config.active_account) throw new Error("no accepted account context");
    const { profile_id, authority, device_id, server_url } = config.active_account;
    return { profile_id, authority, device_id, server_url };
  });
}

async function authorize(page: Page, account: RealOidcAccount): Promise<void> {
  await page.getByTestId("login-server-url").fill(colandBaseUrl());
  await page.getByTestId("start-server-login-button").click();
  await expect(page.locator("#login-handle").or(page.locator("#login-password")))
    .toBeVisible({ timeout: 30_000 });
  const changeAccount = page.getByTestId("coauth-login-change-identifier");
  if (await changeAccount.isVisible()) await changeAccount.click();
  await submitCoauthPasswordCredentials(page, account);
  const approve = page.getByTestId("coauth-oauth-approve");
  const inkson = page.getByTestId("auth-shell").or(page.getByTestId("client-shell"));
  await expect(approve.or(inkson)).toBeVisible({ timeout: 30_000 });
  if (await approve.isVisible()) await approve.click();
  await expect(inkson).toBeVisible({ timeout: 30_000 });
}

async function completeNewIdentity(page: Page): Promise<void> {
  await page.getByTestId("choose-new-identity").click();
  await expect(page.getByTestId("account-switcher")).toHaveCount(0);
  const words = page.getByTestId("onboarding-recovery-key-display").locator("li");
  await expect(words).toHaveCount(24);
  const recoveryKey = (await words.allTextContents()).map((word) => word.trim()).join(" ");
  await page.getByTestId("onboarding-recovery-key-confirm").fill(recoveryKey);
  await page.getByTestId("onboarding-bind-identity").click();
  await expect(page.getByTestId("onboarding-complete")).toBeVisible({ timeout: 120_000 });
  await page.getByTestId("onboarding-complete").getByRole("link", { name: "Continue", exact: true }).click();
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 30_000 });
}

async function addAccount(page: Page): Promise<void> {
  await page.getByTestId("account-menu-button").click();
  await page.getByTestId("account-menu").getByTestId("account-add").click();
  await expect(page.getByTestId("login-panel")).toBeVisible();
  await expect(page.getByTestId("account-switcher")).toHaveCount(0);
  await expect(page.getByTestId("return-previous-account")).toBeVisible();
  await expect(page.getByTestId("start-server-login-button")).toHaveText("Sign in to this server");
}

async function selectSavedAccount(page: Page, account: SavedAccount): Promise<void> {
  if (!(await page.getByTestId("account-menu").isVisible())) {
    await page.getByTestId("account-menu-button").click();
  }
  // The previous account's already-issued request may finish during retirement.
  // Require a real successful response for the selected principal as well as
  // the matching published account; a local metadata change alone cannot pass.
  const viewer = page.waitForResponse(async (response) => {
    if (new URL(response.url()).pathname !== "/_arkret/self/account/viewer" || response.status() !== 200) return false;
    if (await response.finished()) return false;
    try {
      return (await response.json()).principal_id === account.authority.principal_id;
    } catch (error) {
      // Retiring the old account aborts fetches even after response headers.
      // Chrome can then discard the body before reporting request failure.
      if (response.request().failure() || (error instanceof Error && error.message.includes("No data found for resource"))) return false;
      throw error;
    }
  });
  await page.getByTestId("account-switch-select").selectOption(account.profile_id);
  const result = await (await viewer).json();
  expect(result.principal_id).toBe(account.authority.principal_id);
  expect(result.primary_handle_claim.claim.subject_account_id).toEqual(account.authority);
  await expect(page.getByTestId("client-shell")).toBeVisible();
  expect(await currentAccount(page)).toEqual(account);
}

test("real saved sessions survive add-account, switch both ways and require Coauth after logout @saved-account-session-gate", async ({ browser, request }) => {
  test.setTimeout(360_000);
  const authority = coauthBaseUrl();
  if (!authority || !optionalEnv("COTEST_REAL_OIDC_LOGIN")) {
    assertJointStackNotRequired("real saved-account session switching");
    test.skip(true, "requires the real Coauth browser stack");
    return;
  }
  const stamp = Date.now();
  const first = await registerUnboundCoauthPasswordAccount(request, authority, { handle: `warm-first-${stamp}` });
  const second = await registerUnboundCoauthPasswordAccount(request, authority, { handle: `warm-second-${stamp}` });
  const context = await browser.newContext({
    baseURL: inksonBaseUrl(),
    ignoreHTTPSErrors: optionalEnv("COTEST_IGNORE_HTTPS") === "1",
  });
  const page = await context.newPage();
  await page.addLocatorHandler(page.locator('#__dx-toast[aria-hidden="false"]'), async (notice) => {
    await notice.click();
  });
  try {
    await page.goto("/login");
    await expect(page.getByTestId("login-panel")).toBeVisible();
    await expect(page.getByTestId("account-switcher")).toHaveCount(0);
    await authorize(page, first);
    await completeNewIdentity(page);
    const firstAccount = await currentAccount(page);
    await page.reload();
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 30_000 });
    expect(await currentAccount(page)).toEqual(firstAccount);

    const documentOrigin = await page.evaluate(() => performance.timeOrigin);
    const authorizationRequests: URL[] = [];
    const captureAuthorization = (incoming: { url(): string }) => {
      const url = new URL(incoming.url());
      if (url.origin === new URL(authority).origin && url.pathname === "/authorize") {
        authorizationRequests.push(url);
      }
    };
    page.on("request", captureAuthorization);
    await addAccount(page);
    await page.getByTestId("login-server-url").fill("https://unused-server.example/");
    await page.getByTestId("return-previous-account").click();
    await expect(page.getByTestId("client-shell")).toBeVisible();
    expect(await currentAccount(page)).toEqual(firstAccount);
    expect(await page.evaluate(() => performance.timeOrigin)).toBe(documentOrigin);
    expect(authorizationRequests).toHaveLength(0);

    await addAccount(page);
    await authorize(page, second);
    await completeNewIdentity(page);
    const secondAccount = await currentAccount(page);
    expect(secondAccount.authority.principal_id).not.toBe(firstAccount.authority.principal_id);
    expect(secondAccount.authority.station_id).toBe(firstAccount.authority.station_id);
    // An older installation may have saved identities without display labels.
    // A normal authenticated bootstrap must recover the real handle, while
    // preserving the accepted profile, device and credentials.
    await page.evaluate(() => {
      const profiles = JSON.parse(localStorage.getItem("inkson.profiles.v1") ?? "{}");
      profiles.profiles.find((profile: { profile_id: string }) => profile.profile_id === profiles.active_profile_id).label = "";
      localStorage.setItem("inkson.profiles.v1", JSON.stringify(profiles));
    });
    await page.reload();
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 30_000 });
    expect(await currentAccount(page)).toEqual(secondAccount);
    await page.getByTestId("account-menu-button").click();
    await expect(page.getByTestId("account-switch-select").locator(`option[value="${firstAccount.profile_id}"]`)).toContainText(first.handle);
    await expect(page.getByTestId("account-switch-select").locator(`option[value="${secondAccount.profile_id}"]`)).toContainText(second.handle);
    const warmOrigin = await page.evaluate(() => performance.timeOrigin);
    const authorizationsBeforeSwitch = authorizationRequests.length;
    await selectSavedAccount(page, firstAccount);
    await selectSavedAccount(page, secondAccount);
    expect(await page.evaluate(() => performance.timeOrigin)).toBe(warmOrigin);
    expect(authorizationRequests).toHaveLength(authorizationsBeforeSwitch);

    await selectSavedAccount(page, firstAccount);
    await page.getByTestId("account-menu-button").click();
    await page.getByTestId("account-menu-session-logout").click();
    await expect(page.getByTestId("login-panel")).toBeVisible();
    await expect(page.getByTestId("account-switcher")).toHaveCount(0);
    await expect(page.getByTestId("client-shell")).toHaveCount(0);
    await expect(page.getByTestId("login-server-url")).toHaveValue(firstAccount.server_url);
    await authorize(page, first);
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 30_000 });
    expect(await currentAccount(page)).toEqual(firstAccount);
    const returningRequest = authorizationRequests.at(-1)!;
    expect(returningRequest.searchParams.get("prompt")).toBe("login");
    expect(returningRequest.searchParams.has("login_hint")).toBe(false);
    await selectSavedAccount(page, secondAccount);
  } finally {
    await context.close();
  }
});

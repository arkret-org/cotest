import { writeFile } from "node:fs/promises";
import { expect, test, type Page } from "../../helpers/arkret-test";
import { coauthBaseUrl, colandBaseUrl, inksonBaseUrl, optionalEnv } from "../../helpers/env";
import { registerUnboundCoauthPasswordAccount } from "../../helpers/coauth-register";
import { submitCoauthPasswordCredentials, type RealOidcAccount } from "../../helpers/real-oidc-login";
import { assertJointStackNotRequired } from "../../helpers/users";
import { enterSecretText } from "../../helpers/secret-input";

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
  await page.locator(".auth-station-field input").fill(colandBaseUrl());
  await page.locator(".auth-primary").click();
  await expect(page.getByLabel("Username", { exact: true }).or(page.getByLabel("Password", { exact: true })))
    .toBeVisible({ timeout: 30_000 });
  const changeAccount = page.locator(".login-container").getByRole("button", { name: "Use another account", exact: true });
  if (await changeAccount.isVisible()) await changeAccount.click();
  await submitCoauthPasswordCredentials(page, account);
  const approve = page.locator(".login-container").getByRole("button", { name: "Allow", exact: true });
  const inkson = page.locator(".auth-shell").or(page.locator(".shell.app"));
  await expect(approve.or(inkson)).toBeVisible({ timeout: 30_000 });
  if (await approve.isVisible()) await approve.click();
  await expect(inkson).toBeVisible({ timeout: 30_000 });
}

async function completeNewIdentity(page: Page): Promise<void> {
  await page.locator(".choose-new-identity").click();
  await expect(page.locator(".account-switcher")).toHaveCount(0);
  const words = page.locator(".onboarding-recovery-key-display .rk-word");
  await expect(words).toHaveCount(24);
  const recoveryKey = (await words.allTextContents()).map((word) => word.trim()).join(" ");
  await enterSecretText(page, page.getByLabel("Re-enter the 24 words", { exact: true }), recoveryKey);
  await page.locator(".onboarding-bind-identity").click();
  await page.locator(".onboarding-continue")
    .and(page.getByRole("button", { name: "Continue", exact: true }))
    .click({ timeout: 120_000 });
  await expect(page.locator(".shell.app")).toBeVisible({ timeout: 30_000 });
}

async function addAccount(page: Page): Promise<void> {
  await page.locator(".rail-account").click();
  await page.locator(".account-page").locator(".account-picker__add").click();
  await expect(page.locator(".auth-panel")).toBeVisible();
  await expect(page.locator(".account-switcher")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Back to previous account", exact: true })).toBeVisible();
  await expect(page.locator(".auth-primary")).toHaveText("Sign in to this server");
}

function accountCard(page: Page, account: SavedAccount) {
  const station = account.server_url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return page.locator(".account-switch-row").filter({ hasText: account.authority.principal_id })
    .and(page.getByRole("button", { name: new RegExp(station) }));
}

async function selectSavedAccount(page: Page, account: SavedAccount): Promise<void> {
  if (!(await page.locator(".account-page").isVisible())) {
    await page.locator(".rail-account").click();
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
  await accountCard(page, account).click();
  const result = await (await viewer).json();
  expect(result.principal_id).toBe(account.authority.principal_id);
  expect(result.primary_handle_claim.claim.subject_account_id).toEqual(account.authority);
  await expect(page.locator(".shell.app")).toBeVisible();
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
  const browserErrors: string[] = [];
  page.on("pageerror", error => browserErrors.push(error.stack ?? error.message));
  await page.addLocatorHandler(page.locator('#__dx-toast[aria-hidden="false"]'), async (notice) => {
    await notice.click();
  });
  try {
    await page.goto("/login");
    await expect(page.locator(".auth-panel")).toBeVisible();
    await expect(page.locator(".account-switcher")).toHaveCount(0);
    await test.step("authorize the first saved account", () => authorize(page, first));
    await completeNewIdentity(page);
    const firstAccount = await currentAccount(page);
    await page.reload();
    await expect(page.locator(".shell.app")).toBeVisible({ timeout: 30_000 });
    expect(await currentAccount(page)).toEqual(firstAccount);

    await test.step("open the account page and enter Settings from the mobile rail", async () => {
      const viewport = page.viewportSize()!;
      const avatar = page.locator(".rail-account");
      const accountPage = page.locator(".account-page");
      const settings = accountPage.getByRole("link", { name: "Settings", exact: true });
      await page.setViewportSize({ width: 390, height: 844 });
      await expect(page.locator(".rail-settings")).toBeHidden();
      await avatar.click();
      await expect(page).toHaveURL(/\/account$/);
      await expect(avatar).toHaveAttribute("aria-current", "page");
      await expect(accountPage.locator(".who")).toContainText(first.handle);
      await settings.click();
      await expect(page).toHaveURL(/\/settings$/);
      await expect(page.locator(".settings-sidebar-column")).toBeVisible();
      await page.goBack();
      await expect(accountPage).toBeVisible();
      await page.setViewportSize(viewport);
      await expect(settings).toBeHidden();
      await expect(page.locator(".rail-settings")).toBeVisible();
    });

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
    await page.locator(".auth-station-field input").fill("https://unused-server.example/");
    await page.getByRole("button", { name: "Back to previous account", exact: true }).click();
    await expect(page.locator(".shell.app")).toBeVisible();
    expect(await currentAccount(page)).toEqual(firstAccount);
    expect(await page.evaluate(() => performance.timeOrigin)).toBe(documentOrigin);
    expect(authorizationRequests).toHaveLength(0);

    await addAccount(page);
    await test.step("reauthenticate to add the second account", () => authorize(page, second));
    await completeNewIdentity(page);
    const secondAccount = await currentAccount(page);
    expect(secondAccount.authority.principal_id).not.toBe(firstAccount.authority.principal_id);
    expect(secondAccount.authority.station_id).toBe(firstAccount.authority.station_id);
    // A saved identity can remain unnamed until its verified handle arrives.
    // A normal authenticated bootstrap must recover the real handle, while
    // preserving the accepted profile, device and credentials.
    await page.evaluate(() => {
      const profiles = JSON.parse(localStorage.getItem("inkson.profiles.v1") ?? "{}");
      profiles.profiles.find((profile: { profile_id: string }) => profile.profile_id === profiles.active_profile_id).label = "";
      localStorage.setItem("inkson.profiles.v1", JSON.stringify(profiles));
    });
    await page.addInitScript(() => {
      const owners: string[] = [];
      Object.assign(window, { savedProfileLabelOwnerIds: owners });
      const remember = (owner: string | null) => {
        if (owner && !owners.includes(owner)) owners.push(owner);
      };
      // Observe only the public owner marker, never private DOM values.
      new MutationObserver(records => {
        for (const record of records) {
          if (record.type === "attributes" && record.target === document.documentElement) {
            remember(record.oldValue);
          }
        }
        remember(document.documentElement?.getAttribute("data-inkson-app-shell") ?? null);
      }).observe(document, {
        childList: true, subtree: true, attributes: true,
        attributeFilter: ["data-inkson-app-shell"], attributeOldValue: true,
      });
    });
    await page.reload();
    try {
      await expect(page.locator(".shell.app")).toBeVisible({ timeout: 30_000 });
      expect(await currentAccount(page)).toEqual(secondAccount);
      await page.locator(".rail-account").click();
      await expect(accountCard(page, firstAccount)).toContainText(first.handle);
      await expect.poll(() => page.evaluate(profileId => {
        const saved = JSON.parse(localStorage.getItem("inkson.profiles.v1") ?? "{}");
        return saved.profiles.find((profile: { profile_id: string }) => profile.profile_id === profileId)?.label;
      }, secondAccount.profile_id)).toMatch(new RegExp(`^${second.handle}:`));
      expect(await page.evaluate(() => (window as unknown as {
        savedProfileLabelOwnerIds: string[];
      }).savedProfileLabelOwnerIds.length), "label repair retains the authenticated account owner").toBe(1);
    } finally {
      const count = await page.evaluate(() => (window as unknown as {
        savedProfileLabelOwnerIds?: string[];
      }).savedProfileLabelOwnerIds?.length ?? null).catch(() => null);
      // Persist only a public lifetime count, never DOM or input material.
      const file = test.info().outputPath("saved-profile-label-owner-count.json");
      await writeFile(file, JSON.stringify({ distinct_public_owner_count: count }));
      await test.info().attach("saved-profile-label-owner-count", {
        path: file, contentType: "application/json",
      });
    }
    const warmOrigin = await page.evaluate(() => performance.timeOrigin);
    const authorizationsBeforeSwitch = authorizationRequests.length;
    await selectSavedAccount(page, firstAccount);
    await selectSavedAccount(page, secondAccount);
    expect(await page.evaluate(() => performance.timeOrigin)).toBe(warmOrigin);
    expect(authorizationRequests).toHaveLength(authorizationsBeforeSwitch);

    await selectSavedAccount(page, firstAccount);
    await page.locator(".rail-account").click();
    const currentLogout = page.waitForResponse(response => new URL(response.url()).pathname === "/_arkret/gate/account/logout");
    await page.getByRole("button", { name: "Sign out of this account", exact: true }).click();
    expect((await currentLogout).status()).toBe(200);
    await expect.poll(() => currentAccount(page)).toEqual(secondAccount);
    await expect(page.locator(".shell.app")).toBeVisible();
    await page.reload();
    await expect(page.locator(".shell.app")).toBeVisible();
    expect(await currentAccount(page)).toEqual(secondAccount);
    await page.locator(".rail-account").click();
    await accountCard(page, firstAccount).click();
    await expect(page.locator(".auth-panel")).toBeVisible();
    await expect(page.locator(".account-switcher")).toHaveCount(0);
    await expect(page.locator(".shell.app")).toHaveCount(0);
    await expect(page.locator(".auth-station-field input")).toHaveValue(firstAccount.server_url);
    await page.reload();
    await expect(page.locator(".auth-panel")).toBeVisible();
    await expect(page.locator(".shell.app")).toHaveCount(0);
    await test.step("reauthenticate the logged-out account", () => authorize(page, first));
    await expect(page.locator(".shell.app")).toBeVisible({ timeout: 30_000 });
    expect(await currentAccount(page)).toEqual(firstAccount);
    const returningRequest = authorizationRequests.at(-1)!;
    expect(returningRequest.searchParams.get("prompt")).toBe("login");
    expect(returningRequest.searchParams.has("login_hint")).toBe(false);
    await selectSavedAccount(page, secondAccount);

    await test.step("create an encrypted Realm without trapping after acceptance", async () => {
      const errors: string[] = [];
      const recordError = (error: Error) => errors.push(error.message);
      page.on("pageerror", recordError);
      try {
        await page.goto(`${inksonBaseUrl()}/setup/realms`);
        await page.locator(".realm-title-input input").fill(`Saved session Realm ${Date.now()}`);
        await page.locator(".new-realm-next-button").click();
        await page.locator(".new-realm-next-button").click();
        await page.locator(".create-realm-button").click();
        await expect(page.locator(".selected-realm-id")).toBeVisible();
        await expect(page.locator(".open-created-realm")).toBeVisible({ timeout: 90_000 });
        await expect(page.locator(".realm-setup-done")).toContainText("MLS Genesis accepted; encryption active on this device");
        await page.locator(".open-created-realm").click();
        const realmUrl = page.url();
        await page.reload();
        await expect(page.locator(".shell.app")).toBeVisible();
        expect(page.url()).toBe(realmUrl);
        expect(await currentAccount(page)).toEqual(secondAccount);
        expect(errors).toEqual([]);
      } finally {
        page.off("pageerror", recordError);
      }
    });

    await test.step("sign out all saved sessions and retain the logout across cold reloads", async () => {
      const errors: string[] = [];
      const recordError = (error: Error) => errors.push(error.message);
      page.on("pageerror", recordError);
      const logouts: number[] = [];
      const recordLogout = (response: { url(): string; status(): number }) => {
        if (new URL(response.url()).pathname === "/_arkret/gate/account/logout") logouts.push(response.status());
      };
      page.on("response", recordLogout);
      try {
        await page.locator(".rail-account").click();
        await page.locator(".account-page-sign-out-all").click();
        await expect(page.locator(".auth-panel")).toBeVisible();
        await expect.poll(() => logouts.filter(status => status === 200).length).toBe(2);
        for (let count = 0; count < 2; count++) {
          await page.reload();
          await expect(page.locator(".auth-panel")).toBeVisible();
          await expect(page.locator(".shell.app")).toHaveCount(0);
        }
        const cold = await context.newPage();
        try {
          await cold.goto(inksonBaseUrl());
          await expect(cold.locator(".auth-panel")).toBeVisible();
          await expect(cold.locator(".shell.app")).toHaveCount(0);
        } finally {
          await cold.close();
        }
        expect(errors).toEqual([]);
      } finally {
        page.off("pageerror", recordError);
        page.off("response", recordLogout);
      }
    });
    expect(browserErrors).toEqual([]);
  } finally {
    const file = test.info().outputPath("public-browser-status.json");
    await writeFile(file, JSON.stringify({
      path: new URL(page.url()).pathname,
      errors: browserErrors,
      headings: await page.locator("h1,h2,h3").allTextContents().catch(() => []),
      statuses: await page.locator(".auth-status,.account-handoff-status,.auth-error").allTextContents().catch(() => []),
    }));
    await context.close();
  }
});

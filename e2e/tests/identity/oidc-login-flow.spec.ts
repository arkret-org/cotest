// Real OIDC browser login — the full yougen → coauth → soland lifecycle.
//
// End-to-end regression net for the login chain brought up on 2026-06-16:
// yougen Continue → coauth /authorize → password login → consent →
// /auth/callback → session-grant issuance → self-path grant+DPoP →
// signed-in app. One serial flow walks the whole account lifecycle:
//
//   1. new-user registration (self-contained, over coauth's registration API)
//   2. first login            → reaches the signed-in app shell, no /login bounce
//   3. session persistence    → a full page reload stays signed in (this is the
//                               exact regression for the "login succeeds but
//                               reload bounces to /login" bug — naked-bearer 401
//                               on /_cokret/root/* + bearer not re-persisted to
//                               the upgraded secure store)
//   4. logout                 → returns to the login panel, session cleared
//   5. returning-user login   → the same account signs back in
//
// The account is created self-contained via registerCoauthPasswordAccount,
// which relies on the dev email-delivery bypass minting the deterministic code
// "123456" — so no pre-seeded account, mock-email scraping, or external
// credentials are required.
//
// ── Why it is opt-in (skipped unless COTEST_REAL_OIDC_LOGIN is set) ───────────
// It drives coauth's interactive login + consent pages, which only carry the
// `data-testid` hooks this test selects (`coauth-login-submit`,
// `coauth-oauth-approve`) and mint the deterministic dev code when coauth is
// built from the source that added them (alongside this test). A prebuilt
// coauth bundle won't have either, so the flow would hang/flake. Gate it on an
// explicit opt-in until the joint harness rebuilds coauth from source by
// default; then this flag can be dropped. The server-side invariants are pinned
// unconditionally in oidc-login-chain.spec.ts, which runs on CI.
//
//   COTEST_REAL_OIDC_LOGIN=1 \
//   COTEST_COAUTH_BASE_URL=…  COTEST_SOLAND_BASE_URL=…  COTEST_YOUGEN_BASE_URL=… \
//     npx playwright test identity/oidc-login-flow
//
// Optional: set COTEST_OIDC_LOGIN_HANDLE + COTEST_OIDC_LOGIN_PASSWORD to drive
// an existing account instead of self-registering.

import { expect, test, type Page } from "@playwright/test";
import {
  coauthBaseUrl,
  optionalEnv,
  realOidcLoginHandle,
  realOidcLoginPassword,
  solandBaseUrl,
} from "../../helpers/env";
import { openUserPage, uniqueUser, type JointUserPage } from "../../helpers/users";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";

test.describe.configure({ mode: "serial" });

type Account = { handle: string; password: string };

// Drive yougen's "start server login" through coauth and back to the signed-in
// app. Robust to both paths: a fresh coauth session shows the login form +
// consent; a returning coauth session may bounce straight back to the app.
// coauth selectors:
//   #login-handle / #login-password    — login.rs form inputs
//   [data-testid=coauth-login-submit]   — login.rs "Sign in" button
//   [data-testid=coauth-oauth-approve]  — oauth_approval.rs "Allow" button (skipped once approved)
async function serverLoginViaCoauth(page: Page, account: Account): Promise<void> {
  await page.getByTestId("login-server-url").fill(solandBaseUrl());
  await page.getByTestId("start-server-login-button").click();

  const loginHandle = page.locator("#login-handle");
  const shell = page.getByTestId("client-shell");

  // Wait until coauth either asks for credentials or (returning session) the
  // app shell comes back.
  await expect(loginHandle.or(shell)).toBeVisible({ timeout: 60_000 });
  if (await loginHandle.isVisible()) {
    await loginHandle.fill(account.handle);
    await page.locator("#login-password").fill(account.password);
    await page.getByTestId("coauth-login-submit").click();
  }

  // Consent is optional — coauth skips it when the client+scope were already
  // approved for this account.
  const approve = page.getByTestId("coauth-oauth-approve");
  const consentShown = await approve
    .waitFor({ state: "visible", timeout: 20_000 })
    .then(() => true)
    .catch(() => false);
  if (consentShown) {
    await approve.click();
  }

  // Signed in: app shell renders, no login panel. (An "Authorize this device"
  // MLS modal may overlay the shell — that's the legitimate next step, not a
  // login failure — so we assert the shell, not the absence of any modal.)
  await expect(shell).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("login-panel")).toHaveCount(0);
  expect(new URL(page.url()).pathname).not.toBe("/login");
}

async function logout(jointPage: JointUserPage): Promise<void> {
  const page = jointPage.page;
  // The logout control lives in the topbar account menu (yougen app.rs:
  // account-menu-button → account-menu-session-logout). It performs a hard
  // logout (revokes the session grant) and redirects to /login.
  await page.getByTestId("account-menu-button").click();
  await page.getByTestId("account-menu-session-logout").click();
  await expect(page.getByTestId("login-panel")).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("client-shell")).toHaveCount(0);
}

test.describe("real OIDC browser login lifecycle", () => {
  const coauth = coauthBaseUrl();
  const optIn = optionalEnv("COTEST_REAL_OIDC_LOGIN");

  test("register → login → reload persists → logout → returning login", async ({
    browser,
    request,
  }) => {
    test.skip(!coauth, "coauth not started for this run");
    test.skip(
      !optIn,
      "set COTEST_REAL_OIDC_LOGIN=1 to opt into the real browser login ceremony " +
        "(needs coauth built from source: login/consent testids + deterministic dev code)",
    );

    // 1. Establish a password account: an explicitly-provided one, else
    //    self-register a fresh new user over coauth's registration API.
    const envHandle = realOidcLoginHandle();
    const envPassword = realOidcLoginPassword();
    const account: Account =
      envHandle && envPassword
        ? { handle: envHandle, password: envPassword }
        : await registerCoauthPasswordAccount(request, coauth!);

    // Open yougen with no session token so it lands on the login panel; the
    // injected account_did/device_id are placeholders overridden by the OIDC
    // callback identity.
    const jointPage = await openUserPage(browser, uniqueUser("oidc-login"));
    const page = jointPage.page;
    try {
      // 2. First login (new user).
      await test.step("new user signs in and reaches the app", async () => {
        await jointPage.gotoLogin();
        await serverLoginViaCoauth(page, account);
      });

      // 3. Session persists across a full reload — the core "reload bounces to
      //    /login" regression. Give it room: the secure-store upgrade that
      //    persists the bearer can lag the first paint.
      await test.step("session survives a full page reload", async () => {
        await page.reload({ waitUntil: "domcontentloaded" });
        await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
        await expect(page.getByTestId("login-panel")).toHaveCount(0);
        expect(new URL(page.url()).pathname).not.toBe("/login");
      });

      // 4. Logout.
      await test.step("logout clears the session and returns to /login", async () => {
        await logout(jointPage);
      });

      // 5. Returning-user login (same account, no re-registration).
      await test.step("returning user signs back in", async () => {
        await serverLoginViaCoauth(page, account);
      });
    } finally {
      await jointPage.close();
    }
  });

  test("wrong password is rejected at coauth and never reaches the app", async ({
    browser,
    request,
  }) => {
    test.skip(!coauth, "coauth not started for this run");
    test.skip(!optIn, "set COTEST_REAL_OIDC_LOGIN=1 to opt into the real browser login ceremony");

    const account = await registerCoauthPasswordAccount(request, coauth!);
    const jointPage = await openUserPage(browser, uniqueUser("oidc-login-bad"));
    const page = jointPage.page;
    try {
      await jointPage.gotoLogin();
      await page.getByTestId("login-server-url").fill(solandBaseUrl());
      await page.getByTestId("start-server-login-button").click();

      // Submit the real handle with a wrong password.
      await expect(page.locator("#login-handle")).toBeVisible({ timeout: 60_000 });
      await page.locator("#login-handle").fill(account.handle);
      await page.locator("#login-password").fill(`${account.password}-WRONG`);
      await page.getByTestId("coauth-login-submit").click();

      // coauth surfaces the error and stays on its login page; yougen never
      // reaches the signed-in shell.
      await expect(page.locator("#login-error")).toBeVisible({ timeout: 30_000 });
      await expect(page.locator("#login-handle")).toBeVisible();
      await expect(page.getByTestId("client-shell")).toHaveCount(0);
    } finally {
      await jointPage.close();
    }
  });
});

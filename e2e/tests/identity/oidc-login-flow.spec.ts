// Real OIDC browser login — the full inkson → coauth → soland lifecycle.
//
// End-to-end regression net for the login chain brought up on 2026-06-16:
// inkson Continue → coauth /authorize → password login → consent →
// /auth/callback → session-grant issuance → self-path grant+DPoP →
// signed-in app. One serial flow walks the whole account lifecycle:
//
//   1. new-user registration (self-contained, over coauth's registration API)
//   2. first login            → reaches the signed-in app shell, no /login bounce
//   3. session persistence    → a full page reload stays signed in (this is the
//                               exact regression for the "login succeeds but
//                               reload bounces to /login" bug — naked-bearer 401
//                               on /_arkret/root/* + bearer not re-persisted to
//                               the upgraded secure store)
//   4. logout                 → returns to the login panel, session cleared
//   5. returning-user login   → the same account signs back in
//
// The account is created self-contained via registerCoauthPasswordAccount,
// which relies on the dev email-delivery bypass minting the deterministic code
// "123456" — so no pre-seeded account, mock-email scraping, or external
// credentials are required.
//
// ── CI gate ──────────────────────────────────────────────────────────────────
// It drives coauth's interactive login + consent pages, which only carry the
// `data-testid` hooks this test selects (`coauth-login-submit`,
// `coauth-oauth-approve`) and mint the deterministic dev code when coauth is
// built from source. The joint harness provisions that stack and sets
// COTEST_REAL_OIDC_LOGIN=1, so this regression flow is part of the default
// joint-smoke gate. Ad-hoc runs without that env still skip; if the harness
// declares the joint stack present, missing prerequisites fail loudly instead
// of reporting a false green.
//
//   COTEST_REAL_OIDC_LOGIN=1 \
//   COTEST_COAUTH_BASE_URL=…  COTEST_SOLAND_BASE_URL=…  COTEST_INKSON_BASE_URL=… \
//     npx playwright test identity/oidc-login-flow
//
import { expect, test } from "@playwright/test";
import {
  coauthBaseUrl,
  optionalEnv,
  solandBaseUrl,
} from "../../helpers/env";
import { openUserPage, uniqueUser } from "../../helpers/users";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import {
  hardLogoutViaAccountMenu,
  serverLoginViaCoauth,
  submitCoauthPasswordCredentials,
} from "../../helpers/real-oidc-login";
import { assertJointStackNotRequired } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("real OIDC browser login lifecycle @fully-implemented", () => {
  const coauth = coauthBaseUrl();
  const optIn = optionalEnv("COTEST_REAL_OIDC_LOGIN");

  test("register → login → reload persists → logout → returning login", async ({
    browser,
    request,
  }) => {
    test.skip(!coauth, "coauth not started for this run");
    if (!optIn) {
      assertJointStackNotRequired("OIDC browser login lifecycle");
      test.skip(
        true,
        "set COTEST_REAL_OIDC_LOGIN=1 to opt into the real browser login ceremony " +
          "(needs coauth built from source: login/consent testids + deterministic dev code)",
      );
    }

    // 1. Establish a client-signed principal account. A bare password account
    // is intentionally insufficient because the session-grant request cannot
    // infer a principal DID from the OAuth subject.
    const account = await registerCoauthPasswordAccount(request, coauth!);

    // A session-grant request is explicitly principal-bound. Registration
    // gives the client that verified DID, so persist it as the returning-account
    // selection before opening OIDC; the callback must never infer a principal
    // from an unbound OAuth subject.
    const returningUser = uniqueUser("oidc-login");
    returningUser.did = account.did;
    const jointPage = await openUserPage(browser, returningUser);
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
        await hardLogoutViaAccountMenu(jointPage);
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
    if (!optIn) {
      assertJointStackNotRequired("OIDC wrong-password browser login");
      test.skip(true, "set COTEST_REAL_OIDC_LOGIN=1 to opt into the real browser login ceremony");
    }

    const account = await registerCoauthPasswordAccount(request, coauth!);
    const jointPage = await openUserPage(browser, uniqueUser("oidc-login-bad"), {
      neutralLoginConfig: true,
    });
    const page = jointPage.page;
    try {
      await jointPage.gotoLogin();
      await page.getByTestId("login-server-url").fill(solandBaseUrl());
      await page.getByTestId("start-server-login-button").click();

      // Submit the real handle with a wrong password.
      await submitCoauthPasswordCredentials(page, {
        handle: account.handle,
        password: `${account.password}-WRONG`,
      });

      // coauth surfaces the error and stays on its login page; inkson never
      // reaches the signed-in shell.
      await expect(page.locator("#login-error")).toBeVisible({ timeout: 30_000 });
      await expect(page.locator("#login-password")).toBeVisible();
      await expect(page.getByTestId("client-shell")).toHaveCount(0);
    } finally {
      await jointPage.close();
    }
  });
});

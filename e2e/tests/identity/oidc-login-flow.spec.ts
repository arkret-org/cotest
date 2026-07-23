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

  test("a bound client that receives a forged principal_unknown fails closed without minting a second identity", async ({
    browser,
    request,
  }) => {
    test.skip(!coauth, "coauth not started for this run");
    if (!optIn) {
      assertJointStackNotRequired("forged principal_unknown fail-closed flow");
      test.skip(true, "set COTEST_REAL_OIDC_LOGIN=1 to opt into the real browser login ceremony");
    }

    // A fully bound account: client-signed entry 0 with a verified binding.
    const account = await registerCoauthPasswordAccount(request, coauth!);
    const returningUser = uniqueUser("forged-unknown");
    returningUser.did = account.did;
    const jointPage = await openUserPage(browser, returningUser);
    const page = jointPage.page;
    try {
      // Establish the bound client state with one real login, then log out so
      // the durable per-account entry and returning-account selection exist.
      await test.step("bound client signs in once and logs out", async () => {
        await jointPage.gotoLogin();
        await serverLoginViaCoauth(page, account);
        await hardLogoutViaAccountMenu(jointPage);
      });

      // Force the full credential ceremony on the next attempt and forge the
      // Account Authority's session-grant answer into `principal_unknown`,
      // pretending the verified binding vanished.
      await page.context().clearCookies();
      let forgedResponses = 0;
      await page.route("**/_arkret/gate/account/session-grants", async (route) => {
        forgedResponses += 1;
        // Exact wire ErrorEnvelope shape per api-conventions.md §5: required
        // top-level ok/error/request_id, required error.code/error.message,
        // request_id in the canonical ak:request:<uuid7> form.
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({
            ok: false,
            error: { code: "principal_unknown", message: "principal_unknown" },
            request_id: "ak:request:01964137-0000-7000-8000-000000000000",
          }),
        });
      });
      const identityCreationCalls: string[] = [];
      page.on("request", (interceptedRequest) => {
        const url = interceptedRequest.url();
        if (
          url.includes("/_arkret/gate/account/identity-binding-challenges") ||
          url.includes("/_arkret/gate/account/register") ||
          url.includes("submit-did-operation")
        ) {
          identityCreationCalls.push(url);
        }
      });

      await test.step("forged principal_unknown surfaces recovery guidance", async () => {
        await page.getByTestId("login-server-url").fill(solandBaseUrl());
        await page.getByTestId("start-server-login-button").click();
        await submitCoauthPasswordCredentials(page, account);
        const approve = page.getByTestId("coauth-oauth-approve");
        if (
          await approve
            .waitFor({ state: "visible", timeout: 20_000 })
            .then(() => true)
            .catch(() => false)
        ) {
          await approve.click();
        }
        const authStatus = page.getByTestId("auth-status");
        await expect(authStatus).toContainText("No new identity was created", {
          timeout: 120_000,
        });
        await expect(authStatus).toContainText("recovery or diagnostics");
      });

      await test.step("no second identity is minted or drafted", async () => {
        expect(forgedResponses).toBeGreaterThan(0);
        expect(
          identityCreationCalls,
          "a forged principal_unknown must never trigger identity creation calls",
        ).toEqual([]);
        await expect(page.getByTestId("onboarding-panel")).toHaveCount(0);
        await expect(page.getByTestId("account-handoff-onboarding")).toHaveCount(0);
        await expect(page.getByTestId("login-panel")).toBeVisible();
        const state = await page.evaluate((expectedDid) => {
          const pendingKeys: string[] = [];
          for (let index = 0; index < localStorage.length; index += 1) {
            const key = localStorage.key(index) ?? "";
            if (!key.startsWith("inkson.local_state.v1")) {
              continue;
            }
            const raw = localStorage.getItem(key) ?? "";
            if (
              raw.includes('"pending_account_handoff":{') ||
              raw.includes('"pending_principal_registration":{')
            ) {
              pendingKeys.push(key);
            }
          }
          // The per-account blob lives in the encrypted IndexedDB store on
          // wasm; the localStorage root index keeps the durable known-DID
          // marker for the bound account.
          const rootIndex = JSON.parse(
            localStorage.getItem("inkson.local_state.v1") ?? "{}",
          ) as { known_dids?: string[] };
          const boundAccountKnown = (rootIndex.known_dids ?? []).includes(expectedDid);
          return { pendingKeys, boundAccountKnown };
        }, account.did);
        expect(
          state.pendingKeys,
          "a forged principal_unknown must not draft identity creation checkpoints",
        ).toEqual([]);
        expect(
          state.boundAccountKnown,
          "the bound account's known-DID marker must survive the forged error",
        ).toBe(true);
      });
    } finally {
      await page.unrouteAll({ behavior: "ignoreErrors" });
      await jointPage.close();
    }
  });
});

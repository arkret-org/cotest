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
import { coauthBaseUrl, optionalEnv, solandBaseUrl } from "../../helpers/env";
import { openUserPage, uniqueUser } from "../../helpers/users";
import {
  registerCoauthPasswordAccount,
  registerUnboundCoauthPasswordAccount,
} from "../../helpers/coauth-register";
import {
  hardLogoutViaAccountMenu,
  serverLoginViaCoauth,
  submitCoauthPasswordCredentials,
} from "../../helpers/real-oidc-login";
import { assertJointStackNotRequired } from "../../helpers/users";

test.describe("real OIDC browser login lifecycle @fully-implemented", () => {
  const coauth = coauthBaseUrl();
  const optIn = optionalEnv("COTEST_REAL_OIDC_LOGIN");

  test("unbound account completes Recovery Key onboarding through the real UI @onboarding-recovery-gate @onboarding-resume-gate", async ({
    browser,
    request,
  }) => {
    // A cold joint stack may compile/load WASM and materialize the first PCR
    // successor Seal. Keep the test-level deadline above its longest explicit
    // assertion so Playwright cannot abort a healthy flow at the global 180s
    // default while that assertion is still waiting.
    test.setTimeout(360_000);
    test.skip(!coauth, "coauth not started for this run");
    if (!optIn) {
      assertJointStackNotRequired("Recovery Key onboarding UI lifecycle");
      test.skip(
        true,
        "set COTEST_REAL_OIDC_LOGIN=1 to opt into the real browser onboarding ceremony",
      );
    }

    const browserUser = uniqueUser("onboarding-ui");
    const account = await registerUnboundCoauthPasswordAccount(
      request,
      coauth!,
      {
        handle: browserUser.name,
      },
    );
    const jointPage = await openUserPage(browser, browserUser, {
      neutralLoginConfig: true,
      autoCompleteRecoveryKeySetup: false,
    });
    const page = jointPage.page;
    const onboardingResponses: Array<{ url: string; status: number }> = [];
    const identityCreationRequests: string[] = [];
    page.on("response", (response) => {
      const url = new URL(response.url());
      if (url.pathname === "/_arkret/gate/account/onboarding") {
        onboardingResponses.push({
          url: response.url(),
          status: response.status(),
        });
      }
    });
    page.on("request", (request) => {
      const url = request.url();
      if (
        url.includes("/_arkret/gate/account/identity-binding-challenges") ||
        url.includes("/_arkret/gate/account/register") ||
        url.includes("submit-did-operation")
      ) {
        identityCreationRequests.push(url);
      }
    });
    try {
      await jointPage.gotoLogin();
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

      await page.getByTestId("choose-new-identity").click();
      const displayedWords = page
        .getByTestId("onboarding-recovery-key-display")
        .locator("li");
      await expect(displayedWords).toHaveCount(24, { timeout: 120_000 });
      const recoveryKey = (await displayedWords.allTextContents())
        .map((word) => word.trim())
        .join(" ");
      expect(recoveryKey.split(/\s+/)).toHaveLength(24);
      await page
        .getByTestId("onboarding-recovery-key-confirm")
        .fill(recoveryKey);

      let interruptedBootstrapSeal = false;
      const interruptFirstBootstrapSeal = async (
        route: import("@playwright/test").Route,
      ) => {
        if (
          !interruptedBootstrapSeal &&
          route.request().method() === "POST"
        ) {
          interruptedBootstrapSeal = true;
          await route.abort("connectionfailed");
          return;
        }
        await route.continue();
      };
      await page.route(
        "**/_arkret/self/seals",
        interruptFirstBootstrapSeal,
      );
      await page.getByTestId("onboarding-bind-identity").click();

      await expect(
        page.getByTestId("onboarding-resume-diagnostics"),
      ).toBeVisible({ timeout: 240_000 });
      await expect(page.getByTestId("retry-onboarding-resume")).toBeVisible();
      expect(
        interruptedBootstrapSeal,
        "the test must interrupt the recovery-material gate after account acceptance",
      ).toBe(true);
      const creationRequestCountAtInterruption =
        identityCreationRequests.length;

      await page.unroute(
        "**/_arkret/self/seals",
        interruptFirstBootstrapSeal,
      );
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(
        page.getByTestId("onboarding-recovery-key-display").locator("li"),
      ).toHaveCount(24, { timeout: 120_000 });
      await page
        .getByTestId("onboarding-recovery-key-confirm")
        .fill(recoveryKey);
      await page.getByTestId("onboarding-bind-identity").click();

      await expect(page.getByTestId("onboarding-complete")).toContainText(
        "Identity ready",
        { timeout: 240_000 },
      );
      expect(
        onboardingResponses.length,
        "the UI must reconcile onboarding through the Account Authority",
      ).toBeGreaterThan(0);
      for (const response of onboardingResponses) {
        expect(new URL(response.url).origin).toBe(new URL(coauth!).origin);
        expect(response.status).not.toBe(401);
        expect(response.status).not.toBe(404);
      }
      expect(
        identityCreationRequests.length,
        "resuming an accepted setup must not create another identity or device",
      ).toBe(creationRequestCountAtInterruption);

      await page
        .getByTestId("onboarding-complete")
        .getByRole("link", {
          name: "Continue",
        })
        .click();
      await expect(page.getByTestId("client-shell")).toBeVisible({
        timeout: 120_000,
      });
      await expect(page.getByTestId("login-panel")).toHaveCount(0);
    } finally {
      await jointPage.close();
    }
  });

  test("register → login → reload persists → logout → returning login @returning-login-gate", async ({
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
    returningUser.fullDid = account.fullDid;
    const jointPage = await openUserPage(browser, returningUser);
    const page = jointPage.page;
    let firstDeviceId = "";
    try {
      // 2. First login (new user).
      await test.step("new user signs in and reaches the app", async () => {
        await jointPage.gotoLogin();
        await serverLoginViaCoauth(page, account);
        firstDeviceId = await page.evaluate(() => {
          const config = JSON.parse(
            window.localStorage.getItem("inkson.config.v1") ?? "{}",
          ) as { device_id?: string };
          return config.device_id ?? "";
        });
        expect(firstDeviceId, "first login must persist its device id").not.toBe("");
      });

      // 3. Session persists across a full reload — the core "reload bounces to
      //    /login" regression. Give it room: the secure-store upgrade that
      //    persists the bearer can lag the first paint.
      await test.step("session survives a full page reload", async () => {
        await page.reload({ waitUntil: "domcontentloaded" });
        await expect(page.getByTestId("client-shell")).toBeVisible({
          timeout: 120_000,
        });
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
        expect(new URL(page.url()).pathname).not.toBe("/onboarding");
        await expect(page.getByTestId("pcr-policy-device-recovery")).toHaveCount(0);
        const returningDeviceId = await page.evaluate(() => {
          const config = JSON.parse(
            window.localStorage.getItem("inkson.config.v1") ?? "{}",
          ) as { device_id?: string };
          return config.device_id ?? "";
        });
        expect(
          returningDeviceId,
          "hard re-login must preserve the durable device identity",
        ).toBe(firstDeviceId);
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
      test.skip(
        true,
        "set COTEST_REAL_OIDC_LOGIN=1 to opt into the real browser login ceremony",
      );
    }

    const account = await registerCoauthPasswordAccount(request, coauth!);
    const jointPage = await openUserPage(
      browser,
      uniqueUser("oidc-login-bad"),
      {
        neutralLoginConfig: true,
      },
    );
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
      await expect(page.locator("#login-error")).toBeVisible({
        timeout: 30_000,
      });
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
      test.skip(
        true,
        "set COTEST_REAL_OIDC_LOGIN=1 to opt into the real browser login ceremony",
      );
    }

    // A fully bound account: client-signed entry 0 with a verified binding.
    const account = await registerCoauthPasswordAccount(request, coauth!);
    const returningUser = uniqueUser("forged-unknown");
    returningUser.did = account.did;
    returningUser.fullDid = account.fullDid;
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
      await page.route(
        "**/_arkret/gate/account/session-grants",
        async (route) => {
          forgedResponses += 1;
          // Exact wire ErrorEnvelope shape per api-conventions.md §5: required
          // top-level ok/error/request_id, required error.code/error.message,
          // request_id in the canonical ak:request:<uuid7> form.
          await route.fulfill({
            status: 404,
            contentType: "application/json",
            body: JSON.stringify({
              ok: false,
              error: {
                code: "principal_unknown",
                message: "principal_unknown",
              },
              request_id: "ak:request:01964137-0000-7000-8000-000000000000",
            }),
          });
        },
      );
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
        await expect(
          page.getByTestId("account-handoff-onboarding"),
        ).toHaveCount(0);
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
          // wasm; the localStorage root index keeps the durable typed authority
          // marker for the bound account.
          const rootIndex = JSON.parse(
            localStorage.getItem("inkson.local_state.v1") ?? "{}",
          ) as {
            known_profiles?: Array<{
              authority?: { principal_id?: string };
            }>;
          };
          const boundAccountKnown = (rootIndex.known_profiles ?? []).some(
            (profile) => profile.authority?.principal_id === expectedDid,
          );
          return { pendingKeys, boundAccountKnown };
        }, account.did);
        expect(
          state.pendingKeys,
          "a forged principal_unknown must not draft identity creation checkpoints",
        ).toEqual([]);
        expect(
          state.boundAccountKnown,
          "the bound account's typed authority marker must survive the forged error",
        ).toBe(true);
      });
    } finally {
      await page.unrouteAll({ behavior: "ignoreErrors" });
      await jointPage.close();
    }
  });
});

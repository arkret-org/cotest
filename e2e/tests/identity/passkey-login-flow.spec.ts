import { randomUUID } from "node:crypto";
import {
  expect,
  test,
  type BrowserContext,
  type Page,
} from "../../helpers/arkret-test";
import { coauthBaseUrl, optionalEnv, solandBaseUrl } from "../../helpers/env";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import {
  hardLogoutViaAccountMenu,
  submitCoauthPasswordCredentials,
} from "../../helpers/real-oidc-login";
import {
  assertJointStackNotRequired,
  openDpopUserPageForAccount,
} from "../../helpers/users";

async function installVirtualAuthenticator(
  context: BrowserContext,
  page: Page,
) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const authenticatorIds: string[] = [];
  const add = async (transport: "internal" | "usb" = "internal") => {
    const { authenticatorId } = await cdp.send(
      "WebAuthn.addVirtualAuthenticator",
      {
        options: {
          protocol: "ctap2",
          transport,
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      },
    );
    authenticatorIds.push(authenticatorId);
    return authenticatorId;
  };
  await add();
  return {
    cdp,
    add,
    async dispose() {
      for (const authenticatorId of authenticatorIds) {
        await cdp
          .send("WebAuthn.removeVirtualAuthenticator", { authenticatorId })
          .catch(() => undefined);
      }
      await cdp.send("WebAuthn.disable").catch(() => undefined);
      await cdp.detach().catch(() => undefined);
    },
  };
}

test.describe("Coauth passkey browser lifecycle @fully-implemented", () => {
  const coauth = coauthBaseUrl();
  const secondaryCoauth = optionalEnv("COTEST_COAUTH_SECONDARY_BASE_URL");
  const optIn =
    optionalEnv("COTEST_REAL_PASSKEY") ?? optionalEnv("COTEST_REAL_OIDC_LOGIN");

  test("register → rename → logout → passkey login → replay and last-revoke fail closed", async ({
    browser,
    request,
  }) => {
    test.skip(!coauth, "coauth not started for this run");
    if (!optIn) {
      assertJointStackNotRequired("WebAuthn passkey browser lifecycle");
      test.skip(
        true,
        "set COTEST_REAL_PASSKEY=1 to run the real browser WebAuthn ceremony",
      );
    }

    const handle = `e2e-passkey-${randomUUID()}`.toLowerCase();
    const account = await registerCoauthPasswordAccount(request, coauth!, {
      handle,
    });

    const returningFlow = await openDpopUserPageForAccount(
      browser,
      request,
      "passkey-login",
      account,
    );
    expect(returningFlow, "canonical founding-device session").toBeTruthy();
    const jointPage = returningFlow!.page;
    const page = jointPage.page;
    const context = page.context();
    const authenticator = await installVirtualAuthenticator(context, page);
    try {
      await test.step("anonymous callers cannot attach a passkey to an account hint", async () => {
        const anonymous = await browser.newContext();
        try {
          const staleHint = await anonymous.request.post(
            `${coauth}/_coauth/account/auth/passkey/register/start`,
            { data: { account_id: handle, display_name: "attacker" } },
          );
          expect(staleHint.status()).toBe(400);
          const unauthenticated = await anonymous.request.post(
            `${coauth}/_coauth/account/auth/passkey/register/start`,
            { data: { display_name: "attacker" } },
          );
          expect(unauthenticated.status()).toBe(401);
        } finally {
          await anonymous.close();
        }
      });

      await test.step("recent password authentication registers and renames a passkey", async () => {
        await page.goto(`${coauth}/login`);
        await submitCoauthPasswordCredentials(page, account);
        await expect(page).toHaveURL(
          new RegExp(`${coauth!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/?$`),
        );

        await page.goto(`${coauth}/security`);
        await page.locator("#new-passkey-label").fill("Virtual security key");
        await page.getByTestId("coauth-add-passkey").click();
        await expect(
          page.getByText("Virtual security key", { exact: true }),
        ).toBeVisible({
          timeout: 30_000,
        });

        const label = page.locator('input[id^="passkey-label-"]');
        await label.fill("Renamed passkey");
        await page.getByRole("button", { name: "Save name" }).click();
        await expect(
          page.getByText("Renamed passkey", { exact: true }),
        ).toBeVisible();
      });

      await test.step("passkey assertion creates the normal browser session", async () => {
        const logout = await context.request.post(
          `${coauth}/_coauth/account/auth/logout`,
          { data: {} },
        );
        expect(logout.ok()).toBe(true);

        let finishBody: unknown;
        let completedOnSecondary = false;
        const finishPath = "/_coauth/account/auth/passkey/auth/finish";
        await page.route(`**${finishPath}`, async (route) => {
          const outgoing = route.request();
          finishBody = outgoing.postDataJSON();
          if (!secondaryCoauth) {
            await route.continue();
            return;
          }

          const headers = await outgoing.allHeaders();
          delete headers["content-length"];
          delete headers.host;
          const response = await route.fetch({
            url: `${secondaryCoauth}${finishPath}`,
            headers,
          });
          completedOnSecondary = true;
          await route.fulfill({ response });
        });

        await page.goto(`${coauth}/login`);
        const loginHandle = page.locator("#login-handle");
        await expect(loginHandle).toBeVisible({ timeout: 60_000 });
        await loginHandle.click();
        await loginHandle.fill(handle);
        await expect(loginHandle).toHaveValue(handle, { timeout: 5_000 });
        await page.getByTestId("coauth-login-identifier-submit").click();
        await page.getByTestId("coauth-login-passkey").focus();
        await page.keyboard.press("Enter");
        await expect(page).toHaveURL(
          new RegExp(`${coauth!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/?$`),
          {
            timeout: 30_000,
          },
        );
        await page.unroute(`**${finishPath}`);
        expect(finishBody).toBeTruthy();
        if (secondaryCoauth) {
          expect(completedOnSecondary).toBe(true);
        }

        const replay = await context.request.post(
          `${coauth}/_coauth/account/auth/passkey/auth/finish`,
          { data: finishBody },
        );
        expect(replay.status()).toBe(400);
      });

      await test.step("credential projection is redacted and the last passkey is protected", async () => {
        const crossOrigin = await context.request.post(
          `${coauth}/_coauth/account/auth/passkey/register/start`,
          {
            data: {},
            headers: {
              origin: "https://evil.example",
              "sec-fetch-site": "cross-site",
            },
          },
        );
        expect(crossOrigin.status()).toBe(403);

        const listed = await context.request.get(
          `${coauth}/_coauth/self/passkeys`,
        );
        expect(listed.ok()).toBe(true);
        const body = (await listed.json()) as {
          passkeys: Array<Record<string, unknown>>;
        };
        expect(body.passkeys).toHaveLength(1);
        const passkey = body.passkeys[0];
        expect(typeof passkey.id).toBe("string");
        expect(passkey.label).toBe("Renamed passkey");
        expect(passkey).not.toHaveProperty("credential_id");
        expect(passkey).not.toHaveProperty("credential_id_b64");
        expect(passkey).not.toHaveProperty("public_key");

        const overlongRename = await context.request.patch(
          `${coauth}/_coauth/self/passkeys/${String(passkey.id)}`,
          { data: { label: "x".repeat(81) } },
        );
        expect(overlongRename.status()).toBe(400);

        const csrfStyleRevoke = await context.request.post(
          `${coauth}/_coauth/self/passkeys/${String(passkey.id)}/revoke`,
          {
            data: "{}",
            headers: { "content-type": "text/plain" },
          },
        );
        expect(csrfStyleRevoke.status()).toBe(400);

        const revoke = await context.request.post(
          `${coauth}/_coauth/self/passkeys/${String(passkey.id)}/revoke`,
          { data: {} },
        );
        expect(revoke.status()).toBe(409);

        await page.goto(`${coauth}/security`);
        await authenticator.add("usb");
        await page.locator("#new-passkey-label").fill("Replacement passkey");
        await page.getByTestId("coauth-add-passkey").click();
        await expect(
          page.getByText("Replacement passkey", { exact: true }),
        ).toBeVisible({ timeout: 30_000 });

        const withReplacement = await context.request.get(
          `${coauth}/_coauth/self/passkeys`,
        );
        expect(withReplacement.ok()).toBe(true);
        const replacementBody = (await withReplacement.json()) as {
          passkeys: Array<{ id: string; label?: string }>;
        };
        expect(replacementBody.passkeys).toHaveLength(2);
        const original = replacementBody.passkeys.find(
          (candidate) => candidate.label === "Renamed passkey",
        );
        expect(original).toBeTruthy();

        const revokeOriginal = await context.request.post(
          `${coauth}/_coauth/self/passkeys/${original!.id}/revoke`,
          { data: {} },
        );
        expect(revokeOriginal.ok()).toBe(true);

        const active = await context.request.get(
          `${coauth}/_coauth/self/passkeys`,
        );
        expect(active.ok()).toBe(true);
        const activeBody = (await active.json()) as {
          passkeys: Array<{ label?: string }>;
        };
        expect(activeBody.passkeys).toEqual([
          expect.objectContaining({ label: "Replacement passkey" }),
        ]);
      });

      await test.step("passkey continues OIDC and mints the canonical proof-bound session grant", async () => {
        const logout = await context.request.post(
          `${coauth}/_coauth/account/auth/logout`,
          { data: {} },
        );
        expect(logout.ok()).toBe(true);

        // The Coauth account session and Inkson's Station session are
        // independent. End the latter explicitly so /login does not correctly
        // redirect the still-authenticated founding device back to the shell.
        await jointPage.gotoHome();
        await hardLogoutViaAccountMenu(jointPage);
        await jointPage.gotoLogin();
        await page.getByTestId("login-server-url").fill(solandBaseUrl());
        await page.getByTestId("start-server-login-button").click();

        const identifier = page.locator("#login-handle");
        const passkeyButton = page.getByTestId("coauth-login-passkey");
        await expect(identifier.or(passkeyButton)).toBeVisible({
          timeout: 60_000,
        });
        if (await identifier.isVisible()) {
          await identifier.fill(handle);
          await page.getByTestId("coauth-login-identifier-submit").click();
        }
        await passkeyButton.click();

        const approve = page.getByTestId("coauth-oauth-approve");
        if (
          await approve
            .waitFor({ state: "visible", timeout: 20_000 })
            .then(() => true)
            .catch(() => false)
        ) {
          await approve.click();
        }
        await expect(page.getByTestId("client-shell")).toBeVisible({
          timeout: 120_000,
        });
        await expect(page.getByTestId("login-panel")).toHaveCount(0);
      });
    } finally {
      await authenticator.dispose();
      await jointPage.close();
    }
  });
});

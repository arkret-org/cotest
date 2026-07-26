import { randomUUID } from "node:crypto";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { coauthBaseUrl, optionalEnv, solandBaseUrl } from "../../helpers/env";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import { submitCoauthPasswordCredentials } from "../../helpers/real-oidc-login";
import {
  assertJointStackNotRequired,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

async function installVirtualAuthenticator(context: BrowserContext, page: Page) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return {
    cdp,
    authenticatorId,
    async dispose() {
      await cdp
        .send("WebAuthn.removeVirtualAuthenticator", { authenticatorId })
        .catch(() => undefined);
      await cdp.send("WebAuthn.disable").catch(() => undefined);
      await cdp.detach().catch(() => undefined);
    },
  };
}

test.describe("Coauth passkey browser lifecycle @fully-implemented", () => {
  const coauth = coauthBaseUrl();
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

    const returningUser = uniqueUser("passkey-login");
    returningUser.did = account.did;
    const jointPage = await openUserPage(browser, returningUser);
    const page = jointPage.page;
    const context = page.context();
    const authenticator = await installVirtualAuthenticator(context, page);
    try {
      await test.step("anonymous callers cannot attach a passkey to an account hint", async () => {
        const anonymous = await browser.newContext();
        try {
          const response = await anonymous.request.post(
            `${coauth}/_coauth/account/auth/passkey/register/start`,
            { data: { account_id: handle, display_name: "attacker" } },
          );
          expect(response.status()).toBe(401);
        } finally {
          await anonymous.close();
        }
      });

      await test.step("recent password authentication registers and renames a passkey", async () => {
        await page.goto(`${coauth}/login`);
        await submitCoauthPasswordCredentials(page, account);
        await expect(page).toHaveURL(new RegExp(`${coauth!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/?$`));

        await page.goto(`${coauth}/security`);
        await page.locator("#new-passkey-label").fill("Virtual security key");
        await page.getByTestId("coauth-add-passkey").click();
        await expect(page.getByText("Virtual security key", { exact: true })).toBeVisible({
          timeout: 30_000,
        });

        const label = page.locator('input[id^="passkey-label-"]');
        await label.fill("Renamed passkey");
        await page.getByRole("button", { name: "Save name" }).click();
        await expect(page.getByText("Renamed passkey", { exact: true })).toBeVisible();
      });

      await test.step("passkey assertion creates the normal browser session", async () => {
        const logout = await context.request.post(
          `${coauth}/_coauth/account/auth/logout`,
          { data: {} },
        );
        expect(logout.ok()).toBe(true);

        let finishBody: unknown;
        page.on("request", (outgoing) => {
          if (
            new URL(outgoing.url()).pathname ===
            "/_coauth/account/auth/passkey/auth/finish"
          ) {
            finishBody = outgoing.postDataJSON();
          }
        });

        await page.goto(`${coauth}/login`);
        await page.locator("#login-handle").fill(handle);
        await page.getByTestId("coauth-login-identifier-submit").click();
        await page.getByTestId("coauth-login-passkey").click();
        await expect(page).toHaveURL(new RegExp(`${coauth!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/?$`), {
          timeout: 30_000,
        });
        expect(finishBody).toBeTruthy();

        const replay = await context.request.post(
          `${coauth}/_coauth/account/auth/passkey/auth/finish`,
          { data: finishBody },
        );
        expect(replay.status()).toBe(400);
      });

      await test.step("credential projection is redacted and the last passkey is protected", async () => {
        const listed = await context.request.get(`${coauth}/_coauth/self/passkeys`);
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
      });

      await test.step("passkey continues OIDC and mints the canonical proof-bound session grant", async () => {
        const logout = await context.request.post(
          `${coauth}/_coauth/account/auth/logout`,
          { data: {} },
        );
        expect(logout.ok()).toBe(true);

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

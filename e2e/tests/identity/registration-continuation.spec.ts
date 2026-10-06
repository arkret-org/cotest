import { expect, test } from "../../helpers/arkret-test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import { registrationEmailCode } from "../../helpers/coauth-register";
import { submitCoauthPasswordCredentials } from "../../helpers/real-oidc-login";
import { openUserPage, uniqueUser } from "../../helpers/users";

for (const scenario of ["fresh browser", "handoff response loss", "stale busy checkpoint"]) {
  const loseHandoffResponse = scenario === "handoff response loss";
  const staleBusy = scenario === "stale busy checkpoint";
  test(`direct registration with ${scenario} preserves setup through reload and same-device sign-in @fully-implemented @onboarding-resume-gate`, async ({ browser, request }) => {
    test.setTimeout(180_000);
    test.skip(!coauthBaseUrl(), "Coauth is required for the registration continuation");
    const user = uniqueUser("registration-continuation");
    const account = { handle: user.name, password: "1amTester!" };
    const email = `${user.name}@example.test`;
    const jointPage = await openUserPage(browser, user, {
      neutralLoginConfig: true,
      autoCompleteRecoveryKeySetup: false,
    });
    const page = jointPage.page;
    let lostResponse = false;
    const leaseIds: string[] = [];
    const holderPublicKeys: string[] = [];
    page.on("request", (request) => {
      if (new URL(request.url()).pathname.endsWith("/authentication-handoffs") && request.method() === "POST") {
        const proof = request.headers()["dpop"];
        const header = JSON.parse(Buffer.from(proof.split(".")[0], "base64url").toString("utf8"));
        holderPublicKeys.push(header.jwk.x);
      }
    });
    {
      await page.route("**/_arkret/gate/account/authentication-handoffs", async (route) => {
        if (route.request().method() !== "POST") {
          await route.continue();
          return;
        }
        const response = await route.fetch();
        expect(response.status()).toBe(200);
        const outcome = await response.json();
        expect(outcome.binding.state).toBe("identity_creation_active");
        leaseIds.push(outcome.binding.identity_creation_lease.identity_creation_lease_id);
        const injectFault = !lostResponse && (loseHandoffResponse || staleBusy);
        if (injectFault) lostResponse = true;
        if (injectFault && loseHandoffResponse) {
          await route.abort("connectionfailed");
        } else if (injectFault && staleBusy) {
          // Exercise replacement of a previously persisted busy view with a
          // fresh authoritative active response, without waiting for a lease.
          outcome.binding = {
            state: "identity_creation_busy",
            retry_after_ms: 131_000,
            expires_at: outcome.binding.identity_creation_lease.expires_at,
          };
          await route.fulfill({ response, json: outcome });
        } else {
          await route.fulfill({ response });
        }
      });
    }
    try {
      await page.goto("/register");
      await page.getByTestId("register-server").fill(solandBaseUrl());
      await page.getByTestId("register-open-account-authority").click();
      await page.locator('input[autocomplete="username"]').fill(account.handle);
      await page.locator('input[autocomplete="email"]').fill(email);
      const passwords = page.locator('input[type="password"]');
      await expect(passwords).toHaveCount(2);
      await passwords.nth(0).fill(account.password);
      await passwords.nth(1).fill(account.password);
      await page.getByRole("button", { name: /create account/i }).click();
      const codeInput = page.locator('input[autocomplete="one-time-code"]');
      await expect(codeInput).toBeVisible();
      const code = await registrationEmailCode(request, email);
      await expect.poll(async () => {
        if (!(await codeInput.isVisible())) return true;
        await codeInput.fill(code);
        await page.getByRole("button", { name: /^verify$/i }).click();
        return !(await codeInput.isVisible());
      }, { timeout: 30_000, intervals: [500] }).toBe(true);
      const displayName = page.locator('input[autocomplete="name"]');
      await expect(displayName).toBeVisible();
      await displayName.fill(user.displayName);
      await page.getByRole("button", { name: /^continue$/i }).click();
      const initialApproval = page.getByTestId("coauth-oauth-approve");
      const finishRegistration = page.getByRole("button", { name: /^create account$/i });
      await expect(initialApproval.or(finishRegistration).or(page.getByTestId("choose-new-identity"))).toBeVisible();
      if (await finishRegistration.isVisible()) await finishRegistration.click();
      await expect(initialApproval.or(page.getByTestId("choose-new-identity"))).toBeVisible();
      if (await initialApproval.isVisible()) await initialApproval.click();
      if (loseHandoffResponse) {
        await expect(page.getByTestId("auth-status")).toContainText("Start sign-in again");
        expect(lostResponse).toBe(true);
      } else if (staleBusy) {
        await expect(page.getByText("Setup is already in progress", { exact: true })).toBeVisible();
        await page.reload();
        await expect(page.getByText("Setup is already in progress", { exact: true })).toBeVisible();
      } else {
        await expect(page.getByTestId("choose-new-identity")).toBeVisible();
        await expect(page).toHaveURL(/\/onboarding$/);
        await page.reload();
        await expect(page.getByTestId("choose-new-identity")).toBeVisible();
      }
      const firstDevice = await page.evaluate(() =>
        JSON.parse(localStorage.getItem("inkson.local_state.v1") ?? "{}").pending_login?.device_id,
      );
      expect(firstDevice).toMatch(/^ak:device:/);
      await jointPage.gotoLogin();
      await page.getByTestId("login-server-url").fill(solandBaseUrl());
      await page.getByTestId("start-server-login-button").click();
      await submitCoauthPasswordCredentials(page, account);
      const approve = page.getByTestId("coauth-oauth-approve");
      if (await approve.waitFor({ state: "visible", timeout: 5_000 }).then(() => true).catch(() => false)) {
        await approve.click();
      }
      await expect(page.getByTestId("choose-new-identity")).toBeVisible();
      await expect(page.getByText("Setup is already in progress", { exact: true })).toHaveCount(0);
      expect(leaseIds).toHaveLength(2);
      expect(leaseIds[1], "same-device reauthentication must retain the live setup lease").toBe(leaseIds[0]);
      expect(holderPublicKeys).toHaveLength(2);
      expect(holderPublicKeys[0]).toBeTruthy();
      expect(holderPublicKeys[1], "reauthentication must use the exact original DPoP public key").toBe(holderPublicKeys[0]);
      expect(await page.evaluate(() =>
        JSON.parse(localStorage.getItem("inkson.local_state.v1") ?? "{}").pending_login?.device_id,
      )).toBe(firstDevice);
      if (scenario === "fresh browser") {
        // Reach the actual Human PCR successor and durable completion. The
        // identity chooser alone cannot detect a failed first backup pointer.
        await page.getByTestId("choose-new-identity").click();
        const words = page.getByTestId("onboarding-recovery-key-display").locator("li");
        await expect(words).toHaveCount(24);
        const recoveryKey = (await words.allTextContents()).map((word) => word.trim()).join(" ");
        await page.getByTestId("onboarding-recovery-key-confirm").fill(recoveryKey);
        let pointerEventId: string | undefined;
        const pointerAcceptance = page.waitForResponse((response) => {
          if (!new URL(response.url()).pathname.endsWith("/_arkret/self/events")) return false;
          const event = response.request().postDataJSON()?.event;
          if (event?.kind !== "ak.key_backup.active_series") return false;
          pointerEventId = event.event_id;
          return true;
        });
        const historicalLookup = page.waitForRequest((request) => {
          if (!new URL(request.url()).pathname.endsWith("/_arkret/self/signer-keys/query")) return false;
          return request.postDataJSON()?.queries?.some((selector: Record<string, unknown>) =>
            selector.verification_mode === "historical_event" && selector.sender_kind === "account_device"
            && pointerEventId !== undefined
            && (selector.committed_event_ref as { event_id?: string } | undefined)?.event_id === pointerEventId,
          ) === true;
        });
        await page.getByTestId("onboarding-bind-identity").click();
        const accepted = await pointerAcceptance;
        expect(accepted.ok()).toBe(true);
        const event = accepted.request().postDataJSON().event;
        const outcome = await accepted.json();
        expect(outcome.commit.event_ref).toBe(event.event_id);
        expect(outcome.commit).not.toHaveProperty("producer_signer_fact_digest");
        const lookup = (await historicalLookup).postDataJSON();
        expect(lookup.recipient_account_id).toEqual(event.actor_id.account_id);
        expect(lookup.queries).toContainEqual({
          verification_mode: "historical_event", sender_kind: "account_device",
          actor: event.actor_id, device_id: firstDevice,
          verification_method: event.producer_proof.verification_method,
          committed_event_ref: {
            event_id: event.event_id, commit_id: outcome.commit.commit_id,
            stream_ref: outcome.commit.stream_ref, stream_position: outcome.commit.stream_position,
          },
        });
        await expect(page.getByTestId("onboarding-complete")).toContainText("Identity ready", {
          timeout: 90_000,
        });
        await page.getByTestId("onboarding-complete").getByRole("link", { name: "Continue" }).click();
        await expect(page.getByTestId("client-shell")).toBeVisible();
        await page.reload();
        await expect(page.getByTestId("client-shell")).toBeVisible();
        await expect(page.getByTestId("retry-onboarding-resume")).toHaveCount(0);
      }
    } catch (error) {
      console.error("Registration continuation failed at", new URL(page.url()).pathname,
        await page.locator("h1,h2").allTextContents());
      throw error;
    } finally {
      await jointPage.close();
    }
  });
}

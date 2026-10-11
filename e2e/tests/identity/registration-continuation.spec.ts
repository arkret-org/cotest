import { expect, test, type Page } from "../../helpers/arkret-test";
import { coauthBaseUrl, colandBaseUrl } from "../../helpers/env";
import { registrationEmailCode } from "../../helpers/coauth-register";
import { submitCoauthPasswordCredentials } from "../../helpers/real-oidc-login";
import { openUserPage, uniqueUser } from "../../helpers/users";
import { assertAuthoritySubmitOutcome } from "../../helpers/coland-api";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

for (const scenario of ["fresh browser", "handoff response loss", "stale busy checkpoint", "active-series response loss"]) {
  const loseHandoffResponse = scenario === "handoff response loss";
  const staleBusy = scenario === "stale busy checkpoint";
  const losePointerResponse = scenario === "active-series response loss";
  test(`direct registration with ${scenario} preserves setup through reload and same-device sign-in @fully-implemented @onboarding-resume-gate`, async ({ browser, request }) => {
    test.setTimeout(180_000);
    test.skip(!coauthBaseUrl(), "Coauth is required for the registration continuation");
    const user = uniqueUser("registration-continuation");
    const account = { handle: user.name, password: "1amTester!" };
    const email = `${user.name}@example.test`;
    const profile = losePointerResponse
      ? fs.mkdtempSync(path.join(os.tmpdir(), "arkret-pcr-replay-")) : undefined;
    let jointPage = await openUserPage(browser, user, {
      persistentUserDataDir: profile,
      neutralLoginConfig: true,
      autoCompleteRecoveryKeySetup: false,
    });
    let page = jointPage.page;
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
      await page.getByTestId("register-server").fill(colandBaseUrl());
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
      await page.getByTestId("login-server-url").fill(colandBaseUrl());
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
      if (scenario === "fresh browser" || losePointerResponse) {
        // Reach the actual Human PCR successor and durable completion. The
        // identity chooser alone cannot detect a failed first backup pointer.
        await page.getByTestId("choose-new-identity").click();
        const words = page.getByTestId("onboarding-recovery-key-display").locator("li");
        await expect(words).toHaveCount(24);
        const recoveryKey = (await words.allTextContents()).map((word) => word.trim()).join(" ");
        await page.getByTestId("onboarding-recovery-key-confirm").fill(recoveryKey);
        let pointerEventId: string | undefined;
        let originalPointer: Record<string, unknown> | undefined;
        let originalOutcome: Record<string, unknown> | undefined;
        let pointerResponseLost = false;
        const pointerRequests: string[] = [];
        const foundingUnits: unknown[] = [];
        const observeSubmissions = (target: Page) => target.on("request", (request) => {
          if (request.method() !== "POST" || !request.postData()) return;
          let body: Record<string, unknown>;
          try { body = request.postDataJSON(); } catch { return; }
          const creation = body.identity_creation as Record<string, unknown> | undefined;
          if (creation?.pcr_genesis_unit) foundingUnits.push(creation.pcr_genesis_unit);
          if (!new URL(request.url()).pathname.endsWith("/_arkret/self/events")) return;
          const event = body.event as Record<string, unknown> | undefined;
          if (event?.kind === "ak.key_backup.active_series") pointerRequests.push(request.postData()!);
        });
        observeSubmissions(page);
        if (losePointerResponse) {
          await page.route(/\/_arkret\/self\/events(?:\?.*)?$/, async (route) => {
            const event = route.request().postDataJSON()?.event;
            if (event?.kind !== "ak.key_backup.active_series") { await route.continue(); return; }
            if (!pointerResponseLost) {
              const accepted = await route.fetch();
              expect(accepted.ok(), "active-series must be committed before losing its response").toBe(true);
              originalOutcome = await accepted.json();
              assertAuthoritySubmitOutcome(originalOutcome!, event, "original PCR successor");
              originalPointer = event;
              pointerEventId = event.event_id;
              pointerResponseLost = true;
            }
            await route.abort("connectionfailed");
          });
          await page.getByTestId("onboarding-bind-identity").click();
          await expect.poll(() => pointerResponseLost, { timeout: 90_000 }).toBe(true);
          expect(originalPointer).toBeDefined();
          await expect(page.getByTestId("onboarding-complete")).toHaveCount(0);
          await jointPage.close();
          jointPage = await openUserPage(browser, user, {
            persistentUserDataDir: profile,
            resumePersistentProfile: true,
            neutralLoginConfig: true,
            autoCompleteRecoveryKeySetup: false,
          });
          page = jointPage.page;
          observeSubmissions(page);
        }
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
        if (losePointerResponse) {
          await page.goto("/onboarding");
          // Restart may restore custody and ask for the same explicit confirmation.
          const confirm = page.getByTestId("onboarding-recovery-key-confirm");
          await expect(page.getByTestId("onboarding-complete").or(confirm)).toBeVisible({ timeout: 90_000 });
          if (await confirm.isVisible()) {
            const restoredWords = await page.getByTestId("onboarding-recovery-key-display").locator("li").allTextContents();
            expect(restoredWords.map(word => word.trim()).join(" ") === recoveryKey,
              "restart must retain the original recovery authority").toBe(true);
            await confirm.fill(recoveryKey);
            await page.getByTestId("onboarding-bind-identity").click();
          }
          // The durable outbound drain starts with the connected client, not
          // while the completion page still owns the handoff continuation.
          await expect(page.getByTestId("onboarding-complete")).toContainText("Identity ready", {
            timeout: 90_000,
          });
          await page.getByTestId("onboarding-complete").getByRole("link", { name: "Continue" }).click();
          await expect(page.getByTestId("client-shell")).toBeVisible();
        } else {
          await page.getByTestId("onboarding-bind-identity").click();
        }
        const accepted = await pointerAcceptance;
        expect(accepted.ok()).toBe(true);
        const event = accepted.request().postDataJSON().event;
        const outcome = await accepted.json();
        if (losePointerResponse) {
          expect(outcome.status).toBe("duplicate");
          expect(event).toEqual(originalPointer);
          expect(outcome.commit).toEqual(originalOutcome!.commit);
          expect(pointerRequests.length, "restart must replay the frozen original submission").toBeGreaterThan(1);
          expect(new Set(pointerRequests).size, "no new active-series Event or signature on resume").toBe(1);
          expect(foundingUnits.length, "the real register must carry the original PCR founding unit").toBeGreaterThan(0);
          expect(new Set(foundingUnits.map(unit => JSON.stringify(unit))).size,
            "resume must not create a second PCR founding unit").toBe(1);
        }
        expect(outcome.commit.event_ref).toBe(event.event_id);
        expect(outcome.commit).not.toHaveProperty("producer_signer_fact_digest");
        if (!losePointerResponse) {
          await expect(page.getByTestId("onboarding-complete")).toContainText("Identity ready", {
            timeout: 90_000,
          });
          await page.getByTestId("onboarding-complete").getByRole("link", { name: "Continue" }).click();
          await expect(page.getByTestId("client-shell")).toBeVisible();
        }
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
        if (losePointerResponse) {
          const active = await page.evaluate(() => {
            const account = JSON.parse(localStorage.getItem("inkson.config.v1") ?? "{}").active_account;
            return { authority: account?.authority, device: account?.device_id, pcr: account?.principal_control_realm_id };
          });
          expect(active.authority).toEqual((originalPointer!.actor_id as { account_id: unknown }).account_id);
          expect(active.device).toBe(firstDevice);
          expect(active.pcr).toBe(originalPointer!.realm_id);
        }
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
      if (profile) {
        const actual = fs.realpathSync(profile);
        if (path.dirname(actual) !== fs.realpathSync(os.tmpdir()) || !path.basename(actual).startsWith("arkret-pcr-replay-")) {
          throw new Error("PCR replay profile escaped the test temp root");
        }
        fs.rmSync(actual, { recursive: true, force: true });
      }
    }
  });
}

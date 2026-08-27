import { expect, test, type Page, type Response } from "../../helpers/arkret-test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import { COAUTH_DEV_EMAIL_CODE } from "../../helpers/coauth-register";
import { openUserPage, uniqueUser } from "../../helpers/users";

type ProtocolHit = {
  method: string;
  path: string;
  status: number;
  requestBody?: Record<string, unknown>;
  responseBody?: Record<string, unknown>;
  errorCode?: string;
};

test.describe.configure({ mode: "serial" });

test.describe("identity.recovery-key-to-encrypted-realm @fully-implemented", () => {
  test("fresh browser registration creates and reloads a real encrypted Realm", async ({
    browser,
  }) => {
    test.setTimeout(600_000);
    const coauth = coauthBaseUrl();
    if (!coauth) {
      throw new Error(
        "canonical encrypted-Realm journey requires the Coauth preflight to succeed",
      );
    }

    const user = uniqueUser("canonical-encrypted-realm");
    const password = "1amTester!";
    const jointPage = await openUserPage(browser, user, {
      neutralLoginConfig: true,
      autoCompleteRecoveryKeySetup: false,
    });
    const page = jointPage.page;
    const protocolHits: ProtocolHit[] = [];
    const protocolDiagnostics: string[] = [];
    observeProtocol(page, protocolHits, protocolDiagnostics);

    try {
      await test.step("register and authorize through the product UI", async () => {
        await jointPage.gotoLogin();
        await page.getByTestId("login-server-url").fill(solandBaseUrl());
        await page.getByTestId("start-server-login-button").click();

        await page.getByRole("link", { name: /create account/i }).click();
        await page.locator('input[autocomplete="username"]').fill(user.name);
        await page
          .locator('input[autocomplete="email"]')
          .fill(`${user.name}@example.test`);
        const passwordFields = page.locator('input[type="password"]');
        await expect(passwordFields).toHaveCount(2);
        await passwordFields.nth(0).fill(password);
        await passwordFields.nth(1).fill(password);
        await page.getByRole("button", { name: /create account/i }).click();

        const verificationCode = page.locator(
          'input[autocomplete="one-time-code"]',
        );
        await expect(verificationCode).toBeVisible({ timeout: 120_000 });
        const verify = page.getByRole("button", { name: /^verify$/i });
        await expect
          .poll(
            async () => {
              if (!(await verificationCode.isVisible().catch(() => false))) {
                return true;
              }
              await verificationCode.fill(COAUTH_DEV_EMAIL_CODE);
              await verify.click();
              return !(await verificationCode.isVisible().catch(() => false));
            },
            {
              timeout: 30_000,
              intervals: [500],
              message:
                "Coauth asynchronous email-verification job must accept the dev code",
            },
          )
          .toBe(true);

        const displayName = page.locator('input[autocomplete="name"]');
        if (
          await displayName.isVisible({ timeout: 30_000 }).catch(() => false)
        ) {
          await displayName.fill(user.displayName);
          await page.getByRole("button", { name: /^continue$/i }).click();
        }

        const approve = page.getByTestId("coauth-oauth-approve");
        await expect(approve).toBeVisible({ timeout: 120_000 });
        await approve.click();

        await page.getByTestId("choose-new-identity").click();
        const words = page
          .getByTestId("onboarding-recovery-key-display")
          .locator("li");
        await expect(words).toHaveCount(24, { timeout: 120_000 });
        const recoveryKey = (await words.allTextContents())
          .map((word) => word.trim())
          .join(" ");
        expect(recoveryKey.split(/\s+/)).toHaveLength(24);
        await page
          .getByTestId("onboarding-recovery-key-confirm")
          .fill(recoveryKey);
        await page.getByTestId("onboarding-bind-identity").click();
        await expect
          .poll(
            async () => {
              if (
                await page
                  .getByTestId("onboarding-complete")
                  .isVisible()
                  .catch(() => false)
              ) {
                return "complete";
              }
              if (new URL(page.url()).pathname === "/login") {
                return `unexpected-login\n${protocolDiagnostics.join("\n")}`;
              }
              return "pending";
            },
            { timeout: 240_000 },
          )
          .toBe("complete");
        await expect(page.getByTestId("onboarding-complete")).toContainText(
          "Identity ready",
        );
        await page
          .getByTestId("onboarding-complete")
          .getByRole("link", { name: "Continue" })
          .click();
        await expect(page.getByTestId("client-shell")).toBeVisible({
          timeout: 120_000,
        });
      });

      const identity = await readActiveIdentity(page);
      expect(identity.coreId).toMatch(/^ak:did_core:/);
      expect(identity.fullId).toMatch(/^did:/);
      expect(identity.coreId).not.toBe(identity.fullId);

      await test.step("Inkson publishes its RFC 9420 KeyPackage", async () => {
        await expect
          .poll(
            () =>
              protocolHits.find(
                (hit) =>
                  hit.path === "/_arkret/self/keys/keypackages/upload" &&
                  hit.status === 200,
              ),
            { timeout: 180_000 },
          )
          .toBeTruthy();
        const upload = protocolHits.find(
          (hit) =>
            hit.path === "/_arkret/self/keys/keypackages/upload" &&
            hit.status === 200,
        )!;
        expect(upload.requestBody?.principal_id).toBe(identity.coreId);
        expect(upload.requestBody?.device_id).toBe(identity.deviceId);
        const endpointSignature = upload.requestBody?.endpoint_signature as
          | { kid?: string }
          | undefined;
        expect(endpointSignature?.kid).toMatch(
          new RegExp(`^${escapeRegex(identity.fullId)}#`),
        );
        const entries = upload.requestBody?.keypackages;
        expect(entries).toHaveLength(8);
        for (const entry of entries as Array<Record<string, unknown>>) {
          expect(entry).not.toHaveProperty("endpoint_signature");
        }
        expect(upload.responseBody?.accepted).toBeGreaterThan(0);
        expect(upload.responseBody?.rejected ?? []).toEqual([]);
        expect(upload.responseBody).not.toHaveProperty("available_count");
      });

      const backupPut = protocolHits.find(
        (hit) =>
          hit.method === "PUT" &&
          /^\/_arkret\/self\/keys\/backups\//.test(hit.path) &&
          hit.status === 200,
      );
      expect(
        backupPut,
        "Recovery Key onboarding must persist encrypted recovery metadata",
      ).toBeTruthy();
      expect(backupPut?.requestBody?.actor_id).toBe(identity.coreId);

      const message = `canonical encrypted message ${Date.now()}`;
      let realmId = "";
      const uploadCountBeforeReload = protocolHits.filter(
        (hit) => hit.path === "/_arkret/self/keys/keypackages/upload",
      ).length;
      await test.step("create, open, write and reload the encrypted Realm", async () => {
        await expect(
          page.getByTestId("encrypted-realm-recovery-gate"),
        ).toHaveCount(0);
        realmId = await jointPage.createRealm({
          title: `Canonical encrypted Realm ${Date.now()}`,
          summary: "fresh-user real-stack encrypted Realm acceptance",
          discoverability: "unlisted",
          joinRule: "invite",
          historyAccess: "since_join",
          encryptionProfile: "mls_rfc9420",
          completeRecoveryKeySetup: false,
          allowPassivePromptDismissal: false,
        });
        await expect(
          page.getByTestId("encrypted-realm-recovery-gate"),
        ).toHaveCount(0);
        await jointPage.sendTimelineMessage(realmId, message);
        await expect(jointPage.timelineEvent(message)).toBeVisible({
          timeout: 120_000,
        });

        const encryptedWrite = protocolHits.find((hit) => {
          if (
            hit.method !== "POST" ||
            hit.path !== "/_arkret/self/events" ||
            !hit.requestBody
          ) {
            return false;
          }
          const wire = JSON.stringify(hit.requestBody);
          return wire.includes(realmId) && !wire.includes(message);
        });
        expect(
          encryptedWrite,
          "server ingress must contain ciphertext rather than the message plaintext",
        ).toBeTruthy();

        await page.reload({ waitUntil: "domcontentloaded" });
        await expect(page.getByTestId("client-shell")).toBeVisible({
          timeout: 120_000,
        });
        const returningIdentity = await readActiveIdentity(page);
        expect(returningIdentity).toEqual(identity);
        await jointPage.gotoTimelineRealm(realmId);
        await expect(jointPage.timelineEvent(message)).toBeVisible({
          timeout: 120_000,
        });
        await expect(page.getByTestId("network-state-badge")).toHaveText(
          "online",
          { timeout: 120_000 },
        );
        // This is a negative temporal assertion: give the publisher effect a
        // bounded observation window after the authenticated network and Chat
        // surface are ready, then verify that it emitted no refill upload.
        await page.waitForTimeout(5_000);
        expect(
          protocolHits.filter(
            (hit) => hit.path === "/_arkret/self/keys/keypackages/upload",
          ),
          "healthy local KeyPackage inventory reload must perform zero uploads",
        ).toHaveLength(uploadCountBeforeReload);
      });

      await test.step("manual recovery performs one bounded batch-only refill", async () => {
        await jointPage.gotoSettings();
        await page.getByTestId("settings-nav-item-encryption").click();
        await expect(page.getByTestId("encryption-settings")).toBeVisible();
        await page
          .getByTestId("settings-mls-keypackages-refill-button")
          .click();
        await expect(
          page.getByTestId("settings-mls-keypackages-refill-status"),
        ).toContainText(/published|已发布|补充/, { timeout: 120_000 });

        await expect
          .poll(
            () =>
              protocolHits.filter(
                (hit) => hit.path === "/_arkret/self/keys/keypackages/upload",
              ).length,
            { timeout: 30_000 },
          )
          .toBe(uploadCountBeforeReload + 1);
        const refill = protocolHits
          .filter((hit) => hit.path === "/_arkret/self/keys/keypackages/upload")
          .at(-1)!;
        expect(refill.requestBody).toHaveProperty("endpoint_signature");
        const entries = refill.requestBody?.keypackages as Array<
          Record<string, unknown>
        >;
        expect(entries).toHaveLength(8);
        for (const entry of entries) {
          expect(entry).not.toHaveProperty("endpoint_signature");
        }
        expect(refill.responseBody).not.toHaveProperty("available_count");
      });

      expect(
        protocolHits.some(
          (hit) => hit.path === "/_arkret/self/events" && hit.status < 400,
        ),
        "Realm bootstrap/write event ingress was not observed",
      ).toBe(true);
      expect(
        protocolHits.some(
          (hit) => hit.path === "/_arkret/self/seals" && hit.status < 400,
        ),
        "Recovery/Realm Seal submission was not observed",
      ).toBe(true);
      expect(
        protocolHits.filter(
          (hit) =>
            hit.status >= 500 &&
            !(
              hit.method === "POST" &&
              hit.path === "/_arkret/root/identity/recovery-policy" &&
              hit.errorCode === "frontier_unavailable"
            ),
        ),
        "unexpected Arkret 5xx responses",
      ).toEqual([]);
      expect(
        protocolHits.some(
          (hit) =>
            hit.method === "POST" &&
            hit.path === "/_arkret/root/identity/recovery-policy" &&
            hit.status === 503 &&
            hit.errorCode === "frontier_unavailable",
        ),
        "unsealed recovery-policy publication must expose the normative pending response",
      ).toBe(true);
      expect(protocolDiagnostics, protocolDiagnostics.join("\n")).toEqual([]);
    } finally {
      await jointPage.close();
    }
  });
});

function observeProtocol(
  page: Page,
  hits: ProtocolHit[],
  diagnostics: string[],
): void {
  page.on("console", (message) => {
    if (
      /retry.*exhaust|frontier_unavailable|MLS runtime|session coordinator|session_state|session boot|onboarding/i.test(
        message.text(),
      )
    ) {
      diagnostics.push(`console:${message.type()}:${message.text()}`);
    }
  });
  page.on("pageerror", (error) => {
    // A document reload aborts Inkson's in-flight Fetch streams. Chromium
    // surfaces that lifecycle cancellation both as requestfailed below and as
    // this exact page error; neither is a service or protocol failure.
    if (/^The user aborted a request\.?$/i.test(error.message)) return;
    diagnostics.push(`pageerror:${error.message}`);
  });
  page.on("requestfailed", (request) => {
    const path = new URL(request.url()).pathname;
    const errorText = request.failure()?.errorText ?? "";
    if (
      path.startsWith("/_arkret/") &&
      /ERR_ABORTED|NS_BINDING_ABORTED|aborted|cancel/i.test(errorText)
    ) {
      return;
    }
    if (path.startsWith("/_arkret/")) {
      diagnostics.push(
        `requestfailed:${request.method()} ${request.url()} ${errorText}`,
      );
    }
  });
  page.on("response", (response) => {
    const path = new URL(response.url()).pathname;
    if (!path.startsWith("/_arkret/")) return;
    void recordResponse(response, path).then((hit) => hits.push(hit));
  });
}

async function recordResponse(
  response: Response,
  path: string,
): Promise<ProtocolHit> {
  const request = response.request();
  const requestBody = request.postData()
    ? safeRecord(request.postData()!)
    : undefined;
  const responseBody = safeRecord(await response.text().catch(() => ""));
  return {
    method: request.method(),
    path,
    status: response.status(),
    requestBody,
    responseBody,
    errorCode: errorCode(responseBody),
  };
}

function safeRecord(raw: string): Record<string, unknown> | undefined {
  try {
    const value = JSON.parse(raw) as unknown;
    return value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function errorCode(
  body: Record<string, unknown> | undefined,
): string | undefined {
  const nested = body?.error;
  if (nested && typeof nested === "object" && !Array.isArray(nested)) {
    const code = (nested as Record<string, unknown>).code;
    if (typeof code === "string") return code;
  }
  return typeof body?.code === "string" ? body.code : undefined;
}

async function readActiveIdentity(page: Page): Promise<{
  coreId: string;
  fullId: string;
  deviceId: string;
}> {
  return page.evaluate(() => {
    const config = JSON.parse(
      localStorage.getItem("inkson.config.v1") ?? "{}",
    ) as {
      active_account?: {
        authority?: { principal_id?: string };
        resolution?: { full_id?: string };
        device_id?: string;
      };
    };
    const coreId = config.active_account?.authority?.principal_id ?? "";
    const fullId = config.active_account?.resolution?.full_id ?? "";
    const deviceId = config.active_account?.device_id ?? "";
    if (!coreId || !fullId || !deviceId) {
      throw new Error(
        "Inkson active account omitted its typed identity coordinates",
      );
    }
    return { coreId, fullId, deviceId };
  });
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

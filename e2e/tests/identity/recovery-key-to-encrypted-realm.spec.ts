import { expect, test, type Page, type Response } from "@playwright/test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

type ProtocolHit = {
  method: string;
  path: string;
  status: number;
  requestBody?: Record<string, unknown>;
  responseBody?: Record<string, unknown>;
  errorCode?: string;
};

test.describe.configure({ mode: "serial" });

test.describe(
  "identity.recovery-key-to-encrypted-realm @fully-implemented",
  () => {
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

          await page
            .getByRole("link", { name: /create account/i })
            .click();
          await page.locator('input[autocomplete="username"]').fill(user.name);
          const passwordFields = page.locator('input[type="password"]');
          await expect(passwordFields).toHaveCount(2);
          await passwordFields.nth(0).fill(password);
          await passwordFields.nth(1).fill(password);
          await page
            .getByRole("button", { name: /create account/i })
            .click();

          const displayName = page.locator('input[autocomplete="name"]');
          if (await displayName.isVisible({ timeout: 30_000 }).catch(() => false)) {
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
          await expect(page.getByTestId("onboarding-complete")).toContainText(
            "Identity ready",
            { timeout: 240_000 },
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
          await page.waitForLoadState("networkidle");
          expect(
            protocolHits.filter(
              (hit) => hit.path === "/_arkret/self/keys/keypackages/upload",
            ),
            "healthy local KeyPackage inventory reload must perform zero uploads",
          ).toHaveLength(uploadCountBeforeReload);
        });

        expect(
          protocolHits.some(
            (hit) =>
              hit.path === "/_arkret/self/events" && hit.status < 400,
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
          protocolHits.filter((hit) => hit.status >= 500),
          "unexpected Arkret 5xx responses",
        ).toEqual([]);
        expect(
          protocolHits.filter((hit) => hit.errorCode === "frontier_unavailable"),
          "frontier_unavailable must fail the canonical journey",
        ).toEqual([]);
        expect(protocolDiagnostics, protocolDiagnostics.join("\n")).toEqual([]);
      } finally {
        await jointPage.close();
      }
    });
  },
);

function observeProtocol(
  page: Page,
  hits: ProtocolHit[],
  diagnostics: string[],
): void {
  page.on("console", (message) => {
    if (/retry.*exhaust|frontier_unavailable|MLS runtime/i.test(message.text())) {
      diagnostics.push(`console:${message.type()}:${message.text()}`);
    }
  });
  page.on("pageerror", (error) => diagnostics.push(`pageerror:${error.message}`));
  page.on("requestfailed", (request) => {
    if (new URL(request.url()).pathname.startsWith("/_arkret/")) {
      diagnostics.push(
        `requestfailed:${request.method()} ${request.url()} ${request.failure()?.errorText ?? ""}`,
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

function errorCode(body: Record<string, unknown> | undefined): string | undefined {
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
      throw new Error("Inkson active account omitted its typed identity coordinates");
    }
    return { coreId, fullId, deviceId };
  });
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

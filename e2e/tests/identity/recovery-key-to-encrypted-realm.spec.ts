import { expect, test, type Page, type Response } from "../../helpers/arkret-test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
// The mock_email delivery boundary supplies the verification code; registration stays in the UI.
import { registrationEmailCode } from "../../helpers/coauth-register";
import { openUserPage, uniqueUser } from "../../helpers/users";
import { assertAuthoritySubmitOutcome } from "../../helpers/soland-api";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

type ProtocolHit = {
  method: string;
  path: string;
  status: number;
  observedAt: number;
  requestRealmId?: string;
  requestBody?: Record<string, unknown>;
  responseBody?: Record<string, unknown>;
  errorCode?: string;
};

test.describe.configure({ mode: "serial" });

test.describe("identity.recovery-key-to-encrypted-realm @fully-implemented", () => {
  for (const cut of ["none", "accepted_create_response_loss", "accepted_discussion_response_loss", "accepted_default_selection_response_loss"] as const) {
  test("fresh browser registration creates, writes, and reloads plaintext and encrypted Realms; " + cut, async ({
    browser,
    request,
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
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), "arkret-live-creator-"));
    let jointPage = await openUserPage(browser, user, {
      persistentUserDataDir: profile,
      neutralLoginConfig: true,
      autoCompleteRecoveryKeySetup: false,
    });
    let page = jointPage.page;
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
        const deliveredCode = await registrationEmailCode(
          request,
          `${user.name}@example.test`,
        );
        const verify = page.getByRole("button", { name: /^verify$/i });
        await expect
          .poll(
            async () => {
              if (!(await verificationCode.isVisible().catch(() => false))) {
                return true;
              }
              await verificationCode.fill(deliveredCode);
              await verify.click();
              return !(await verificationCode.isVisible().catch(() => false));
            },
            {
              timeout: 30_000,
              intervals: [500],
              message:
                "Coauth must accept the delivered email verification code",
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
      expect(identity.did).toMatch(/^did:/);
      expect(identity.coreId).not.toBe(identity.did);

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
          new RegExp(`^${escapeRegex(identity.did)}#`),
        );
        const entries = upload.requestBody?.keypackages;
        expect(entries).toHaveLength(8);
        for (const entry of entries as Array<Record<string, unknown>>) {
          expect(entry).not.toHaveProperty("endpoint_signature");
        }
        expect(upload.responseBody?.accepted).toBeGreaterThan(0);
        expect(upload.responseBody?.rejections ?? []).toEqual([]);
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
      expect(backupPut?.requestBody?.actor_id).toEqual({ kind: "account", account_id: identity.accountId });

      const message = `canonical encrypted message ${Date.now()}`;
      let realmId = "";
      const uploadCountBeforeReload = protocolHits.filter(
        (hit) => hit.path === "/_arkret/self/keys/keypackages/upload",
      ).length;
      await test.step("create, open, write and reload the encrypted Realm", async () => {
        await expect(
          page.getByTestId("encrypted-realm-recovery-gate"),
        ).toHaveCount(0);
        const faultKind = cut === "accepted_create_response_loss" ? "ak.realm.create"
          : cut === "accepted_discussion_response_loss" ? "ak.strand.create"
          : "ak.realm.set_default_strand";
        let scopeCreateRequest: Record<string, unknown> | undefined;
        let acceptedInterrupted: Record<string, unknown> | undefined;
        let lostResponse = false;
        const createRequests: string[] = [];
        const interruptedRequests: string[] = [];
        const genesisRequests: string[] = [];
        const initializationRequests: Array<{ kind: string; raw: string; event: Record<string, unknown> }> = [];
        const primaryEvent = (body?: Record<string, unknown>) => body?.unit_kind === "ordinary_realm_bootstrap"
          ? (body.events as Array<{ event: Record<string, unknown> }>)[0]?.event
          : body?.event as Record<string, unknown> | undefined;
        const trackCreate = (eventPage: Page) => eventPage.on("request", (outgoing) => {
          if (new URL(outgoing.url()).pathname !== "/_arkret/self/events") return;
          const body = safeRecord(outgoing.postData() ?? "");
          const event = primaryEvent(body);
          if (event?.kind === "ak.realm.create") {
            const candidateRealm = String(event.event_id).replace(/^ak:event:/, "ak:realm:");
            if (!realmId) realmId = candidateRealm;
            if (candidateRealm === realmId) {
              scopeCreateRequest ??= body;
              createRequests.push(outgoing.postData()!);
              if (faultKind === event.kind) interruptedRequests.push(outgoing.postData()!);
            }
          }
          if (event?.realm_id !== realmId) return;
          if (["ak.strand.create", "ak.realm.set_default_strand", "ak.mls.genesis"].includes(String(event.kind))) {
            initializationRequests.push({ kind: String(event.kind), raw: outgoing.postData()!, event });
          }
          if (event.kind === "ak.mls.genesis") genesisRequests.push(outgoing.postData()!);
          if (event.kind === faultKind) interruptedRequests.push(outgoing.postData()!);
        });
        trackCreate(page);
        if (cut !== "none") {
          await page.route(/\/_arkret\/self\/events(?:\?.*)?$/, async (route) => {
            const body = route.request().postDataJSON() as Record<string, unknown>;
            const event = primaryEvent(body);
            const matchesRealm = event?.kind === "ak.realm.create"
              ? String(event.event_id).replace(/^ak:event:/, "ak:realm:") === realmId
              : event?.realm_id === realmId;
            if (event?.kind !== faultKind || !matchesRealm) { await route.continue(); return; }
            if (!lostResponse) {
              const accepted = await route.fetch();
              expect(accepted.ok(), "the original product initialization Event must be accepted before response loss").toBe(true);
              const outcome = await accepted.json() as Record<string, unknown>;
              if (body.unit_kind === "ordinary_realm_bootstrap") {
                const events = body.events as Array<{ event: Record<string, unknown> }>;
                const commits = outcome.commits as Array<Record<string, unknown>>;
                expect(outcome.unit_kind).toBe("ordinary_realm_bootstrap");
                expect(commits).toHaveLength(events.length);
                events.forEach((submission, index) => assertAuthoritySubmitOutcome(
                  { status: outcome.status, commit: commits[index] }, submission.event, "accepted original bootstrap"));
              } else {
                assertAuthoritySubmitOutcome(outcome, event, "accepted original discussion initialization");
              }
              acceptedInterrupted = body;
              lostResponse = true;
            }
            await route.abort("aborted");
          });
        }
        const creating = jointPage.createRealm({
          title: `Canonical encrypted Realm ${Date.now()}`,
          summary: "fresh-user real-stack encrypted Realm acceptance",
          discoverability: "unlisted",
          joinRule: "invite",
          historyAccess: "since_join",
          mlsActivated: true,
          completeRecoveryKeySetup: false,
          allowPassivePromptDismissal: false,
        }).then(value => ({ value }), error => ({ error }));
        if (cut !== "none") {
          await expect.poll(() => lostResponse, { timeout: 120_000 }).toBe(true);
          expect(acceptedInterrupted).toBeDefined();
          expect(realmId).toMatch(/^ak:realm:/);
          expect(genesisRequests, "response loss must interrupt the creator before Genesis authoring").toHaveLength(0);
          await jointPage.close();
          await creating;
          jointPage = await openUserPage(browser, user, {
            persistentUserDataDir: profile,
            resumePersistentProfile: true,
            neutralLoginConfig: true,
            autoCompleteRecoveryKeySetup: false,
          });
          page = jointPage.page;
          observeProtocol(page, protocolHits, protocolDiagnostics);
          trackCreate(page);
          await jointPage.gotoHome();
          await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
          expect(await readActiveIdentity(page)).toEqual(identity);
          await waitForEventIngress(protocolHits,
            (wire) => wire.includes(realmId) && wire.includes("ak.mls.genesis"),
            "resumed original creator Genesis ingress");
          expect(interruptedRequests.length, "resume must replay the original accepted initialization bytes").toBeGreaterThan(1);
          for (const raw of interruptedRequests) {
            expect(raw).toBe(interruptedRequests[0]);
            expect(safeRecord(raw)).toEqual(acceptedInterrupted);
          }
          for (const raw of createRequests) {
            expect(raw).toBe(createRequests[0]);
            expect(safeRecord(raw)).toEqual(scopeCreateRequest);
          }
        } else {
          const result = await creating;
          if ("error" in result) throw result.error;
          realmId = result.value;
        }
        await expect(
          page.getByTestId("encrypted-realm-recovery-gate"),
        ).toHaveCount(0);
        await waitForEventIngress(protocolHits,
          (wire) => wire.includes(realmId) && wire.includes("ak.mls.genesis"),
          "original creator Genesis follows product discussion initialization");
        const discussionCreates = initializationRequests.filter(hit => hit.kind === "ak.strand.create");
        const defaultSelections = initializationRequests.filter(hit => hit.kind === "ak.realm.set_default_strand");
        expect(discussionCreates.length).toBeGreaterThan(0);
        expect(defaultSelections.length).toBeGreaterThan(0);
        expect(new Set(discussionCreates.map(hit => hit.raw)).size, "one original default discussion").toBe(1);
        expect(new Set(defaultSelections.map(hit => hit.raw)).size, "one original default selection").toBe(1);
        const defaultStrandId = String(discussionCreates[0].event.event_id).replace(/^ak:event:/, "ak:strand:");
        expect((defaultSelections[0].event.payload as Record<string, unknown>).strand_id).toBe(defaultStrandId);
        const genesisIndex = initializationRequests.findIndex(hit => hit.kind === "ak.mls.genesis");
        expect(genesisIndex, "Genesis follows the original default selection").toBeGreaterThan(
          initializationRequests.findIndex(hit => hit.kind === "ak.realm.set_default_strand"));
        await jointPage.sendTimelineMessage(realmId, message);
        await expect(jointPage.timelineEvent(message)).toBeVisible({
          timeout: 120_000,
        });

        const encryptedWrite = await waitForEventIngress(
          protocolHits,
          (wire) =>
            wire.includes(realmId) &&
            wire.includes("ak.message.create") &&
            wire.includes("encrypted_content"),
          "encrypted Realm message ingress",
        );
        expect(
          JSON.stringify(encryptedWrite.requestBody),
          "server ingress must contain ciphertext rather than the message plaintext",
        ).not.toContain(message);

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

      await test.step("restart the browser process and resume the original encrypted Realm", async () => {
        const genesis = await waitForEventIngress(
          protocolHits,
          (wire) => wire.includes(realmId) && wire.includes("ak.mls.genesis"),
          "original encrypted Realm Genesis ingress",
        );
        const originalGenesis = genesis.requestBody;
        await jointPage.close();
        jointPage = await openUserPage(browser, user, {
          persistentUserDataDir: profile,
          resumePersistentProfile: true,
          neutralLoginConfig: true,
          autoCompleteRecoveryKeySetup: false,
        });
        page = jointPage.page;
        observeProtocol(page, protocolHits, protocolDiagnostics);
        await jointPage.gotoHome();
        await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
        expect(await readActiveIdentity(page)).toEqual(identity);
        await jointPage.gotoTimelineRealm(realmId);
        await expect(jointPage.timelineEvent(message)).toBeVisible({ timeout: 120_000 });
        const originalIngress = new Set(protocolHits);
        const resumedMessage = `process resumed encrypted message ${Date.now()}`;
        await jointPage.sendTimelineMessage(realmId, resumedMessage);
        await expect(jointPage.timelineEvent(resumedMessage)).toBeVisible({ timeout: 120_000 });
        const resumedWrite = await waitForEventIngress(
          protocolHits,
          (wire) => wire.includes(realmId) && wire.includes("ak.message.create") && wire.includes("encrypted_content") &&
            ![...originalIngress].some((hit) => JSON.stringify(hit.requestBody) === wire),
          "resumed encrypted Realm message ingress",
        );
        expect(JSON.stringify(resumedWrite.requestBody)).not.toContain(resumedMessage);
        const genesisWrites = protocolHits.filter(
          (hit) => hit.path === "/_arkret/self/events" && hit.requestBody &&
            JSON.stringify(hit.requestBody).includes(realmId) &&
            JSON.stringify(hit.requestBody).includes("ak.mls.genesis"),
        );
        expect(genesisWrites.length).toBeGreaterThan(0);
        for (const hit of genesisWrites) expect(hit.requestBody).toEqual(originalGenesis);
      });

      const plaintextMessage = `canonical plaintext message ${Date.now()}`;
      let plaintextRealmId = "";
      await test.step("create, open, write and reload the non-encrypted Realm", async () => {
        plaintextRealmId = await jointPage.createRealm({
          title: `Canonical plaintext Realm ${Date.now()}`,
          summary: "fresh-user real-stack non-encrypted Realm acceptance",
          discoverability: "unlisted",
          joinRule: "invite",
          historyAccess: "all_history_for_current_members",
          mlsActivated: false,
          completeRecoveryKeySetup: false,
          allowPassivePromptDismissal: false,
        });
        await jointPage.sendTimelineMessage(
          plaintextRealmId,
          plaintextMessage,
        );
        await expect(jointPage.timelineEvent(plaintextMessage)).toBeVisible({
          timeout: 120_000,
        });

        const plaintextWrite = await waitForEventIngress(
          protocolHits,
          (wire) =>
            wire.includes(plaintextRealmId) &&
            wire.includes("ak.message.create") &&
            wire.includes(plaintextMessage),
          "non-encrypted Realm message ingress",
        );
        expect(JSON.stringify(plaintextWrite.requestBody)).not.toContain(
          "encrypted_content",
        );

        await page.reload({ waitUntil: "domcontentloaded" });
        await expect(page.getByTestId("client-shell")).toBeVisible({
          timeout: 120_000,
        });
        await jointPage.gotoTimelineRealm(plaintextRealmId);
        await expect(jointPage.timelineEvent(plaintextMessage)).toBeVisible({
          timeout: 120_000,
        });
        await expect(page.getByTestId("network-state-badge")).toHaveText(
          "online",
          { timeout: 120_000 },
        );
      });

      await test.step("manual recovery preserves a healthy bounded inventory", async () => {
        await jointPage.gotoSettings();
        await page.getByTestId("settings-nav-item-encryption").click();
        await expect(page.getByTestId("encryption-settings")).toBeVisible();
        await page
          .getByTestId("settings-mls-keypackages-refill-button")
          .click();
        await expect(
          page.getByTestId("settings-mls-keypackages-refill-status"),
        ).toContainText(/published:\s*0|已发布[^0-9]*0|补充[^0-9]*0/, {
          timeout: 120_000,
        });

        // The fresh device still owns its full initial batch.  Replenishment
        // is threshold based, so the explicit maintenance action is a no-op;
        // it must not upload a duplicate batch merely because the user clicked
        // the button.  The initial bounded upload shape is asserted above.
        expect(
          protocolHits.filter(
            (hit) => hit.path === "/_arkret/self/keys/keypackages/upload",
          ),
        ).toHaveLength(uploadCountBeforeReload);
      });

      expect(
        protocolHits.some(
          (hit) => hit.path === "/_arkret/self/events" && hit.status < 400,
        ),
        "Realm bootstrap/write event ingress was not observed",
      ).toBe(true);
      const journeyRealms = [realmId, plaintextRealmId];
      const pendingSnapshots = protocolHits.filter(hit =>
        isExpectedSnapshotCutPending(hit, journeyRealms));
      if (pendingSnapshots.length > 0) {
        await expect.poll(() => protocolHits.filter(hit => isExpectedSnapshotCutPending(hit, journeyRealms)).every(pending => protocolHits.some(hit =>
          hit.path === pending.path && hit.method === "GET" && hit.status === 200 &&
          hit.observedAt > pending.observedAt && hit.requestRealmId === pending.requestRealmId &&
          hit.responseBody?.realm_id === pending.requestRealmId && Boolean(hit.responseBody?.signature))),
          { timeout: 120_000, message: "each unavailable exact Realm cut must resolve to a later signed snapshot" },
        ).toBe(true);
      }
      expect(
        protocolHits.filter(
          (hit) =>
            hit.status >= 500 &&
            !isExpectedRecoveryPolicyPending(hit) &&
            !isExpectedSnapshotCutPending(hit, journeyRealms),
        ),
        "unexpected Arkret 5xx responses",
      ).toEqual([]);
      expect(protocolDiagnostics, protocolDiagnostics.join("\n")).toEqual([]);
    } finally {
      await jointPage.close();
      fs.rmSync(profile, { recursive: true, force: true });
    }
  });
  }
});

function observeProtocol(
  page: Page,
  hits: ProtocolHit[],
  diagnostics: string[],
): void {
  page.on("console", (message) => {
    if (
      /retry.*exhaust|MLS runtime|session coordinator|session_state|session boot|onboarding/i.test(
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
    const observedAt = Date.now();
    void recordResponse(response, path, observedAt).then((hit) => hits.push(hit));
  });
}

async function recordResponse(
  response: Response,
  path: string,
  observedAt: number,
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
    observedAt,
    requestRealmId: new URL(response.url()).searchParams.get("realm_id") ?? undefined,
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
  if (typeof body?.code === "string") return body.code;
  // RFC 9457 problem responses carry the Arkret wire code in the canonical
  // problem type even when they omit the optional compatibility `code` field.
  if (typeof body?.type === "string") {
    const match = body.type.match(/\/problems\/([^/?#]+)$/);
    if (match) return match[1];
  }
  return undefined;
}

// `ak.root.identity.recovery_policy.command.publish.v1` answers the retry-safe
// `revision_unavailable` until its Principal Control Realm Commit materializes;
// Inkson retries the same Event, so that 503 is not a service failure.
function isExpectedRecoveryPolicyPending(hit: ProtocolHit): boolean {
  return (
    hit.errorCode === "revision_unavailable" &&
    hit.method === "POST" &&
    hit.path === "/_arkret/root/identity/recovery-policy"
  );
}

// A mixed durable cut cannot be signed as a valid snapshot. This registered
// unavailable response is pending, and the journey requires a later real read.
function isExpectedSnapshotCutPending(hit: ProtocolHit, realmIds: string[]): boolean {
  return hit.status === 503 && hit.errorCode === "realm_state_snapshot_unavailable" &&
    hit.method === "GET" && hit.path === "/_arkret/self/realm-state-snapshot/head" &&
    hit.requestRealmId !== undefined && realmIds.includes(hit.requestRealmId);
}

async function readActiveIdentity(page: Page): Promise<{
  coreId: string;
  accountId: { principal_id: string; station_id: string };
  did: string;
  deviceId: string;
}> {
  return page.evaluate(() => {
    const config = JSON.parse(
      localStorage.getItem("inkson.config.v1") ?? "{}",
    ) as {
      active_account?: {
        authority?: { principal_id?: string; station_id?: string };
        resolution?: { did?: string };
        device_id?: string;
      };
    };
    const coreId = config.active_account?.authority?.principal_id;
    const stationId = config.active_account?.authority?.station_id;
    const did = config.active_account?.resolution?.did;
    const deviceId = config.active_account?.device_id;
    if (
      typeof coreId !== "string" ||
      typeof stationId !== "string" ||
      typeof did !== "string" ||
      typeof deviceId !== "string"
    ) {
      throw new Error(
        "Inkson active account omitted its typed identity coordinates",
      );
    }
    return { coreId, accountId: { principal_id: coreId, station_id: stationId }, did, deviceId };
  });
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function waitForEventIngress(
  hits: ProtocolHit[],
  predicate: (wire: string) => boolean,
  context: string,
): Promise<ProtocolHit> {
  await expect
    .poll(
      () =>
        hits.find(
          (hit) =>
            hit.method === "POST" &&
            hit.path === "/_arkret/self/events" &&
            hit.status < 400 &&
            hit.requestBody !== undefined &&
            predicate(JSON.stringify(hit.requestBody)),
        ),
      { timeout: 120_000, message: `${context} was not observed` },
    )
    .toBeTruthy();
  return hits.find(
    (hit) =>
      hit.method === "POST" &&
      hit.path === "/_arkret/self/events" &&
      hit.status < 400 &&
      hit.requestBody !== undefined &&
      predicate(JSON.stringify(hit.requestBody)),
  )!;
}

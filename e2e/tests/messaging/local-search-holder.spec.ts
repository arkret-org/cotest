// Real accepted Device roots and issuer-backed holder sessions for both readers.
import { expect, test } from "../../helpers/arkret-test";
import type { PlaywrightTestArgs, PlaywrightWorkerArgs, TestInfo } from "@playwright/test";
import { createRealmViaApi, sendPlaintextMessageViaApi } from "../../helpers/api";
import { authHeaders, resolveDefaultStrandId } from "../../helpers/coland-api";
import { coauthBaseUrl, colandBaseUrl } from "../../helpers/env";
import { observeNativeSearch } from "../../helpers/native-search";
import { postponeSearchEncryptionPrompts } from "../../helpers/local-search";
import { createDpopUserSession, issueUserSession, openDpopUserPageFromSession,
  pairSiblingDeviceSession, selfPathHeadersForDpopSession, type DpopUserSession } from "../../helpers/users";

test("0540 real local search binds paired Devices and withdraws a revoked Device holder", async ({ browser, request }, testInfo) => {
  await runHolderRevocation({ browser, request }, testInfo, "Device");
});

test("0540 real local search binds paired Devices and withdraws a revoked session holder", async ({ browser, request }, testInfo) => {
  await runHolderRevocation({ browser, request }, testInfo, "session");
});

async function runHolderRevocation(
  { browser, request }: Pick<PlaywrightTestArgs & PlaywrightWorkerArgs, "browser" | "request">,
  testInfo: TestInfo,
  revokedHolder: "Device" | "session",
) {
  test.setTimeout(1_200_000);
  const owner = await createDpopUserSession(request, "search-holder");
  if (!owner) throw new Error("search holder acceptance requires real Coauth sessions");
  const sibling = await pairSiblingDeviceSession(request, owner);
  const token = await issueUserSession(request, owner.user);
  const realm = await createRealmViaApi(request, token, {
    ownerId: owner.user.id, title: "Search holder sources", discoverability: "listed",
    historyAccess: "all_history_for_current_members", mlsActivated: false,
  });
  const strand = await resolveDefaultStrandId(request, token, realm);
  const body = `accepted holder search ${Date.now()}`;
  const accepted = await sendPlaintextMessageViaApi(request, token, realm, body,
    { actorId: owner.user.id, strandId: strand });
  const flows = [];
  const observations: Array<Record<string, unknown>> = [];
  const native = async (step: string, session: DpopUserSession) => {
    const observed = await observeNativeSearch(session, realm, body,
      testInfo.outputPath(`native-${session.user.deviceId.split(":").at(-1)}.json`));
    expect(observed.view.results).toHaveLength(1);
    expect(observed.view.results[0]!.event_id).toBe(accepted.event_id);
    expect(observed.view.results[0]!.content.body).toBe(body);
    observations.push({ step, observed });
    return observed.view.results[0]!;
  };
  try {
    for (const session of [owner, sibling]) {
      const flow = await openDpopUserPageFromSession(browser, session, {
        prepareMlsDevice: revokedHolder === "Device" && session === owner,
      });
      if (!flow) throw new Error("paired holder browser did not initialize");
      flows.push(flow);
      await postponeSearchEncryptionPrompts(flow.page.page, prompt =>
        observations.push({ step: "postpone-optional-encryption-prompt", prompt,
          device: session.user.deviceId }));
      if (revokedHolder === "Device" && session === owner) {
        // A plaintext-only account need not have an active recovery policy.
        // Establish its first policy and backup through the full Settings
        // custody-confirmation flow before requiring SecurityRotation.
        const policyUrl = `${colandBaseUrl()}/_arkret/root/identity/recovery-policy`;
        const policy = await request.get(policyUrl, {
          headers: selfPathHeadersForDpopSession(owner, "GET", policyUrl),
        });
        expect(policy.status()).toBe(200);
        const activePolicy = (await policy.json()).active_policy;
        if (activePolicy === null) {
          await flow.page.gotoAppPanel("/settings/recovery", "recovery-panel");
          const page = flow.page.page;
          await page.getByTestId("recovery-key-regenerate").click();
          const generated = (await page.getByTestId("recovery-key-current").textContent())!.trim();
          expect(generated.split(/\s+/).length).toBe(24);
          await page.getByTestId("recovery-key-confirm-input").evaluate((element, secret) => {
            Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(element, secret);
            element.dispatchEvent(new Event("input", { bubbles: true }));
          }, generated);
          await page.getByTestId("recovery-key-clear-live").click();
          await expect(page.getByTestId("recovery-key-confirm-form")).toHaveCount(0, { timeout: 120_000 });
          await expect(page.getByTestId("recovery-key-regenerate")).toBeDisabled();
          flow.page.session.onRecoveryKeyConfigured?.(generated);
        } else {
          expect(activePolicy).toBeTruthy();
          await flow.page.completeMlsAccountBackupIfPrompted(owner.recoveryKey!, 1_000);
        }
        expect(owner.recoveryKey?.trim().split(/\s+/).length).toBe(24);
        await expect.poll(async () => {
          const response = await request.get(policyUrl, {
            headers: selfPathHeadersForDpopSession(owner, "GET", policyUrl),
          });
          return response.ok() && Boolean((await response.json()).active_policy);
        }, { timeout: 120_000 }).toBe(true);
        const backupsUrl = `${colandBaseUrl()}/_arkret/self/keys/backups?backup_kind=secret_storage`;
        await expect.poll(async () => {
          const response = await request.get(backupsUrl, {
            headers: selfPathHeadersForDpopSession(owner, "GET", backupsUrl),
          });
          if (!response.ok()) return false;
          const current = await response.json();
          const pointer = current.active_series?.secret_storage;
          return pointer?.state === "active" && Array.isArray(current.backups)
            && current.backups.some((backup: { backup_kind?: string; series_id?: string;
              encryption?: { recipient_method?: string } }) => backup.backup_kind === "secret_storage"
              && backup.series_id === pointer.active_series_id
              && backup.encryption?.recipient_method === "recovery_public_key");
        }, { timeout: 120_000 }).toBe(true);
        observations.push({ step: "authoritative-secret-storage-series-before-device-rotation",
          realRecoverySettingsUiCompleted: activePolicy === null,
          activePolicyObserved: true, authoritativePointerAndEnvelopeObserved: true });
      }
      await flow.page.gotoTimelineRealm(realm);
      await flow.page.completeRecoveryKeySetupIfPrompted(100);
      await flow.page.page.keyboard.press("Control+F");
      const panel = flow.page.page.getByTestId("global-search-panel");
      await panel.getByTestId("global-search-input").fill(body);
      await panel.getByTestId("global-search-submit").click();
      const row = panel.getByTestId("global-search-result-item");
      await expect(row).toHaveCount(1);
      await expect(row).toHaveAttribute("data-event-id", accepted.event_id);
      const result = await native("accepted-device-positive", session);
      expect(result.covering_commit.commit_id).toBe(await row.getAttribute("data-commit-id"));
    }
    // Replace the local session through the real root picker while an actual
    // authenticated IndexedDB candidate read is pending. The issuer grant
    // stays valid: an independent native positive distinguishes root retirement
    // from a server revoke or an accidentally expired source.
    const replacingPage = flows[0]!.page.page;
    const origin = await replacingPage.evaluate(() => performance.timeOrigin);
    await replacingPage.evaluate(() => {
      const waiting: Array<() => void> = [];
      const barrier = { observed: 0, delivered: 0, armed: true, release: () => {
        barrier.armed = false;
        for (const resume of waiting.splice(0)) resume();
      } };
      Object.assign(window, { holderSearchReadBarrier: barrier });
      const decrypt = SubtleCrypto.prototype.decrypt;
      SubtleCrypto.prototype.decrypt = function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto["decrypt"]>) {
        return decrypt.apply(this, args).then(value => {
          let tuple: unknown;
          try { tuple = JSON.parse(new TextDecoder().decode(value)); } catch { return value; }
          if (barrier.armed && Array.isArray(tuple) && typeof tuple[0] === "string"
              && tuple[0].includes("/search/")) {
            barrier.observed++;
            return new Promise<ArrayBuffer>(resolve => waiting.push(() => {
              barrier.delivered++;
              resolve(value);
            }));
          }
          return value;
        });
      };
    });
    // A current publication can already have refreshed this query and paused
    // its authenticated read. Ordinary Enter also submits when it is idle;
    // the barrier below proves a real read rather than assuming a click ran.
    await replacingPage.getByTestId("global-search-input").press("Enter");
    await expect.poll(() => replacingPage.evaluate(() => (window as unknown as {
      holderSearchReadBarrier: { observed: number };
    }).holderSearchReadBarrier.observed)).toBeGreaterThan(0);
    await expect(replacingPage.getByTestId("global-search-results-loading")).toBeVisible();
    await replacingPage.getByTestId("account-menu-button").click();
    const picker = replacingPage.getByTestId("account-menu").getByTestId("account-switch-select");
    const savedProfile = await picker.inputValue();
    expect(savedProfile).not.toBe("");
    await replacingPage.getByTestId("account-menu").getByTestId("account-add").click();
    await expect(replacingPage.getByTestId("login-panel")).toBeVisible({ timeout: 120_000 });
    await expect(replacingPage.getByTestId("client-shell")).toHaveCount(0);
    await replacingPage.evaluate(() => (window as unknown as {
      holderSearchReadBarrier: { release: () => void };
    }).holderSearchReadBarrier.release());
    await expect.poll(() => replacingPage.evaluate(() => {
      const b = (window as unknown as { holderSearchReadBarrier: { observed: number; delivered: number } }).holderSearchReadBarrier;
      return b.delivered === b.observed && b.delivered > 0;
    })).toBe(true);
    const retainedSource = await native("issuer-holder-remains-valid-during-local-replacement", owner);
    await expect(replacingPage.getByTestId("login-panel")).toBeVisible();
    await expect(replacingPage.getByTestId("global-search-result-item")).toHaveCount(0);
    await replacingPage.getByTestId("return-previous-account").click();
    await expect(replacingPage.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    expect(await replacingPage.evaluate(() => JSON.parse(localStorage.getItem("inkson.config.v1") ?? "{}").active_account?.profile_id)).toBe(savedProfile);
    await flows[0]!.page.completeRecoveryKeySetupIfPrompted(100);
    expect(await replacingPage.evaluate(() => performance.timeOrigin)).toBe(origin);
    await replacingPage.keyboard.press("Control+F");
    await expect(replacingPage.getByTestId("global-search-results-empty")).toBeVisible();
    await expect(replacingPage.getByTestId("global-search-result-item")).toHaveCount(0);
    await replacingPage.getByTestId("global-search-input").fill(body);
    await replacingPage.getByTestId("global-search-submit").click();
    const freshRow = replacingPage.getByTestId("global-search-result-item");
    await expect(freshRow).toHaveCount(1);
    await expect(freshRow).toHaveAttribute("data-event-id", retainedSource.event_id);
    await expect(freshRow).toHaveAttribute("data-commit-id", retainedSource.covering_commit.commit_id);
    await expect(freshRow.getByTestId("global-search-result-snippet")).toHaveText(body);
    observations.push({ step: "same-document-root-session-and-pending-device-replacement",
      sameDocument: true, deliveredLateAuthenticatedRead: true,
      originalEvent: retainedSource.event_id, originalCommit: retainedSource.covering_commit.commit_id });
    if (revokedHolder === "Device") {
      // device-lifecycle section 2.2 requires a durable prepared rotation before
      // its revoke Event. Exercise the existing complete product transaction.
      expect(owner.recoveryKey?.trim().split(/\s+/).length).toBe(24);
      const ownerPage = flows[0]!.page.page;
      await ownerPage.goto(new URL("/settings/devices", ownerPage.url()).toString());
      const target = ownerPage.locator(`[data-testid="device-row"][data-device-id="${sibling.user.deviceId}"]`);
      await expect(target).toBeVisible({ timeout: 120_000 });
      await target.getByTestId("device-revoke-button").click();
      // Deliver the ordinary input event without putting Recovery Key words
      // into a locator.fill failure's reporter-visible call log.
      await ownerPage.getByTestId("device-revoke-passphrase-input").evaluate((element, secret) => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(element, secret);
        element.dispatchEvent(new Event("input", { bubbles: true }));
      }, owner.recoveryKey!);
      await ownerPage.getByTestId("device-revoke-confirm-button").click();
      await expect(ownerPage.getByTestId("device-revoke-status"))
        .toContainText("through transaction", { timeout: 180_000 });
      await expect(flows[1]!.page.page.getByTestId("global-search-result-item")).toHaveCount(0,
        { timeout: 120_000 });
      await expect(observeNativeSearch(sibling, realm, body,
        testInfo.outputPath("revoked-device-native.json"))).rejects.toThrow(/401|unauthorized|revok|not.*active|unavailable/i);
      await native("independent-holder-still-authorized", owner);
      await flows[0]!.page.gotoTimelineRealm(realm);
      await ownerPage.keyboard.press("Control+F");
      await ownerPage.getByTestId("global-search-input").fill(body);
      await ownerPage.getByTestId("global-search-submit").click();
      await expect(ownerPage.getByTestId("global-search-result-snippet")).toHaveText(body);

    } else {
      const url = `${coauthBaseUrl()}/_arkret/gate/account/session-grants/revoke`;
      const revoked = await request.post(url, { headers: authHeaders(owner.grantJwt, "POST", url) });
      expect(revoked.status(), await revoked.text()).toBe(200);
      const outcome = await revoked.json();
      expect(outcome.revoked_count).toBe(1);
      expect(outcome.revoked_session_grant_ids).toEqual([owner.grantId]);
      await expect(flows[0]!.page.page.getByTestId("global-search-result-item")).toHaveCount(0,
        { timeout: 120_000 });
      await expect(observeNativeSearch(owner, realm, body,
        testInfo.outputPath("revoked-session-native.json"))).rejects.toThrow(/401|unauthorized|revok|grant.*invalid/i);
      await native("independent-session-remains-authorized-after-targeted-revoke", sibling);
      const siblingPage = flows[1]!.page.page;
      await siblingPage.getByTestId("global-search-input").fill(body);
      await siblingPage.getByTestId("global-search-submit").click();
      await expect(siblingPage.getByTestId("global-search-results-loading")).toHaveCount(0);
      await expect(siblingPage.getByTestId("global-search-result-item"))
        .toHaveAttribute("data-event-id", accepted.event_id);
      await expect(siblingPage.getByTestId("global-search-result-snippet")).toHaveText(body);
    }
    for (const flow of (revokedHolder === "Device" ? [flows[1]!] : [flows[0]!])) {
      await flow.page.page.reload({ waitUntil: "domcontentloaded" });
      await expect(flow.page.page.getByTestId("login-panel")).toBeVisible({ timeout: 120_000 });
      await expect(flow.page.page.getByTestId("global-search-result-item")).toHaveCount(0);
      await expect(flow.page.page.getByTestId("client-shell")).toHaveCount(0, { timeout: 120_000 });
    }
  } finally {
    await testInfo.attach("real-holder-search.json", {
      body: JSON.stringify({ acceptedEvent: accepted.event_id, observations }, null, 2),
      contentType: "application/json",
    });
    for (const flow of flows) await flow.page.close();
  }
}

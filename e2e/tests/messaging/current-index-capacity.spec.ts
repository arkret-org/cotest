// Real Station metadata and durable WASM startup; no supplied current projection.
import { expect, test } from "../../helpers/arkret-test";
import { createRealmViaApi, sendPlaintextMessageViaApi } from "../../helpers/api";
import { resolveDefaultStrandId } from "../../helpers/coland-api";
import { postponeSearchEncryptionPrompts } from "../../helpers/local-search";
import { createDpopUserSession, issueUserSession, openDpopUserPageFromSession } from "../../helpers/users";

test("0540 real Station 1/100/1000 Realm durable cold startup records first screen and long tasks", async ({
  browser, request,
}, testInfo) => {
  test.setTimeout(7_200_000);
  const session = await createDpopUserSession(request, "current-capacity");
  if (!session) throw new Error("capacity acceptance requires real Coauth DPoP login");
  const token = await issueUserSession(request, session.user);
  const prefix = `capacity-0540-${Date.now()}-`;
  const realms: string[] = [];
  const measurements: Array<Record<string, unknown>> = [];
  let flow: Awaited<ReturnType<typeof openDpopUserPageFromSession>>;
  let postpone: (() => Promise<void>) | undefined;
  let postponedPrompts = 0;
  const recoveryPolicyWrites: string[] = [];
  try {
    for (const count of [1, 100, 1000]) {
      // Stop this document's subscriptions while provisioning the next size;
      // the same browser context retains its genuine encrypted IndexedDB.
      if (flow) await flow.page.page.goto("about:blank");
      const provisionStarted = Date.now();
      while (realms.length < count) {
        const offset = realms.length;
        const batch = await Promise.allSettled(Array.from({ length: Math.min(4, count - offset) },
          (_, index) => createRealmViaApi(request, token, {
            ownerId: session.user.id,
            title: `${prefix}${String(offset + index + 1).padStart(4, "0")}`,
            discoverability: "listed", historyAccess: "all_history_for_current_members",
            mlsActivated: false,
          })));
        for (const result of batch) if (result.status === "fulfilled") realms.push(result.value);
        const failure = batch.find(result => result.status === "rejected");
        if (failure?.status === "rejected") throw failure.reason;
        if (offset === 0) {
          const strandId = await resolveDefaultStrandId(request, token, realms[0]!);
          await sendPlaintextMessageViaApi(request, token, realms[0]!, `${prefix}accepted-body`, {
            actorId: session.user.id, strandId,
          });
        }
        if (realms.length % 100 === 0) console.log(`0540 accepted ${realms.length} real Realms`);
      }
      const provisioningMs = Date.now() - provisionStarted;
      flow ??= await openDpopUserPageFromSession(browser, session, {
        prepareMlsDevice: false, autoCompleteRecoveryKeySetup: false,
      });
      if (!flow) throw new Error("capacity browser did not initialize its accepted account");
      const page = flow.page.page;
      // These accepted Realms explicitly disable MLS. Ordinary reads may
      // postpone unpublished recovery setup without starting a crypto writer.
      postpone ??= await postponeSearchEncryptionPrompts(page, () => postponedPrompts++,
        { allowUnpublishedRecoverySetup: true });
      if (count === 1) {
        page.on("request", request => {
          if (request.method() === "POST"
            && new URL(request.url()).pathname === "/_arkret/root/identity/recovery-policy") {
            recoveryPolicyWrites.push("POST /_arkret/root/identity/recovery-policy");
          }
        });
        await page.addInitScript(() => {
          const metrics = { longTaskCount: 0, longTaskTotalMs: 0, longestTaskMs: 0,
            inputFrames: [] as number[], start: performance.now() };
          Object.assign(window, { currentCapacityMetrics: metrics });
          new PerformanceObserver(list => {
            for (const entry of list.getEntries()) {
              metrics.longTaskCount++;
              metrics.longTaskTotalMs += entry.duration;
              metrics.longestTaskMs = Math.max(metrics.longestTaskMs, entry.duration);
            }
          }).observe({ type: "longtask", buffered: true });
          document.addEventListener("input", event => {
            if (!(event.target instanceof HTMLElement) || event.target.dataset.testid !== "chat-input") return;
            const start = performance.now();
            requestAnimationFrame(() => metrics.inputFrames.push(performance.now() - start));
          }, true);
        });
      }
      const promptsBefore = postponedPrompts;
      const loadingStarted = Date.now();
      await flow.page.gotoHome();
      const rows = page.locator(`[data-testid="realm-tree-node-button"][title^="${prefix}"]`);
      const more = page.getByTestId("realm-list-load-more");
      let loadMoreClicks = 0;
      await expect.poll(async () => {
        await postpone!();
        const visible = await rows.count();
        if (visible < count && await more.isVisible()) {
          await more.click();
          loadMoreClicks++;
        }
        return visible;
      }, { timeout: 600_000, intervals: [1000],
        message: `all ${count} accepted Realm summaries reach the real navigation` }).toBe(count);
      const fullMetadataVisibleMs = Date.now() - loadingStarted;
      await flow.page.gotoTimelineRealm(realms[0]!, { completeRecoveryKeySetup: false });
      await expect(page.getByTestId("message-list").getByText(`${prefix}accepted-body`, { exact: true }))
        .toBeVisible({ timeout: 120_000 });
      // A full document reload keeps the previously installed durable dataset.
      // It is a cold application start, not a new browser-profile first install.
      const coldStarted = Date.now();
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page.getByTestId("message-list").getByText(`${prefix}accepted-body`, { exact: true }))
        .toBeVisible({ timeout: 120_000 });
      const coldBodyVisibleMs = Date.now() - coldStarted;
      await expect(rows).toHaveCount(count, { timeout: 120_000 });
      await postpone();
      const input = page.getByTestId("chat-input");
      await input.fill("unsent capacity responsiveness check");
      await expect(input).toHaveValue("unsent capacity responsiveness check");
      await input.fill("");
      await expect.poll(() => page.evaluate(() => (window as unknown as {
        currentCapacityMetrics: { inputFrames: number[] };
      }).currentCapacityMetrics.inputFrames.length)).toBeGreaterThanOrEqual(2);
      await postpone();
      const metrics = await page.evaluate(() => ({
        ...(window as unknown as { currentCapacityMetrics: {
          longTaskCount: number; longTaskTotalMs: number; longestTaskMs: number;
          inputFrames: number[]; start: number;
        } }).currentCapacityMetrics,
        hardwareConcurrency: navigator.hardwareConcurrency, userAgent: navigator.userAgent,
        viewport: { width: innerWidth, height: innerHeight },
      }));
      measurements.push({ businessRealmCount: count, principalControlRealmCount: 1,
        acceptedRealmIds: [...realms], provisioningMs, provisioningConcurrency: 4, fullMetadataVisibleMs, loadMoreClicks,
        recoveryPromptDismissals: postponedPrompts - promptsBefore,
        recoveryPolicyWriteCount: recoveryPolicyWrites.length,
        coldBodyVisibleMs, retainedNavigationRows: await rows.count(), metrics });
      await testInfo.attach(`real-capacity-${count}.json`, {
        body: JSON.stringify(measurements.at(-1), null, 2), contentType: "application/json",
      });
      await page.screenshot({ path: testInfo.outputPath(`real-capacity-${count}.png`) });
      expect(recoveryPolicyWrites, "plaintext startup does not publish a recovery policy").toEqual([]);
      expect(Math.max(...metrics.inputFrames), "real composer input paint under the retained dataset").toBeLessThan(1000);
    }
  } finally {
    await testInfo.attach("real-capacity-summary.json", {
      body: JSON.stringify(measurements, null, 2), contentType: "application/json",
    });
    await flow?.page.close();
  }
});

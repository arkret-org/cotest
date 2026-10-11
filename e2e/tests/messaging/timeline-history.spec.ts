// Real account/WASM history acceptance; no injected projection or DOM fixture.
import { expect, test } from "../../helpers/arkret-test";
import { createSharedRealmViaApi, sendPlaintextMessageViaApi } from "../../helpers/api";
import { resolveDefaultStrandId } from "../../helpers/coland-api";
import { ensureRegistered, issueUserSession, openDpopUserPage, uniqueUser } from "../../helpers/users";
import { stepShot } from "../../helpers/screenshots";
import { sampleAndAdvanceTimeline } from "../../helpers/timeline-visibility";

test("AV-UI-BOUND real WASM cold history keeps 256 variable-height messages reachable", async ({
  browser, request,
}, testInfo) => {
  test.setTimeout(900_000);
  const flow = await openDpopUserPage(browser, request, "history-owner", { prepareMlsDevice: false });
  if (!flow) throw new Error("history acceptance requires real Coauth DPoP login");
  const peer = uniqueUser("history-peer");
  try {
    await ensureRegistered(request, peer);
    const token = await issueUserSession(request, flow.user);
    const realmId = await createSharedRealmViaApi(request, flow.user, token, peer, {
      title: `WASM history ${Date.now()}`,
      historyAccess: "all_history_for_current_members",
    });
    const strandId = await resolveDefaultStrandId(request, token, realmId);
    const count = 256;
    for (let index = 0; index < count; index++) {
      await sendPlaintextMessageViaApi(request, token, realmId,
        `history-row-${index.toString().padStart(3, "0")}\n${"Variable height content. ".repeat(1 + index % 17)}`,
        { actorId: flow.user.id, strandId });
    }

    const page = flow.page.page;
    await page.addInitScript(() => {
      const evidence = {
        longTasks: [] as number[], inputFrames: [] as number[], peakRows: 0,
        renderedRows: [] as number[],
        installedWindows: [] as Array<{ top: number; rows: number[] }>,
        omittedWindowRecords: 0,
      };
      const rendered = new Set<number>();
      let previousWindow = "";
      Object.assign(window, { timelineHistoryEvidence: evidence });
      new PerformanceObserver(list => {
        for (const entry of list.getEntries()) evidence.longTasks.push(entry.duration);
      }).observe({ type: "longtask", buffered: true });
      new MutationObserver(() => {
        const feed = document.querySelector<HTMLElement>('[data-testid="message-list"]');
        const mounted = feed?.querySelectorAll('[data-virtual-index]') ?? [];
        evidence.peakRows = Math.max(evidence.peakRows, mounted.length);
        const indices = Array.from(mounted).flatMap(row => {
          const match = /history-row-(\d{3})/.exec(row.textContent ?? "");
          return match ? [Number(match[1])] : [];
        });
        for (const index of indices) {
          if (!rendered.has(index)) {
            rendered.add(index);
            evidence.renderedRows.push(index);
          }
        }
        const signature = indices.join(",");
        if (signature !== previousWindow) {
          previousWindow = signature;
          // Passive DOM evidence distinguishes installed rows from a later
          // Playwright sample. It supplies no history or authority state.
          if (evidence.installedWindows.length < 1024) {
            evidence.installedWindows.push({ top: feed?.scrollTop ?? 0, rows: indices });
          } else {
            evidence.omittedWindowRecords++;
          }
        }
      }).observe(document, { childList: true, subtree: true });
      document.addEventListener("input", event => {
        if (!(event.target instanceof HTMLElement) || event.target.dataset.testid !== "chat-input") return;
        const start = performance.now();
        requestAnimationFrame(() => evidence.inputFrames.push(performance.now() - start));
      }, true);
    });
    const started = Date.now();
    await flow.page.gotoTimelineRealm(realmId);
    const feed = page.getByTestId("message-list");
    await expect(feed.getByText("history-row-255", { exact: false })).toBeVisible({ timeout: 120_000 });
    const coldVisibleMs = Date.now() - started;
    const seen = new Set<number>();
    await feed.evaluate(element => { element.scrollTop = 0; });
    await expect(feed.getByText("history-row-000", { exact: false })).toBeVisible({ timeout: 30_000 });
    for (let step = 0; step < count * 4 && seen.size < count; step++) {
      const sample = await sampleAndAdvanceTimeline(feed);
      expect(sample.length, "mounted history window").toBeLessThanOrEqual(120);
      for (const text of sample) {
        const match = /history-row-(\d{3})/.exec(text);
        if (match) seen.add(Number(match[1]));
      }
      if (seen.size === count) break;
      // Allow the actual eval channel and Dioxus render to install each window.
      await page.waitForTimeout(75);
    }
    await testInfo.attach("real-wasm-history-traversal", {
      body: JSON.stringify({ seen: [...seen].sort((a, b) => a - b),
        installed: await page.evaluate(() => {
          const record = (window as unknown as { timelineHistoryEvidence: {
            renderedRows: number[]; installedWindows: Array<{ top: number; rows: number[] }>;
            omittedWindowRecords: number;
          } }).timelineHistoryEvidence;
          return { renderedRows: record.renderedRows.slice().sort((a, b) => a - b),
            windows: record.installedWindows, omittedWindowRecords: record.omittedWindowRecords };
        }), geometry: await feed.evaluate(element => ({
        top: element.scrollTop, height: element.scrollHeight, viewport: element.clientHeight,
        mounted: Array.from(element.querySelectorAll<HTMLElement>("[data-virtual-index]"))
          .map(row => Number(row.dataset.virtualIndex)),
      })) }, null, 2), contentType: "application/json",
    });
    expect([...seen].sort((a, b) => a - b), "every accepted message is reachable through real scroll")
      .toEqual(Array.from({ length: count }, (_, index) => index));

    const input = page.getByTestId("chat-input");
    await input.fill("unsent history responsiveness check");
    await expect(input).toHaveValue("unsent history responsiveness check");
    await input.fill("");
    await expect(input).toHaveValue("");
    await feed.evaluate(element => { element.scrollTop = 0; });
    await expect(feed.getByText("history-row-000", { exact: false })).toBeVisible();
    await feed.hover();
    const beforeWheel = await feed.evaluate(element => element.scrollTop);
    await page.mouse.wheel(0, 500);
    await expect.poll(() => feed.evaluate(element => element.scrollTop)).toBeGreaterThan(beforeWheel);
    await feed.evaluate(element => { element.scrollTop = element.scrollHeight; });
    await expect(feed.getByText("history-row-255", { exact: false })).toBeVisible();
    await stepShot(page, testInfo, "real-wasm-history-latest");
    const evidence = await page.evaluate(() => {
      const record = (window as unknown as { timelineHistoryEvidence: {
        longTasks: number[]; inputFrames: number[]; peakRows: number;
      } }).timelineHistoryEvidence;
      return { ...record, viewport: { width: innerWidth, height: innerHeight },
        hardwareConcurrency: navigator.hardwareConcurrency, userAgent: navigator.userAgent };
    });
    await testInfo.attach("real-wasm-history-performance", {
      body: JSON.stringify({ count, coldVisibleMs, reachableRows: seen.size, ...evidence }, null, 2),
      contentType: "application/json",
    });
    expect(evidence.peakRows, "transient DOM peak also respects window cap").toBeLessThanOrEqual(120);
    expect(evidence.inputFrames.length, "real composer input paint evidence").toBeGreaterThanOrEqual(2);
    expect(Math.max(...evidence.inputFrames), "input remains responsive under retained history")
      .toBeLessThan(1000);
  } finally {
    await flow.page.close();
  }
});

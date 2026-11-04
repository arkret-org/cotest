import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Page, TestInfo } from "@playwright/test";

type SaveCounters = { pre_authoring_retries: number; ingress_observed: boolean;
  saw_save_progress: boolean; saw_current_card_wait: boolean };

// Observe trusted event handoff and renderer node replacement without recording
// any input values, text, keys, URLs, HTML or application/network payloads.
export async function observeCardSaveAction(page: Page) {
  await page.evaluate(() => {
    const events: Array<Record<string, string | number | boolean>> = [];
    const replacements: Array<{ added: number; removed: number; at: number }> = [];
    const root = document.querySelector(".card-detail-modal");
    const node = (element: Element | null) => {
      const id = element?.closest("[data-gly-node]")?.getAttribute("data-gly-node") ?? "";
      return /^\d+\.(?:\d+\.)*\d+$/.test(id) ? id : "";
    };
    const kinds = ["pointerdown", "pointerup", "click", "focusin", "focusout", "keydown", "keyup"];
    const receive = (event: Event) => {
      if (events.length >= 256) return;
      const element = event.target instanceof Element ? event.target : null;
      const kind = element?.closest(".card-detail-save-button") ? "save-button"
        : element?.closest(".card-detail-edit-form") ? "editor" : "other";
      events.push({ type: event.type, at: Math.round(performance.now()), trusted: event.isTrusted,
        node: node(element), active_node: node(document.activeElement),
        connected: element?.isConnected ?? false, inside_modal: root?.contains(element) ?? false,
        target_kind: kind, activation_key: event instanceof KeyboardEvent && ["Enter", " "].includes(event.key) });
    };
    for (const kind of kinds) document.addEventListener(kind, receive, true);
    const observer = new MutationObserver(records => {
      if (replacements.length >= 128) return;
      const added = records.reduce((sum, record) => sum + record.addedNodes.length, 0);
      const removed = records.reduce((sum, record) => sum + record.removedNodes.length, 0);
      if (added || removed) replacements.push({ added, removed, at: Math.round(performance.now()) });
    });
    if (root) observer.observe(root, { subtree: true, childList: true });
    (window as any).__cotestCardSaveAction = () => {
      for (const kind of kinds) document.removeEventListener(kind, receive, true);
      observer.disconnect();
      delete (window as any).__cotestCardSaveAction;
      return { events, replacements, unavailable: false };
    };
  });
  return async (info: TestInfo, counters: SaveCounters) => {
    const trace = await page.evaluate(() => (window as any).__cotestCardSaveAction?.())
      .catch(() => undefined) ?? { events: [], replacements: [], unavailable: true };
    const file = info.outputPath(`card-save-action-${randomUUID()}.json`);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify({
      pre_authoring_retries: counters.pre_authoring_retries,
      ingress_observed: counters.ingress_observed,
      saw_save_progress: counters.saw_save_progress,
      saw_current_card_wait: counters.saw_current_card_wait,
      events: trace.events,
      replacements: trace.replacements,
      unavailable: trace.unavailable,
    }, null, 2));
    await info.attach("card-save-action", { path: file, contentType: "application/json" });
  };
}

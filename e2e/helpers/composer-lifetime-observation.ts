import type { Page } from "@playwright/test";
import { randomUUID } from "node:crypto";

// Passive, bounded UI coordinates: never retain draft text, account names,
// targets, credentials, or arbitrary DOM properties.
export async function observeComposerLifetime(page: Page) {
  const key = `cotest-composer-${randomUUID()}`;
  await page.evaluate(key => {
    const ids = new WeakMap<Element, number>();
    let next = 0;
    let frame = 0;
    let last = "";
    const edges: Array<Record<string, number | boolean | string>> = [];
    const sample = (source: "mounted" | "input" | "render") => {
      const inputs = document.querySelectorAll<HTMLTextAreaElement | HTMLInputElement>(".chat-input");
      const input = inputs[0];
      if (input && !ids.has(input)) ids.set(input, ++next);
      const state = { input_count: inputs.length, input_node: input ? ids.get(input)! : 0,
        nonempty: Boolean(input?.value), enabled: Boolean(input && !input.disabled),
        app_empty_hint_count: document.querySelectorAll(".chat-input-hint").length,
        ready_panel_count: document.querySelectorAll(".chat-panel.initial-sync-complete").length,
        selected_channel_count: document.querySelectorAll(".channel-item.active").length };
      const encoded = JSON.stringify(state);
      if (source !== "input" && encoded === last) return;
      last = encoded;
      if (edges.length < 256) edges.push({ at: Date.now(), source, ...state });
    };
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(() => { frame = 0; sample("render"); });
    };
    const input = (event: Event) => {
      if (event.target instanceof Element && event.target.matches(".chat-input")) {
        sample("input");
        schedule();
      }
    };
    const observer = new MutationObserver(schedule);
    observer.observe(document, { subtree: true, childList: true, attributes: true,
      attributeFilter: ["class", "disabled"] });
    document.addEventListener("input", input, true);
    const observations = ((window as any).__cotestComposerObservations ??= new Map());
    observations.set(key, () => {
      observer.disconnect();
      document.removeEventListener("input", input, true);
      if (frame) cancelAnimationFrame(frame);
      sample("render");
      return { edges, distinct_input_nodes: next, truncated: edges.length === 256 };
    });
    sample("mounted");
  }, key);
  return async () => page.evaluate(key => {
    const observations = (window as any).__cotestComposerObservations;
    const finish = observations?.get(key);
    if (!finish) return { edges: [], distinct_input_nodes: 0, truncated: false, document_replaced: true };
    observations.delete(key);
    if (observations.size === 0) delete (window as any).__cotestComposerObservations;
    return finish();
  }, key).catch(() => ({ edges: [], distinct_input_nodes: 0, truncated: false, document_unavailable: true }));
}

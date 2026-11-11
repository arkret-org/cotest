import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Page, TestInfo } from "@playwright/test";

type SaveCounters = { pre_authoring_retries: number; ingress_observed: boolean;
  saw_save_progress: boolean; saw_current_card_wait: boolean };

// Observe trusted event handoff and renderer node replacement without recording
// any input values, text, keys, URLs, HTML or application/network payloads.
export async function observeCardSaveAction(page: Page) {
  return observeSubmissionAction(page, {
    root: ".card-detail-modal", button: ".card-detail-save-button",
    editor: ".card-detail-edit-form", name: "card-save",
  });
}

export async function observeMessageSendAction(page: Page) {
  return observeSubmissionAction(page, {
    root: ".chat-panel", button: ".send-chat-button",
    editor: "textarea,[contenteditable=true]", name: "message-send",
  });
}

async function observeSubmissionAction(page: Page, selectors: {
  root: string; button: string; editor: string; name: string;
}) {
  await page.evaluate(selectors => {
    const events: Array<Record<string, string | number | boolean>> = [];
    const replacements: Array<{ added: number; removed: number; at: number }> = [];
    const attributes: Array<{ node: string; disabled: boolean; aria_disabled: boolean; inert: boolean; at: number }> = [];
    const root = document.querySelector(selectors.root);
    const node = (element: Element | null) => {
      const id = element?.closest("[data-gly-node]")?.getAttribute("data-gly-node") ?? "";
      return /^\d+\.(?:\d+\.)*\d+$/.test(id) ? id : "";
    };
    const kinds = ["pointerdown", "pointerup", "click", "focusin", "focusout", "keydown", "keyup"];
    const receive = (event: Event) => {
      if (events.length >= 256) return;
      const element = event.target instanceof Element ? event.target : null;
      const button = element?.closest(selectors.button) ?? null;
      const kind = button ? "submit-button"
        : element?.closest(selectors.editor) ? "editor" : "other";
      const observed = { type: event.type, at: Math.round(performance.now()), trusted: event.isTrusted,
        node: node(element), active_node: node(document.activeElement),
        connected: element?.isConnected ?? false, inside_modal: root?.contains(element) ?? false,
        target_kind: kind, activation_key: event instanceof KeyboardEvent && ["Enter", " "].includes(event.key),
        disabled: button instanceof HTMLButtonElement && button.disabled,
        aria_disabled: button?.getAttribute("aria-disabled") === "true",
        inert: Boolean(button?.closest("[inert]")),
        default_prevented: event.defaultPrevented, final_default_prevented: false,
        final_disabled: false, final_connected: false,
        primary_pointer: event instanceof PointerEvent && event.isPrimary,
        primary_button: event instanceof MouseEvent && event.button === 0,
        path_has_save: event.composedPath().some(item => item instanceof Element && Boolean(item.closest(selectors.button))),
      };
      events.push(observed);
      setTimeout(() => {
        observed.final_default_prevented = event.defaultPrevented;
        observed.final_disabled = button instanceof HTMLButtonElement && button.disabled;
        observed.final_connected = button?.isConnected ?? false;
      }, 0);
    };
    for (const kind of kinds) document.addEventListener(kind, receive, true);
    const observer = new MutationObserver(records => {
      for (const record of records) {
        if (attributes.length >= 128 || record.type !== "attributes") continue;
        const button = record.target instanceof Element ? record.target.closest(selectors.button) : null;
        if (!button) continue;
        attributes.push({ node: node(button), disabled: button instanceof HTMLButtonElement && button.disabled,
          aria_disabled: button.getAttribute("aria-disabled") === "true", inert: Boolean(button.closest("[inert]")),
          at: Math.round(performance.now()) });
      }
      if (replacements.length >= 128) return;
      const added = records.reduce((sum, record) => sum + record.addedNodes.length, 0);
      const removed = records.reduce((sum, record) => sum + record.removedNodes.length, 0);
      if (added || removed) replacements.push({ added, removed, at: Math.round(performance.now()) });
    });
    if (root) observer.observe(root, { subtree: true, childList: true, attributes: true,
      attributeFilter: ["disabled", "aria-disabled", "inert"] });
    (window as any).__cotestSubmissionAction = async () => {
      await new Promise<void>(resolve => setTimeout(resolve, 0));
      for (const kind of kinds) document.removeEventListener(kind, receive, true);
      observer.disconnect();
      delete (window as any).__cotestSubmissionAction;
      return { events, replacements, attributes, unavailable: false };
    };
  }, selectors);
  return async (info: TestInfo, counters: SaveCounters | Record<string, number | boolean> = {}) => {
    const trace = await page.evaluate(() => (window as any).__cotestSubmissionAction?.())
      .catch(() => undefined) ?? { events: [], replacements: [], unavailable: true };
    const file = info.outputPath(`${selectors.name}-action-${randomUUID()}.json`);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify({
      ...counters,
      events: trace.events,
      replacements: trace.replacements,
      attributes: trace.attributes ?? [],
      unavailable: trace.unavailable,
    }, null, 2));
    await info.attach(`${selectors.name}-action`, { path: file, contentType: "application/json" });
  };
}

import { createHash } from "node:crypto";
import { expect, type Locator, type Page } from "@playwright/test";

const references = new WeakMap<Page, Set<string>>();

function collect(value: unknown, found: Set<string>): void {
  if (typeof value === "string") {
    if (/^ak:event:[A-Za-z0-9_-]+$/.test(value)) found.add(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collect(item, found);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) collect(item, found);
  }
}

/** Passive identity breadcrumbs only. These references never establish admission,
 * authorization or signer validity; each scenario retains its actual proof checks.
 */
export function observeMessageReferences(page: Page): void {
  if (references.has(page)) return;
  const found = new Set<string>();
  references.set(page, found);
  const read = (text: string) => { try { collect(JSON.parse(text), found); } catch {} };
  page.on("request", request => {
    if (!new URL(request.url()).pathname.startsWith("/_arkret/")) return;
    try { collect(request.postDataJSON(), found); } catch {}
  });
  page.on("response", response => {
    const pathname = new URL(response.url()).pathname;
    if (!pathname.startsWith("/_arkret/") || pathname.endsWith("/subscribe")
        || !response.headers()["content-type"]?.includes("json")) return;
    void response.text().then(read).catch(() => {});
  });
  page.on("websocket", socket => {
    if (!new URL(socket.url()).pathname.startsWith("/_arkret/")) return;
    socket.on("framereceived", frame => read(typeof frame.payload === "string" ? frame.payload : frame.payload.toString("utf8")));
  });
}

export async function eventIdFromMessage(message: Locator): Promise<string> {
  const page = message.page();
  const candidates = references.get(page);
  if (!candidates) throw new Error("Message identity observation must start before the product page loads");
  let matched = "";
  await expect(async () => {
    const realm = new URL(page.url()).pathname.split("/").map(decodeURIComponent).find(value => value.startsWith("ak:realm:"));
    if (realm) {
      const fold = await page.evaluate(realm => {
        const hook = (window as unknown as Record<string, unknown>).__inkson_sidecar_fold_evidence_v1;
        return typeof hook === "function" ? (hook as (realm: string) => string)(realm) : null;
      }, realm);
      if (fold) collect(JSON.parse(fold), candidates);
    }
    const id = await message.getAttribute("id");
    const matches = [...candidates].filter(event => `chat-message-${createHash("sha256").update(event).digest("hex")}` === id);
    expect(matches, "the rendered row must bind one actual wire/projection Event reference").toHaveLength(1);
    matched = matches[0];
  }).toPass({ timeout: 30_000, intervals: [250, 500, 1_000] });
  return matched;
}

export async function expectPlaintextMessage(message: Locator, options: { timeout?: number } = {}): Promise<void> {
  await expect(message).toBeVisible(options);
  await expect(message).not.toHaveClass(/\bis-crypto-pending\b/, options);
  await expect(message.locator(".crypto-status-row")).toHaveCount(0, options);
  await expect(message.locator(".content-block-text, .content-block-markdown").first()).toBeVisible(options);
}

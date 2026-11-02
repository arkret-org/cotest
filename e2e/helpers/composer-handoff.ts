import { expect, type Locator, type Page } from "@playwright/test";

/** Ordinary Realm/Circle/Direct sends clear the draft before enqueueing the original.
 * Agent Sidecar activation has its own pending command and is intentionally separate.
 */
export async function submitOrdinaryComposerDraft(scope: Page | Locator, original: string,
  options: { timeout?: number; click?: () => Promise<void> } = {}): Promise<void> {
  const input = scope.locator(".chat-input");
  const send = scope.locator(".send-chat-button");
  await expect(input).toHaveValue(original);
  // Observe an application-owned state, rather than only the browser's fill value.
  await expect(scope.locator(".chat-input-hint")).toHaveCount(0);
  const deadline = Date.now() + (options.timeout ?? 90_000);
  await expect(async () => {
    const value = await input.inputValue();
    if (value === "") return;
    expect(value, "keep the exact draft until its ordinary authoring handoff").toBe(original);
    await expect(send).toBeEnabled({ timeout: Math.max(1, Math.min(3_000, deadline - Date.now())) });
    if (options.click) await options.click();
    else await send.click({ timeout: Math.max(1, Math.min(3_000, deadline - Date.now())) });
    await expect(input).toHaveValue("", { timeout: 1_000 });
  }).toPass({ timeout: Math.max(1, deadline - Date.now()), intervals: [250, 500, 1_000] });
}

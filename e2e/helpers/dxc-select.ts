import { expect, type Locator } from "@playwright/test";

/**
 * Pick an option from a dioxus-components (dxc) Select.
 *
 * Background: after the yougen frontend migrated from a native `<select>` to
 * the dxc `Select` (dioxus-primitives), the dropdown renders as a custom
 * popover — a `button[aria-haspopup="listbox"]` trigger plus a
 * `div[role="listbox"]` container with `div[role="option"]` entries — no
 * longer a native `<select>`/`<option>`. Playwright's
 * `locator.selectOption()` therefore throws
 * `Element is not a <select> element` and every e2e still using it breaks.
 *
 * yougen's `SelectOption` exposes the underlying value as `data-value` (see
 * `yougen/src/ui/select/component.rs`); this helper locates and clicks the
 * option by that value, keeping call semantics equivalent to the original
 * `selectOption(value)` (the string passed in is unchanged).
 *
 * @param scope Locator pointing at the Select's outer container (usually
 *   `page.getByTestId("xxx-select")`)
 * @param value the option's underlying value (identical to the first
 *   argument of the original `selectOption`)
 */
export async function selectDxcOption(scope: Locator, value: string): Promise<void> {
  const trigger = scope.locator('button[aria-haspopup="listbox"]').first();
  await expect(trigger).toBeVisible({ timeout: 30_000 });
  if ((await trigger.getAttribute("aria-expanded")) !== "true") {
    await trigger.click();
  }
  const quotedValue = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const option = scope.locator(`[role="option"][data-value="${quotedValue}"]`);
  await option.click();
  if ((await trigger.getAttribute("aria-expanded")) === "true") {
    await trigger.press("Escape").catch(() => {});
    await scope.page().mouse.click(0, 0).catch(() => {});
  }
}

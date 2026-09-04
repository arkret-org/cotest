import { expect, type Locator } from "@playwright/test";

/**
 * Pick an option from a dioxus-components (dxc) Select.
 *
 * Background: after the inkson frontend migrated from a native `<select>` to
 * the dxc `Select` (dioxus-primitives), the dropdown renders as a custom
 * popover — a `button[aria-haspopup="listbox"]` trigger plus a
 * `div[role="listbox"]` container with `div[role="option"]` entries — no
 * longer a native `<select>`/`<option>`. Playwright's
 * `locator.selectOption()` therefore throws
 * `Element is not a <select> element` and every e2e still using it breaks.
 *
 * inkson's `SelectOption` exposes the underlying value as `data-value` (see
 * `inkson/src/ui/select/component.rs`); this helper locates and clicks the
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
  const quotedValue = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  let selected = false;
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      await expect(trigger).toBeVisible({ timeout: 30_000 });
      if ((await trigger.getAttribute("aria-expanded")) !== "true") {
        await trigger.click({ timeout: 15_000 });
      }
      // Recreate the locator on every attempt. Account bootstrap can complete
      // a recovery-key modal between opening the popover and clicking its
      // option, which remounts the dxc Select and detaches the old option.
      await scope
        .locator(`[role="option"][data-value="${quotedValue}"]`)
        .click({ timeout: 15_000 });
      selected = true;
      break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!selected) {
    throw lastError;
  }
  if ((await trigger.getAttribute("aria-expanded")) === "true") {
    await trigger.press("Escape").catch(() => {});
    await scope.page().mouse.click(0, 0).catch(() => {});
  }
}

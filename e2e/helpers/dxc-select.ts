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
  const native = await scope.evaluate(element => element.tagName === "SELECT")
    ? scope : scope.locator("select");
  if (await native.count() > 0) {
    await expect(native).toHaveCount(1);
    await expect(native).toBeVisible({ timeout: 30_000 });
    await native.selectOption(value, { timeout: 15_000 });
    return;
  }
  if (await scope.evaluate(element => element.matches('.sapid-select[data-gly-combobox="select"]'))) {
    await expect(scope).toHaveCount(1);
    await expect(scope).toBeVisible({ timeout: 30_000 });
    await expect(scope).toBeEnabled({ timeout: 30_000 });
    const controls = await scope.getAttribute("aria-controls");
    const suffix = "-listbox-4_root";
    if (!controls?.startsWith("sapid-select-") || !controls.endsWith(suffix)) {
      throw new Error("The Sapid select has no exact listbox identity");
    }
    if (!/^[\x21-\x7e]{1,64}$/.test(value)) {
      throw new Error("The Sapid option key must be a bounded ASCII semantic identity");
    }
    // Sapid's public SemanticId uses the same namespace for trigger, listbox,
    // and wire-keyed options. Match the full identity, not a display label.
    const optionId = `${controls.slice(0, -suffix.length)}-option-${value.length}_${value}`;
    const quote = (text: string) => text.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    const panel = scope.page().locator(`[role="listbox"][id="${quote(controls)}"]`);
    if ((await scope.getAttribute("aria-expanded")) !== "true") {
      await scope.click({ timeout: 15_000 });
    }
    await expect(panel).toBeVisible({ timeout: 30_000 });
    const option = panel.locator(`[role="option"][id="${quote(optionId)}"][data-gly-option-owner="${quote(controls)}"]`);
    await expect(option).toHaveCount(1);
    await expect(option).toBeEnabled({ timeout: 15_000 });
    await option.click({ timeout: 15_000 });
    await expect(option).toHaveAttribute("aria-selected", "true", { timeout: 15_000 });
    await expect(scope).toHaveAttribute("aria-expanded", "false", { timeout: 15_000 });
    return;
  }
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

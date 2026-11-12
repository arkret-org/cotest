import { expect, type Locator } from "@playwright/test";

const quote = (text: string) => text.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

async function control(scope: Locator): Promise<Locator> {
  await expect(scope).toBeVisible({ timeout: 30_000 });
  if (await scope.evaluate(element => element.matches('select, .sapid-select[data-gly-combobox="select"]'))) return scope;
  // A visible field can precede mounting its controlled child.
  const child = scope.locator('.sapid-select[data-gly-combobox="select"], select:visible');
  await expect(child).toHaveCount(1);
  return child;
}

async function open(control: Locator): Promise<Locator> {
  await expect(control).toBeEnabled({ timeout: 30_000 });
  const id = await control.getAttribute("aria-controls");
  if (!id) throw new Error("The product select has no listbox identity");
  if (await control.getAttribute("aria-expanded") !== "true") await control.click({ timeout: 1_000 });
  const panel = control.page().locator(`[role="listbox"][id="${quote(id)}"]`);
  await expect(panel).toBeVisible({ timeout: 1_000 });
  return panel;
}

async function choose(
  scope: Locator, resolve: (panel: Locator, trigger: Locator) => Locator | Promise<Locator>,
  label?: string | RegExp,
): Promise<void> {
  let selected: { panel: Locator; name: string | RegExp } | undefined;
  // A frame can retire a menu before activation. Reacquire this local choice.
  // Keep post-activation checks outside the retry to expose lost user edits.
  await expect(async () => {
    const trigger = await control(scope);
    const panel = await open(trigger);
    const option = await resolve(panel, trigger);
    await expect(option).toHaveCount(1, { timeout: 1_000 });
    await expect(option).toBeEnabled({ timeout: 1_000 });
    const name = label ?? await option.getAttribute("aria-label");
    expect(name, "the product option must expose its accessible label").toBeTruthy();
    await expect(option).toHaveAccessibleName(name!, { timeout: 1_000 });
    await option.click({ timeout: 1_000 });
    selected = { panel, name: name! };
  }).toPass({ timeout: 30_000, intervals: [100, 250, 500] });
  expect(selected).toBeDefined();
  await expect(selected!.panel).toBeHidden();
  await expect(await control(scope)).toContainText(selected!.name);
}

/** Select an actual public option key; field wrappers and native controls are supported. */
export async function selectProductOptionByKey(scope: Locator, value: string): Promise<void> {
  const trigger = await control(scope);
  if (await trigger.evaluate(element => element.tagName === "SELECT")) {
    await trigger.selectOption(value);
    return;
  }
  await choose(scope, async (panel, current) => {
    const id = await current.getAttribute("aria-controls");
    const suffix = "-listbox-4_root";
    if (!id?.startsWith("sapid-select-") || !id.endsWith(suffix) || !/^[\x21-\x7e]{1,64}$/.test(value)) {
      throw new Error("The Sapid option key has no exact semantic identity");
    }
    const optionId = id.slice(0, -suffix.length) + "-option-" + value.length + "_" + value;
    return panel.locator('[role="option"][id="' + quote(optionId)
      + '"][data-gly-option-owner="' + quote(id) + '"]');
  });
}

/** Choose the visible label when the control owns opaque presentation keys. */
export async function selectProductOptionByLabel(scope: Locator, label: string | RegExp): Promise<void> {
  const trigger = await control(scope);
  if (await trigger.evaluate(element => element.tagName === "SELECT")) {
    const option = trigger.locator("option").filter({ hasText: label });
    await expect(option).toHaveCount(1);
    await trigger.selectOption({ label: (await option.innerText()).trim() });
    return;
  }
  await choose(scope, panel => panel.getByRole("option", { name: label, exact: true }), label);
}

export async function selectProductOptionByReference(scope: Locator, reference: string): Promise<void> {
  const escaped = reference.replace(/[^\w-]/g, "\\$&");
  await selectProductOptionByLabel(scope, new RegExp("(?:\\(" + escaped + "\\)| · " + escaped + ")$"));
}

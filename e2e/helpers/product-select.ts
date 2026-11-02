import { expect, type Locator } from "@playwright/test";

const quote = (text: string) => text.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

async function control(scope: Locator): Promise<Locator> {
  await expect(scope).toBeVisible({ timeout: 30_000 });
  if (await scope.evaluate(element => element.matches('select, .sapid-select[data-gly-combobox="select"]'))) return scope;
  const trigger = scope.locator('.sapid-select[data-gly-combobox="select"]');
  const child = await trigger.count() ? trigger : scope.locator('select:visible');
  await expect(child).toHaveCount(1);
  return child;
}

async function open(control: Locator): Promise<Locator> {
  await expect(control).toBeEnabled({ timeout: 30_000 });
  const id = await control.getAttribute("aria-controls");
  if (!id) throw new Error("The product select has no listbox identity");
  if (await control.getAttribute("aria-expanded") !== "true") await control.click();
  const panel = control.page().locator(`[role="listbox"][id="${quote(id)}"]`);
  await expect(panel).toBeVisible();
  return panel;
}

async function choose(control: Locator, option: Locator): Promise<void> {
  await expect(option).toHaveCount(1);
  await expect(option).toBeEnabled();
  const label = (await option.innerText()).trim();
  await option.click();
  await expect(control).toHaveAttribute("aria-expanded", "false");
  await expect(control).toContainText(label);
}

/** Select an actual public option key; field wrappers and native controls are supported. */
export async function selectProductOptionByKey(scope: Locator, value: string): Promise<void> {
  const trigger = await control(scope);
  if (await trigger.evaluate(element => element.tagName === "SELECT")) {
    await trigger.selectOption(value);
    return;
  }
  const panel = await open(trigger);
  const id = await trigger.getAttribute("aria-controls");
  const suffix = "-listbox-4_root";
  if (!id?.startsWith("sapid-select-") || !id.endsWith(suffix) || !/^[\x21-\x7e]{1,64}$/.test(value)) {
    throw new Error("The Sapid option key has no exact semantic identity");
  }
  const optionId = `${id.slice(0, -suffix.length)}-option-${value.length}_${value}`;
  await choose(trigger, panel.locator(`[role="option"][id="${quote(optionId)}"][data-gly-option-owner="${quote(id)}"]`));
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
  const panel = await open(trigger);
  await choose(trigger, panel.getByRole("option", { name: label, exact: true }));
}

export async function selectProductOptionByReference(scope: Locator, reference: string): Promise<void> {
  const escaped = reference.replace(/[^\w-]/g, "\\$&");
  await selectProductOptionByLabel(scope, new RegExp("(?:\\(" + escaped + "\\)| · " + escaped + ")$"));
}

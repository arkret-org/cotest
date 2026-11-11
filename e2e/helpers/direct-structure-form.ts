import { expect, type Page } from "@playwright/test";

// Form preparation changes only the local draft; it must never submit an Event.
export async function prepareDirectStructureForm(page: Page, action: string, topic?: string) {
  const panel = page.locator(".direct-structure");
  // Selecting a Chat can still replace its controls after the DOM event returns.
  // Reapply the local draft to the current form and read it back before authoring.
  await expect(async () => {
    const actions = panel.getByRole("combobox", { name: "Action", exact: true });
    if (!await actions.isVisible()) await panel.getByRole("button", { name: "Manage chats and topics" }).click({ timeout: 1_000 });
    await actions.selectOption(action, { timeout: 1_000 });
    await expect(actions).toHaveValue(action, { timeout: 1_000 });
    if (topic) {
      const topics = panel.getByRole("combobox", { name: "Topic", exact: true });
      // A remounted native select may retain a DOM value before its new
      // change handler owns the draft. Force a complete local selection.
      const empty = topics.locator('option[value=""]:not([data-gly-placeholder]):not([disabled])');
      await expect(empty).toHaveCount(1, { timeout: 1_000 });
      const emptyIndex = await empty.evaluate(option => (option as HTMLOptionElement).index);
      await topics.selectOption({ index: emptyIndex }, { timeout: 1_000 });
      await expect(topics).toHaveValue("", { timeout: 1_000 });
      await topics.selectOption(topic, { timeout: 1_000 });
      await expect(topics).toHaveValue(topic, { timeout: 1_000 });
    }
    await expect(actions).toHaveValue(action, { timeout: 1_000 });
  }).toPass({ timeout: 10_000, intervals: [100, 250] });
}

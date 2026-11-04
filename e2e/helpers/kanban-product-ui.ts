import { expect, type Locator, type Page } from "@playwright/test";

/** Prepare a local member filter without selecting or submitting anything. */
export async function filterCardAssignee(page: Page, actorId: string): Promise<Locator> {
  await page.bringToFront();
  const detail = page.locator(".card-detail-modal");
  const filter = detail.getByRole("textbox", { name: "Filter members", exact: true });
  const option = detail.locator(".assignee-picker-option");
  await expect(async () => {
    // A pending card refresh can replace the controls during an input event.
    // Reapply only this local query, then inspect the current controls.
    await filter.click({ timeout: 1_000 });
    await filter.fill("", { timeout: 1_000 });
    await filter.fill(actorId, { timeout: 1_000 });
    await expect(filter).toHaveValue(actorId, { timeout: 1_000 });
    await expect(option).toHaveCount(1, { timeout: 1_000 });
  }).toPass({ timeout: 10_000, intervals: [100, 250] });
  return option;
}

export async function fillCardNarrative(
  page: Page,
  name: "Description" | "Synthesis",
  value: string,
): Promise<void> {
  const form = page.locator(".card-detail-edit-form");
  const editor = form.getByRole("textbox", { name, exact: true });
  await page.bringToFront();
  await expect(editor).toBeVisible({ timeout: 45_000 });
  await editor.click();
  await editor.fill(value);
  await expect(form.locator(".card-rich-editor-preview")).toHaveText(value);
  await expect(form.locator(".card-detail-save-button")).toBeEnabled({ timeout: 45_000 });
}

/** Author one List through the accepted Board's ordinary product composer. */
export async function addBoardList(page: Page, title: string): Promise<Locator> {
  await expect(page).toHaveURL(url => /^\/kanban\/ak:realm:[^/]+\/board\/ak:space:[^/]+$/
    .test(decodeURIComponent(url.pathname)), { timeout: 120_000 });
  const composer = page.locator(".board-list-compose");
  const input = composer.locator(".new-column-input");
  const submit = composer.locator(".add-column-button");
  await expect(composer).toBeVisible();
  await expect(submit).toBeEnabled({ timeout: 120_000 });
  await input.fill(title);
  await expect(input).toHaveValue(title);
  await expect(composer.locator(".input-empty-prompt")).toHaveCount(0);
  let activated = false;
  await expect(async () => {
    const value = await input.inputValue();
    if (value === "") {
      expect(activated, "the List draft clears only after the ordinary submission handoff").toBe(true);
      return;
    }
    expect(value, "retain the exact List intent until enqueueing its original").toBe(title);
    await expect(submit).toBeEnabled({ timeout: 3_000 });
    await submit.click({ timeout: 3_000 });
    activated = true;
    await expect(input).toHaveValue("", { timeout: 1_000 });
  }).toPass({ timeout: 90_000, intervals: [250, 500, 1_000] });
  const column = page.locator(".kanban-column").filter({
    has: page.locator(".kanban-column-title").and(page.getByText(title, { exact: true })),
  });
  await expect(column).toHaveCount(1, { timeout: 120_000 });
  await expect(column).toBeVisible();
  return column;
}

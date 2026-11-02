import { expect, type Locator, type Page } from "@playwright/test";

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
    has: page.locator(".kanban-column-title").and(page.getByRole("button", { name: title, exact: true })),
  });
  await expect(column).toHaveCount(1, { timeout: 120_000 });
  await expect(column).toBeVisible();
  return column;
}

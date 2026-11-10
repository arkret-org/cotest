import { expect, type Locator, type Page } from "@playwright/test";
import type { AccountId } from "./generated/spec-wire-objects";
import { accountRow } from "./product-locators";

/** Select through the public list and verify the complete identity in its detail. */
export async function selectContact(page: Page, account: AccountId): Promise<Locator> {
  const detail = accountRow(page, ".contact-row", account);
  await expect(async () => {
    if (await detail.isVisible()) return;
    const choices = page.locator(".contacts-list-pane .contact-list-item:not(.contact-agent-list-item)");
    for (let index = 0; index < await choices.count(); index += 1) {
      await choices.nth(index).click({ timeout: 3_000 });
      if (await detail.isVisible()) return;
    }
    await expect(detail).toBeVisible({ timeout: 1_000 });
  }).toPass({ timeout: 90_000, intervals: [500, 1_000, 2_000] });
  return detail;
}

/** The accepted Contact's ordinary Message action owns Direct resolution. */
export async function contactMessage(page: Page, account: AccountId): Promise<Locator> {
  const detail = await selectContact(page, account);
  await expect(detail.locator(".event-head").getByText("Contact", { exact: true })).toBeVisible({ timeout: 90_000 });
  const message = detail.locator(".contact-message");
  await expect(message).toBeEnabled({ timeout: 90_000 });
  return message;
}

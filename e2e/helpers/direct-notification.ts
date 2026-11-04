import { expect, type Page } from "@playwright/test";

export async function openDirectChatNotification(page: Page, realmId: string, chatId: string) {
  const notificationsButton = page.locator(".topbar-notifications-link:visible");
  await expect(notificationsButton).toHaveCount(1);
  await notificationsButton.click();
  const panel = page.locator(".notifications-drawer-panel");
  await expect(panel).toBeVisible();
  const notification = panel.locator(`.notification-item:not(.notification-read)[aria-label=${JSON.stringify(realmId)}]`)
    .filter({ has: page.locator(".notification-open-chat") });
  await expect(notification).toHaveCount(1, { timeout: 90_000 });
  await expect(notification).toBeVisible();
  await notification.locator(".notification-open-chat").click();
  await expect.poll(() => new URL(page.url()).pathname.split("/").map(decodeURIComponent))
    .toEqual(["", "direct", realmId, chatId]);
  await expect(page.locator(".direct-structure").getByRole("combobox", { name: "Chat", exact: true })).toHaveValue(chatId);
  await panel.getByRole("button", { name: "Close", exact: true }).click();
  await expect(panel).toHaveCount(0);
  await expect(page.locator(".direct-structure").getByRole("combobox", { name: "Chat", exact: true })
    .locator(`option[value=${JSON.stringify(chatId)}]`)).not.toContainText("unread", { timeout: 90_000 });
}

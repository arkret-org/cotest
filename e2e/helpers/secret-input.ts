import { expect, type Locator, type Page } from "@playwright/test";

// Custody scenarios must disable trace, video and screenshots while words are
// visible. Use Chrome's trusted input channel without a secret-bearing fill
// step title, synthetic DOM event or raw transport error in the report.
export async function enterSecretText(page: Page, input: Locator, text: string): Promise<void> {
  await page.bringToFront();
  await expect(input).toBeVisible();
  await input.focus();
  await page.keyboard.press("ControlOrMeta+A");
  const keyboard = await page.context().newCDPSession(page);
  try {
    await keyboard.send("Input.insertText", { text });
  } catch {
    throw new Error("secret confirmation could not be entered through the native input channel");
  } finally {
    await keyboard.detach();
  }
  await expect.poll(async () => (await input.inputValue()).trim() === text.trim(),
    { message: "secret confirmation must retain the actual custody material" }).toBe(true);
}

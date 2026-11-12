import { expect, type Page } from "@playwright/test";

// Search fixtures may keep encryption keys unavailable. Postpone only these
// ordinary prompts; leave foreground security workflows and all keys intact.
export async function postponeSearchEncryptionPrompts(
  page: Page,
  onPostpone?: (prompt: string) => void,
  options: { allowUnpublishedRecoverySetup?: boolean } = {},
): Promise<() => Promise<void>> {
  const prompts: Array<readonly [string, string]> = [
    ["Restore encryption keys", "Not now"],
    ["Back up encrypted history", "Remind me later"],
  ];
  if (options.allowUnpublishedRecoverySetup) {
    // Plaintext reads do not require the E2EE recovery-material gate. Only
    // these callers may postpone its unpublished setup through normal UI.
    prompts.push(["Set up your recovery key", "Close without publishing"],
      ["Set up your recovery key", "Not now"]);
  }
  const pauseAttribute = "data-cotest-search-reminders-paused";
  const reminders = [...new Set(prompts.map(([prompt]) => prompt))]
    .map(prompt => page.locator(`html:not([${pauseAttribute}])`)
      .getByRole("dialog", { name: prompt, exact: true }));
  const installHandlers = async () => {
    for (const reminder of reminders) {
      await page.addLocatorHandler(reminder, postpone, { noWaitAfter: true });
    }
  };
  const frontmost = async () => {
    for (const [prompt, dismiss] of prompts) {
      const button = page.getByRole("dialog", { name: prompt, exact: true })
        .getByRole("button", { name: dismiss, exact: true });
      let uncovered: boolean;
      try {
        if (!await button.isVisible() || !await button.isEnabled({ timeout: 500 })) continue;
        uncovered = await button.evaluate(element => {
          const bounds = element.getBoundingClientRect();
          const top = document.elementFromPoint(bounds.x + bounds.width / 2,
            bounds.y + bounds.height / 2);
          return Boolean(top && (top === element || element.contains(top)));
        }, undefined, { timeout: 500 });
      } catch (error) {
        if (page.isClosed()) return null;
        if (!await button.isVisible()) continue;
        throw error;
      }
      if (uncovered) return { prompt, dismiss };
    }
    return null;
  };
  let postponing = false;
  const postpone = async () => {
    if (postponing || page.isClosed()) return;
    postponing = true;
    try {
      // Pause only the fixture's matching predicate. Unregistering an active
      // handler discards Playwright's waiter before it can resume the action.
      // The actual dialog and all foreground security gates stay unchanged.
      await page.evaluate(attribute => document.documentElement.setAttribute(attribute, ""), pauseAttribute);
      for (let attempt = 0; attempt < 3; attempt++) {
        const selected = await frontmost();
        if (!selected) return;
        const dialog = page.getByRole("dialog", { name: selected.prompt, exact: true });
        try {
          await dialog.getByRole("button", { name: selected.dismiss, exact: true }).click({ timeout: 2_500 });
          await expect(dialog).toBeHidden({ timeout: 2_500 });
        } catch (error) {
          // The initial setup can reveal words between hit-test and click.
          // Re-select its normal dismissal; another foreground workflow keeps
          // its own action, and a still-clickable broken button must fail.
          if (page.isClosed()) return;
          const current = await frontmost();
          if (!current) return;
          if (attempt === 2) throw error;
          continue;
        }
        onPostpone?.(selected.prompt);
      }
      if (await frontmost()) throw new Error("search encryption reminders did not settle after three normal dismissals");
    } catch (error) {
      if (!page.isClosed()) throw error;
    } finally {
      try {
        if (!page.isClosed()) {
          await page.evaluate(attribute => document.documentElement.removeAttribute(attribute), pauseAttribute);
        }
      } catch (error) {
        if (!page.isClosed()) throw error;
      } finally {
        postponing = false;
      }
    }
  };
  // A covered reminder must not hold up the foreground security workflow.
  await installHandlers();
  await postpone();
  return postpone;
}

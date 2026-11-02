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
  const frontmost = async () => {
    for (const [prompt, dismiss] of prompts) {
      const button = page.getByRole("dialog", { name: prompt, exact: true })
        .getByRole("button", { name: dismiss, exact: true });
      if (!await button.isVisible() || !await button.isEnabled()) continue;
      const uncovered = await button.evaluate(element => {
        const bounds = element.getBoundingClientRect();
        const top = document.elementFromPoint(bounds.x + bounds.width / 2,
          bounds.y + bounds.height / 2);
        return Boolean(top && (top === element || element.contains(top)));
      });
      if (uncovered) return { prompt, dismiss };
    }
    return null;
  };
  let postponing = false;
  const postpone = async () => {
    if (postponing) return;
    postponing = true;
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const selected = await frontmost();
        if (!selected) return;
        const dialog = page.getByRole("dialog", { name: selected.prompt, exact: true });
        try {
          await dialog.getByRole("button", { name: selected.dismiss, exact: true }).click({ timeout: 1_000 });
        } catch (error) {
          // The initial setup can reveal words between hit-test and click.
          // Re-select its normal dismissal; another foreground workflow keeps
          // its own action, and a still-clickable broken button must fail.
          const current = await frontmost();
          if (current?.prompt !== selected.prompt) return;
          if (current.dismiss !== selected.dismiss) continue;
          throw error;
        }
        await expect(dialog).toBeHidden();
        onPostpone?.(selected.prompt);
      }
      if (await frontmost()) throw new Error("search encryption reminders did not settle after three normal dismissals");
    } finally {
      postponing = false;
    }
  };
  for (const prompt of new Set(prompts.map(([prompt]) => prompt))) {
    // A covered background reminder remains visible while the real workflow
    // is active. Waiting for it to hide here would deadlock that workflow.
    await page.addLocatorHandler(page.getByRole("dialog", { name: prompt, exact: true }), postpone, { noWaitAfter: true });
  }
  await postpone();
  return postpone;
}

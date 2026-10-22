import { expect, type Page } from "@playwright/test";

// Search fixtures may keep encryption keys unavailable. Postpone only these
// ordinary prompts; leave foreground security workflows and all keys intact.
export async function postponeSearchEncryptionPrompts(
  page: Page,
  onPostpone?: (prompt: string) => void,
  options: { allowUnpublishedRecoverySetup?: boolean } = {},
): Promise<() => Promise<void>> {
  const prompts: Array<readonly [string, string]> = [
    ["mls-unlock-banner", "mls-unlock-dismiss"],
    ["mls-backup-modal", "mls-backup-dismiss"],
  ];
  if (options.allowUnpublishedRecoverySetup) {
    // Plaintext reads do not require the E2EE recovery-material gate. Only
    // these callers may postpone its unpublished setup through normal UI.
    prompts.push(["recovery-key-setup-modal", "recovery-key-setup-dismiss-unpublished"],
      ["recovery-key-setup-modal", "recovery-key-setup-dismiss"]);
  }
  const frontmost = () => page.evaluate(entries => {
    for (const [prompt, dismiss] of entries) {
      const button = document.querySelector<HTMLButtonElement>(
        `[data-testid="${prompt}"] [data-testid="${dismiss}"]`,
      );
      if (!button || button.disabled) continue;
      const bounds = button.getBoundingClientRect();
      if (!bounds.width || !bounds.height) continue;
      const top = document.elementFromPoint(bounds.x + bounds.width / 2,
        bounds.y + bounds.height / 2);
      if (top && (top === button || button.contains(top))) return { prompt, dismiss };
    }
    return null;
  }, prompts);
  let postponing = false;
  const postpone = async () => {
    if (postponing) return;
    postponing = true;
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const selected = await frontmost();
        if (!selected) return;
        const dialog = page.getByTestId(selected.prompt);
        try {
          await dialog.getByTestId(selected.dismiss).click({ timeout: 1_000 });
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
    await page.addLocatorHandler(page.getByTestId(prompt), postpone, { noWaitAfter: true });
  }
  await postpone();
  return postpone;
}

import { expect, type Page } from "@playwright/test";

const recoverySetupCompletions = new WeakMap<Page, Promise<string>>();
const completedRecoverySetups = new WeakMap<Page, string>();
const failedRecoverySetups = new WeakMap<Page, unknown>();
const closingRecoveryPages = new WeakSet<Page>();

// Cleanup owns the already-started publication too. Stop re-arming before
// awaiting that writer, and propagate its real failure before closing Page.
export async function finishRecoverySetupBeforeClose(page: Page): Promise<void> {
  closingRecoveryPages.add(page);
  const active = recoverySetupCompletions.get(page);
  if (active) await active;
  if (failedRecoverySetups.has(page)) throw failedRecoverySetups.get(page);
}

// Publish only one completion per page. Locator handlers must not await an
// existing operation: it may be the action whose auto-wait invoked them.
export function completeRecoverySetup(
  page: Page,
  recoveryKey: string,
): Promise<string> {
  if (failedRecoverySetups.has(page)) {
    return Promise.reject(failedRecoverySetups.get(page));
  }
  const active = recoverySetupCompletions.get(page);
  if (active) return active;
  if (closingRecoveryPages.has(page)) {
    return Promise.reject(new Error("recovery setup cannot start during Page cleanup"));
  }
  const operation = Promise.resolve().then(async () => {
    expect(
      recoveryKey.trim().split(/\s+/).filter(Boolean).length,
      "recovery-key setup must expose exactly 24 words",
    ).toBe(24);
    const dialog = page.getByTestId("recovery-key-setup-banner").last();
    if (
      completedRecoverySetups.get(page) === recoveryKey &&
      await dialog.isHidden()
    ) {
      return recoveryKey;
    }
    const confirmation = page.getByTestId("recovery-key-setup-confirm-key").last();
    const saved = page.getByTestId("recovery-key-setup-saved").last();
    await confirmation.fill(recoveryKey, { timeout: 10_000 });
    const confirmMatches = async () =>
      (await confirmation.inputValue()).trim() === recoveryKey;
    await expect.poll(confirmMatches, {
      timeout: 10_000,
      message: "recovery-key confirmation must exactly match the generated key",
    }).toBe(true);
    await saved.click({ timeout: 10_000 });
    const deadline = Date.now() + 90_000;
    while (Date.now() < deadline) {
      const hidden = await dialog
        .waitFor({
          state: "hidden",
          timeout: Math.max(1, Math.min(5_000, deadline - Date.now())),
        })
        .then(() => true, (error) => {
          if (error instanceof Error && error.name === "TimeoutError") return false;
          throw error;
        });
      if (hidden) {
        completedRecoverySetups.set(page, recoveryKey);
        return recoveryKey;
      }
      // The product re-enables Save after a retry-safe pending publication.
      // Retry inside this sole writer without refilling or racing a handler.
      const canRetry = await saved.isEnabled({
        timeout: Math.max(1, Math.min(1_000, deadline - Date.now())),
      }).catch(async (error: unknown) => {
        // Publication may remove Save after the hidden probe timed out.
        // Only actual dialog closure makes that detached-button race benign.
        if (error instanceof Error && error.name === "TimeoutError" && await dialog.isHidden()) {
          return false;
        }
        throw error;
      });
      if (canRetry) {
        expect(
          await confirmMatches(),
          "recovery-key confirmation must remain unchanged before publication retry",
        ).toBe(true);
        await saved.click({ timeout: 10_000 });
      }
    }
    await expect(dialog).toBeHidden({ timeout: 1 });
    completedRecoverySetups.set(page, recoveryKey);
    return recoveryKey;
  }).catch((error) => {
    // A handler may already have released its action after 5s. Preserve a
    // later real failure for the next handler or explicit completion caller.
    failedRecoverySetups.set(page, error);
    throw error;
  }).finally(() => recoverySetupCompletions.delete(page));
  recoverySetupCompletions.set(page, operation);
  return operation;
}

export async function installRecoverySetupHandler(
  page: Page,
  onConfigured?: (key: string) => void,
): Promise<void> {
  const rearmAfter = (completion: Promise<unknown>) => {
    void completion.then(arm, arm).catch((error) => {
      if (!page.isClosed()) failedRecoverySetups.set(page, error);
    });
  };
  const arm = async () => {
    if (closingRecoveryPages.has(page) || page.isClosed()) return;
    await page.addLocatorHandler(
      page.getByTestId("recovery-key-setup-generated-key"),
      async (generated) => {
        if (closingRecoveryPages.has(page)) return;
        if (failedRecoverySetups.has(page)) throw failedRecoverySetups.get(page);
        const active = recoverySetupCompletions.get(page);
        if (active) {
          rearmAfter(active);
          return;
        }
        const recoveryKey = (await generated.inputValue()).trim();
        const configured = completeRecoverySetup(page, recoveryKey)
          .then(() => onConfigured?.(recoveryKey));
        // After the initial 5s the handler is removed, while the sole writer
        // continues publication retries. It re-arms only after that writer ends.
        rearmAfter(configured);
        await Promise.race([
          configured,
          new Promise((resolve) => setTimeout(resolve, 5_000)),
        ]);
      },
      { noWaitAfter: true, times: 1 },
    );
  };
  await arm();
}

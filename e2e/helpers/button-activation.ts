import { expect, type Locator } from "@playwright/test";

// A readiness update can disable a control between Playwright's actionability
// check and pointerdown. Retry only an activation the browser never delivered.
// Once a trusted enabled click is delivered, the caller owns the outcome;
// this helper must never deliver another activation.
export async function clickEnabledButton(
  form: Locator,
  selector: string,
  options: { action: string; owner: string; timeout?: number },
): Promise<void> {
  const timeout = options.timeout ?? 30_000;
  const owner = await form.elementHandle({ timeout });
  if (!owner) throw new Error(`${options.action} requires its original ${options.owner}`);
  const observed = await owner.evaluateHandle((element, selector) => {
    const state = { activated: false, dispose: () => {} };
    const receive = (event: Event) => {
      const target = event.target instanceof Element
        ? event.target.closest(selector) : null;
      if (event.isTrusted && target instanceof HTMLButtonElement
          && element.contains(target) && !target.disabled
          && target.getAttribute("aria-disabled") !== "true" && !target.closest("[inert]")) {
        state.activated = true;
      }
    };
    element.addEventListener("click", receive, true);
    state.dispose = () => element.removeEventListener("click", receive, true);
    return state;
  }, selector);
  const deadline = Date.now() + timeout;
  try {
    while (Date.now() < deadline) {
      if (await observed.evaluate(state => state.activated)) return;
      if (!await owner.evaluate(element => element.isConnected)) {
        throw new Error(`${options.owner} retired before a trusted ${options.action} activation`);
      }
      const button = await owner.$(selector);
      if (!button) throw new Error(`original ${options.owner} has no ${options.action} control`);
      try {
        await expect.poll(() => button.isEnabled(), {
          timeout: Math.max(1, Math.min(1_000, deadline - Date.now())),
        }).toBe(true);
        await button.click({ timeout: Math.max(1, Math.min(1_000, deadline - Date.now())) });
      } catch (error) {
        if (await observed.evaluate(state => state.activated)) return;
        if (Date.now() >= deadline) throw error;
      } finally {
        await button.dispose();
      }
      if (await observed.evaluate(state => state.activated)) return;
      await form.page().waitForTimeout(Math.max(1, Math.min(100, deadline - Date.now())));
    }
    throw new Error(`${options.action} did not receive a trusted enabled activation within its original budget`);
  } finally {
    await observed.evaluate(state => state.dispose()).catch(() => {});
    await observed.dispose();
    await owner.dispose();
  }
}

import { expect, type Locator } from "@playwright/test";

// A readiness update can disable Save between Playwright's actionability
// check and pointerdown. Retry only an activation the browser never delivered.
// Once a trusted enabled click is delivered, the existing submission observer
// owns the outcome; this helper must never submit another operation.
export async function clickCardSave(form: Locator, timeout = 30_000): Promise<void> {
  const owner = await form.elementHandle({ timeout });
  if (!owner) throw new Error("card Save requires its original editor");
  const observed = await owner.evaluateHandle(element => {
    const state = { activated: false, dispose: () => {} };
    const receive = (event: Event) => {
      const target = event.target instanceof Element
        ? event.target.closest(".card-detail-save-button") : null;
      if (event.isTrusted && target instanceof HTMLButtonElement
          && element.contains(target) && !target.disabled
          && target.getAttribute("aria-disabled") !== "true" && !target.closest("[inert]")) {
        state.activated = true;
      }
    };
    element.addEventListener("click", receive, true);
    state.dispose = () => element.removeEventListener("click", receive, true);
    return state;
  });
  const deadline = Date.now() + timeout;
  try {
    while (Date.now() < deadline) {
      if (await observed.evaluate(state => state.activated)) return;
      if (!await owner.evaluate(element => element.isConnected)) {
        throw new Error("card editor retired before a trusted Save activation");
      }
      const button = await owner.$(".card-detail-save-button");
      if (!button) throw new Error("original card editor has no Save control");
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
    throw new Error("card Save did not receive a trusted enabled activation within its original budget");
  } finally {
    await observed.evaluate(state => state.dispose()).catch(() => {});
    await observed.dispose();
    await owner.dispose();
  }
}

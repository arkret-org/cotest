import type { Locator } from "@playwright/test";
import { clickEnabledButton } from "./button-activation.ts";

export async function clickCardSave(form: Locator, timeout = 30_000): Promise<void> {
  await clickEnabledButton(form, ".card-detail-save-button", {
    action: "Save", owner: "card editor", timeout,
  });
}

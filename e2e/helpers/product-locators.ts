import type { Locator, Page } from "@playwright/test";
import type { AccountId } from "./generated/spec-wire-objects";

// The product exposes the full recipient to assistive technology while its
// visible label may be a petname. Select the complete Account, including Station.
export function accountRow(scope: Page, rowClass: string, account: AccountId): Locator {
  if (!/^\.[a-zA-Z0-9_-]+$/.test(rowClass)) throw new Error("one product row class required");
  return scope.locator(rowClass).filter({
    has: scope.getByText(`Principal: ${account.principal_id} · Station: ${account.station_id}`, { exact: true }),
  });
}

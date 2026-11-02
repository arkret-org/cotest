import type { Locator, Page } from "@playwright/test";
import type { AccountId, ActorId } from "./generated/spec-wire-objects";
import { canonicalJson } from "./coland-api/wire-client";

function row(scope: Page | Locator, rowClass: string): Locator {
  if (!/^\.[a-zA-Z0-9_-]+$/.test(rowClass)) throw new Error("one product row class required");
  return scope.locator(rowClass);
}

function pageFor(scope: Page | Locator): Page {
  return "page" in scope ? scope.page() : scope;
}

// The product exposes the full recipient to assistive technology while its
// visible label may be a petname. Select the complete Account, including Station.
export function accountRow(scope: Page | Locator, rowClass: string, account: AccountId): Locator {
  return row(scope, rowClass).filter({
    has: pageFor(scope).getByText(`Principal: ${account.principal_id} · Station: ${account.station_id}`, { exact: true }),
  });
}

export function actorRow(scope: Page | Locator, rowClass: string, actor: ActorId): Locator {
  return row(scope, rowClass).filter({
    has: pageFor(scope).getByLabel(canonicalJson(actor), { exact: true }),
  });
}

export function agentMemberRow(scope: Page | Locator, account: AccountId): Locator {
  return row(scope, ".card-detail-agent-row").filter({
    has: pageFor(scope).getByText(`Agent: ${account.principal_id} · Principal: ${account.principal_id} · Station: ${account.station_id}`, { exact: true }),
  });
}

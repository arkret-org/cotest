// Account states (active / soft_logged_out / locked / suspended / deactivated)
// Contract: e2e/scenarios/identity/account-states.md
// Spec: identity/account-lifecycle.md §3

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("account states", () => {
  test("baseline active: /account/me returns state=active (or is silent on state)", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-baseline");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const meResp = await request.get(`${solandBaseUrl()}/api/v1/account/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(meResp.ok()).toBeTruthy();
    const me = await meResp.json();
    expect(me.did).toBe(alice.did);
    if ("state" in me) {
      expect(me.state).toBe("active");
    }
  });

  test.fixme(
    // @blocking-on: soland#identity-account-states-gap
    // @user-promise: e2e/scenarios/identity/account-states.md
    // @expected-live-by: 2026Q3
    "soft logout revokes access token; refresh token still works to get new access",
    async () => {
      // spec: account-lifecycle.md §3
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-account-states-gap
    // @user-promise: e2e/scenarios/identity/account-states.md
    // @expected-live-by: 2026Q3
    "admin lock: POST /admin/accounts/<did>/lock → all sessions invalidated; /account/me returns 401",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#identity-account-states-gap
    // @user-promise: e2e/scenarios/identity/account-states.md
    // @expected-live-by: 2026Q3
    "governance suspend: new token requests rejected; old in-flight tokens valid until expiry",
    async () => {
      // spec: account-lifecycle.md §3 suspend semantics
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-account-states-gap
    // @user-promise: e2e/scenarios/identity/account-states.md
    // @expected-live-by: 2026Q3
    "user-initiated deactivate: all tokens revoked; account state=deactivated; messages remain visible (deactivated ≠ erasure)",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#identity-account-states-gap
    // @user-promise: e2e/scenarios/identity/account-states.md
    // @expected-live-by: 2026Q3
    "audit: each state transition writes cx.account.state_change with from/to/actor/reason/timestamp",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#identity-account-states-gap
    // @user-promise: e2e/scenarios/identity/account-states.md
    // @expected-live-by: 2026Q3
    "E28.2 cross-server suspension: alice suspended on α; β learns of suspension via sync within reconciliation window",
    async () => {},
  );
});

// Account auth + device authorization
// Contract: e2e/scenarios/identity/account-device-auth.md
// Spec: identity/account-lifecycle.md §2-§3, key-management.md §6, device-lifecycle.md §2

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("account auth + device strand", () => {
  test("auth refresh endpoint surface probe", async ({ request }) => {
    const probe = await request.post(`${solandBaseUrl()}/_cokret/gate/auth/refresh`, {
      data: { refresh_token: "probe-token" },
    });
    // 4xx for bad token / not implemented; 5xx is a bug.
    expect(probe.status()).toBeLessThan(500);
  });

  test("expired access token returns 401 on protected endpoint", async ({ request }) => {
    const meResp = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: { authorization: `Bearer expired-or-bogus-token` },
    });
    expect([401, 403]).toContain(meResp.status());
  });

  test.fixme(
    // @blocking-on: soland#identity-account-device-auth-gap
    // @user-promise: e2e/scenarios/identity/account-device-auth.md
    // @expected-live-by: 2026Q3
    "alice registers via OIDC bridge (mock IdP); coauth issues short-term ck.session.grant + refresh_token",
    async () => {
      // spec: account-lifecycle.md §2.1, key-management.md §6
      // harness gap: mock IdP service.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-account-device-auth-gap
    // @user-promise: e2e/scenarios/identity/account-device-auth.md
    // @expected-live-by: 2026Q3
    "device-2 pairs via QR + cross-signing; coauth issues device-specific session_grant",
    async () => {
      // spec: device-lifecycle.md §2.1, §10
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-account-device-auth-gap
    // @user-promise: e2e/scenarios/identity/account-device-auth.md
    // @expected-live-by: 2026Q3
    "expired access token triggers /_cokret/gate/auth/refresh; new session_grant issued without re-OIDC",
    async () => {
      // spec: key-management.md §6 refresh path.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-account-device-auth-gap
    // @user-promise: e2e/scenarios/identity/account-device-auth.md
    // @expected-live-by: 2026Q3
    "soft logout revokes access token but keeps refresh; refresh later restores access",
    async () => {
      // spec: account-lifecycle.md §3 (soft_logged_out)
    },
  );
});

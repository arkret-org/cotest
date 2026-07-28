// Account auth + device authorization
// Contract: e2e/scenarios/identity/account-device-auth.md
// Spec: identity/account-lifecycle.md §2-§4, key-management.md §5-§6,
// crypto-media/device-lifecycle.md §2 and §5.4.

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";

test.describe.configure({ mode: "serial" });

test.describe("account auth + device strand", () => {
  test("session-grant refresh endpoint surface probe", async ({ request }) => {
    const probe = await request.post(
      `${solandBaseUrl()}/_arkret/gate/account/session-grants/refresh`,
      { data: { grant_jwt: "probe-grant", audience: "cotest" } },
    );
    expect(probe.status()).toBeLessThan(500);
  });

  test("expired session credential returns 401 on protected endpoint", async ({
    request,
  }) => {
    const meResp = await request.get(
      `${solandBaseUrl()}/_soland/self/account/me`,
      { headers: { authorization: "Bearer expired-or-bogus-token" } },
    );
    expect([401, 403]).toContain(meResp.status());
  });

});

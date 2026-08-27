// Account auth + device authorization
// Contract: e2e/scenarios/identity/account-device-auth.md
// Spec: identity/account-lifecycle.md §2-§4, key-management.md §5-§6,
// crypto-media/device-lifecycle.md §2 and §5.4.

import { expect, test } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";

test.describe.configure({ mode: "serial" });

test.describe("account auth + device strand", () => {
  test("legacy open refresh body is rejected", async ({ request }) => {
    const probe = await request.post(
      `${solandBaseUrl()}/_arkret/gate/account/session-grants/refresh`,
      { data: { grant_jwt: "probe-grant", audience: "cotest" } },
    );
    expect([400, 401, 403, 422]).toContain(probe.status());
  });

  test("Bearer session credential is rejected on protected endpoint", async ({
    request,
  }) => {
    const meResp = await request.get(
      `${solandBaseUrl()}/_soland/self/account/me`,
      { headers: { authorization: "Bearer expired-or-bogus-token" } },
    );
    expect([401, 403]).toContain(meResp.status());
  });

});

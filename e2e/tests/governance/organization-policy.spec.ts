// Organization directory + moderation policy inheritance
// Contract: e2e/scenarios/governance/organization-policy.md
// Spec: governance/content-moderation.md §7, identity/identity-did.md §6, models/governance-objects.md §3

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("organization policy inheritance", () => {
  test("organization policy endpoint surface probe", async ({ request }) => {
    const alice = uniqueUser("s30-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const probe = await request.get(`${solandBaseUrl()}/api/v1/organizations`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect([200, 401, 403, 404]).toContain(probe.status());
    expect(probe.status()).toBeLessThan(500);
  });

  test.fixme(
    // @blocking-on: soland#governance-organization-policy-gap
    // @user-promise: e2e/scenarios/governance/organization-policy.md
    // @expected-live-by: 2026Q3
    "acme-org publishes cx.organization.moderation_policy with deny_join targets; spaces under acme inherit the policy automatically",
    async () => {
      // spec: content-moderation.md §7
    },
  );

  test.fixme(
    // @blocking-on: soland#governance-organization-policy-gap
    // @user-promise: e2e/scenarios/governance/organization-policy.md
    // @expected-live-by: 2026Q3
    "mallory's join attempt on an Acme space is rejected with organization_policy_denied; space-level override requires organization approval",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#governance-organization-policy-gap
    // @user-promise: e2e/scenarios/governance/organization-policy.md
    // @expected-live-by: 2026Q3
    "policy update at organization level fans out to all member spaces without per-space rewrites",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#governance-organization-policy-gap
    // @user-promise: e2e/scenarios/governance/organization-policy.md
    // @expected-live-by: 2026Q3
    "tab-organizations search returns acme-org with member count and verified badge",
    async () => {
      // spec: discovery-directory.md §2
    },
  );

  test.fixme(
    // @blocking-on: soland#governance-organization-policy-gap
    // @user-promise: e2e/scenarios/governance/organization-policy.md
    // @expected-live-by: 2026Q3
    "E30.1 cross-org space joining most-restrictive of the two organizations' policies",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#governance-organization-policy-gap
    // @user-promise: e2e/scenarios/governance/organization-policy.md
    // @expected-live-by: 2026Q3
    "appeal flow: mallory submits appeal via policy.appeal.endpoint; moderator reviews; possible override",
    async () => {},
  );
});

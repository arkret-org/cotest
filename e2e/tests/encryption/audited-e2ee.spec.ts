// Audited E2EE (franking + moderator decryption attestation)
// Contract: e2e/scenarios/encryption/audited-e2ee.md
// Spec: crypto-media/audited-e2ee.md §2-§4, encryption-and-audit.md §3, governance/content-moderation.md §3.4

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("audited E2EE", () => {
  test("audit events endpoint surface probe", async ({ request }) => {
    const alice = uniqueUser("s25-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const probe = await request.get(
      `${solandBaseUrl()}/api/v1/audit/events?space_id=cx:space:probe`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect([200, 401, 403, 404]).toContain(probe.status());
    expect(probe.status()).toBeLessThan(500);
  });

  test.fixme(
    // @blocking-on: soland#encryption-audited-e2ee-gap
    // @user-promise: e2e/scenarios/encryption/audited-e2ee.md
    // @expected-live-by: 2026Q3
    "alice configures audit_disclosure_policy on E2EE space; cx.moderation.franking_proof generated for each encrypted message (ciphertext_digest only, no plaintext)",
    async () => {
      // spec: audited-e2ee.md §4, encryption-and-audit.md §3
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-audited-e2ee-gap
    // @user-promise: e2e/scenarios/encryption/audited-e2ee.md
    // @expected-live-by: 2026Q3
    "report on a message triggers audit_disclosure_policy.trigger; audit-agent is invited to access via attested ceremony",
    async () => {
      // spec: audited-e2ee.md §3 + governance/content-moderation.md §3.4
      // harness gap: mock audit-agent service.
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-audited-e2ee-gap
    // @user-promise: e2e/scenarios/encryption/audited-e2ee.md
    // @expected-live-by: 2026Q3
    "audit-agent's access writes cx.audit.accessed entry; alice in space-admin/audit sees the access record",
    async () => {
      // spec: audited-e2ee.md §4
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-audited-e2ee-gap
    // @user-promise: e2e/scenarios/encryption/audited-e2ee.md
    // @expected-live-by: 2026Q3
    "E25.1 tampered cx.moderation.franking_proof ciphertext_digest causes downstream verification to fail",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#encryption-audited-e2ee-gap
    // @user-promise: e2e/scenarios/encryption/audited-e2ee.md
    // @expected-live-by: 2026Q3
    "E25.3 alice revokes audit_disclosure_policy; subsequent audit-agent requests are rejected (still leaving historical accessed records intact)",
    async () => {},
  );
});

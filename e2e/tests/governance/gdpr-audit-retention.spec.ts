// GDPR export / erasure / audit / retention
// Contract: e2e/scenarios/governance/gdpr-audit-retention.md
// Spec: identity/account-lifecycle.md §3, §8, models/space-and-place.md §2.2 (retention)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("GDPR / audit / retention", () => {
  test("export and erase endpoints surface probe", async ({ request }) => {
    const alice = uniqueUser("s27-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const exportProbe = await request.post(`${solandBaseUrl()}/api/v1/account/export`, {
      headers: { authorization: `Bearer ${token}` },
      data: {},
    });
    expect(exportProbe.status()).toBeLessThan(500);

    const eraseProbe = await request.post(`${solandBaseUrl()}/api/v1/account/erase`, {
      headers: { authorization: `Bearer ${token}` },
      data: {},
    });
    expect(eraseProbe.status()).toBeLessThan(500);
  });

  test.fixme(
    "GDPR export returns a JSON bundle containing account/profile/spaces/messages/devices/audit_log; alice's own messages are plaintext, others' E2EE ciphertext-only",
    async () => {
      // spec: account-lifecycle.md §8
    },
  );

  test.fixme(
    "alice erases account → state=erasure_pending → background tasks pseudonymize PII, revoke devices, tombstone messages; subsequent /account/me returns 401",
    async () => {
      // spec: account-lifecycle.md §3
    },
  );

  test.fixme(
    "after erasure, bob's view shows alice's messages as [user erased] tombstone; directory search no longer finds alice",
    async () => {},
  );

  test.fixme(
    "audit log contains cx.audit.exported, cx.audit.erasure_initiated, cx.audit.erasure_completed entries",
    async () => {},
  );

  test.fixme(
    "retention_policy.ttl: events older than the TTL are tombstoned (not physically deleted if anchored)",
    async () => {
      // spec: space-and-place.md §2.2
    },
  );

  test.fixme(
    "E27.3 cross-server erasure fan-out: alice's DID erased on α; β tombstones her events too within reconciliation window",
    async () => {},
  );
});

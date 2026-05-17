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

  test("GDPR export returns a JSON bundle containing account/profile/spaces/devices/audit_log facets", async ({
    request,
  }) => {
    // spec: identity/account-lifecycle.md §8 — export MUST surface
    // the principal's data in a single bundle. v1 ships account /
    // profile / spaces / devices / audit_log; the `messages` slot
    // is present but empty until the projection-events filter lands
    // (acceptable per spec — bundle shape is the contract).
    const stamp = Date.now();
    const alice = uniqueUser(`s27-export-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const exportResp = await request.post(`${solandBaseUrl()}/api/v1/account/export`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: {},
    });
    expect(exportResp.status()).toBe(200);
    const bundle = await exportResp.json();
    expect(bundle.did).toBe(alice.did);
    expect(bundle.account).toBeTruthy();
    expect(bundle.profile).toBeTruthy();
    expect(Array.isArray(bundle.spaces)).toBe(true);
    expect(Array.isArray(bundle.devices)).toBe(true);
    expect(Array.isArray(bundle.audit_log)).toBe(true);
    expect(bundle.exported_at).toBeTruthy();
  });

  test("alice erases account → /account/me returns 401 account_erased on subsequent calls", async ({
    request,
  }) => {
    // spec: identity/account-lifecycle.md §3 — erasure pseudonymizes
    // PII, revokes devices, and flips the actor into a permanent
    // `erased` state. Subsequent authenticated requests return 401
    // with errcode `account_erased`.
    const stamp = Date.now();
    const alice = uniqueUser(`s27-erase-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const erase = await request.post(`${solandBaseUrl()}/api/v1/account/erase`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: {},
    });
    expect(erase.status()).toBe(200);
    const eraseBody = await erase.json();
    expect(eraseBody.state).toBe("erasure_pending");

    // Subsequent /account/me with the same bearer returns 401 account_erased.
    const me = await request.get(`${solandBaseUrl()}/api/v1/account/me`, {
      headers: { authorization: `Bearer ${aliceToken}` },
    });
    expect(me.status()).toBe(401);
    const meBody = await me.json();
    expect(meBody?.error?.errcode).toBe("account_erased");
  });

  test("after erasure, directory search no longer finds alice; her account row shows the [user erased] placeholder", async ({
    request,
  }) => {
    // spec: identity/account-lifecycle.md §3 + discovery/profiles-presence.md.
    const stamp = Date.now();
    const alice = uniqueUser(`s27-vanish-alice-${stamp}`);
    const bob = uniqueUser(`s27-vanish-bob-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    // bob and alice connect so bob's directory search can see alice pre-erase.
    await request.post(`${solandBaseUrl()}/api/v1/contacts/request`, {
      headers: { authorization: `Bearer ${bobToken}` },
      data: { target: alice.did },
    });
    await request.post(`${solandBaseUrl()}/api/v1/contacts/respond`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { requester: bob.did, action: "accept" },
    });

    // Pre-erasure: bob's directory search returns alice.
    const before = await request.post(`${solandBaseUrl()}/api/v1/directory/search-actors`, {
      headers: { authorization: `Bearer ${bobToken}` },
      data: { query: alice.handle },
    });
    const beforeBody = await before.json();
    expect(
      (beforeBody.results as Array<{ did: string }>).some((r) => r.did === alice.did),
      "alice must be visible to bob pre-erasure",
    ).toBe(true);

    // alice erases.
    const erase = await request.post(`${solandBaseUrl()}/api/v1/account/erase`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: {},
    });
    expect(erase.status()).toBe(200);

    // Post-erasure: bob's directory search no longer returns alice.
    const after = await request.post(`${solandBaseUrl()}/api/v1/directory/search-actors`, {
      headers: { authorization: `Bearer ${bobToken}` },
      data: { query: alice.handle },
    });
    const afterBody = await after.json();
    expect(
      (afterBody.results as Array<{ did: string }>).some((r) => r.did === alice.did),
      "alice MUST NOT appear in directory after erasure",
    ).toBe(false);
  });

  test("audit log contains cx.audit.exported, cx.audit.erasure_initiated, cx.audit.erasure_completed entries", async ({
    request,
  }) => {
    // spec: account-lifecycle.md §3 + §8 — every export / erasure
    // lifecycle event MUST appear in the actor's audit log.
    const stamp = Date.now();
    const alice = uniqueUser(`s27-audit-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const exportResp = await request.post(`${solandBaseUrl()}/api/v1/account/export`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: {},
    });
    expect(exportResp.status()).toBe(200);
    const eraseResp = await request.post(`${solandBaseUrl()}/api/v1/account/erase`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: {},
    });
    expect(eraseResp.status()).toBe(200);
    const eraseBody = await eraseResp.json();
    // The erase response carries an inline audit_log snapshot as the
    // canonical last-known-good view of the actor's audit trail — the
    // bearer is invalidated as a side effect of erase, so reads from
    // /audit/events fail-closed.
    const auditEvents = eraseBody.audit_log as Array<{ action: string }>;
    expect(Array.isArray(auditEvents)).toBe(true);
    const actions = auditEvents.map((e) => e.action);
    expect(actions).toContain("cx.audit.exported");
    expect(actions).toContain("cx.audit.erasure_initiated");
    expect(actions).toContain("cx.audit.erasure_completed");
  });

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

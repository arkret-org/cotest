// GDPR export / erasure / audit / retention
// Contract: e2e/scenarios/governance/gdpr-audit-retention.md
// Spec: identity/account-lifecycle.md §3, §8, models/realm-and-space.md §2.2 (retention)

import { expect, test } from "@playwright/test";
import {
  hasDualSoland,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import {
  acceptInviteApi,
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  listInvitesApi,
  queryPeerEventsApi,
  queryRealmEventsApi,
  sendMessageApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import {
  requestContactArkret,
  respondContactArkret,
} from "../../helpers/contact-api";

test.describe.configure({ mode: "serial" });

test.describe("GDPR / audit / retention", () => {
  test("removed export/erase rails stay 404; the §8.1 erasure-request intake resolves fail-closed", async ({ request }) => {
    const alice = uniqueUser("s27-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    // The incomplete product-private export rail and the product-private erase
    // rail were intentionally removed — no compatibility shim, so both must
    // stay 404.
    const exportProbe = await request.get(`${solandBaseUrl()}/_soland/self/account/export`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(exportProbe.status()).toBe(404);

    const eraseProbe = await request.post(`${solandBaseUrl()}/_soland/self/account/erase`, {
      headers: { authorization: `Bearer ${token}` },
      data: {},
    });
    expect(eraseProbe.status()).toBe(404);

    // The current self-erasure surface is the spec entry point
    // (account-lifecycle.md §8.1 ak.self.account.command.request_erasure). It
    // records the intent durably and is fail-closed on fresh high-risk
    // authentication, so a bare probe is refused — but the route MUST resolve.
    const erasureRequestProbe = await request.post(
      `${solandBaseUrl()}/_arkret/self/account/erasure-requests`,
      {
        headers: { authorization: `Bearer ${token}` },
        data: {},
      },
    );
    expect(erasureRequestProbe.status()).not.toBe(404);
    expect(erasureRequestProbe.status()).toBeLessThan(500);
  });

  test("GDPR export returns a JSON bundle containing account/profile/realms/devices/audit_log facets", async ({
    request,
  }) => {
    test.skip(
      true,
      "the incomplete product-private account export rail was intentionally removed; restore this coverage with the complete data-portability workflow",
    );
    // spec: identity/account-lifecycle.md §8 — export MUST surface
    // the principal's data in a single bundle. v1 ships account /
    // profile / realms / devices / audit_log; the `messages` slot
    // is present but empty until the projection-events filter lands
    // (acceptable per spec — bundle shape is the contract).
    const stamp = Date.now();
    const alice = uniqueUser(`s27-export-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const exportResp = await request.get(`${solandBaseUrl()}/_soland/self/account/export`, {
      headers: { authorization: `Bearer ${aliceToken}` },
    });
    expect(exportResp.status()).toBe(200);
    const bundle = await exportResp.json();
    expect(bundle.did).toBe(alice.did);
    expect(bundle.account).toBeTruthy();
    expect(bundle.profile).toBeTruthy();
    expect(Array.isArray(bundle.realms)).toBe(true);
    expect(Array.isArray(bundle.devices)).toBe(true);
    expect(Array.isArray(bundle.audit_log)).toBe(true);
    expect(bundle.exported_at).toBeTruthy();
  });

  test("alice erases account → /account/me returns 401 account_erased on subsequent calls", async ({
    request,
  }) => {
    test.skip(
      true,
      "the product-private /_soland/self/account/erase rail was intentionally removed; the spec entry point " +
        "(account-lifecycle.md §8.1 ak.self.account.command.request_erasure, soland intake at " +
        "/_arkret/self/account/erasure-requests) only records the intent durably — blocked on the " +
        "Account Authority issuance channel (spec-open 2026-08-18-2325) and authentication freshness " +
        "(spec-open 2026-08-18-2326)",
    );
    // spec: identity/account-lifecycle.md §3 — erasure pseudonymizes
    // PII, revokes devices, and flips the actor into a permanent
    // `erasure_pending` state. Subsequent authenticated requests return 401
    // with errcode `account_erased`.
    const stamp = Date.now();
    const alice = uniqueUser(`s27-erase-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const erase = await request.post(`${solandBaseUrl()}/_soland/self/account/erase`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: {},
    });
    expect(erase.status()).toBe(200);
    const eraseBody = await erase.json();
    expect(eraseBody.state).toBe("erasure_pending");
    expect(eraseBody.erasure_receipt?.schema).toBe("ak.schema.erasure_receipt.v1");
    expect(eraseBody.erasure_receipt?.outcome).toBe("completed");

    // Subsequent /account/me with the same bearer returns 401 account_erased.
    const me = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: { authorization: `Bearer ${aliceToken}` },
    });
    expect(me.status()).toBe(401);
    const meBody = await me.json();
    expect(wireErrCode(meBody)).toBe("account_erased");
  });

  test("after erasure, directory search no longer finds alice; her account row shows the [user erased] placeholder", async ({
    request,
  }) => {
    test.skip(
      true,
      "the product-private /_soland/self/account/erase rail was intentionally removed; the spec entry point " +
        "(account-lifecycle.md §8.1 ak.self.account.command.request_erasure, soland intake at " +
        "/_arkret/self/account/erasure-requests) only records the intent durably — blocked on the " +
        "Account Authority issuance channel (spec-open 2026-08-18-2325) and authentication freshness " +
        "(spec-open 2026-08-18-2326)",
    );
    // spec: identity/account-lifecycle.md §3 + discovery/profiles-presence.md.
    const stamp = Date.now();
    const alice = uniqueUser(`s27-vanish-alice-${stamp}`);
    const bob = uniqueUser(`s27-vanish-bob-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    // bob and alice connect so bob's directory search can see alice pre-erase.
    const { outcome } = await requestContactArkret(request, bobToken, alice.did, {
      requestedScopes: ["direct_message"],
    });
    await respondContactArkret(request, aliceToken, {
      requestId: outcome.request_event_ref,
      requester: bob.did,
      action: "accept",
      grantedScopes: ["direct_message"],
    });

    // Pre-erasure: bob's directory search returns alice.
    const before = await request.post(`${solandBaseUrl()}/_arkret/find/directory/search-actors`, {
      headers: { authorization: `Bearer ${bobToken}` },
      data: { query: alice.did },
    });
    const beforeBody = await before.json();
    expect(
      (
        beforeBody.actors as Array<{ actor_id?: string; preview?: { did?: string } }>
      ).some((r) => r.actor_id === alice.did || r.preview?.did === alice.did),
      "alice must be visible to bob pre-erasure",
    ).toBe(true);

    // alice erases.
    const erase = await request.post(`${solandBaseUrl()}/_soland/self/account/erase`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: {},
    });
    expect(erase.status()).toBe(200);

    // Post-erasure: bob's directory search no longer returns alice.
    const after = await request.post(`${solandBaseUrl()}/_arkret/find/directory/search-actors`, {
      headers: { authorization: `Bearer ${bobToken}` },
      data: { query: alice.did },
    });
    const afterBody = await after.json();
    expect(
      (
        afterBody.actors as Array<{ actor_id?: string; preview?: { did?: string } }>
      ).some((r) => r.actor_id === alice.did || r.preview?.did === alice.did),
      "alice MUST NOT appear in directory after erasure",
    ).toBe(false);
  });

  test("audit log contains org.arkret.soland.audit.erasure_initiated and ak.audit.erasure_receipt entries", async ({
    request,
  }) => {
    test.skip(
      true,
      "the product-private /_soland/self/account/erase rail was intentionally removed; the spec entry point " +
        "(account-lifecycle.md §8.1 ak.self.account.command.request_erasure, soland intake at " +
        "/_arkret/self/account/erasure-requests) only records the intent durably — blocked on the " +
        "Account Authority issuance channel (spec-open 2026-08-18-2325) and authentication freshness " +
        "(spec-open 2026-08-18-2326)",
    );
    // spec: account-lifecycle.md §3 — every erasure lifecycle event MUST
    // appear in the actor's audit log. Account export coverage is separately
    // skipped until the complete data-portability workflow replaces the
    // intentionally removed incomplete product-private endpoint.
    const stamp = Date.now();
    const alice = uniqueUser(`s27-audit-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const eraseResp = await request.post(`${solandBaseUrl()}/_soland/self/account/erase`, {
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
    expect(actions).toContain("org.arkret.soland.audit.erasure_initiated");
    expect(actions).toContain("ak.audit.erasure_receipt");
    const receiptEvent = auditEvents.find((e) => e.action === "ak.audit.erasure_receipt") as
      | { payload?: { schema?: string; outcome?: string; proofs?: unknown[] } }
      | undefined;
    expect(receiptEvent?.payload?.schema).toBe("ak.schema.erasure_receipt.v1");
    expect(receiptEvent?.payload?.outcome).toBe("completed");
    expect(Array.isArray(receiptEvent?.payload?.proofs)).toBe(true);
  });

  test("retention_policy.ttl: events older than the TTL are tombstoned (not physically deleted if anchored)", async ({
    request,
  }) => {
    // spec: realm-and-space.md §2.2 — expired timeline content is redacted
    // while event_id / canonical history remain available for anchored chains.
    const stamp = Date.now();
    const alice = uniqueUser(`s27-retention-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S27 retention ${stamp}`,
      discoverability: "listed",
      history_visibility: "shared",
      ownerDid: alice.did,
    });
    // `realm.schema.json` is closed and declares only `retention_policy_id`
    // (a reference to a policy object) — never an inline `retention_policy`.
    // The deployment-local TTL is configured through the same admin surface the
    // sweep below uses, which is where soland actually stores it.
    const configured = await request.post(
      `${solandBaseUrl()}/_soland/admin/retention/policy`,
      {
        headers: authHeaders(aliceToken),
        data: { realm_id: realmId, ttl: "30d" },
      },
    );
    expect(configured.status()).toBe(200);
    const oldBody = `retention ttl should expire ${stamp}`;
    const oldCreatedAt = canonicalTimestamp(
      new Date(Date.now() - 31 * 24 * 60 * 60 * 1000),
    );
    const sent = await sendMessageApi(
      request,
      aliceToken,
      realmId,
      oldBody,
      { createdAt: oldCreatedAt },
    );

    const before = await queryRealmEventsApi(request, aliceToken, realmId);
    expect(JSON.stringify(before)).toContain(oldBody);

    const sweep = await request.post(
      `${solandBaseUrl()}/_soland/admin/retention/sweep`,
      {
        headers: authHeaders(aliceToken),
        data: { realm_id: realmId },
      },
    );
    expect(sweep.status()).toBe(200);
    const sweepBody = await sweep.json();
    expect(sweepBody.physical_delete_count).toBe(0);
    const tombstone = (
      sweepBody.tombstoned as Array<{
        event_id?: string;
        sealed?: boolean;
        physical_delete?: boolean;
      }>
    ).find((row) => row.event_id === sent.event_id);
    expect(tombstone).toBeTruthy();
    expect(tombstone?.sealed).toBe(true);
    expect(tombstone?.physical_delete).toBe(false);

    const after = await queryRealmEventsApi(request, aliceToken, realmId);
    const events = after.events as Array<{
      event_id?: string;
      payload?: Record<string, unknown>;
    }>;
    const retained = events.find((event) => event.event_id === sent.event_id);
    expect(retained, "expired event_id must remain in the timeline").toBeTruthy();
    const retainedJson = JSON.stringify(retained);
    expect(retainedJson).toContain("[expired]");
    expect(retainedJson).toContain("retention_policy.ttl");
    expect(retainedJson).not.toContain(oldBody);

    const direct = await request.get(
      `${solandBaseUrl()}/_arkret/self/events/${encodeURIComponent(sent.event_id)}`,
      { headers: authHeaders(aliceToken) },
    );
    expect(direct.status()).toBe(200);
    const directJson = JSON.stringify(await direct.json());
    expect(directJson).toContain("[expired]");
    expect(directJson).not.toContain(oldBody);
  });

  test(
    "E27.3 cross-server erasure fan-out: alice's DID erased on α; β tombstones her events too within reconciliation window",
    async ({ request }) => {
      // spec: identity/account-lifecycle.md §8 + federation reconciliation:
      // erasure receipt MUST fan out to remote servers that hold actor events.
      test.skip(
        true,
        "the product-private /_soland/self/account/erase rail was intentionally removed; the spec entry point " +
          "(account-lifecycle.md §8.1 ak.self.account.command.request_erasure, soland intake at " +
          "/_arkret/self/account/erasure-requests) only records the intent durably — blocked on the " +
          "Account Authority issuance channel (spec-open 2026-08-18-2325) and authentication freshness " +
          "(spec-open 2026-08-18-2326)",
      );
      test.skip(!hasDualSoland(), "requires DualSoland runner topology");

      const stamp = Date.now();
      const alice = uniqueUser(`s27-fanout-alice-${stamp}`, "alpha");
      const bob = uniqueUser(`s27-fanout-bob-${stamp}`, "beta");
      await ensureRegistered(request, alice, { server: "alpha" });
      await ensureRegistered(request, bob, { server: "beta" });
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice, { server: "alpha" }),
        issueDevSession(request, bob, { server: "beta" }),
      ]);

      const realmId = await createRealmApi(
        request,
        aliceToken,
        {
          title: `S27 fanout ${stamp}`,
          discoverability: "listed",
          history_visibility: "shared",
          invitees: [bob.did],
          invitee_service_ids: { [bob.did]: solandServiceId("beta") },
          ownerDid: alice.did,
          creator_service_id: solandServiceId("alpha"),
          plaintext_visible_services: [
            solandServiceId("alpha"),
            solandServiceId("beta"),
          ],
        },
        { server: "alpha" },
      );

      let betaInvite:
        | { id: string; realm_id: string; invitee?: string }
        | undefined;
      await expect
        .poll(
          async () => {
            const invites = await listInvitesApi(request, bobToken, {
              server: "beta",
            });
            betaInvite = invites.find(
              (invite) =>
                invite.invitee === bob.did &&
                invite.realm_id === realmId,
            );
            return Boolean(betaInvite);
          },
          { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBeTruthy();
      await acceptInviteApi(
        request,
        bobToken,
        bob.did,
        betaInvite!.realm_id,
        betaInvite!.id,
        { server: "beta" },
      );

      const aliceBody = `alice erasable cross-server body ${stamp}`;
      await sendMessageApi(request, aliceToken, realmId, aliceBody, {
        server: "alpha",
      });
      await expect
        .poll(
          async () => {
            const body = await queryRealmEventsApi(request, bobToken, realmId, {
              server: "beta",
              limit: 100,
            });
            return JSON.stringify(body);
          },
          { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toContain(aliceBody);

      const remoteBefore = await queryPeerEventsApi(request, {
        server: "beta",
        actorDid: alice.did,
        sourceDid: solandServiceId("alpha"),
        limit: 100,
      });
      const beforeJson = JSON.stringify(remoteBefore);
      expect(beforeJson).toContain(alice.did);
      expect(beforeJson).toContain(aliceBody);

      const erase = await request.post(`${solandBaseUrl("alpha")}/_soland/self/account/erase`, {
        headers: { authorization: `Bearer ${aliceToken}` },
        data: {},
      });
      expect(erase.status()).toBe(200);
      const eraseBody = await erase.json();
      expect(eraseBody.erasure_receipt?.schema).toBe("ak.schema.erasure_receipt.v1");

      await expect
        .poll(
          async () => {
            const remoteAfter = await queryPeerEventsApi(request, {
              server: "beta",
              actorDid: alice.did,
              sourceDid: solandServiceId("alpha"),
              limit: 100,
            });
            return JSON.stringify(remoteAfter);
          },
          { timeout: 60_000 },
        )
        .toContain("[user erased]");

      const betaTimelineAfter = await queryRealmEventsApi(
        request,
        bobToken,
        realmId,
        {
          server: "beta",
          limit: 100,
        },
      );
      const betaTimelineAfterJson = JSON.stringify(betaTimelineAfter);
      expect(betaTimelineAfterJson).toContain("[user erased]");
      expect(betaTimelineAfterJson).not.toContain(aliceBody);
    },
  );
});

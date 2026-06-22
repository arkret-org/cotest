// Pluggable policy decision service (realm-level external policy_server)
// Contract: e2e/scenarios/authz/policy-server-check.md
// Spec: authz/policy-server.md §2 (ck.realm.policy_server Move),
//        §3 (POST /_cokret/self/policy/check request/response contract),
//        §4 (obligations + fail-closed default).
// Depends on: mock-policy-server.mjs reachable via process.env.MOCK_POLICY_SERVER_PORT
//             (delivered by a parallel task; this spec assumes it's already running).

import { expect, test } from "@playwright/test";
import {
  mockPolicyServerBaseUrl as configuredMockPolicyServerBaseUrl,
  mockPolicyServerDid,
  solandBaseUrl,
} from "../../helpers/env";
import {
  authHeaders,
  createRealmApi,
  expectJsonOk,
} from "../../helpers/soland-api";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

function mockPolicyServerBaseUrl(): string {
  const configured = configuredMockPolicyServerBaseUrl();
  if (configured) {
    return configured;
  }
  const port = process.env.MOCK_POLICY_SERVER_PORT;
  if (port) {
    return `http://127.0.0.1:${port}`;
  }
  // The PUT/GET projection smoke does not call the upstream service; using
  // loopback keeps the contract runnable in single-server profiles where the
  // mock policy service is not provisioned.
  return "http://127.0.0.1:9";
}

test.describe("policy server check", () => {
  test("policy server config API projects ck.realm.policy_server and authz stays fail-closed without a grant", async ({
    request,
  }) => {
    const stamp = Date.now();
    const describeResp = await request.get(`${solandBaseUrl()}/_cokret/describe`);
    const describe = await expectJsonOk<Record<string, unknown>>(
      describeResp,
      "server describe authz self surface",
    );
    expect(describe.supported_operations).toEqual(
      expect.arrayContaining([
        "ck.self.authz.query.check",
        "ck.self.authz.grants.query.effective",
        "ck.self.authz.invites.query.list",
        "ck.self.policy.query.check",
      ]),
    );
    const limits = describe.limits as Record<string, unknown>;
    const authzPolicy = limits.authz_policy as Record<string, unknown>;
    expect(authzPolicy.self_surface_status).toBe("standard_self_supported");
    const authzCheck = authzPolicy.authz_check as Record<string, unknown>;
    expect(authzCheck.path).toBe("/_cokret/self/authz/check");
    expect(authzCheck.operation_specific_error_codes).toEqual(
      expect.arrayContaining(["policy_unavailable"]),
    );
    expect(authzCheck.usable_as_event_auth_context).toBe(false);
    const effectiveGrants = authzPolicy.effective_grants as Record<string, unknown>;
    expect(effectiveGrants.path).toBe("/_cokret/self/authz/effective-grants");
    const invites = authzPolicy.invites as Record<string, unknown>;
    expect(invites.path).toBe("/_cokret/self/authz/invites");
    expect(invites.response_schema_ref).toBe(
      "schemas/authz-operations.schema.json#/$defs/authz_invite_list",
    );

    const alice = uniqueUser(`s30-policy-config-alice-${stamp}`);
    const bob = uniqueUser(`s30-policy-config-bob-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S30 policy config ${stamp}`,
      discoverability: "listed",
      history_visibility: "shared",
      public: true,
    });
    const policyServerDid = mockPolicyServerDid() ?? "did:web:policy.example.com";
    const policyServerUrl = `${mockPolicyServerBaseUrl()}/_cokret/self/policy/check`;

    const put = await request.put(
      `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/policy-server`,
      {
        headers: authHeaders(aliceToken),
        data: {
          policy_server_did: policyServerDid,
          policy_server_url: policyServerUrl,
          cache_ttl_seconds: 5,
          timeout_ms: 1500,
          on_timeout: "fail_closed",
        },
      },
    );
    const projected = await expectJsonOk<Record<string, unknown>>(
      put,
      "put realm policy server",
    );
    expect(projected.realm_id).toBe(realmId);
    expect(projected.policy_server_did).toBe(policyServerDid);
    expect(projected.policy_server_url).toBe(policyServerUrl);
    expect(projected.from_org_fallback).toBe(false);

    const get = await request.get(
      `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/policy-server`,
      { headers: authHeaders(aliceToken) },
    );
    const fetched = await expectJsonOk<Record<string, unknown>>(
      get,
      "get realm policy server",
    );
    expect(fetched.policy_server_did).toBe(policyServerDid);
    expect(fetched.policy_server_url).toBe(policyServerUrl);

    const denied = await request.post(`${solandBaseUrl()}/_cokret/self/authz/check`, {
      headers: authHeaders(aliceToken),
      data: {
        actor_id: bob.did,
        action: "ck.message.create",
        resource: {
          kind: "realm",
          id: realmId,
          realm_id: realmId,
        },
      },
    });
    const decision = await expectJsonOk<{
      decision: string;
      reason_code?: string;
    }>(
      denied,
      "authz check without grant",
    );
    expect(decision.decision).toBe("hard_deny");
    expect(decision.reason_code).toBeTruthy();
  });

  test.fixme(
    // @blocking-on: soland#authz-policy-server-check-gap
    // @user-promise: e2e/scenarios/authz/policy-server-check.md
    // @expected-live-by: 2026Q3
    "alice configures policy server; invite triggers /policy/check with allow→deny→obligation lifecycle",
    async ({ browser, request }, testInfo) => {
      // Mirrors scenarios/authz/policy-server-check.md Phases A→E.
      // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
      const stamp = Date.now();
      const alice = uniqueUser(`s30-policy-alice-${stamp}`);
      const bob = uniqueUser(`s30-policy-bob-${stamp}`);
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, bob),
      ]);
      const aliceToken = await issueDevSession(request, alice);
      const bobToken = await issueDevSession(request, bob);
      const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });
      // bob's token is provisioned so the harness can later observe bob-side
      // effects of the deny (e.g. the invite never landing in bob's inbox).
      void bobToken;

      try {
        const realmId = await alicePage.createRealm({
          title: `S30 policy ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });
        // Phase A — Realm declares policy server endpoint.
        // soland gap: runtime invite integration not implemented; coauth /policy/check v2 missing
        const realmResp = await request.put(
          `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/policy-server`,
          {
            headers: authHeaders(aliceToken),
            data: {
              policy_server_did: mockPolicyServerDid() ?? "did:web:policy.example.com",
              policy_server_url: `${mockPolicyServerBaseUrl()}/_cokret/self/policy/check`,
              cache_ttl_seconds: 5,
              timeout_ms: 1500,
              on_timeout: "fail_closed",
            },
          },
        );
        expect(realmResp.status()).toBe(200);

        // Phase B — mock default allow → invite succeeds.
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        const allowScenario = await request.post(
          `${mockPolicyServerBaseUrl()}/scenarios`,
          { data: { default: { decision: "allow" } } },
        );
        expect(allowScenario.status()).toBe(200);
        await alicePage.gotoRealmAdmin(realmId);
        // (drive invite-member → send-invite-button against alicePage; assert
        // realm-admin-panel status contains "invited" + bob.did)
        await stepShot(alicePage.page, testInfo, "policy-allow-invite");

        // Phase C — flip mock to deny → invite rejected with reason.
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        const denyScenario = await request.post(
          `${mockPolicyServerBaseUrl()}/scenarios`,
          {
            data: {
              match: { action: "ck.invite.create", target: bob.did },
              decision: "deny",
              reason: "external_policy_blocks_user",
            },
          },
        );
        expect(denyScenario.status()).toBe(200);
        // (re-drive invite, assert HTTP 412 + errcode "policy_denied" +
        // invite-error testid renders "external_policy_blocks_user")

        // Phase D — deny + obligation `log_event` → audit log written.
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        const obligationScenario = await request.post(
          `${mockPolicyServerBaseUrl()}/scenarios`,
          {
            data: {
              match: { action: "ck.invite.create" },
              decision: "deny",
              reason: "external_policy_blocks_user",
              obligations: [
                {
                  kind: "log_event",
                  target: "audit_log",
                  fields: { category: "policy_block", severity: "info" },
                },
              ],
            },
          },
        );
        expect(obligationScenario.status()).toBe(200);
        // (re-drive invite, then GET /_soland/self/audit/events?actor=alice.did
        //  &action=policy.deny and assert >=1 entry with
        //  target.category="policy_block" + target.upstream_reason="external_policy_blocks_user")

        // Phase E — signed_transcript covers all checks; ed25519 verifies.
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        const inspect = await request.get(`${mockPolicyServerBaseUrl()}/inspect`);
        expect(inspect.status()).toBe(200);
        const body = await inspect.json();
        expect(Array.isArray(body.checks)).toBe(true);
        expect(body.signed_transcript).toBeTruthy();
        // (verify ed25519 signature via mock's public key; assert each entry has
        //  request_id, action, actor_id, decision, occurred_at)
      } finally {
        await alicePage.close();
      }
    },
  );

  test.fixme(
    // @blocking-on: soland#authz-policy-server-check-gap
    // @user-promise: e2e/scenarios/authz/policy-server-check.md
    // @expected-live-by: 2026Q3
    "E3.1 policy server timeout → soland fail-closed (deny with reason policy_timeout)",
    async ({ browser, request }) => {
      // spec: authz/policy-server.md §4 — fail_mode=closed default behavior.
      // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
      const stamp = Date.now();
      const alice = uniqueUser(`s30-timeout-alice-${stamp}`);
      const bob = uniqueUser(`s30-timeout-bob-${stamp}`);
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, bob),
      ]);
      const aliceToken = await issueDevSession(request, alice);
      const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });

      try {
        await request.post(`${mockPolicyServerBaseUrl()}/scenarios`, {
          data: { default: { decision: "allow", delay_ms: 9000 } },
        });

        const realmId = await alicePage.createRealm({
          title: `S30 timeout ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });
        await request.put(
          `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/policy-server`,
          {
            headers: authHeaders(aliceToken),
            data: {
              policy_server_did: mockPolicyServerDid() ?? "did:web:policy.example.com",
              policy_server_url: `${mockPolicyServerBaseUrl()}/_cokret/self/policy/check`,
              cache_ttl_seconds: 0,
              timeout_ms: 1500,
              on_timeout: "fail_closed",
            },
          },
        );
        void realmId;
        void bob;
        // (drive invite; assert soland responds 412 errcode="policy_denied"
        //  reason="policy_timeout" within ~2s of issuing the request)
      } finally {
        await alicePage.close();
      }
    },
  );

  test.fixme(
    // @blocking-on: soland#authz-policy-server-check-gap
    // @user-promise: e2e/scenarios/authz/policy-server-check.md
    // @expected-live-by: 2026Q3
    "E3.2 multi-source priority: org policy_server overrides realm policy_server (more-specific wins)",
    async ({ browser, request }) => {
      // spec: authz/policy-server.md §3.2 — org override realm.
      // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
      const stamp = Date.now();
      const alice = uniqueUser(`s30-multisrc-alice-${stamp}`);
      const bob = uniqueUser(`s30-multisrc-bob-${stamp}`);
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, bob),
      ]);
      const aliceToken = await issueDevSession(request, alice);
      const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });

      try {
        const realmId = await alicePage.createRealm({
          title: `S30 multisrc ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });
        await request.put(
          `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/policy-server`,
          {
            headers: authHeaders(aliceToken),
            data: {
              policy_server_did: mockPolicyServerDid() ?? "did:web:policy.example.com",
              policy_server_url: `${mockPolicyServerBaseUrl()}/_cokret/self/policy/check?source=realm`,
              cache_ttl_seconds: 0,
              timeout_ms: 1500,
              on_timeout: "fail_closed",
            },
          },
        );
        const orgPolicyServerBinding = {
          policy_server_did: mockPolicyServerDid() ?? "did:web:policy-org.example.com",
          policy_server_url: `${mockPolicyServerBaseUrl()}/_cokret/self/policy/check?source=org`,
          cache_ttl_seconds: 0,
          timeout_ms: 1500,
          on_timeout: "fail_closed",
        };
        void orgPolicyServerBinding;
        // Mock: realm path → allow, org path → deny. Expected final: deny.
        await request.post(`${mockPolicyServerBaseUrl()}/scenarios`, {
          data: {
            routes: {
              "/_cokret/self/policy/check?source=realm": { default: { decision: "allow" } },
              "/_cokret/self/policy/check?source=org": { default: { decision: "deny", reason: "org_blocks" } },
            },
          },
        });
        void bob;
        void alicePage;
        // (drive invite; assert final HTTP 412 + reason includes "org_blocks";
        //  /inspect.checks shows both sources were called, org decision won)
      } finally {
        await alicePage.close();
      }
    },
  );

  test.fixme(
    // @blocking-on: soland#authz-policy-server-check-gap
    // @user-promise: e2e/scenarios/authz/policy-server-check.md
    // @expected-live-by: 2026Q3
    "E3.3 cache_ttl idempotency: repeated identical action within ttl triggers only one upstream /policy/check",
    async ({ browser, request }) => {
      // spec: authz/policy-server.md §3 — cache_ttl_ms governs upstream call rate.
      // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
      const stamp = Date.now();
      const alice = uniqueUser(`s30-cache-alice-${stamp}`);
      const bob = uniqueUser(`s30-cache-bob-${stamp}`);
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, bob),
      ]);
      const aliceToken = await issueDevSession(request, alice);
      const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });

      try {
        await request.post(`${mockPolicyServerBaseUrl()}/scenarios`, {
          data: { default: { decision: "allow" } },
        });
        const realmId = await alicePage.createRealm({
          title: `S30 cache ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });
        await request.put(
          `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/policy-server`,
          {
            headers: authHeaders(aliceToken),
            data: {
              policy_server_did: mockPolicyServerDid() ?? "did:web:policy.example.com",
              policy_server_url: `${mockPolicyServerBaseUrl()}/_cokret/self/policy/check`,
              cache_ttl_seconds: 5,
              timeout_ms: 1500,
              on_timeout: "fail_closed",
            },
          },
        );

        const baseline = await request.get(`${mockPolicyServerBaseUrl()}/inspect`);
        const baselineBody = await baseline.json();
        const baselineCount = (baselineBody.checks ?? []).length;
        void baselineCount;
        void bob;
        void alicePage;
        // (bob sends two identical ck.message.create within 5s; assert
        //  /inspect.checks.length grows by exactly 1 — or the second entry
        //  carries from_cache=true depending on mock implementation)
      } finally {
        await alicePage.close();
      }
    },
  );
});

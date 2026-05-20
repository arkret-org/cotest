// Pluggable policy decision service (realm-level external policy_server)
// Contract: e2e/scenarios/authz/policy-server-check.md
// Spec: authz/policy-server.md §2 (cx.realm.policy_server Move),
//        §3 (POST /api/v1/policy/check request/response contract),
//        §4 (obligations + fail-closed default).
// Depends on: mock-policy-server.mjs reachable via process.env.MOCK_POLICY_SERVER_PORT
//             (delivered by a parallel task; this spec assumes it's already running).

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

function mockPolicyServerBaseUrl(): string {
  const port = process.env.MOCK_POLICY_SERVER_PORT;
  if (!port) {
    throw new Error(
      "MOCK_POLICY_SERVER_PORT not set; expected mock-policy-server.mjs to be running.",
    );
  }
  return `http://127.0.0.1:${port}`;
}

test.describe("policy server check", () => {
  test.fixme(
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
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      // bob's token is provisioned so the harness can later observe bob-side
      // effects of the deny (e.g. the invite never landing in bob's inbox).
      void bobToken;

      try {
        // Phase A — Realm declares policy server endpoint.
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        const realmResp = await request.post(`${solandBaseUrl()}/api/v1/realm/state`, {
          headers: { authorization: `Bearer ${aliceToken}` },
          data: {
            kind: "cx.realm.policy_server",
            endpoint: `${mockPolicyServerBaseUrl()}/api/v1/policy/check`,
            fail_mode: "closed",
            cache_ttl_ms: 5000,
          },
        });
        expect(realmResp.status()).toBe(200);

        const spaceId = await alicePage.createSpace({
          title: `S30 policy ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });

        // Phase B — mock default allow → invite succeeds.
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        const allowScenario = await request.post(
          `${mockPolicyServerBaseUrl()}/scenarios`,
          { data: { default: { decision: "allow" } } },
        );
        expect(allowScenario.status()).toBe(200);
        await alicePage.gotoSpaceAdmin(spaceId);
        // (drive invite-member → send-invite-button against alicePage; assert
        // space-admin-panel status contains "invited" + bob.did)
        await stepShot(alicePage.page, testInfo, "policy-allow-invite");

        // Phase C — flip mock to deny → invite rejected with reason.
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        const denyScenario = await request.post(
          `${mockPolicyServerBaseUrl()}/scenarios`,
          {
            data: {
              match: { action: "cx.invite.create", target: bob.did },
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
              match: { action: "cx.invite.create" },
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
        // (re-drive invite, then GET /api/v1/audit/events?actor=alice.did
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
        //  request_id, action, actor, decision, occurred_at)
      } finally {
        await alicePage.close();
      }
    },
  );

  test.fixme(
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
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

      try {
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        await request.post(`${solandBaseUrl()}/api/v1/realm/state`, {
          headers: { authorization: `Bearer ${aliceToken}` },
          data: {
            kind: "cx.realm.policy_server",
            endpoint: `${mockPolicyServerBaseUrl()}/api/v1/policy/check`,
            fail_mode: "closed",
            cache_ttl_ms: 0,
          },
        });
        await request.post(`${mockPolicyServerBaseUrl()}/scenarios`, {
          data: { default: { decision: "allow", delay_ms: 9000 } },
        });

        const spaceId = await alicePage.createSpace({
          title: `S30 timeout ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });
        void spaceId;
        void bob;
        // (drive invite; assert soland responds 412 errcode="policy_denied"
        //  reason="policy_timeout" within ~2s of issuing the request)
      } finally {
        await alicePage.close();
      }
    },
  );

  test.fixme(
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
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

      try {
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        await request.post(`${solandBaseUrl()}/api/v1/realm/state`, {
          headers: { authorization: `Bearer ${aliceToken}` },
          data: {
            kind: "cx.realm.policy_server",
            endpoint: `${mockPolicyServerBaseUrl()}/api/v1/policy/check?source=realm`,
            fail_mode: "closed",
            cache_ttl_ms: 0,
          },
        });
        await request.post(`${solandBaseUrl()}/api/v1/org/state`, {
          headers: { authorization: `Bearer ${aliceToken}` },
          data: {
            kind: "cx.org.policy_server",
            endpoint: `${mockPolicyServerBaseUrl()}/api/v1/policy/check?source=org`,
            fail_mode: "closed",
            cache_ttl_ms: 0,
          },
        });
        // Mock: realm path → allow, org path → deny. Expected final: deny.
        await request.post(`${mockPolicyServerBaseUrl()}/scenarios`, {
          data: {
            routes: {
              "/api/v1/policy/check?source=realm": { default: { decision: "allow" } },
              "/api/v1/policy/check?source=org": { default: { decision: "deny", reason: "org_blocks" } },
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
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

      try {
        // soland gap: policy_server endpoint integration not implemented; coauth /policy/check v2 missing
        await request.post(`${solandBaseUrl()}/api/v1/realm/state`, {
          headers: { authorization: `Bearer ${aliceToken}` },
          data: {
            kind: "cx.realm.policy_server",
            endpoint: `${mockPolicyServerBaseUrl()}/api/v1/policy/check`,
            fail_mode: "closed",
            cache_ttl_ms: 5000,
          },
        });
        await request.post(`${mockPolicyServerBaseUrl()}/scenarios`, {
          data: { default: { decision: "allow" } },
        });

        const baseline = await request.get(`${mockPolicyServerBaseUrl()}/inspect`);
        const baselineBody = await baseline.json();
        const baselineCount = (baselineBody.checks ?? []).length;
        void baselineCount;
        void bob;
        void alicePage;
        // (bob sends two identical cx.message.create within 5s; assert
        //  /inspect.checks.length grows by exactly 1 — or the second entry
        //  carries from_cache=true depending on mock implementation)
      } finally {
        await alicePage.close();
      }
    },
  );
});

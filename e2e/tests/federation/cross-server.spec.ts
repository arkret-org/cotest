// Cross-server federation
// Contract: e2e/scenarios/federation/cross-server.md
// Spec refs:
//   - sync/federation.md §2.1-§2.4 (trust roots, Anchor finality, profiles)
//   - §3.1-§3.2 DID server identity + RFC 9421 request signature
//   - §4.1 push protocol, §4.1.0 push sequence
//   - §4.2 pull / backfill, §4.5 fork detection / frontier exchange
//   - §5.1 cross-domain invite
//
// Soland implementation status (2026-05 audit):
//   ✓ POST /api/v1/federation/push-operations handler routed and ingests events
//   ✓ GET  /api/v1/federation/pull-operations cursor-based
//   ✓ Per-event accepted / rejected partial-accept
//   ✓ Idempotent by operation_id
//   ✓ SOLAND_FEDERATION_PEERS env wires peer URLs
//   ✗ RFC 9421 HTTP Message Signature NOT verified — peer impersonation possible
//   ✗ service_binding_ref.reducer_profile_digest NOT validated
//   ✗ Outbound push is STUBBED (logs only, no real HTTP); soland-α won't push
//     bob's invite to soland-β automatically. The push() must be exercised by
//     the test or by future soland work.
//   ✗ cx.invite.create on a remote DID does NOT trigger federation push.

import { expect, test } from "@playwright/test";
import { hasDualSoland, solandBaseUrl, solandServiceDid } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  acceptInviteApi,
  authHeaders,
  listInvitesApi,
  makeOperation,
  pushFederationOperations,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.beforeEach(() => {
  test.skip(
    !hasDualSoland(),
    "S2 requires dual soland topology — pass -DualSoland to scripts/run-joint-e2e.ps1",
  );
});

test.describe("cross-server federation", () => {
  test("both soland instances expose /federation/push-operations and /federation/pull-operations endpoints", async ({
    request,
  }) => {
    // Sanity: both servers up and exposing the federation surface.
    const alphaHealth = await request.get(`${solandBaseUrl("alpha")}/health`);
    expect(alphaHealth.ok()).toBeTruthy();
    const betaHealth = await request.get(`${solandBaseUrl("beta")}/health`);
    expect(betaHealth.ok()).toBeTruthy();

    // POST without auth/body should not 404 — endpoint MUST exist.
    const pushProbe = await request.post(`${solandBaseUrl("beta")}/api/v1/federation/push-operations`, {
      data: {},
    });
    expect(pushProbe.status()).not.toBe(404);

    const pullProbe = await request.get(`${solandBaseUrl("beta")}/api/v1/federation/pull-operations?space_id=cx:space:probe`);
    expect(pullProbe.status()).not.toBe(404);
  });

  test("alice on α and bob on β are independently registered + dev-logged-in against their own server", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-alice-${stamp}`);
    const bob = uniqueUser(`s2-bob-${stamp}`);

    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceToken = await issueDevSession(request, alice, { server: "alpha" });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });

    const alicePage = await openUserPage(browser, alice, {
      sessionToken: aliceToken,
      server: "alpha",
    });
    const bobPage = await openUserPage(browser, bob, {
      sessionToken: bobToken,
      server: "beta",
    });

    try {
      await alicePage.gotoHome();
      expect(alicePage.serverUrl).toBe(solandBaseUrl("alpha"));
      await bobPage.gotoHome();
      expect(bobPage.serverUrl).toBe(solandBaseUrl("beta"));

      // Each principal context binds to its own server.
      const aliceMeResp = await request.get(`${solandBaseUrl("alpha")}/api/v1/account/me`, {
        headers: { authorization: `Bearer ${aliceToken}` },
      });
      expect(aliceMeResp.ok()).toBeTruthy();
      const aliceMe = await aliceMeResp.json();
      expect(aliceMe.did).toBe(alice.did);

      const bobMeResp = await request.get(`${solandBaseUrl("beta")}/api/v1/account/me`, {
        headers: { authorization: `Bearer ${bobToken}` },
      });
      expect(bobMeResp.ok()).toBeTruthy();
      const bobMe = await bobMeResp.json();
      expect(bobMe.did).toBe(bob.did);
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("alice@α creates a space and invites bob (whose DID lives on β); UI surfaces the invite locally", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-alice-${stamp}`);
    const bob = uniqueUser(`s2-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceToken = await issueDevSession(request, alice, { server: "alpha" });

    const alicePage = await openUserPage(browser, alice, {
      sessionToken: aliceToken,
      server: "alpha",
    });

    try {
      const spaceId = await alicePage.createSpace({
        title: `S2 Cross-server ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
      });
      await alicePage.inviteFromAdmin(spaceId, bob.did);
      await stepShot(alicePage.page, testInfo, "alpha-invite-issued");

      // The invite MUST be visible in α's space-invites list right after issuing.
      const aliceInviteRow = alicePage.page
        .getByTestId("invite-row")
        .filter({ hasText: bob.did });
      await expect(aliceInviteRow).toBeVisible({ timeout: 30_000 });
    } finally {
      await alicePage.close();
    }
  });

  test(
    "α→β federation push smoke delivers an invite-shaped operation to β pull + invite APIs",
    async ({ request }) => {
      // API-first smoke for G3.S0: the real β federation ingestion and pull
      // surfaces accept an α-origin operation. The fully automatic yougen
      // invite/accept round trip remains pinned in the richer fixme below.
      const stamp = Date.now();
      const alice = uniqueUser(`s2-outbound-alice-${stamp}`);
      const bob = uniqueUser(`s2-outbound-bob-${stamp}`);
      await ensureRegistered(request, alice, { server: "alpha" });
      await ensureRegistered(request, bob, { server: "beta" });
      await issueDevSession(request, alice, { server: "alpha" });
      const bobToken = await issueDevSession(request, bob, { server: "beta" });

      const alphaDescribe = await request.get(`${solandBaseUrl("alpha")}/api/v1/server/describe`);
      expect(alphaDescribe.ok()).toBeTruthy();
      const alphaDescribeBody = await alphaDescribe.json();
      expect(alphaDescribeBody.experimental_features ?? []).toContain(
        "federation.outbound_push.signed_intent",
      );

      const spaceId = typedId("space");
      const inviteOperation = makeOperation({
        spaceId,
        objectType: "cx.member.state",
        payload: {
          actor_id: bob.did,
          member: bob.did,
          membership: "invite",
          space_title: `S2 pushed invite ${stamp}`,
          discoverability: "public",
          history_visibility: "shared",
        },
      });

      const push = await pushFederationOperations(request, [inviteOperation], {
        origin: solandServiceDid("alpha"),
        destination: solandServiceDid("beta"),
        server: "beta",
        spaceId,
        serviceBindingRef: `${solandServiceDid("alpha")}#cotest-cross-server-smoke`,
      });
      expect(push.accepted).toContain(inviteOperation.operation_id);
      expect(push.rejected ?? []).toEqual([]);

      const pull = await request.get(
        `${solandBaseUrl("beta")}/api/v1/federation/pull-operations?space_id=${encodeURIComponent(spaceId)}&limit=10`,
      );
      expect(pull.ok()).toBeTruthy();
      const pullBody = await pull.json();
      expect((pullBody.operations ?? []).map((op: { operation_id: string }) => op.operation_id)).toContain(
        inviteOperation.operation_id,
      );

      const projectedRealmId = spaceId.replace(/^cx:space:/, "cx:realm:");
      const invites = await listInvitesApi(request, bobToken, { server: "beta" });
      const invite = invites.find(
        (item) =>
          [spaceId, projectedRealmId].includes(item.space_id) && item.invitee === bob.did,
      );
      expect(invite).toBeTruthy();
      await acceptInviteApi(request, bobToken, bob.did, invite!.space_id, invite!.invite_id, { server: "beta" });

      const betaSpace = await request.get(
        `${solandBaseUrl("beta")}/api/v1/spaces/${encodeURIComponent(invite!.space_id)}`,
        { headers: authHeaders(bobToken) },
      );
      expect(betaSpace.ok()).toBeTruthy();
      expect((await betaSpace.json()).members ?? []).toContain(bob.did);
    },
  );

  test.fixme(
    // @blocking-on: soland#federation-cross-server-gap
    // @user-promise: e2e/scenarios/federation/cross-server.md
    // @expected-live-by: 2026Q3
    "α invite UI event automatically fans out to β and β acceptance propagates back to α",
    async () => {
      // Remaining full contract:
      //   1. alice@α inviteFromAdmin(spaceId, bob.did) emits cx.invite.create
      //   2. soland-α resolves bob's server to β and dispatches the operation
      //   3. bob's β-bound yougen sees the invite row and accepts
      //   4. β pushes accept back to α; α records bob as joined member
    },
  );

  test.fixme(
    // @blocking-on: soland#federation-cross-server-gap
    // @user-promise: e2e/scenarios/federation/cross-server.md
    // @expected-live-by: 2026Q3
    "two-way timeline messaging: alice@α and bob@β exchange messages and both servers converge on identical effective state",
    async () => {
      // spec: §4.1 push + §4.5 frontier exchange
      // soland gap: outbound push stubbed; no automatic propagation.
      //
      // Acceptance criteria:
      //   - alice's message on α appears in bob's timeline on β within 30s
      //   - bob's reply on β appears in alice's timeline on α within 30s
      //   - GET /api/v1/spaces/${spaceId}/anchor-frontier on both servers
      //     returns event sets that are causally consistent
    },
  );

  test.fixme(
    // @blocking-on: soland#federation-cross-server-gap
    // @user-promise: e2e/scenarios/federation/cross-server.md
    // @expected-live-by: 2026Q3
    "Pull / backfill: after a network partition, β fetches missing α events via GET /api/v1/federation/pull-operations",
    async () => {
      // spec: §4.2 pull / backfill
      // soland gap: pull endpoint exists but α never persists "outgoing push
      // failure" state, so β doesn't know what cursor to ask for.
    },
  );

  test.fixme(
    // @blocking-on: soland#federation-cross-server-gap
    // @user-promise: e2e/scenarios/federation/cross-server.md
    // @expected-live-by: 2026Q3
    "Idempotent push: replaying the same (origin, destination, event_id) returns accepted (no duplicate write); reducer_profile_digest mismatch returns rejected with reason_code=reducer_profile_mismatch",
    async () => {
      // spec: §4.1 reducer_profile_digest gate + §4.1.1 idempotency
      // soland gap: reducer_profile_digest NOT validated; idempotency only on
      // (origin, operation_id), not full tuple.
    },
  );

  test.fixme(
    // @blocking-on: soland#federation-cross-server-gap
    // @user-promise: e2e/scenarios/federation/cross-server.md
    // @expected-live-by: 2026Q3
    "Capability revoke fanout: after alice revokes β's service delegation, α MUST stop pushing future events to β (§4.4)",
    async () => {
      // spec: §4.4 capability revoke fanout
      // soland gap: no service-delegation revoke fanout implemented.
    },
  );

  test.fixme(
    // @blocking-on: soland#federation-cross-server-gap
    // @user-promise: e2e/scenarios/federation/cross-server.md
    // @expected-live-by: 2026Q3
    "RFC 9421 signature failure: tampered Signature header makes β reject the entire batch with 4xx",
    async () => {
      // spec: §3.2 RFC 9421 request signature
      // soland gap: HTTP Message Signature NOT verified — peer can impersonate.
    },
  );
});

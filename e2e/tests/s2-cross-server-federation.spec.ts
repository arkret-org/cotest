// S2 — Cross-server federation
// Contract: e2e/scenarios/S2-cross-server-federation.md
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
//   ✗ service_binding_ref.reducer_profile_hash NOT validated
//   ✗ Outbound push is STUBBED (logs only, no real HTTP); soland-α won't push
//     bob's invite to soland-β automatically. The push() must be exercised by
//     the test or by future soland work.
//   ✗ cx.invite.create on a remote DID does NOT trigger federation push.

import { expect, test } from "@playwright/test";
import { hasDualSoland, solandBaseUrl } from "../helpers/env";
import { stepShot } from "../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../helpers/users";

test.describe.configure({ mode: "serial" });

test.beforeEach(() => {
  test.skip(
    !hasDualSoland(),
    "S2 requires dual soland topology — pass -DualSoland to scripts/run-joint-e2e.ps1",
  );
});

test.describe("S2 — cross-server federation", () => {
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

  test.fixme(
    "α→β federation push delivers the invite event to bob@β automatically; bob's β-bound yougen sees the invite row and accepts",
    async () => {
      // spec: sync/federation.md §4.1 (push) + §5.1 (cross-domain invite)
      // soland gap: outbound federation push is stubbed (federation.rs:548-572
      // — only logs, no HTTP). cx.invite.create with remote DID does not
      // trigger broadcast_move_to_peers automatically.
      //
      // Acceptance criteria once soland ships outbound push:
      //   1. alice@α inviteFromAdmin(spaceId, bob.did) emits cx.invite.create
      //   2. soland-α resolves bob's server to β (via DID Document) and
      //      POSTs /api/v1/federation/push-operations with the event envelope
      //   3. soland-β returns 200 with accepted[invite.event_id]
      //   4. bob's β-bound yougen sees the invite in space-admin invite list
      //   5. bob clicks accept-invite-button; β submits cx.invite.accept
      //   6. β pushes accept back to α; α records bob as joined member
      //   7. alice's α-bound /space/${spaceId}/admin shows bob in members
    },
  );

  test.fixme(
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
    "Pull / backfill: after a network partition, β fetches missing α events via GET /api/v1/federation/pull-operations",
    async () => {
      // spec: §4.2 pull / backfill
      // soland gap: pull endpoint exists but α never persists "outgoing push
      // failure" state, so β doesn't know what cursor to ask for.
    },
  );

  test.fixme(
    "Idempotent push: replaying the same (origin, destination, event_id) returns accepted (no duplicate write); reducer_profile_hash mismatch returns rejected with reason_code=reducer_profile_mismatch",
    async () => {
      // spec: §4.1 reducer_profile_hash gate + §4.1.1 idempotency
      // soland gap: reducer_profile_hash NOT validated; idempotency only on
      // (origin, operation_id), not full tuple.
    },
  );

  test.fixme(
    "Capability revoke fanout: after alice revokes β's service delegation, α MUST stop pushing future events to β (§4.4)",
    async () => {
      // spec: §4.4 capability revoke fanout
      // soland gap: no service-delegation revoke fanout implemented.
    },
  );

  test.fixme(
    "RFC 9421 signature failure: tampered Signature header makes β reject the entire batch with 4xx",
    async () => {
      // spec: §3.2 RFC 9421 request signature
      // soland gap: HTTP Message Signature NOT verified — peer can impersonate.
    },
  );
});

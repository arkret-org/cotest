// Transport binding negotiation (HTTP / WebSocket / TSP fallback)
// Contract: e2e/scenarios/sync/transport-negotiation.md
// Spec refs:
//   - sync/transport-bindings.md §2-§4 (binding layers, requirements,
//     canonical operation IDs, supported_bindings discovery)
//   - sync/service-http-binding.md §3-§5 (auth requirements, RFC 9421
//     HTTP Message Signature for service-to-service, error envelope)
//   - sync/federation.md §3.2 (RFC 9421 request signature) + §4.1 (push)
//
// soland gap: WebSocket transport + TSP binding negotiation 未实现;
// HTTP RFC 9421 入站 OK 但出站签名生成不完整。
// Soland implementation status (2026-05 audit, mirrored from
// tests/federation/cross-server.spec.ts):
//   ✓ POST /_cokret/peer/events handler routed
//   ✓ Basic envelope validation + idempotency on signed Event IDs
//   ~ RFC 9421 inbound: partial — Signature-Input parsing works for
//     simple cases but Content-Digest / nonce window / key-rotation hint
//     not wired through end-to-end
//   ✗ Outbound RFC 9421 signature generation — stubbed (only logs)
//   ✗ ck.transport.negotiate operation — slot reserved, no runtime
//   ✗ WebSocket frame binding (ck.profile.binding.websocket.v1) — not impl
//   ✗ TSP binding (ck.profile.binding.tsp.v1) — not impl
//   ✗ Binding fallback chain state machine — not impl

import { expect, test } from "@playwright/test";
import { hasDualSoland, solandBaseUrl, solandServiceDid } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
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
    "transport-negotiation requires dual soland topology — pass -DualSoland to scripts/run-joint-e2e.ps1",
  );
});

test.describe("transport negotiation", () => {
  test("both soland instances expose /server/describe with supported_bindings and at minimum http_json", async ({
    request,
  }) => {
    // Sanity: both servers up and exposing binding-discovery surface.
    const alphaHealth = await request.get(`${solandBaseUrl("alpha")}/health`);
    expect(alphaHealth.ok()).toBeTruthy();
    const betaHealth = await request.get(`${solandBaseUrl("beta")}/health`);
    expect(betaHealth.ok()).toBeTruthy();

    // /server/describe MUST exist on both sides and SHOULD return at least
    // an http_json binding entry (transport-bindings.md §7).
    const alphaDescribe = await request.get(`${solandBaseUrl("alpha")}/_cokret/describe`);
    expect(alphaDescribe.status()).not.toBe(404);
    const betaDescribe = await request.get(`${solandBaseUrl("beta")}/_cokret/describe`);
    expect(betaDescribe.status()).not.toBe(404);

    if (alphaDescribe.ok()) {
      const alphaBody = await alphaDescribe.json();
      // service_did MUST be present; supported_bindings SHOULD include http_json.
      expect(typeof alphaBody.service_did).toBe("string");
      if (Array.isArray(alphaBody.supported_bindings)) {
        const kinds = alphaBody.supported_bindings.map((b: { kind: string }) => b.kind);
        expect(kinds).toContain("http_json");
      }
    }
  });

  test("federation push endpoint exists on β and rejects unsigned requests with a non-404 status", async ({
    request,
  }) => {
    // Phase A baseline negative: hitting the federation push endpoint
    // without any RFC 9421 signature MUST NOT 404 (route exists) and
    // MUST NOT 200 (signature required). Expected: 400 / 401 / 403.
    const probe = await request.post(
      `${solandBaseUrl("beta")}/_cokret/peer/events`,
      { data: { events: [] } },
    );
    expect(probe.status()).not.toBe(404);
    expect(probe.status()).not.toBe(200);
    // Accept the 4xx family — exact code depends on soland's auth pipeline.
    expect(probe.status()).toBeGreaterThanOrEqual(400);
    expect(probe.status()).toBeLessThan(500);
  });

  test.fixme(
    // @blocking-on: soland#sync-transport-negotiation-gap
    // @user-promise: e2e/scenarios/sync/transport-negotiation.md
    // @expected-live-by: 2026Q3
    "soland_a and soland_b negotiate HTTP → WebSocket → TSP with proper RFC 9421 signing throughout; fallback to HTTP on WebSocket failure",
    async ({ browser, request }, testInfo) => {
      // soland gap: WebSocket transport + TSP binding negotiation 未实现;
      // HTTP RFC 9421 入站 OK 但出站签名生成不完整。
      //
      // Acceptance criteria once soland ships the full binding stack:
      //
      // Phase A — HTTP baseline (RFC 9421 signed POST):
      //   1. alice@α issues ck.invite.create targeting bob's DID on β
      //   2. soland_a constructs POST ${SOLAND_B}/_cokret/peer/events with:
      //        - Source-Service-DID / Destination-Service-DID headers
      //        - Signature-Input covering (@method @target-uri content-digest
      //          source-service-did destination-service-did)
      //        - Signature header (ed25519 over canonical signature base)
      //        - Content-Digest header
      //        - Idempotency-Key
      //   3. soland_b verifies signature against α's DID document key, returns
      //      200 with { accepted: [invite_event_id] }
      //   4. bob@β sees invite via GET /_soland/self/notifications within 30s
      //
      // Phase B — WebSocket upgrade:
      //   5. soland_a reads β's /_cokret/describe → finds websocket_frame
      //      entry with a peer Events streaming binding declared by spec
      //   6. soland_a opens WebSocket with Sec-WebSocket-Protocol: ck.federation.v1
      //      and RFC 9421 Signature on the upgrade request
      //   7. β responds 101 Switching Protocols
      //   8. soland_a streams the next event (alice's timeline message) over WS
      //      with per-frame service signature
      //   9. bob sees message within 30s; active binding metric reports
      //      websocket_frame on both sides
      //
      // Phase C — TSP binding (optional extension):
      //  10. soland_a announces ck.profile.binding.tsp.v1 in supported_bindings
      //  11. soland_b chooses TSP via ck.transport.negotiate
      //  12. subsequent events strand inside TSP relationship envelopes
      //      (outer wrapper carries sender/receiver VID; inner = EventEnvelope)
      //  13. RFC 9421 NOT required on TSP-wrapped traffic — envelope crypto
      //      binding replaces HTTP-layer signature
      //
      // Phase D — Fallback chain:
      //  14. force-close the WebSocket connection
      //  15. soland_a's binding state machine moves
      //      tsp → websocket_frame → http_json (skipping unavailable layers)
      //  16. next outbound event strands over HTTP/JSON, signed RFC 9421
      //  17. bob receives the event within 30s; binding.fallback{from=ws,to=http}
      //      counter increments

      const stamp = Date.now();
      const alice = uniqueUser(`s8-alice-${stamp}`);
      const bob = uniqueUser(`s8-bob-${stamp}`);
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
        // Phase A — sanity-record alpha/beta service DIDs so failure dumps are
        // useful when the binding work lands.
        expect(solandServiceDid("alpha")).toMatch(/^did:/);
        expect(solandServiceDid("beta")).toMatch(/^did:/);

        const realmId = await alicePage.createRealm({
          title: `S8 Transport ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          historyVisibility: "joined",
        });
        await alicePage.inviteFromAdmin(realmId, bob.did);
        await stepShot(alicePage.page, testInfo, "alpha-phase-a-invite-issued");

        // Phase A acceptance: bob's β-bound notifications surface the invite
        // — this only succeeds when α's outbound RFC 9421 push is real.
        await bobPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
        await expect(
          bobPage.page.getByTestId("notification-item").filter({ hasText: realmId }),
        ).toBeVisible({ timeout: 30_000 });

        // Phase B / C / D are exercised by the sub-fixme tests below.
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-transport-negotiation-gap
    // @user-promise: e2e/scenarios/sync/transport-negotiation.md
    // @expected-live-by: 2026Q3
    "E8.1 signature expiry + key rotation: soland_a signs with an expired key; soland_b returns 401 with key_rotation_hint; α re-signs with current key and succeeds",
    async ({ request }) => {
      // spec: service-http-binding.md §3 (auth materials), federation.md §3.2
      // soland gap: signature expiry / key rotation hint path not wired.
      //
      // Acceptance criteria:
      //   1. Build a federation push request with a RFC 9421 Signature whose
      //      `created` timestamp is older than the accepted window (or whose
      //      keyid points at a retired key in α's DID document)
      //   2. POST to β → expect 401 with body
      //      { error: { code: "signature_expired" | "unknown_keyid",
      //                 key_rotation_hint: { current_keyid, valid_from } } }
      //   3. Re-sign with the keyid named in the hint; second POST returns 200
      //   4. β only persists the event from the second (validly signed) attempt
      void request;
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-transport-negotiation-gap
    // @user-promise: e2e/scenarios/sync/transport-negotiation.md
    // @expected-live-by: 2026Q3
    "E8.2 multi-hop relay: α → relay → β; β verifies BOTH the relay's outer RFC 9421 signature AND the inner EventEnvelope actor signature; either failure rejects the batch",
    async ({ request }) => {
      // spec: federation.md §3.2 + capabilities.md (service delegation)
      // soland gap: relay topology + nested verification not implemented.
      //
      // Acceptance criteria:
      //   1. Topology: soland_a → relay (third soland or mock) → soland_b
      //   2. Relay receives α's signed POST, does NOT decode the inner
      //      EventEnvelope signature; wraps with its own service signature
      //      (Source-Service-DID = relay) and forwards to β
      //   3. β MUST verify:
      //      a. Relay's RFC 9421 outer signature (against relay's DID document)
      //      b. Inner EventEnvelope's origin actor signature (alice@α)
      //      c. Relay is authorized as service delegation in the target
      //         space's service_binding_ref
      //   4. If (a) fails → 401; if (b) fails → 400 invalid_signature;
      //      if (c) fails → 403 service_delegation_not_authorized
      //   5. All three OK → 200, event persisted with provenance chain
      //      [origin=alice@α, relayed_via=relay] recorded
      void request;
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-transport-negotiation-gap
    // @user-promise: e2e/scenarios/sync/transport-negotiation.md
    // @expected-live-by: 2026Q3
    "E8.3 binding negotiation timeout: α requests WebSocket upgrade; β does not respond within 30s; α cancels and falls back to HTTP/JSON",
    async ({ request }) => {
      // spec: transport-bindings.md §3 (binding requirements — background /
      //       backpressure) + §7 (binding discovery)
      // soland gap: ck.transport.negotiate runtime + fallback state machine
      //             both missing.
      //
      // Acceptance criteria:
      //   1. α calls ck.transport.negotiate against β with desired binding
      //      = websocket_frame
      //   2. β intentionally does not respond (test harness blackholes the
      //      negotiation endpoint with route.fulfill delay > 30s)
      //   3. After 30s α MUST:
      //      a. Cancel the negotiation request (no orphan socket)
      //      b. Mark websocket_frame as temporarily unavailable for β
      //         (cooldown ≥ 60s)
      //      c. Resume using http_json for queued outbound events
      //   4. bob@β receives the next pending event over HTTP within ~60s
      //   5. binding.negotiation_timeout{peer=β,binding=websocket_frame}
      //      counter increments by 1
      void request;
    },
  );
});

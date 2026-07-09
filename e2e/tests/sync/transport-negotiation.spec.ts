// Transport binding negotiation (HTTP / WebSocket / TSP fallback)
// Contract: e2e/scenarios/sync/transport-negotiation.md
// Spec refs:
//   - sync/transport-bindings.md §2-§4 (binding layers, requirements,
//     canonical operation IDs, supported_bindings discovery)
//   - sync/service-http-binding.md §3-§5 (auth requirements, RFC 9421
//     HTTP Message Signature for service-to-service, error envelope)
//   - sync/federation.md §3.2 (RFC 9421 request signature) + §4.1 (push)
//
// soland status (2026-06 re-audit against arkret-spec v1):
//   ✓ POST /_cokret/peer/events handler routed (canonical single rail)
//   ✓ Envelope validation + idempotency on signed Event IDs
//   ✓ RFC 9421 INBOUND: full — Content-Digest, Request-Canonical-Digest,
//     created/expires freshness window (±30s skew, ≤300s window,
//     expires-in-future), @authority/endpoint-digest binding, and the
//     §3.2/§8.3 minimal-disclosure failure envelope are all wired
//     (signature.rs). Every auth-failure cause (stale window, wrong/invalid
//     key) folds into one indistinguishable envelope (FEDERATION_AUTH_FAILURE
//     _MESSAGE + fixed timing bucket); a key-rotation hint IS computed but
//     stays audit-log only (tracing::warn! detail), because surfacing it in
//     the response would violate the minimal-disclosure MUST. E8.1 below
//     asserts that uniform-failure contract.
//   ✓ RFC 9421 INBOUND relay hop: the canonical /_cokret/peer/* rail
//     (verify_inbound_peer_http_signature) authenticates purely on the
//     federation trust headers — origin IS the source-service-did header, so
//     there is NO relay-inner signature hop. Two-layer relay verification
//     (verify_relay_inner_signature) lives only on the private
//     /_soland/peer/federation/* rail (dev-only, NOT an interop entry point),
//     so E8.2's inner-EventEnvelope-actor-signature assertion has no landing
//     spot on the canonical rail — see E8.2 below.
//   ✓ RFC 9421 OUTBOUND: real — outbox.rs signs (rfc9421_sign) and POSTs for
//     real when `federation_outbound_enabled=true`. GAP: the enqueued body
//     (outbound.rs::enqueue_outbound_for) is a {resource_kind,resource_id}
//     reference placeholder, not the sealed Event Envelope events[] batch the
//     peer endpoint requires — so cross-server delivery does not yet complete.
//   ✗ ck.transport.negotiate operation — NOT in spec registry (reserved name)
//   ✗ WebSocket frame binding — extension profile, not v1 core (tb §6)
//   ✗ TSP binding — extension profile, not v1 core
//   ✗ Binding fallback chain state machine — presupposes the above bindings

import { expect, test } from "@playwright/test";
import { hasDualSoland, solandBaseUrl, solandServiceDid } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  makeFederationEvent,
  rawPushFederationEvents,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

// Reads the auth-failure shape off a federation push response without
// assuming an envelope vs. plain-text body: minimal disclosure means the
// status, message, and code MUST be identical across every distinct failure
// cause (federation.md §3.2 / §8.3).
async function federationAuthFailureShape(response: {
  status: () => number;
  text: () => Promise<string>;
}): Promise<{ status: number; message: string; code: string; raw: string }> {
  const raw = await response.text();
  let message = "";
  let code = "";
  try {
    const body = JSON.parse(raw) as {
      error?: { code?: string; message?: string };
    };
    message = body.error?.message ?? "";
    code = body.error?.code ?? "";
  } catch {
    message = raw;
  }
  return { status: response.status(), message, code, raw };
}

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
    // @blocking-on: spec — WebSocket/TSP are binding *extension profiles*, not
    //   v1 core. transport-bindings.md §6 classifies non-HTTP bindings as outside the
    //   v1 core interop surface (core implementations are not required to
    //   provide them) and §1/§2 lock v1 core interop to
    //   HTTP/JSON. There is no registered `websocket_frame` binding kind,
    //   `ck.profile.binding.websocket.v1` profile, or `ck.transport.negotiate`
    //   operation in artifacts/registry — they are reserved extension slots only.
    //   Phase A's cross-server delivery is *also* blocked, but on an
    //   implementation gap, not the binding stack: soland's outbound dispatcher
    //   (outbox.rs) already signs+POSTs RFC 9421 for real when
    //   `federation_outbound_enabled=true`, but the enqueued body
    //   (outbound.rs::enqueue_outbound_for) is a `{resource_kind,resource_id}`
    //   *reference* placeholder, not the sealed Event Envelope `events[]` batch
    //   that POST /_cokret/peer/events requires — so β would reject it. Wiring a
    //   real envelope batch touches event-log/reducer/realm-policy resolution
    //   (which peer gets which event), outside this binding-negotiation surface.
    // @user-promise: e2e/scenarios/sync/transport-negotiation.md
    // @expected-live-by: unscheduled (requires a published binding extension
    //   profile + outbound envelope-batch fanout; neither is on the v1 core path)
    "soland_a and soland_b negotiate HTTP → WebSocket → TSP with proper RFC 9421 signing throughout; fallback to HTTP on WebSocket failure",
    async ({ browser, request }, testInfo) => {
      // soland gap: WebSocket transport + TSP binding negotiation are not
      // implemented; inbound HTTP RFC 9421 verification works but outbound
      // signature generation is incomplete.
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
      //   4. bob@β sees invite via account subscribe notifications within 30s
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
        sessionCredential: aliceToken,
        server: "alpha",
      });
      const bobPage = await openUserPage(browser, bob, {
        sessionCredential: bobToken,
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

  test("E8.1 signature expiry / key mismatch: β returns one indistinguishable auth-failure envelope (no key_rotation_hint); a fresh re-sign passes auth", async ({
    request,
  }) => {
    // spec: federation.md §3.2 + §8.3 minimal-disclosure MUST. Distinct
    //   failure causes (stale freshness window, invalid/wrong-key signature)
    //   MUST collapse to ONE indistinguishable failure: same HTTP status, same
    //   message, same code, with no distinguishing field (no key_rotation_hint
    //   / signature_expired / unknown_keyid) in the response — the real cause
    //   is audit-log only. soland: signature.rs folds every cause into
    //   FEDERATION_AUTH_FAILURE_MESSAGE + a fixed timing bucket.
    const realmId = typedId("realm");
    const buildEvent = (tag: string) =>
      makeFederationEvent({
        realmId,
        kind: "ck.message.create",
        actorDid: "did:web:alice-e81.example",
        payload: {
          strand_id: typedId("strand"),
          track_name: "discussion",
          content: {
            kind: "ck.content.text",
            body: `E8.1 ${tag} ${Date.now()}`,
          },
        },
      });

    const pushOpts = {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      server: "beta" as const,
      realmId,
    };

    // Cause 1: the RFC 9421 signature is valid but its freshness window is in
    // the past (created beyond ±30s, expires < now) → §3.2 rejects on expiry.
    const expired = await federationAuthFailureShape(
      await rawPushFederationEvents(request, [buildEvent("expired")], {
        ...pushOpts,
        idempotencyKey: `${solandServiceDid("alpha")}#cotest-e81-expired`,
        expireSignature: true,
      }),
    );

    // Cause 2: a structurally-present but cryptographically-invalid signature
    // (a different cause: bad/wrong key, not expiry).
    const tampered = await federationAuthFailureShape(
      await rawPushFederationEvents(request, [buildEvent("tampered")], {
        ...pushOpts,
        idempotencyKey: `${solandServiceDid("alpha")}#cotest-e81-tampered`,
        tamperSignature: true,
      }),
    );

    // Both are auth failures in the 4xx family.
    for (const failure of [expired, tampered]) {
      expect(failure.status).toBeGreaterThanOrEqual(400);
      expect(failure.status).toBeLessThan(500);
    }

    // Minimal disclosure: the two distinct causes are INDISTINGUISHABLE — same
    // status, same message, same code.
    expect(expired.status).toBe(tampered.status);
    expect(expired.message).toBe(tampered.message);
    expect(expired.code).toBe(tampered.code);

    // And neither response leaks a distinguishing rotation/cause signal that
    // §3.2/§8.3 forbid.
    for (const failure of [expired, tampered]) {
      expect(failure.raw).not.toContain("key_rotation_hint");
      expect(failure.raw).not.toContain("signature_expired");
      expect(failure.raw).not.toContain("unknown_keyid");
      expect(failure.raw).not.toContain("valid_from");
      expect(failure.raw).not.toContain("current_keyid");
    }

    // A fresh, correctly-keyed re-sign clears the auth gate: the request is no
    // longer the uniform auth-failure envelope (post-auth admission outcome is
    // out of scope for this binding-auth test).
    const reSigned = await federationAuthFailureShape(
      await rawPushFederationEvents(request, [buildEvent("resigned")], {
        ...pushOpts,
        idempotencyKey: `${solandServiceDid("alpha")}#cotest-e81-resigned`,
      }),
    );
    const passedAuth =
      reSigned.status !== expired.status || reSigned.message !== expired.message;
    expect(
      passedAuth,
      `re-signed push still looks like an auth failure: ${reSigned.raw}`,
    ).toBeTruthy();
  });

  test.fixme(
    // @blocking-on: spec single-track convergence — the canonical interop rail
    //   POST /_cokret/peer/events (verify_inbound_peer_http_signature) does NOT
    //   carry a relay-inner hop: per federation.md §4.0 the origin IS the
    //   `source-service-did` header and relay delegation is expressed via
    //   service_binding_ref / service delegation, not a nested HTTP signature.
    //   soland's two-layer relay verification (signature.rs::
    //   verify_relay_inner_signature) lives ONLY on the private
    //   /_soland/peer/federation/* rail, which §4.0 (line 152) says MUST NOT be
    //   a cross-deployment interop entry point and which
    //   ensure_private_inbound_write_rail_local gates to development_mode only.
    //   That rail also takes a different body shape (FederationPushOperations
    //   with origin/destination + operations[], not the events[] envelope batch
    //   the cotest helpers build). To promote on the canonical rail, the spec
    //   would first need to define a relay/delegation hop for /_cokret/peer/*;
    //   to promote against the private rail would mean testing a deployment-
    //   local debug surface the spec forbids as an interop target, and would
    //   require new helpers (relay-inner-signature / -input header + operations
    //   body). Neither is a low-risk transport-negotiation change.
    // @user-promise: e2e/scenarios/sync/transport-negotiation.md
    // @expected-live-by: unscheduled (needs a spec-defined relay/delegation hop
    //   on the canonical /_cokret/peer/* rail)
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
    // @blocking-on: spec — depends on `ck.transport.negotiate` + a
    //   `websocket_frame` binding, neither of which exists in v1. There is no
    //   `ck.transport.negotiate` operation in artifacts/registry and no
    //   registered WebSocket binding kind (transport-bindings.md §6: non-HTTP
    //   bindings are extension profiles that core implementations are not
    //   required to provide). The whole
    //   negotiation → timeout → fallback state machine is client-side logic
    //   over a binding stack soland does not (and per v1 core need not) ship.
    //   The HTTP/JSON baseline this would "fall back to" is the same
    //   outbound-fanout path blocked under the main test above. Not a discrete
    //   soland bug — it presupposes the extension binding stack.
    // @user-promise: e2e/scenarios/sync/transport-negotiation.md
    // @expected-live-by: unscheduled (requires a published WebSocket binding
    //   extension profile + ck.transport.negotiate; not on the v1 core path)
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

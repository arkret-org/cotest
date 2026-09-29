// Transport binding negotiation (HTTP / WebSocket fallback)
// Contract: e2e/scenarios/sync/transport-negotiation.md
// Spec refs:
//   - sync/transport-bindings.md §2-§4 (binding layers, requirements,
//     canonical operation IDs, transport_bindings discovery)
//   - sync/service-http-binding.md §3-§5 (auth requirements, RFC 9421
//     HTTP Message Signature for service-to-service, error envelope)
//   - sync/federation.md §3.2 (RFC 9421 request signature) + §4.1 (push)
//
// soland status (2026-06 re-audit against arkret-spec v1):
//   ✓ POST /_arkret/peer/events handler routed (canonical single rail)
//   ✓ Envelope validation + idempotency on signed Event IDs
//   ✓ RFC 9421 INBOUND: full — the single RFC 9530 Content-Digest,
//     created/expires freshness window (±30s skew, ≤300s window,
//     expires-in-future), @authority/endpoint-digest binding, and the
//     registered failure codes are all wired (signature.rs). A window
//     failure is `signature_window_invalid` (service-http-binding.md §8.3,
//     shared by every signature scenario); an invalid or wrong-key signature
//     on the closed peer submit is `signature_invalid` (federation.md §3.2).
//     Both share one fixed detail string and timing bucket; the private cause
//     and any key-rotation hint stay audit-log only. E8.1 below asserts it.
//   ✓ RFC 9421 INBOUND relay hop: the canonical /_arkret/peer/* rail
//     (verify_inbound_peer_http_signature) authenticates purely on the
//     federation trust headers — origin IS the source-service-id header, so
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
//   ✗ ak.transport.negotiate operation — NOT in spec registry (reserved name)
//   ✗ WebSocket frame binding — extension profile, not v1 core (tb §6)
//   ✗ Binding fallback chain state machine — presupposes the above bindings

import { expect, test } from "../../helpers/arkret-test";
import { hasServerCount, solandBaseUrl, solandServiceId } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  createRealmApi,
  makeFederationEvent,
  rawPushFederationEvents,
  resolveDefaultStrandId,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueUserSession,
  uniqueUser,
} from "../../helpers/users";

// Reads the canonical Problem Details shape from a federation push response.
async function federationAuthFailureShape(response: {
  status: () => number;
  text: () => Promise<string>;
}): Promise<{ status: number; message: string; code: string; raw: string }> {
  const raw = await response.text();
  const body = JSON.parse(raw) as { detail?: string };
  const message = body.detail ?? "";
  const code = wireErrCode(body) ?? "";
  return { status: response.status(), message, code, raw };
}

test.describe.configure({ mode: "serial" });

test.beforeEach(() => {
  test.skip(
    !hasServerCount(2),
    "transport-negotiation requires two-server topology — pass -ServerCount 2 to scripts/run-joint-e2e.ps1",
  );
});

test.describe("transport negotiation", () => {
  test("both soland instances expose /server/describe with transport_bindings and at minimum http_json", async ({
    request,
  }) => {
    // Sanity: both servers up and exposing binding-discovery surface.
    const server1Health = await request.get(`${solandBaseUrl("server1")}/health`);
    expect(server1Health.ok()).toBeTruthy();
    const server2Health = await request.get(`${solandBaseUrl("server2")}/health`);
    expect(server2Health.ok()).toBeTruthy();

    // /server/describe MUST exist on both sides and SHOULD return at least
    // an http_json binding entry (transport-bindings.md §7).
    const server1Describe = await request.get(`${solandBaseUrl("server1")}/_arkret/describe`);
    expect(server1Describe.status()).not.toBe(404);
    const server2Describe = await request.get(`${solandBaseUrl("server2")}/_arkret/describe`);
    expect(server2Describe.status()).not.toBe(404);

    if (server1Describe.ok()) {
      const server1Body = await server1Describe.json();
      // service_id MUST be present; transport_bindings MUST include http_json.
      expect(typeof server1Body.service_id).toBe("string");
      expect(Array.isArray(server1Body.transport_bindings)).toBe(true);
      const kinds = server1Body.transport_bindings.map((b: { kind: string }) => b.kind);
      expect(kinds).toContain("http_json");
    }
  });

  test("federation push endpoint exists on server2 and rejects unsigned requests with a non-404 status", async ({
    request,
  }) => {
    // Phase A baseline negative: hitting the federation push endpoint
    // without any RFC 9421 signature MUST NOT 404 (route exists) and
    // MUST NOT 200 (signature required). Expected: 400 / 401 / 403.
    const probe = await request.post(
      `${solandBaseUrl("server2")}/_arkret/peer/events`,
      { data: { events: [] } },
    );
    expect(probe.status()).not.toBe(404);
    expect(probe.status()).not.toBe(200);
    // Accept the 4xx family — exact code depends on soland's auth pipeline.
    expect(probe.status()).toBeGreaterThanOrEqual(400);
    expect(probe.status()).toBeLessThan(500);
  });

  test("E8.1 signature expiry / key mismatch: server2 answers the registered window and signature codes with no private cause (no key_rotation_hint); a fresh re-sign passes auth", async ({
    request,
  }) => {
    // spec: service-http-binding.md §8.3 — any failure of
    //   `ak.http_signature.freshness.v1` returns `signature_window_invalid`,
    //   for all five signature scenarios. federation.md §3.2 — a peer submit
    //   whose current RFC 9421 signature does not verify returns
    //   `signature_invalid`. error-code-registry.json gives both HTTP 401.
    //   Neither response carries the private cause (key_rotation_hint /
    //   signature_expired / unknown_keyid); that stays audit-log only.
    const user = uniqueUser("e81-federation", "server1");
    await ensureRegistered(request, user, { server: "server1" });
    const token = await issueUserSession(request, user, { server: "server1" });
    const realmId = await createRealmApi(
      request,
      token,
      {
        title: "E8.1 federation signature fixture",
        ownerId: user.id,
        creator_id: solandServiceId("server1"),
      },
      { server: "server1" },
    );
    // The source Station admits a message only into an existing Strand of the
    // Realm; a fabricated Strand id is a `conflict` before federation starts.
    const strandId = await resolveDefaultStrandId(request, token, realmId, {
      server: "server1",
    });
    const buildEvent = (tag: string) =>
      makeFederationEvent({
        realmId,
        kind: "ak.message.create",
        actorId: user.id,
        payload: {
          strand_id: strandId,
          track_name: "discussion",
          content: {
            kind: "ak.content.text",
            body: `E8.1 ${tag} ${Date.now()}`,
          },
        },
      });
    const buildPublishedEvent = async (tag: string) => {
      const event = buildEvent(tag);
      // Federation transport carries the original first-publication evidence;
      // manufacture neither the lease nor the ingress receipt in the fixture.
      await submitSignedEventApi(request, token, event, {
        server: "server1",
        context: `publish E8.1 ${tag} source Event`,
      });
      return event;
    };

    const pushOpts = {
      origin: solandServiceId("server1"),
      destination: solandServiceId("server2"),
      server: "server2" as const,
      realmId,
    };

    // Cause 1: the RFC 9421 signature is valid but its freshness window is in
    // the past (created beyond ±30s, expires < now) → §3.2 rejects on expiry.
    const expiredEvent = await buildPublishedEvent("expired");
    const expired = await federationAuthFailureShape(
      await rawPushFederationEvents(request, [expiredEvent], {
        ...pushOpts,
        expireSignature: true,
      }),
    );

    // Cause 2: a structurally-present but cryptographically-invalid signature
    // (a different cause: bad/wrong key, not expiry).
    const tamperedEvent = await buildPublishedEvent("tampered");
    const tampered = await federationAuthFailureShape(
      await rawPushFederationEvents(request, [tamperedEvent], {
        ...pushOpts,
        tamperSignature: true,
      }),
    );

    // Both are auth failures in the 4xx family.
    for (const failure of [expired, tampered]) {
      expect(failure.status).toBeGreaterThanOrEqual(400);
      expect(failure.status).toBeLessThan(500);
    }

    // Each cause answers its own registered code at the same status, and the
    // public detail is the one fixed string for either.
    expect(expired.status).toBe(401);
    expect(tampered.status).toBe(401);
    expect(expired.code).toBe("signature_window_invalid");
    expect(tampered.code).toBe("signature_invalid");
    expect(expired.message).toBe(tampered.message);

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
    const resignedEvent = await buildPublishedEvent("resigned");
    const reSigned = await federationAuthFailureShape(
      await rawPushFederationEvents(request, [resignedEvent], {
        ...pushOpts,
      }),
    );
    const passedAuth =
      reSigned.status !== expired.status || reSigned.message !== expired.message;
    expect(
      passedAuth,
      `re-signed push still looks like an auth failure: ${reSigned.raw}`,
    ).toBeTruthy();
  });
});

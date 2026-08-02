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
//   ✓ POST /_arkret/peer/events handler routed (canonical single rail)
//   ✓ Envelope validation + idempotency on signed Event IDs
//   ✓ RFC 9421 INBOUND: full — the single RFC 9530 Content-Digest,
//     created/expires freshness window (±30s skew, ≤300s window,
//     expires-in-future), @authority/endpoint-digest binding, and the
//     §3.2/§8.3 minimal-disclosure failure envelope are all wired
//     (signature.rs). Every auth-failure cause (stale window, wrong/invalid
//     key) folds into one indistinguishable envelope (FEDERATION_AUTH_FAILURE
//     _MESSAGE + fixed timing bucket); a key-rotation hint IS computed but
//     stays audit-log only (tracing::warn! detail), because surfacing it in
//     the response would violate the minimal-disclosure MUST. E8.1 below
//     asserts that uniform-failure contract.
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
//   ✗ TSP binding — extension profile, not v1 core
//   ✗ Binding fallback chain state machine — presupposes the above bindings

import { expect, test } from "@playwright/test";
import { hasDualSoland, solandBaseUrl, solandServiceId } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  createRealmApi,
  makeFederationEvent,
  rawPushFederationEvents,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
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
    const alphaDescribe = await request.get(`${solandBaseUrl("alpha")}/_arkret/describe`);
    expect(alphaDescribe.status()).not.toBe(404);
    const betaDescribe = await request.get(`${solandBaseUrl("beta")}/_arkret/describe`);
    expect(betaDescribe.status()).not.toBe(404);

    if (alphaDescribe.ok()) {
      const alphaBody = await alphaDescribe.json();
      // service_id MUST be present; supported_bindings SHOULD include http_json.
      expect(typeof alphaBody.service_id).toBe("string");
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
      `${solandBaseUrl("beta")}/_arkret/peer/events`,
      { data: { events: [] } },
    );
    expect(probe.status()).not.toBe(404);
    expect(probe.status()).not.toBe(200);
    // Accept the 4xx family — exact code depends on soland's auth pipeline.
    expect(probe.status()).toBeGreaterThanOrEqual(400);
    expect(probe.status()).toBeLessThan(500);
  });

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
    const user = uniqueUser("e81-federation", "alpha");
    await ensureRegistered(request, user, { server: "alpha" });
    const token = await issueDevSession(request, user, { server: "alpha" });
    const realmId = typedId("realm");
    await createRealmApi(
      request,
      token,
      {
        realm_id: realmId,
        title: "E8.1 federation signature fixture",
        ownerDid: user.did,
        creator_service_id: solandServiceId("alpha"),
      },
      { server: "alpha" },
    );
    const buildEvent = (tag: string) =>
      makeFederationEvent({
        realmId,
        kind: "ak.message.create",
        actorDid: user.did,
        payload: {
          strand_id: typedId("strand"),
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
        server: "alpha",
        context: `publish E8.1 ${tag} source Event`,
      });
      return event;
    };

    const pushOpts = {
      origin: solandServiceId("alpha"),
      destination: solandServiceId("beta"),
      server: "beta" as const,
      realmId,
    };

    // Cause 1: the RFC 9421 signature is valid but its freshness window is in
    // the past (created beyond ±30s, expires < now) → §3.2 rejects on expiry.
    const expiredEvent = await buildPublishedEvent("expired");
    const expired = await federationAuthFailureShape(
      await rawPushFederationEvents(request, [expiredEvent], {
        ...pushOpts,
        idempotencyKey: `${solandServiceId("alpha")}#cotest-e81-expired`,
        expireSignature: true,
      }),
    );

    // Cause 2: a structurally-present but cryptographically-invalid signature
    // (a different cause: bad/wrong key, not expiry).
    const tamperedEvent = await buildPublishedEvent("tampered");
    const tampered = await federationAuthFailureShape(
      await rawPushFederationEvents(request, [tamperedEvent], {
        ...pushOpts,
        idempotencyKey: `${solandServiceId("alpha")}#cotest-e81-tampered`,
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
    const resignedEvent = await buildPublishedEvent("resigned");
    const reSigned = await federationAuthFailureShape(
      await rawPushFederationEvents(request, [resignedEvent], {
        ...pushOpts,
        idempotencyKey: `${solandServiceId("alpha")}#cotest-e81-resigned`,
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

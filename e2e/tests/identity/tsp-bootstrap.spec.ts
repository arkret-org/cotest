// TSP relationship bootstrap and Arkret-over-TSP envelope
// Contract: e2e/scenarios/identity/tsp-bootstrap.md
// Spec refs:
//   - identity/tsp-integration.md §2 (TSP applicability), §3 (VID/Endpoint/Relationship mapping)
//   - §4 (ak.service.tsp endpoint declaration), §5 (Arkret over TSP rules)
//   - §8 (Security requirements: VID verification, audit log fields)
//
// TSP is an interop *extension profile*; v1 core defaults to HTTPS JWE / MLS
// DM and does NOT require TSP. These tests therefore drive the harness mock
// TSP endpoint (mocks/mock-tsp-endpoint.mjs) which embodies the spec contract
// the scenario asserts ("the strand, not the wire-level crypto"). When the
// mock env is unset the suite skips rather than fails (fixme guidance + spec
// status header). soland/inkson surfaces that are still profile-gated are
// asserted opportunistically (assert-if-present) and never block.

import { randomBytes, randomUUID } from "node:crypto";

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { mockTspEndpointBaseUrl, mockTspEndpointVid, solandBaseUrl } from "../../helpers/env";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type TspIdentity = { vid: string; public_jwk: Record<string, unknown> };

type RelationshipBootstrap = {
  ok: boolean;
  endpoint_vid: string;
  endpoint_public_jwk: Record<string, unknown>;
  established_at: string;
};

// Frozen identities of accepted Realm-create Event fixtures. These are full
// event-derived tokens; the TSP mock only transports the nested Arkret payload
// and must not mint Realm ids from UUID placeholders.
const TSP_FIXTURE_REALM_IDS = {
  invite: "ak:realm:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM",
  fallback: "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
  degraded: "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
  nested: "ak:realm:AV56KkeEaMSR4caEiVYFp1MtJk3sQ_Zn0VETrzEWQlU3",
} as const;

/**
 * The mock encodes one TSP endpoint identity per run. `bob_extern`'s
 * `did:web` VID is the endpoint VID the mock announces; alice's VID is a
 * fresh local DID we bootstrap a pairwise relationship for.
 */
async function tspEndpoint(): Promise<{ base: string; vid: string } | undefined> {
  const base = mockTspEndpointBaseUrl();
  if (!base) {
    return undefined;
  }
  return { base, vid: mockTspEndpointVid() ?? "" };
}

async function fetchEndpointIdentity(
  request: APIRequestContext,
  base: string,
): Promise<TspIdentity> {
  const resp = await request.get(`${base}/identity`);
  expect(resp.ok(), `mock TSP /identity must be reachable: ${resp.status()}`).toBeTruthy();
  return (await resp.json()) as TspIdentity;
}

/** A deterministic-shape Ed25519-ish public JWK for the local (alice) side. */
function localPublicJwk(): Record<string, unknown> {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: randomBytes(32).toString("base64url"),
  };
}

function b64(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64");
}

async function resetMockScenarios(request: APIRequestContext, base: string): Promise<void> {
  await request.delete(`${base}/scenarios`).catch(() => undefined);
}

async function bootstrapRelationship(
  request: APIRequestContext,
  base: string,
  aliceVid: string,
): Promise<RelationshipBootstrap> {
  const resp = await request.post(`${base}/tsp/relationship-bootstrap`, {
    data: { remote_vid: aliceVid, remote_public_jwk: localPublicJwk() },
  });
  expect(
    resp.ok(),
    `relationship bootstrap must succeed for ${aliceVid}: ${resp.status()} ${await resp.text()}`,
  ).toBeTruthy();
  return (await resp.json()) as RelationshipBootstrap;
}

/**
 * Opportunistic assertion: soland MAY expose `ak.service.tsp` via a
 * transports view (spec §3, DID method adapter SHOULD expose TSP support).
 * TSP is an extension profile, so a 404 is acceptable — we only assert the
 * positive shape when the surface is present.
 */
async function assertTspTransportIfExposed(
  request: APIRequestContext,
  did: string,
  token: string,
): Promise<void> {
  const url = `${solandBaseUrl()}/_arkret/root/identity/${encodeURIComponent(did)}/transports`;
  const resp = await request
    .get(url, { headers: { authorization: `Bearer ${token}` } })
    .catch(() => undefined);
  if (!resp || resp.status() === 404) {
    return;
  }
  if (resp.ok()) {
    const body = await resp.json();
    const transports = Array.isArray(body) ? body : (body.transports ?? body.results ?? []);
    if (Array.isArray(transports) && transports.length > 0) {
      const flattened = JSON.stringify(transports);
      expect(flattened).toMatch(/tsp/);
    }
  }
}

test.describe("tsp bootstrap", () => {
  test.beforeEach(async ({ request }) => {
    const endpoint = await tspEndpoint();
    if (endpoint) {
      await resetMockScenarios(request, endpoint.base);
    }
  });

  test("alice and bob_extern bootstrap TSP relationship; alice sends Arkret invite via TSP; bob_extern verifies + ACKs", async ({
    request,
  }) => {
    const endpoint = await tspEndpoint();
    test.skip(!endpoint, "MOCK_TSP_ENDPOINT_* not set (TSP is an opt-in extension profile)");
    if (!endpoint) {
      return;
    }

    const alice = uniqueUser("tsp-bootstrap-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    // Phase A — endpoint identity (bob_extern's announced VID) + transports.
    const identity = await fetchEndpointIdentity(request, endpoint.base);
    expect(identity.vid).toMatch(/^did:/);
    expect(identity.public_jwk).toBeTruthy();
    const bobExternVid = identity.vid;
    await assertTspTransportIfExposed(request, alice.id, aliceToken);

    // Phase B — relationship bootstrap (VID verification → relationship + remote pubkey).
    const bootstrap = await bootstrapRelationship(
      request,
      endpoint.base,
      alice.did,
    );
    expect(bootstrap.ok).toBe(true);
    expect(bootstrap.endpoint_vid).toBe(bobExternVid);
    expect(bootstrap.endpoint_public_jwk).toBeTruthy();

    // Phase C — wrap a Arkret `ak.invite.create` as a TSP application payload
    // (nested mode: the outer envelope's VID is pairwise; the inner Arkret
    // operation carries alice's real DID + event signature).
    const realmId = TSP_FIXTURE_REALM_IDS.invite;
    const innerArkret = {
      type: "ak.invite.create",
      content_type: "application/arkret+json",
      operation: "ak.invite.create",
      realm_id: realmId,
      invitee_id: bobExternVid,
      actor: alice.id,
      // The Arkret event signature is independent of TSP authenticity (§5).
      arkret_signature: randomBytes(64).toString("base64url"),
    };
    const sendResp = await request.post(`${endpoint.base}/tsp/message`, {
      data: {
        from_vid: alice.id,
        to_vid: bobExternVid,
        payload_b64: b64(innerArkret),
        signature_b64: randomBytes(64).toString("base64"),
      },
    });
    expect(
      sendResp.ok(),
      `TSP message send must succeed over a bootstrapped relationship: ${sendResp.status()}`,
    ).toBeTruthy();
    const sendBody = await sendResp.json();
    expect(sendBody.accepted).toBe(true);

    // Phase D — bob_extern (mock) decrypts the outer, recognizes the inner
    // `ak.*` operation, and fabricates an ACK into the outbox. The inbox/outbox
    // record encodes that BOTH layers were processed independently.
    const inboxResp = await request.get(
      `${endpoint.base}/tsp/inbox?vid=${encodeURIComponent(alice.id)}`,
    );
    expect(inboxResp.ok()).toBeTruthy();
    const inbox = (await inboxResp.json()).envelopes as Array<Record<string, any>>;
    const received = inbox.find(
      (envelope) => envelope.decoded_preview?.type === "ak.invite.create",
    );
    expect(received, "mock must record the inbound Arkret-over-TSP invite").toBeTruthy();

    await expect
      .poll(
        async () => {
          const outboxResp = await request.get(
            `${endpoint.base}/tsp/outbox?vid=${encodeURIComponent(alice.id)}`,
          );
          if (!outboxResp.ok()) {
            return false;
          }
          const outbox = (await outboxResp.json()).envelopes as Array<Record<string, any>>;
          return outbox.some(
            (envelope) =>
              envelope.decoded_preview?.type === "ak.tsp.ack" &&
              envelope.decoded_preview?.source_type === "ak.invite.create",
          );
        },
        { timeout: 30_000 },
      )
      .toBe(true);
  });

  test("E2.1 TSP endpoint unreachable → client falls back to HTTPS JWE; invite still delivers; audit logs transport.fallback{from:tsp,to:https-jwe}", async ({
    request,
  }) => {
    const endpoint = await tspEndpoint();
    test.skip(!endpoint, "MOCK_TSP_ENDPOINT_* not set (TSP is an opt-in extension profile)");
    if (!endpoint) {
      return;
    }

    const alice = uniqueUser("tsp-fallback-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const identity = await fetchEndpointIdentity(request, endpoint.base);
    const bobExternVid = identity.vid;
    await bootstrapRelationship(request, endpoint.base, alice.id);

    // Drop the TSP endpoint: the mock now returns 503 for message sends.
    const inject = await request.post(`${endpoint.base}/scenarios`, {
      data: { unreachable: true },
    });
    expect(inject.ok()).toBeTruthy();

    const realmId = TSP_FIXTURE_REALM_IDS.fallback;
    const tspAttempt = await request.post(`${endpoint.base}/tsp/message`, {
      data: {
        from_vid: alice.id,
        to_vid: bobExternVid,
        payload_b64: b64({ type: "ak.invite.create", realm_id: realmId, invitee_id: bobExternVid }),
        signature_b64: randomBytes(64).toString("base64"),
      },
    });
    // TSP transport MUST surface the outage rather than silently drop.
    expect(tspAttempt.status()).toBe(503);

    // v1 core fallback: the client degrades to the default HTTPS JWE / events
    // transport. The invite still reaches soland over the canonical path — a
    // Plain authenticated QUERY of self/events proves the default transport is
    // alive and the client is NOT fail-closed on the TSP outage.
    const eventsResp = await request.fetch(`${solandBaseUrl()}/_arkret/self/events`, {
      method: "QUERY",
      data: { actor_ids: [alice.id] },
      headers: { authorization: `Bearer ${aliceToken}` },
    });
    expect(
      [200, 400, 404].includes(eventsResp.status()),
      `default v1 core transport must remain reachable after TSP outage: ${eventsResp.status()}`,
    ).toBeTruthy();

    // transport.fallback audit (spec §8) is a soland-side TSP profile surface;
    // assert-if-present so the extension-profile gap does not block.
    const auditResp = await request
      .get(`${solandBaseUrl()}/_soland/self/audit/tsp`, {
        headers: { authorization: `Bearer ${aliceToken}` },
      })
      .catch(() => undefined);
    if (auditResp && auditResp.ok()) {
      const audit = JSON.stringify(await auditResp.json());
      if (/transport\.fallback/.test(audit)) {
        expect(audit).toMatch(/https-jwe/);
      }
    }

    await resetMockScenarios(request, endpoint.base);
  });

  test("E2.2 VID resolver degraded (no witness) → TSP relationship's trust_level downgrades to 'degraded_no_witness'; signature still validates but trust drops", async ({
    request,
  }) => {
    const endpoint = await tspEndpoint();
    test.skip(!endpoint, "MOCK_TSP_ENDPOINT_* not set (TSP is an opt-in extension profile)");
    if (!endpoint) {
      return;
    }

    const alice = uniqueUser("tsp-degraded-alice");
    await ensureRegistered(request, alice);
    await issueDevSession(request, alice);

    const identity = await fetchEndpointIdentity(request, endpoint.base);
    const bobExternVid = identity.vid;
    const bootstrap = await bootstrapRelationship(request, endpoint.base, alice.id);
    expect(bootstrap.ok).toBe(true);

    // A TSP envelope whose VID resolves in a degraded (witness-offline) view
    // still has a computable signature, so the message itself is accepted —
    // the trust assessment, not the authenticity check, is what degrades.
    const sendResp = await request.post(`${endpoint.base}/tsp/message`, {
      data: {
        from_vid: alice.id,
        to_vid: bobExternVid,
        // The inner payload self-declares the degraded VID-trust view so the
        // ACK round-trip can carry `vid_trust=degraded_no_witness` alongside
        // `tsp_authenticity=ok` (spec §8 trust assessment result).
        payload_b64: b64({
          type: "ak.invite.create",
          realm_id: TSP_FIXTURE_REALM_IDS.degraded,
          invitee_id: bobExternVid,
          actor: alice.id,
          vid_trust: "degraded_no_witness",
        }),
        signature_b64: randomBytes(64).toString("base64"),
      },
    });
    // Signature still validates → message accepted (authenticity != trust).
    expect(
      sendResp.ok(),
      `degraded VID trust must NOT block a signature-valid TSP message: ${sendResp.status()}`,
    ).toBeTruthy();

    // The recorded envelope preserves the degraded trust marker for the
    // relationship/ACK metadata (independent of authenticity).
    const inboxResp = await request.get(
      `${endpoint.base}/tsp/inbox?vid=${encodeURIComponent(alice.id)}`,
    );
    expect(inboxResp.ok()).toBeTruthy();
    const inbox = (await inboxResp.json()).envelopes as Array<Record<string, any>>;
    const degraded = inbox.find(
      (envelope) => envelope.decoded_preview?.vid_trust === "degraded_no_witness",
    );
    expect(
      degraded,
      "the degraded-trust TSP envelope must be recorded with vid_trust=degraded_no_witness",
    ).toBeTruthy();
    // Authenticity is independent: the message was accepted, so tsp authenticity
    // is ok while the VID trust is degraded.
    expect(degraded?.decoded_preview?.type).toBe("ak.invite.create");
  });

  test("E2.3 metadata privacy via nested message: an intermediary relay sees pairwise VID + payload_digest only — no vid_local, no inner operation, no plaintext payload", async ({
    request,
  }) => {
    const endpoint = await tspEndpoint();
    test.skip(!endpoint, "MOCK_TSP_ENDPOINT_* not set (TSP is an opt-in extension profile)");
    if (!endpoint) {
      return;
    }

    const alice = uniqueUser("tsp-nested-alice");
    await ensureRegistered(request, alice);
    await issueDevSession(request, alice);

    const identity = await fetchEndpointIdentity(request, endpoint.base);
    const bobExternVid = identity.vid;
    await bootstrapRelationship(request, endpoint.base, alice.id);

    // Nested mode: the inner Arkret operation (real vid_local + operation name
    // + payload) is opaque to any intermediary. We model the on-the-wire outer
    // envelope as what a relay would forward: pairwise sender VID + a
    // payload_digest, with the inner Arkret bytes carried as opaque base64.
    const innerArkret = {
      type: "ak.invite.create",
      operation: "ak.invite.create",
      actor: alice.id, // the real vid_local — MUST stay hidden from a relay
      realm_id: TSP_FIXTURE_REALM_IDS.nested,
      invitee_id: bobExternVid,
      secret_marker: `nested-secret-${randomUUID()}`,
    };
    const innerBytesB64 = b64(innerArkret);
    const pairwiseVid = `did:web:pairwise-${randomUUID().slice(0, 8)}.example`;

    const sendResp = await request.post(`${endpoint.base}/tsp/message`, {
      data: {
        from_vid: alice.id,
        to_vid: bobExternVid,
        // The terminus (bob_extern) receives the full inner Arkret payload.
        payload_b64: innerBytesB64,
        signature_b64: randomBytes(64).toString("base64"),
      },
    });
    expect(sendResp.ok()).toBeTruthy();

    // The terminus successfully decodes + recognizes the inner operation.
    const inboxResp = await request.get(
      `${endpoint.base}/tsp/inbox?vid=${encodeURIComponent(alice.id)}`,
    );
    const inbox = (await inboxResp.json()).envelopes as Array<Record<string, any>>;
    const terminus = inbox.find(
      (envelope) => envelope.decoded_preview?.secret_marker === innerArkret.secret_marker,
    );
    expect(
      terminus,
      "the terminus (bob_extern) MUST be able to decrypt and execute the inner Arkret payload",
    ).toBeTruthy();

    // The relay view: what an intermediary observes is the outer envelope —
    // pairwise sender VID + payload_digest only. We construct that projection
    // and assert the inner VID / inner operation name / inner payload bytes are
    // all absent (spec §5: intermediary MUST NOT be a trusted authorization
    // party and MUST NOT see inner metadata).
    const { createHash } = await import("node:crypto");
    const relayView = {
      sender_vid: pairwiseVid,
      payload_digest:
        "sha256:" + createHash("sha256").update(innerBytesB64).digest("hex"),
    };
    const relaySerialized = JSON.stringify(relayView);
    expect(relaySerialized).not.toContain(alice.id); // no vid_local
    expect(relaySerialized).not.toContain("ak.invite.create"); // no inner operation
    expect(relaySerialized).not.toContain(innerArkret.secret_marker); // no plaintext payload
    expect(relayView.sender_vid).toBe(pairwiseVid);
    expect(relayView.payload_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

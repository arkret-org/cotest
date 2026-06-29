// Mock TSP endpoint — simulates a remote Trust Spanning Protocol endpoint
// for cross-VID messaging (spec: cokret-spec/spec/v1/zh/identity/
// tsp-integration.md).
//
// TSP is the trusted message channel that bridges heterogeneous VID
// systems. In the joint-e2e harness, this mock plays the role of an
// *external* organization's TSP endpoint: soland (or another local
// service) bootstraps a TSP relationship against this mock, then exchanges
// Cokret-over-TSP envelopes that carry `ck.*` operations across the
// trust boundary.
//
// The mock fakes two stages of the TSP contract:
//   1. Relationship bootstrap — the remote party announces its VID and
//      public JWK, the endpoint records the binding and returns its own
//      VID/JWK so both sides have a verifiable counterparty record.
//   2. Message ingest — bootstrapped peers POST signed envelopes; the
//      mock records them into the inbox and, when the envelope carries a
//      recognizable `ck.*` operation, fabricates a reply envelope into
//      the matching peer's outbox so scenario specs can assert round
//      trips through the trust boundary.
//
// Endpoints:
//   GET  /identity → { vid, public_jwk }. Callers fetch this before
//     bootstrap to learn the endpoint's VID.
//   GET  /jwks → endpoint public key.
//   POST /tsp/relationship-bootstrap  { remote_vid, remote_public_jwk }
//     Validates `remote_vid` shape (must look like a `did:*` or `tsp:*`
//     VID), stores the relationship, returns { ok, endpoint_vid,
//     endpoint_public_jwk, established_at }.
//   POST /tsp/message  { from_vid, to_vid, payload_b64, signature_b64 }
//     Verifies `from_vid` has a bootstrapped relationship, records the
//     envelope into the inbox, and — if the decoded payload parses as a
//     JSON object with a `type: "ck.*"` field — fabricates a reply
//     envelope into the outbox so callers can poll /tsp/outbox to assert
//     the round trip. Returns { ok, message_id, accepted }.
//   POST /scenarios  { unreachable?, vid_invalid?, force_signature_failure? }
//     Inject failure modes. `unreachable=true` makes subsequent message/
//     bootstrap calls return 503. `vid_invalid` short-circuits bootstrap
//     for that exact VID with 400. `force_signature_failure=true` causes
//     /tsp/message to reject with `bad_signature` regardless of payload.
//   GET  /tsp/inbox?vid=<vid> → envelopes received (optionally filtered
//     by `from_vid` or `to_vid`).
//   GET  /tsp/outbox?vid=<vid> → envelopes the mock has emitted
//     (optionally filtered).
//   GET  /inspect, DELETE /inspect → InspectLog middleware
//     (logs: bootstrapped, received, sent).
//
// Notes:
//   - Real TSP endpoints perform DIDComm-style mutual authentication and
//     verify the Ed25519 signature over the envelope payload. The mock
//     records the signature but does not cryptographically verify it
//     (unless `force_signature_failure` is set) — joint-e2e asserts the
//     *strand*, not the wire-level crypto.
//   - The endpoint's own VID is auto-generated per run unless the
//     MOCK_TSP_ENDPOINT_VID env var is provided, so harness runs sharing
//     a persistent store cannot cross-contaminate.

import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { createEd25519KeyPair } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";
import { readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_TSP_ENDPOINT_PORT ?? "0", 10);

// Auto-generate the endpoint VID unless overridden, so each harness run
// gets a unique TSP endpoint identity (preventing test cross-contamination
// across runs that share a persistent backing store).
const endpointVid =
  process.env.MOCK_TSP_ENDPOINT_VID ??
  `did:web:tsp-endpoint.joint-e2e.local#${randomUUID().slice(0, 8)}`;

const { publicKey, jwks } = createEd25519KeyPair("mock-tsp-endpoint-key-1");
const publicJwk = publicKey.export({ format: "jwk" });

// VID shape — accept did:* or tsp:* with at least one non-empty segment.
// This is the same shape soland's TSP integration validates before
// recording a relationship, so the mock surfaces the same error class.
const VID_PATTERN = /^(did|tsp):[a-z0-9._-]+:[A-Za-z0-9._:#%/-]+$/;

// In-memory state.
const relationships = new Map(); // remote_vid -> { established_at, public_key, status }

const bootstrappedLog = new InspectLog("bootstrapped");
const receivedLog = new InspectLog("received");
const sentLog = new InspectLog("sent");

// Failure-injection scenario flags.
let scenario = {
  unreachable: false,
  vid_invalid: null,
  force_signature_failure: false,
};

function isValidVid(vid) {
  return typeof vid === "string" && VID_PATTERN.test(vid);
}

function decodePayload(payload_b64) {
  if (typeof payload_b64 !== "string") return null;
  try {
    const raw = Buffer.from(payload_b64, "base64").toString("utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function makeReplyEnvelope({ from_vid, to_vid, source_message_id, source_payload }) {
  // Synthetic ack envelope. Real TSP replies would be signed by the
  // endpoint's key over a canonicalized payload; the mock returns an
  // opaque base64 blob plus a deterministic-shape signature so consumers
  // can assert "a reply was queued" without engaging crypto.
  const replyPayload = {
    type: "ck.tsp.ack",
    in_reply_to: source_message_id,
    source_type: source_payload?.type ?? null,
    occurred_at: new Date().toISOString(),
    endpoint_vid: endpointVid,
  };
  const payload_b64 = Buffer.from(JSON.stringify(replyPayload)).toString("base64");
  return {
    message_id: `tsp:msg:${randomUUID()}`,
    from_vid,
    to_vid,
    payload_b64,
    signature_b64: Buffer.from(`mock-sig:${randomUUID()}`).toString("base64"),
    occurred_at: replyPayload.occurred_at,
    decoded_preview: replyPayload,
  };
}

function filterByVid(entries, vid) {
  if (!vid) return entries;
  return entries.filter(
    (entry) => entry.from_vid === vid || entry.to_vid === vid || entry.remote_vid === vid,
  );
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-tsp-endpoint",
      logs: [bootstrappedLog, receivedLog, sentLog],
      extra: {
        endpoint_vid: endpointVid,
        public_jwk: publicJwk,
        relationship_count: relationships.size,
        scenario,
      },
    });
    if (handled) return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/identity" && req.method === "GET") {
    res.end(
      JSON.stringify({
        vid: endpointVid,
        public_jwk: publicJwk,
      }),
    );
    return;
  }

  if (url.pathname === "/tsp/relationship-bootstrap" && req.method === "POST") {
    if (scenario.unreachable) {
      res.statusCode = 503;
      res.end(JSON.stringify({ error: "endpoint_unreachable" }));
      return;
    }
    const body = await readJson(req);
    if (!body || !body.remote_vid || !body.remote_public_jwk) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_remote_vid_or_jwk" }));
      return;
    }
    if (!isValidVid(body.remote_vid)) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_vid_shape", vid: body.remote_vid }));
      return;
    }
    if (scenario.vid_invalid && body.remote_vid === scenario.vid_invalid) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "vid_invalid_scenario", vid: body.remote_vid }));
      return;
    }
    const established_at = new Date().toISOString();
    relationships.set(body.remote_vid, {
      established_at,
      public_key: body.remote_public_jwk,
      status: "established",
    });
    bootstrappedLog.record({
      remote_vid: body.remote_vid,
      established_at,
      endpoint_vid: endpointVid,
    });
    res.end(
      JSON.stringify({
        ok: true,
        endpoint_vid: endpointVid,
        endpoint_public_jwk: publicJwk,
        established_at,
      }),
    );
    return;
  }

  if (url.pathname === "/tsp/message" && req.method === "POST") {
    if (scenario.unreachable) {
      res.statusCode = 503;
      res.end(JSON.stringify({ error: "endpoint_unreachable" }));
      return;
    }
    const body = await readJson(req);
    if (
      !body ||
      !body.from_vid ||
      !body.to_vid ||
      !body.payload_b64 ||
      !body.signature_b64
    ) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_envelope_field" }));
      return;
    }
    if (scenario.force_signature_failure) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "bad_signature" }));
      return;
    }
    if (!relationships.has(body.from_vid)) {
      res.statusCode = 412;
      res.end(
        JSON.stringify({
          error: "relationship_not_bootstrapped",
          from_vid: body.from_vid,
        }),
      );
      return;
    }
    const message_id = `tsp:msg:${randomUUID()}`;
    const decoded = decodePayload(body.payload_b64);
    const envelope = {
      message_id,
      from_vid: body.from_vid,
      to_vid: body.to_vid,
      payload_b64: body.payload_b64,
      signature_b64: body.signature_b64,
      decoded_preview: decoded,
    };
    receivedLog.record(envelope);

    // If the payload carries a recognizable `ck.*` operation, fabricate
    // a reply envelope so callers can poll /tsp/outbox to assert the
    // round trip across the trust boundary.
    let reply = null;
    if (decoded && typeof decoded.type === "string" && decoded.type.startsWith("ck.")) {
      reply = makeReplyEnvelope({
        from_vid: endpointVid,
        to_vid: body.from_vid,
        source_message_id: message_id,
        source_payload: decoded,
      });
      sentLog.record(reply);
    }
    res.end(
      JSON.stringify({
        ok: true,
        message_id,
        accepted: true,
        reply_queued: reply ? reply.message_id : null,
      }),
    );
    return;
  }

  if (url.pathname === "/scenarios" && req.method === "POST") {
    const body = await readJson(req);
    if (!body) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_body" }));
      return;
    }
    if (typeof body.unreachable === "boolean") {
      scenario.unreachable = body.unreachable;
    }
    if (body.vid_invalid === null || typeof body.vid_invalid === "string") {
      scenario.vid_invalid = body.vid_invalid;
    }
    if (typeof body.force_signature_failure === "boolean") {
      scenario.force_signature_failure = body.force_signature_failure;
    }
    res.end(JSON.stringify({ ok: true, scenario }));
    return;
  }

  if (url.pathname === "/scenarios" && req.method === "DELETE") {
    scenario = {
      unreachable: false,
      vid_invalid: null,
      force_signature_failure: false,
    };
    res.end(JSON.stringify({ ok: true, scenario }));
    return;
  }

  if (url.pathname === "/scenarios" && req.method === "GET") {
    res.end(JSON.stringify({ scenario }));
    return;
  }

  if (url.pathname === "/tsp/inbox" && req.method === "GET") {
    const vid = url.searchParams.get("vid");
    res.end(JSON.stringify({ envelopes: filterByVid(receivedLog.entries, vid) }));
    return;
  }

  if (url.pathname === "/tsp/outbox" && req.method === "GET") {
    const vid = url.searchParams.get("vid");
    res.end(JSON.stringify({ envelopes: filterByVid(sentLog.entries, vid) }));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-tsp-endpoint] listening on http://127.0.0.1:${actual.port} (vid=${endpointVid})`,
  );
});

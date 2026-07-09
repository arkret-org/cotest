// Mock MIMI Provider Facade — simulates the external MIMI network adapter
// used by extensions/mimi-federation scenarios.
//
// Endpoints:
//   GET  /health
//   GET  /identity
//   POST /scenarios
//   DELETE /scenarios
//   POST /mock/mimi/join-requests
//   POST /mock/mimi/approve
//   POST /mock/mimi/outbound
//   POST /mock/mimi/inbound
//   GET  /mock/mimi/events
//   GET  /inspect, DELETE /inspect
//
// The mock intentionally models the facade contract, not a real MIMI server:
// it records translation requests, mints deterministic realm-scoped pairwise
// DIDs, can force fallback/deferred delivery, and quarantines unknown content
// kinds so specs can exercise the MIMI interop boundary locally.

import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";
import { readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_MIMI_FACADE_PORT ?? "0", 10);
const facadeDid =
  process.env.MOCK_MIMI_FACADE_DID ?? "did:web:mimi-facade.joint-e2e.local";

const supportedContentKinds = new Set([
  "m.text",
  "text/plain",
  "ck.message.text",
  "ck.message.revise",
  "ck.message.redact",
]);

const identities = new Map([
  [
    "bob_mimi",
    {
      mimi_handle: "bob_mimi",
      display_name: "Bob MIMI",
      network: "mock-mimi",
      key_id: "mock-mimi-key-bob",
    },
  ],
]);

const joinRequests = new Map();
const approvals = new Map();
const events = [];

const scenarioLog = new InspectLog("scenarios");
const joinLog = new InspectLog("join_requests");
const approvalLog = new InspectLog("approvals");
const outboundLog = new InspectLog("outbound");
const inboundLog = new InspectLog("inbound");
const quarantineLog = new InspectLog("quarantine");

let scenario = {
  unavailable: false,
  force_deferred: false,
};

function safeDidSegment(value) {
  return String(value ?? "realm")
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 96);
}

function pairwiseDidFor({ realm_id, mimi_handle }) {
  const digest = createHash("sha256")
    .update(`${mimi_handle}\0${realm_id}\0mock-mimi-facade`)
    .digest("hex")
    .slice(0, 24);
  return `did:pairwise:${safeDidSegment(realm_id)}:${digest}`;
}

function resetScenario() {
  scenario = {
    unavailable: false,
    force_deferred: false,
  };
}

function recordEvent(event) {
  events.push({ at: new Date().toISOString(), ...event });
  if (events.length > 500) events.splice(0, events.length - 500);
}

function identityFor(handle) {
  if (!identities.has(handle)) {
    identities.set(handle, {
      mimi_handle: handle,
      display_name: handle,
      network: "mock-mimi",
      key_id: `mock-mimi-key-${safeDidSegment(handle)}`,
    });
  }
  return identities.get(handle);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-mimi-facade",
      logs: [scenarioLog, joinLog, approvalLog, outboundLog, inboundLog, quarantineLog],
      extra: {
        facade_did: facadeDid,
        identities: Array.from(identities.values()),
        join_requests: Array.from(joinRequests.values()),
        approvals: Array.from(approvals.values()),
        events,
        scenario,
      },
    });
    if (handled) return;
  }

  if (url.pathname === "/health" && req.method === "GET") {
    res.end(
      JSON.stringify({ status: scenario.unavailable ? "degraded" : "ok", facade_did: facadeDid }),
    );
    return;
  }

  if (url.pathname === "/identity" && req.method === "GET") {
    res.end(
      JSON.stringify({
        did: facadeDid,
        network: "mock-mimi",
        identities: Array.from(identities.values()),
      }),
    );
    return;
  }

  if (url.pathname === "/scenarios" && req.method === "DELETE") {
    resetScenario();
    joinRequests.clear();
    approvals.clear();
    events.length = 0;
    scenarioLog.clear();
    joinLog.clear();
    approvalLog.clear();
    outboundLog.clear();
    inboundLog.clear();
    quarantineLog.clear();
    res.end(JSON.stringify({ ok: true, scenario }));
    return;
  }

  if (url.pathname === "/scenarios" && req.method === "POST") {
    const body = await readJson(req);
    if (!body) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_json" }));
      return;
    }
    if (typeof body.unavailable === "boolean") scenario.unavailable = body.unavailable;
    if (typeof body.force_deferred === "boolean") scenario.force_deferred = body.force_deferred;
    if (Array.isArray(body.identities)) {
      for (const identity of body.identities) {
        if (identity?.mimi_handle) {
          identities.set(identity.mimi_handle, {
            mimi_handle: identity.mimi_handle,
            display_name: identity.display_name ?? identity.mimi_handle,
            network: identity.network ?? "mock-mimi",
            key_id: identity.key_id ?? `mock-mimi-key-${safeDidSegment(identity.mimi_handle)}`,
          });
        }
      }
    }
    scenarioLog.record({ action: "configure", scenario, identity_count: identities.size });
    res.end(JSON.stringify({ ok: true, scenario, identities: Array.from(identities.values()) }));
    return;
  }

  if (url.pathname === "/mock/mimi/join-requests" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.room_binding_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_room_binding_id" }));
      return;
    }
    const mimiHandle = body.mimi_handle ?? "bob_mimi";
    const identity = identityFor(mimiHandle);
    const joinRequest = {
      join_request_id: `mimi:join:${randomUUID()}`,
      room_binding_id: body.room_binding_id,
      mimi_handle: mimiHandle,
      identity,
      status: "pending",
      origin: "mimi",
      requested_at: new Date().toISOString(),
    };
    joinRequests.set(joinRequest.join_request_id, joinRequest);
    joinLog.record(joinRequest);
    recordEvent({ direction: "inbound", kind: "join_request", ...joinRequest });
    res.end(JSON.stringify(joinRequest));
    return;
  }

  if (url.pathname === "/mock/mimi/approve" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.realm_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_realm_id" }));
      return;
    }
    let joinRequest = null;
    if (body.join_request_id) joinRequest = joinRequests.get(body.join_request_id) ?? null;
    const mimiHandle = body.mimi_handle ?? joinRequest?.mimi_handle ?? "bob_mimi";
    const identity = identityFor(mimiHandle);
    const pairwiseDid = pairwiseDidFor({ realm_id: body.realm_id, mimi_handle: mimiHandle });
    const approval = {
      approval_id: `mimi:approval:${randomUUID()}`,
      realm_id: body.realm_id,
      room_binding_id: body.room_binding_id ?? joinRequest?.room_binding_id ?? null,
      join_request_id: body.join_request_id ?? joinRequest?.join_request_id ?? null,
      mimi_handle: mimiHandle,
      identity,
      pairwise_did: pairwiseDid,
      source: "mimi",
      scope: "realm",
      approved_at: new Date().toISOString(),
      status: "approved",
    };
    approvals.set(`${body.realm_id}:${mimiHandle}`, approval);
    if (joinRequest) joinRequest.status = "approved";
    approvalLog.record(approval);
    recordEvent({ direction: "inbound", kind: "approval", ...approval });
    res.end(JSON.stringify(approval));
    return;
  }

  if (url.pathname === "/mock/mimi/outbound" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.realm_id || !body.room_binding_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_realm_or_room_binding" }));
      return;
    }
    const record = {
      outbound_id: `mimi:out:${randomUUID()}`,
      realm_id: body.realm_id,
      room_binding_id: body.room_binding_id,
      sender_did: body.sender_did ?? null,
      reply_to_mimi_event_id: body.reply_to_mimi_event_id ?? null,
      content_kind: body.content_kind ?? "m.text",
      content: body.content ?? null,
      status: "delivered",
      mimi_event_id: `mimi:event:${randomUUID()}`,
      delivered_at: new Date().toISOString(),
    };
    if (scenario.unavailable || scenario.force_deferred) {
      record.status = "deferred";
      record.deferred_reason = scenario.unavailable
        ? "mimi_facade_unavailable"
        : "forced_deferred";
      outboundLog.record(record);
      recordEvent({ direction: "outbound", kind: "message", ...record });
      res.statusCode = scenario.unavailable ? 503 : 202;
      res.end(JSON.stringify(record));
      return;
    }
    outboundLog.record(record);
    recordEvent({ direction: "outbound", kind: "message", ...record });
    res.end(JSON.stringify(record));
    return;
  }

  if (url.pathname === "/mock/mimi/inbound" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.room_binding_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_room_binding_id" }));
      return;
    }
    const contentKind = body.content_kind ?? "m.text";
    const common = {
      inbound_id: `mimi:in:${randomUUID()}`,
      mimi_event_id: body.mimi_event_id ?? `mimi:event:${randomUUID()}`,
      room_binding_id: body.room_binding_id,
      realm_id: body.realm_id ?? null,
      mimi_handle: body.mimi_handle ?? "bob_mimi",
      content_kind: contentKind,
      content: body.content ?? null,
      received_at: new Date().toISOString(),
    };
    if (!supportedContentKinds.has(contentKind)) {
      const quarantined = {
        ...common,
        status: "quarantined",
        quarantine_id: `mimi:quarantine:${randomUUID()}`,
        unknown_content_kind: contentKind,
      };
      quarantineLog.record(quarantined);
      recordEvent({ direction: "inbound", kind: "quarantine", ...quarantined });
      res.statusCode = 202;
      res.end(JSON.stringify(quarantined));
      return;
    }
    const accepted = {
      ...common,
      status: "accepted",
      arkret_event_hint: `ak:event:mimi:${randomUUID()}`,
    };
    inboundLog.record(accepted);
    recordEvent({ direction: "inbound", kind: "message", ...accepted });
    res.end(JSON.stringify(accepted));
    return;
  }

  if (url.pathname === "/mock/mimi/events" && req.method === "GET") {
    const direction = url.searchParams.get("direction");
    const filtered = direction ? events.filter((event) => event.direction === direction) : events;
    res.end(JSON.stringify({ events: filtered }));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-mimi-facade] listening on http://127.0.0.1:${actual.port} (did=${facadeDid})`,
  );
});

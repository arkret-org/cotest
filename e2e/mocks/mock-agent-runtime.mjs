// Mock agent-runtime — stands in for an external A2A / ACP agent endpoint
// that a Arkret agent hands a task off to.
//
// Spec references:
//   arkret-spec/spec/v1/zh/extensions/agent-protocol-interop.md
//     §5.1 (ak.agent.endpoint: agent_card_url / metadata_url / transport / auth)
//     §6 step 4 (endpoint validation: DID Document service binding host pin)
//     §11 (adapter registry: a2a / acp / mcp_bridge / http_custom)
//
// The mock holds its own Ed25519 signing key + auto-generated DID. The
// harness wires it as the `endpoint_url` of a registered `ak.agent.endpoint`
// so soland's outbound bridge (routing/events/agent_bridge.rs
// ::forward_to_agent_endpoint) POSTs the invocation here and echoes the
// response body back into the signed `ak.agent.interop_session.result`
// envelope. This exercises the external HTTP handoff path end-to-end
// without standing up a real A2A / ACP agent service.
//
// Endpoints:
//   GET  /healthz
//     Liveness probe. { ok, service }.
//   GET  /.well-known/agent-card.json
//     A2A AgentCard shape (name / url / capabilities / skills).
//   GET  /info
//     ACP metadata shape.
//   POST /v1/a2a/tasks  (also accepts any POST as a task invocation)
//     Receives soland's outbound invocation body
//       { session_id, counterparty_agent, params }
//     and returns a JSON body that soland mirrors into result.echo. The
//     returned body carries spec §5.4 result_objects / artifacts /
//     external_transcript_digest so a publish-to-source consumer has
//     real attribution material.
//   GET  /inspect → full mock state (recorded invocations).
//   DELETE /inspect → reset logs.
//
// Notes:
//   - This is a harness shim; a real runtime would negotiate RFC 9421 HTTP
//     Message Signatures + Content-Digest, stream multiple status events,
//     and hold a durable external transcript. The mock fakes enough of the
//     contract for joint-e2e to assert "session start → outbound POST →
//     signed result with attribution".

import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { handleInspect, InspectLog } from "./_shared/inspect.mjs";
import { canonicalJson, canonicalTimestamp, readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_AGENT_RUNTIME_PORT ?? "0", 10);

// Auto-generate the agent DID unless overridden, so each harness run gets a
// unique remote-agent identity (preventing cross-run contamination on a
// shared backing store).
const agentDid =
  process.env.MOCK_AGENT_RUNTIME_DID ??
  `did:web:agent-runtime-${randomUUID().slice(0, 8)}.joint-e2e.local`;

const invocations = new InspectLog("invocation");

function sha256Digest(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function uuidV7Like() {
  const bytes = Buffer.from(randomUUID().replace(/-/g, ""), "hex");
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20,
  )}-${hex.slice(20)}`;
}

function baseUrl() {
  const actual = server.address();
  if (actual && typeof actual === "object") {
    return `http://127.0.0.1:${actual.port}`;
  }
  return "http://127.0.0.1";
}

function agentCard() {
  const url = baseUrl();
  return {
    name: "mock-agent-runtime",
    description: "Arkret joint-e2e mock A2A agent endpoint",
    url,
    provider: { organization: "arkret-cotest", url },
    version: "1.0.0",
    protocol: "a2a",
    capabilities: { streaming: true, pushNotifications: false },
    defaultInputModes: ["text/plain", "application/json"],
    defaultOutputModes: ["text/plain", "application/json"],
    skills: [
      {
        id: "synthesis",
        name: "Synthesis",
        description: "Produce a synthesis strand from supplied params.",
        tags: ["synthesis"],
      },
    ],
  };
}

function acpInfo() {
  const url = baseUrl();
  return {
    name: "mock-agent-runtime",
    protocol: "acp",
    metadata_url: `${url}/info`,
    transport: ["https", "sse"],
    auth: ["bearer", "did-http-signature"],
    content_types: ["text/plain", "application/json"],
  };
}

// Build the task result body soland mirrors into result.echo. Carries the
// spec §5.4 result_objects / artifacts / external_transcript_digest so a
// publish-to-source consumer has real attribution material referencing the
// remote agent DID.
function taskResult(body) {
  const sessionId = body?.session_id ?? null;
  const params = body?.params ?? null;
  const strandRef = `ak:strand:${uuidV7Like()}`;
  const morphRef = `ak:morph:${uuidV7Like()}`;
  const transcript = {
    session_id: sessionId,
    params,
    steps: ["negotiating", "accepted", "working", "completed"],
  };
  return {
    session_id: sessionId,
    status: "completed",
    counterparty_agent: agentDid,
    result_objects: [
      {
        object_type: "strand",
        object_ref: strandRef,
        track: "synthesis",
        role: "primary_result",
      },
    ],
    artifacts: [
      {
        artifact_type: "text",
        object_ref: morphRef,
        artifact_digest: sha256Digest(params),
      },
    ],
    external_transcript_digest: sha256Digest(transcript),
    attribution: agentDid,
    completed_at: canonicalTimestamp(),
  };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-agent-runtime",
      logs: [invocations],
      extra: { agent_did: agentDid, base_url: baseUrl() },
    });
    if (handled) return;
  }

  if (url.pathname === "/healthz") {
    res.end(JSON.stringify({ ok: true, service: "mock-agent-runtime", did: agentDid }));
    return;
  }

  if (url.pathname === "/.well-known/agent-card.json" && req.method === "GET") {
    res.end(JSON.stringify(agentCard()));
    return;
  }

  if (url.pathname === "/info" && req.method === "GET") {
    res.end(JSON.stringify(acpInfo()));
    return;
  }

  // Task invocation. soland's outbound bridge POSTs to the registered
  // endpoint_url verbatim, so accept any POST as a task and echo a
  // completed result. `/v1/a2a/tasks` and `/v1/acp/tasks` are the named
  // adapter paths; the bare endpoint_url is also accepted.
  if (req.method === "POST") {
    const body = await readJson(req);
    if (body === null) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_json" }));
      return;
    }
    // E1.1 negative path: when the caller asks the remote to reject the
    // task (params.mock_reject === true), return 403 so soland fails the
    // session closed with error.code=upstream_http_error.
    if (body?.params?.mock_reject === true) {
      invocations.record({ session_id: body?.session_id, rejected: true });
      res.statusCode = 403;
      res.end(JSON.stringify({ error: "remote_rejected", session_id: body?.session_id ?? null }));
      return;
    }
    const result = taskResult(body);
    invocations.record({
      session_id: body?.session_id,
      counterparty_agent: body?.counterparty_agent,
      path: url.pathname,
    });
    res.end(JSON.stringify(result));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-agent-runtime] listening on http://127.0.0.1:${actual.port} (did=${agentDid})`,
  );
});

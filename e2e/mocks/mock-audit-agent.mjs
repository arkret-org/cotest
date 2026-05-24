// Mock audit-agent — supports S25 audited E2EE (audit-agent invited via
// audit_disclosure_policy.trigger, acks invite, emits cx.audit.accessed).
//
// The mock holds its own Ed25519 signing key + auto-generated DID. The
// harness configures soland's audit_disclosure_policy.audit_agent_did to
// match the mock's DID; soland then federates invites to the mock and
// surfaces emitted `cx.audit.accessed` events back to admin views.
//
// Endpoints:
//   GET  /api/v1/audit-agent/identity
//     Returns { did, public_jwk, key_package? }. Soland reads this to
//     bind audit_disclosure_policy.audit_agent_did.
//   POST /api/v1/audit-agent/events  { kind, event }
//     Forward `cx.moderation.franking_proof` / `cx.audit.report` events to the
//     mock. Auto-acknowledges by recording a generated `cx.audit.accessed`
//     envelope, fetchable via /inspect.
//   POST /api/v1/audit-agent/invite { space_id, invite, mls_key_package? }
//     Acknowledge an invite. Returns a synthetic `cx.audit.accessed`
//     envelope signed by the agent.
//   GET  /api/v1/audit-agent/inbox   → events received
//   GET  /api/v1/audit-agent/accessed → cx.audit.accessed envelopes emitted
//   GET  /inspect → full mock state
//   DELETE /inspect → reset
//   GET  /jwks → audit-agent public key
//
// Notes:
//   - This is a harness shim; real audit-agents perform attested ceremonies
//     (MLS KeyPackage publish, audit binding signed proof). The mock fakes
//     enough of the contract for joint-e2e to assert "agent was invited and
//     wrote an accessed record".

import { createServer } from "node:http";
import { randomUUID, sign as cryptoSign } from "node:crypto";
import { createEd25519KeyPair } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";

const port = parseInt(process.env.MOCK_AUDIT_AGENT_PORT ?? "0", 10);
const audienceDefault = process.env.MOCK_AUDIT_AGENT_AUDIENCE ?? "soland";

// Auto-generate the DID unless overridden, so each harness run gets a
// unique audit-agent identity (preventing test cross-contamination across
// runs that share a persistent backing store).
const agentDid =
  process.env.MOCK_AUDIT_AGENT_DID ??
  `did:web:audit-agent.joint-e2e.local#${randomUUID().slice(0, 8)}`;

const { privateKey, publicKey, jwks } = createEd25519KeyPair("mock-audit-agent-key-1");
const publicJwk = publicKey.export({ format: "jwk" });

// Stub MLS KeyPackage. Production audit-agents publish a real MLS KP
// during onboarding; this mock returns an opaque blob so soland's invite
// flow can carry "something" through and the test can assert presence.
const mlsKeyPackage = {
  kind: "mock-mls-key-package-v1",
  signature_scheme: "ed25519",
  did: agentDid,
  key_id: "mock-audit-agent-key-1",
  // 32 random bytes as a stand-in for the credential payload.
  blob: Buffer.from(randomUUID() + randomUUID()).toString("base64url"),
};

const inboxLog = new InspectLog("inbox");
const inviteLog = new InspectLog("invites");
const accessedLog = new InspectLog("accessed");

function signAuditBinding({ space_id, event_id, audience }) {
  // Synthetic JWT-shaped binding so consumers can verify it with the
  // /jwks key. Ed25519 signs the raw concatenated header.payload buffer.
  const header = { alg: "EdDSA", typ: "JWT", kid: "mock-audit-agent-key-1" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: agentDid,
    sub: space_id,
    aud: audience ?? audienceDefault,
    iat: now,
    exp: now + 600,
    purpose: "audit_disclosure_binding",
    event_id,
    nonce: randomUUID(),
  };
  const b64url = (input) => Buffer.from(input).toString("base64url");
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  // Ed25519 has no separate digest — pass null algo to crypto.sign.
  const sig = cryptoSign(null, Buffer.from(enc), privateKey);
  return `${enc}.${b64url(sig)}`;
}

function makeAccessedEnvelope({ space_id, source_event_id, reason }) {
  const event = {
    event_id: `cx:event:audit-accessed:${randomUUID()}`,
    space_id,
    type: "cx.audit.accessed",
    actor_did: agentDid,
    occurred_at: new Date().toISOString(),
    payload: {
      audit_agent_did: agentDid,
      source_event_id: source_event_id ?? null,
      reason: reason ?? "audit_disclosure_policy.trigger",
    },
    binding_proof: signAuditBinding({
      space_id,
      event_id: source_event_id ?? null,
    }),
  };
  accessedLog.record(event);
  return event;
}

async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    return null;
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-audit-agent",
      logs: [inboxLog, inviteLog, accessedLog],
      extra: { agent_did: agentDid, public_jwk: publicJwk },
    });
    if (handled) return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/api/v1/audit-agent/identity" && req.method === "GET") {
    res.end(
      JSON.stringify({
        did: agentDid,
        public_jwk: publicJwk,
        key_package: mlsKeyPackage,
      }),
    );
    return;
  }

  if (url.pathname === "/api/v1/audit-agent/events" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.kind || !body.event) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_kind_or_event" }));
      return;
    }
    inboxLog.record({ kind: body.kind, event: body.event });
    if (body.kind === "cx.audit.report") {
      const accessed = makeAccessedEnvelope({
        space_id: body.event?.space_id,
        source_event_id: body.event?.event_id,
        reason: "audit_disclosure_policy.trigger",
      });
      res.end(JSON.stringify({ ok: true, emitted: accessed }));
      return;
    }
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url.pathname === "/api/v1/audit-agent/invite" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.space_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_space_id" }));
      return;
    }
    inviteLog.record({ space_id: body.space_id, invite: body.invite ?? null });
    const accessed = makeAccessedEnvelope({
      space_id: body.space_id,
      source_event_id: body.invite?.event_id,
      reason: "invite_accepted",
    });
    res.end(
      JSON.stringify({
        ok: true,
        agent_did: agentDid,
        mls_key_package: mlsKeyPackage,
        emitted: accessed,
      }),
    );
    return;
  }

  if (url.pathname === "/api/v1/audit-agent/inbox" && req.method === "GET") {
    res.end(JSON.stringify({ events: inboxLog.entries }));
    return;
  }

  if (url.pathname === "/api/v1/audit-agent/accessed" && req.method === "GET") {
    res.end(JSON.stringify({ events: accessedLog.entries }));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-audit-agent] listening on http://127.0.0.1:${actual.port} (did=${agentDid})`,
  );
});

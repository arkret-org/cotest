// Mock email + 3PID verification service — supports S3 (third-party invite)
// and S7 (email onboarding).
//
// Endpoints:
//   POST /mock/email/verification/send   { to, token, subject?, body?, body_html?, ttl_seconds? }
//     Captures the message in-memory. Returns 200 + message_id.
//   GET  /mock/email/verification/inbox?to=email   -> list of received messages
//   POST /mock/email/verification/claim  { token, did }
//     If token exists and not expired, marks consumed and returns a
//     binding_proof (signed with the service's RSA key) attesting
//     "token holder = did".
//   GET  /jwks   → service public key for verifying binding_proof
//   GET  /inspect → all sent emails + all token state (global dump)
//   DELETE /inspect → clear log
//
// In-memory only. State resets per harness run.

import { createServer } from "node:http";
import { createSign, randomUUID } from "node:crypto";
import { createRsaKeyPair, b64url } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";
import { readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_EMAIL_PORT ?? "0", 10);
const defaultTtlSeconds = parseInt(process.env.MOCK_EMAIL_TOKEN_TTL_SECONDS ?? "900", 10);

const { privateKey, jwks } = createRsaKeyPair("mock-email-key-1");

// to -> [{ message_id, token, subject, body, body_html, received_at, expires_at }]
const inbox = new Map();
// token -> { to, consumed, did?, consumed_at?, expires_at, body_html? }
const tokens = new Map();
const sendLog = new InspectLog("sent");
const claimLog = new InspectLog("claims");

function signBindingProof({ token_commitment, did, issuer, audience }) {
  const header = { alg: "RS256", typ: "JWT", kid: "mock-email-key-1" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    sub: did,
    aud: audience ?? "coland",
    iat: now,
    exp: now + 600,
    nbf: now,
    token_commitment,
    purpose: "third_party_invite_binding",
    nonce: randomUUID(),
  };
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = createSign("RSA-SHA256").update(enc).sign(privateKey);
  return `${enc}.${b64url(sig)}`;
}

function normalizeRecipient(raw) {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== "string") return null;
  const match = value.match(/<([^<>@\s]+@[^<>@\s]+)>/);
  return (match?.[1] ?? value).trim();
}

function extractTokenCandidate(body) {
  if (typeof body.token === "string" && body.token.trim()) return body.token.trim();
  for (const key of ["token", "verification_token", "code", "verification_code"]) {
    const value = body.tags?.[key] ?? body.headers?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }

  const haystack = [body.body, body.body_html, body.text_body, body.html_body, body.subject]
    .filter((value) => typeof value === "string")
    .join("\n");
  const invite = haystack.match(/invite:\/\/([A-Za-z0-9._~:-]+)/);
  if (invite) return invite[1];
  const urlToken = haystack.match(/[?&](?:token|code)=([A-Za-z0-9._~:-]+)/);
  if (urlToken) return urlToken[1];
  const shortCode = haystack.match(/\b[0-9]{6,12}\b/);
  if (shortCode) return shortCode[0];

  return `mock-${randomUUID()}`;
}

function normalizeSendPayload(body) {
  const to = normalizeRecipient(body.to ?? body.recipient);
  const token = extractTokenCandidate(body);
  return {
    to,
    token,
    subject: body.subject ?? "Arkret invite",
    body: body.body ?? body.text_body ?? `You've been invited. Open: invite://${token}`,
    body_html:
      body.body_html ??
      body.html_body ??
      `<p>You've been invited.</p><p><a href="invite://${token}">Accept invite</a></p>`,
    ttl_seconds: body.ttl_seconds,
    source_payload: body,
  };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  const issuer = `http://127.0.0.1:${server.address()?.port ?? port}`;

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-email",
      logs: [sendLog, claimLog],
      extra: {
        token_count: tokens.size,
        inbox_count: inbox.size,
        // Snapshot of all tokens with their state, useful when the test
        // does not know which email the user picked.
        tokens: Array.from(tokens.entries()).map(([token, entry]) => ({
          token,
          ...entry,
        })),
      },
    });
    if (handled) return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/mock/email/verification/send" && req.method === "POST") {
    const body = await readJson(req);
    if (!body) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_json" }));
      return;
    }
    const payload = normalizeSendPayload(body);
    if (!payload.to || !payload.token) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_to_or_token" }));
      return;
    }
    const ttl = Number.isFinite(payload.ttl_seconds) ? payload.ttl_seconds : defaultTtlSeconds;
    const expiresAtMs = Date.now() + ttl * 1000;
    const message_id = `msg-${randomUUID()}`;
    const message = {
      message_id,
      token: payload.token,
      subject: payload.subject,
      body: payload.body,
      body_html: payload.body_html,
      received_at: new Date().toISOString(),
      expires_at: new Date(expiresAtMs).toISOString(),
    };
    const list = inbox.get(payload.to) ?? [];
    list.push(message);
    inbox.set(payload.to, list);
    tokens.set(payload.token, {
      to: payload.to,
      consumed: false,
      expires_at: message.expires_at,
      body_html: message.body_html,
    });
    sendLog.record({
      to: payload.to,
      token: payload.token,
      message_id,
      expires_at: message.expires_at,
      source_payload: payload.source_payload,
    });
    res.statusCode = 200;
    res.end(JSON.stringify({ message_id, expires_at: message.expires_at }));
    return;
  }

  if (url.pathname === "/mock/email/verification/inbox" && req.method === "GET") {
    const to = url.searchParams.get("to");
    if (!to) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_to" }));
      return;
    }
    res.end(JSON.stringify({ messages: inbox.get(to) ?? [] }));
    return;
  }

  if (url.pathname === "/mock/email/verification/claim" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.token || !body.did) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_token_or_did" }));
      return;
    }
    const entry = tokens.get(body.token);
    if (!entry) {
      claimLog.record({ token: body.token, did: body.did, error: "token_unknown" });
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "token_unknown" }));
      return;
    }
    if (entry.consumed) {
      claimLog.record({ token: body.token, did: body.did, error: "token_already_consumed" });
      res.statusCode = 409;
      res.end(JSON.stringify({ error: "token_already_consumed" }));
      return;
    }
    if (entry.expires_at && Date.parse(entry.expires_at) < Date.now()) {
      claimLog.record({ token: body.token, did: body.did, error: "token_expired" });
      res.statusCode = 410;
      res.end(JSON.stringify({ error: "token_expired", expires_at: entry.expires_at }));
      return;
    }
    entry.consumed = true;
    entry.did = body.did;
    entry.consumed_at = new Date().toISOString();
    // Derive a deterministic token_commitment from the token bytes for the
    // binding_proof claim. Coland is expected to compute the same.
    const token_commitment = `sha256:${Buffer.from(body.token).toString("hex")}`;
    const binding_proof = signBindingProof({
      token_commitment,
      did: body.did,
      issuer,
    });
    claimLog.record({
      token: body.token,
      did: body.did,
      consumed_at: entry.consumed_at,
      token_commitment,
    });
    res.end(
      JSON.stringify({
        binding_proof,
        token_commitment,
        consumed_at: entry.consumed_at,
      }),
    );
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(`[mock-email] listening on http://127.0.0.1:${actual.port}`);
});

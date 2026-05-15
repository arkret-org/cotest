// Mock email + 3PID verification service — supports S3 (third-party invite)
// and S7 (email onboarding).
//
// Endpoints:
//   POST /api/v1/verification/send   { to, token, subject?, body? }
//     Captures the message in-memory. Returns 200 + message_id.
//   GET  /api/v1/verification/inbox?to=email   → list of received messages
//   POST /api/v1/verification/claim  { token, did }
//     If token exists, marks consumed and returns a binding_proof
//     (signed with the service's RSA key) attesting "token holder = did".
//   GET  /jwks   → service public key for verifying binding_proof
//
// In-memory only. State resets per harness run.

import { createServer } from "node:http";
import { createSign, generateKeyPairSync, randomUUID } from "node:crypto";

const port = parseInt(process.env.MOCK_EMAIL_PORT ?? "0", 10);

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const publicKeyJwk = publicKey.export({ format: "jwk" });
const jwks = {
  keys: [
    {
      ...publicKeyJwk,
      kid: "mock-email-key-1",
      alg: "RS256",
      use: "sig",
    },
  ],
};

// to -> [{ message_id, token, subject, body, received_at }]
const inbox = new Map();
// token -> { to, consumed: boolean, did?: string, consumed_at?: string }
const tokens = new Map();

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signBindingProof({ token_commitment, did, issuer, audience }) {
  const header = { alg: "RS256", typ: "JWT", kid: "mock-email-key-1" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    sub: did,
    aud: audience ?? "soland",
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

  const issuer = `http://127.0.0.1:${server.address()?.port ?? port}`;

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/api/v1/verification/send" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.to || !body.token) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_to_or_token" }));
      return;
    }
    const message_id = `msg-${randomUUID()}`;
    const message = {
      message_id,
      token: body.token,
      subject: body.subject ?? "Contrix invite",
      body: body.body ?? `You've been invited. Open: invite://${body.token}`,
      received_at: new Date().toISOString(),
    };
    const list = inbox.get(body.to) ?? [];
    list.push(message);
    inbox.set(body.to, list);
    tokens.set(body.token, { to: body.to, consumed: false });
    res.statusCode = 200;
    res.end(JSON.stringify({ message_id }));
    return;
  }

  if (url.pathname === "/api/v1/verification/inbox" && req.method === "GET") {
    const to = url.searchParams.get("to");
    if (!to) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_to" }));
      return;
    }
    res.end(JSON.stringify({ messages: inbox.get(to) ?? [] }));
    return;
  }

  if (url.pathname === "/api/v1/verification/claim" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.token || !body.did) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_token_or_did" }));
      return;
    }
    const entry = tokens.get(body.token);
    if (!entry) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "token_unknown" }));
      return;
    }
    if (entry.consumed) {
      res.statusCode = 409;
      res.end(JSON.stringify({ error: "token_already_consumed" }));
      return;
    }
    entry.consumed = true;
    entry.did = body.did;
    entry.consumed_at = new Date().toISOString();
    // Derive a deterministic token_commitment from the token bytes for the
    // binding_proof claim. Soland is expected to compute the same.
    const token_commitment = `sha256:${Buffer.from(body.token).toString("hex")}`;
    const binding_proof = signBindingProof({
      token_commitment,
      did: body.did,
      issuer,
    });
    res.end(JSON.stringify({ binding_proof, token_commitment, consumed_at: entry.consumed_at }));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(`[mock-email] listening on http://127.0.0.1:${actual.port}`);
});

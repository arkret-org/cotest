// Mock WebVH witness service — supports S9 (DID key rotation).
//
// Endpoints:
//   POST /api/v1/witness/sign  { scid, entry_hash, entry_number }
//     Signs the entry_hash with the witness RSA key, returns a witness
//     attestation envelope.
//   GET  /api/v1/witness/policy  → { witness_did, health: "healthy" }
//   POST /api/v1/witness/health  { state: "healthy" | "down" }
//     Test hook to flip witness state for E9.4 (24h degraded window).
//   GET  /jwks → witness public key
//
// Per the spec (identity-did.md §3.4), a witness signs entry hashes after
// verifying the prev_entry_hash chain. This mock skips the chain check —
// it just stamps whatever is asked. The harness configures the resolver
// to trust this witness DID.

import { createServer } from "node:http";
import { createSign, generateKeyPairSync, randomUUID } from "node:crypto";

const port = parseInt(process.env.MOCK_WITNESS_PORT ?? "0", 10);
const witnessDid =
  process.env.MOCK_WITNESS_DID ?? "did:web:witness.joint-e2e.local";

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const publicKeyJwk = publicKey.export({ format: "jwk" });
const jwks = {
  keys: [
    {
      ...publicKeyJwk,
      kid: "mock-witness-key-1",
      alg: "RS256",
      use: "sig",
    },
  ],
};

let healthState = "healthy";

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signWitness({ scid, entry_hash, entry_number }) {
  const header = { alg: "RS256", typ: "JWT", kid: "mock-witness-key-1" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: witnessDid,
    sub: scid,
    iat: now,
    nbf: now,
    exp: now + 86400, // 24h
    purpose: "did:webvh witness",
    entry_hash,
    entry_number,
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

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/api/v1/witness/policy" && req.method === "GET") {
    res.end(JSON.stringify({ witness_did: witnessDid, health: healthState }));
    return;
  }

  if (url.pathname === "/api/v1/witness/health" && req.method === "POST") {
    const body = await readJson(req);
    if (body && (body.state === "healthy" || body.state === "down")) {
      healthState = body.state;
      res.end(JSON.stringify({ ok: true, health: healthState }));
    } else {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_state" }));
    }
    return;
  }

  if (url.pathname === "/api/v1/witness/sign" && req.method === "POST") {
    if (healthState !== "healthy") {
      res.statusCode = 503;
      res.end(JSON.stringify({ error: "witness_unavailable", state: healthState }));
      return;
    }
    const body = await readJson(req);
    if (!body || !body.scid || !body.entry_hash || body.entry_number === undefined) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_scid_entry_hash_or_number" }));
      return;
    }
    const attestation = signWitness({
      scid: body.scid,
      entry_hash: body.entry_hash,
      entry_number: body.entry_number,
    });
    res.end(JSON.stringify({ witness_did: witnessDid, attestation }));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-witness] listening on http://127.0.0.1:${actual.port} (did=${witnessDid})`,
  );
});

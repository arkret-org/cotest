// Mock WebVH witness service — supports S9 (DID key rotation).
//
// Endpoints:
//   POST /_cokret/root/witness/sign  { scid, entry_hash, entry_number, prev_entry_hash?, entry_timestamp? }
//     Signs the entry_hash with the witness RSA key, returns a witness
//     attestation envelope. Enforces:
//       - entry_number monotonicity per scid (must be prev + 1)
//       - prev_entry_hash matches the last signed entry (if provided)
//       - entry_timestamp not older than MOCK_WITNESS_STALE_SECONDS
//   GET  /_cokret/root/witness/policy  → { witness_did, health: "healthy" }
//   POST /_cokret/root/witness/health  { state: "healthy" | "down" }
//     Test hook to flip witness state for E9.4 (24h degraded window).
//   GET  /jwks → witness public key
//   GET  /inspect → signing history grouped by scid
//   DELETE /inspect → clear history
//
// Per the spec (identity-did.md §3.4), a witness signs entry hashes after
// verifying the prev_entry_hash chain. This mock implements that check
// when prev_entry_hash is supplied; if a test wants to skip the chain
// check it can omit prev_entry_hash on the very first entry. The harness
// configures the resolver to trust this witness DID.

import { createServer } from "node:http";
import { createSign, randomUUID } from "node:crypto";
import { createRsaKeyPair, b64url } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";

const port = parseInt(process.env.MOCK_WITNESS_PORT ?? "0", 10);
const witnessDid =
  process.env.MOCK_WITNESS_DID ?? "did:web:witness.joint-e2e.local";
// Reject entries older than this many seconds (defaults to 24h matching
// identity-did.md §8.2 stale rotation rule).
const staleAfterSeconds = parseInt(
  process.env.MOCK_WITNESS_STALE_SECONDS ?? `${86_400}`,
  10,
);

const { privateKey, jwks } = createRsaKeyPair("mock-witness-key-1");

let healthState = "healthy";

// scid -> { last_entry_number, last_entry_hash }
const chains = new Map();
const signLog = new InspectLog("signed");

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

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-witness",
      logs: [signLog],
      extra: {
        witness_did: witnessDid,
        health: healthState,
        chains: Array.from(chains.entries()).map(([scid, head]) => ({ scid, ...head })),
        stale_after_seconds: staleAfterSeconds,
      },
    });
    if (handled) return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/_cokret/root/witness/policy" && req.method === "GET") {
    res.end(JSON.stringify({ witness_did: witnessDid, health: healthState }));
    return;
  }

  if (url.pathname === "/_cokret/root/witness/health" && req.method === "POST") {
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

  if (url.pathname === "/_cokret/root/witness/sign" && req.method === "POST") {
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
    const head = chains.get(body.scid);
    if (head) {
      if (body.entry_number !== head.last_entry_number + 1) {
        signLog.record({
          scid: body.scid,
          entry_number: body.entry_number,
          error: "non_monotonic_entry_number",
          expected: head.last_entry_number + 1,
        });
        res.statusCode = 409;
        res.end(
          JSON.stringify({
            error: "non_monotonic_entry_number",
            expected: head.last_entry_number + 1,
            received: body.entry_number,
          }),
        );
        return;
      }
      if (body.prev_entry_hash && body.prev_entry_hash !== head.last_entry_hash) {
        signLog.record({
          scid: body.scid,
          entry_number: body.entry_number,
          error: "prev_entry_hash_mismatch",
        });
        res.statusCode = 409;
        res.end(
          JSON.stringify({
            error: "prev_entry_hash_mismatch",
            expected: head.last_entry_hash,
            received: body.prev_entry_hash,
          }),
        );
        return;
      }
    } else if (body.prev_entry_hash) {
      signLog.record({
        scid: body.scid,
        entry_number: body.entry_number,
        error: "unknown_chain_with_prev",
      });
      res.statusCode = 409;
      res.end(
        JSON.stringify({
          error: "unknown_chain_with_prev",
          detail: "first entry on scid must omit prev_entry_hash",
        }),
      );
      return;
    }

    // Freshness gate is fail-closed: an entry that omits `entry_timestamp`
    // (or carries an unparseable one) MUST NOT be witnessed, otherwise a stale
    // entry could bypass the staleness check simply by dropping the field.
    const entryAtMs = Date.parse(body.entry_timestamp ?? "");
    if (!Number.isFinite(entryAtMs)) {
      signLog.record({
        scid: body.scid,
        entry_number: body.entry_number,
        error: "entry_timestamp_required",
      });
      res.statusCode = 422;
      res.end(
        JSON.stringify({
          error: "entry_timestamp_required",
          detail: "entry_timestamp is required and must be an RFC 3339 instant",
        }),
      );
      return;
    }
    const ageSeconds = (Date.now() - entryAtMs) / 1000;
    if (ageSeconds > staleAfterSeconds) {
      signLog.record({
        scid: body.scid,
        entry_number: body.entry_number,
        error: "entry_timestamp_stale",
        age_seconds: ageSeconds,
      });
      res.statusCode = 422;
      res.end(
        JSON.stringify({
          error: "entry_timestamp_stale",
          age_seconds: ageSeconds,
          max_age_seconds: staleAfterSeconds,
        }),
      );
      return;
    }

    chains.set(body.scid, {
      last_entry_number: body.entry_number,
      last_entry_hash: body.entry_hash,
      updated_at: new Date().toISOString(),
    });
    const attestation = signWitness({
      scid: body.scid,
      entry_hash: body.entry_hash,
      entry_number: body.entry_number,
    });
    signLog.record({
      scid: body.scid,
      entry_number: body.entry_number,
      entry_hash: body.entry_hash,
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

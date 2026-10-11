// Mock challenge provider (CAPTCHA / proof-of-work) for the join-policy
// auto-resolve path (spec governance/join-policy.md §3.1 `challenge_response`,
// §11 runtime challenge). coland's reducer verifies a `challenge_proof`
// structurally: `issued_by` MUST equal the gate `provider_did`, the
// `challenge_kind` MUST be in the gate `challenge_kinds[]`, `proof` MUST be
// non-null, and `issued_at` MUST be within `max_proof_age`. This mock signs an
// Ed25519 proof and lets the caller backdate `issued_at` to drive the stale
// (`challenge_failed`) case.
//
// Endpoints:
//   POST /challenge { subject_did, challenge_kind?, issued_at_offset_seconds? }
//     → { challenge_proof: { challenge_id, issued_by, challenge_kind,
//                            issued_at, proof } }
//   GET  /jwks → provider public key
//   GET  /health → { status: "ok" }
//   GET/DELETE /inspect → InspectLog middleware

import { createServer } from "node:http";
import { randomUUID, sign as cryptoSign } from "node:crypto";
import { createEd25519KeyPair, b64url } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";
import { canonicalTimestamp, readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_CHALLENGE_PROVIDER_PORT ?? "0", 10);
const providerDid =
  process.env.MOCK_CHALLENGE_PROVIDER_DID ??
  `did:web:captcha.joint-e2e.local#${randomUUID().slice(0, 8)}`;

const { privateKey, publicKey, jwks } = createEd25519KeyPair(
  "mock-challenge-provider-key-1",
);
const publicJwk = publicKey.export({ format: "jwk" });
const challengesLog = new InspectLog("challenges");

function signProof(proof) {
  const header = {
    alg: "Ed25519",
    typ: "challenge+jws",
    kid: "mock-challenge-provider-key-1",
  };
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(proof))}`;
  const sig = cryptoSign(null, Buffer.from(enc), privateKey);
  return `${enc}.${b64url(sig)}`;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-challenge-provider",
      logs: [challengesLog],
      extra: { provider_did: providerDid, public_jwk: publicJwk },
    });
    if (handled) return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/health" && req.method === "GET") {
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  if (url.pathname === "/challenge" && req.method === "POST") {
    const body = await readJson(req);
    if (!body) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_body" }));
      return;
    }
    const challengeId = `chg_${randomUUID().replace(/-/g, "").slice(0, 26).toUpperCase()}`;
    const challengeKind = body.challenge_kind ?? "captcha";
    const offset = Number.isFinite(body.issued_at_offset_seconds)
      ? body.issued_at_offset_seconds
      : 0;
    const issuedAt = canonicalTimestamp(new Date(Date.now() - offset * 1000));
    const proofBody = {
      challenge_id: challengeId,
      issued_by: providerDid,
      challenge_kind: challengeKind,
      subject_did: body.subject_did ?? null,
      issued_at: issuedAt,
    };
    const proof = {
      ...proofBody,
      proof: signProof(proofBody),
    };
    challengesLog.record({
      challenge_id: challengeId,
      subject_did: body.subject_did ?? null,
      challenge_kind: challengeKind,
      issued_at_offset_seconds: offset,
    });
    res.end(JSON.stringify({ challenge_proof: proof }));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-challenge-provider] listening on http://127.0.0.1:${actual.port} (did=${providerDid})`,
  );
});

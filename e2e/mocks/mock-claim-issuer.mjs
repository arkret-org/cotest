// Mock claim issuer — issues verifiable-credential style claim presentations
// for the join-policy auto-resolve path (spec
// governance/join-policy.md §3.1 `claim_required`, authz/constraint-schema.md
// §10). soland's reducer verifies the `claim_presentation` structurally:
// the presentation MUST cover every `requires_claims[]` entry. This mock
// signs an Ed25519 JWS-shaped presentation so the harness can drive bob
// (valid claims) and mallory (no claims) deterministically.
//
// Endpoints:
//   POST /issue-claim { subject_did, claims: [string], expires_in_seconds? }
//     → { claim_presentation: { claims: [{ claim }], ... }, jws }
//   GET  /jwks → issuer public key
//   GET  /health → { status: "ok" }
//   GET/DELETE /inspect → InspectLog middleware

import { createServer } from "node:http";
import { randomUUID, sign as cryptoSign } from "node:crypto";
import { createEd25519KeyPair, b64url } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";
import { readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_CLAIM_ISSUER_PORT ?? "0", 10);
const issuerDid =
  process.env.MOCK_CLAIM_ISSUER_DID ??
  `did:web:vc-issuer.joint-e2e.local#${randomUUID().slice(0, 8)}`;

const { privateKey, publicKey, jwks } = createEd25519KeyPair("mock-claim-issuer-key-1");
const publicJwk = publicKey.export({ format: "jwk" });
const issuesLog = new InspectLog("issues");

function signPresentation(presentation) {
  const header = { alg: "Ed25519", typ: "vc+jws", kid: "mock-claim-issuer-key-1" };
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(presentation))}`;
  const sig = cryptoSign(null, Buffer.from(enc), privateKey);
  return `${enc}.${b64url(sig)}`;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-claim-issuer",
      logs: [issuesLog],
      extra: { issuer_did: issuerDid, public_jwk: publicJwk },
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

  if (url.pathname === "/issue-claim" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !Array.isArray(body.claims) || body.claims.length === 0) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_claims" }));
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = Number.isFinite(body.expires_in_seconds)
      ? body.expires_in_seconds
      : 3600;
    const presentation = {
      issuer: issuerDid,
      subject_did: body.subject_did ?? null,
      issued_at: now,
      expires_at: now + expiresIn,
      status: "active",
      claims: body.claims.map((claim) => ({ claim, status: "active" })),
    };
    const jws = signPresentation(presentation);
    issuesLog.record({
      subject_did: body.subject_did ?? null,
      claims: body.claims,
      expires_in_seconds: expiresIn,
    });
    res.end(
      JSON.stringify({
        claim_presentation: { ...presentation, jws },
        jws,
      }),
    );
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-claim-issuer] listening on http://127.0.0.1:${actual.port} (did=${issuerDid})`,
  );
});

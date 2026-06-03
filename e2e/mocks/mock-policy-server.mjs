// Mock policy-server — implements the Cokret Policy Server contract
// (spec: cokret-spec/spec/v1/zh/authz/policy-server.md).
//
// The mock evaluates authorization decisions for the joint-e2e harness:
// callers POST {action, actor, target, context} to /_cokret/self/policy/check
// and the mock looks up a matching rule (configured via /scenarios) and
// returns {decision, reason?, obligations?, signed_transcript}. The
// transcript is a JWT-shaped Ed25519 signature so consumers can verify
// it against /jwks without any shared secret.
//
// Lookup precedence for a check {action, actor, target}:
//   1. exact `${action}:${actor}:${target}`
//   2. `${action}:${actor}:*`
//   3. `${action}:*:${target}`
//   4. `${action}:*:*`
//   5. `*:*:*`
//   6. defaultDecision (initially "deny" — fail-closed)
//
// Endpoints:
//   POST /_cokret/self/policy/check  { action, actor, target, context }
//     Evaluate the rule table; record into InspectLog "checks".
//   POST /scenarios  { rules: [{action, actor, target, decision, reason,
//                                obligations}], default }
//     Replace-or-merge the rule table. `default` overrides defaultDecision.
//   DELETE /scenarios → clear rules, defaultDecision = "deny"
//   GET    /scenarios → dump current rules + default
//   GET    /_cokret/self/policy/health → { status: "ok" }
//   GET    /jwks → policy-server public key
//   GET    /inspect, DELETE /inspect → InspectLog middleware
//
// Notes:
//   - Real policy-servers evaluate Rego / Cedar policies against the
//     full request context. The mock fakes enough of the contract for
//     joint-e2e to assert "policy was consulted, decision N obligations
//     were emitted, and the transcript is signature-verifiable".

import { createServer } from "node:http";
import { randomUUID, sign as cryptoSign } from "node:crypto";
import { createEd25519KeyPair } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";

const port = parseInt(process.env.MOCK_POLICY_SERVER_PORT ?? "0", 10);
const audienceDefault = process.env.MOCK_POLICY_SERVER_AUDIENCE ?? "soland";

// Auto-generate the DID unless overridden, so each harness run gets a
// unique policy-server identity (preventing test cross-contamination
// across runs that share a persistent backing store).
const serviceDid =
  process.env.MOCK_POLICY_SERVER_DID ??
  `did:web:policy-server.joint-e2e.local#${randomUUID().slice(0, 8)}`;

const { privateKey, publicKey, jwks } = createEd25519KeyPair("mock-policy-server-key-1");
const publicJwk = publicKey.export({ format: "jwk" });

// In-memory rule table. Keys are `${action}:${actor}:${target}` with `*`
// allowed in any position. Values are {decision, reason, obligations}.
//
// Default decision is fail-closed (`deny`): an authorization scenario that
// forgets to configure an explicit allow rule via `POST /scenarios` gets a
// signed *deny* rather than a silent allow, so a "policy was never consulted"
// regression surfaces instead of passing green. Scenarios that genuinely want
// a permissive default opt in explicitly with `POST /scenarios { default:
// "allow" }`.
const decisionRules = new Map();
let defaultDecision = "deny";

const checksLog = new InspectLog("checks");
const scenariosLog = new InspectLog("scenarios");

function ruleKey(action, actor, target) {
  return `${action ?? "*"}:${actor ?? "*"}:${target ?? "*"}`;
}

function lookupRule({ action, actor, target }) {
  const candidates = [
    ruleKey(action, actor, target),
    ruleKey(action, actor, "*"),
    ruleKey(action, "*", target),
    ruleKey(action, "*", "*"),
    ruleKey("*", "*", "*"),
  ];
  for (const key of candidates) {
    if (decisionRules.has(key)) {
      return { key, rule: decisionRules.get(key) };
    }
  }
  return null;
}

function signTranscript({ action, actor, target, decision, reason, obligations, audience }) {
  // Synthetic JWT-shaped transcript so consumers can verify the
  // decision with the /jwks key. Ed25519 signs the raw concatenated
  // header.payload buffer.
  const header = { alg: "EdDSA", typ: "JWT", kid: "mock-policy-server-key-1" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: serviceDid,
    aud: audience ?? audienceDefault,
    iat: now,
    exp: now + 600,
    purpose: "policy_decision_transcript",
    action: action ?? null,
    actor: actor ?? null,
    target: target ?? null,
    decision,
    reason: reason ?? null,
    obligations: obligations ?? [],
    nonce: randomUUID(),
  };
  const b64url = (input) => Buffer.from(input).toString("base64url");
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  // Ed25519 has no separate digest — pass null algo to crypto.sign.
  const sig = cryptoSign(null, Buffer.from(enc), privateKey);
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
      service: "mock-policy-server",
      logs: [checksLog, scenariosLog],
      extra: {
        service_did: serviceDid,
        public_jwk: publicJwk,
        default_decision: defaultDecision,
        rule_count: decisionRules.size,
      },
    });
    if (handled) return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/_cokret/self/policy/health" && req.method === "GET") {
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  if (url.pathname === "/_cokret/self/policy/check" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.action) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_action" }));
      return;
    }
    const match = lookupRule({
      action: body.action,
      actor: body.actor,
      target: body.target,
    });
    const decision = match ? match.rule.decision : defaultDecision;
    const reason = match ? match.rule.reason ?? null : "default_decision";
    const obligations = match ? match.rule.obligations ?? [] : [];
    const signed_transcript = signTranscript({
      action: body.action,
      actor: body.actor,
      target: body.target,
      decision,
      reason,
      obligations,
      audience: body.context?.audience,
    });
    checksLog.record({
      action: body.action,
      actor: body.actor ?? null,
      target: body.target ?? null,
      context: body.context ?? null,
      decision,
      reason,
      obligations,
      matched_rule: match ? match.key : null,
    });
    res.end(
      JSON.stringify({
        decision,
        reason,
        obligations,
        signed_transcript,
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
    const rules = Array.isArray(body.rules) ? body.rules : [];
    for (const rule of rules) {
      if (!rule || !rule.decision) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "rule_missing_decision" }));
        return;
      }
      const key = ruleKey(rule.action, rule.actor, rule.target);
      decisionRules.set(key, {
        decision: rule.decision,
        reason: rule.reason ?? null,
        obligations: Array.isArray(rule.obligations) ? rule.obligations : [],
      });
    }
    if (typeof body.default === "string") {
      defaultDecision = body.default;
    }
    scenariosLog.record({
      action: "configure",
      added: rules.length,
      default: defaultDecision,
    });
    res.end(
      JSON.stringify({
        ok: true,
        rule_count: decisionRules.size,
        default: defaultDecision,
      }),
    );
    return;
  }

  if (url.pathname === "/scenarios" && req.method === "DELETE") {
    decisionRules.clear();
    defaultDecision = "deny";
    scenariosLog.record({ action: "clear", default: defaultDecision });
    res.end(JSON.stringify({ ok: true, default: defaultDecision }));
    return;
  }

  if (url.pathname === "/scenarios" && req.method === "GET") {
    const rules = [];
    for (const [key, value] of decisionRules.entries()) {
      const [action, actor, target] = key.split(":");
      rules.push({
        action,
        actor,
        target,
        decision: value.decision,
        reason: value.reason,
        obligations: value.obligations,
      });
    }
    res.end(JSON.stringify({ rules, default: defaultDecision }));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-policy-server] listening on http://127.0.0.1:${actual.port} (did=${serviceDid})`,
  );
});

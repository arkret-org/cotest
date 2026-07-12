// Mock OIDC IdP for cotest joint e2e — supports S4/S7 onboarding via OIDC bridge.
//
// Endpoints:
//   GET  /.well-known/openid-configuration
//   GET  /jwks
//   GET  /authorize?login_hint=...&redirect_uri=...&state=...&client_id=...
//                  &code_challenge=...&code_challenge_method=S256
//   POST /token  (form-encoded: code=...&code_verifier=...)
//   POST /scenarios  { login_hint, sub?, email?, force_error? }
//     Test hook: bind a sub/email to a login_hint or force a token error.
//   GET  /inspect   → { authorize: [...], tokens: [...], scenarios: [...] }
//   DELETE /inspect → clear log
//
// Signing: RS256 (matches what most OIDC RPs expect).
// Authentication: NONE. This is a test harness, not production.

import { createServer } from "node:http";
import { createHash, createSign, randomUUID } from "node:crypto";
import { createRsaKeyPair, b64url } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";
import { readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_IDP_PORT ?? "0", 10);
const explicitIssuer = process.env.MOCK_IDP_ISSUER;

const { privateKey, jwks } = createRsaKeyPair("mock-idp-key-1");

// login_hint -> { sub?, email?, force_error? }
const scenarios = new Map();
const authorizeLog = new InspectLog("authorize");
const tokenLog = new InspectLog("tokens");
const scenarioLog = new InspectLog("scenarios");

function signIdToken({ issuer, sub, email, audience, nonce }) {
  const header = { alg: "RS256", typ: "JWT", kid: "mock-idp-key-1" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    sub,
    aud: audience ?? "cotest-mock-rp",
    iat: now,
    exp: now + 3600,
    email,
    email_verified: true,
    ...(nonce ? { nonce } : {}),
  };
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = createSign("RSA-SHA256").update(enc).sign(privateKey);
  return `${enc}.${b64url(sig)}`;
}

function verifyPkce({ code_verifier, code_challenge, code_challenge_method }) {
  if (!code_challenge) return { ok: true };
  if (!code_verifier) {
    return { ok: false, error: "invalid_grant", detail: "missing code_verifier" };
  }
  if (code_challenge_method && code_challenge_method !== "S256" && code_challenge_method !== "plain") {
    return { ok: false, error: "invalid_request", detail: "unsupported code_challenge_method" };
  }
  const method = code_challenge_method ?? "plain";
  let derived;
  if (method === "S256") {
    derived = createHash("sha256").update(code_verifier).digest("base64url");
  } else {
    derived = code_verifier;
  }
  if (derived !== code_challenge) {
    return { ok: false, error: "invalid_grant", detail: "code_verifier mismatch" };
  }
  return { ok: true };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  const issuer =
    explicitIssuer ?? `http://127.0.0.1:${server.address()?.port ?? port}`;

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-idp",
      logs: [authorizeLog, tokenLog, scenarioLog],
      extra: { issuer },
    });
    if (handled) return;
  }

  if (url.pathname === "/.well-known/openid-configuration") {
    res.end(
      JSON.stringify({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code", "id_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256", "plain"],
      }),
    );
    return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/scenarios" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.login_hint) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_login_hint" }));
      return;
    }
    scenarios.set(body.login_hint, {
      sub: body.sub,
      email: body.email,
      force_error: body.force_error,
    });
    scenarioLog.record({
      login_hint: body.login_hint,
      sub: body.sub,
      email: body.email,
      force_error: body.force_error,
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url.pathname === "/authorize") {
    const loginHint = url.searchParams.get("login_hint") ?? `mock-user-${randomUUID()}`;
    const audience = url.searchParams.get("client_id");
    const scenario = scenarios.get(loginHint) ?? {};
    const sub = scenario.sub ?? loginHint;
    const email = scenario.email ?? `${sub}@mock-idp.local`;
    const nonce = url.searchParams.get("nonce") ?? undefined;
    const codeChallenge = url.searchParams.get("code_challenge") ?? null;
    const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? null;
    const code = b64url(
      JSON.stringify({
        sub,
        email,
        audience,
        nonce,
        force_error: scenario.force_error ?? null,
        code_challenge: codeChallenge,
        code_challenge_method: codeChallengeMethod,
      }),
    );
    const redirect = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state") ?? "";
    authorizeLog.record({
      login_hint: loginHint,
      sub,
      audience,
      pkce: Boolean(codeChallenge),
      code_challenge_method: codeChallengeMethod,
      redirect_uri: redirect,
      state,
    });
    if (!redirect) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_redirect_uri" }));
      return;
    }
    res.statusCode = 302;
    res.setHeader(
      "location",
      `${redirect}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
    );
    res.end();
    return;
  }

  if (url.pathname === "/token" && req.method === "POST") {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString();
    const form = new URLSearchParams(body);
    const code = form.get("code");
    const codeVerifier = form.get("code_verifier") ?? undefined;
    const clientId = form.get("client_id") ?? undefined;
    if (!code) {
      tokenLog.record({ error: "missing_code", client_id: clientId });
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_request", error_description: "missing code" }));
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(Buffer.from(code, "base64url").toString());
    } catch {
      tokenLog.record({ error: "invalid_grant_parse", client_id: clientId });
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_grant", error_description: "code not parseable" }));
      return;
    }
    if (parsed.force_error) {
      tokenLog.record({ error: parsed.force_error, client_id: clientId, sub: parsed.sub });
      res.statusCode = 400;
      res.end(
        JSON.stringify({
          error: parsed.force_error,
          error_description: `mock-idp scenario forced ${parsed.force_error}`,
        }),
      );
      return;
    }
    const pkce = verifyPkce({
      code_verifier: codeVerifier,
      code_challenge: parsed.code_challenge,
      code_challenge_method: parsed.code_challenge_method,
    });
    if (!pkce.ok) {
      tokenLog.record({ error: pkce.error, detail: pkce.detail, client_id: clientId, sub: parsed.sub });
      res.statusCode = 400;
      res.end(JSON.stringify({ error: pkce.error, error_description: pkce.detail }));
      return;
    }
    const idToken = signIdToken({
      issuer,
      sub: parsed.sub,
      email: parsed.email,
      audience: parsed.audience,
      nonce: parsed.nonce,
    });
    tokenLog.record({
      sub: parsed.sub,
      email: parsed.email,
      audience: parsed.audience,
      pkce: Boolean(parsed.code_challenge),
      client_id: clientId,
    });
    res.end(
      JSON.stringify({
        access_token: "mock-access-token",
        token_type: "Bearer",
        id_token: idToken,
        expires_in: 3600,
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
    `[mock-idp] listening on http://127.0.0.1:${actual.port} (issuer=${explicitIssuer ?? `http://127.0.0.1:${actual.port}`})`,
  );
});

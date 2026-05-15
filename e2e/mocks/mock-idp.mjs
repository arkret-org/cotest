// Mock OIDC IdP for cotest joint e2e — supports S4/S7 onboarding via OIDC bridge.
//
// Endpoints:
//   GET  /.well-known/openid-configuration
//   GET  /jwks
//   GET  /authorize?login_hint=...&redirect_uri=...&state=...&client_id=...
//   POST /token  (form-encoded: code=...)
//
// Signing: RS256 (matches what most OIDC RPs expect).
// Authentication: NONE. This is a test harness, not production.

import { createServer } from "node:http";
import { createSign, generateKeyPairSync, randomUUID } from "node:crypto";

const port = parseInt(process.env.MOCK_IDP_PORT ?? "0", 10);
const explicitIssuer = process.env.MOCK_IDP_ISSUER;

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

const publicKeyJwk = publicKey.export({ format: "jwk" });
const jwks = {
  keys: [
    {
      ...publicKeyJwk,
      kid: "mock-idp-key-1",
      alg: "RS256",
      use: "sig",
    },
  ],
};

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signIdToken({ issuer, sub, email, audience }) {
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
  };
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = createSign("RSA-SHA256").update(enc).sign(privateKey);
  return `${enc}.${b64url(sig)}`;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  const issuer =
    explicitIssuer ?? `http://127.0.0.1:${server.address()?.port ?? port}`;

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
      }),
    );
    return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/authorize") {
    const sub = url.searchParams.get("login_hint") ?? `mock-user-${randomUUID()}`;
    const audience = url.searchParams.get("client_id");
    const code = b64url(JSON.stringify({ sub, audience }));
    const redirect = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state") ?? "";
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
    if (!code) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_code" }));
      return;
    }
    try {
      const { sub, audience } = JSON.parse(Buffer.from(code, "base64url").toString());
      const idToken = signIdToken({
        issuer,
        sub,
        email: `${sub}@mock-idp.local`,
        audience,
      });
      res.end(
        JSON.stringify({
          access_token: "mock-access-token",
          token_type: "Bearer",
          id_token: idToken,
          expires_in: 3600,
        }),
      );
    } catch {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_grant" }));
    }
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

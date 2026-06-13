// Mock applet-registry — simulates the Cokret Applet Registry that creates
// controller-signed Applet Packages and forwards external applet activity into
// soland's canonical Applet transaction endpoint.
//
// Spec references:
//   cokret-spec/spec/v1/zh/extensions/applet-integration.md
//   cokret-spec/spec/v1/zh/extensions/applet-schema.md
//
// The mock holds its own Ed25519 signing key + auto-generated DID. The
// harness wires soland (and other consumers) to MOCK_APPLET_REGISTRY_DID so
// applet package install and transaction flows can be exercised
// end-to-end without standing up a real registry implementation.
//
// Endpoints:
//   GET  /identity
//     Returns { did, public_jwk }. Soland binds applet_registry_did to this.
//   GET  /jwks
//     Registry public key (for verifying registry-signed envelopes).
//   POST /sign-package
//     Returns a sealed controller-signed ck.schema.applet_package.v1 for
//     soland's canonical ck.self.applet.install.command.preview / ck.self.applet.command.install flow.
//   POST /external-event
//     Forwards an external payload to soland's `/_cokret/edge/applet/transactions`.
//   GET  /inspect → full mock state.
//   DELETE /inspect → reset logs.
//
// Notes:
//   - This is a harness shim; real registries enforce package publication,
//     namespace governance, and controller key rotation. The mock fakes enough
//     of the contract for joint-e2e to assert "signed package → soland install
//     → bot actor minted → ghost transaction with accountability".

import { createServer } from "node:http";
import { createHash, randomBytes, randomUUID, sign } from "node:crypto";
import { createEd25519KeyPair } from "./_shared/keypairs.mjs";
import { handleInspect } from "./_shared/inspect.mjs";

const port = parseInt(process.env.MOCK_APPLET_REGISTRY_PORT ?? "0", 10);

// Auto-generate the registry DID unless overridden, so each harness run
// gets a unique registry identity (preventing test cross-contamination
// across runs that share a persistent backing store).
const registryDid =
  process.env.MOCK_APPLET_REGISTRY_DID ??
  `did:web:applet-registry-${randomUUID().slice(0, 8)}.joint-e2e.local`;

const { publicKey, privateKey, jwks } = createEd25519KeyPair("mock-applet-registry-key-1");
const publicJwk = publicKey.export({ format: "jwk" });

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

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  return `{${Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function canonicalHash(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function uuidV7Like() {
  const bytes = randomBytes(16);
  const now = BigInt(Date.now());
  bytes[0] = Number((now >> 40n) & 0xffn);
  bytes[1] = Number((now >> 32n) & 0xffn);
  bytes[2] = Number((now >> 24n) & 0xffn);
  bytes[3] = Number((now >> 16n) & 0xffn);
  bytes[4] = Number((now >> 8n) & 0xffn);
  bytes[5] = Number(now & 0xffn);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20,
  )}-${hex.slice(20)}`;
}

function typedId(kind) {
  return `ck:${kind}:${uuidV7Like()}`;
}

function safeToken(value) {
  const safe = String(value ?? "bridge-demo")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return safe || "bridge-demo";
}

function requestedScopesFromBody(body) {
  const input =
    body.requested_scopes ??
    body.requested_capabilities ??
    body.capabilities ?? ["ck.message.create", "ck.applet.ghost.provision"];
  const mapped = input.map((scope) => {
    if (scope === "message:write") return "ck.message.create";
    if (scope === "actor:provision-ghost") return "ck.applet.ghost.provision";
    return String(scope);
  });
  return Array.from(new Set(mapped));
}

function serverBaseUrl() {
  const actual = server.address();
  if (actual && typeof actual === "object") {
    return `http://127.0.0.1:${actual.port}`;
  }
  return "http://127.0.0.1";
}

function signedPackage(body) {
  const namespace = body.namespace ?? body.metadata?.namespace ?? "bridge.demo";
  const safe = safeToken(namespace);
  const appletId =
    typeof body.applet_id === "string" && body.applet_id.startsWith("ck:applet:")
      ? body.applet_id
      : typedId("applet");
  const createdAt = new Date().toISOString();
  const serviceDid = body.service_did ?? `did:web:applet-${safe}.joint-e2e.local`;
  const packageBase = {
    schema: "ck.schema.applet_package.v1",
    package_id: body.package_id ?? `package:${safe}:${uuidV7Like()}`,
    applet_id: appletId,
    service_did: serviceDid,
    controller_did: body.controller_did ?? registryDid,
    base_url: body.base_url ?? serverBaseUrl(),
    bot_actor_id: body.bot_actor_id ?? `did:web:bot-${safe}.joint-e2e.local`,
    claimed_profiles: ["ck.profile.applet_service.v1"],
    protocols: body.protocols ?? ["bridge"],
    namespaces: body.namespaces ?? {
      actors: [{ exclusive: true, pattern: `did:web:ghost-${safe}:*` }],
      realms: [{ exclusive: true, pattern: `bridge:${safe}:*` }],
      handles: [{ exclusive: true, pattern: `${safe}/*` }],
    },
    requested_scopes: requestedScopesFromBody(body),
    endpoint_policy: body.endpoint_policy ?? {
      endpoints: [
        {
          method: "POST",
          path: "/_cokret/edge/applet/transactions",
          auth: "webhook_signature",
        },
        {
          method: "GET",
          path: "/_cokret/edge/applet/actors/{actor_id}",
          auth: "bearer",
        },
        {
          method: "GET",
          path: "/_cokret/edge/applet/realms/{realm_id_or_alias}",
          auth: "bearer",
        },
      ],
    },
    webhook_auth: body.webhook_auth ?? {
      type: "http_message_signature",
      key_ref: `${registryDid}#mock-applet-registry-key-1`,
      accepted_algs: ["EdDSA"],
    },
    receive_events: body.receive_events ?? true,
    receive_ephemeral: body.receive_ephemeral ?? false,
    rate_limited: body.rate_limited ?? true,
    limits: body.limits ?? {
      max_transaction_events: 100,
      max_payload_bytes: 65536,
      rate_limit_hint: "test",
    },
    ghost_policy: body.ghost_policy ?? {
      enabled: true,
      accountability_template: "bot_actor_and_applet_registry",
    },
    delegation_policy: body.delegation_policy ?? {
      enabled: false,
    },
    e2ee_policy: body.e2ee_policy ?? {
      enabled: false,
      mls_join_requested: false,
    },
    registration_epoch:
      body.registration_epoch ??
      canonicalHash({
        applet_id: appletId,
        service_did: serviceDid,
        namespace: safe,
        created_at: createdAt,
      }),
    created_at: createdAt,
  };
  if (body.widget) {
    packageBase.widget = body.widget;
  }
  const packageDigest = canonicalHash(packageBase);
  const sealed = { ...packageBase, package_digest: packageDigest };
  const payloadDigest = canonicalHash(sealed);
  const jws = sign(null, Buffer.from(canonicalJson(sealed), "utf8"), privateKey).toString(
    "base64url",
  );
  const appletPackage = {
    ...sealed,
    proof: {
      kind: "detached_jws",
      alg: "EdDSA",
      verification_method: `${registryDid}#mock-applet-registry-key-1`,
      payload_digest: payloadDigest,
      created_at: createdAt,
      jws,
    },
  };
  return {
    applet_package: appletPackage,
    package_digest: packageDigest,
    signing_did: registryDid,
  };
}

function matchBotPath(pathname) {
  const m = pathname.match(/^\/bot\/([^/]+)\/accept-invite$/);
  if (!m) return null;
  return { appletId: decodeURIComponent(m[1]) };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-applet-registry",
      logs: [],
      extra: {
        registry_did: registryDid,
        public_jwk: publicJwk,
      },
    });
    if (handled) return;
  }

  if (url.pathname === "/healthz") {
    res.end(JSON.stringify({ ok: true, service: "mock-applet-registry" }));
    return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/sign-package" && req.method === "POST") {
    const body = await readJson(req);
    if (!body) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_json" }));
      return;
    }
    res.end(JSON.stringify(signedPackage(body)));
    return;
  }

  if (url.pathname === "/identity" && req.method === "GET") {
    res.end(JSON.stringify({ did: registryDid, public_jwk: publicJwk }));
    return;
  }

  const botMatch = matchBotPath(url.pathname);
  if (botMatch && req.method === "POST") {
    const body = await readJson(req);
    res.end(
      JSON.stringify({
        applet_id: botMatch.appletId,
        bot_actor_id: null,
        realm_id: body?.realm_id ?? null,
        status: "joined",
      }),
    );
    return;
  }

  if (url.pathname === "/external-event" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.applet_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_applet_id" }));
      return;
    }
    const solandBase =
      body.soland_base_url ??
      process.env.SOLAND_BASE_URL ??
      process.env.COTEST_SOLAND_BASE_URL;
    const authorization =
      req.headers.authorization ??
      body.authorization ??
      (body.access_token ? `Bearer ${body.access_token}` : undefined);
    if (!solandBase || !authorization) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_soland_base_url_or_authorization" }));
      return;
    }
    const upstream = await fetch(
      `${String(solandBase).replace(/\/$/, "")}/_cokret/edge/applet/transactions`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization,
          "Idempotency-Key":
            body.idempotency_key ??
            `external-${body.applet_id}-${body.external_user?.id ?? "bot"}-${Date.now()}`,
        },
        body: JSON.stringify({
          applet_id: body.applet_id,
          realm_id: body.realm_id,
          external_user: body.external_user,
          payload: body.payload,
        }),
      },
    );
    res.statusCode = upstream.status;
    res.end(await upstream.text());
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-applet-registry] listening on http://127.0.0.1:${actual.port} (did=${registryDid})`,
  );
});

// Mock applet-registry — simulates the Arkret Applet Registry that creates
// controller-signed Applet Packages and forwards external applet activity into
// soland's canonical Applet transaction endpoint.
//
// Spec references:
//   arkret-spec/spec/v1/zh/extensions/applet-integration.md
//   arkret-spec/spec/v1/zh/extensions/applet-schema.md
//
// The mock holds its own Ed25519 signing key + auto-generated DID. The
// harness wires soland (and other consumers) to MOCK_APPLET_REGISTRY_DID so
// applet package install and transaction strands can be exercised
// end-to-end without standing up a real registry implementation.
//
// Endpoints:
//   GET  /identity
//     Returns { did, public_jwk }. Soland binds applet_registry_did to this.
//   GET  /jwks
//     Registry public key (for verifying registry-signed envelopes).
//   POST /sign-package
//     Returns a sealed controller-signed ak.schema.applet_package.v1 for
//     soland's canonical ak.self.applet.install.command.preview / ak.self.applet.command.install strand.
//   POST /external-event
//     Forwards an external payload to soland's typed applet ingress route.
//   GET  /inspect → full mock state.
//   DELETE /inspect → reset logs.
//
// Notes:
//   - This is a harness shim; real registries enforce package publication,
//     namespace governance, and controller key rotation. The mock fakes enough
//     of the contract for joint-e2e to assert "signed package → soland install
//     → bot actor minted → ghost transaction with accountability".

import { createServer } from "node:http";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign,
} from "node:crypto";
import { createEd25519KeyPair } from "./_shared/keypairs.mjs";
import { handleInspect } from "./_shared/inspect.mjs";
import { canonicalJson, canonicalTimestamp, readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_APPLET_REGISTRY_PORT ?? "0", 10);

// Auto-generate the registry DID unless overridden, so each harness run
// gets a unique registry identity (preventing test cross-contamination
// across runs that share a persistent backing store).
const registryDid =
  process.env.MOCK_APPLET_REGISTRY_DID ??
  `did:web:applet-registry-${randomUUID().slice(0, 8)}.joint-e2e.local`;

const { publicKey, privateKey, jwks } = createEd25519KeyPair("mock-applet-registry-key-1");
const publicJwk = publicKey.export({ format: "jwk" });


function canonicalHash(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function registrationEpochHash(packageBase, evidence) {
  const methodOrder = new Map([
    ["GET", 0],
    ["POST", 1],
    ["PUT", 2],
    ["PATCH", 3],
    ["DELETE", 4],
  ]);
  const authOrder = new Map([
    ["none", 0],
    ["webhook_signature", 1],
    ["bearer", 2],
    ["mtls", 3],
  ]);
  const sortedEndpoints = [...packageBase.endpoint_policy.endpoints].sort((left, right) => {
    const method = methodOrder.get(left.method) - methodOrder.get(right.method);
    if (method !== 0) return method;
    const path = left.path.localeCompare(right.path);
    if (path !== 0) return path;
    return (authOrder.get(left.auth) ?? -1) - (authOrder.get(right.auth) ?? -1);
  });
  const sortedNamespaces = Object.fromEntries(
    Object.entries(packageBase.namespaces).map(([kind, entries]) => [
      kind,
      [...entries].sort(
        (left, right) =>
          left.pattern.localeCompare(right.pattern) ||
          Number(left.exclusive) - Number(right.exclusive),
      ),
    ]),
  );
  const securityPolicy = {
    claimed_profiles: [...packageBase.claimed_profiles].sort(),
    limits: packageBase.limits,
    ghost_policy: packageBase.ghost_policy,
    delegation_policy: packageBase.delegation_policy,
    e2ee_policy: packageBase.e2ee_policy,
  };
  if (packageBase.widget !== undefined) securityPolicy.widget = packageBase.widget;
  const transcript = {
    schema: "ak.schema.applet_registration_epoch_transcript.v1",
    derived_registration: {
      kind: "ak.applet.registration",
      applet_id: packageBase.applet_id,
      service_id: packageBase.service_id,
      controller_id: packageBase.controller_id,
      base_url: packageBase.base_url,
      bot_actor_id: packageBase.bot_actor_id,
      protocols: [...packageBase.protocols].sort(),
      namespaces: sortedNamespaces,
      receive_events: packageBase.receive_events,
      receive_ephemeral: packageBase.receive_ephemeral,
      rate_limited: packageBase.rate_limited,
      requested_scopes: [...packageBase.requested_scopes].sort(),
      created_at: packageBase.created_at,
    },
    service_did_document: {
      service_id: evidence.service_id,
      document_digest: evidence.did_document_digest,
      method_version: evidence.method_version_evidence,
    },
    accepted_signing_keys: [...evidence.accepted_signing_keys].sort((left, right) =>
      left.key_ref.localeCompare(right.key_ref),
    ),
    endpoint_policy: {
      ...packageBase.endpoint_policy,
      endpoints: sortedEndpoints,
    },
    webhook_auth: {
      ...packageBase.webhook_auth,
      accepted_algs: [...packageBase.webhook_auth.accepted_algs].sort(),
    },
    security_policy: securityPolicy,
  };
  const digest = createHash("sha256")
    .update("arkret-applet-registration-epoch-v1\n", "utf8")
    .update(canonicalJson(transcript), "utf8")
    .digest("hex");
  return `sha256:${digest}`;
}

function rfc3339Now() {
  return canonicalTimestamp();
}

function developmentAppletPublicJwk(verificationMethod) {
  const seed = createHash("sha256")
    .update("soland:applet-service-key:")
    .update(verificationMethod)
    .digest();
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
  return createPublicKey(privateKey).export({ format: "jwk" });
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
  return `ak:${kind}:${uuidV7Like()}`;
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
    body.capabilities ?? ["ak.message.create", "ak.applet.ghost.provision"];
  const mapped = input.map((scope) => {
    if (scope === "message:write") return "ak.message.create";
    if (scope === "actor:provision-ghost") return "ak.applet.ghost.provision";
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
    typeof body.applet_id === "string" && body.applet_id.startsWith("ak:applet:")
      ? body.applet_id
      : typedId("applet");
  const createdAt = rfc3339Now();
  const serviceId =
    body.service_id ?? `did:webvh:z6mkfixture:applet-${safe}.joint-e2e.local`;
  const webhookAuth = body.webhook_auth ?? {
    type: "http_message_signature",
    key_ref: `${serviceId}#applet-service-key`,
    accepted_algs: ["EdDSA"],
  };
  const webhookPublicJwk = developmentAppletPublicJwk(webhookAuth.key_ref);
  const webhookPublicKeyMaterial = canonicalJson(webhookPublicJwk);
  const serviceIdDocument = {
    id: serviceId,
    verificationMethod: {
      [webhookAuth.key_ref]: webhookPublicKeyMaterial,
    },
    updated: createdAt,
  };
  const registrationEpochEvidence = {
    service_id: serviceId,
    did_document_digest: canonicalHash(serviceIdDocument),
    method_version_evidence: serviceId.startsWith("did:webvh:")
      ? {
          method: "did:webvh",
          version_time: createdAt,
          unversioned_refetch: false,
        }
      : {
          method: `did:${String(serviceId).split(":")[1]}`,
          unversioned_refetch: true,
        },
    accepted_signing_keys: [
      {
        key_ref: webhookAuth.key_ref,
        public_key_digest: canonicalHash(webhookPublicJwk),
      },
    ],
  };
  const packageBase = {
    schema: "ak.schema.applet_package.v1",
    package_id: body.package_id ?? `package:${safe}:${uuidV7Like()}`,
    applet_id: appletId,
    service_id: serviceId,
    controller_id: body.controller_id ?? registryDid,
    base_url: body.base_url ?? serverBaseUrl(),
    bot_actor_id: body.bot_actor_id ?? `did:web:bot-${safe}.joint-e2e.local`,
    claimed_profiles: ["ak.profile.applet_service.v1"],
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
          path: "/_arkret/edge/applet/transactions",
          auth: "webhook_signature",
        },
        {
          method: "GET",
          path: "/_arkret/edge/applet/actors/{actor_id}",
          auth: "bearer",
        },
        {
          method: "GET",
          path: "/_arkret/edge/applet/realms/{realm_id_or_alias}",
          auth: "bearer",
        },
      ],
    },
    webhook_auth: webhookAuth,
    receive_events: body.receive_events ?? true,
    receive_ephemeral: body.receive_ephemeral ?? false,
    rate_limited: body.rate_limited ?? true,
    limits: body.limits ?? {
      max_transaction_events: 100,
      max_payload_bytes: 65536,
      rate_limit_per_minute: 60,
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
    registration_epoch_evidence: registrationEpochEvidence,
    created_at: createdAt,
  };
  if (body.widget) {
    packageBase.widget = body.widget;
  }
  packageBase.registration_epoch =
    body.registration_epoch ?? registrationEpochHash(packageBase, registrationEpochEvidence);
  // The evidence is required on input so the Principal Server can validate
  // the service DID epoch, but AppletPackage deliberately excludes it from
  // serialization and therefore from both canonical package transcripts.
  const canonicalPackageBase = { ...packageBase };
  delete canonicalPackageBase.registration_epoch_evidence;
  const packageDigest = canonicalHash(canonicalPackageBase);
  const sealedForSignature = {
    ...canonicalPackageBase,
    package_digest: packageDigest,
  };
  const sealed = { ...packageBase, package_digest: packageDigest };
  const payloadDigest = canonicalHash(sealedForSignature);
  // Detached JWS per RFC 7515 appendix F, matching the SDK contract
  // (arkret-rust-sdk signatures/proof.rs): wire form is `header..signature`
  // with an empty payload segment, signed over `header.BASE64URL(payload)`.
  const jwsHeader = Buffer.from('{"alg":"EdDSA"}', "utf8").toString("base64url");
  const signingInput = `${jwsHeader}.${Buffer.from(canonicalJson(sealedForSignature), "utf8").toString("base64url")}`;
  const signature = sign(null, Buffer.from(signingInput, "utf8"), privateKey).toString(
    "base64url",
  );
  const jws = `${jwsHeader}..${signature}`;
  const appletPackage = {
    ...sealed,
    proof: {
      kind: "detached_jws",
      alg: "EdDSA",
      verification_method: `${registryDid}#mock-applet-registry-key-1`,
      event_digest: payloadDigest,
      created_at: createdAt,
      jws,
    },
  };
  return {
    applet_package: appletPackage,
    package_digest: packageDigest,
    signing_did: registryDid,
    service_id_document: serviceIdDocument,
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
      (body.session_credential ? `Bearer ${body.session_credential}` : undefined);
    if (!solandBase || !authorization) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_soland_base_url_or_authorization" }));
      return;
    }
    let upstream;
    try {
      upstream = await fetch(
        `${String(solandBase).replace(/\/$/, "")}/_soland/edge/applets/${encodeURIComponent(
          body.applet_id,
        )}/ghosts`,
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
            realm_id: body.realm_id,
            external_user: body.external_user,
            payload: body.payload,
          }),
        },
      );
    } catch (err) {
      // soland unreachable / connection refused / timeout: degrade to a
      // structured 502 instead of letting the rejected promise escape the
      // createServer async callback (process-level unhandledRejection) and
      // leaving the client hung with no status written.
      res.statusCode = 502;
      res.end(JSON.stringify({ error: "upstream_unreachable", detail: String(err) }));
      return;
    }
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

// Mock applet-registry — simulates the Contrix Applet Registry that
// (1) accepts signed applet manifest registrations, (2) mints per-applet
// bot actor DIDs as the registry-backed issuing authority, and (3) acts as
// a ghost-actor factory binding external_id → ghost_actor_did with the
// registry recorded as the accountability anchor.
//
// Spec references:
//   contrix-spec/spec/v1/zh/extensions/applet-integration.md
//   contrix-spec/spec/v1/zh/extensions/applet-schema.md
//
// The mock holds its own Ed25519 signing key + auto-generated DID. The
// harness wires soland (and other consumers) to MOCK_APPLET_REGISTRY_DID so
// applet registration / ghost-actor minting flows can be exercised
// end-to-end without standing up a real registry implementation.
//
// Endpoints:
//   GET  /identity
//     Returns { did, public_jwk }. Soland binds applet_registry_did to this.
//   GET  /jwks
//     Registry public key (for verifying registry-signed envelopes).
//   POST /api/v1/applets/register  { manifest, manifest_signature }
//     Accepts a signed applet manifest. Signature is NOT cryptographically
//     verified here (mock shim) — any non-empty value is accepted. Mints a
//     deterministic bot_actor_did and returns
//     { applet_id, bot_actor_did, namespace, status: "registered" }.
//   GET  /api/v1/applets/:applet_id
//     Returns full applet record (manifest, bot_actor_did, capabilities, …).
//   GET  /api/v1/applets
//     Lists all registered applets.
//   POST /api/v1/applets/:applet_id/ghost-actor  { external_id, display_name? }
//     Mints a ghost_actor_did for an external user impersonated through the
//     applet. Accountability is set to { bot_actor_did, registry_did } so
//     audit trails can attribute ghost activity back to the applet + registry.
//   GET  /api/v1/applets/:applet_id/ghost-actors
//     Lists ghost actors minted under an applet.
//   POST /api/v1/applets/:applet_id/revoke
//     Marks the applet status as "revoked". Subsequent ghost-actor mints
//     are rejected. Existing ghost actors are retained for audit history.
//   POST /scenarios  { namespace_conflict?, force_revoke? }
//     Configures mock behavior knobs for scenario specs:
//       - namespace_conflict: when true, the next /register call returns
//         409 namespace_conflict regardless of input.
//       - force_revoke: applet_id to immediately mark as revoked.
//   GET  /inspect → full mock state (logs: registered, ghost_actors, revoked)
//   DELETE /inspect → reset logs (does not clear in-memory applets/ghosts).
//
// Notes:
//   - This is a harness shim; real registries verify manifest signatures
//     against publisher keys, enforce namespace governance, and gate
//     capability grants. The mock fakes enough of the contract for
//     joint-e2e to assert "applet registered → bot actor minted → ghost
//     actor created with accountability pointing back at the registry".

import fs from "node:fs";
import path from "node:path";
import { createServer } from "node:http";
import { createHash, randomUUID, sign } from "node:crypto";
import { createEd25519KeyPair } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";

const port = parseInt(process.env.MOCK_APPLET_REGISTRY_PORT ?? "0", 10);

// Auto-generate the registry DID unless overridden, so each harness run
// gets a unique registry identity (preventing test cross-contamination
// across runs that share a persistent backing store).
const registryDid =
  process.env.MOCK_APPLET_REGISTRY_DID ??
  `did:web:applet-registry.joint-e2e.local#${randomUUID().slice(0, 8)}`;

const { publicKey, privateKey, jwks } = createEd25519KeyPair("mock-applet-registry-key-1");
const publicJwk = publicKey.export({ format: "jwk" });

// In-memory state. `applets` keyed by applet_id; `ghostActors` keyed by
// ghost_actor_did so reverse lookups are cheap.
const applets = new Map();
const ghostActors = new Map();

// Scenario knobs — mutated by POST /scenarios.
const scenario = {
  namespace_conflict: false,
};

const registeredLog = new InspectLog("registered");
const ghostActorsCreatedLog = new InspectLog("ghost_actors_created");
const revokedLog = new InspectLog("revoked");

function deriveAppletId(manifest) {
  // Prefer manifest-supplied applet_id so harness specs can pin a known
  // value; otherwise synthesize from namespace + name + a short uuid.
  if (manifest?.id) return String(manifest.id);
  if (manifest?.applet_id) return String(manifest.applet_id);
  const ns = manifest?.metadata?.namespace ?? manifest?.namespace ?? "anon";
  const name = manifest?.metadata?.display_name ?? manifest?.name ?? "applet";
  return `${ns}.${name}.${randomUUID().slice(0, 8)}`
    .toLowerCase()
    .replace(/[^a-z0-9.\-]/g, "-");
}

function botActorDidFor(appletId) {
  return `did:web:applet.${appletId}.joint-e2e.local`;
}

function ghostActorDidFor(appletId, externalId) {
  const safeExt = String(externalId).toLowerCase().replace(/[^a-z0-9\-]/g, "-");
  return `did:web:ghost.${appletId}-${safeExt}.joint-e2e.local`;
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

function currentAppletSchemaHash() {
  let cursor = process.cwd();
  for (;;) {
    const candidate = path.join(
      cursor,
      "contrix-spec",
      "spec",
      "v1",
      "artifacts",
      "schemas",
      "applet.schema.json",
    );
    if (fs.existsSync(candidate)) {
      return createHash("sha256").update(fs.readFileSync(candidate)).digest("hex");
    }
    const parent = path.dirname(cursor);
    if (parent === cursor) return "";
    cursor = parent;
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

function signedManifest(body) {
  const capabilities =
    body.requested_capabilities ??
    body.capabilities ?? ["realm:portal", "message:write", "actor:provision-ghost"];
  const metadata = {
    ...(body.metadata && typeof body.metadata === "object" ? body.metadata : {}),
    namespace: body.namespace ?? body.metadata?.namespace ?? "bridge.demo",
    display_name: body.display_name ?? body.metadata?.display_name ?? "Demo Bridge Applet",
  };
  const manifest = {
    id:
      body.manifest_id ??
      body.id ??
      `applet:bridge:${metadata.namespace}-${randomUUID().slice(0, 8)}`,
    version: body.version ?? "1.0.0",
    signer_did: body.signer_did ?? registryDid,
    signature: "",
    signer_public_key: publicJwk.x,
    requested_capabilities: capabilities,
    schema_hash: body.schema_hash ?? currentAppletSchemaHash(),
    metadata,
  };
  const signingBody = {
    id: manifest.id,
    metadata: manifest.metadata,
    requested_capabilities: manifest.requested_capabilities,
    schema_hash: manifest.schema_hash,
    signer_did: manifest.signer_did,
    signer_public_key: manifest.signer_public_key,
    version: manifest.version,
  };
  manifest.signature = sign(null, Buffer.from(canonicalJson(signingBody), "utf8"), privateKey)
    .toString("base64url");
  return {
    manifest,
    signature: manifest.signature,
    manifest_signature: manifest.signature,
    signing_did: manifest.signer_did,
  };
}

function matchAppletPath(pathname) {
  // /api/v1/applets/:applet_id[/(ghost-actor|ghost-actors|revoke)]
  const m = pathname.match(
    /^\/api\/v1\/applets\/([^/]+)(?:\/(ghost-actor|ghost-actors|revoke))?$/,
  );
  if (!m) return null;
  return { appletId: decodeURIComponent(m[1]), suffix: m[2] ?? null };
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
      logs: [registeredLog, ghostActorsCreatedLog, revokedLog],
      extra: {
        registry_did: registryDid,
        public_jwk: publicJwk,
        applets: Array.from(applets.values()),
        ghost_actors: Array.from(ghostActors.values()),
        scenario,
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

  if (url.pathname === "/sign-manifest" && req.method === "POST") {
    const body = await readJson(req);
    if (!body) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_json" }));
      return;
    }
    res.end(JSON.stringify(signedManifest(body)));
    return;
  }

  if (url.pathname === "/identity" && req.method === "GET") {
    res.end(JSON.stringify({ did: registryDid, public_jwk: publicJwk }));
    return;
  }

  if (url.pathname === "/scenarios" && req.method === "POST") {
    const body = await readJson(req);
    if (!body) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_json" }));
      return;
    }
    if (typeof body.namespace_conflict === "boolean") {
      scenario.namespace_conflict = body.namespace_conflict;
    }
    if (typeof body.force_revoke === "string") {
      const target = applets.get(body.force_revoke);
      if (target) {
        target.status = "revoked";
        revokedLog.record({ applet_id: target.applet_id, reason: "force_revoke" });
      }
    }
    res.end(JSON.stringify({ ok: true, scenario }));
    return;
  }

  if (url.pathname === "/api/v1/applets/register" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.manifest || !body.manifest_signature) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_manifest_or_signature" }));
      return;
    }
    if (scenario.namespace_conflict) {
      // Consume the knob once so subsequent calls succeed unless re-armed.
      scenario.namespace_conflict = false;
      res.statusCode = 409;
      res.end(JSON.stringify({ error: "namespace_conflict" }));
      return;
    }
    const appletId = deriveAppletId(body.manifest);
    if (applets.has(appletId)) {
      res.statusCode = 409;
      res.end(JSON.stringify({ error: "applet_already_registered", applet_id: appletId }));
      return;
    }
    const botActorDid = botActorDidFor(appletId);
    const record = {
      applet_id: appletId,
      manifest: body.manifest,
      manifest_signature: body.manifest_signature,
      bot_actor_did: botActorDid,
      namespace: body.manifest.namespace ?? null,
      capabilities: Array.isArray(body.manifest.requested_capabilities)
        ? body.manifest.requested_capabilities
        : Array.isArray(body.manifest.capabilities)
          ? body.manifest.capabilities
          : [],
      registered_at: new Date().toISOString(),
      status: "registered",
      issued_by: registryDid,
    };
    applets.set(appletId, record);
    registeredLog.record({
      applet_id: appletId,
      bot_actor_did: botActorDid,
      namespace: record.namespace,
      capabilities: record.capabilities,
    });
    res.end(
      JSON.stringify({
        applet_id: appletId,
        bot_actor_did: botActorDid,
        namespace: record.namespace,
        status: "registered",
      }),
    );
    return;
  }

  if (url.pathname === "/api/v1/applets" && req.method === "GET") {
    res.end(JSON.stringify({ applets: Array.from(applets.values()) }));
    return;
  }

  const appletMatch = matchAppletPath(url.pathname);
  if (appletMatch) {
    const { appletId, suffix } = appletMatch;
    const record = applets.get(appletId);

    if (!record) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "applet_not_found", applet_id: appletId }));
      return;
    }

    if (suffix === null && req.method === "GET") {
      res.end(JSON.stringify(record));
      return;
    }

    if (suffix === "ghost-actor" && req.method === "POST") {
      if (record.status === "revoked") {
        res.statusCode = 409;
        res.end(JSON.stringify({ error: "applet_revoked", applet_id: appletId }));
        return;
      }
      const body = await readJson(req);
      if (!body || !body.external_id) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "missing_external_id" }));
        return;
      }
      const ghostDid = ghostActorDidFor(appletId, body.external_id);
      if (ghostActors.has(ghostDid)) {
        res.end(JSON.stringify(ghostActors.get(ghostDid)));
        return;
      }
      const ghost = {
        ghost_actor_did: ghostDid,
        applet_id: appletId,
        external_id: String(body.external_id),
        display_name: body.display_name ?? null,
        created_at: new Date().toISOString(),
        accountability: {
          bot_actor_did: record.bot_actor_did,
          registry_did: registryDid,
        },
      };
      ghostActors.set(ghostDid, ghost);
      ghostActorsCreatedLog.record({
        applet_id: appletId,
        ghost_actor_did: ghostDid,
        external_id: ghost.external_id,
      });
      res.end(JSON.stringify(ghost));
      return;
    }

    if (suffix === "ghost-actors" && req.method === "GET") {
      const list = Array.from(ghostActors.values()).filter(
        (g) => g.applet_id === appletId,
      );
      res.end(JSON.stringify({ applet_id: appletId, ghost_actors: list }));
      return;
    }

    if (suffix === "revoke" && req.method === "POST") {
      record.status = "revoked";
      record.revoked_at = new Date().toISOString();
      revokedLog.record({ applet_id: appletId, reason: "explicit_revoke" });
      res.end(JSON.stringify({ applet_id: appletId, status: "revoked" }));
      return;
    }
  }

  const botMatch = matchBotPath(url.pathname);
  if (botMatch && req.method === "POST") {
    const record = applets.get(botMatch.appletId);
    const body = await readJson(req);
    if (record) {
      record.joined_spaces ??= [];
    }
    if (record && body?.space_id && !record.joined_spaces.includes(body.space_id)) {
      record.joined_spaces.push(body.space_id);
    }
    res.end(
      JSON.stringify({
        applet_id: botMatch.appletId,
        bot_actor_did: record?.bot_actor_did ?? null,
        space_id: body?.space_id ?? null,
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
      `${String(solandBase).replace(/\/$/, "")}/api/v1/extensions/applets/${encodeURIComponent(
        body.applet_id,
      )}/ghosts`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization,
        },
        body: JSON.stringify({
          space_id: body.space_id,
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

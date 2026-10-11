// Mock applet-registry — simulates the Arkret Applet Registry that creates
// controller-signed Applet Packages and forwards external applet activity into
// coland's canonical Applet transaction endpoint.
//
// Spec references:
//   arkret-spec/spec/v1/zh/extensions/applet-integration.md
//   arkret-spec/spec/v1/zh/extensions/applet-schema.md
//
// The mock holds its own Ed25519 signing key + auto-generated DID. The
// harness wires coland (and other consumers) to MOCK_APPLET_REGISTRY_DID so
// applet package install and transaction strands can be exercised
// end-to-end without standing up a real registry implementation.
//
// Endpoints:
//   GET  /identity
//     Returns { did, public_jwk }. Coland binds applet_registry_did to this.
//   GET  /jwks
//     Registry public key (for verifying registry-signed envelopes).
//   POST /sign-package
//     Returns a sealed controller-signed ak.schema.applet_package.v1 for
//     coland's canonical ak.self.applet.install.command.preview.v1 / ak.self.applet.command.install.v1 strand.
//   POST /_arkret/edge/applet/managed-actors/author
//     Delegates the closed-carrier validation, proof verification, and canonical
//     four-Event construction to cotest-wire's shared Rust SDK authoring kernel.
//     JavaScript owns only HTTP orchestration and durable exact-replay storage.
//   POST /external-event
//     Forwards an external payload to coland's typed applet ingress route.
//   GET  /inspect → full mock state.
//   DELETE /inspect → reset logs.
//
// Notes:
//   - This is a harness shim; real registries enforce package publication,
//     namespace governance, and controller key rotation. The mock fakes enough
//     of the contract for joint-e2e to assert "signed package → coland install
//     → independent Bot provision → Ghost transaction with accountability".

import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign,
} from "node:crypto";
import { createEd25519KeyPair, encodeEd25519PubkeyMultibase, rawEd25519PublicKey } from "./_shared/keypairs.mjs";
import { handleInspect } from "./_shared/inspect.mjs";
import { canonicalJson, readJson } from "./_shared/http.mjs";
import { replaceStateFileSync } from "./_shared/atomic-state.mjs";
import { isolateRequestFailure } from "./_shared/request-handler.mjs";

const port = parseInt(process.env.MOCK_APPLET_REGISTRY_PORT ?? "0", 10);
const durableStateFile = process.env.MOCK_APPLET_REGISTRY_STATE_FILE;
const durableStateKeyFile = process.env.MOCK_APPLET_REGISTRY_STATE_KEY_FILE;
const durableStateSchema = "cotest.mock_applet_registry_state_encrypted.v1";
const durableStateKey = durableStateFile
  ? readDurableStateKey(durableStateKeyFile)
  : undefined;
const durableState =
  durableStateFile && existsSync(durableStateFile)
    ? decryptDurableState(
        JSON.parse(readFileSync(durableStateFile, "utf8")),
        durableStateKey,
      )
    : {};

function readDurableStateKey(path) {
  if (!path) {
    throw new Error(
      "MOCK_APPLET_REGISTRY_STATE_KEY_FILE is required for durable authoring",
    );
  }
  const key = readFileSync(path);
  if (key.length !== 32) {
    throw new Error("mock Applet registry durable-state key must be 32 bytes");
  }
  return key;
}

function encryptDurableState(state, key) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(durableStateSchema, "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(canonicalJson(state), "utf8"),
    cipher.final(),
  ]);
  return {
    schema: durableStateSchema,
    algorithm: "A256GCM",
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

function decryptDurableState(envelope, key) {
  if (
    !exactObjectKeys(envelope, [
      "schema",
      "algorithm",
      "nonce",
      "ciphertext",
      "tag",
    ]) ||
    envelope.schema !== durableStateSchema ||
    envelope.algorithm !== "A256GCM"
  ) {
    throw new Error("mock Applet registry durable-state envelope is invalid");
  }
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(envelope.nonce, "base64url"),
  );
  decipher.setAAD(Buffer.from(durableStateSchema, "utf8"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8"));
}

// Auto-generate the registry DID unless overridden, so each harness run
// gets a unique registry identity (preventing test cross-contamination
// across runs that share a persistent backing store).
function projectDidToCoreId(did) {
  if (did.startsWith("did:webvh:")) {
    const scid = did.slice("did:webvh:".length).split(":", 1)[0];
    if (!scid) throw new Error(`invalid did:webvh value: ${did}`);
    return `ak:did_core:webvh:${scid}`;
  }
  for (const method of ["web", "key"]) {
    const prefix = `did:${method}:`;
    if (did.startsWith(prefix)) {
      return `ak:did_core:${method}:${did.slice(prefix.length)}`;
    }
  }
  throw new Error(`unsupported DID method: ${did}`);
}

const persistedPrivateKey = durableState.registryPrivateJwk
  ? createPrivateKey({ key: durableState.registryPrivateJwk, format: "jwk" })
  : undefined;
const generatedKeyPair = persistedPrivateKey
  ? undefined
  : createEd25519KeyPair("mock-applet-registry-key-1");
const privateKey = persistedPrivateKey ?? generatedKeyPair.privateKey;
const publicKey = createPublicKey(privateKey);
const publicJwk = publicKey.export({ format: "jwk" });
const registryKeyMultibase = encodeEd25519PubkeyMultibase(rawEd25519PublicKey(publicKey));
const registryDid = process.env.MOCK_APPLET_REGISTRY_DID ?? durableState.registryDid ?? `did:key:${registryKeyMultibase}`;
if (!registryDid.startsWith("did:")) {
  throw new Error("MOCK_APPLET_REGISTRY_DID must be a W3C DID");
}
const registryId = projectDidToCoreId(registryDid);
const registryVerificationMethod = registryDid.startsWith("did:key:")
  ? `${registryDid}#${registryKeyMultibase}`
  : `${registryDid}#mock-applet-registry-key-1`;
const jwks = {
  keys: [
    {
      ...publicJwk,
      kid: "mock-applet-registry-key-1",
      alg: "Ed25519",
      use: "sig",
    },
  ],
};
const packagesByApplet = new Map(
  (durableState.packages ?? []).map(([appletId, packageInfo]) => [
    appletId,
    {
      ...packageInfo,
      signingKey: createPrivateKey({
        key: packageInfo.signingPrivateJwk,
        format: "jwk",
      }),
      botSigningKey: packageInfo.botSigningPrivateJwk
        ? createPrivateKey({
            key: packageInfo.botSigningPrivateJwk,
            format: "jwk",
          })
        : undefined,
    },
  ]),
);
const managedActorAuthoringOutcomes = new Map(
  durableState.managedActorAuthoringOutcomes ?? [],
);
const signedPackageOutcomes = new Map(durableState.signedPackageOutcomes ?? []);
let currentStationVerificationMethod = `${stationDid()}#notary-key`;
const provisionedGhosts = new Map();

function persistDurableAuthoringState() {
  if (!durableStateFile) {
    throw new Error(
      "MOCK_APPLET_REGISTRY_STATE_FILE is required for durable authoring",
    );
  }
  mkdirSync(dirname(durableStateFile), { recursive: true });
  const packages = [...packagesByApplet].map(([appletId, packageInfo]) => {
    const { signingKey, botSigningKey, ...serializable } = packageInfo;
    return [
      appletId,
      {
        ...serializable,
        signingPrivateJwk: signingKey.export({ format: "jwk" }),
        ...(botSigningKey
          ? { botSigningPrivateJwk: botSigningKey.export({ format: "jwk" }) }
          : {}),
      },
    ];
  });
  const state = {
    registryDid,
    registryPrivateJwk: privateKey.export({ format: "jwk" }),
    packages,
    managedActorAuthoringOutcomes: [...managedActorAuthoringOutcomes],
    signedPackageOutcomes: [...signedPackageOutcomes],
  };
  const temporary = `${durableStateFile}.${process.pid}.tmp`;
  writeFileSync(
    temporary,
    canonicalJson(encryptDurableState(state, durableStateKey)),
    { mode: 0o600, flush: true },
  );
  replaceStateFileSync(temporary, durableStateFile);
}

function reloadDurableAuthoringState() {
  if (!durableStateFile || !existsSync(durableStateFile)) {
    throw new Error("durable Applet authoring state is unavailable");
  }
  const state = decryptDurableState(
    JSON.parse(readFileSync(durableStateFile, "utf8")),
    durableStateKey,
  );
  packagesByApplet.clear();
  for (const [appletId, packageInfo] of state.packages ?? []) {
    packagesByApplet.set(appletId, {
      ...packageInfo,
      signingKey: createPrivateKey({
        key: packageInfo.signingPrivateJwk,
        format: "jwk",
      }),
      botSigningKey: packageInfo.botSigningPrivateJwk
        ? createPrivateKey({
            key: packageInfo.botSigningPrivateJwk,
            format: "jwk",
          })
        : undefined,
    });
  }
  managedActorAuthoringOutcomes.clear();
  for (const [subject, outcome] of state.managedActorAuthoringOutcomes ?? []) {
    managedActorAuthoringOutcomes.set(subject, outcome);
  }
  signedPackageOutcomes.clear();
  for (const [key, outcome] of state.signedPackageOutcomes ?? []) {
    signedPackageOutcomes.set(key, outcome);
  }
}

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
  const sortedEndpoints = [...packageBase.endpoint_policy.endpoints].sort(
    (left, right) => {
      const method =
        methodOrder.get(left.method) - methodOrder.get(right.method);
      if (method !== 0) return method;
      const path = left.path.localeCompare(right.path);
      if (path !== 0) return path;
      return (
        (authOrder.get(left.auth) ?? -1) - (authOrder.get(right.auth) ?? -1)
      );
    },
  );
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
  if (packageBase.widget !== undefined)
    securityPolicy.widget = packageBase.widget;
  const transcript = {
    schema: "ak.schema.applet_registration_epoch_transcript.v1",
    derived_registration: {
      kind: "ak.applet.registration",
      applet_id: packageBase.applet_id,
      service_id: packageBase.service_id,
      controller_principal_id: packageBase.controller_principal_id,
      base_url: packageBase.base_url,
      protocols: [...packageBase.protocols].sort(),
      namespaces: sortedNamespaces,
      receive_events: packageBase.receive_events,
      receive_signals: packageBase.receive_signals,
      rate_limited: packageBase.rate_limited,
      requested_scopes: [...packageBase.requested_scopes].sort(),
      created_at: packageBase.created_at,
    },
    service_did_document: {
      did: evidence.did,
      document_digest: evidence.document_digest,
      method_version: evidence.method_version_evidence,
    },
    accepted_signing_keys: [...evidence.accepted_signing_keys].sort(
      (left, right) => left.key_ref.localeCompare(right.key_ref),
    ),
    endpoint_policy: {
      ...packageBase.endpoint_policy,
      endpoints: sortedEndpoints,
    },
    webhook_auth: {
      ...packageBase.webhook_auth,
      accepted_signature_algorithms: [
        ...packageBase.webhook_auth.accepted_signature_algorithms,
      ].sort(),
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
  return new Date().toISOString();
}

function requiredStationSetting(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Applet mock requires ${name} from the prepared Station`);
  return value;
}

function stationId() {
  return requiredStationSetting("COTEST_COLAND_SERVICE_ID");
}

function stationDid() {
  return requiredStationSetting("COTEST_COLAND_SERVICE_DID");
}

function configuredStationSeed() {
  const encoded = requiredStationSetting("COTEST_COLAND_SERVICE_SIGNING_KEY");
  const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const seed = Buffer.from(
    normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="),
    "base64",
  );
  if (seed.length !== 32) {
    throw new Error(
      "COTEST_COLAND_SERVICE_SIGNING_KEY must decode to 32 bytes",
    );
  }
  return seed;
}

function stationNotaryPrivateKey() {
  const seed = configuredStationSeed();
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function developmentAppletPrivateKey(verificationMethod) {
  const seed = createHash("sha256")
    .update("coland:applet-service-key:")
    .update(verificationMethod)
    .digest();
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function developmentAppletPublicJwk(verificationMethod) {
  return createPublicKey(
    developmentAppletPrivateKey(verificationMethod),
  ).export({
    format: "jwk",
  });
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

function deriveEventId(event) {
  return deriveEventIdentity(event).event_id;
}

function deriveEventIdentity(event) {
  return runCotestWire("event-derived-id", event);
}

function runCotestWire(commandName, input) {
  const binary = process.env.COTEST_WIRE_BIN;
  if (!binary) {
    throw new Error("Applet mock requires COTEST_WIRE_BIN from the preparation batch");
  }
  const result = spawnSync(binary, [commandName], {
    cwd: process.env.COTEST_ROOT ?? process.cwd().replace(/[\\/]e2e$/, ""),
    encoding: "utf8",
    input: canonicalJson(input),
  });
  if (result.status !== 0) {
    throw new Error(`cotest-wire ${commandName} failed: ${result.stderr}`);
  }
  return JSON.parse(result.stdout);
}

function safeToken(value) {
  const safe = String(value ?? "bridge-demo")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return safe || "bridge-demo";
}

function detachedEventProof(
  event,
  actorDid,
  verificationMethod,
  signingKey,
  proofCreatedAt,
) {
  const createdAt = proofCreatedAt ?? rfc3339Now();
  const signingJwk = signingKey.export({ format: "jwk" });
  if (typeof signingJwk.d !== "string") {
    throw new Error("Applet Event signing key has no private seed");
  }
  return runCotestWire("event-envelope-proof", {
    actor_did: actorDid,
    verification_method: verificationMethod,
    created_at: createdAt,
    event,
    signing_seed_b64url: signingJwk.d,
  });
}

function exactObjectKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === [...expected].sort()[index])
  );
}

// One closed producer-signed Ghost message (event-envelope.schema.json):
// `actor_id` is the accountable Ghost, the installed Service executes and signs
// it with its registration producer key, and `authorization_ref` cites the
// active grant of the Ghost itself (applet-integration.md §8, §9.1, §11).
// The external message provenance is the signed top-level `external_ref`.
function signedGhostMessageEvent({
  packageInfo,
  provision,
  authorizationRef,
  realmId,
  strandId,
  externalId,
  externalMessageId,
  text,
}) {
  const event = {
    kind: "ak.message.create",
    realm_id: realmId,
    scope_ref: { kind: "realm", realm_id: realmId },
    actor_id: provision.ghost_actor_id,
    executed_by: { kind: "service", service_id: packageInfo.serviceId },
    authorization_ref: authorizationRef,
    applet_id: packageInfo.appletId,
    external_ref: {
      protocol: "bridge",
      instance_id: "joint-e2e",
      user_id: externalId,
      event_id: externalMessageId,
    },
    created_at: rfc3339Now(),
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      content: {
        kind: "ak.content.text",
        body: text,
      },
    },
  };
  const eventId = deriveEventId(event);
  event.event_id = eventId;
  const messageId = eventId.replace(/^ak:event:/, "ak:message:");
  const verificationMethod = packageInfo.verificationMethod;
  return {
    event: {
      ...event,
      producer_proof: detachedEventProof(
        event,
        verificationMethod.split("#", 1)[0],
        verificationMethod,
        packageInfo.signingKey,
      ),
    },
    eventId,
    messageId,
  };
}

async function submitSignedAppletTransaction({
  colandBase,
  destinationServiceId,
  packageInfo,
  event,
  idempotencyKey,
}) {
  const target = `${String(colandBase).replace(/\/$/, "")}/_arkret/edge/applet/transactions`;
  const operation = "ak.edge.applet.command.transaction.v1";
  const targetUrl = new URL(target);
  const transaction = {
    applet_id: packageInfo.appletId,
    source_id: packageInfo.serviceId,
    events: [event],
  };
  const body = canonicalJson(transaction);
  const contentDigest = `sha-256=:${createHash("sha256")
    .update(body, "utf8")
    .digest("base64")}:`;
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 60;
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" "arkret-operation" ` +
    `"source-service-id" "destination-service-id" "idempotency-key");` +
    `created=${created};expires=${expires};keyid="${packageInfo.verificationMethod}";` +
    `alg="ed25519"`;
  const signatureBase =
    `"@method": POST\n` +
    `"@target-uri": ${target}\n` +
    `"@authority": ${targetUrl.host}\n` +
    `"content-digest": ${contentDigest}\n` +
    `"arkret-operation": ${operation}\n` +
    `"source-service-id": ${packageInfo.serviceId}\n` +
    `"destination-service-id": ${destinationServiceId}\n` +
    `"idempotency-key": ${idempotencyKey}\n` +
    `"@signature-params": ${signatureParams}`;
  const signature = sign(
    null,
    Buffer.from(signatureBase, "utf8"),
    packageInfo.signingKey,
  ).toString("base64");
  return await fetch(target, {
    method: "POST",
    headers: {
      "arkret-operation": operation,
      "content-type": "application/json",
      "content-digest": contentDigest,
      "source-service-id": packageInfo.serviceId,
      "destination-service-id": destinationServiceId,
      "idempotency-key": idempotencyKey,
      "signature-input": `sig1=${signatureParams}`,
      signature: `sig1=:${signature}:`,
    },
    body,
  });
}

async function submitSignedGhostProvision({
  colandBase,
  destinationServiceId,
  packageInfo,
  appletId,
  requestBody,
  idempotencyKey,
}) {
  const target = `${String(colandBase).replace(/\/$/, "")}/_arkret/self/applets/${encodeURIComponent(appletId)}/ghosts/provision`;
  const operation = "ak.self.applet.ghost.command.provision.v1";
  const targetUrl = new URL(target);
  const body = canonicalJson(requestBody);
  const contentDigest = `sha-256=:${createHash("sha256")
    .update(body, "utf8")
    .digest("base64")}:`;
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 60;
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" "arkret-operation" ` +
    `"source-service-id" "destination-service-id" "idempotency-key");` +
    `created=${created};expires=${expires};keyid="${packageInfo.verificationMethod}";` +
    `alg="ed25519"`;
  const signatureBase =
    `"@method": POST\n` +
    `"@target-uri": ${target}\n` +
    `"@authority": ${targetUrl.host}\n` +
    `"content-digest": ${contentDigest}\n` +
    `"arkret-operation": ${operation}\n` +
    `"source-service-id": ${packageInfo.serviceId}\n` +
    `"destination-service-id": ${destinationServiceId}\n` +
    `"idempotency-key": ${idempotencyKey}\n` +
    `"@signature-params": ${signatureParams}`;
  const signature = sign(
    null,
    Buffer.from(signatureBase, "utf8"),
    packageInfo.signingKey,
  ).toString("base64");
  return await fetch(target, {
    method: "POST",
    headers: {
      "arkret-operation": operation,
      "content-type": "application/json",
      "content-digest": contentDigest,
      "source-service-id": packageInfo.serviceId,
      "destination-service-id": destinationServiceId,
      "idempotency-key": idempotencyKey,
      "signature-input": `sig1=${signatureParams}`,
      signature: `sig1=:${signature}:`,
    },
    body,
  });
}

function requestedScopesFromBody(body) {
  const input = body.requested_scopes ??
    body.requested_capabilities ??
    body.capabilities ?? ["ak.message.create", "ak.applet.ghost.provision"];
  return Array.from(new Set(input.map(String)));
}

function serverBaseUrl() {
  const publicBase = process.env.MOCK_APPLET_REGISTRY_PUBLIC_BASE_URL;
  if (publicBase) {
    const parsed = new URL(publicBase);
    if (parsed.protocol !== "https:") {
      throw new Error("Applet management public base must use HTTPS");
    }
    return publicBase.replace(/\/$/, "");
  }
  const actual = server.address();
  if (actual && typeof actual === "object") {
    return `http://127.0.0.1:${actual.port}`;
  }
  return "http://127.0.0.1";
}

function prepareSignedPackage(body) {
  const namespace = body.namespace ?? body.metadata?.namespace ?? "bridge.demo";
  const safe = safeToken(namespace);
  const appletId =
    typeof body.applet_id === "string" &&
    body.applet_id.startsWith("ak:applet:")
      ? body.applet_id
      : typedId("applet");
  const createdAt = rfc3339Now();
  const serviceDid =
    body.service_id_document?.id ??
    `did:webvh:z6mkfixture:applet-${safe}.joint-e2e.local`;
  const serviceId = body.service_id ?? projectDidToCoreId(serviceDid);
  if (!String(serviceId).startsWith("ak:did_core:")) {
    throw new Error("service_id must be a DidCoreId");
  }
  const webhookAuth = body.webhook_auth ?? {
    kind: "http_message_signature",
    key_ref: `${serviceDid}#applet-service-key`,
    accepted_signature_algorithms: ["ed25519"],
  };
  const webhookPublicJwk =
    body.service_signing_public_jwk ??
    developmentAppletPublicJwk(webhookAuth.key_ref);
  const webhookPublicKeyMaterial = canonicalJson(webhookPublicJwk);
  const serviceIdDocument = body.service_id_document ?? {
    id: serviceDid,
    verificationMethod: {
      [webhookAuth.key_ref]: webhookPublicKeyMaterial,
    },
    updated: createdAt,
  };
  const acceptedKeyMaterial = serviceIdDocument.verificationMethod?.[webhookAuth.key_ref];
  if (typeof acceptedKeyMaterial !== "string") {
    throw new Error("Applet service DID document is missing its webhook signing key");
  }
  const registrationEpochEvidence = {
    did: serviceIdDocument.id,
    document_digest: runCotestWire("did-document-digest", serviceIdDocument),
    method_version_evidence:
      body.service_id_method_version_evidence ??
      (serviceDid.startsWith("did:webvh:")
        ? {
            method: "did:webvh",
            version_time: createdAt,
            unversioned_refetch: false,
          }
        : {
            method: serviceDid.split(":").slice(0, 2).join(":"),
            unversioned_refetch: true,
          }),
    accepted_signing_keys: [
      {
        key_ref: webhookAuth.key_ref,
        public_key_digest: `sha256:${createHash("sha256").update(acceptedKeyMaterial).digest("hex")}`,
      },
    ],
  };
  const packageBase = {
    schema: "ak.schema.applet_package.v1",
    package_id: body.package_id ?? `package:${safe}:${uuidV7Like()}`,
    applet_id: appletId,
    service_id: serviceId,
    controller_principal_id: body.controller_principal_id ?? registryId,
    base_url: body.base_url ?? serverBaseUrl(),
    claimed_profiles: [
      "ak.profile.applet_bridge.v1",
      "ak.profile.applet_service.v1",
    ],
    protocols: body.protocols ?? ["bridge"],
    namespaces: body.namespaces ?? {
      actors: [
        {
          exclusive: true,
          pattern:
            body.actor_namespace_pattern ?? `did:webvh:*:${serviceDid.split(":")[3]}:ghost-${safe}:*`,
        },
      ],
      realms: [{ exclusive: true, pattern: `bridge:${safe}:*` }],
      handles: [{ exclusive: true, pattern: `${safe}/*` }],
    },
    requested_scopes: requestedScopesFromBody(body),
    endpoint_policy: body.endpoint_policy ?? {
      endpoints: [
        {
          method: "POST",
          path: "/_arkret/edge/applet/managed-actors/author",
          auth: "none",
        },
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
    receive_signals: body.receive_signals ?? false,
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
    created_at: createdAt,
  };
  if (new URL(packageBase.base_url).protocol !== "https:") {
    throw new Error("A signed Applet Package requires an HTTPS management base_url");
  }
  if (body.widget) {
    packageBase.widget = body.widget;
  }
  packageBase.registration_epoch =
    body.registration_epoch ??
    registrationEpochHash(packageBase, registrationEpochEvidence);
  const packageDigest = canonicalHash(packageBase);
  const sealedForSignature = {
    ...packageBase,
    package_digest: packageDigest,
  };
  const sealed = { ...packageBase, package_digest: packageDigest };
  const payloadDigest = canonicalHash(sealedForSignature);
  // Detached JWS per RFC 7515 appendix F, matching the SDK contract
  // (arkret-rust-sdk signatures/proof.rs): wire form is `header..signature`
  // with an empty payload segment, signed over `header.BASE64URL(payload)`.
  const jwsHeader = Buffer.from('{"alg":"Ed25519"}', "utf8").toString(
    "base64url",
  );
  const signingInput = `${jwsHeader}.${Buffer.from(canonicalJson(sealedForSignature), "utf8").toString("base64url")}`;
  const signature = sign(
    null,
    Buffer.from(signingInput, "utf8"),
    privateKey,
  ).toString("base64url");
  const jws = `${jwsHeader}..${signature}`;
  const appletPackage = {
    ...sealed,
    proof: {
      kind: "detached_jws",
      verification_method: registryVerificationMethod,
      payload_digest: payloadDigest,
      created_at: createdAt,
      jws,
    },
  };
  const packageInfo = {
    appletId,
    appletPackage,
    namespace,
    safe,
    serviceId,
    serviceDid,
    packageDigest,
    registrationEpoch: packageBase.registration_epoch,
    ...(body.bot_actor_initial_resolution !== undefined
      ? { botInitialResolution: body.bot_actor_initial_resolution }
      : {}),
    ...(body.bot_actor_method_history_evidence !== undefined
      ? { botMethodHistoryEvidence: body.bot_actor_method_history_evidence }
      : {}),
    ...(body.bot_signing_verification_method !== undefined
      ? { botVerificationMethod: body.bot_signing_verification_method }
      : {}),
    botSigningKey: body.bot_signing_private_jwk
      ? createPrivateKey({ key: body.bot_signing_private_jwk, format: "jwk" })
      : undefined,
    verificationMethod: webhookAuth.key_ref,
    signingKey: body.service_signing_private_jwk
      ? createPrivateKey({
          key: body.service_signing_private_jwk,
          format: "jwk",
        })
      : developmentAppletPrivateKey(webhookAuth.key_ref),
  };
  // The caller derives epoch evidence from its formal DID operation and puts
  // it only in the signed registration Event. This response intentionally has
  // no evidence sibling or helper projection.
  return {
    packageInfo,
    response: {
      applet_package: appletPackage,
      package_digest: packageDigest,
      signing_did: registryDid,
      service_id_document: serviceIdDocument,
    },
  };
}

const server = createServer(isolateRequestFailure(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect/authoring-reload" && req.method === "POST") {
    reloadDurableAuthoringState();
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (
    url.pathname === "/inspect/station-key-current" &&
    req.method === "POST"
  ) {
    const body = await readJson(req);
    currentStationVerificationMethod = body?.rotated
      ? `${stationDid()}#notary-key-rotated`
      : `${stationDid()}#notary-key`;
    res.end(
      JSON.stringify({
        ok: true,
        verification_method: currentStationVerificationMethod,
      }),
    );
    return;
  }

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

  if (url.pathname === "/healthz" || url.pathname === "/health") {
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
    const key = req.headers["idempotency-key"];
    if (key !== undefined && (typeof key !== "string" || key.length === 0)) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_idempotency_key" }));
      return;
    }
    const requestDigest = canonicalHash(body);
    const original = key ? signedPackageOutcomes.get(key) : undefined;
    if (original) {
      if (original.requestDigest !== requestDigest) {
        res.statusCode = 409;
        res.end(JSON.stringify({ error: "sign_package_idempotency_conflict" }));
        return;
      }
      res.end(canonicalJson(original.response));
      return;
    }
    let prepared;
    try {
      prepared = prepareSignedPackage(body);
    } catch (error) {
      console.error(`[mock-applet-registry] package preparation: ${error.name}: ${error.message}`);
      throw error;
    }
    const appletId = prepared.packageInfo.appletId;
    const previous = packagesByApplet.get(appletId);
    packagesByApplet.set(appletId, prepared.packageInfo);
    if (key) signedPackageOutcomes.set(key, { requestDigest, response: prepared.response });
    try {
      // Package state and its exact replay result share one durable replacement.
      persistDurableAuthoringState();
    } catch (error) {
      if (previous) packagesByApplet.set(appletId, previous);
      else packagesByApplet.delete(appletId);
      if (key) signedPackageOutcomes.delete(key);
      throw error;
    }
    if (key && req.headers["x-cotest-drop-sign-package-response"] === "1") {
      console.error("[mock-applet-registry] sign-package durable response deliberately lost");
      res.destroy();
      return;
    }
    res.end(canonicalJson(prepared.response));
    return;
  }

  if (url.pathname === "/inspect/bot-authoring-material" && req.method === "POST") {
    const body = await readJson(req);
    const packageInfo = packagesByApplet.get(body?.applet_id);
    if (!packageInfo || !body.request_id || !body.effective_scope || !body.material) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_bot_authoring_material" }));
      return;
    }
    const key = canonicalJson([body.effective_scope, body.request_id]);
    packageInfo.botAuthoringMaterials ??= {};
    const existing = packageInfo.botAuthoringMaterials[key];
    if (existing && canonicalJson(existing) !== canonicalJson(body.material)) {
      res.statusCode = 409;
      res.end(JSON.stringify({ error: "bot_authoring_material_conflict" }));
      return;
    }
    packageInfo.botAuthoringMaterials[key] = body.material;
    persistDurableAuthoringState();
    res.end(JSON.stringify({ status: "stored" }));
    return;
  }

  if (url.pathname === "/inspect/ghost-authoring-material" && req.method === "POST") {
    const body = await readJson(req);
    const packageInfo = packagesByApplet.get(body?.applet_id);
    if (!packageInfo || !body.external_ref || !body.material) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_ghost_authoring_material" }));
      return;
    }
    packageInfo.ghostAuthoringMaterials ??= {};
    packageInfo.ghostAuthoringMaterials[canonicalJson(body.external_ref)] = body.material;
    persistDurableAuthoringState();
    res.end(JSON.stringify({ status: "stored" }));
    return;
  }

  if (url.pathname === "/identity" && req.method === "GET") {
    res.end(JSON.stringify({ did: registryDid, public_jwk: publicJwk }));
    return;
  }

  if (
    url.pathname === "/_arkret/edge/applet/managed-actors/author" &&
    req.method === "POST"
  ) {
    const body = await readJson(req);
    if (!body || !exactObjectKeys(body, ["authoring_request"])) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_author_request" }));
      return;
    }
    const authoringRequest = body.authoring_request;
    const packageInfo = packagesByApplet.get(
      authoringRequest?.basis?.applet_id,
    );
    if (!packageInfo) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "applet_package_not_found" }));
      return;
    }
    const requestDigest = canonicalHash(authoringRequest);
    const subject = [
      authoringRequest?.purpose,
      authoringRequest?.basis?.applet_id,
      authoringRequest?.basis?.target_station_id,
      canonicalJson(authoringRequest?.basis?.effective_scope ?? null),
      authoringRequest?.basis?.request_id ?? "",
      canonicalJson(authoringRequest?.basis?.external_ref ?? null),
    ].join("\n");
    const existing = managedActorAuthoringOutcomes.get(subject);
    if (existing) {
      if (existing.requestDigest === requestDigest) {
        res.end(canonicalJson(existing.outcome));
        return;
      }
    }
    const material = authoringRequest?.purpose === "provision_bot"
      ? packageInfo.botAuthoringMaterials?.[canonicalJson([authoringRequest?.basis?.effective_scope, authoringRequest?.basis?.request_id])]
      : packageInfo.ghostAuthoringMaterials?.[canonicalJson(authoringRequest?.basis?.external_ref ?? null)];
    if (!material?.actor_id || !material.initial_resolution || !material.method_history_evidence) {
      res.statusCode = 409;
      res.end(JSON.stringify({ error: "applet_managed_actor_authoring_material_missing" }));
      return;
    }
    const servicePrivateJwk = packageInfo.signingKey.export({ format: "jwk" });
    if (typeof servicePrivateJwk.d !== "string") {
      res.statusCode = 500;
      res.end(JSON.stringify({ error: "applet_service_key_unavailable" }));
      return;
    }
    const registrationRef = authoringRequest?.purpose === "provision_bot"
      ? authoringRequest?.basis?.registration_event_ref
      : material.registration_ref;
    if (typeof registrationRef !== "string") {
      res.statusCode = 409;
      res.end(JSON.stringify({ error: "managed_actor_registration_ref_unavailable" }));
      return;
    }
    const outcome = runCotestWire("managed-actor-author", {
      authoring_request: authoringRequest,
      applet_package: packageInfo.appletPackage,
      ...material,
      registration_ref: registrationRef,
      service_signing_seed_b64url: servicePrivateJwk.d,
      service_verification_method: packageInfo.verificationMethod,
      station_id: stationId(),
      station_verification_method:
        currentStationVerificationMethod,
      station_public_jwk: createPublicKey(
        stationNotaryPrivateKey(),
      ).export({ format: "jwk" }),
      trust_domain: "ak:trust_domain:coland.local",
    });
    if (outcome.error) {
      res.statusCode = outcome.status ?? 400;
      res.end(canonicalJson({ error: outcome.error, detail: outcome.detail }));
      return;
    }
    managedActorAuthoringOutcomes.set(subject, {
      requestDigest,
      outcome,
    });
    persistDurableAuthoringState();
    res.end(canonicalJson(outcome));
    return;
  }

  if (url.pathname === "/external-event" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.applet_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_applet_id" }));
      return;
    }
    const colandBase =
      body.coland_base_url ??
      process.env.COLAND_BASE_URL ??
      process.env.COTEST_COLAND_BASE_URL;
    if (!colandBase) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_coland_base_url" }));
      return;
    }
    const packageInfo = packagesByApplet.get(body.applet_id);
    if (!packageInfo) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "unknown_applet_package" }));
      return;
    }
    const externalId = String(
      body.external_user?.id ?? body.external_id ?? "bot",
    );
    const displayName = body.external_user?.display_name ?? body.display_name;
    const requestedExternalRef = body.ghost_creation?.external_ref;
    const ghostKey = [
      body.applet_id,
      requestedExternalRef?.protocol ?? "",
      requestedExternalRef?.instance_id ?? "",
      requestedExternalRef?.external_id ?? externalId,
    ].join("\n");
    let provision = provisionedGhosts.get(ghostKey);
    if (!provision) {
      const ghostCreation = body.ghost_creation;
      const bundle = ghostCreation?.managed_actor_bundle;
      const ghostActorId = bundle?.managed_actor_provision_event?.payload?.actor_id;
      if (!ghostCreation?.authoring_request || !bundle || !ghostActorId ||
          typeof ghostCreation.ghost_actor_did !== "string") {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "missing_closed_ghost_creation_unit" }));
        return;
      }
      const provisionAuthorizationRef = body.provision_authorization_ref;
      if (!provisionAuthorizationRef) {
        res.statusCode = 400;
        res.end(
          JSON.stringify({ error: "missing_provision_authorization_ref" }),
        );
        return;
      }
      let provisionResponse;
      try {
        provisionResponse = await submitSignedGhostProvision({
          colandBase,
          destinationServiceId: body.destination_id,
          packageInfo,
          appletId: body.applet_id,
          idempotencyKey: `provision-${body.applet_id}-${safeToken(externalId)}`,
          requestBody: {
            authoring_request: ghostCreation.authoring_request,
            managed_actor_bundle: bundle,
          },
        });
      } catch (err) {
        res.statusCode = 502;
        res.end(
          JSON.stringify({
            error: "upstream_unreachable",
            detail: String(err),
          }),
        );
        return;
      }
      const provisionText = await provisionResponse.text();
      if (!provisionResponse.ok) {
        res.statusCode = provisionResponse.status;
        res.end(provisionText);
        return;
      }
      provision = {
        ...JSON.parse(provisionText),
        ghost_actor_did: ghostCreation.ghost_actor_did,
      };
      provisionedGhosts.set(ghostKey, provision);
    }
    if (body.payload?.kind !== "message") {
      res.end(
        JSON.stringify({
          applet_id: body.applet_id,
          ghost_actor_id: provision.ghost_actor_id,
          principal_control_realm_id: provision.principal_control_realm_id,
          external_id: externalId,
          display_name: displayName,
          authorization_ref: provision.authorization_ref,
        }),
      );
      return;
    }
    const destinationServiceId = body.destination_id;
    if (!destinationServiceId) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_destination_id" }));
      return;
    }
    if (typeof body.strand_id !== "string" || !body.strand_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_strand_id" }));
      return;
    }
    // Deliberately invalid proxy fixture. The terminal child names the Ghost,
    // while this mock signs as Service; live admission must reject the Event.
    // This endpoint is not a managed Account/Device authoring runtime.
    if (typeof body.authorization_ref !== "string" || !body.authorization_ref.startsWith("ak:grant:")) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_authorization_ref" }));
      return;
    }
    const signed = signedGhostMessageEvent({
      packageInfo,
      provision,
      authorizationRef: body.authorization_ref,
      realmId: body.realm_id,
      strandId: body.strand_id,
      externalId,
      externalMessageId: `msg-${randomUUID()}`,
      text: body.payload.text,
    });
    let upstream;
    try {
      upstream = await submitSignedAppletTransaction({
        colandBase,
        destinationServiceId,
        packageInfo,
        event: signed.event,
        idempotencyKey:
          body.idempotency_key ??
          `external-${body.applet_id}-${safeToken(externalId)}-${Date.now()}`,
      });
    } catch (err) {
      // coland unreachable / connection refused / timeout: degrade to a
      // structured 502 instead of letting the rejected promise escape the
      // createServer async callback (process-level unhandledRejection) and
      // leaving the client hung with no status written.
      res.statusCode = 502;
      res.end(
        JSON.stringify({ error: "upstream_unreachable", detail: String(err) }),
      );
      return;
    }
    const upstreamText = await upstream.text();
    if (!upstream.ok) {
      res.statusCode = upstream.status;
      res.end(upstreamText);
      return;
    }
    const outcome = JSON.parse(upstreamText);
    if (outcome.status !== "accepted") {
      res.statusCode = 422;
      res.end(upstreamText);
      return;
    }
    res.end(
      JSON.stringify({
        applet_id: body.applet_id,
        ghost_actor_id: provision.ghost_actor_id,
        external_id: externalId,
        display_name: displayName,
        authorization_ref: provision.authorization_ref,
        message_id: signed.messageId,
        event_id: signed.eventId,
        realm_id: body.realm_id,
        portal_realm_id: body.realm_id,
      }),
    );
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
}));

// The runner owns this loopback server's lifetime. Avoid racing a reused
// Playwright connection against Node's idle keep-alive expiry during the suite.
// Request and header deadlines remain enforced by the HTTP server.
server.keepAliveTimeout = 0;
server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-applet-registry] listening on http://127.0.0.1:${actual.port} (did=${registryDid})`,
  );
});

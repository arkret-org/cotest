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
//   POST /_arkret/edge/applet/install/author
//     Verifies a Principal-Server-signed install authoring request and returns
//     one Applet-service-signed managed-actor bundle for commit relay.
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
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from "node:crypto";
import { createEd25519KeyPair } from "./_shared/keypairs.mjs";
import { handleInspect } from "./_shared/inspect.mjs";
import { canonicalJson, readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_APPLET_REGISTRY_PORT ?? "0", 10);
const durableStateFile = process.env.MOCK_APPLET_REGISTRY_STATE_FILE;
const durableState =
  durableStateFile && existsSync(durableStateFile)
    ? JSON.parse(readFileSync(durableStateFile, "utf8"))
    : {};

// Auto-generate the registry DID unless overridden, so each harness run
// gets a unique registry identity (preventing test cross-contamination
// across runs that share a persistent backing store).
const configuredRegistryDid =
  process.env.MOCK_APPLET_REGISTRY_DID ?? durableState.registryDid;
const registryFullDid = configuredRegistryDid?.startsWith("ak:did_core:")
  ? `did:${configuredRegistryDid.slice("ak:did_core:".length)}`
  : (configuredRegistryDid ??
    `did:web:applet-registry-${randomUUID().slice(0, 8)}.joint-e2e.local`);
const registryDid = configuredRegistryDid?.startsWith("ak:did_core:")
  ? configuredRegistryDid
  : `ak:did_core:${registryFullDid.slice("did:".length)}`;

const persistedPrivateKey = durableState.registryPrivateJwk
  ? createPrivateKey({ key: durableState.registryPrivateJwk, format: "jwk" })
  : undefined;
const generatedKeyPair = persistedPrivateKey
  ? undefined
  : createEd25519KeyPair("mock-applet-registry-key-1");
const privateKey = persistedPrivateKey ?? generatedKeyPair.privateKey;
const publicKey = createPublicKey(privateKey);
const publicJwk = publicKey.export({ format: "jwk" });
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
const installAuthoringOutcomes = new Map(
  durableState.installAuthoringOutcomes ?? [],
);
let currentPrincipalServerVerificationMethod = `${principalServerFullId()}#notary-key`;
const provisionedGhosts = new Map();
const actorSequences = new Map();

function persistDurableAuthoringState() {
  if (!durableStateFile) {
    throw new Error(
      "MOCK_APPLET_REGISTRY_STATE_FILE is required for durable authoring",
    );
  }
  mkdirSync(dirname(durableStateFile), { recursive: true });
  const packages = [...packagesByApplet].map(([appletId, packageInfo]) => [
    appletId,
    {
      ...packageInfo,
      signingKey: undefined,
      signingPrivateJwk: packageInfo.signingKey.export({ format: "jwk" }),
      botSigningKey: undefined,
      botSigningPrivateJwk: packageInfo.botSigningKey?.export({
        format: "jwk",
      }),
    },
  ]);
  const state = {
    registryDid,
    registryPrivateJwk: privateKey.export({ format: "jwk" }),
    packages,
    installAuthoringOutcomes: [...installAuthoringOutcomes],
  };
  const temporary = `${durableStateFile}.${process.pid}.tmp`;
  writeFileSync(temporary, canonicalJson(state), { mode: 0o600 });
  renameSync(temporary, durableStateFile);
}

function reloadDurableAuthoringState() {
  if (!durableStateFile || !existsSync(durableStateFile)) {
    throw new Error("durable Applet authoring state is unavailable");
  }
  const state = JSON.parse(readFileSync(durableStateFile, "utf8"));
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
  installAuthoringOutcomes.clear();
  for (const [requestId, outcome] of state.installAuthoringOutcomes ?? []) {
    installAuthoringOutcomes.set(requestId, outcome);
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
      controller_id: packageBase.controller_id,
      base_url: packageBase.base_url,
      bot_actor_id: packageBase.bot_actor_id,
      protocols: [...packageBase.protocols].sort(),
      namespaces: sortedNamespaces,
      receive_events: packageBase.receive_events,
      receive_signals: packageBase.receive_signals,
      rate_limited: packageBase.rate_limited,
      requested_scopes: [...packageBase.requested_scopes].sort(),
      created_at: packageBase.created_at,
    },
    service_did_document: {
      full_id: evidence.full_id,
      document_digest: evidence.did_document_digest,
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

function principalServerId() {
  return (
    process.env.COTEST_SOLAND_SERVICE_ID ??
    "ak:did_core:key:z6MkquRrzPs7F2ueYKgkbi6CgpYqwhbpBRDLeyWEAHVBxAdN"
  );
}

function principalServerFullId() {
  return (
    process.env.COTEST_SOLAND_SERVICE_FULL_ID ??
    "did:key:z6MkquRrzPs7F2ueYKgkbi6CgpYqwhbpBRDLeyWEAHVBxAdN"
  );
}

function configuredPrincipalServerSeed() {
  const encoded = process.env.COTEST_SOLAND_SERVICE_SIGNING_KEY?.trim();
  if (!encoded) return undefined;
  const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const seed = Buffer.from(
    normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="),
    "base64",
  );
  if (seed.length !== 32) {
    throw new Error(
      "COTEST_SOLAND_SERVICE_SIGNING_KEY must decode to 32 bytes",
    );
  }
  return seed;
}

function principalServerNotaryPrivateKey() {
  const seed =
    configuredPrincipalServerSeed() ??
    createHash("sha256")
      .update("soland:notary-ephemeral:")
      .update(principalServerId())
      .digest();
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function principalServerNotaryDescriptor() {
  const publicKeyDer = createPublicKey(
    principalServerNotaryPrivateKey(),
  ).export({
    format: "der",
    type: "spki",
  });
  const publicKeyBytes = Buffer.from(
    publicKeyDer.subarray(publicKeyDer.length - 32),
  );
  return {
    kind: "single_signer",
    signer: {
      actor_id: principalServerId(),
      verification_method: `${principalServerFullId()}#notary-key`,
      key_kind: "ed25519_raw32",
      jose_algorithm: "Ed25519",
      frozen_public_key_b64u: publicKeyBytes.toString("base64url"),
      frozen_public_key_digest: `sha256:${createHash("sha256")
        .update(publicKeyBytes)
        .digest("hex")}`,
    },
  };
}

function developmentAppletPrivateKey(verificationMethod) {
  const seed = createHash("sha256")
    .update("soland:applet-service-key:")
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
  const binary = process.env.COTEST_WIRE_BIN;
  const command = binary ?? "cargo";
  const args = binary
    ? ["event-derived-id"]
    : ["run", "--quiet", "--bin", "cotest-wire", "--", "event-derived-id"];
  const result = spawnSync(command, args, {
    cwd: process.env.COTEST_ROOT ?? process.cwd().replace(/[\\/]e2e$/, ""),
    encoding: "utf8",
    input: canonicalJson(event),
  });
  if (result.status !== 0) {
    throw new Error(`derive Event id failed: ${result.stderr}`);
  }
  return JSON.parse(result.stdout);
}

function validFormalEventEnvelope(event) {
  const binary = process.env.COTEST_WIRE_BIN;
  const command = binary ?? "cargo";
  const args = binary
    ? ["event-envelope-parse"]
    : ["run", "--quiet", "--bin", "cotest-wire", "--", "event-envelope-parse"];
  const result = spawnSync(command, args, {
    cwd: process.env.COTEST_ROOT ?? process.cwd().replace(/[\\/]e2e$/, ""),
    encoding: "utf8",
    input: canonicalJson(event),
  });
  return result.status === 0;
}

function safeToken(value) {
  const safe = String(value ?? "bridge-demo")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return safe || "bridge-demo";
}

function nextActorSequence(actorDid) {
  const next = (actorSequences.get(actorDid) ?? -1) + 1;
  actorSequences.set(actorDid, next);
  return next;
}

function currentHlc() {
  return `${Date.now().toString(16).padStart(12, "0")}-0000-00000000`;
}

function detachedEventProof(
  event,
  actorDid,
  verificationMethod,
  signingKey,
  actorFullDid,
  proofCreatedAt,
) {
  const createdAt = proofCreatedAt ?? rfc3339Now();
  const signingJwk = signingKey.export({ format: "jwk" });
  if (typeof signingJwk.d !== "string") {
    throw new Error("Applet Event signing key has no private seed");
  }
  const binary = process.env.COTEST_WIRE_BIN;
  const command = binary ?? "cargo";
  const args = binary
    ? ["event-proof"]
    : ["run", "--quiet", "--bin", "cotest-wire", "--", "event-proof"];
  const result = spawnSync(command, args, {
    cwd: process.env.COTEST_ROOT ?? process.cwd().replace(/[\\/]e2e$/, ""),
    encoding: "utf8",
    input: canonicalJson({
      actor_did:
        actorFullDid ??
        (actorDid.startsWith("ak:did_core:")
          ? `did:${actorDid.slice("ak:did_core:".length)}`
          : actorDid),
      verification_method: verificationMethod,
      created_at: createdAt,
      event,
      signing_seed_b64url: signingJwk.d,
    }),
  });
  if (result.status !== 0) {
    throw new Error(`derive Event proof failed: ${result.stderr}`);
  }
  return JSON.parse(result.stdout);
}

function detachedJws(binding, signingKey) {
  const protectedHeader = Buffer.from('{"alg":"Ed25519"}', "utf8").toString(
    "base64url",
  );
  const signingInput = `${protectedHeader}.${Buffer.from(
    canonicalJson(binding),
    "utf8",
  ).toString("base64url")}`;
  const signature = sign(
    null,
    Buffer.from(signingInput, "utf8"),
    signingKey,
  ).toString("base64url");
  return `${protectedHeader}..${signature}`;
}

function exactObjectKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === [...expected].sort()[index])
  );
}

function closedObjectKeys(value, required, optional = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => actual.includes(key)) &&
    actual.every((key) => allowed.has(key))
  );
}

function verifyDetachedJws(jws, canonicalPayload, publicKey) {
  if (typeof jws !== "string") return false;
  const parts = jws.split(".");
  if (parts.length !== 3 || parts[1] !== "") return false;
  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch {
    return false;
  }
  if (!exactObjectKeys(header, ["alg"]) || header.alg !== "Ed25519") {
    return false;
  }
  const signingInput = `${parts[0]}.${Buffer.from(canonicalPayload, "utf8").toString("base64url")}`;
  try {
    return verify(
      null,
      Buffer.from(signingInput, "utf8"),
      publicKey,
      Buffer.from(parts[2], "base64url"),
    );
  } catch {
    return false;
  }
}

function authoringRequestUnsigned(request) {
  return {
    schema: request.schema,
    authoring_request_id: request.authoring_request_id,
    basis: request.basis,
    plan_digest: request.plan_digest,
    expires_at: request.expires_at,
  };
}

function authoringRequestProjection(request) {
  return {
    schema: request.schema,
    basis: request.basis,
    plan_digest: request.plan_digest,
    expires_at: request.expires_at,
  };
}

function derivedAuthoringRequestId(request) {
  const hex = canonicalHash(authoringRequestProjection(request)).slice(
    "sha256:".length,
  );
  const bytes = Buffer.from(hex.slice(0, 32), "hex");
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const uuid = bytes.toString("hex");
  return `ak:operation:${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-${uuid.slice(12, 16)}-${uuid.slice(16, 20)}-${uuid.slice(20)}`;
}

function authoringProofBinding(proof) {
  return {
    payload_digest: proof.payload_digest,
    verification_method: proof.verification_method,
    created_at: proof.created_at,
    domain: proof.domain,
    audience: proof.audience,
  };
}

function eventProofBinding(event, proof) {
  const binding = {
    context: "ak.event_proof.v1",
    event_digest: proof.event_digest,
    actor_id: event.actor_id,
    verification_method: proof.verification_method,
  };
  if (proof.signer_resolution_evidence_ref !== undefined) {
    binding.signer_resolution_evidence_ref =
      proof.signer_resolution_evidence_ref;
  }
  if (proof.signer_resolution_evidence_digest !== undefined) {
    binding.signer_resolution_evidence_digest =
      proof.signer_resolution_evidence_digest;
  }
  binding.created_at = proof.created_at;
  if (proof.domain !== undefined) binding.domain = proof.domain;
  if (proof.audience !== undefined) binding.audience = proof.audience;
  return binding;
}

function publicKeyFromDidDocument(document, verificationMethod) {
  if (!document || document.id !== verificationMethod.split("#", 1)[0]) {
    return undefined;
  }
  const methods = document.verificationMethod;
  let material;
  if (Array.isArray(methods)) {
    const entry = methods.find(
      (candidate) => candidate?.id === verificationMethod,
    );
    material = entry?.publicKeyJwk ?? entry?.public_key_jwk;
  } else if (methods && typeof methods === "object") {
    material = methods[verificationMethod];
  }
  if (typeof material === "string") {
    try {
      material = JSON.parse(material);
    } catch {
      return undefined;
    }
  }
  if (!material || typeof material !== "object") return undefined;
  try {
    return createPublicKey({ key: material, format: "jwk" });
  } catch {
    return undefined;
  }
}

async function resolveCurrentAdminKey(basis) {
  const fullDid = basis.install_actor_id.startsWith("ak:did_core:")
    ? `did:${basis.install_actor_id.slice("ak:did_core:".length)}`
    : basis.install_actor_id;
  const baseUrl =
    process.env.SOLAND_BASE_URL ?? process.env.COTEST_SOLAND_BASE_URL;
  if (!baseUrl || typeof fullDid !== "string") return undefined;
  const requestedEvidenceKinds = fullDid.startsWith("did:webvh:")
    ? ["did_webvh"]
    : [];
  let response;
  try {
    response = await fetch(
      `${String(baseUrl).replace(/\/$/, "")}/_arkret/root/identity/resolve`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: canonicalJson({
          did: fullDid,
          requested_evidence_kinds: requestedEvidenceKinds,
        }),
      },
    );
  } catch {
    return undefined;
  }
  if (!response.ok) return undefined;
  const outcome = await response.json();
  if (
    fullDid.startsWith("did:webvh:") &&
    (!outcome.method_evidence ||
      outcome.method_evidence.version_id === undefined)
  ) {
    return undefined;
  }
  return { fullDid, didDocument: outcome.did_document };
}

function validAdminEventEnvelope(event, basis, expectedKind, resolvedAdmin) {
  if (
    !validFormalEventEnvelope(event) ||
    !event ||
    event.kind !== expectedKind ||
    event.actor_id !== basis.install_actor_id ||
    event.principal_server_id !== basis.target_principal_server_id ||
    event.created_at !== basis.requested_at ||
    canonicalJson(event.scope_ref) !== canonicalJson(basis.effective_scope) ||
    event.realm_id !== basis.effective_scope?.realm_id ||
    !Array.isArray(event.proofs) ||
    event.proofs.length !== 1
  ) {
    return false;
  }
  const proof = event.proofs[0];
  const actorFullId = basis.install_actor_id.startsWith("ak:did_core:")
    ? `did:${basis.install_actor_id.slice("ak:did_core:".length)}`
    : basis.install_actor_id;
  const identity = deriveEventIdentity(event);
  const publicKey = publicKeyFromDidDocument(
    resolvedAdmin?.didDocument,
    proof?.verification_method,
  );
  return (
    proof?.kind === "detached_jws" &&
    proof.verification_method?.startsWith(`${actorFullId}#`) &&
    proof.event_digest === identity.event_digest &&
    event.event_id === identity.event_id &&
    publicKey !== undefined &&
    verifyDetachedJws(
      proof.jws,
      canonicalJson(eventProofBinding(event, proof)),
      publicKey,
    )
  );
}

function registrationPayloadFromPackage(packageInfo) {
  const pkg = packageInfo.appletPackage;
  const manifest = {
    claimed_profiles: pkg.claimed_profiles,
    limits: pkg.limits,
    ghost_policy: pkg.ghost_policy,
    delegation_policy: pkg.delegation_policy,
    e2ee_policy: pkg.e2ee_policy,
    registration_epoch_evidence: packageInfo.registrationEpochEvidence,
  };
  if (pkg.widget !== undefined) manifest.widget = pkg.widget;
  return {
    applet_id: pkg.applet_id,
    service_id: pkg.service_id,
    controller_id: pkg.controller_id,
    base_url: pkg.base_url,
    bot_actor_id: pkg.bot_actor_id,
    claimed_profiles: pkg.claimed_profiles,
    protocols: pkg.protocols,
    namespaces: pkg.namespaces,
    receive_events: pkg.receive_events,
    receive_signals: pkg.receive_signals,
    rate_limited: pkg.rate_limited,
    requested_scopes: pkg.requested_scopes,
    registration_epoch: pkg.registration_epoch,
    webhook_auth: pkg.webhook_auth,
    manifest,
    proof: pkg.proof,
    created_at: pkg.created_at,
  };
}

function validEffectiveScope(scope) {
  return scope?.kind === "realm"
    ? exactObjectKeys(scope, ["kind", "realm_id"]) &&
        typeof scope.realm_id === "string" &&
        /^ak:realm:[A-Za-z0-9_-]{44}$/.test(scope.realm_id)
    : scope?.kind === "circle" &&
        exactObjectKeys(scope, ["kind", "realm_id", "circle_id"]) &&
        typeof scope.realm_id === "string" &&
        /^ak:realm:[A-Za-z0-9_-]{44}$/.test(scope.realm_id) &&
        typeof scope.circle_id === "string" &&
        /^ak:circle:[A-Za-z0-9_-]{44}$/.test(scope.circle_id);
}

function validAuthoringPolicies(basis) {
  const approval = basis.approval_request;
  return (
    validEffectiveScope(basis.effective_scope) &&
    exactObjectKeys(approval, [
      "approve_actions",
      "ghost_actor_mode",
      "delegated_native_actors_allowed",
      "e2ee_join_allowed",
      "widget_allowed",
    ]) &&
    Array.isArray(approval.approve_actions) &&
    approval.approve_actions.length > 0 &&
    approval.approve_actions.every(
      (action) => typeof action === "string" && action.length > 0,
    ) &&
    new Set(approval.approve_actions).size ===
      approval.approve_actions.length &&
    ["disallowed", "controller_approved", "policy_declared"].includes(
      approval.ghost_actor_mode,
    ) &&
    typeof approval.delegated_native_actors_allowed === "boolean" &&
    typeof approval.e2ee_join_allowed === "boolean" &&
    typeof approval.widget_allowed === "boolean" &&
    (basis.actor_policy === undefined ||
      (closedObjectKeys(basis.actor_policy, [], ["ghost_actor_mode"]) &&
        (basis.actor_policy.ghost_actor_mode === undefined ||
          ["disallowed", "controller_approved", "policy_declared"].includes(
            basis.actor_policy.ghost_actor_mode,
          )))) &&
    (basis.e2ee_policy === undefined ||
      (closedObjectKeys(basis.e2ee_policy, [], ["mls_join_allowed"]) &&
        (basis.e2ee_policy.mls_join_allowed === undefined ||
          typeof basis.e2ee_policy.mls_join_allowed === "boolean"))) &&
    (basis.widget_policy === undefined ||
      (closedObjectKeys(basis.widget_policy, [], ["widget_allowed"]) &&
        (basis.widget_policy.widget_allowed === undefined ||
          typeof basis.widget_policy.widget_allowed === "boolean")))
  );
}

async function validateInstallAuthoringRequest(request, packageInfo) {
  if (
    !exactObjectKeys(request, [
      "schema",
      "authoring_request_id",
      "basis",
      "plan_digest",
      "expires_at",
      "proof",
    ]) ||
    request.schema !== "ak.schema.applet_install_authoring_request.v1"
  ) {
    return "authoring_request_not_closed";
  }
  const basis = request.basis;
  if (
    !basis ||
    !closedObjectKeys(
      basis,
      [
        "schema",
        "target_principal_server_id",
        "install_actor_id",
        "applet_id",
        "service_id",
        "package_digest",
        "effective_scope",
        "approval_request",
        "requested_at",
        "requested_expires_at",
        "registration_event",
        "capability_grant_events",
      ],
      ["actor_policy", "e2ee_policy", "widget_policy"],
    ) ||
    basis.schema !== "ak.schema.applet_install_authoring_request_basis.v1" ||
    basis.target_principal_server_id !== principalServerId() ||
    basis.applet_id !== packageInfo.appletId ||
    basis.service_id !== packageInfo.serviceId ||
    basis.package_digest !== packageInfo.packageDigest ||
    !validAuthoringPolicies(basis)
  ) {
    return "authoring_request_coordinate_mismatch";
  }
  const expiresAt = Date.parse(request.expires_at);
  const requestedAt = Date.parse(basis.requested_at);
  const requestedExpiresAt = Date.parse(basis.requested_expires_at);
  if (
    !Number.isFinite(expiresAt) ||
    !Number.isFinite(requestedAt) ||
    !Number.isFinite(requestedExpiresAt) ||
    expiresAt !== requestedExpiresAt ||
    requestedExpiresAt <= requestedAt ||
    requestedExpiresAt - requestedAt > 5 * 60 * 1000 ||
    expiresAt <= Date.now() ||
    expiresAt - Date.now() > 5 * 60 * 1000
  ) {
    return "authoring_request_expired";
  }
  if (request.authoring_request_id !== derivedAuthoringRequestId(request)) {
    return "authoring_request_id_mismatch";
  }
  const proof = request.proof;
  const payloadDigest = canonicalHash(authoringRequestUnsigned(request));
  if (
    !exactObjectKeys(proof, [
      "kind",
      "verification_method",
      "payload_digest",
      "created_at",
      "domain",
      "audience",
      "jws",
    ]) ||
    proof.kind !== "detached_jws" ||
    proof.payload_digest !== payloadDigest ||
    proof.domain !== "arkret.applet.install.authoring-request.v1" ||
    proof.audience !== packageInfo.serviceId ||
    proof.created_at !== basis.requested_at ||
    Date.parse(proof.created_at) > Date.now() + 30_000
  ) {
    return "authoring_request_proof_invalid";
  }
  if (
    !verifyDetachedJws(
      proof.jws,
      canonicalJson(authoringProofBinding(proof)),
      createPublicKey(principalServerNotaryPrivateKey()),
    )
  ) {
    return "authoring_request_proof_invalid";
  }
  if (proof.verification_method !== currentPrincipalServerVerificationMethod) {
    return "authoring_request_proof_invalid";
  }
  const resolvedAdmin = await resolveCurrentAdminKey(basis);
  if (!resolvedAdmin) return "authoring_request_admin_key_untrusted";
  const registration = basis.registration_event;
  if (
    !validAdminEventEnvelope(
      registration,
      basis,
      "ak.applet.registration",
      resolvedAdmin,
    ) ||
    canonicalJson(registration?.payload) !==
      canonicalJson(registrationPayloadFromPackage(packageInfo)) ||
    !Array.isArray(basis.capability_grant_events) ||
    basis.capability_grant_events.length === 0
  ) {
    return "authoring_request_event_binding_invalid";
  }
  const approvedActions = new Set();
  let precedingEventId = registration.event_id;
  let precedingActorSeq = registration.actor_seq;
  for (const event of basis.capability_grant_events) {
    const grant = event?.payload?.grant;
    const expectedConstraint = {
      constraint_kind: "authority_control",
      constraint_subkind: "applet_authority",
      effect: "allow",
      evaluation_class: "grant_local",
      applet_id: packageInfo.appletId,
      executed_by: packageInfo.serviceId,
      registration_epoch: packageInfo.registrationEpoch,
    };
    if (
      !validAdminEventEnvelope(
        event,
        basis,
        "ak.capability.grant",
        resolvedAdmin,
      ) ||
      !exactObjectKeys(event.payload, ["grant"]) ||
      !closedObjectKeys(grant, [
        "schema",
        "realm_id",
        "issuer",
        "subject",
        "subject_principal_server_id",
        "actions",
        "resources",
        "capability_action_registry_digest",
        "constraints",
        "issued_at",
        "expires_at",
        "issuer_authority_refs",
      ]) ||
      grant.schema !== "ak.schema.capability.v1" ||
      grant.realm_id !== basis.effective_scope?.realm_id ||
      grant?.issuer !== basis.install_actor_id ||
      grant?.subject !== packageInfo.serviceId ||
      grant?.subject_principal_server_id !== basis.target_principal_server_id ||
      canonicalJson(grant?.resources) !==
        canonicalJson([basis.effective_scope]) ||
      grant.capability_action_registry_digest !==
        packageInfo.capabilityActionRegistryDigest ||
      canonicalJson(grant.constraints) !==
        canonicalJson([expectedConstraint]) ||
      !Array.isArray(grant.issuer_authority_refs) ||
      grant.issuer_authority_refs.length !== 1 ||
      !exactObjectKeys(grant.issuer_authority_refs[0], [
        "kind",
        "realm_id",
        "cell_ref",
        "controller_epoch_at_issuance",
        "authority_generation",
      ]) ||
      grant.issuer_authority_refs[0]?.kind !== "realm_root" ||
      grant.issuer_authority_refs[0]?.realm_id !==
        basis.effective_scope?.realm_id ||
      typeof grant.issuer_authority_refs[0]?.cell_ref !== "string" ||
      !Number.isSafeInteger(
        grant.issuer_authority_refs[0]?.controller_epoch_at_issuance,
      ) ||
      !Number.isSafeInteger(
        grant.issuer_authority_refs[0]?.authority_generation,
      ) ||
      event.actor_seq !== precedingActorSeq + 1 ||
      canonicalJson(event.prev_refs) !== canonicalJson([precedingEventId]) ||
      !Array.isArray(grant?.actions) ||
      grant.actions.length === 0 ||
      grant.actions.some(
        (action) =>
          !basis.approval_request?.approve_actions?.includes(action) ||
          approvedActions.has(action),
      )
    ) {
      return "authoring_request_event_binding_invalid";
    }
    grant.actions.forEach((action) => approvedActions.add(action));
    precedingEventId = event.event_id;
    precedingActorSeq = event.actor_seq;
  }
  return undefined;
}

function deterministicHlc(createdAt, label) {
  const physical = Date.parse(createdAt)
    .toString(16)
    .padStart(12, "0")
    .slice(-12);
  const node = createHash("sha256").update(label).digest("hex").slice(0, 8);
  return `${physical}-0000-${node}`;
}

function signedAppletEvent(
  packageInfo,
  fields,
  proofCreatedAt,
  signerAuthority,
) {
  const event = {
    ...fields,
    actor_id: fields.actor_id,
    principal_server_id: principalServerId(),
    created_at: proofCreatedAt,
    hlc:
      fields.hlc ??
      deterministicHlc(proofCreatedAt, `${fields.kind}:${fields.actor_seq}`),
    prev_refs: fields.prev_refs ?? [],
    refs: fields.refs ?? [],
    requirements: fields.requirements,
    payload: fields.payload,
  };
  const signingAuthority =
    signerAuthority === "bot"
      ? {
          verificationMethod: packageInfo.botVerificationMethod,
          signingKey: packageInfo.botSigningKey,
        }
      : {
          verificationMethod: packageInfo.verificationMethod,
          signingKey: packageInfo.signingKey,
        };
  const eventId = deriveEventId(event);
  event.event_id = eventId;
  return {
    ...event,
    proofs: [
      detachedEventProof(
        event,
        fields.actor_id,
        signingAuthority.verificationMethod,
        signingAuthority.signingKey,
        undefined,
        proofCreatedAt,
      ),
    ],
  };
}

function grantIdFromEvent(event) {
  return String(event.event_id).replace(/^ak:event:/, "ak:grant:");
}

function buildInstallManagedActorBundle(request, packageInfo) {
  const basis = request.basis;
  const createdAt = request.proof.created_at;
  const realmId = basis.effective_scope.realm_id;
  const registrationRef = basis.registration_event.event_id;
  const appletAuthorityRef = grantIdFromEvent(basis.capability_grant_events[0]);
  const botId = packageInfo.botActorId;
  const common = {
    authorization_ref: appletAuthorityRef,
    applet_id: packageInfo.appletId,
  };
  const provisionEvent = signedAppletEvent(
    packageInfo,
    {
      kind: "ak.applet.managed_actor.provision",
      realm_id: realmId,
      scope_ref: { kind: "realm", realm_id: realmId },
      actor_id: packageInfo.serviceId,
      actor_seq: 0,
      ...common,
      requirements: { schema: ["ak.schema.applet_managed_actor_provision.v1"] },
      payload: {
        schema: "ak.schema.applet_managed_actor_provision.v1",
        applet_id: packageInfo.appletId,
        service_id: packageInfo.serviceId,
        actor_id: botId,
        actor_principal_server_id: principalServerId(),
        actor_role: "bot",
        initial_resolution: packageInfo.botInitialResolution,
        method_history_evidence: packageInfo.botMethodHistoryEvidence,
        registration_ref: registrationRef,
        applet_authority_ref: appletAuthorityRef,
      },
    },
    createdAt,
    "service",
  );
  const pcrGenesisEvent = signedAppletEvent(
    packageInfo,
    {
      kind: "ak.realm.create",
      scope_ref: { kind: "realm_genesis" },
      actor_id: botId,
      actor_seq: 0,
      executed_by: packageInfo.serviceId,
      ...common,
      refs: [
        {
          id: provisionEvent.event_id,
          role: "applet_managed_actor_provision",
          critical: true,
        },
      ],
      preconditions: [
        {
          cell: "ak:cell:ak.component.realm.create.v1:null",
          predicate: { op: "head_eq", value: null },
        },
      ],
      requirements: { schema: ["ak.schema.realm_genesis.v1"] },
      payload: {
        object: {
          schema: "ak.schema.realm_genesis.v1",
          purpose: "applet_managed_control",
          genesis_salt: createHash("sha256")
            .update(`${request.authoring_request_id}:bot-pcr`)
            .digest("base64url"),
          trust_domain: "ak:trust_domain:soland.local",
          schema_refs: [
            "ak.schema.realm.v1",
            "ak.profile.principal_control_realm.v1",
          ],
          reducer_profile: "ak.reducer.core.v1",
          encryption_profile: "mls_rfc9420",
          security_class: "standard",
          digest_algorithm: "sha256",
          notary: principalServerNotaryDescriptor(),
          capability_action_registry_digest:
            packageInfo.capabilityActionRegistryDigest,
          initial_resolution: packageInfo.botInitialResolution,
        },
      },
    },
    createdAt,
    "service",
  );
  const accountabilityWithoutProof = {
    schema: "ak.schema.accountability_grant.v1",
    issuer: packageInfo.serviceId,
    subject: botId,
    accountability_scope: "contracted_service",
    not_before: createdAt,
    grant_status: "active",
  };
  const accountabilityPayloadDigest = `sha256:${createHash("sha256")
    .update("ak.accountability-grant-v1\n", "utf8")
    .update(canonicalJson(accountabilityWithoutProof), "utf8")
    .digest("hex")}`;
  const accountabilityEvent = signedAppletEvent(
    packageInfo,
    {
      kind: "ak.identity.accountability_grant",
      realm_id: realmId,
      scope_ref: { kind: "realm", realm_id: realmId },
      actor_id: packageInfo.serviceId,
      actor_seq: 1,
      prev_refs: [provisionEvent.event_id],
      ...common,
      requirements: { schema: ["ak.schema.accountability_grant.v1"] },
      payload: {
        ...accountabilityWithoutProof,
        proof: {
          kind: "detached_jws",
          verification_method: packageInfo.verificationMethod,
          payload_digest: accountabilityPayloadDigest,
          created_at: createdAt,
          jws: detachedJws(
            {
              context: "ak.accountability_grant_proof.v1",
              payload_digest: accountabilityPayloadDigest,
              issuer: packageInfo.serviceId,
              subject: botId,
              verification_method: packageInfo.verificationMethod,
              created_at: createdAt,
            },
            packageInfo.signingKey,
          ),
        },
      },
    },
    createdAt,
    "service",
  );
  const profileEvent = signedAppletEvent(
    packageInfo,
    {
      kind: "ak.profile.create",
      realm_id: realmId,
      scope_ref: { kind: "realm", realm_id: realmId },
      actor_id: botId,
      actor_seq: 0,
      executed_by: packageInfo.serviceId,
      ...common,
      refs: [
        {
          id: accountabilityEvent.event_id,
          role: "accountability",
          critical: true,
        },
      ],
      requirements: { schema: ["ak.schema.actor_profile.v1"] },
      payload: {
        object: {
          schema: "ak.schema.actor_profile.v1",
          realm_id: realmId,
          principal_id: botId,
          actor_kind: "integration",
          display_name: "Applet Bot",
          accountable_principal_ids: [packageInfo.serviceId],
          profile_fields: { managed_by_applet: packageInfo.appletId },
          created_at: createdAt,
        },
      },
    },
    createdAt,
    "service",
  );
  const authoringRequestDigest = canonicalHash(request);
  const unsignedBundle = {
    schema: "ak.schema.applet_managed_actor_authoring_bundle.v1",
    authoring_request_digest: authoringRequestDigest,
    bot_actor_provision_event: provisionEvent,
    bot_pcr_genesis_event: pcrGenesisEvent,
    bot_accountability_grant_event: accountabilityEvent,
    bot_profile_event: profileEvent,
  };
  const bundlePayloadDigest = canonicalHash(unsignedBundle);
  const proof = {
    kind: "detached_jws",
    verification_method: packageInfo.verificationMethod,
    payload_digest: bundlePayloadDigest,
    created_at: createdAt,
    domain: "arkret.applet.install.managed-actor-bundle.v1",
    audience: principalServerId(),
    jws: "",
  };
  proof.jws = detachedJws(authoringProofBinding(proof), packageInfo.signingKey);
  return { ...unsignedBundle, proof };
}

async function readRealmFrontier(solandBase, authorization, realmId) {
  const response = await fetch(
    `${String(solandBase).replace(/\/$/, "")}/_arkret/self/seals/frontier`,
    {
      method: "QUERY",
      headers: { authorization, "content-type": "application/json" },
      body: canonicalJson({ realm_id: realmId }),
    },
  );
  const responseText = await response.text();
  if (!response.ok) {
    throw new Error(
      `Realm frontier returned ${response.status}: ${responseText}`,
    );
  }
  const body = JSON.parse(responseText);
  const frontier = body?.frontier;
  const leaves = frontier?.seal_basis?.leaves;
  if (
    frontier?.kind !== "realm_seal" ||
    !Array.isArray(leaves) ||
    leaves.length !== 1 ||
    typeof leaves[0] !== "string"
  ) {
    throw new Error(
      "Realm frontier response is missing the accepted Seal basis",
    );
  }
  return {
    sealRef: leaves[0],
    sealBasis: { leaves: [...leaves] },
  };
}

function signedGhostMessageEvent({
  packageInfo,
  provision,
  principalServerId,
  authorizationRef,
  realmId,
  strandId,
  sealRef,
  externalId,
  displayName,
  text,
}) {
  const createdAt = rfc3339Now();
  const keyFragment = packageInfo.verificationMethod.split("#", 2)[1];
  const event = {
    kind: "ak.message.create",
    realm_id: realmId,
    scope_ref: { kind: "realm", realm_id: realmId },
    actor_id: provision.ghost_actor_id,
    principal_server_id: principalServerId,
    actor_seq: nextActorSequence(provision.ghost_actor_id),
    created_at: createdAt,
    hlc: currentHlc(),
    prev_refs: [provision.profile_event_ref],
    refs: [],
    executed_by: packageInfo.serviceId,
    authorization_ref: authorizationRef,
    applet_id: packageInfo.appletId,
    seal_ref: sealRef,
    auth_context: {
      actor_id: packageInfo.serviceId,
      key_id: keyFragment ?? packageInfo.verificationMethod,
      key_epoch: 0,
    },
    external_ref: {
      protocol: "bridge",
      instance_id: "joint-e2e",
      external_id: externalId,
    },
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      content: {
        kind: "ak.content.text",
        body: text,
        portal: {
          applet_id: packageInfo.appletId,
          bot_actor_id: packageInfo.botActorId,
          ghost_actor_id: provision.ghost_actor_id,
          portal_realm_id: realmId,
          external_id: externalId,
          display_name: displayName,
        },
      },
    },
  };
  const eventId = deriveEventId(event);
  event.event_id = eventId;
  const messageId = eventId.replace(/^ak:event:/, "ak:message:");
  // Applet-originated ghost events are executed and signed by the installed
  // service principal; actor_id remains the accountable ghost identity.
  const verificationMethod = packageInfo.verificationMethod;
  return {
    event: {
      ...event,
      proofs: [
        detachedEventProof(
          event,
          provision.ghost_actor_id,
          verificationMethod,
          packageInfo.signingKey,
        ),
      ],
    },
    eventId,
    messageId,
  };
}

async function submitSignedAppletTransaction({
  solandBase,
  destinationServiceId,
  packageInfo,
  event,
  idempotencyKey,
}) {
  const target = `${String(solandBase).replace(/\/$/, "")}/_arkret/edge/applet/transactions`;
  const targetUrl = new URL(target);
  const transaction = {
    source_service_id: packageInfo.serviceId,
    events: [event],
  };
  const body = canonicalJson(transaction);
  const contentDigest = `sha-256=:${createHash("sha256")
    .update(body, "utf8")
    .digest("base64")}:`;
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 60;
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" ` +
    `"source-service-id" "destination-service-id" "idempotency-key");` +
    `created=${created};expires=${expires};keyid="${packageInfo.verificationMethod}";` +
    `alg="ed25519"`;
  const signatureBase =
    `"@method": POST\n` +
    `"@target-uri": ${target}\n` +
    `"@authority": ${targetUrl.host}\n` +
    `"content-digest": ${contentDigest}\n` +
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
  solandBase,
  destinationServiceId,
  packageInfo,
  appletId,
  requestBody,
  idempotencyKey,
}) {
  const target = `${String(solandBase).replace(/\/$/, "")}/_arkret/self/applets/${encodeURIComponent(appletId)}/ghosts/provision`;
  const targetUrl = new URL(target);
  const body = canonicalJson(requestBody);
  const contentDigest = `sha-256=:${createHash("sha256")
    .update(body, "utf8")
    .digest("base64")}:`;
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 60;
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" ` +
    `"source-service-id" "destination-service-id" "idempotency-key");` +
    `created=${created};expires=${expires};keyid="${packageInfo.verificationMethod}";` +
    `alg="ed25519"`;
  const signatureBase =
    `"@method": POST\n` +
    `"@target-uri": ${target}\n` +
    `"@authority": ${targetUrl.host}\n` +
    `"content-digest": ${contentDigest}\n` +
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
    typeof body.applet_id === "string" &&
    body.applet_id.startsWith("ak:applet:")
      ? body.applet_id
      : typedId("applet");
  const createdAt = rfc3339Now();
  const serviceFullId =
    body.service_id_document?.id ??
    body.service_id ??
    `did:webvh:z6mkfixture:applet-${safe}.joint-e2e.local`;
  const serviceId = String(body.service_id ?? serviceFullId).startsWith(
    "ak:did_core:",
  )
    ? body.service_id
    : `ak:did_core:${String(serviceFullId).slice("did:".length)}`;
  const webhookAuth = body.webhook_auth ?? {
    kind: "http_message_signature",
    key_ref: `${serviceFullId}#applet-service-key`,
    accepted_signature_algorithms: ["ed25519"],
  };
  const webhookPublicJwk =
    body.service_signing_public_jwk ??
    developmentAppletPublicJwk(webhookAuth.key_ref);
  const webhookPublicKeyMaterial = canonicalJson(webhookPublicJwk);
  const serviceIdDocument = body.service_id_document ?? {
    id: serviceFullId,
    verificationMethod: {
      [webhookAuth.key_ref]: webhookPublicKeyMaterial,
    },
    updated: createdAt,
  };
  const registrationEpochEvidence = {
    full_id: serviceIdDocument.id,
    did_document_digest: canonicalHash(serviceIdDocument),
    method_version_evidence:
      body.service_id_method_version_evidence ??
      (serviceFullId.startsWith("did:webvh:")
        ? {
            method: "did:webvh",
            version_time: createdAt,
            unversioned_refetch: false,
          }
        : {
            method: `did:${String(serviceId).split(":")[1]}`,
            unversioned_refetch: true,
          }),
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
    bot_actor_id:
      body.bot_actor_id ?? `ak:did_core:web:bot-${safe}.joint-e2e.local`,
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
            body.actor_namespace_pattern ?? `did:webvh:*:*:ghost-${safe}:*`,
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
          path: "/_arkret/edge/applet/install/author",
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
      verification_method: `${registryFullDid}#mock-applet-registry-key-1`,
      payload_digest: payloadDigest,
      created_at: createdAt,
      jws,
    },
  };
  packagesByApplet.set(appletId, {
    appletId,
    appletPackage,
    botActorId: packageBase.bot_actor_id,
    namespace,
    safe,
    serviceId,
    serviceFullId,
    packageDigest,
    registrationEpoch: packageBase.registration_epoch,
    registrationEpochEvidence,
    botInitialResolution: body.bot_actor_initial_resolution,
    botMethodHistoryEvidence: body.bot_actor_method_history_evidence,
    botVerificationMethod: body.bot_signing_verification_method,
    botSigningKey: body.bot_signing_private_jwk
      ? createPrivateKey({ key: body.bot_signing_private_jwk, format: "jwk" })
      : undefined,
    capabilityActionRegistryDigest: body.capability_action_registry_digest,
    verificationMethod: webhookAuth.key_ref,
    signingKey: body.service_signing_private_jwk
      ? createPrivateKey({
          key: body.service_signing_private_jwk,
          format: "jwk",
        })
      : developmentAppletPrivateKey(webhookAuth.key_ref),
  });
  persistDurableAuthoringState();
  return {
    applet_package: appletPackage,
    registration_epoch_evidence: registrationEpochEvidence,
    package_digest: packageDigest,
    signing_did: registryDid,
    service_id_document: serviceIdDocument,
  };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect/authoring-reload" && req.method === "POST") {
    reloadDurableAuthoringState();
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (
    url.pathname === "/inspect/principal-server-key-current" &&
    req.method === "POST"
  ) {
    const body = await readJson(req);
    currentPrincipalServerVerificationMethod = body?.rotated
      ? `${principalServerFullId()}#notary-key-rotated`
      : `${principalServerFullId()}#notary-key`;
    res.end(
      JSON.stringify({
        ok: true,
        verification_method: currentPrincipalServerVerificationMethod,
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

  if (
    url.pathname === "/_arkret/edge/applet/install/author" &&
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
    const existing = installAuthoringOutcomes.get(
      authoringRequest?.authoring_request_id,
    );
    if (existing) {
      if (existing.requestDigest !== requestDigest) {
        res.statusCode = 409;
        res.end(JSON.stringify({ error: "authoring_request_id_conflict" }));
        return;
      }
      res.end(canonicalJson(existing.outcome));
      return;
    }
    const invalidReason = await validateInstallAuthoringRequest(
      authoringRequest,
      packageInfo,
    );
    if (invalidReason) {
      res.statusCode =
        invalidReason === "authoring_request_expired" ? 410 : 400;
      res.end(JSON.stringify({ error: invalidReason }));
      return;
    }
    if (
      !packageInfo.botInitialResolution ||
      !packageInfo.botMethodHistoryEvidence ||
      !packageInfo.botVerificationMethod ||
      !packageInfo.botSigningKey ||
      !packageInfo.capabilityActionRegistryDigest
    ) {
      res.statusCode = 409;
      res.end(
        JSON.stringify({ error: "applet_bot_authoring_material_missing" }),
      );
      return;
    }
    const outcome = {
      managed_actor_bundle: buildInstallManagedActorBundle(
        authoringRequest,
        packageInfo,
      ),
    };
    installAuthoringOutcomes.set(authoringRequest.authoring_request_id, {
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
    const solandBase =
      body.soland_base_url ??
      process.env.SOLAND_BASE_URL ??
      process.env.COTEST_SOLAND_BASE_URL;
    const authorization =
      req.headers.authorization ??
      body.authorization ??
      (body.session_credential
        ? `Bearer ${body.session_credential}`
        : undefined);
    if (!solandBase || !authorization) {
      res.statusCode = 400;
      res.end(
        JSON.stringify({ error: "missing_soland_base_url_or_authorization" }),
      );
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
      const ghostActorId = ghostCreation?.ghost_actor_id;
      if (
        typeof ghostActorId !== "string" ||
        typeof ghostCreation?.actor_principal_server_id !== "string" ||
        !ghostCreation?.managed_actor_provision_event ||
        !ghostCreation?.pcr_genesis_event ||
        !ghostCreation?.accountability_grant_event ||
        !ghostCreation?.profile_event
      ) {
        res.statusCode = 400;
        res.end(
          JSON.stringify({ error: "missing_closed_ghost_creation_unit" }),
        );
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
          solandBase,
          destinationServiceId: body.destination_service_id,
          packageInfo,
          appletId: body.applet_id,
          idempotencyKey: `provision-${body.applet_id}-${safeToken(externalId)}`,
          requestBody: {
            schema: "ak.applet.ghost_actor.provision_request.v1",
            applet_id: body.applet_id,
            service_id: packageInfo.serviceId,
            ghost_actor_id: ghostActorId,
            actor_principal_server_id: ghostCreation.actor_principal_server_id,
            ...(displayName ? { display_name: displayName } : {}),
            realm_id: body.realm_id,
            external_ref: ghostCreation.external_ref,
            managed_actor_provision_event:
              ghostCreation.managed_actor_provision_event,
            pcr_genesis_event: ghostCreation.pcr_genesis_event,
            accountability_grant_event:
              ghostCreation.accountability_grant_event,
            profile_event: ghostCreation.profile_event,
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
      provision = JSON.parse(provisionText);
      actorSequences.set(ghostActorId, 0);
      provisionedGhosts.set(ghostKey, provision);
    }
    if (body.payload?.kind !== "message") {
      res.end(
        JSON.stringify({
          applet_id: body.applet_id,
          ghost_actor_id: provision.ghost_actor_id,
          external_id: externalId,
          display_name: displayName,
          authorization_ref: provision.authorization_ref,
        }),
      );
      return;
    }
    const destinationServiceId = body.destination_service_id;
    if (!destinationServiceId) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_destination_service_id" }));
      return;
    }
    if (typeof body.strand_id !== "string" || !body.strand_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_strand_id" }));
      return;
    }
    let sealRef;
    try {
      ({ sealRef } = await readRealmFrontier(
        solandBase,
        authorization,
        body.realm_id,
      ));
    } catch (err) {
      res.statusCode = 502;
      res.end(
        JSON.stringify({
          error: "realm_frontier_unavailable",
          detail: String(err),
        }),
      );
      return;
    }
    const signed = signedGhostMessageEvent({
      packageInfo,
      provision,
      principalServerId: destinationServiceId,
      authorizationRef: body.authorization_ref ?? provision.authorization_ref,
      realmId: body.realm_id,
      strandId: body.strand_id,
      sealRef,
      externalId,
      displayName,
      text: body.payload.text,
    });
    let upstream;
    try {
      upstream = await submitSignedAppletTransaction({
        solandBase,
        destinationServiceId,
        packageInfo,
        event: signed.event,
        idempotencyKey:
          body.idempotency_key ??
          `external-${body.applet_id}-${safeToken(externalId)}-${Date.now()}`,
      });
    } catch (err) {
      // soland unreachable / connection refused / timeout: degrade to a
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
    if (!outcome.ok) {
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
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-applet-registry] listening on http://127.0.0.1:${actual.port} (did=${registryDid})`,
  );
});

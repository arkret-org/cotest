// Mock DID document host — the counting "authority" behind DID-P1-C01.
//
// WHY THIS IS A NETWORK MOCK AND NOT AN IN-PROCESS SPY
// ----------------------------------------------------
// The task DID-P1-C01 asks for a resolver spy that is resettable and can be
// counted per DID / purpose. cotest has **no Cargo dependency** on coland /
// flagon / coauth / floria — they are launched as pre-built sibling
// binaries and driven over HTTP (see
// `src/scenarios/_helpers/external_binary.rs`). A Rust trait spy therefore
// cannot be injected into those processes. The only place a cross-process
// "authority fetch" is observable is the wire, so the spy lives here: a DID
// document host that counts every document / log / witness fetch per DID.
// A scenario proves "this operation made zero additional authority network
// calls" by resetting the counters, running the operation, and asserting the
// delta is 0 — stronger evidence than an in-process spy, because it also
// covers fetches made by code cotest does not link against.
//
// RELATIONSHIP TO mock-witness.mjs (no overlap, deliberate seam)
// --------------------------------------------------------------
// `mock-witness.mjs` is the witness *signing authority*: it accepts
// `POST /mock/witness/sign` and returns an attestation over an entry hash,
// enforcing entry-number monotonicity and the prev-hash chain. It does NOT
// host any `did.json` / `did.jsonl` / `did-witness.json` file. This mock is
// the *hosting* side: it serves those three leaves and counts the fetches.
// The two compose via `POST /control/attest`, which asks the configured
// witness mock to sign the current entry and folds the returned attestation
// into this DID's `did-witness.json`. Witness signing logic is NOT duplicated
// here.
//
// ENDPOINTS
// ---------
// Counted (every request below increments the per-DID counters, including
// error responses — a 404 is still an authority network call):
//   GET /.well-known/did.json          did:web / did:webvh document
//   GET /<seg>/…/did.json              path-form document
//   GET /.well-known/did.jsonl         did:webvh log
//   GET /<seg>/…/did.jsonl             path-form log
//   GET /.well-known/did-witness.json  did:webvh witness proofs
//   GET /<seg>/…/did-witness.json      path-form witness proofs
//
// Not counted (harness control plane):
//   GET    /inspect                → handleInspect() shape + counts/dids extras
//   DELETE /inspect                → clear fetch log AND reset counters
//   GET    /inspect/counts[?did=]  → { counts: { [did]: {document,log,witness,total} }, total }
//   POST   /inspect/reset          → same as DELETE /inspect (explicit verb)
//   GET    /control/dids           → registered DIDs, current version, state
//   POST   /control/register       → { did, versions? } register a DID at runtime
//   POST   /control/rotate         → { did, to? } advance/select the current version
//   POST   /control/deactivate     → { did } serve a deactivated document + final entry
//   POST   /control/fail           → { did, status, leaf? } force a status on fetches
//   POST   /control/attest         → { did } pull a witness attestation from mock-witness
//   POST   /control/reset          → restore every DID to version 0 / active / no override
//   GET    /health                 → liveness probe
//
// PRESET VERSIONS, NOT LIVE KEY CEREMONY
// --------------------------------------
// Every DID is registered with `MOCK_DID_HOST_VERSIONS` (default 3) versions
// generated once at startup. `/control/rotate` and `/control/deactivate` only
// switch which preset version is current — no cryptographic material is
// minted per control call, so rotation scenarios are deterministic and cheap.
//
// SIGNATURE FIDELITY (read before relying on it)
// ----------------------------------------------
// Log entries carry a REAL Ed25519 signature over the JCS-canonical entry with
// the `proof` member removed, using that version's update key. That is enough
// for "the bytes changed and are self-consistent" assertions. It is NOT
// validated against the SDK's `verify_did_webvh_v1_chain_and_witness_bytes`,
// so this mock is not a source of verification-grade did:webvh history —
// build those with `e2e/helpers/webvh-api.ts` or a real did:webvh provider.
//
// ENV
//   MOCK_DID_HOST_PORT        listen port (0 = ephemeral)
//   MOCK_DID_HOST_AUTHORITY   authority the generated DIDs live under
//   MOCK_DID_HOST_SCID        did:webvh SCID (default z6mkfixture, matches
//                             src/harness/mod.rs FIXTURE_WEBVH_SCID)
//   MOCK_DID_HOST_FIXTURE     JSON file listing the DIDs to preseed; defaults
//                             to tests/fixtures/_shared/_canonical_dids.json
//   MOCK_DID_HOST_EXTRA_DIDS  comma-separated extra DIDs to register
//   MOCK_DID_HOST_VERSIONS    preset versions per DID (default 3)
//   MOCK_DID_HOST_WITNESS_URL base URL of mock-witness.mjs for /control/attest

import { createServer } from "node:http";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  base58btcEncode,
  encodeEd25519PubkeyMultibase,
  rawEd25519PublicKey,
} from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";
import { canonicalJson, readJson, sendJson } from "./_shared/http.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

const port = parseInt(process.env.MOCK_DID_HOST_PORT ?? "0", 10);
const authority = process.env.MOCK_DID_HOST_AUTHORITY ?? "did-host.joint-e2e.local";
const scid = process.env.MOCK_DID_HOST_SCID ?? "z6mkfixture";
const versionCount = Math.max(1, parseInt(process.env.MOCK_DID_HOST_VERSIONS ?? "3", 10));
const witnessUrl = (process.env.MOCK_DID_HOST_WITNESS_URL ?? "").replace(/\/$/, "");
const fixturePath =
  process.env.MOCK_DID_HOST_FIXTURE ??
  path.resolve(HERE, "..", "..", "tests", "fixtures", "_shared", "_canonical_dids.json");

// leaf file name -> counter bucket ("purpose", in task vocabulary)
const LEAVES = new Map([
  ["did.json", "document"],
  ["did.jsonl", "log"],
  ["did-witness.json", "witness"],
]);
const CONTENT_TYPES = {
  document: "application/did+json",
  log: "application/jsonl",
  witness: "application/json",
};
/// Bucket for fetches whose path/host matched no registered DID. These are
/// still authority network calls and MUST be visible, otherwise a scenario
/// could "prove" zero additional calls while the service hammered a typo'd
/// path.
const UNRESOLVED = "<unresolved>";

const fetchLog = new InspectLog("fetches");
/// Exact per-DID counters. Deliberately separate from `fetchLog`: the log is
/// FIFO-bounded at 500 entries, so counts derived from it would silently
/// under-report on a long run. Counts are authoritative; the log is forensics.
/// did -> { document, log, witness, total }
const counts = new Map();
/// did -> registration record
const registry = new Map();

function emptyCounts() {
  return { document: 0, log: 0, witness: 0, total: 0 };
}

function countFetch(did, kind) {
  let entry = counts.get(did);
  if (!entry) {
    entry = emptyCounts();
    counts.set(did, entry);
  }
  entry[kind] += 1;
  entry.total += 1;
}

function countsSnapshot(filterDid) {
  const out = {};
  for (const [did, entry] of counts) {
    if (filterDid && did !== filterDid) continue;
    out[did] = { ...entry };
  }
  if (filterDid && !out[filterDid]) out[filterDid] = emptyCounts();
  return out;
}

function totalCount(filterDid) {
  let total = 0;
  for (const [did, entry] of counts) {
    if (filterDid && did !== filterDid) continue;
    total += entry.total;
  }
  return total;
}

function resetCounts() {
  counts.clear();
  fetchLog.clear();
}

// ── DID parsing / HTTP path derivation ────────────────────────────────────
//
// Mirrors the SDK's URL derivation (arkret-rust-sdk
// crates/identity/src/helpers.rs `did_web_document_url` / `did_webvh_url` and
// crates/models-identity/src/did_document.rs) so a document this mock serves
// is reachable at exactly the path a real resolver would request.

function parseDid(did) {
  if (did.startsWith("did:web:")) {
    const parts = did.slice("did:web:".length).split(":");
    const rawAuthority = parts.shift() ?? "";
    if (!rawAuthority) return null;
    return { method: "did:web", scid: null, authority: decodeAuthority(rawAuthority), segments: parts };
  }
  if (did.startsWith("did:webvh:")) {
    const parts = did.slice("did:webvh:".length).split(":");
    const didScid = parts.shift() ?? "";
    const rawAuthority = parts.shift() ?? "";
    if (!didScid || !rawAuthority) return null;
    return {
      method: "did:webvh",
      scid: didScid,
      authority: decodeAuthority(rawAuthority),
      segments: parts,
    };
  }
  return null;
}

function decodeAuthority(raw) {
  return raw.replace(/%3A/gi, ":");
}

function basePathFor(parsed) {
  return parsed.segments.length === 0 ? "/.well-known" : `/${parsed.segments.join("/")}`;
}

function hostOf(authorityValue) {
  const stripped = authorityValue.startsWith("[")
    ? authorityValue.slice(0, authorityValue.indexOf("]") + 1)
    : authorityValue.split(":")[0];
  return stripped.toLowerCase();
}

// ── Preset version generation ─────────────────────────────────────────────

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}

function buildVersions(did, parsed, count) {
  const versions = [];
  let previousVersionId = null;
  for (let index = 0; index < count; index += 1) {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const multibase = encodeEd25519PubkeyMultibase(rawEd25519PublicKey(publicKey));
    const keyId = `${did}#key-${index + 1}`;
    // Deterministic-per-process version time so log entries are ordered but a
    // scenario can still tell versions apart.
    const versionTime = new Date(Date.UTC(2026, 0, 1 + index)).toISOString();
    const document = {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: did,
      verificationMethod: [
        { id: keyId, type: "Multikey", controller: did, publicKeyMultibase: multibase },
      ],
      authentication: [keyId],
      assertionMethod: [keyId],
    };
    const versionId = `${index + 1}-z${base58btcEncode(
      sha256(Buffer.from(`${did}|${index + 1}|${multibase}`, "utf8")),
    ).slice(0, 44)}`;
    versions.push({
      versionId,
      previousVersionId,
      versionTime,
      keyId,
      multibase,
      privateKey,
      document,
      scid: parsed.scid ?? scid,
    });
    previousVersionId = versionId;
  }
  return versions;
}

/// A did:webvh log entry for `version`, signed with that version's update key.
/// The signature covers the JCS-canonical entry with `proof` removed.
function logEntryFor(record, version, { deactivated = false } = {}) {
  const isFirst = version.previousVersionId === null;
  const parameters = isFirst
    ? {
        method: "did:webvh:1.0",
        scid: version.scid,
        updateKeys: [version.multibase],
        portable: false,
      }
    : { updateKeys: [version.multibase] };
  if (deactivated) parameters.deactivated = true;
  const state = deactivated ? { ...version.document, deactivated: true } : version.document;
  const unsigned = {
    versionId: version.versionId,
    versionTime: version.versionTime,
    parameters,
    state,
  };
  const signature = sign(null, Buffer.from(canonicalJson(unsigned), "utf8"), version.privateKey);
  return {
    ...unsigned,
    proof: [
      {
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        verificationMethod: `did:key:${version.multibase}#${version.multibase}`,
        created: version.versionTime,
        proofPurpose: "authentication",
        proofValue: `z${base58btcEncode(signature)}`,
      },
    ],
  };
}

function registerDid(did, { versions = versionCount } = {}) {
  const parsed = parseDid(did);
  if (!parsed) throw new Error(`unsupported DID method: ${did}`);
  const record = {
    did,
    method: parsed.method,
    authority: parsed.authority,
    host: hostOf(parsed.authority),
    basePath: basePathFor(parsed),
    scid: parsed.scid,
    versions: buildVersions(did, parsed, versions),
    current: 0,
    deactivated: false,
    statusOverride: null, // { status, leaf? }
    witnessAttestations: [], // filled by POST /control/attest
  };
  registry.set(did, record);
  return record;
}

function currentVersion(record) {
  return record.versions[record.current];
}

function documentFor(record) {
  const version = currentVersion(record);
  return record.deactivated ? { ...version.document, deactivated: true } : version.document;
}

function logFor(record) {
  const entries = [];
  for (let index = 0; index <= record.current; index += 1) {
    entries.push(logEntryFor(record, record.versions[index]));
  }
  if (record.deactivated) {
    entries.push(logEntryFor(record, currentVersion(record), { deactivated: true }));
  }
  return `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`;
}

function witnessFor(record) {
  return {
    versionId: currentVersion(record).versionId,
    proof: record.witnessAttestations,
  };
}

function describe(record) {
  return {
    did: record.did,
    method: record.method,
    authority: record.authority,
    base_path: record.basePath,
    scid: record.scid,
    version_index: record.current,
    version_id: currentVersion(record).versionId,
    version_count: record.versions.length,
    deactivated: record.deactivated,
    status_override: record.statusOverride,
    witness_attestation_count: record.witnessAttestations.length,
    urls: [...LEAVES.keys()].map((leaf) => `${record.basePath}/${leaf}`),
  };
}

// ── Preseed ───────────────────────────────────────────────────────────────

/// Collect DIDs from a fixture file. Two accepted shapes:
///   - `_canonical_dids.json`: { actors: { name: { did } } }
///   - dedicated: { dids: [ "did:…", { did, versions? } ] }
function didsFromFixture(file) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    console.error(`[mock-did-host] fixture ${file} unreadable: ${error.message}`);
    return [];
  }
  const out = [];
  if (parsed && typeof parsed.actors === "object" && parsed.actors) {
    for (const actor of Object.values(parsed.actors)) {
      if (actor && typeof actor.did === "string") out.push({ did: actor.did });
    }
  }
  if (Array.isArray(parsed?.dids)) {
    for (const entry of parsed.dids) {
      if (typeof entry === "string") out.push({ did: entry });
      else if (entry && typeof entry.did === "string") out.push(entry);
    }
  }
  return out;
}

const preseed = didsFromFixture(fixturePath);
// Every fixture DID also gets a did:webvh twin hosted under this mock's own
// authority, so scenarios have both a no-history (did:web) and a versioned
// (did:webvh) subject without the fixture file having to spell both out.
for (const entry of [...preseed]) {
  const parsed = parseDid(entry.did);
  if (!parsed || parsed.method !== "did:web") continue;
  const localId = hostOf(parsed.authority).split(".")[0];
  preseed.push({ did: `did:webvh:${scid}:${authority}:${localId}` });
}
for (const extra of (process.env.MOCK_DID_HOST_EXTRA_DIDS ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean)) {
  preseed.push({ did: extra });
}
for (const entry of preseed) {
  if (registry.has(entry.did)) continue;
  try {
    registerDid(entry.did, { versions: entry.versions ?? versionCount });
  } catch (error) {
    console.error(`[mock-did-host] skipping ${entry.did}: ${error.message}`);
  }
}

// ── Lookup ────────────────────────────────────────────────────────────────

/// Resolve the DID a fetch is for. Precedence:
///   1. explicit `?did=` (used by harness self-tests and the Rust client)
///   2. Host header authority + base path (what a real resolver sends —
///      `did:web:alice.example` fetches with `Host: alice.example`)
///   3. base path alone, when exactly one DID claims it
/// Returns { record } | { error, candidates }
function lookupDid(url, req, basePath) {
  const explicit = url.searchParams.get("did");
  if (explicit) {
    const record = registry.get(explicit);
    return record ? { record } : { error: "unknown_did" };
  }
  const candidates = [...registry.values()].filter((record) => record.basePath === basePath);
  if (candidates.length === 0) return { error: "unknown_did" };
  const requestHost = hostOf(req.headers.host ?? "");
  const hostMatches = candidates.filter((record) => record.host === requestHost);
  if (hostMatches.length === 1) return { record: hostMatches[0] };
  if (candidates.length === 1) return { record: candidates[0] };
  return {
    error: "ambiguous_did_path",
    candidates: candidates.map((record) => record.did),
  };
}

// ── Server ────────────────────────────────────────────────────────────────

const startedAt = new Date().toISOString();

async function handleControl(url, req, res) {
  if (url.pathname === "/control/dids" && req.method === "GET") {
    sendJson(res, 200, {
      service: "mock-did-host",
      authority,
      scid,
      dids: [...registry.values()].map(describe),
    });
    return true;
  }
  if (req.method !== "POST") return false;
  const body = (await readJson(req)) ?? {};
  const requireRecord = () => {
    const record = registry.get(body.did);
    if (!record) sendJson(res, 404, { error: "unknown_did", did: body.did ?? null });
    return record;
  };

  switch (url.pathname) {
    case "/control/register": {
      if (typeof body.did !== "string" || !body.did) {
        sendJson(res, 400, { error: "did_required" });
        return true;
      }
      try {
        const record = registerDid(body.did, { versions: body.versions ?? versionCount });
        sendJson(res, 200, { ok: true, did: describe(record) });
      } catch (error) {
        sendJson(res, 400, { error: "unsupported_did", detail: error.message });
      }
      return true;
    }
    case "/control/rotate": {
      const record = requireRecord();
      if (!record) return true;
      let next;
      if (body.to === undefined || body.to === null) {
        next = record.current + 1;
      } else if (typeof body.to === "number") {
        next = body.to;
      } else {
        next = record.versions.findIndex((version) => version.versionId === body.to);
      }
      if (!Number.isInteger(next) || next < 0 || next >= record.versions.length) {
        sendJson(res, 409, {
          error: "no_such_version",
          requested: body.to ?? record.current + 1,
          version_count: record.versions.length,
        });
        return true;
      }
      record.current = next;
      record.deactivated = false;
      record.witnessAttestations = [];
      sendJson(res, 200, { ok: true, did: describe(record) });
      return true;
    }
    case "/control/deactivate": {
      const record = requireRecord();
      if (!record) return true;
      record.deactivated = true;
      sendJson(res, 200, { ok: true, did: describe(record) });
      return true;
    }
    case "/control/fail": {
      const record = requireRecord();
      if (!record) return true;
      if (body.status === null || body.status === undefined) {
        record.statusOverride = null;
      } else if (!Number.isInteger(body.status) || body.status < 400 || body.status > 599) {
        sendJson(res, 400, { error: "status_must_be_4xx_or_5xx" });
        return true;
      } else {
        record.statusOverride = { status: body.status, leaf: body.leaf ?? null };
      }
      sendJson(res, 200, { ok: true, did: describe(record) });
      return true;
    }
    case "/control/attest": {
      const record = requireRecord();
      if (!record) return true;
      if (!witnessUrl) {
        sendJson(res, 412, {
          error: "witness_not_configured",
          detail: "set MOCK_DID_HOST_WITNESS_URL to the mock-witness base URL",
        });
        return true;
      }
      const version = currentVersion(record);
      const entryHash = `z${base58btcEncode(
        sha256(Buffer.from(canonicalJson(logEntryFor(record, version)), "utf8")),
      )}`;
      // Witness signing stays in mock-witness.mjs — this only relays.
      const signResponse = await fetch(`${witnessUrl}/mock/witness/sign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          scid: `${record.scid}:${record.did}`,
          entry_hash: entryHash,
          entry_number: record.witnessAttestations.length + 1,
          entry_timestamp: new Date().toISOString(),
        }),
      });
      const signBody = await signResponse.json().catch(() => ({}));
      if (!signResponse.ok) {
        sendJson(res, 502, { error: "witness_sign_failed", detail: signBody });
        return true;
      }
      record.witnessAttestations.push({
        witness_did: signBody.witness_did,
        entry_hash: entryHash,
        attestation: signBody.attestation,
      });
      sendJson(res, 200, { ok: true, did: describe(record) });
      return true;
    }
    case "/control/reset": {
      for (const record of registry.values()) {
        record.current = 0;
        record.deactivated = false;
        record.statusOverride = null;
        record.witnessAttestations = [];
      }
      sendJson(res, 200, { ok: true, dids: [...registry.values()].map(describe) });
      return true;
    }
    default:
      return false;
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");

  if (url.pathname === "/health") {
    sendJson(res, 200, {
      service: "mock-did-host",
      started_at: startedAt,
      authority,
      scid,
      did_count: registry.size,
    });
    return;
  }

  // ── control plane (never counted) ───────────────────────────────────────
  if (url.pathname === "/inspect/counts" && req.method === "GET") {
    const filter = url.searchParams.get("did") ?? undefined;
    sendJson(res, 200, {
      service: "mock-did-host",
      now: new Date().toISOString(),
      total: totalCount(filter),
      counts: countsSnapshot(filter),
    });
    return;
  }
  if (url.pathname === "/inspect/reset" && req.method === "POST") {
    resetCounts();
    sendJson(res, 200, { ok: true, cleared: ["fetches", "counts"] });
    return;
  }
  if (url.pathname === "/inspect") {
    // DELETE /inspect keeps handleInspect's semantics (clear the logs) and
    // additionally zeroes the counters — leaving stale counts behind after an
    // explicit clear would be a trap for scenario authors.
    if (req.method === "DELETE") counts.clear();
    const handled = handleInspect(req, res, {
      service: "mock-did-host",
      logs: [fetchLog],
      extra: {
        started_at: startedAt,
        authority,
        scid,
        total: totalCount(),
        counts: countsSnapshot(),
        dids: [...registry.values()].map(describe),
      },
    });
    if (handled) return;
  }
  if (url.pathname.startsWith("/control/") && (await handleControl(url, req, res))) return;

  // ── document plane (counted) ────────────────────────────────────────────
  const segments = url.pathname.split("/").filter(Boolean);
  const leaf = segments[segments.length - 1];
  const kind = LEAVES.get(leaf ?? "");
  if (!kind) {
    sendJson(res, 404, { error: "not_found" });
    return;
  }
  const basePath = `/${segments.slice(0, -1).join("/")}`;
  const found = lookupDid(url, req, basePath);
  if (!found.record) {
    countFetch(UNRESOLVED, kind);
    fetchLog.record({
      did: null,
      kind,
      path: url.pathname,
      host: req.headers.host ?? null,
      status: found.error === "ambiguous_did_path" ? 409 : 404,
      error: found.error,
      candidates: found.candidates,
    });
    sendJson(res, found.error === "ambiguous_did_path" ? 409 : 404, {
      error: found.error,
      path: url.pathname,
      candidates: found.candidates,
      detail:
        found.error === "ambiguous_did_path"
          ? "several DIDs share this path; disambiguate with a Host header or ?did="
          : undefined,
    });
    return;
  }

  const record = found.record;
  const version = currentVersion(record);
  const override = record.statusOverride;
  if (override && (override.leaf === null || override.leaf === leaf)) {
    countFetch(record.did, kind);
    fetchLog.record({
      did: record.did,
      kind,
      path: url.pathname,
      version_id: version.versionId,
      status: override.status,
      forced: true,
    });
    sendJson(res, override.status, { error: "forced_failure", did: record.did });
    return;
  }
  if (kind !== "document" && record.method !== "did:webvh") {
    countFetch(record.did, kind);
    fetchLog.record({
      did: record.did,
      kind,
      path: url.pathname,
      status: 404,
      error: "not_a_webvh_did",
    });
    sendJson(res, 404, { error: "not_a_webvh_did", did: record.did, method: record.method });
    return;
  }

  countFetch(record.did, kind);
  fetchLog.record({
    did: record.did,
    kind,
    path: url.pathname,
    version_id: version.versionId,
    deactivated: record.deactivated,
    status: 200,
  });
  res.writeHead(200, { "content-type": CONTENT_TYPES[kind] });
  if (kind === "log") {
    res.end(logFor(record));
  } else if (kind === "witness") {
    res.end(JSON.stringify(witnessFor(record)));
  } else {
    res.end(JSON.stringify(documentFor(record)));
  }
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-did-host] listening on http://127.0.0.1:${actual.port} ` +
      `(authority=${authority}, scid=${scid}, dids=${registry.size})`,
  );
});

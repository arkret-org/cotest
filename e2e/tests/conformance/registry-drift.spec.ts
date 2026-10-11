// Conformance — Registry Drift / Current Catalog
// Contract: e2e/scenarios/conformance/registry-drift.md
// Spec: conformance/schema-registry.md §1 (source-of-truth declaration) /
//       §3 (event type constraints) / §6 (evolution constraints + critical
//       extension fail-closed)
// Artifacts (machine-readable source-of-truth):
//   - arkret-spec/spec/v1/artifacts/profiles/conformance-profiles.json
//   - arkret-spec/spec/v1/artifacts/registry/event-kind-registry.json
//   - arkret-spec/spec/v1/artifacts/registry/forbidden-model-terms.json
//   - arkret-spec/spec/v1/artifacts/registry/forbidden-wire-fields.json
//   - arkret-spec/spec/v1/artifacts/registry/operation-registry.json
//
// Treat the artifacts as the source-of-truth and walk coland's live
// `/_arkret/describe` for drift. The LIVE phases below (C / E)
// are pure artifact-vs-describe diffs and need no fixme — they are tagged
// @fully-implemented so they run under the joint-smoke profile.
//
// Phase A / F now run live as negative probes: they submit a removed event
// kind and scan server-managed responses for forbidden model terms.

import { forbiddenWireScanner, type WireViolation } from "../../helpers/forbidden-wire";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type APIResponse, expect, test } from "../../helpers/arkret-test";
import { colandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueUserSession,
  uniqueUser,
} from "../../helpers/users";
import {
  authHeaders,
  createRealmApi,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/coland-api";

// ---------------------------------------------------------------------------
// Artifact loader
// ---------------------------------------------------------------------------
// Resolves relative to this spec file so cwd doesn't matter. From
// cotest/e2e/tests/conformance/<spec>.spec.ts that's four levels up to land at
// the repo root, then down into arkret-spec/spec/v1/artifacts.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const artifactsRoot = resolve(__dirname, "../../../../arkret-spec/spec/v1/artifacts");
const profilesRoot = resolve(artifactsRoot, "profiles");
const registryRoot = resolve(artifactsRoot, "registry");

function loadProfileJson<T = unknown>(name: string): T {
  const path = resolve(profilesRoot, name);
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function loadRegistryJson<T = unknown>(name: string): T {
  const path = resolve(registryRoot, name);
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

type DriftEntry = {
  id: string;
  // forbidden-model-terms.json carries the term under `term` for the
  // namespace-prefix rows (`cx.` / `cx:`) and under `id` everywhere else.
  term?: string;
  since_revision?: string;
  rejection_level: "hard_reject" | "migration_only" | "compat_only" | "docs_only";
  replacement?: string | null;
  allowed_contexts?: string[];
  notes?: string;
  context?: string;
};

type DriftRegistry = {
  kind: string;
  entries: DriftEntry[];
};

type OperationRegistry = {
  operations: Array<{ operation_id: string; http?: string; grpc?: string; mq?: string }>;
  operation_bundles: Array<{
    operation_bundle_id: string;
    members: Array<{ operation_id: string }>;
  }>;
  surface_groups: Array<{ surface: string; surface_class: string; operations: string[] }>;
};

type ConformanceProfiles = {
  profile_roles: Record<string, string>;
};

type EventKindRegistry = {
  event_kinds: Array<{ event_kind: string; status: string }>;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Yield every (path, key, value) tuple in a nested JSON tree. Walks both
 * plain objects and arrays; primitives are leaves. Used by Phase C to collect
 * any nested `profile_id` claims.
 */
function* walkTree(
  node: unknown,
  path: string[] = [],
): Generator<{ path: string[]; key: string; value: unknown }> {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      yield* walkTree(node[i], [...path, String(i)]);
    }
    return;
  }
  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    yield { path: [...path, key], key, value };
    yield* walkTree(value, [...path, key]);
  }
}

/** Exact current-v1 operation ids expanded from role-scoped registered bundles. */
function pickClaimedOperations(
  describe: unknown,
  operationRegistry: OperationRegistry,
): string[] | null {
  if (!describe || typeof describe !== "object") return null;
  const d = describe as Record<string, unknown>;
  if (!Array.isArray(d.supported_operation_bundles)) return null;
  const bundles = new Map(
    operationRegistry.operation_bundles.map((bundle) => [
      bundle.operation_bundle_id,
      bundle.members,
    ]),
  );
  const operationIds = new Set<string>();
  for (const bundleId of d.supported_operation_bundles) {
    if (typeof bundleId !== "string") return null;
    const members = bundles.get(bundleId);
    if (!members) return null;
    for (const member of members) operationIds.add(member.operation_id);
  }
  return [...operationIds];
}

/**
 * Collect every profile id string claimed anywhere in the describe document.
 * Covers the canonical top-level arrays plus any nested object with a
 * `profile_id` / `id` key whose ancestor path mentions "profile".
 */
function collectClaimedProfileIds(describe: unknown): Set<string> {
  const found = new Set<string>();
  if (!describe || typeof describe !== "object") return found;
  const d = describe as Record<string, unknown>;
  const topLevelArrays: Array<unknown> = [
    d.supported_profiles,
    d.verified_profiles,
  ];
  for (const arr of topLevelArrays) {
    if (Array.isArray(arr)) {
      for (const entry of arr) {
        if (typeof entry === "string") found.add(entry);
        else if (entry && typeof entry === "object") {
          const id = (entry as Record<string, unknown>).id ?? (entry as Record<string, unknown>).profile_id;
          if (typeof id === "string") found.add(id);
        }
      }
    }
  }
  // Defensive: deep-walk for any nested `profile_id` value.
  for (const { key, value, path } of walkTree(describe)) {
    if (typeof value !== "string") continue;
    if (key === "profile_id") found.add(value);
    if (key === "id" && path.some((p) => /profile/i.test(p))) found.add(value);
  }
  return found;
}

// Escape a literal for embedding in a RegExp source.
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Build a matcher for a forbidden term. The previous Phase F filtered terms
// through /^[A-Za-z_ -]+$/, silently dropping every term that carried a dot,
// colon, or parenthesis (`cx.`, `cx:`, `Realm(kind=list)`, …) — exactly the
// terms most worth catching. Instead we escape the term and only anchor a word
// boundary on a side that ends in a word character, so:
//   * `Room`            → /\bRoom\b/      (avoids matching inside "Bedroom")
//   * `cx.`             → /\bcx\./        (trailing `.` is not a word char)
//   * `Realm(kind=list)`→ /\bRealm\(kind=list\)/
//   * `受控协作 Realm`   → matched as a plain escaped substring (CJK chars are
//                          not in \w, so neither side gets a boundary).
function forbiddenTermMatcher(term: string): RegExp {
  const escaped = escapeRegExp(term);
  const leading = /^\w/.test(term) ? "\\b" : "";
  const trailing = /\w$/.test(term) ? "\\b" : "";
  return new RegExp(`${leading}${escaped}${trailing}`);
}

function* stringLeaves(node: unknown, path: string[] = []): Generator<{ path: string[]; value: string }> {
  if (typeof node === "string") {
    yield { path, value: node };
    return;
  }
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      yield* stringLeaves(node[i], [...path, String(i)]);
    }
    return;
  }
  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    yield* stringLeaves(value, [...path, key]);
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe.configure({ mode: "serial" });

test.describe("conformance registry drift @fully-implemented", () => {
  // Load all artifacts once; failures here surface as test setup errors which
  // is what we want (the spec build is broken, not the wire).
  const conformanceProfiles = loadProfileJson<ConformanceProfiles>("conformance-profiles.json");
  const eventKindRegistry = loadRegistryJson<EventKindRegistry>("event-kind-registry.json");
  const forbiddenModelTerms = loadRegistryJson<DriftRegistry>("forbidden-model-terms.json");
  const forbiddenWireFields = loadRegistryJson<DriftRegistry>("forbidden-wire-fields.json");
  const operationRegistry = loadRegistryJson<OperationRegistry>("operation-registry.json");

  test("Phase C — every claimed profile has a canonical conformance profile entry", async ({
    request,
  }, testInfo) => {
    // The candidate v1 line intentionally carries no historical migration or
    // deprecated-profile registry. `profile_roles` is the canonical index for
    // every current profile id, so any describe claim absent from it is drift.
    const canonicalProfiles = new Set(Object.keys(conformanceProfiles.profile_roles));
    expect(canonicalProfiles.size).toBeGreaterThan(0);

    const resp = await request.get(`${colandBaseUrl()}/_arkret/describe`);
    expect(resp.ok()).toBeTruthy();
    const describe = await resp.json();

    const claimed = collectClaimedProfileIds(describe);
    await testInfo.attach("describe-claimed-profile-ids", {
      body: JSON.stringify([...claimed].sort(), null, 2),
      contentType: "application/json",
    });
    await testInfo.attach("canonical-conformance-profile-ids", {
      body: JSON.stringify([...canonicalProfiles].sort(), null, 2),
      contentType: "application/json",
    });

    const rogue = [...claimed].filter((id) => !canonicalProfiles.has(id));
    expect(rogue, `coland describe claimed profile id(s) absent from canonical catalog: ${rogue.join(", ")}`).toEqual([]);
  });

  test("Phase E — every claimed operation has a canonical operation-registry entry", async ({
    request,
  }, testInfo) => {
    // spec: schema-registry.md §1 + operation-registry.json registry_rules
    // "Generated views ... MUST NOT introduce ... operation_id values that
    // are absent from this catalog." Equivalently: a service describe that
    // advertises an operation_id missing from the canonical registry is a
    // rogue claim.
    const canonicalOps = new Set(operationRegistry.operations.map((o) => o.operation_id));
    expect(canonicalOps.size).toBeGreaterThan(0);

    const resp = await request.get(`${colandBaseUrl()}/_arkret/describe`);
    expect(resp.ok()).toBeTruthy();
    const describe = await resp.json();

    const claimedOps = pickClaimedOperations(describe, operationRegistry);
    if (!claimedOps) {
      test.skip(
        true,
        "describe did not expose valid supported_operation_bundles — cannot verify operation coverage",
      );
      return;
    }

    const rogue = claimedOps.filter((op) => !canonicalOps.has(op));
    const missingFromImpl = [...canonicalOps].filter((op) => !claimedOps.includes(op));
    await testInfo.attach("describe-claimed-operations", {
      body: JSON.stringify(claimedOps.sort(), null, 2),
      contentType: "application/json",
    });
    await testInfo.attach("operations-not-claimed-by-coland", {
      // expected to be non-empty (coland is partial impl); informational only.
      body: JSON.stringify(missingFromImpl.sort(), null, 2),
      contentType: "application/json",
    });

    expect(rogue, `coland describe claimed operation_id(s) absent from canonical registry: ${rogue.join(", ")}`).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Live negative probes against the current rejection registries
  // -------------------------------------------------------------------------

  test("Phase A — POST event with removed kind is hard-rejected with schema_violation", async ({
    request,
  }) => {
    const removed = forbiddenWireFields.entries.find(
      (entry) =>
        entry.rejection_level === "hard_reject" &&
        entry.context === "event_kind" &&
        entry.allowed_contexts?.includes("negative_test"),
    );
    expect(removed, "forbidden hard-reject event kind fixture").toBeTruthy();
    const activeEventKinds = new Set(eventKindRegistry.event_kinds.map((entry) => entry.event_kind));
    expect(activeEventKinds.has(removed!.id), "negative event kind must be absent from active registry").toBeFalsy();
    const alice = uniqueUser("registry-drift-a");
    await ensureRegistered(request, alice);
    const token = await issueUserSession(request, alice);
    const envelope = signedEventEnvelope({
      actorId: alice.id,
      realmId: "ak:realm:AWKBMlbiCDVvdxpftc7u00CFiTYThQbKQJCj2gi91O9H",
      kind: removed!.id,
      // The kind is intentionally absent from the active registry. The proof
      // is otherwise valid: human-device producer proofs do not depend on the
      // Event kind (device-lifecycle.md section 8.2.2).
      payload: {},
    });
    const resp = await request.post(`${colandBaseUrl()}/_arkret/self/events`, {
      headers: authHeaders(token, "POST", `${colandBaseUrl()}/_arkret/self/events`),
      data: { event: envelope },
    });
    expect(resp.status()).toBeGreaterThanOrEqual(400);
    const body = await resp.json();
    expect(["schema_violation", "unknown_event_kind"]).toContain(wireErrCode(body));
    expect(JSON.stringify(body)).not.toContain('"status":"accepted"');
  });

  test("Phase F — server-managed read surfaces don't leak forbidden model terms", async ({
    request,
  }, testInfo) => {
    // forbidden-model-terms.json carries the term under `id` for most rows and
    // under `term` for the `cx.` / `cx:` namespace-prefix rows. Keep every
    // hard_reject term (do NOT pre-filter punctuated terms — the matcher below
    // handles dots/colons/parens). docs_only terms are intentionally out of
    // scope.
    const forbiddenTerms = forbiddenModelTerms.entries
      .filter((entry) => entry.rejection_level === "hard_reject")
      .map((entry) => entry.term ?? entry.id)
      .filter((term): term is string => typeof term === "string" && term.length > 0);
    expect(forbiddenTerms.length).toBeGreaterThan(0);
    const matchers = forbiddenTerms.map((term) => ({
      term,
      regex: forbiddenTermMatcher(term),
    }));

    // Stand up a real authed actor so the scan reaches the reader / receipt
    // surfaces a leak would surface on, not just the anonymous describe/health
    // pair the previous Phase F covered.
    const alice = uniqueUser("registry-drift-terms");
    await ensureRegistered(request, alice);
    const token = await issueUserSession(request, alice);

    // Submit a benign event so the write receipt is part of the scan surface.
    const probeRealmId = "ak:realm:AV1vAwt2NWgRW6lXhHcPfu4l8U3dkzSjWbQ_xXTw370Q";
    const submitReceipt = await request.post(`${colandBaseUrl()}/_arkret/self/events`, {
      headers: authHeaders(token, "POST", `${colandBaseUrl()}/_arkret/self/events`),
      data: { event: signedEventEnvelope({
        actorId: alice.id,
        realmId: probeRealmId,
        kind: "ak.read_cursor.advance",
        payload: {},
      }) },
    });

    const surfaces: Array<{ name: string; response: APIResponse; requireOk?: boolean }> = [
      { name: "server.describe", response: await request.get(`${colandBaseUrl()}/_arkret/describe`), requireOk: true },
      { name: "health", response: await request.get(`${colandBaseUrl()}/health`), requireOk: true },
      { name: "directory.describe", response: await request.get(`${colandBaseUrl()}/_arkret/find/directory/describe`) },
      { name: "account.viewer", response: await request.get(`${colandBaseUrl()}/_arkret/self/account/viewer`, { headers: authHeaders(token, "GET", `${colandBaseUrl()}/_arkret/self/account/viewer`) }) },
      { name: "streams.scan", response: await request.fetch(`${colandBaseUrl()}/_arkret/self/streams/scan`, { method: "POST", data: { realm_id: probeRealmId, stream_ref: { kind: "realm", realm_id: probeRealmId }, limit: 20 }, headers: authHeaders(token, "POST", `${colandBaseUrl()}/_arkret/self/streams/scan`) }) },
      { name: "notifications", response: await request.get(`${colandBaseUrl()}/_arkret/self/notifications`, { headers: authHeaders(token, "GET", `${colandBaseUrl()}/_arkret/self/notifications`) }) },
      { name: "events.submit.receipt", response: submitReceipt },
    ];

    const violations: Array<{ surface: string; status: number; path: string; term: string; value: string }> = [];
    const scanned: Array<{ surface: string; status: number }> = [];
    for (const surface of surfaces) {
      const status = surface.response.status();
      scanned.push({ surface: surface.name, status });
      if (surface.requireOk) {
        expect(surface.response.ok(), `${surface.name} responded ${status}`).toBeTruthy();
      }
      // Authed reader / receipt surfaces may legitimately 4xx in some
      // deployments (feature not mounted, empty inbox). Server-managed text
      // still arrives on the error body, so scan whatever JSON came back and
      // skip only non-JSON / empty responses.
      let body: unknown;
      try {
        body = await surface.response.json();
      } catch {
        continue;
      }
      for (const leaf of stringLeaves(body)) {
        for (const { term, regex } of matchers) {
          if (regex.test(leaf.value)) {
            violations.push({
              surface: surface.name,
              status,
              path: leaf.path.join("."),
              term,
              value: leaf.value,
            });
          }
        }
      }
    }
    await testInfo.attach("forbidden-model-term-scan", {
      body: JSON.stringify({ forbiddenTerms, scanned, violations }, null, 2),
      contentType: "application/json",
    });
    expect(violations).toEqual([]);
  });

  test("Phase G — submitted Event Envelopes carry no forbidden wire field", async ({
    request,
  }, testInfo) => {
    const scanner = forbiddenWireScanner(artifactsRoot);

    const alice = uniqueUser("forbidden-wire-fields");
    await ensureRegistered(request, alice);
    const token = await issueUserSession(request, alice);

    const realmId = await createRealmApi(request, token, {
      title: "forbidden-wire-fields probe",
      mls_activated: false,
    });
    const strandId = await resolveDefaultStrandId(request, token, realmId);

    const messageEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        content: { kind: "ak.content.text", body: "forbidden-wire-fields probe" },
      },
    });
    const messageReceipt = await submitSignedEventApi(request, token, messageEnvelope, {
      context: "forbidden-wire-fields message",
    });
    expect(
      messageEnvelope.producer_proof,
      "ordinary Event carries its exact device's portable producer proof",
    ).toMatchObject({
      kind: "detached_jws",
      verification_method: `${alice.did}#${alice.deviceId}`,
      event_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      jws: expect.any(String),
    });
    expect(messageEnvelope).not.toHaveProperty("auth_context");
    expect(messageEnvelope).not.toHaveProperty("data_basis");

    const cursorEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.read_cursor.advance",
      payload: {},
    });

    const documents: Array<{ name: string; document: unknown }> = [
      { name: "message.envelope", document: messageEnvelope },
      { name: "message.receipt", document: messageReceipt },
      { name: "read_cursor.envelope", document: cursorEnvelope },
    ];

    const violations: WireViolation[] = [];
    for (const { name, document } of documents) {
      const found = name.endsWith(".envelope")
        ? scanner.scanEvent(document as Record<string, unknown>)
        : scanner.scan(document, "http_response", "service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome");
      for (const violation of found) {
        violations.push({ ...violation, path: `${name}:${violation.path}` });
      }
    }
    await testInfo.attach("forbidden-wire-field-scan", {
      body: JSON.stringify(
        { rule_count: scanner.ruleCount, documents: documents.map((d) => d.name), violations },
        null,
        2,
      ),
      contentType: "application/json",
    });
    expect(
      violations,
      `forbidden wire field(s) on submitted envelope: ${violations.map((v) => `${v.id}@${v.path}`).join(", ")}`,
    ).toEqual([]);
  });
});

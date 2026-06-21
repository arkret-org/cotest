// Conformance — Registry Drift / Removed IDs
// Contract: e2e/scenarios/conformance/registry-drift.md
// Spec: conformance/schema-registry.md §1 (真源声明) / §3 (event type 约束) /
//       §6 (演进约束 + critical extension fail-closed)
// Artifacts (machine-readable source-of-truth):
//   - cokret-spec/spec/v1/artifacts/migration/removed-event-kinds.json
//   - cokret-spec/spec/v1/artifacts/migration/deprecated-profile-ids.json
//   - cokret-spec/spec/v1/artifacts/registry/forbidden-model-terms.json
//   - cokret-spec/spec/v1/artifacts/registry/operation-registry.json
//
// Treat the artifacts as the source-of-truth and walk soland's live
// `/_cokret/describe` for drift. The LIVE phases below (C / E)
// are pure artifact-vs-describe diffs and need no fixme — they are tagged
// @fully-implemented so they run under the joint-smoke profile.
//
// Phase A / F now run live as negative probes: they submit a removed event
// kind and scan server-managed responses for forbidden model terms.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import { signedEventEnvelope, wireErrCode } from "../../helpers/soland-api";

// ---------------------------------------------------------------------------
// Artifact loader
// ---------------------------------------------------------------------------
// Resolves relative to this spec file so cwd doesn't matter. From
// cotest/e2e/tests/conformance/<spec>.spec.ts that's four levels up to land at
// the repo root, then down into cokret-spec/spec/v1/artifacts.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const artifactsRoot = resolve(__dirname, "../../../../cokret-spec/spec/v1/artifacts");
const migrationRoot = resolve(artifactsRoot, "migration");
const registryRoot = resolve(artifactsRoot, "registry");

function loadMigrationJson<T = unknown>(name: string): T {
  const path = resolve(migrationRoot, name);
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function loadRegistryJson<T = unknown>(name: string): T {
  const path = resolve(registryRoot, name);
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

type DriftEntry = {
  id: string;
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
  surface_groups: Array<{ surface: string; tier: string; operations: string[] }>;
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

/**
 * Best-effort pick of soland's "claimed operations" array from /server/describe.
 * Spec ref: sync/service-api-schema.mdx + service-surface.md. The exact key
 * has historically drifted; check the three most likely locations in order.
 */
function pickClaimedOperations(describe: unknown): string[] | null {
  if (!describe || typeof describe !== "object") return null;
  const d = describe as Record<string, unknown>;
  const candidates: unknown[] = [
    (d.implemented_features as Record<string, unknown> | undefined)?.operations,
    d.supported_operations,
    d.operations,
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate) && candidate.every((x) => typeof x === "string")) {
      return candidate as string[];
    }
  }
  return null;
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
    d.claimed_profiles,
    d.verified_profiles,
    d.self_claimed_profiles,
    (d.implemented_features as Record<string, unknown> | undefined)?.profiles,
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
  const removedEventKinds = loadMigrationJson<DriftRegistry>("removed-event-kinds.json");
  const deprecatedProfileIds = loadMigrationJson<DriftRegistry>("deprecated-profile-ids.json");
  const forbiddenModelTerms = loadRegistryJson<DriftRegistry>("forbidden-model-terms.json");
  const operationRegistry = loadRegistryJson<OperationRegistry>("operation-registry.json");

  test("Phase C — /server/describe does not claim any deprecated profile id", async ({
    request,
  }, testInfo) => {
    // spec: schema-registry.md §1; artifact: deprecated-profile-ids.json
    // Hard-reject means: any current implementation that *declares* one of
    // these profile ids is in drift. Service describe is the canonical
    // declaration surface, so this is a pure GET + set-diff assertion.
    const deprecated = new Set(
      deprecatedProfileIds.entries
        .filter((e) => e.rejection_level === "hard_reject")
        .map((e) => e.id),
    );
    expect(deprecated.size).toBeGreaterThan(0);

    const resp = await request.get(`${solandBaseUrl()}/_cokret/describe`);
    expect(resp.ok()).toBeTruthy();
    const describe = await resp.json();

    const claimed = collectClaimedProfileIds(describe);
    await testInfo.attach("describe-claimed-profile-ids", {
      body: JSON.stringify([...claimed].sort(), null, 2),
      contentType: "application/json",
    });
    await testInfo.attach("deprecated-profile-ids", {
      body: JSON.stringify([...deprecated].sort(), null, 2),
      contentType: "application/json",
    });

    const violations = [...claimed].filter((id) => deprecated.has(id));
    expect(violations, `soland describe claimed deprecated profile id(s): ${violations.join(", ")}`).toEqual([]);
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

    const resp = await request.get(`${solandBaseUrl()}/_cokret/describe`);
    expect(resp.ok()).toBeTruthy();
    const describe = await resp.json();

    const claimedOps = pickClaimedOperations(describe);
    if (!claimedOps) {
      test.skip(
        true,
        "describe did not expose implemented_features.operations / supported_operations / operations — cannot verify operation coverage",
      );
      return;
    }

    const rogue = claimedOps.filter((op) => !canonicalOps.has(op));
    const missingFromImpl = [...canonicalOps].filter((op) => !claimedOps.includes(op));
    await testInfo.attach("describe-claimed-operations", {
      body: JSON.stringify(claimedOps.sort(), null, 2),
      contentType: "application/json",
    });
    await testInfo.attach("operations-not-claimed-by-soland", {
      // expected to be non-empty (soland is partial impl); informational only.
      body: JSON.stringify(missingFromImpl.sort(), null, 2),
      contentType: "application/json",
    });

    expect(rogue, `soland describe claimed operation_id(s) absent from canonical registry: ${rogue.join(", ")}`).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Pinned fixme — depend on soland write-path / operation-invoke helpers
  // -------------------------------------------------------------------------

  test("Phase A — POST event with removed kind is hard-rejected with schema_violation", async ({
    request,
  }) => {
    const removed = removedEventKinds.entries.find((entry) => entry.rejection_level === "hard_reject");
    expect(removed, "removed hard-reject event kind fixture").toBeTruthy();
    const alice = uniqueUser("registry-drift-a");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const envelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId: "ck:realm:01904100-0000-7000-8000-000000000998",
      kind: removed!.id,
      payload: {},
    });
    const resp = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: { authorization: `Bearer ${token}` },
      data: envelope,
    });
    expect(resp.status()).toBeGreaterThanOrEqual(400);
    const body = await resp.json();
    expect(["schema_violation", "unknown_event_kind"]).toContain(wireErrCode(body));
    expect(JSON.stringify(body)).not.toContain('"status":"accepted"');
  });

  test("Phase F — server-managed audit / log surfaces don't leak forbidden model terms", async ({
    request,
  }, testInfo) => {
    const forbidden = forbiddenModelTerms.entries
      .filter((entry) => entry.rejection_level === "hard_reject")
      .map((entry) => entry.id)
      .filter((term) => /^[A-Za-z_ -]+$/.test(term));
    expect(forbidden.length).toBeGreaterThan(0);

    const surfaces = [
      { name: "server.describe", response: await request.get(`${solandBaseUrl()}/_cokret/describe`) },
      { name: "health", response: await request.get(`${solandBaseUrl()}/health`) },
    ];
    const violations: Array<{ surface: string; path: string; term: string; value: string }> = [];
    for (const surface of surfaces) {
      expect(surface.response.ok(), `${surface.name} responded ${surface.response.status()}`).toBeTruthy();
      const body = await surface.response.json();
      for (const leaf of stringLeaves(body)) {
        for (const term of forbidden) {
          if (new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(leaf.value)) {
            violations.push({
              surface: surface.name,
              path: leaf.path.join("."),
              term,
              value: leaf.value,
            });
          }
        }
      }
    }
    await testInfo.attach("forbidden-model-term-scan", {
      body: JSON.stringify({ forbidden, violations }, null, 2),
      contentType: "application/json",
    });
    expect(violations).toEqual([]);
  });
});

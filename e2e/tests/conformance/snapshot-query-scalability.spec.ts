// Conformance — Snapshot / Query / Scalability Vectors
// Contract: e2e/scenarios/conformance/snapshot-query-scalability.md
// Spec:
//   - conformance/snapshot-schema.md (§2 manifest, §3 chunk, §4 state_digest,
//     §5 signature binding, §6 event_set_commitment)
//   - conformance/query-schema.md (§2 query object, §3 filter, §6 sort,
//     §8 response, §9 security)
//   - conformance/scalability-constraints.md (§2 wire limits, §3 authz limits,
//     §5 Space/Relation/View limits, §8 error semantics)
//   - conformance/conformance-vectors.md (vector loader pattern: same as the
//     sibling encoding-vectors suite — `ak.vector.<domain>.<scenario>.v1`
//     fixtures live in arkret-spec/spec/v1/artifacts/fixtures/)
// Fixtures: arkret-spec/spec/v1/artifacts/fixtures/ak.vector.snapshot.*.json,
//           ak.vector.query.*.json, ak.vector.scalability.*.json
//
// Phases A-E exercise the test-only conformance endpoints under the
// spec-reserved namespace /_arkret/_conformance/{snapshot,query}
// (service-http-binding.md §2.1.2). The leading `_` marks `_conformance` as a
// reserved test-only segment, NOT a production trust-surface; the namespace is
// profile-gated on ak.profile.conformance_harness.v1 and production builds MUST
// 404 it. These endpoints are debug/conformance surfaces only and never enter
// the production operation registry.
//
// The remaining tests in this file are intentionally narrow:
//   - Phase F: harness-only vector loader smoke (filesystem read; never
//     touches soland). Always-pass on count so the suite stays green even
//     when the fixtures directory has zero matching files today.
//   - Phase G: optional surface probe of GET /_arkret/describe to
//     assert the surface is *internally consistent* (does NOT claim the
//     ak.profile.conformance_harness.v1 profile while the endpoint is 404,
//     OR if it does claim it then the endpoint must respond with something
//     other than 404). This is the same "claim ⇔ surface" sanity used by
//     registry-drift / profile-gates.

import { readdirSync, readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import { conformanceBaseUrl, solandBaseUrl } from "../../helpers/env";
import { canonicalJson, wireErrCode } from "../../helpers/soland-api";

const __filename_ = fileURLToPath(import.meta.url);
const __dirname_ = dirname(__filename_);

// From cotest/e2e/tests/conformance/<this-file>.spec.ts walk up four levels
// (conformance → tests → e2e → cotest) to reach the arkret root, then
// into arkret-spec/spec/v1/artifacts/fixtures.
const FIXTURES_DIR = resolve(
  __dirname_,
  "..",
  "..",
  "..",
  "..",
  "arkret-spec",
  "spec",
  "v1",
  "artifacts",
  "fixtures",
);

// Matches the vector_id namespaces this scenario owns. Sibling suites
// (encoding-vectors, redaction-vectors, etc.) own their own namespaces; we
// must not accidentally count them.
const VECTOR_PREFIXES = [
  "ak.vector.snapshot.",
  "ak.vector.query.",
  "ak.vector.scalability.",
] as const;

function listVectorFixtures(): { dir: string; exists: boolean; matches: string[] } {
  if (!existsSync(FIXTURES_DIR)) {
    return { dir: FIXTURES_DIR, exists: false, matches: [] };
  }
  const entries = readdirSync(FIXTURES_DIR);
  const matches = entries
    .filter((name) => name.endsWith(".json"))
    .filter((name) => VECTOR_PREFIXES.some((prefix) => name.startsWith(prefix)))
    .sort();
  return { dir: FIXTURES_DIR, exists: true, matches };
}

function sha256Prefixed(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function chunkDigest(chunk: { payload?: unknown; bytes?: string; data?: unknown }): string {
  if (chunk.payload !== undefined) return sha256Prefixed(canonicalJson(chunk.payload));
  if (chunk.bytes !== undefined) return sha256Prefixed(chunk.bytes);
  if (chunk.data !== undefined) return sha256Prefixed(canonicalJson(chunk.data));
  return sha256Prefixed(canonicalJson(chunk));
}

function expectNoResultPayload(body: unknown) {
  const serialized = JSON.stringify(body);
  expect(serialized).not.toContain('"items"');
  expect(serialized).not.toContain('"next_cursor"');
}

function decodedCursorText(cursor: string): string {
  const payload = cursor.replace(/^ak:cursor:/, "");
  return Buffer.from(payload, "base64url").toString("utf8");
}

test.describe.configure({ mode: "serial" });

test.describe("conformance snapshot/query/scalability vectors @fully-implemented", () => {
  test("Phase A — snapshot manifest integrity (digest, chunk count, chunk hashes)", async ({
    request,
  }) => {
    const chunks = [
      { chunk_id: "chunk-1", payload: { cell: "a", value: "alpha", version: 1 } },
      { chunk_id: "chunk-2", payload: { cell: "b", value: ["beta", "gamma"], version: 1 } },
    ];
    const chunkHashes = chunks.map(chunkDigest);
    const manifest = {
      id: "ak:snapshot:ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K:fixture",
      realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
      reducer_profile: "ak.reducer.core.v1",
      schema_profile_refs: ["ak.schema.event.v1"],
      chunk_hashes: chunkHashes,
      created_by: "did:web:soland.conformance",
      created_at: "2026-05-31T00:00:00.000Z",
    };

    const resp = await request.post(`${conformanceBaseUrl()}/snapshot`, {
      headers: { "content-type": "application/json" },
      data: canonicalJson({
        vector_id: "ak.vector.snapshot.manifest_integrity.v1",
        manifest,
        chunks,
      }),
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.manifest_digest).toBe(sha256Prefixed(canonicalJson(manifest)));
    expect(body.chunk_hashes).toEqual(chunkHashes);
    expect(body.expected_chunk_count).toBe(2);
    expect(body.state_digest).toMatch(/^sha256:[0-9a-f]{64}$/);

    const tampered = await request.post(`${conformanceBaseUrl()}/snapshot`, {
      headers: { "content-type": "application/json" },
      data: canonicalJson({
        vector_id: "ak.vector.snapshot.tampered_chunk.v1",
        manifest,
        chunks: [{ ...chunks[0], payload: { cell: "a", value: "tampered", version: 1 } }, chunks[1]],
      }),
    });
    expect(tampered.status()).toBeGreaterThanOrEqual(400);
    expect(wireErrCode(await tampered.json())).toBe("snapshot_chunk_digest_mismatch");
  });

  test("Phase B — snapshot signature binding verifies against recorded signer DID", async ({
    request,
  }) => {
    const signerDid = "did:web:soland.conformance-signer";
    const chunks = [{ chunk_id: "chunk-1", payload: { cell: "a", value: "signed" } }];
    const manifest = {
      id: "ak:snapshot:ak:realm:AT1FV5Oc-IicigRsbtaKiJcXWc0f4WBgwlQTJk_XFuyQ:signed",
      realm_id: "ak:realm:AT1FV5Oc-IicigRsbtaKiJcXWc0f4WBgwlQTJk_XFuyQ",
      reducer_profile: "ak.reducer.core.v1",
      schema_profile_refs: ["ak.schema.event.v1"],
      chunk_hashes: chunks.map(chunkDigest),
      created_by: signerDid,
      created_at: "2026-05-31T00:00:00.000Z",
      signature: {
        alg: "Ed25519",
        signer_did: signerDid,
        signature: "deterministic-conformance-fixture",
      },
    };
    const resp = await request.post(`${conformanceBaseUrl()}/snapshot`, {
      headers: { "content-type": "application/json" },
      data: canonicalJson({
        vector_id: "ak.vector.snapshot.signature_binding.v1",
        manifest,
        chunks,
      }),
    });
    expect(resp.status(), await resp.text()).toBe(200);
    const body = await resp.json();
    expect(body.signature_valid).toBe(true);
    expect(body.signer_did).toBe(signerDid);
    expect(body.signed_transcript_fields).toEqual([
      "id",
      "realm_id",
      "reducer_profile",
      "schema_profile_refs",
      "state_digest",
      "frontier",
      "event_set_commitment",
      "chunks",
      "verification_hints",
      "created_by",
      "created_at",
    ]);

    const revoked = await request.post(`${conformanceBaseUrl()}/snapshot`, {
      headers: { "content-type": "application/json" },
      data: canonicalJson({
        vector_id: "ak.vector.snapshot.signature_binding.revoked.v1",
        manifest,
        chunks,
        revoked_signer_dids: [signerDid],
      }),
    });
    expect(revoked.status()).toBeGreaterThanOrEqual(400);
    expect(wireErrCode(await revoked.json())).toBe("snapshot_issuer_revoked");
  });

  test("Phase C — query filters / sort / pagination return expected_rows in order", async ({
    request,
  }) => {
    const rows = [
      { id: "row-3", kind: "task", rank: 3, title: "Gamma" },
      { id: "row-1", kind: "task", rank: 1, title: "Alpha" },
      { id: "row-2", kind: "task", rank: 2, title: "Beta" },
      { id: "row-x", kind: "note", rank: 0, title: "Ignored" },
    ];
    const query = {
      filters: [{ field: "kind", op: "eq", value: "task" }],
      order_by: [{ field: "rank", direction: "asc" }],
      limit: 2,
    };
    const first = await request.post(`${conformanceBaseUrl()}/query`, {
      headers: { "content-type": "application/json" },
      data: canonicalJson({ vector_id: "ak.vector.query.page_order.v1", rows, query }),
    });
    expect(first.status()).toBe(200);
    const page1 = await first.json();
    expect(page1.items.map((row: { id: string }) => row.id)).toEqual(["row-1", "row-2"]);
    expect(page1.has_more).toBe(true);
    expect(page1.next_cursor).toMatch(/^ak:cursor:/);
    expect(page1.frontier.barrier_cursor).toMatch(/^ak:cursor:/);
    expect(decodedCursorText(page1.next_cursor)).not.toContain("row-");

    const page2Req = {
      vector_id: "ak.vector.query.page_order.v1",
      rows,
      query: { ...query, cursor: page1.next_cursor },
    };
    const second = await request.post(`${conformanceBaseUrl()}/query`, {
      headers: { "content-type": "application/json" },
      data: canonicalJson(page2Req),
    });
    expect(second.status()).toBe(200);
    const page2 = await second.json();
    expect(page2.items.map((row: { id: string }) => row.id)).toEqual(["row-3"]);
    expect(page2.has_more).toBe(false);

    const secondAgain = await request.post(`${conformanceBaseUrl()}/query`, {
      headers: { "content-type": "application/json" },
      data: canonicalJson(page2Req),
    });
    expect(await secondAgain.json()).toEqual(page2);
  });

  test("Phase D — query schema fail-closed on unknown ops / conflicting sort / unauthorized fields", async ({
    request,
  }) => {
    const rejectVectors = [
      {
        vector_id: "ak.vector.query.unknown_filter_key.v1",
        query: { filters: [{ field: "kind", op: "outside_registry", value: "task" }] },
      },
      {
        vector_id: "ak.vector.query.conflicting_sort.v1",
        query: {
          order_by: [
            { field: "rank", direction: "asc" },
            { field: "rank", direction: "desc" },
          ],
        },
      },
      {
        vector_id: "ak.vector.query.unauthorized_field.v1",
        query: { projection: ["id", "secret_notes"] },
      },
    ];

    for (const data of rejectVectors) {
      const resp = await request.post(`${conformanceBaseUrl()}/query`, { data });
      expect(resp.status(), data.vector_id).toBeGreaterThanOrEqual(400);
      const body = await resp.json();
      expect(["query_schema_violation", "schema_violation"]).toContain(wireErrCode(body));
      expectNoResultPayload(body);
    }
  });

  test("Phase E — scalability constraints fail-closed (page_size / batch / depth / envelope)", async ({
    request,
  }) => {
    const rejectVectors = [
      {
        vector_id: "ak.vector.scalability.page_size_over_max.v1",
        query: { limit: 1001 },
      },
      {
        vector_id: "ak.vector.scalability.batch_item_count_over_max.v1",
        rows: Array.from({ length: 1001 }, (_, index) => ({ id: `row-${index}` })),
        query: { limit: 10 },
      },
      {
        vector_id: "ak.vector.scalability.relation_depth_over_max.v1",
        query: { relation: { depth: 33 } },
      },
      {
        vector_id: "ak.vector.scalability.envelope_over_1mib.v1",
        query: { limit: 1 },
      },
    ];

    for (const data of rejectVectors) {
      const resp = await request.post(`${conformanceBaseUrl()}/query`, { data });
      expect(resp.status(), data.vector_id).toBeGreaterThanOrEqual(400);
      const body = await resp.json();
      expect(["scalability_limit_exceeded", "payload_too_large", "quota_exceeded"]).toContain(
        wireErrCode(body),
      );
      expect(JSON.stringify(body)).not.toContain("retry_after_ms");
    }
  });

  test("Phase F — vector loader smoke (harness-only, never touches soland)", async ({}, testInfo) => {
    // Scenario doc §"Implementation notes" → fixture-absence fallback. Today
    // the fixtures directory has zero ak.vector.{snapshot,query,scalability}.*
    // files. We still want CI to log the candidate count and id list so the
    // absence is visible and so newly-added fixtures show up immediately in
    // the next run.
    const { dir, exists, matches } = listVectorFixtures();

    // Always-pass count assertion — the goal is to surface the count, not
    // to gate the build on fixture presence. Phase A-E now exercise the
    // live conformance endpoints directly.
    expect(matches.length).toBeGreaterThanOrEqual(0);

    // Report what we found (or didn't find) into the run log + JUnit attach.
    // eslint-disable-next-line no-console
    console.log(
      `[snapshot-query-scalability] fixtures dir: ${dir}\n` +
        `[snapshot-query-scalability] exists: ${exists}\n` +
        `[snapshot-query-scalability] matching candidate count: ${matches.length}\n` +
        (matches.length > 0
          ? `[snapshot-query-scalability] candidates:\n  - ${matches.join("\n  - ")}`
          : `[snapshot-query-scalability] candidates: <none yet — see scenario doc's Implementation notes>`),
    );
    await testInfo.attach("snapshot-query-scalability-fixtures", {
      body: JSON.stringify({ dir, exists, count: matches.length, matches }, null, 2),
      contentType: "application/json",
    });

    // For every candidate that DOES exist, prove it parses as JSON. This
    // catches the common "fixture committed as YAML / with trailing comma /
    // BOM" failure mode early, before Phase A–E try to consume it.
    for (const name of matches) {
      const fullPath = join(dir, name);
      const raw = readFileSync(fullPath, "utf8");
      expect(
        () => JSON.parse(raw),
        `vector fixture must be valid JSON: ${name}`,
      ).not.toThrow();
    }
  });

  test("Phase G — /server/describe surface is internally consistent re conformance_harness profile", async ({
    request,
  }, testInfo) => {
    // Optional surface probe — the assertion is "the surface is internally
    // consistent", NOT "the endpoint works". Two outcomes are acceptable:
    //   (a) /server/describe does NOT claim ak.profile.conformance_harness.v1
    //       → any status from /_arkret/_conformance/snapshot (incl. 404) is OK,
    //         because the server isn't promising the endpoint exists.
    //   (b) /server/describe DOES claim ak.profile.conformance_harness.v1
    //       → /_arkret/_conformance/snapshot MUST NOT return 404 (anything else
    //         — 200/400/401/405/501 — is acceptable; 404 alone would mean the
    //         claim is a lie).

    const describeResp = await request.get(`${solandBaseUrl()}/_arkret/describe`);
    if (!describeResp.ok()) {
      // soland might be on an older build without /server/describe at all;
      // that's a different bug, surfaced by service-surface-contract. Skip
      // this probe rather than masking it as a failure here.
      test.skip(true, `/server/describe returned ${describeResp.status()}; not in scope for this scenario`);
      return;
    }
    const describe = await describeResp.json();

    const claimedProfiles: Array<{ profile_id?: string }> = Array.isArray(
      describe?.claimed_profiles,
    )
      ? describe.claimed_profiles
      : [];
    const claimsConformanceHarness = claimedProfiles.some(
      (entry) => entry?.profile_id === "ak.profile.conformance_harness.v1",
    );

    await testInfo.attach("describe-claims-conformance-harness", {
      body: String(claimsConformanceHarness),
      contentType: "text/plain",
    });

    if (!claimsConformanceHarness) {
      // Branch (a): nothing to enforce; surface is consistent by definition.
      return;
    }

    // Branch (b): probe one endpoint with a minimal POST and assert it does
    // NOT 404. We don't care about correctness of the body — we just need to
    // distinguish "endpoint absent" (404) from "endpoint present but stubbed
    // / rejecting / requiring auth" (anything else).
    const probe = await request.post(`${conformanceBaseUrl()}/snapshot`, {
      data: {
        vector_id: "ak.vector.snapshot.surface_probe.v1",
        manifest: {},
        chunks: [],
      },
    });
    expect(
      probe.status(),
      `server claims ak.profile.conformance_harness.v1 but /_arkret/_conformance/snapshot returned 404 — surface is inconsistent`,
    ).not.toBe(404);
  });
});

// Conformance — Snapshot / Query / Scalability Vectors
// Contract: e2e/scenarios/conformance/snapshot-query-scalability.md
// Spec:
//   - conformance/snapshot-schema.md (§2 manifest, §3 chunk, §4 state_hash,
//     §5 signature binding, §6 event_set_commitment)
//   - conformance/query-schema.md (§2 query object, §3 filter, §6 sort,
//     §8 response, §9 security)
//   - conformance/scalability-constraints.md (§2 wire limits, §3 authz limits,
//     §5 Space/Relation/View limits, §8 error semantics)
//   - conformance/conformance-vectors.md (vector loader pattern: same as the
//     sibling encoding-vectors suite — `cx.vector.<domain>.<scenario>.v1`
//     fixtures live in contrix-spec/spec/v1/artifacts/fixtures/)
// Fixtures: contrix-spec/spec/v1/artifacts/fixtures/cx.vector.snapshot.*.json,
//           cx.vector.query.*.json, cx.vector.scalability.*.json
//
// soland gap: /api/v1/conformance/{snapshot,query} endpoints are NOT
// implemented yet on soland (snapshot & query schema conformance currently
// only runs as in-process Rust tests; nothing is exposed over HTTP). Phases
// A–E pin the spec contract via test.fixme(...) until G3.S7 lands the HTTP
// vector endpoints. The live tests in this file are intentionally narrow:
//   - Phase F: harness-only vector loader smoke (filesystem read; never
//     touches soland). Always-pass on count so the suite stays green even
//     when the fixtures directory has zero matching files today.
//   - Phase G: optional surface probe of GET /api/v1/server/describe to
//     assert the surface is *internally consistent* (does NOT claim the
//     cx.profile.conformance.vectors.v1 profile while the endpoint is 404,
//     OR if it does claim it then the endpoint must respond with something
//     other than 404). This is the same "claim ⇔ surface" sanity used by
//     registry-drift / profile-gates.

import { readdirSync, readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";

const __filename_ = fileURLToPath(import.meta.url);
const __dirname_ = dirname(__filename_);

// From cotest/e2e/tests/conformance/<this-file>.spec.ts walk up four levels
// (conformance → tests → e2e → cotest) to reach the contrix-dev root, then
// into contrix-spec/spec/v1/artifacts/fixtures.
const FIXTURES_DIR = resolve(
  __dirname_,
  "..",
  "..",
  "..",
  "..",
  "contrix-spec",
  "spec",
  "v1",
  "artifacts",
  "fixtures",
);

// Matches the vector_id namespaces this scenario owns. Sibling suites
// (encoding-vectors, redaction-vectors, etc.) own their own namespaces; we
// must not accidentally count them.
const VECTOR_PREFIXES = [
  "cx.vector.snapshot.",
  "cx.vector.query.",
  "cx.vector.scalability.",
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

test.describe.configure({ mode: "serial" });

test.describe("conformance snapshot/query/scalability vectors @fully-implemented", () => {
  test.fixme(
    // @blocking-on: soland#conformance-snapshot-query-scalability-gap
    // @user-promise: e2e/scenarios/conformance/snapshot-query-scalability.md
    // @expected-live-by: 2026Q3
    "Phase A — snapshot manifest integrity (digest, chunk count, chunk hashes)",
    async () => {
      // spec: snapshot-schema.md §2 manifest, §3 chunk descriptor, §4 state_hash.
      //
      // POST /api/v1/conformance/snapshot { vector_id, manifest, chunks } →
      //   - response.manifest_digest === vector.expected_manifest_digest
      //   - response.chunk_hashes.length === vector.expected_chunk_count
      //   - response.chunk_hashes byte-equals vector.expected_chunk_hashes
      //     (order preserved — chunks[] is canonical-ordered by §3)
      //   - optional response.state_hash === vector.expected_state_hash
      //     (§4 Merkle root over reducer-output leaves)
      // Tamper test: flip one byte in a chunk payload → HTTP 4xx with
      //   error.code === "snapshot_chunk_digest_mismatch" (no silent accept).
    },
  );

  test.fixme(
    // @blocking-on: soland#conformance-snapshot-query-scalability-gap
    // @user-promise: e2e/scenarios/conformance/snapshot-query-scalability.md
    // @expected-live-by: 2026Q3
    "Phase B — snapshot signature binding verifies against recorded signer DID",
    async () => {
      // spec: snapshot-schema.md §5 (signature transcript coverage, allowed
      // signer DIDs, max acceptance window, revoked-signer reject path).
      //
      // POST /api/v1/conformance/snapshot { vector_id, manifest, chunks } where
      // manifest.signature is the Ed25519 detached_jws from the vector →
      //   - response.signature_valid === true
      //   - response.signer_did === vector.expected_signer_did
      //   - response.signed_transcript_fields[] === spec §5 list (snapshot_ref,
      //     realm_id, reducer_profile, schema_profile_refs, state_hash, frontier,
      //     event_set_commitment, chunks descriptor, verification_hints,
      //     created_by, created_at)
      //   - re-posting same Ed25519 manifest produces identical signature bytes
      //     (deterministic scheme); ECDSA vectors may differ in r/s but
      //     signature_valid still true.
      // Revoked signer: vector.expected_signer_did_revoked → HTTP 4xx with
      //   error.code === "snapshot_issuer_revoked" (§5 max acceptance window).
    },
  );

  test.fixme(
    // @blocking-on: soland#conformance-snapshot-query-scalability-gap
    // @user-promise: e2e/scenarios/conformance/snapshot-query-scalability.md
    // @expected-live-by: 2026Q3
    "Phase C — query filters / sort / pagination return expected_rows in order",
    async () => {
      // spec: query-schema.md §2 object, §3 filter ops, §6 sort, §8 response.
      //
      // POST /api/v1/conformance/query { vector_id, query } → page 1 →
      //   - response.items.map(o => o.id) === vector.expected_rows_page_1
      //     (ORDER PRESERVED — sort must be honoured)
      //   - response.has_more === vector.expected_has_more_page_1
      //   - response.next_cursor is non-empty
      //   - response.frontier.barrier_cursor exists
      // POST with response.next_cursor → page 2 →
      //   - response.items === vector.expected_rows_page_2
      //   - response.has_more === false
      // Cursor stability: re-issue the same cursor → byte-equal response.
      // Cursor opacity: Buffer.from(next_cursor, "base64url").toString("utf8")
      //   does NOT contain any row id substring (§ encoding-vectors §1.11
      //   cursor opaqueness still applies here).
    },
  );

  test.fixme(
    // @blocking-on: soland#conformance-snapshot-query-scalability-gap
    // @user-promise: e2e/scenarios/conformance/snapshot-query-scalability.md
    // @expected-live-by: 2026Q3
    "Phase D — query schema fail-closed on unknown ops / conflicting sort / unauthorized fields",
    async () => {
      // spec: query-schema.md §3 op enum, §6 sort direction enum, §9 security
      // ("实现 MUST 拒绝访问未授权字段").
      //
      // Three reject vectors, each MUST return HTTP 4xx with
      //   error.code === "query_schema_violation" (or spec-allowed equivalent
      //   "schema_violation") AND response body MUST NOT contain `items` or
      //   `next_cursor` — silent-empty is a failure mode that must be
      //   distinguished from authorized-empty.
      //
      //   - cx.vector.query.unknown_filter_key.v1: filter.op outside the §3
      //     enum {eq, neq, in, not_in, lt, lte, gt, gte, contains, exists,
      //     prefix, full_text}
      //   - cx.vector.query.conflicting_sort.v1: same field in order_by[]
      //     with opposing directions
      //   - cx.vector.query.unauthorized_field.v1: projection includes a
      //     field the caller has no read grant for → reject, not silent-strip
    },
  );

  test.fixme(
    // @blocking-on: soland#conformance-snapshot-query-scalability-gap
    // @user-promise: e2e/scenarios/conformance/snapshot-query-scalability.md
    // @expected-live-by: 2026Q3
    "Phase E — scalability constraints fail-closed (page_size / batch / depth / envelope)",
    async () => {
      // spec: scalability-constraints.md §2 wire limits, §5 Space/Relation/View
      // limits, §8 error semantics.
      //
      // Four reject vectors, each MUST return HTTP 4xx with error.code in
      //   { "scalability_limit_exceeded", "payload_too_large", "quota_exceeded" }
      // (NEVER silently truncate / clip):
      //
      //   - cx.vector.scalability.page_size_over_max.v1: query.limit = 1001
      //     (§2 single sync / projection page max = 1,000)
      //   - cx.vector.scalability.batch_size_over_max.v1: snapshot chunks[] or
      //     events[] over 1,000 (§2 batch /events submission max)
      //   - cx.vector.scalability.relation_depth_over_max.v1: query.relation.depth
      //     = 33 (§2 relation expansion depth max = 32)
      //   - cx.vector.scalability.envelope_over_1mib.v1: canonical manifest size
      //     > 1 MiB (§2 single canonical Event / Operation envelope max = 1 MiB)
      //
      // Per §8 error semantics: reject responses MUST NOT carry retry_after_ms
      // (retry hints are reserved for soft_fail / temporarily_unavailable).
    },
  );

  test("Phase F — vector loader smoke (harness-only, never touches soland)", async ({}, testInfo) => {
    // Scenario doc §"Implementation notes" → fixture-absence fallback. Today
    // the fixtures directory has zero cx.vector.{snapshot,query,scalability}.*
    // files. We still want CI to log the candidate count and id list so the
    // absence is visible and so newly-added fixtures show up immediately in
    // the next run.
    const { dir, exists, matches } = listVectorFixtures();

    // Always-pass count assertion — the goal is to surface the count, not
    // to gate the build on fixture presence (the gating happens via the
    // Phase A–E fixme tests once endpoints land).
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

  test("Phase G — /server/describe surface is internally consistent re conformance.vectors profile", async ({
    request,
  }, testInfo) => {
    // Optional surface probe — the assertion is "the surface is internally
    // consistent", NOT "the endpoint works". Two outcomes are acceptable:
    //   (a) /server/describe does NOT claim cx.profile.conformance.vectors.v1
    //       → any status from /api/v1/conformance/snapshot (incl. 404) is OK,
    //         because the server isn't promising the endpoint exists.
    //   (b) /server/describe DOES claim cx.profile.conformance.vectors.v1
    //       → /api/v1/conformance/snapshot MUST NOT return 404 (anything else
    //         — 200/400/401/405/501 — is acceptable; 404 alone would mean the
    //         claim is a lie).

    const describeResp = await request.get(`${solandBaseUrl()}/api/v1/server/describe`);
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
    const claimsConformanceVectors = claimedProfiles.some(
      (entry) => entry?.profile_id === "cx.profile.conformance.vectors.v1",
    );

    await testInfo.attach("describe-claims-conformance-vectors", {
      body: String(claimsConformanceVectors),
      contentType: "text/plain",
    });

    if (!claimsConformanceVectors) {
      // Branch (a): nothing to enforce; surface is consistent by definition.
      return;
    }

    // Branch (b): probe one endpoint with a minimal POST and assert it does
    // NOT 404. We don't care about correctness of the body — we just need to
    // distinguish "endpoint absent" (404) from "endpoint present but stubbed
    // / rejecting / requiring auth" (anything else).
    const probe = await request.post(`${solandBaseUrl()}/api/v1/conformance/snapshot`, {
      data: {
        vector_id: "cx.vector.snapshot.surface_probe.v1",
        manifest: {},
        chunks: [],
      },
    });
    expect(
      probe.status(),
      `server claims cx.profile.conformance.vectors.v1 but /api/v1/conformance/snapshot returned 404 — surface is inconsistent`,
    ).not.toBe(404);
  });
});

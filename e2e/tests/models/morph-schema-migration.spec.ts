// Models — Morph Schema Migration
// Contract: e2e/scenarios/models/morph-schema-migration.md
// Spec: models/morph.md §4.1 (schema_refs[] Evolution Policy, S1/S2/S3),
//       §4.0 (decision matrix — schema evolution row),
//       §6 (schema evolution generic constraints).
// Profile: ck.profile.morph.schema_migration_transformations.v1
//   defined in cokret-spec/spec/v1/artifacts/profiles/conformance-profiles.json
//   — opt-in Realm profile permitting ck.morph.schema_migrate events with
//     compatibility_class ∈ {breaking, transformation}.
// Decision table (canonical): cokret-spec/spec/v1/artifacts/registry/morph-type-decision-table.json
//   — 4 precedence sources for "what a Morph is and what it allows" merge.
// Event kind: ck.morph.schema_migrate (event-kind-registry.json, category=morph,
//             status=active, reducer_input=true).
// Error codes (error-code-registry.json):
//   - morph_schema_refs_evolution_unauthorized
//   - morph_schema_refs_transformation_unsupported
//   - morph_schema_version_binding_missing
//
// soland gap: Morph reducer support for schema_refs[] evolution is partial.
// gap report §1.2/§1.3 lists Morph schema migration as an implementation gap
// (no live reducer enforcement of additive vs. breaking gate, no
// schema_migration_breaking audit emission). Phases A / B / C / D below are
// pinned with test.fixme until the reducer + audit surface land.
//
// Phase E is a pure artifact schema probe (load morph-type-decision-table.json
// and the migration profile block, assert structural invariants). No soland
// writes required, so it is tagged @fully-implemented and ships live today.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

// ---------------------------------------------------------------------------
// Artifact loader (mirrors the G1.T4 registry-drift pattern)
// ---------------------------------------------------------------------------
// From cotest/e2e/tests/models/<spec>.spec.ts → four levels up to the repo
// root, then down into cokret-spec/spec/v1/artifacts. cwd-independent.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const artifactsRoot = resolve(__dirname, "../../../../cokret-spec/spec/v1/artifacts");
const registryRoot = resolve(artifactsRoot, "registry");
const profilesRoot = resolve(artifactsRoot, "profiles");

function loadJson<T = unknown>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

// Shape of morph-type-decision-table.json. Mirrors morph.md §4 four-source
// merge precedence. We only describe the fields the test touches; unknown
// fields pass through.
type DecisionTablePrecedence = {
  order: number;
  source: string;
  role: string;
  writable_by?: string[];
  consumed_by?: string[];
  MUST_NOT_consume_by?: string[];
  create_locked?: boolean;
  tightening_only?: boolean;
  notes?: string;
};

type MorphDecisionTable = {
  version: string;
  source_of_truth: boolean;
  applies_to: string;
  describes: string;
  precedence: DecisionTablePrecedence[];
  merge_rules: Array<{ rule: string; reads?: string[]; ignores?: string[]; scope?: string[] }>;
  conflict_resolution: Array<{ case: string; winner?: string; result?: string; rationale?: string }>;
  conformance_must_test: string[];
};

// Shape of the migration profile block inside conformance-profiles.json.
// Spec ref: morph.md §4.1 S3 + the profile registry entry.
type MigrationProfileBlock = {
  description: string;
  required_endpoints: string[];
  required_event_kinds: string[];
  rejected_event_kinds: string[];
  required_schemas: string[];
  required_fixtures: string[];
  optional_extensions: string[];
  feature_discovery: {
    required: string[];
    unsupported_optional: string;
  };
  additional_requirements: {
    capability_must: string;
    from_set_check_must: string;
    deterministic_transformation_must: string;
  };
};

// conformance-profiles.json top-level shape (only the keys this test touches).
// Real document has many more sibling keys (profile_tiers, profile_roles, ...);
// we deliberately only carve out the slice we read so spec growth doesn't
// constantly drift this type. Profile-id → requirements mapping lives under
// `profile_requirements`; the global v1 catalog list lives under
// `implementation_profiles`.
type ConformanceProfilesDoc = {
  implementation_profiles: string[];
  profile_requirements: Record<string, MigrationProfileBlock | Record<string, unknown>>;
};

const MIGRATION_PROFILE_ID = "ck.profile.morph.schema_migration_transformations.v1";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe.configure({ mode: "serial" });

test.describe("morph schema migration @fully-implemented", () => {
  // Phase E (LIVE) — artifact loading + structural invariants. If the JSON
  // can't be parsed, this surfaces as test setup failure (which is exactly
  // what we want — the spec build is broken, not the wire).
  const decisionTable = loadJson<MorphDecisionTable>(
    resolve(registryRoot, "morph-type-decision-table.json"),
  );
  const profilesDoc = loadJson<ConformanceProfilesDoc>(
    resolve(profilesRoot, "conformance-profiles.json"),
  );

  test("Phase E — morph-type-decision-table.json parses and exposes the four §4 precedence sources", async ({}, testInfo) => {
    // spec: morph.md §4 (four sources merge precedence) + the artifact
    //       itself which is marked source_of_truth=true.
    expect(decisionTable.source_of_truth).toBe(true);
    expect(decisionTable.applies_to).toBe("ck:morph:");

    // §4 lists exactly four declaration sources (1 schema_refs[], 2 realm
    // profile, 3 morph_type, 4 facets). The artifact MUST mirror that.
    expect(decisionTable.precedence.length).toBeGreaterThanOrEqual(4);
    const orders = decisionTable.precedence.map((p) => p.order).sort((a, b) => a - b);
    expect(orders).toEqual([1, 2, 3, 4]);

    // Spot-check that order=1 is the schema_refs[] structural truth row —
    // this is the source schema_migrate events evolve, so if it disappears
    // or moves the whole migration story is broken.
    const order1 = decisionTable.precedence.find((p) => p.order === 1);
    expect(order1, "decision-table order=1 entry must exist").toBeDefined();
    expect(order1!.source).toBe("morph.schema_refs[]");
    expect(order1!.role).toBe("structural_truth");

    // §4.0 row "Schema 演进" reads from order=1 + §4.1 S2/S3; order=4
    // (facets) MUST NOT be consumed by reducer / authz / wire. Assert the
    // facet row carries that MUST_NOT marker so future spec drift (e.g.
    // someone quietly letting facets gate authz) trips this test.
    const order4 = decisionTable.precedence.find((p) => p.order === 4);
    expect(order4, "decision-table order=4 (facets) entry must exist").toBeDefined();
    expect(order4!.source).toBe("morph.facets (map)");
    expect(Array.isArray(order4!.MUST_NOT_consume_by)).toBe(true);
    expect(order4!.MUST_NOT_consume_by).toEqual(
      expect.arrayContaining([
        "authz.decide",
        "reducer.state_machine",
        "reducer.field_validation",
        "wire.interop",
      ]),
    );

    // Per-row drift detector: consumed_by ∩ MUST_NOT_consume_by MUST be
    // empty for every precedence row. A non-empty intersection would mean
    // the artifact contradicts itself.
    for (const row of decisionTable.precedence) {
      const consumed = new Set(row.consumed_by ?? []);
      const forbidden = new Set(row.MUST_NOT_consume_by ?? []);
      const overlap = [...consumed].filter((c) => forbidden.has(c));
      expect(
        overlap,
        `precedence order=${row.order} (${row.source}) has consumed_by ∩ MUST_NOT_consume_by = ${JSON.stringify(overlap)}`,
      ).toEqual([]);
    }

    await testInfo.attach("morph-decision-table-precedence", {
      body: JSON.stringify(
        decisionTable.precedence.map((p) => ({ order: p.order, source: p.source, role: p.role })),
        null,
        2,
      ),
      contentType: "application/json",
    });
    await testInfo.attach("morph-decision-table-conformance-tests", {
      body: JSON.stringify(decisionTable.conformance_must_test, null, 2),
      contentType: "application/json",
    });
  });

  test("Phase E — ck.profile.morph.schema_migration_transformations.v1 profile block parses with the §4.1 S3 invariants", async ({}, testInfo) => {
    // spec: morph.md §4.1 S3 (breaking / transformation opt-in) +
    //       conformance-profiles.json profile registry entry.
    const profileBlock = profilesDoc.profile_requirements[MIGRATION_PROFILE_ID] as
      | MigrationProfileBlock
      | undefined;
    expect(
      profileBlock,
      `${MIGRATION_PROFILE_ID} must exist in conformance-profiles.json#/profile_requirements`,
    ).toBeDefined();

    // The profile commits the deployment to a) requiring ck.morph.schema_migrate
    // event kind support, and b) gating it on the ck.morph.schema.migrate
    // capability action. Both invariants are in additional_requirements +
    // required_event_kinds.
    expect(profileBlock!.required_event_kinds).toContain("ck.morph.schema_migrate");

    expect(profileBlock!.additional_requirements).toBeDefined();
    expect(profileBlock!.additional_requirements.capability_must).toMatch(
      /cx\.morph\.schema\.migrate/,
    );
    expect(profileBlock!.additional_requirements.from_set_check_must).toMatch(
      /from_schema_refs/,
    );
    expect(profileBlock!.additional_requirements.deterministic_transformation_must).toMatch(
      /deterministic|replay/i,
    );

    // feature_discovery.required must list the three discovery keys clients
    // need to negotiate the migration dialect with the server. Hardcoded
    // list intentional — adding a fourth key is a spec-side decision that
    // should land in this test in the same change.
    expect(profileBlock!.feature_discovery.required).toEqual(
      expect.arrayContaining([
        "supported_compatibility_classes",
        "transformation_rules_dialect",
        "schema_migrate_capability_action",
      ]),
    );

    // The v1 implementation_profiles top-level list MUST also enumerate this
    // profile id, otherwise the deployment tier matrix in
    // conformance-profiles.json doesn't know about it.
    expect(profilesDoc.implementation_profiles).toContain(MIGRATION_PROFILE_ID);

    await testInfo.attach("migration-profile-block", {
      body: JSON.stringify(profileBlock, null, 2),
      contentType: "application/json",
    });
  });

  // -------------------------------------------------------------------------
  // Pinned fixme — depend on soland Morph reducer + schema-evolution surface
  // -------------------------------------------------------------------------

  test.fixme(
    // @blocking-on: soland#models-morph-schema-migration-gap
    // @user-promise: e2e/scenarios/models/morph-schema-migration.md
    // @expected-live-by: 2026Q3
    "Phase A — ck.morph.schema_migrate with unsupported transformation_rules is hard-rejected",
    async ({ request }) => {
      // spec: morph.md §4.1 S3 (breaking / transformation 类需 Realm 显式启用
      //       ck.profile.morph.schema_migration_transformations.v1 profile,
      //       未声明 → reducer MUST failed_precondition reason=
      //       morph_schema_refs_transformation_unsupported).
      //
      // Acceptance criteria (once soland Morph reducer + schema-evolution
      // surface land):
      //   1. alice registers, dev-logins, creates a test Realm R (without
      //      declaring the migration profile), then a Morph M with
      //      schema_refs = ["ck.schema.morph.customer_risk.v1"].
      //   2. alice POSTs ck.morph.schema_migrate with:
      //        compatibility_class = "transformation"
      //        transformation_rules[*].rule = "ck.transform.bogus.unsupported.v1"
      //      (a rule id deliberately outside the profile's
      //      transformation_rules_dialect).
      //   3. Expect HTTP 4xx (400 or 422) and error.code ∈ {
      //        failed_precondition,
      //        schema_violation,
      //        morph_schema_refs_transformation_unsupported,
      //        unsupported_transformation_rule,
      //      }.
      //   4. Response body MUST NOT echo a partially-applied Morph or a
      //      side-effect transcript — reducer must fail at registration,
      //      before transformation execution.
      //   5. Re-GET the Morph: schema_refs[] is unchanged from step 1.
      void request;
    },
  );

  test.fixme(
    // @blocking-on: soland#models-morph-schema-migration-gap
    // @user-promise: e2e/scenarios/models/morph-schema-migration.md
    // @expected-live-by: 2026Q3
    "Phase B — additive schema_refs[] migration accepted and v1 history stays bound to v1 schema",
    async ({ request }) => {
      // spec: morph.md §4.1 S1 (per-event requirements.schema[] version
      //       binding — readers MUST validate historical events against the
      //       schema bound at write time, NOT current schema_refs[]) +
      //       §4.1 S2 (ck.morph.update schema_refs[] change is the
      //       additive-only fast path) +
      //       §4.1 S3 additive arm (core reducer MUST accept additive
      //       ck.morph.schema_migrate without the opt-in profile).
      //
      // Acceptance criteria (once soland Morph reducer lands):
      //   1. alice creates Morph M_b with schema_refs = ["...customer_risk.v1"]
      //      and writes some v1 fields.
      //   2. alice POSTs ck.morph.update with schema_refs[] expanded to
      //      ["...customer_risk.v1", "...customer_risk.optional_ext.v1"]
      //      (additive: optional fields only).
      //      The event's requirements.schema[] MUST include both old and
      //      new schema ids (overlap window — spec §4.1 S2).
      //   3. Expect HTTP 2xx. GET the Morph: schema_refs[] is the new set;
      //      v1 fields still present.
      //   4. Pull /_cokret/self/audit/recent (or equivalent). Assert there is one
      //      schema_evolution entry recording issuer, schema_refs old/new,
      //      authorization_ref.
      //   5. alice POSTs ck.morph.schema_migrate with
      //      compatibility_class = "additive" stacking another optional
      //      extension. HTTP 2xx (no profile opt-in needed for additive).
      //   6. GET event history: events written before step 2 still carry
      //      their original requirements.schema[] binding (NOT silently
      //      rewritten to the new schema set).
      void request;
    },
  );

  test.fixme(
    // @blocking-on: soland#models-morph-schema-migration-gap
    // @user-promise: e2e/scenarios/models/morph-schema-migration.md
    // @expected-live-by: 2026Q3
    "Phase C — breaking / transformation migration requires opt-in profile + capability and emits schema_migration_breaking audit",
    async ({ request }) => {
      // spec: morph.md §4.1 S3 (breaking / transformation arms — Realm MUST
      //       declare ck.profile.morph.schema_migration_transformations.v1
      //       opt-in AND reducer MUST gate on ck.morph.schema.migrate
      //       capability action; absence → failed_precondition reason=
      //       morph_schema_refs_transformation_unsupported or capability_denied).
      //
      // Acceptance criteria:
      //   1. In Realm R (no migration profile declared), alice POSTs
      //      ck.morph.schema_migrate with compatibility_class = "breaking"
      //      (e.g. to_schema_refs[] removes a required field).
      //      Expect HTTP 4xx, error.code =
      //      morph_schema_refs_transformation_unsupported.
      //   2. alice POSTs ck.realm.profile.update declaring the migration
      //      profile + granting ck.morph.schema.migrate to her own DID.
      //   3. alice re-POSTs the breaking schema_migrate from step 1.
      //      Expect HTTP 2xx.
      //   4. Pull audit log; assert one entry with kind matching
      //      /schema_migration|morph_schema_migrate|breaking/i, carrying:
      //        issuer = alice.did
      //        from_schema_refs[], to_schema_refs[]
      //        compatibility_class = "breaking"
      //        capability_used = "ck.morph.schema.migrate"
      //        profile_ref = MIGRATION_PROFILE_ID
      //   5. alice POSTs schema_migrate with
      //      compatibility_class = "transformation" and well-formed
      //      transformation_rules[] (each rule.id ∈ profile
      //      transformation_rules_dialect). Expect HTTP 2xx.
      //   6. alice revokes her own ck.morph.schema.migrate capability via
      //      ck.realm.policy.update, then re-POSTs a transformation migrate.
      //      Expect HTTP 4xx, error.code = capability_denied.
      void request;
    },
  );

  test.fixme(
    // @blocking-on: soland#models-morph-schema-migration-gap
    // @user-promise: e2e/scenarios/models/morph-schema-migration.md
    // @expected-live-by: 2026Q3
    "Phase D — deterministic transform vectors produce byte-equal output (gated on fixture availability)",
    async ({ request }) => {
      // spec: morph.md §4.1 S3 + profile additional_requirements
      //       .deterministic_transformation_must.
      //
      // Pinned fixme for two reasons:
      //   (a) cokret-spec/spec/v1/artifacts/fixtures/ does NOT currently
      //       contain any ck.vector.morph.*.json fixtures (grep verified at
      //       scenario authoring time, see scenarios/models/morph-schema-migration.md
      //       Phase D step 20). Without fixtures there is no expected_output
      //       to assert against.
      //   (b) Even when fixtures land, the transformation driver path
      //       depends on soland's schema_migrate reducer (covered by Phase C).
      //
      // Acceptance criteria (once ck.vector.morph.* fixtures land):
      //   1. Enumerate all ck.vector.morph.*.json files under
      //      cokret-spec/spec/v1/artifacts/fixtures/.
      //   2. For each vector v:
      //      a. Seed Morph state matching v.input.
      //      b. POST ck.morph.schema_migrate with v.input.payload
      //         (from_schema_refs[], to_schema_refs[], compatibility_class,
      //         transformation_rules[]).
      //      c. GET the Morph projection after migration.
      //      d. Assert canonical_json(projection) byte-equals
      //         v.expected_output (canonical JSON, sorted keys).
      //      e. If v exposes expected_digest, assert digest match.
      //   3. The driver MUST run each vector deterministically across two
      //      back-to-back invocations (no clock-dependent or randomised
      //      transformation results).
      void request;
    },
  );
});

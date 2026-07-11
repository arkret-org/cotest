// Models — Morph Schema Migration
// Contract: e2e/scenarios/models/morph-schema-migration.md
// Spec: models/morph.md §4.1 (schema_refs[] Evolution Policy, S1/S2/S3),
//       §4.0 (decision matrix — schema evolution row),
//       §6 (schema evolution generic constraints).
// Profile: ak.profile.morph.schema_migration_transformations.v1
//   defined in arkret-spec/spec/v1/artifacts/profiles/conformance-profiles.json
//   — opt-in Realm profile permitting ak.morph.schema_migrate events with
//     compatibility_class ∈ {breaking, transformation}.
// Decision table (canonical): arkret-spec/spec/v1/artifacts/registry/morph-type-decision-table.json
//   — 4 precedence sources for "what a Morph is and what it allows" merge.
// Event kind: ak.morph.schema_migrate (event-kind-registry.json, category=morph,
//             status=active, reducer_input=true).
// Error codes (error-code-registry.json):
//   - morph_schema_refs_evolution_unauthorized
//   - morph_schema_refs_transformation_unsupported
//   - morph_schema_version_binding_missing
//
// soland surface: the ak.morph.schema_migrate reducer is live. Phase A drives
// the unsupported-transformation-rule hard reject; Phase B the additive arm
// (no opt-in profile); Phase C the breaking/transformation opt-in profile gate
// + schema_migration_breaking audit emission; Phase D the deterministic
// transformation vectors (ak.vector.morph.*).
//
// Phase E is a pure artifact schema probe (load morph-type-decision-table.json
// and the migration profile block, assert structural invariants). No soland
// writes required, so it is tagged @fully-implemented and ships live today.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  canonicalJson,
  createRealmApi,
  grantCapabilityEventApi,
  sha256CanonicalJson,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

// ---------------------------------------------------------------------------
// Artifact loader (mirrors the G1.T4 registry-drift pattern)
// ---------------------------------------------------------------------------
// From cotest/e2e/tests/models/<spec>.spec.ts → four levels up to the repo
// root, then down into arkret-spec/spec/v1/artifacts. cwd-independent.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const artifactsRoot = resolve(__dirname, "../../../../arkret-spec/spec/v1/artifacts");
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

const MIGRATION_PROFILE_ID = "ak.profile.morph.schema_migration_transformations.v1";

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
    expect(decisionTable.applies_to).toBe("ak:morph:");

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

  test("Phase E — ak.profile.morph.schema_migration_transformations.v1 profile block parses with the §4.1 S3 invariants", async ({}, testInfo) => {
    // spec: morph.md §4.1 S3 (breaking / transformation opt-in) +
    //       conformance-profiles.json profile registry entry.
    const profileBlock = profilesDoc.profile_requirements[MIGRATION_PROFILE_ID] as
      | MigrationProfileBlock
      | undefined;
    expect(
      profileBlock,
      `${MIGRATION_PROFILE_ID} must exist in conformance-profiles.json#/profile_requirements`,
    ).toBeDefined();

    // The profile commits the deployment to a) requiring ak.morph.schema_migrate
    // event kind support, and b) gating it on the ak.morph.schema_migrate
    // capability action. Both invariants are in additional_requirements +
    // required_event_kinds.
    expect(profileBlock!.required_event_kinds).toContain("ak.morph.schema_migrate");

    expect(profileBlock!.additional_requirements).toBeDefined();
    expect(profileBlock!.additional_requirements.capability_must).toMatch(
      /ak\.morph\.schema_migrate/,
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
  // Live — soland ak.morph.schema_migrate reducer + schema-evolution surface
  // -------------------------------------------------------------------------

  test("Phase A — ak.morph.schema_migrate with unsupported transformation_rules is hard-rejected", async ({
    request,
  }) => {
    // spec: morph.md §4.1 S3 — a transformation migration whose
    // transformation_rules[*].rule id is outside the profile dialect is
    // hard-rejected at registration with `unsupported_transformation_rule`,
    // with no partial Morph mutation.
    const alice = uniqueUser("morph-migrate-a-alice");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    // Realm WITHOUT the migration profile declared.
    const realmId = await createRealmApi(request, token, {
      title: `Morph migrate A ${Date.now()}`,
    });
    const morphId = morphTypedId();
    const fromRefs = ["ak.schema.morph.customer_risk.v1"];
    await createCustomerRiskMorph(request, token, alice.did, realmId, morphId, fromRefs, {
      status: "open",
      severity: "high",
    });

    const result = await submitSchemaMigrateRaw(request, token, {
      actorDid: alice.did,
      realmId,
      morphId,
      fromRefs,
      toRefs: ["ak.schema.morph.customer_risk.v1", "ak.schema.morph.customer_risk.ext.v1"],
      compatibilityClass: "transformation",
      transformationRules: [{ rule: "ak.transform.bogus.unsupported.v1", from: "status", to: "state" }],
    });

    expect(result.status, `migrate body: ${result.text}`).toBeGreaterThanOrEqual(400);
    expect(result.status).toBeLessThan(500);
    expect(
      [
        "failed_precondition",
        "schema_violation",
        "morph_schema_refs_transformation_unsupported",
        "unsupported_transformation_rule",
      ],
      `unexpected error code in ${result.text}`,
    ).toContain(wireErrCode(result.body));

    // No partially-applied Morph / transcript echoed back.
    expect(result.text).not.toMatch(/"morph_id"\s*:\s*"ak:morph:/);

    // Re-GET: schema_refs[] unchanged.
    const projection = await readMorphProjection(request, token, realmId, morphId);
    expect(projection.document.schema_refs).toEqual(fromRefs);
  });

  test("Phase B — additive ak.morph.schema_migrate accepted without opt-in profile and preserves fields", async ({
    request,
  }) => {
    // spec: morph.md §4.1 S3 additive arm — the core reducer MUST accept an
    // additive ak.morph.schema_migrate (to_schema_refs[] only adds a
    // backward-compatible profile) WITHOUT the opt-in
    // ak.profile.morph.schema_migration_transformations.v1 profile, and the
    // §4.1 S1 per-event requirements.schema[] binding carries the union of
    // from/to schema ids.
    //
    // Scope note: the §4.1 S2 ak.morph.update schema_refs[] additive fast path
    // is a separate (still-rejected) surface — soland's morph.update payload
    // validator returns morph_schema_refs_evolution_unauthorized for any patch
    // touching schema_refs — so this phase exercises the schema_migrate additive
    // arm, which is the implemented core path.
    const alice = uniqueUser("morph-migrate-b-alice");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    // Realm WITHOUT the migration profile (additive needs no opt-in).
    const realmId = await createRealmApi(request, token, {
      title: `Morph migrate B ${Date.now()}`,
    });
    const morphId = morphTypedId();
    const fromRefs = ["ak.schema.morph.customer_risk.v1"];
    const toRefs = ["ak.schema.morph.customer_risk.v1", "ak.schema.morph.customer_risk.ext.v1"];
    const fields = { status: "open", severity: "high" };
    await createCustomerRiskMorph(request, token, alice.did, realmId, morphId, fromRefs, fields);

    const result = await submitSchemaMigrateRaw(request, token, {
      actorDid: alice.did,
      realmId,
      morphId,
      fromRefs,
      toRefs,
      compatibilityClass: "additive",
    });
    expect([200, 201], `additive migrate failed: ${result.text}`).toContain(result.status);

    // GET the Morph: schema_refs[] is the new superset; v1 business fields are
    // preserved (additive does not transform fields).
    const projection = await readMorphProjection(request, token, realmId, morphId);
    expect(projection.document.schema_refs).toEqual(toRefs);
    expect(projection.document.fields).toMatchObject(fields);
  });

  test("Phase C — breaking / transformation migration requires the opt-in profile and emits schema_migration_breaking audit", async ({
    request,
  }) => {
    // spec: morph.md §4.1 S3 — breaking / transformation migrations require the
    // Realm to declare ak.profile.morph.schema_migration_transformations.v1;
    // absent → morph_schema_refs_transformation_unsupported. On acceptance the
    // server emits a schema_migration_breaking audit carrying issuer / from /
    // to / compatibility_class / capability_used / profile_ref.
    //
    // Scope note: the capability conjunct is satisfied here because the Realm
    // owner (alice) is implicitly authorized. The full non-owner grant →
    // capability_denied → revoke cycle rides the event-minted capability
    // surface (ak.capability.grant / revoke) that the authz/capability-chain
    // suite is still fixme'd on; the unsupported-rule hard reject below
    // exercises the other fail-closed branch of this reducer.
    const alice = uniqueUser("morph-migrate-c-alice");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, token, {
      title: `Morph migrate C ${Date.now()}`,
    });
    const morphId = morphTypedId();
    const fromRefs = ["ak.schema.morph.customer_risk.v1"];
    const toRefs = ["ak.schema.morph.customer_risk.ext.v1"];
    await createCustomerRiskMorph(request, token, alice.did, realmId, morphId, fromRefs, {
      status: "open",
      severity: "high",
    });

    // 1. breaking without the migration profile → reject.
    const beforeProfile = await submitSchemaMigrateRaw(request, token, {
      actorDid: alice.did,
      realmId,
      morphId,
      fromRefs,
      toRefs,
      compatibilityClass: "breaking",
    });
    expect(beforeProfile.status, `breaking pre-profile body: ${beforeProfile.text}`).toBeGreaterThanOrEqual(400);
    expect(wireErrCode(beforeProfile.body)).toBe("morph_schema_refs_transformation_unsupported");

    // 2. declare the opt-in migration profile via ak.realm.update.
    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.realm.update",
        payload: {
          target_ref: realmId,
          active_profiles: [MIGRATION_PROFILE_ID],
          patch: {
            active_profiles: { $op: "set", value: [MIGRATION_PROFILE_ID] },
          },
        },
      }),
      { context: "declare migration profile" },
    );

    // 3. breaking now accepted.
    const breakingAccepted = await submitSchemaMigrateRaw(request, token, {
      actorDid: alice.did,
      realmId,
      morphId,
      fromRefs,
      toRefs,
      compatibilityClass: "breaking",
    });
    expect([200, 201], `breaking post-profile body: ${breakingAccepted.text}`).toContain(
      breakingAccepted.status,
    );
    const afterBreaking = await readMorphProjection(request, token, realmId, morphId);
    expect(afterBreaking.document.schema_refs).toEqual(toRefs);

    // 4. audit record.
    const audit = await waitForBreakingAudit(request, token, realmId);
    expect(audit, "schema_migration_breaking audit not found").toBeTruthy();
    expect(audit!.payload.issuer).toBe(alice.did);
    expect(audit!.payload.from_schema_refs).toEqual(fromRefs);
    expect(audit!.payload.to_schema_refs).toEqual(toRefs);
    expect(audit!.payload.compatibility_class).toBe("breaking");
    expect(String(audit!.payload.capability_used)).toMatch(/ak\.morph\.schema[._]migrate/);
    expect(audit!.payload.profile_ref).toBe(MIGRATION_PROFILE_ID);

    // 5. transformation with well-formed dialect rules accepted.
    const transformationAccepted = await submitSchemaMigrateRaw(request, token, {
      actorDid: alice.did,
      realmId,
      morphId,
      fromRefs: toRefs,
      toRefs: ["ak.schema.morph.customer_risk.v1", "ak.schema.morph.customer_risk.ext.v1"],
      compatibilityClass: "transformation",
      transformationRules: [{ rule: "ak.transform.identity.v1" }],
    });
    expect([200, 201], `transformation body: ${transformationAccepted.text}`).toContain(
      transformationAccepted.status,
    );

    // 6. transformation with a rule id outside the dialect → hard reject.
    const transformationRejected = await submitSchemaMigrateRaw(request, token, {
      actorDid: alice.did,
      realmId,
      morphId,
      fromRefs: ["ak.schema.morph.customer_risk.v1", "ak.schema.morph.customer_risk.ext.v1"],
      toRefs: ["ak.schema.morph.customer_risk.ext.v1"],
      compatibilityClass: "transformation",
      transformationRules: [{ rule: "ak.transform.not_in_dialect.v1" }],
    });
    expect(transformationRejected.status).toBeGreaterThanOrEqual(400);
    expect(wireErrCode(transformationRejected.body)).toBe("unsupported_transformation_rule");
  });

  test("Phase D — deterministic transform vectors produce byte-equal output", async ({
    request,
  }) => {
    // spec: morph.md §4.1 S3 + the migration profile
    // additional_requirements.deterministic_transformation_must — every
    // transformation vector under artifacts/fixtures maps input.fields to
    // expected_output deterministically; running the same vector twice yields
    // byte-identical canonical JSON.
    const vectors = loadMorphTransformationVectors();
    expect(vectors.length, "no ak.vector.morph.* transformation vectors found").toBeGreaterThan(0);

    const alice = uniqueUser("morph-migrate-d-alice");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    // Vectors are transformation-class → the Realm declares the opt-in profile.
    const realmId = await createRealmApi(request, token, {
      title: `Morph migrate D ${Date.now()}`,
    });
    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.realm.update",
        payload: {
          target_ref: realmId,
          active_profiles: [MIGRATION_PROFILE_ID],
          patch: { active_profiles: { $op: "set", value: [MIGRATION_PROFILE_ID] } },
        },
      }),
      { context: "declare migration profile for vectors" },
    );

    for (const vector of vectors) {
      const expectedCanonical = canonicalJson(vector.expected_output);
      if (typeof vector.expected_output_digest === "string") {
        expect(
          `sha256:${sha256CanonicalJson(vector.expected_output)}`,
          `vector ${vector.vector_id} expected_output_digest drift`,
        ).toBe(vector.expected_output_digest);
      }

      // Run the same vector twice (fresh Morph each time) and assert both the
      // expected canonical bytes and cross-run determinism.
      const observed: string[] = [];
      for (let run = 0; run < 2; run += 1) {
        const morphId = morphTypedId();
        await createCustomerRiskMorph(
          request,
          token,
          alice.did,
          realmId,
          morphId,
          vector.input.from_schema_refs,
          vector.input.fields,
        );
        const migrate = await submitSchemaMigrateRaw(request, token, {
          actorDid: alice.did,
          realmId,
          morphId,
          fromRefs: vector.input.payload.from_schema_refs,
          toRefs: vector.input.payload.to_schema_refs,
          compatibilityClass: vector.input.payload.compatibility_class,
          transformationRules: vector.input.payload.transformation_rules,
        });
        expect(
          [200, 201],
          `vector ${vector.vector_id} run ${run} migrate body: ${migrate.text}`,
        ).toContain(migrate.status);

        const projection = await readMorphProjection(request, token, realmId, morphId);
        observed.push(canonicalJson(projection.document.fields));
      }
      expect(observed[0], `vector ${vector.vector_id} output canonical-bytes mismatch`).toBe(
        expectedCanonical,
      );
      expect(observed[1], `vector ${vector.vector_id} not replay-deterministic`).toBe(observed[0]);
    }
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function morphTypedId(): string {
  return typedId("operation").replace("ak:operation:", "ak:morph:");
}

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

async function createCustomerRiskMorph(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  morphId: string,
  schemaRefs: string[],
  fields: Record<string, unknown>,
): Promise<void> {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ak.morph.create",
      payload: {
        object: {
          id: morphId,
          schema: "ak.schema.morph.v1",
          realm_id: realmId,
          // views.md §377 / service-http-binding.md §230 — the single-Morph read
          // surface GET /_arkret/self/realms/{realm_id}/morphs/{morph_id} is the
          // *document* Morph projection (response document_morph_projection_outcome,
          // which carries `document.schema_refs` and `document.fields`). It serves
          // only morph_type=="document" (soland projection_query.rs
          // get_document_projection). Business morph field state is otherwise read
          // via the canonical event/snapshot history, which has no HTTP field-read
          // surface — so this HTTP migration read-back test uses a document Morph.
          // morph_type is orthogonal to schema_refs (the customer_risk reference
          // schemas the §4.1 S3 transformation vectors evolve), and immutable per
          // §4.1 S2, so the migration semantics are unchanged.
          morph_type: "document",
          stage: "in_progress",
          schema_refs: schemaRefs,
          fields,
          created_by: actorDid,
          created_at: nowIso(),
        },
      },
    }),
    { context: `create customer_risk-schema document morph ${morphId}` },
  );
}

type SchemaMigrateArgs = {
  actorDid: string;
  realmId: string;
  morphId: string;
  fromRefs: string[];
  toRefs: string[];
  compatibilityClass: string;
  transformationRules?: Array<Record<string, unknown>>;
};

async function submitSchemaMigrateRaw(
  request: APIRequestContext,
  token: string,
  args: SchemaMigrateArgs,
): Promise<{ status: number; text: string; body: unknown }> {
  // morph.md §4.1 S1 — bind the migration schema set (union of from/to) into
  // requirements.schema[] so the reducer's version-binding check is satisfied.
  const requirementsSchema = Array.from(new Set([...args.fromRefs, ...args.toRefs]));
  // morph.md §4.1 S3 — ak.morph.schema_migrate is gated by the high-tier
  // capability action `ak.morph.schema_migrate`; the authorization is carried on
  // the envelope `refs[]` with role `authorized_by`, which MUST resolve to the
  // accepted Event that produced the authorizing grant (event-and-patch.md §2.2;
  // soland event_log/submit.rs rejects unresolved authorized_by refs with
  // dependency_missing, and event_log/sdk_projection.rs projects
  // refs[authorized_by][0] into the operation's authorization_ref). The payload
  // itself is closed
  // (ak.schema.event_payload.v1#/$defs/morph_schema_migrate_payload,
  // additionalProperties:false) and only declares morph_id / from_schema_refs /
  // to_schema_refs / compatibility_class / transformation_rules.
  //
  // The Realm owner is implicitly authorized for the capability check
  // (operations/policy.rs validate_morph_schema_migrate_authz short-circuits the
  // owner), but soland still requires a resolvable authorized_by ref — so mint a
  // real owner-issued grant for the action and reference its carrying event.
  const { eventId: authorizationEventId } = await grantCapabilityEventApi(request, token, {
    ownerDid: args.actorDid,
    realmId: args.realmId,
    subjectDid: args.actorDid,
    actions: ["ak.morph.schema_migrate"],
  });
  const envelope = signedEventEnvelope({
    actorDid: args.actorDid,
    realmId: args.realmId,
    kind: "ak.morph.schema_migrate",
    requirementsSchema,
    refs: [{ role: "authorized_by", id: authorizationEventId }],
    payload: {
      morph_id: args.morphId,
      from_schema_refs: args.fromRefs,
      to_schema_refs: args.toRefs,
      compatibility_class: args.compatibilityClass,
      ...(args.transformationRules ? { transformation_rules: args.transformationRules } : {}),
    },
  });
  const response = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
    headers: authHeaders(token),
    data: envelope,
  });
  const text = await response.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  return { status: response.status(), text, body };
}

async function readMorphProjection(
  request: APIRequestContext,
  token: string,
  realmId: string,
  morphId: string,
): Promise<{ document: { schema_refs: string[]; fields: Record<string, unknown> } }> {
  const response = await request.get(
    `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/morphs/${encodeURIComponent(morphId)}`,
    { headers: authHeaders(token) },
  );
  const text = await response.text();
  expect(response.ok(), `read morph projection ${response.status()}: ${text}`).toBeTruthy();
  return JSON.parse(text);
}

type AuditEntry = { payload: Record<string, unknown> };

async function waitForBreakingAudit(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<AuditEntry | undefined> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const response = await request.get(
      `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=${encodeURIComponent(realmId)}&kind=schema_migration_breaking`,
      { headers: authHeaders(token) },
    );
    if (response.ok()) {
      const body = (await response.json()) as { events?: AuditEntry[] };
      const entry = (body.events ?? []).find(
        (event) => event.payload && typeof event.payload === "object",
      );
      if (entry) {
        return entry;
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return undefined;
}

type MorphTransformationVector = {
  vector_id: string;
  input: {
    from_schema_refs: string[];
    fields: Record<string, unknown>;
    payload: {
      from_schema_refs: string[];
      to_schema_refs: string[];
      compatibility_class: string;
      transformation_rules?: Array<Record<string, unknown>>;
    };
  };
  expected_output: Record<string, unknown>;
  expected_output_digest?: string;
};

function loadMorphTransformationVectors(): MorphTransformationVector[] {
  const fixturesDir = resolve(artifactsRoot, "fixtures");
  const collected: MorphTransformationVector[] = [];
  for (const file of readdirSync(fixturesDir)) {
    if (!file.endsWith(".json")) {
      continue;
    }
    let parsed: unknown;
    try {
      parsed = loadJson(resolve(fixturesDir, file));
    } catch {
      continue;
    }
    const vectors = (parsed as { vectors?: unknown }).vectors;
    if (!Array.isArray(vectors)) {
      continue;
    }
    for (const vector of vectors) {
      const candidate = vector as Partial<MorphTransformationVector>;
      if (
        typeof candidate.vector_id === "string" &&
        candidate.vector_id.startsWith("ak.vector.morph.") &&
        candidate.input &&
        candidate.expected_output
      ) {
        collected.push(candidate as MorphTransformationVector);
      }
    }
  }
  return collected;
}

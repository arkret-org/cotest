// Conformance — Profile Claim Gates
// Contract: e2e/scenarios/conformance/profile-gates.md
// Spec: conformance/conformance-profiles.md §2 / §2.1 / §3 (profile tiers, fail-closed
//         on unsupported event kind, critical extension fail-closed),
//       sync/service-surface.md §3.0 (claim-level partition; dev-mode verified_profiles=[]).
// Catalog artifact: contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json
//
// soland gap: `soland/src/routing/system/describe.rs::apply_claim_level_partition`
//   already emits `claimed_profiles[]` (4 self_claimed entries) + `verified_profiles=[]`
//   (hard `Vec::new()` under dev mode, guarded by validate_v2). Phase A / D / E run live
//   against this surface. Phase B (unsupported standard event kind reject) and Phase C
//   (critical extension fail-closed at submit time) need the event-submit reject path
//   to emit canonical `unsupported_event_kind` / `unsupported_feature` codes, which
//   soland's submit handler does not yet do — those phases stay pinned via test.fixme.
//
// coauth note: `coauth/crates/backend/src/handlers/contrix.rs` now self-claims
//   `cx.profile.auth_server.v1` and intentionally does NOT claim
//   `cx.profile.identity_registry.v1` / `cx.profile.principal_server.v1`. The
//   coauth-specific partition test remains fixme because coauth is optional in
//   single-server topologies and the verified-profile write path is deployment
//   dependent, but the pinned expectation below reflects the current auth-server
//   contract rather than the older empty-claims placeholder.
//
// The describe block is tagged @fully-implemented so that the 3 live tests (Phase A,
// Phase D, Phase E) run under the default `joint-smoke` profile. The fixme tests
// are kept inside the same block on purpose — Playwright's fixme marker keeps them
// visible in reports without failing the run.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";

// ESM-friendly __dirname so `node --experimental-vm-modules` / Playwright's loader
// can resolve the spec artifact path regardless of cwd.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Repo-relative path from cotest/e2e/tests/conformance/ → contrix-spec/.
const CATALOG_PATH = path.resolve(
  __dirname,
  "../../../../contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json",
);

type ClaimedProfileEntry = {
  profile_id?: string;
  claim_kind?: string;
  notes?: string;
};

type VerifiedProfileEntry = {
  profile_id?: string;
  claim_kind?: string;
  cotest_run_id?: string;
  artifact_hash?: string;
  artifact_ref?: string;
  cotest_issuer_did?: string;
  signature?: string;
  timestamp?: string;
  valid_until?: string;
};

type DescribeResponse = {
  development_mode?: boolean;
  claimed_profiles?: ClaimedProfileEntry[];
  verified_profiles?: VerifiedProfileEntry[];
  unsupported_profiles?: Array<{ profile?: string; status?: string }>;
};

type ConformanceCatalog = {
  implementation_profiles?: string[];
  profile_tiers?: {
    v1_profile_catalog?: string[];
    v1_minimal_interop_floor?: string[];
    extension_profile_implementation?: string[];
  };
};

test.describe.configure({ mode: "serial" });

test.describe("conformance profile gates @fully-implemented", () => {
  test("Phase A — soland claimed_profiles and verified_profiles are partitioned by claim_kind", async ({
    request,
  }, testInfo) => {
    // spec: conformance-profiles.md §2.1 (self_claimed vs verified entries),
    //       service-surface.md §3.0 (claim_kind enum; partition invariant).
    //
    // claimed_profiles[].claim_kind MUST be "self_claimed" for every entry.
    // verified_profiles entries, if present, MUST carry cotest_run_id / artifact_hash /
    //   artifact_ref / cotest_issuer_did / signature / timestamp.
    // The two profile_id sets MUST be disjoint — a profile cannot be simultaneously
    // self-claimed and cotest-verified.
    const resp = await request.get(`${solandBaseUrl()}/api/v1/server/describe`);
    expect(resp.status()).toBe(200);
    const body = (await resp.json()) as DescribeResponse;

    expect(Array.isArray(body.claimed_profiles), "claimed_profiles is an array").toBe(true);
    expect(Array.isArray(body.verified_profiles), "verified_profiles is an array").toBe(true);

    const claimed = body.claimed_profiles ?? [];
    const verified = body.verified_profiles ?? [];

    expect(claimed.length, "soland claims at least the v1 floor + principal server").toBeGreaterThan(
      0,
    );

    for (const entry of claimed) {
      expect(typeof entry.profile_id, "claimed entry profile_id is string").toBe("string");
      expect(entry.profile_id, "claimed entry profile_id is non-empty").toBeTruthy();
      expect(entry.claim_kind, "claimed entry claim_kind === self_claimed").toBe("self_claimed");
    }

    for (const entry of verified) {
      expect(entry.profile_id, "verified entry profile_id present").toBeTruthy();
      expect(entry.cotest_run_id, "verified entry cotest_run_id present").toBeTruthy();
      expect(entry.artifact_hash, "verified entry artifact_hash present").toBeTruthy();
      expect(entry.artifact_ref, "verified entry artifact_ref present").toBeTruthy();
      expect(entry.cotest_issuer_did, "verified entry cotest_issuer_did present").toBeTruthy();
      expect(entry.signature, "verified entry signature present").toBeTruthy();
      expect(entry.timestamp, "verified entry timestamp present").toBeTruthy();
    }

    const claimedIds = new Set(claimed.map((e) => e.profile_id).filter(Boolean) as string[]);
    const verifiedIds = new Set(verified.map((e) => e.profile_id).filter(Boolean) as string[]);
    for (const id of verifiedIds) {
      expect(
        claimedIds.has(id),
        `profile ${id} appears in both claimed_profiles and verified_profiles (partition violated)`,
      ).toBe(false);
    }

    await testInfo.attach("soland-claim-partition", {
      body: JSON.stringify(
        {
          claimed_profile_ids: Array.from(claimedIds),
          verified_profile_ids: Array.from(verifiedIds),
        },
        null,
        2,
      ),
      contentType: "application/json",
    });
  });

  test("Phase D — soland in development_mode keeps verified_profiles strictly empty", async ({
    request,
  }) => {
    // spec: service-surface.md §3.0 — when development_mode=true, verified_profiles
    //   MUST be []; never null, never a placeholder stub. soland enforces this with
    //   validate_v2 (`describe.rs::server_describe`).
    const resp = await request.get(`${solandBaseUrl()}/api/v1/server/describe`);
    expect(resp.status()).toBe(200);
    const body = (await resp.json()) as DescribeResponse;

    // cotest harness always boots soland with development_mode=true. If this ever
    // flips, the test below makes the regression visible rather than skipping silently.
    expect(body.development_mode, "cotest harness boots soland with development_mode=true").toBe(
      true,
    );
    expect(Array.isArray(body.verified_profiles), "verified_profiles is an array").toBe(true);
    expect(body.verified_profiles, "dev-mode verified_profiles is exactly []").toEqual([]);
  });

  test("Phase E — every claimed profile id exists in the canonical profile catalog", async ({
    request,
  }, testInfo) => {
    // spec: conformance-profiles.md §2.1 (v1_profile_catalog tiering);
    //       artifact: conformance-profiles.json (implementation_profiles ∪
    //       profile_tiers.v1_profile_catalog ∪ profile_tiers.extension_profile_implementation).
    //
    // Every entry in soland's claimed_profiles MUST resolve to a profile id known by
    // the canonical catalog. This catches typos and forward-references to draft
    // profiles before they ship.
    expect(fs.existsSync(CATALOG_PATH), `catalog exists at ${CATALOG_PATH}`).toBe(true);
    const catalog = JSON.parse(fs.readFileSync(CATALOG_PATH, "utf8")) as ConformanceCatalog;

    const knownProfiles = new Set<string>([
      ...(catalog.implementation_profiles ?? []),
      ...(catalog.profile_tiers?.v1_profile_catalog ?? []),
      ...(catalog.profile_tiers?.extension_profile_implementation ?? []),
    ]);
    expect(knownProfiles.size, "catalog known-profiles set is non-empty").toBeGreaterThan(0);

    const resp = await request.get(`${solandBaseUrl()}/api/v1/server/describe`);
    expect(resp.status()).toBe(200);
    const body = (await resp.json()) as DescribeResponse;

    const claimed = body.claimed_profiles ?? [];
    const claimedIds = claimed.map((e) => e.profile_id).filter(Boolean) as string[];
    expect(claimedIds.length, "soland declares at least one claimed profile").toBeGreaterThan(0);

    const orphans = claimedIds.filter((id) => !knownProfiles.has(id));
    expect(
      orphans,
      `claimed profile ids missing from catalog ${CATALOG_PATH}: ${JSON.stringify(orphans)}`,
    ).toEqual([]);

    // unsupported_profiles[] (e.g. cx.profile.soland_limited_server.v1) are limitation
    // descriptors, not conformance claims. They MUST NOT appear in claimed_profiles
    // and they MUST NOT be required to live in the catalog.
    const unsupported = body.unsupported_profiles ?? [];
    for (const u of unsupported) {
      expect(
        claimedIds.includes(u.profile ?? ""),
        `${u.profile} is in unsupported_profiles AND in claimed_profiles`,
      ).toBe(false);
    }

    await testInfo.attach("catalog-coverage", {
      body: JSON.stringify(
        {
          catalog_path: CATALOG_PATH,
          known_count: knownProfiles.size,
          claimed_ids: claimedIds,
          unsupported_ids: unsupported.map((u) => u.profile),
        },
        null,
        2,
      ),
      contentType: "application/json",
    });
  });

  test.fixme(
    // @blocking-on: soland#conformance-profile-gates-gap
    // @user-promise: e2e/scenarios/conformance/profile-gates.md
    // @expected-live-by: 2026Q3
    "Phase B — unsupported standard event kind submit MUST fail closed (no silent accept-and-drop)",
    async () => {
      // spec: conformance-profiles.md §2.1 (write receiver receiving an active standard
      //   Event kind outside its claimed_profiles MUST return unsupported_event_kind /
      //   unsupported_feature / schema_violation / quarantine);
      // artifact: conformance-profiles.json
      //   .default_unsupported_behavior.write_receiver_unknown_active_standard_kind
      //   .allowed_results.
      //
      // Steps:
      //   1) Pick an active standard kind in event-kind-registry.json that maps to a
      //      profile NOT in soland's claimed_profiles (candidate:
      //      cx.applet.transaction.v1 ↔ cx.profile.applet_service.v1).
      //   2) Register + dev-login alice via ensureRegistered + issueDevSession.
      //   3) POST /api/v1/events/submit { kind: <unsupported>, ...minimal payload... }
      //      with Bearer token.
      //   4) Assert: status 4xx; error.code ∈ {unsupported_event_kind,
      //      unsupported_feature, schema_violation}; body does NOT carry
      //      accepted:true / event_id.
      //   5) Compare alice's actor frontier (`GET .../actor/frontier?actor=<did>`)
      //      before and after — actor_seq MUST be strictly equal (no silent
      //      accept-and-drop).
      //
      // Blocked on: soland's event submit handler does not yet emit the canonical
      //   unsupported_event_kind code on profile-out-of-scope kinds; current path
      //   surfaces a generic schema_violation. Pin until the dedicated reject path
      //   lands (tracked under G3.S series).
    },
  );

  test.fixme(
    // @blocking-on: soland#conformance-profile-gates-gap
    // @user-promise: e2e/scenarios/conformance/profile-gates.md
    // @expected-live-by: 2026Q3
    "Phase C — event requiring an undeclared critical extension MUST fail closed",
    async () => {
      // spec: conformance-profiles.md §2.1 (requirements.critical_extensions[]
      //   unsupported → fail closed, priority OVER profile's "ignorable optional"
      //   allowance);
      // artifact: conformance-profiles.json
      //   .default_unsupported_behavior.unknown_required_feature_or_critical_extension
      //   .allowed_results = [unsupported_feature, schema_violation, soft_fail,
      //   quarantine].
      //
      // Steps:
      //   1) Build an event envelope whose requirements.critical_extensions[] points
      //      at an extension id that soland's claimed_profiles entries do NOT advertise
      //      (e.g. "cx.ext.audit_attestation.v1" on a soland that does not claim
      //      cx.profile.attested_audit.e2ee.v1).
      //   2) POST /api/v1/events/submit with the envelope.
      //   3) Assert one of:
      //      - submit fails closed with error.code in the allowed_results set;
      //      - OR describe response carries either a notes field on the relevant
      //        claimed_profiles entry, or an `unsupported_extensions[]` array, that
      //        explicitly disclaims the critical extension.
      //   4) Reject the hybrid state: silent submit acceptance combined with a
      //      reducer that depends on the unimplemented extension MUST NOT happen.
      //
      // Blocked on: soland envelope validator does not yet read
      //   requirements.critical_extensions[] against claimed_profiles. Pin until the
      //   validator path is wired (tracked under G3.S series).
    },
  );

  test.fixme(
    // @blocking-on: soland#conformance-profile-gates-gap
    // @user-promise: e2e/scenarios/conformance/profile-gates.md
    // @expected-live-by: 2026Q3
    "Phase A coauth — coauth self-claims auth_server only, not identity_registry/principal_server",
    async ({ request }) => {
      // spec: conformance-profiles.md §9a (auth_server profile);
      //       auth_server additional_requirements:
      //       - MUST NOT claim cx.profile.identity_registry.v1
      //       - MUST NOT claim cx.profile.principal_server.v1
      //       - verified_profiles is partitioned from self-claimed profiles.
      //
      // Steps:
      //   1) Skip if COTEST_COAUTH_BASE_URL not set (single-server topology).
      //   2) GET ${coauthBaseUrl()}/api/v1/server/describe.
      //   3) Assert claimed_profiles contains cx.profile.auth_server.v1 with
      //      claim_kind=self_claimed.
      //   4) Assert claimed_profiles does NOT contain cx.profile.identity_registry.v1
      //      or cx.profile.principal_server.v1.
      //   5) Assert every verified_profiles entry, if any, carries
      //      claim_kind=cotest_verified and does not overlap claimed_profiles.
      //
      // Blocked on: joint-e2e does not always boot coauth, and verified-profile
      //   artifacts are environment-dependent. Keep fixme until the coauth service
      //   is mandatory in this scenario's run profile.
      const baseUrl = coauthBaseUrl();
      test.skip(!baseUrl, "coauth not configured (COTEST_COAUTH_BASE_URL unset)");
      void request;
      void baseUrl;
    },
  );
});

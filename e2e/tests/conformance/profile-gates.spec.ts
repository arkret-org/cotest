// Conformance — Profile Claim Gates
// Contract: e2e/scenarios/conformance/profile-gates.md
// Spec: conformance/conformance-profiles.md §2 / §2.1 / §3 (profile tiers, fail-closed
//         on unsupported event kind, critical extension fail-closed),
//       sync/service-surface.md §3.0 (claim-level partition; dev-mode verified_profiles=[]).
// Catalog artifact: cokret-spec/spec/v1/artifacts/profiles/conformance-profiles.json
//
// soland gap: `soland/src/routing/system/describe.rs::apply_claim_level_partition`
//   already emits `claimed_profiles[]` (4 self_claimed entries) + `verified_profiles=[]`
//   (hard `Vec::new()` under dev mode, guarded by validate). Phase A / D / E run live
//   against this surface. Phase B (unsupported standard event kind reject) and Phase C
//   (critical extension fail-closed at submit time) now run live against soland's
//   submit reject path.
//
// coauth note: `coauth/crates/backend/src/handlers/cokret.rs` now self-claims
//   `ck.profile.auth_server.v1` and intentionally does NOT claim
//   `ck.profile.identity_registry.v1` / `ck.profile.principal_server.v1`. The
//   coauth-specific partition test runs live when COTEST_COAUTH_BASE_URL is
//   configured and skips cleanly in single-server topologies.
//
// The describe block is tagged @fully-implemented so these live tests run under
// the default `joint-smoke` profile.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import { signedEventEnvelope, wireErrCode } from "../../helpers/soland-api";

// ESM-friendly __dirname so `node --experimental-vm-modules` / Playwright's loader
// can resolve the spec artifact path regardless of cwd.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Repo-relative path from cotest/e2e/tests/conformance/ → cokret-spec/.
const CATALOG_PATH = path.resolve(
  __dirname,
  "../../../../cokret-spec/spec/v1/artifacts/profiles/conformance-profiles.json",
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
  artifact_digest?: string;
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
    // verified_profiles entries, if present, MUST carry cotest_run_id / artifact_digest /
    //   artifact_ref / cotest_issuer_did / signature / timestamp.
    // The two profile_id sets MUST be disjoint — a profile cannot be simultaneously
    // self-claimed and cotest-verified.
    const resp = await request.get(`${solandBaseUrl()}/_cokret/describe`);
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
      expect(entry.artifact_digest, "verified entry artifact_digest present").toBeTruthy();
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
    //   validate (`describe.rs::server_describe`).
    const resp = await request.get(`${solandBaseUrl()}/_cokret/describe`);
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

    const resp = await request.get(`${solandBaseUrl()}/_cokret/describe`);
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

  test("Phase B — unsupported standard event kind submit MUST fail closed (no silent accept-and-drop)", async ({
    request,
  }) => {
    const alice = uniqueUser("profile-gate-b");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const envelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId: "ck:realm:01904100-0000-7000-8000-000000000999",
      kind: "ck.applet.transaction",
      payload: { transaction_id: "ck:txn:profile-gate", params: {} },
    });

    const resp = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: { authorization: `Bearer ${token}` },
      data: envelope,
    });
    expect(resp.status()).toBeGreaterThanOrEqual(400);
    const body = await resp.json();
    expect([
      "unsupported_event_kind",
      "unsupported_feature",
      "schema_violation",
      "unknown_event_kind",
    ]).toContain(wireErrCode(body));
    expect(JSON.stringify(body)).not.toContain('"accepted"');
    expect(JSON.stringify(body)).not.toContain('"status":"accepted"');
  });

  test("Phase C — event requiring an undeclared critical extension MUST fail closed", async ({
    request,
  }) => {
    const alice = uniqueUser("profile-gate-c");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const envelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId: "ck:realm:01904100-0000-7000-8000-000000001000",
      kind: "ck.message.create",
      payload: {
        flow_id: "ck:flow:01904100-0000-7000-8000-000000001000",
        track_name: "discussion",
        content: { kind: "ck.content.text", body: "must not accept unknown critical extension" },
      },
    });
    (envelope.requirements as { critical_extensions: unknown[] }).critical_extensions = [
      {
        id: "cx.ext.audit_attestation.unimplemented.v1",
        fail_closed: true,
        extension_scope: "payload",
      },
    ];

    const resp = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: { authorization: `Bearer ${token}` },
      data: envelope,
    });
    expect(resp.status()).toBeGreaterThanOrEqual(400);
    const body = await resp.json();
    expect(["unsupported_feature", "schema_violation", "soft_fail", "quarantine"]).toContain(
      wireErrCode(body),
    );
    expect(JSON.stringify(body)).not.toContain('"status":"accepted"');
  });

  test("Phase A coauth — coauth self-claims auth_server only, not identity_registry/principal_server", async ({
    request,
  }) => {
    const baseUrl = coauthBaseUrl();
    test.skip(!baseUrl, "coauth not configured (COTEST_COAUTH_BASE_URL unset)");
    const resp = await request.get(`${baseUrl}/_cokret/describe`);
    expect(resp.status()).toBe(200);
    const body = (await resp.json()) as DescribeResponse;
    const claimed = body.claimed_profiles ?? [];
    const claimedIds = new Set(claimed.map((entry) => entry.profile_id).filter(Boolean));
    expect(claimedIds.has("ck.profile.auth_server.v1")).toBe(true);
    expect(claimedIds.has("ck.profile.identity_registry.v1")).toBe(false);
    expect(claimedIds.has("ck.profile.principal_server.v1")).toBe(false);
    for (const entry of claimed) {
      expect(entry.claim_kind).toBe("self_claimed");
    }
    for (const entry of body.verified_profiles ?? []) {
      expect(entry.claim_kind).toBe("cotest_verified");
      expect(claimedIds.has(entry.profile_id)).toBe(false);
    }
  });
});

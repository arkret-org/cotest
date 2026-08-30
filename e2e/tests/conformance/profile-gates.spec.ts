// Conformance — Profile Claim Gates
// Contract: e2e/scenarios/conformance/profile-gates.md
// Spec: conformance/conformance-profiles.md §2 / §2.1 / §3 (profile tiers, fail-closed
//         on unsupported event kind, critical extension fail-closed),
//       sync/service-surface.md §3.0 (claim-level partition; dev-mode verified_profiles=[]).
// Catalog artifact: arkret-spec/spec/v1/artifacts/profiles/conformance-profiles.json
//
// soland gap: `soland/src/routing/system/describe.rs::apply_claim_level_partition`
//   already emits `claimed_profiles[]` (4 self_claimed entries) + `verified_profiles=[]`
//   (hard `Vec::new()` under dev mode, guarded by validate). Phase A / D / E run live
//   against this surface. Phase B (unsupported standard event kind reject) and Phase C
//   (critical extension fail-closed at submit time) now run live against soland's
//   submit reject path.
//
// coauth is a private authentication process. It has no public Arkret service
// role, profile claim, or `/_arkret/describe` document.
//
// The describe block is tagged @fully-implemented so these live tests run under
// the default `joint-smoke` profile.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "../../helpers/arkret-test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import {
  refreshEventEnvelopeProof,
  signedEventEnvelope,
  wireErrCode,
} from "../../helpers/soland-api";

// ESM-friendly __dirname so `node --experimental-vm-modules` / Playwright's loader
// can resolve the spec artifact path regardless of cwd.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Repo-relative path from cotest/e2e/tests/conformance/ → arkret-spec/.
const CATALOG_PATH = path.resolve(
  __dirname,
  "../../../../arkret-spec/spec/v1/artifacts/profiles/conformance-profiles.json",
);

type ClaimedProfileEntry = {
  profile_id?: string;
  claim_kind?: string;
  notes?: string;
};

type VerifiedProfileEntry = {
  profile_id?: string;
  claim_kind?: string;
  verification_run_id?: string;
  artifact_digest?: string;
  artifact_ref?: string;
  verifier_did?: string;
  signature?: string;
  timestamp?: string;
  expires_at?: string;
};

type DescribeResponse = {
  development_mode?: boolean;
  claimed_profiles?: ClaimedProfileEntry[];
  verified_profiles?: VerifiedProfileEntry[];
  unsupported_profiles?: Array<{ profile?: string; status?: string }>;
};

type ConformanceCatalog = {
  implementation_profiles?: string[];
  // hardening_profiles[] is a first-class array of opt-in security-hardening
  // profile ids in the authoritative conformance-profiles.json matrix
  // (conformance-profiles.md §2.1: the json is the full matrix; the markdown
  // is a non-exhaustive view). They are independently advertisable in
  // /_arkret/describe.claimed_profiles — e.g. crypto-media/encryption-and-audit.md
  // §2.5 requires a Station federating MLS-backed Realms to advertise
  // ak.profile.mls_governance_binding.full.v1.
  hardening_profiles?: string[];
  candidate_profiles?: string[];
  profile_sets?: {
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
    // verified_profiles entries, if present, MUST carry verification_run_id / artifact_digest /
    //   artifact_ref / verifier_did / signature / timestamp.
    // The two profile_id sets MUST be disjoint — a profile cannot be simultaneously
    // self-claimed and cotest-verified.
    const resp = await request.get(`${solandBaseUrl()}/_arkret/describe`);
    expect(resp.status()).toBe(200);
    const body = (await resp.json()) as DescribeResponse;

    expect(Array.isArray(body.claimed_profiles), "claimed_profiles is an array").toBe(true);
    expect(Array.isArray(body.verified_profiles), "verified_profiles is an array").toBe(true);

    const claimed = body.claimed_profiles ?? [];
    const verified = body.verified_profiles ?? [];

    expect(claimed.length, "soland claims at least the v1 floor + Station").toBeGreaterThan(
      0,
    );

    for (const entry of claimed) {
      expect(typeof entry.profile_id, "claimed entry profile_id is string").toBe("string");
      expect(entry.profile_id, "claimed entry profile_id is non-empty").toBeTruthy();
      expect(entry.claim_kind, "claimed entry claim_kind === self_claimed").toBe("self_claimed");
    }

    for (const entry of verified) {
      expect(entry.profile_id, "verified entry profile_id present").toBeTruthy();
      expect(entry.claim_kind, "verified entry claim_kind").toBe("conformance_verified");
      expect(entry.verification_run_id, "verified entry verification_run_id present").toBeTruthy();
      expect(entry.artifact_digest, "verified entry artifact_digest present").toBeTruthy();
      expect(entry.artifact_ref, "verified entry artifact_ref present").toBeTruthy();
      expect(entry.verifier_did, "verified entry verifier_did present").toBeTruthy();
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
    const resp = await request.get(`${solandBaseUrl()}/_arkret/describe`);
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
    //       profile_sets.v1_profile_catalog ∪ profile_sets.extension_profile_implementation
    //       ∪ hardening_profiles).
    //
    // Every entry in soland's claimed_profiles MUST resolve to a profile id known by
    // the canonical catalog. This catches typos and forward-references to draft
    // profiles before they ship. hardening_profiles[] is included because opt-in
    // hardening profiles are independently advertisable in claimed_profiles (e.g.
    // ak.profile.mls_governance_binding.full.v1, the cross-deployment E2EE MLS
    // federation interop floor — crypto-media/encryption-and-audit.md §2.5).
    expect(fs.existsSync(CATALOG_PATH), `catalog exists at ${CATALOG_PATH}`).toBe(true);
    const catalog = JSON.parse(fs.readFileSync(CATALOG_PATH, "utf8")) as ConformanceCatalog;

    const knownProfiles = new Set<string>([
      ...(catalog.implementation_profiles ?? []),
      ...(catalog.profile_sets?.v1_profile_catalog ?? []),
      ...(catalog.profile_sets?.extension_profile_implementation ?? []),
      ...(catalog.hardening_profiles ?? []),
      ...(catalog.candidate_profiles ?? []),
    ]);
    expect(knownProfiles.size, "catalog known-profiles set is non-empty").toBeGreaterThan(0);

    const resp = await request.get(`${solandBaseUrl()}/_arkret/describe`);
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

    // unsupported_profiles[] (e.g. ak.profile.soland_limited_server.v1) are limitation
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
      actorId: alice.id,
      realmId: "ak:realm:AY0rSzrDAC1zeYgGHFxVjALohUeclZwWr9eDkFlNy2df",
      kind: "ak.edge.applet.command.transaction.v1",
      // `ak:transaction:` is the canonical typed ID prefix. The abbreviated
      // `ak:txn:` is a `hard_reject` entry in
      // artifacts/registry/forbidden-wire-fields.json, so using it here made
      // the payload independently invalid and let this gate pass on the wrong
      // rejection reason.
      payload: {
        transaction_id: "ak:transaction:01904100-0000-7000-8000-00000000f001",
        params: {},
      },
    });

    const resp = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
      headers: { authorization: `Bearer ${token}` },
      data: envelope,
    });
    expect(resp.status()).toBeGreaterThanOrEqual(400);
    const body = await resp.json();
    // conformance-profiles.md §2.1 permits schema_violation when an active
    // standard kind is outside the receiver's supported registry/profile.
    // The invariant here is fail-closed with no accepted Event.
    expect([
      "schema_violation",
      "unsupported_event_kind",
      "unsupported_feature",
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
      actorId: alice.id,
      realmId: "ak:realm:AVAS1PeoJLynuHDRgmf-2LvFQSeNYWxMtub5zKMmPWtI",
      kind: "ak.message.create",
      payload: {
        strand_id: "ak:strand:AdGCQqzuG2c1_NhzvkJ6aU8RcePRF6KHFaD0ObxpalrU",
        track_name: "discussion",
        content: { kind: "ak.content.text", body: "must not accept unknown critical extension" },
      },
    });
    (envelope.requirements as { critical_extensions: unknown[] }).critical_extensions = [
      {
        id: "ak.ext.audit_attestation.unimplemented.v1",
        fail_closed: true,
        extension_scope: "payload",
      },
    ];
    refreshEventEnvelopeProof(envelope);

    const resp = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
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

  test("Phase A coauth — private authentication process exposes no public describe", async ({
    request,
  }) => {
    const baseUrl = coauthBaseUrl();
    test.skip(!baseUrl, "coauth not configured (COTEST_COAUTH_BASE_URL unset)");
    const resp = await request.get(`${baseUrl}/_arkret/describe`);
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });
});

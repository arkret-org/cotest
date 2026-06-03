// Sync — Service Surface Contract (describe / errors / pagination / idempotency)
// Contract: e2e/scenarios/sync/service-surface-contract.md
// Spec: sync/service-surface.md §3, §3.0, §17 (canonical ServiceDescribe + claim-level partition)
//       sync/api-conventions.md §4 (success envelope), §5/§5.1/§5.2 (error envelope, unknown path,
//                                   method_not_allowed, unsupported_feature),
//                                §6 (idempotency), §7/§7.1 (opaque cursor + list pagination),
//                                §11 (feature discovery)
//       sync/service-api-schema.mdx §2 (canonical ServiceDescribe required fields)
//
// Both soland (`soland/src/routing/system/describe.rs` + `soland/src/wire.rs`) and coauth
// (`coauth/crates/backend/src/handlers/cokret.rs::server_describe`) already serve
// `GET /api/v1/server/describe` with the claim-level partition layer in place, so the two
// describe probes are LIVE today. Phase B (error envelope) is also live on
// soland. Phases C (pagination cursor), D (idempotency key) and E
// (unsupported_feature fail-closed) stay pinned via test.fixme until the
// matching wire paths are tightened end-to-end.
//
// Only the describe describe-block is tagged @fully-implemented — that's the slice safe to
// run under joint-smoke. The untagged service-surface block carries Phase B plus the
// remaining fixme placeholders, so the extra live probe does not broaden PR-level gating.

import { expect, test, type APIRequestContext } from "@playwright/test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type ErrorEnvelope = {
  ok?: boolean;
  error?: {
    code?: string;
    message?: string;
  };
  request_id?: string;
};

async function expectCanonicalSolandErrorEnvelope(request: APIRequestContext) {
  const unknown = await request.get(
    `${solandBaseUrl()}/api/v1/__definitely_does_not_exist__/probe`,
  );
  expect(unknown.status(), "unknown API path status").toBe(404);
  expect(unknown.headers()["content-type"] ?? "", "unknown path content-type").toContain(
    "application/json",
  );
  const unknownBody = (await unknown.json()) as ErrorEnvelope;
  expect(unknownBody).toMatchObject({
    ok: false,
    error: { code: "unrecognized_endpoint" },
  });
  expect(unknownBody.error?.message, "unknown path error message").toBeTruthy();
  expect(unknownBody.request_id, "unknown path request_id").toMatch(/^ck:[a-z_]+:/);

  const wrongMethod = await request.post(`${solandBaseUrl()}/api/v1/server/describe`);
  expect(wrongMethod.status(), "known path wrong method status").toBe(405);
  expect(wrongMethod.headers()["content-type"] ?? "", "wrong method content-type").toContain(
    "application/json",
  );
  expect(wrongMethod.headers()["allow"] ?? "", "wrong method Allow header").toContain("GET");
  const wrongMethodBody = (await wrongMethod.json()) as ErrorEnvelope;
  expect(wrongMethodBody).toMatchObject({
    ok: false,
    error: { code: "method_not_allowed" },
  });
  expect(wrongMethodBody.error?.message, "wrong method error message").toBeTruthy();
  expect(wrongMethodBody.request_id, "wrong method request_id").toMatch(/^ck:[a-z_]+:/);
}

// ---------- LIVE: describe-endpoint probes (soland + coauth) ----------

test.describe("describes soland surface @fully-implemented", () => {
  test("soland /api/v1/server/describe returns canonical ServiceDescribe shape", async ({
    request,
  }, testInfo) => {
    // spec: service-surface.md §3 (canonical shape), §3.0 (claim-level partition),
    //       §17 (line-level interop required fields); service-api-schema.mdx §2.
    //
    // Asserts the §17 must-have fields are present, that the §3.0 six claim-level
    // fields (implemented_features / claimed_profiles / verified_profiles /
    // experimental_features / compat_surfaces + development_mode) are partitioned
    // correctly, and that dev-mode posture forces verified_profiles == [].
    const resp = await request.get(`${solandBaseUrl()}/api/v1/server/describe`);
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"] ?? "").toContain("application/json");
    const body = await resp.json();

    // §17 — canonical ServiceDescribe required fields
    expect(body.service_did, "service_did").toBeTruthy();
    expect(body.trust_domain, "trust_domain").toMatch(/^ck:trust_domain:/);
    expect(body.service_type, "service_type").toBe("principal_server");
    expect(body.protocol_version, "protocol_version").toBe("1.0");
    expect(Array.isArray(body.supported_profiles), "supported_profiles is array").toBe(true);
    expect(Array.isArray(body.supported_operations), "supported_operations is array").toBe(true);
    expect(Array.isArray(body.supported_bindings), "supported_bindings is array").toBe(true);
    expect(body.supported_bindings.length, "≥1 binding").toBeGreaterThanOrEqual(1);
    expect(body.supported_bindings[0].kind, "http_json binding").toBe("http_json");
    expect(Array.isArray(body.supported_features), "supported_features is array").toBe(true);
    expect(body.auth_metadata, "auth_metadata present").toBeTruthy();
    expect(body.limits, "limits present").toBeTruthy();
    expect(body.plaintext_visibility, "plaintext_visibility present").toBeTruthy();
    expect(typeof body.development_mode, "development_mode boolean").toBe("boolean");

    // §3.0 — claim-level partition
    expect(Array.isArray(body.implemented_features), "implemented_features array").toBe(true);
    expect(Array.isArray(body.claimed_profiles), "claimed_profiles array").toBe(true);
    expect(Array.isArray(body.verified_profiles), "verified_profiles array").toBe(true);
    expect(Array.isArray(body.experimental_features), "experimental_features array").toBe(true);
    expect(Array.isArray(body.compat_surfaces), "compat_surfaces array").toBe(true);

    // §3.0 — self-claim has claim_kind === "self_claimed"; cotest_verified MUST live
    // only under verified_profiles, never copied into claimed_profiles.
    for (const entry of body.claimed_profiles as Array<{ claim_kind?: string }>) {
      expect(entry.claim_kind, "claimed_profiles[*].claim_kind").toBe("self_claimed");
    }

    // §3.0 — when development_mode=true, verified_profiles MUST be empty.
    if (body.development_mode === true) {
      expect(body.verified_profiles, "dev-mode verified_profiles is empty").toEqual([]);
    }

    // §4.2 + service-api-schema.mdx §2.1 — every principal server must surface
    // at least cx.server.describe + cx.events.submit on supported_operations.
    expect(body.supported_operations, "exposes cx.server.describe").toContain("cx.server.describe");
    expect(body.supported_operations, "exposes cx.events.submit").toContain("cx.events.submit");

    await testInfo.attach("soland-describe", {
      body: JSON.stringify(body, null, 2),
      contentType: "application/json",
    });
  });
});

test.describe("describes coauth surface @fully-implemented", () => {
  test("coauth /api/v1/server/describe returns auth_server shape and does not claim identity_registry", async ({
    request,
  }, testInfo) => {
    // spec: service-surface.md §3 (service_type naming — auth_server),
    //       G3.C3 (coauth MUST NOT claim canonical identity_registry profile).
    //
    // coauthBaseUrl() returns undefined when COTEST_COAUTH_BASE_URL is not configured
    // (single-server / soland-only profiles). Skip rather than fail in that case.
    const baseUrl = coauthBaseUrl();
    test.skip(!baseUrl, "coauth not configured (COTEST_COAUTH_BASE_URL unset)");

    const resp = await request.get(`${baseUrl}/api/v1/server/describe`);
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"] ?? "").toContain("application/json");
    const body = await resp.json();

    // §3 — service_type registered values
    expect(body.service_type, "service_type").toBe("auth_server");
    expect(body.protocol_version, "protocol_version").toBe("1.0");

    // §3.0 — six claim-level fields present
    expect(Array.isArray(body.implemented_features)).toBe(true);
    expect(Array.isArray(body.claimed_profiles)).toBe(true);
    expect(Array.isArray(body.verified_profiles)).toBe(true);
    expect(Array.isArray(body.experimental_features)).toBe(true);
    expect(Array.isArray(body.compat_surfaces)).toBe(true);
    expect(typeof body.development_mode).toBe("boolean");

    // G3.C3 — coauth MUST NOT claim canonical identity registry profile.
    const claimed = (body.claimed_profiles ?? []) as Array<{ profile_id?: string }>;
    const claimedIds = claimed.map((c) => c.profile_id).filter(Boolean);
    expect(claimedIds, "coauth does not self-claim identity_registry").not.toContain(
      "cx.profile.identity_registry.v1",
    );
    expect(claimedIds, "coauth does not self-claim principal_server").not.toContain(
      "cx.profile.principal_server.v1",
    );

    // auth_metadata should expose at least one of oauth_issuer / supported_auth_methods.
    expect(body.auth_metadata, "auth_metadata present").toBeTruthy();
    const hasOauthIssuer = typeof body.auth_metadata?.oauth_issuer === "string";
    const hasAuthMethods =
      Array.isArray(body.auth_metadata?.supported_auth_methods) &&
      body.auth_metadata.supported_auth_methods.length > 0;
    expect(hasOauthIssuer || hasAuthMethods, "auth metadata advertises issuer or methods").toBe(
      true,
    );

    // §3.0 dev-mode invariant also applies to coauth.
    if (body.development_mode === true) {
      expect(body.verified_profiles, "dev-mode verified_profiles is empty").toEqual([]);
    }

    await testInfo.attach("coauth-describe", {
      body: JSON.stringify(body, null, 2),
      contentType: "application/json",
    });
  });
});

// ---------- Mixed: live error-envelope probe plus remaining fixme phases ----------

test.describe("service surface contract — error envelope, pagination, idempotency, fail-closed", () => {
  test.fixme(
    // @blocking-on: soland#sync-service-surface-contract-gap
    // @user-promise: e2e/scenarios/sync/service-surface-contract.md
    // @expected-live-by: 2026Q3
    "Phase A.E1: claim_kind partition does not leak between claimed_profiles and verified_profiles",
    async () => {
      // spec: service-surface.md §3.0 (claim levels), §17 (line-level interop required).
      //
      // For each entry in verified_profiles: claim_kind === "cotest_verified" AND
      //   entry has non-empty cotest_run_id + artifact_digest + artifact_ref +
      //   cotest_issuer_did + signature + timestamp.
      // For each entry in claimed_profiles: claim_kind === "self_claimed" AND
      //   the same profile_id MUST NOT also appear in verified_profiles unless
      //   the verified entry was produced by an out-of-band cotest run (then
      //   verified copy wins; self-claim copy MUST be dropped).
      //
      // Blocked on: G4.T3 verified-profile write path. Until cotest produces real
      // verified-profile artifacts, both arrays are observable but only the
      // self_claimed side carries data — partition correctness can't be exercised
      // end-to-end yet.
    },
  );

  test(
    "Phase B: unknown path returns 404 unrecognized_endpoint with standard error envelope",
    async ({ request }) => {
      // spec: api-conventions.md §5 (standard error envelope —
      //         { ok: false, error: { code, message, retry_after_ms?, details? }, request_id }),
      //       §5.2 (404 unrecognized_endpoint, MUST NOT return HTML / stack /
      //         framework error, MUST terminate at routing layer with no side effects).
      await expectCanonicalSolandErrorEnvelope(request);
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-service-surface-contract-gap
    // @user-promise: e2e/scenarios/sync/service-surface-contract.md
    // @expected-live-by: 2026Q3
    "Phase C: list endpoint pagination cursor is opaque, gap-free, and non-overlapping across pages",
    async () => {
      // spec: api-conventions.md §7 (cursor opaque; wire form `ck:cursor:<base64url>`;
      //         invalid → invalid_param; expired → cursor_expired; TTL ≤ 7d for stream cursors),
      //       §7.1 (list pagination response: { items, next_cursor, has_more }).
      //
      // 1) Seed ≥5 list-visible items as alice (via POST /api/v1/events or seed helper).
      // 2) GET /api/v1/events?limit=2 (or whichever list endpoint reaches
      //    §7.1 shape first) → page1.
      //    Assert: items.length <= 2, next_cursor matches /^ck:cursor:[A-Za-z0-9_-]+$/,
      //            has_more === true.
      // 3) Follow next_cursor through page2 + page3.
      //    Assert: union(pageN.items.ids) covers seeded ids (no gap);
      //            pairwise intersection is empty (no overlap);
      //            Buffer.from(cursor.slice("ck:cursor:".length), "base64url").toString("utf8")
      //              does NOT contain any seeded item id (cursor opacity).
      // 4) Tamper next_cursor by flipping one char → POST again.
      //    Assert: status 4xx, error.code ∈ {"invalid_param", "cursor_expired"}.
      //
      // Blocked on: §7.1 wire shape is not yet uniformly applied to list endpoints
      // in soland; current /authz/invites etc. don't all emit `{items, next_cursor,
      // has_more}` with `ck:cursor:` token form. Pin until at least one list
      // endpoint matches the spec shape exactly.
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-service-surface-contract-gap
    // @user-promise: e2e/scenarios/sync/service-surface-contract.md
    // @expected-live-by: 2026Q3
    "Phase D: Idempotency-Key replay returns the cached first response; same key + different body returns duplicate_conflict",
    async ({ request }) => {
      // spec: api-conventions.md §6 (idempotency —
      //         same key + same canonical body → semantically equivalent result;
      //         same key + different canonical body → duplicate_conflict;
      //         server SHOULD persist idempotency mapping at least until the
      //         related Event is fully synced or expired).
      //
      // 1) ensureRegistered + issueDevSession for alice on soland.
      // 2) Build a minimal write body B1 (POST /api/v1/events envelope or
      //    equivalent write endpoint that accepts Idempotency-Key).
      // 3) POST with header { Idempotency-Key: `ssc-${randomUUID()}` } + body B1 → R1.
      //    Assert: status 2xx, response carries event_id / request_id / accepted state.
      // 4) Repeat with SAME Idempotency-Key + SAME canonical B1 → R2.
      //    Assert: R2.event_id === R1.event_id (no new event created); R2
      //            mirrors R1's accepted state.
      // 5) POST with SAME Idempotency-Key but a body B2 that differs in one field → R3.
      //    Assert: status 409, error.code === "duplicate_conflict".
      // 6) Side-effect probe: query frontier or list endpoint; the event count
      //    delta from step 3 to step 5 MUST be exactly 1.
      //
      // Blocked on: soland currently relies on event_id idempotency for /events;
      // a generic `Idempotency-Key` header path across non-event writes is not
      // uniformly wired. Pin until §6 header path is honoured end-to-end.
      const stamp = Date.now();
      const alice = uniqueUser(`ssc-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const _token = await issueDevSession(request, alice);
      void _token;
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-service-surface-contract-gap
    // @user-promise: e2e/scenarios/sync/service-surface-contract.md
    // @expected-live-by: 2026Q3
    "Phase E: event requiring an undeclared feature is rejected with unsupported_feature (fail-closed)",
    async () => {
      // spec: api-conventions.md §5.1 (unsupported_feature is reserved for
      //         Event.requirements.features[] / requirements.critical_extensions[]
      //         pointing at a feature this implementation has NOT advertised;
      //         MUST NOT be substituted with unsupported_event_kind or
      //         generic schema_violation),
      //       service-surface.md §2.4 (services must publish supported_features).
      //
      // 1) Pull soland's describe (re-use Phase A); compute pickFeature =
      //    a feature id that is in NEITHER supported_features NOR implemented_features
      //    (e.g. "cx.feature.mimi_room_passthrough.v1" on default dev soland).
      // 2) POST /api/v1/events with envelope:
      //      { ..., requirements: { features: [pickFeature], critical_extensions: [] }, ... }
      // 3) Assert: status 4xx (likely 422 or 400),
      //            error.code === "unsupported_feature",
      //            error.code !== "unsupported_event_kind",
      //            error.code !== "schema_violation".
      // 4) Verify the event did NOT land: poll frontier / events list and confirm
      //    no event with that envelope id is observable.
      //
      // Blocked on: soland's envelope validator currently surfaces feature gaps
      // through a mix of codes (schema_violation / capability_denied); §5.1
      // demands the specific `unsupported_feature` code. Pin until validator
      // emits the canonical code on the features[] gap.
    },
  );
});

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
// (`coauth/crates/backend/src/handlers/arkret.rs::server_describe`) already serve
// `GET /_arkret/describe` with the claim-level partition layer in place, so the two
// describe probes are LIVE today. Phase A.E1 (claim_kind partition), Phase B
// (error envelope), Phase E (unsupported_feature fail-closed), Phase C (opaque
// list-pagination cursor on `ak.self.events.query.scan`) and Phase D (generic
// `Idempotency-Key` header path on POST /_arkret/self/events) are all live on
// soland.
//
// Only the describe describe-block is tagged @fully-implemented — that's the slice safe to
// run under joint-smoke. The untagged service-surface block carries the broader
// Phases A.E1/B/C/D/E probes, so the extra live probes do not broaden PR-level
// gating.

import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  createRealmViaApi,
  listRealmEventsViaApi,
} from "../../helpers/api";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  alignSignedEventToActorFrontierApi,
  authHeaders,
  refreshEventEnvelopeProof,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
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
    `${solandBaseUrl()}/_arkret/self/__definitely_does_not_exist__/probe`,
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
  expect(unknownBody.request_id, "unknown path request_id").toMatch(/^ak:[a-z_]+:/);

  const wrongMethod = await request.post(`${solandBaseUrl()}/_arkret/describe`);
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
  expect(wrongMethodBody.request_id, "wrong method request_id").toMatch(/^ak:[a-z_]+:/);
}

function submittedEventId(body: unknown): string | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const record = body as Record<string, unknown>;
  if (typeof record.event_id === "string") {
    return record.event_id;
  }
  for (const key of ["accepted", "duplicate"]) {
    const values = record[key];
    if (Array.isArray(values) && typeof values[0] === "string") {
      return values[0];
    }
  }
  return undefined;
}

function submittedEventOutcome(
  body: unknown,
  eventId: string,
): "accepted" | "duplicate" | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const record = body as Record<string, unknown>;
  if (record.status === "accepted" || record.status === "duplicate") {
    return record.status;
  }
  if (Array.isArray(record.duplicate) && record.duplicate.includes(eventId)) {
    return "duplicate";
  }
  if (Array.isArray(record.accepted) && record.accepted.includes(eventId)) {
    return "accepted";
  }
  return undefined;
}

async function startSharedDescribeBinding(
  descriptions: Readonly<Record<string, Record<string, unknown>>>,
): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    const requestUrl = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method !== "GET" || requestUrl.pathname !== "/_arkret/describe") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          ok: false,
          error: {
            code: "unrecognized_endpoint",
            message: "only the shared describe binding is exposed by this fixture",
          },
          request_id: `ak:request:${randomUUID()}`,
        }),
      );
      return;
    }

    const serviceKind = requestUrl.searchParams.get("service_kind");
    const description = serviceKind ? descriptions[serviceKind] : undefined;
    if (!description) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          ok: false,
          error: {
            code: "invalid_param",
            message: serviceKind
              ? `service_kind ${JSON.stringify(serviceKind)} is not available on this binding`
              : "service_kind is required when multiple roles share this binding",
          },
          request_id: `ak:request:${randomUUID()}`,
        }),
      );
      return;
    }

    res.writeHead(200, {
      "cache-control": "no-store",
      "content-type": "application/json",
    });
    res.end(JSON.stringify(description));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

// ---------- LIVE: describe-endpoint probes (soland + coauth) ----------

test.describe("describes soland surface @fully-implemented", () => {
  test("soland /_arkret/describe returns canonical ServiceDescribe shape", async ({
    request,
  }, testInfo) => {
    // spec: service-surface.md §3 (canonical shape), §3.0 (claim-level partition),
    //       §17 (line-level interop required fields); service-api-schema.mdx §2.
    //
    // Asserts the §17 must-have fields are present, that the §3.0 six claim-level
    // fields (implemented_features / claimed_profiles / verified_profiles /
    // experimental_features / compat_surfaces + development_mode) are partitioned
    // correctly, and that dev-mode posture forces verified_profiles == [].
    const resp = await request.get(`${solandBaseUrl()}/_arkret/describe`);
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"] ?? "").toContain("application/json");
    const body = await resp.json();

    // §17 — canonical ServiceDescribe required fields
    expect(body.service_id, "service_id").toBeTruthy();
    expect(body.trust_domain, "trust_domain").toMatch(/^ak:trust_domain:/);
    expect(body.service_kind, "service_kind").toBe("principal_server");
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

    // §3.0 — self-claim has claim_kind === "self_claimed"; conformance_verified MUST live
    // only under verified_profiles, never copied into claimed_profiles.
    for (const entry of body.claimed_profiles as Array<{ claim_kind?: string }>) {
      expect(entry.claim_kind, "claimed_profiles[*].claim_kind").toBe("self_claimed");
    }

    // §3.0 — when development_mode=true, verified_profiles MUST be empty.
    if (body.development_mode === true) {
      expect(body.verified_profiles, "dev-mode verified_profiles is empty").toEqual([]);
    }

    // §4.2 + service-api-schema.mdx §2.1 — every principal server must surface
    // at least ak.server.query.describe + ak.self.events.command.submit on supported_operations.
    expect(body.supported_operations, "exposes ak.server.query.describe").toContain("ak.server.query.describe");
    expect(body.supported_operations, "exposes ak.self.events.command.submit").toContain("ak.self.events.command.submit");

    await testInfo.attach("soland-describe", {
      body: JSON.stringify(body, null, 2),
      contentType: "application/json",
    });
  });

  test("soland describe accepts only its registered role selector", async ({
    request,
  }) => {
    const selected = await request.get(
      `${solandBaseUrl()}/_arkret/describe?service_kind=principal_server`,
    );
    expect(selected.status()).toBe(200);
    expect((await selected.json()).service_kind).toBe("principal_server");

    const rejected = await request.get(
      `${solandBaseUrl()}/_arkret/describe?service_kind=auth_server`,
    );
    expect(rejected.status()).toBe(400);
    expect(wireErrCode(await rejected.json())).toBe("invalid_param");
  });
});

test.describe("describes coauth surface @fully-implemented", () => {
  test("coauth /_arkret/describe returns auth_server shape and does not claim identity_registry", async ({
    request,
  }, testInfo) => {
    // spec: service-surface.md §3 (service_kind naming — auth_server),
    //       G3.C3 (coauth MUST NOT claim canonical identity_registry profile).
    //
    // coauthBaseUrl() returns undefined when COTEST_COAUTH_BASE_URL is not configured
    // (single-server / soland-only profiles). Skip rather than fail in that case.
    const baseUrl = coauthBaseUrl();
    test.skip(!baseUrl, "coauth not configured (COTEST_COAUTH_BASE_URL unset)");

    const resp = await request.get(`${baseUrl}/_arkret/describe`);
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"] ?? "").toContain("application/json");
    const body = await resp.json();

    // §3 — service_kind registered values
    expect(body.service_kind, "service_kind").toBe("auth_server");
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
      "ak.profile.identity_registry.v1",
    );
    expect(claimedIds, "coauth does not self-claim principal_server").not.toContain(
      "ak.profile.principal_server.v1",
    );

    // auth_metadata routes account flows through Account Authority; methods only
    // describe login proof providers.
    expect(body.auth_metadata, "auth_metadata present").toBeTruthy();
    expect(
      body.auth_metadata?.account_authority?.gate_account_base,
      "auth metadata advertises account authority",
    ).toMatch(/^https?:\/\//);
    expect(Array.isArray(body.auth_metadata?.methods), "auth metadata advertises methods[]").toBe(
      true,
    );
    expect(body.auth_metadata.methods.length, "auth metadata methods[] is non-empty").toBeGreaterThan(0);

    // §3.0 dev-mode invariant also applies to coauth.
    if (body.development_mode === true) {
      expect(body.verified_profiles, "dev-mode verified_profiles is empty").toEqual([]);
    }

    await testInfo.attach("coauth-describe", {
      body: JSON.stringify(body, null, 2),
      contentType: "application/json",
    });
  });

  test("coauth describe accepts only its registered role selector", async ({
    request,
  }) => {
    const baseUrl = coauthBaseUrl();
    test.skip(!baseUrl, "coauth not configured (COTEST_COAUTH_BASE_URL unset)");

    const selected = await request.get(
      `${baseUrl}/_arkret/describe?service_kind=auth_server`,
    );
    expect(selected.status()).toBe(200);
    expect((await selected.json()).service_kind).toBe("auth_server");

    const rejected = await request.get(
      `${baseUrl}/_arkret/describe?service_kind=principal_server`,
    );
    expect(rejected.status()).toBe(400);
    expect(wireErrCode(await rejected.json())).toBe("invalid_param");
  });
});

test.describe("shared public describe binding @fully-implemented", () => {
  test("requires a registered role and returns the selected role's closed describe", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not configured (COTEST_COAUTH_BASE_URL unset)");
    if (!coauth) {
      return;
    }

    const [principalResponse, authResponse] = await Promise.all([
      request.get(
        `${solandBaseUrl()}/_arkret/describe?service_kind=principal_server`,
      ),
      request.get(`${coauth}/_arkret/describe?service_kind=auth_server`),
    ]);
    expect(principalResponse.status()).toBe(200);
    expect(authResponse.status()).toBe(200);
    const principal = (await principalResponse.json()) as Record<string, unknown>;
    const auth = (await authResponse.json()) as Record<string, unknown>;

    const shared = await startSharedDescribeBinding({
      principal_server: principal,
      auth_server: auth,
    });
    try {
      const missing = await request.get(`${shared.baseUrl}/_arkret/describe`);
      expect(missing.status()).toBe(400);
      expect(wireErrCode(await missing.json())).toBe("invalid_param");

      const invalid = await request.get(
        `${shared.baseUrl}/_arkret/describe?service_kind=directory_service`,
      );
      expect(invalid.status()).toBe(400);
      expect(wireErrCode(await invalid.json())).toBe("invalid_param");

      const selectedPrincipal = await request.get(
        `${shared.baseUrl}/_arkret/describe?service_kind=principal_server`,
      );
      const selectedAuth = await request.get(
        `${shared.baseUrl}/_arkret/describe?service_kind=auth_server`,
      );
      expect(selectedPrincipal.status()).toBe(200);
      expect(selectedAuth.status()).toBe(200);
      const selectedPrincipalBody =
        (await selectedPrincipal.json()) as Record<string, unknown>;
      const selectedAuthBody =
        (await selectedAuth.json()) as Record<string, unknown>;

      // The shared discovery binding selects complete role descriptions; it
      // does not aggregate operation/profile/plaintext boundaries or rewrite
      // either role's DID and advertised service bindings.
      expect(selectedPrincipalBody).toEqual(principal);
      expect(selectedAuthBody).toEqual(auth);
      expect(selectedPrincipalBody.service_kind).toBe("principal_server");
      expect(selectedAuthBody.service_kind).toBe("auth_server");
      expect(selectedPrincipalBody.service_id).not.toBe(selectedAuthBody.service_id);
      expect(selectedPrincipalBody.supported_operations).not.toEqual(
        selectedAuthBody.supported_operations,
      );
      expect(selectedPrincipalBody.claimed_profiles).not.toEqual(
        selectedAuthBody.claimed_profiles,
      );
      expect(selectedPrincipalBody.plaintext_visibility).not.toEqual(
        selectedAuthBody.plaintext_visibility,
      );
    } finally {
      await shared.close();
    }
  });
});

// ---------- Mixed: broader live service-surface probes ----------

test.describe("service surface contract — error envelope, pagination, idempotency, fail-closed", () => {
  test(
    "Phase A.E1: claim_kind partition does not leak between claimed_profiles and verified_profiles",
    async ({ request }, testInfo) => {
      type ProfileClaim = {
        profile_id?: unknown;
        claim_kind?: unknown;
        verification_run_id?: unknown;
        artifact_digest?: unknown;
        artifact_ref?: unknown;
        verifier_did?: unknown;
        signature?: unknown;
        timestamp?: unknown;
      };
      const resp = await request.get(`${solandBaseUrl()}/_arkret/describe`);
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      const claimed = (body.claimed_profiles ?? []) as ProfileClaim[];
      const verified = (body.verified_profiles ?? []) as ProfileClaim[];

      expect(Array.isArray(claimed), "claimed_profiles is array").toBe(true);
      expect(Array.isArray(verified), "verified_profiles is array").toBe(true);

      const claimedIds = new Set<string>();
      for (const entry of claimed) {
        expect(typeof entry.profile_id, "claimed profile_id").toBe("string");
        const profileId = entry.profile_id as string;
        expect(profileId, "claimed profile_id is non-empty").not.toBe("");
        expect(entry.claim_kind, `claimed ${profileId} claim_kind`).toBe("self_claimed");
        expect(entry.claim_kind, `claimed ${profileId} must not be conformance_verified`).not.toBe(
          "conformance_verified",
        );
        expect(claimedIds.has(profileId), `claimed ${profileId} appears once`).toBe(false);
        claimedIds.add(profileId);
      }

      const verifiedIds = new Set<string>();
      for (const entry of verified) {
        expect(typeof entry.profile_id, "verified profile_id").toBe("string");
        const profileId = entry.profile_id as string;
        expect(profileId, "verified profile_id is non-empty").not.toBe("");
        expect(entry.claim_kind, `verified ${profileId} claim_kind`).toBe("conformance_verified");
        for (const field of [
          "verification_run_id",
          "artifact_digest",
          "artifact_ref",
          "verifier_did",
          "signature",
          "timestamp",
        ] as const) {
          expect(entry[field], `verified ${profileId} ${field}`).toBeTruthy();
        }
        expect(verifiedIds.has(profileId), `verified ${profileId} appears once`).toBe(false);
        verifiedIds.add(profileId);
        expect(
          claimedIds.has(profileId),
          `${profileId} must not appear in both claimed_profiles and verified_profiles`,
        ).toBe(false);
      }

      if (body.development_mode === true) {
        expect(verified, "dev-mode verified_profiles is empty").toEqual([]);
      }

      await testInfo.attach("phase-a-e1-describe", {
        body: JSON.stringify(body, null, 2),
        contentType: "application/json",
      });
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

  test(
    "Phase D0: Event ID replay is idempotent and body drift returns duplicate_conflict",
    async ({ request }) => {
      // spec: api-conventions.md §6 (`event_id` idempotency path) and
      //       §4.2 (`ak.self.events.command.submit` write surface).
      //
      // Matrix Complement's transaction replay coverage maps most directly to
      // Arkret's canonical Event ID replay: exact same Event is duplicate/no-op;
      // same event_id with a different canonical body is a conflict.
      const stamp = Date.now();
      const alice = uniqueUser(`ssc-event-id-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const realmId = await createRealmViaApi(request, token, {
        title: `ssc event idempotency ${stamp}`,
        historyVisibility: "shared",
        ownerDid: alice.did,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);
      const body = `event id replay ${stamp}`;
      const envelope = signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.message.create",
        payload: {
          strand_id: strandId,
          track_name: "discussion",
          content: { kind: "ak.content.text", body },
        },
      });
      const eventId = String(envelope.event_id);
      await alignSignedEventToActorFrontierApi(request, token, envelope);

      const first = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(token),
        data: envelope,
      });
      expect([200, 201], `first submit returned ${first.status()}`).toContain(first.status());
      const firstBody = await first.json();
      expect(submittedEventId(firstBody)).toBe(eventId);
      expect(submittedEventOutcome(firstBody, eventId)).toBe("accepted");

      const duplicate = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(token),
        data: envelope,
      });
      expect(duplicate.status(), `duplicate submit status`).toBe(200);
      const duplicateBody = await duplicate.json();
      expect(submittedEventId(duplicateBody)).toBe(eventId);
      expect(submittedEventOutcome(duplicateBody, eventId)).toBe("duplicate");

      const eventsAfterDuplicate = await listRealmEventsViaApi(request, token, realmId);
      expect(eventsAfterDuplicate.filter((event) => event.event_id === eventId)).toHaveLength(1);

      const drift = signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        eventId,
        kind: "ak.message.create",
        payload: {
          strand_id: strandId,
          track_name: "discussion",
          content: { kind: "ak.content.text", body: `${body} drift` },
        },
      });
      const conflict = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(token),
        data: drift,
      });
      expect(conflict.status(), "same event_id with different body").toBe(409);
      expect(wireErrCode(await conflict.json())).toBe("duplicate_conflict");

      const eventsAfterConflict = await listRealmEventsViaApi(request, token, realmId);
      expect(eventsAfterConflict.filter((event) => event.event_id === eventId)).toHaveLength(1);
      expect(JSON.stringify(eventsAfterConflict)).toContain(body);
      expect(JSON.stringify(eventsAfterConflict)).not.toContain(`${body} drift`);
    },
  );

  test(
    "Phase C: list endpoint pagination cursor is opaque, gap-free, and non-overlapping across pages",
    async ({ request }) => {
      // spec: api-conventions.md §7 (cursor opaque; wire form `ak:cursor:<base64url>`;
      //         invalid → invalid_param; expired → cursor_expired),
      //       §7.1 (list pagination response: { <items_field>, next_cursor, has_more };
      //         client paginates by `has_more`, follows `next_cursor`).
      //
      // The `ak.self.events.query.scan` list surface at GET /_arkret/self/events
      // is the first list endpoint to reach the §7.1 wire shape exactly:
      // `{ events, next_cursor: "ak:cursor:<base64url>", has_more, prev_cursor }`.
      const stamp = Date.now();
      const alice = uniqueUser(`ssc-page-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const realmId = await createRealmViaApi(request, token, {
        title: `ssc pagination ${stamp}`,
        historyVisibility: "shared",
        ownerDid: alice.did,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);

      // Seed ≥5 list-visible messages so a limit=2 page leaves ≥2 more pages.
      const seededEventIds: string[] = [];
      for (let i = 0; i < 6; i += 1) {
        const envelope = signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.message.create",
          payload: {
            strand_id: strandId,
            track_name: "discussion",
            content: { kind: "ak.content.text", body: `page seed ${i} ${stamp}` },
          },
        });
        await submitSignedEventApi(request, token, envelope, {
          context: `seed pagination event ${i}`,
        });
        seededEventIds.push(String(envelope.event_id));
      }
      const seededSet = new Set(seededEventIds);

      const cursorRe = /^ak:cursor:[A-Za-z0-9_-]+$/;
      const fetchPage = async (after?: string) => {
        const url = new URL(`${solandBaseUrl()}/_arkret/self/events`);
        url.searchParams.set("realms", realmId);
        url.searchParams.set("limit", "2");
        if (after) {
          url.searchParams.set("after", after);
        }
        const resp = await request.get(url.toString(), { headers: authHeaders(token) });
        expect(resp.status(), "list page status").toBe(200);
        const body = (await resp.json()) as {
          events?: Array<{ event_id?: string }>;
          next_cursor?: string;
          has_more?: boolean;
        };
        expect(Array.isArray(body.events), "page events[] is array").toBe(true);
        expect(typeof body.has_more, "has_more boolean MUST be present").toBe("boolean");
        return body;
      };

      // Walk pages strictly by has_more / next_cursor, collecting only the
      // seeded ids so unrelated bootstrap events do not perturb the assertions.
      const pageSeededIds: string[][] = [];
      let cursor: string | undefined;
      let sawHasMoreTrue = false;
      for (let guard = 0; guard < 12; guard += 1) {
        const page = await fetchPage(cursor);
        const ids = (page.events ?? [])
          .map((event) => event.event_id)
          .filter((id): id is string => typeof id === "string");
        pageSeededIds.push(ids.filter((id) => seededSet.has(id)));
        if (page.next_cursor !== undefined) {
          // §7 — opaque ak:cursor token; decoding it MUST NOT reveal any seeded id.
          expect(page.next_cursor, "next_cursor wire form").toMatch(cursorRe);
          const decoded = Buffer.from(
            page.next_cursor.slice("ak:cursor:".length),
            "base64url",
          ).toString("utf8");
          for (const id of seededEventIds) {
            expect(decoded, "cursor is opaque (no seeded id leaks)").not.toContain(id);
          }
        }
        if (page.has_more === true) {
          sawHasMoreTrue = true;
          expect(page.next_cursor, "has_more=true MUST carry next_cursor").toMatch(cursorRe);
        }
        if (page.has_more !== true || !page.next_cursor) {
          break;
        }
        cursor = page.next_cursor;
      }

      // At least one page was bounded (proves the limit=2 cap paginated).
      expect(sawHasMoreTrue, "limit=2 over ≥6 items must page (has_more=true seen)").toBe(true);

      // Gap-free: union over all pages covers every seeded id.
      const union = new Set<string>(pageSeededIds.flat());
      for (const id of seededEventIds) {
        expect(union.has(id), `seeded id ${id} appears in some page (no gap)`).toBe(true);
      }
      // Non-overlapping: no seeded id appears on two pages.
      const seen = new Set<string>();
      for (const ids of pageSeededIds) {
        for (const id of ids) {
          expect(seen.has(id), `seeded id ${id} appears on exactly one page (no overlap)`).toBe(
            false,
          );
          seen.add(id);
        }
      }

      // Tampered cursor → 4xx invalid_param / cursor_expired (api-conventions §7).
      const firstPage = await fetchPage();
      const validCursor = firstPage.next_cursor;
      expect(validCursor, "first page must carry a next_cursor to tamper").toMatch(cursorRe);
      const flippedChar = validCursor![validCursor!.length - 1] === "A" ? "B" : "A";
      const tampered = validCursor!.slice(0, -1) + flippedChar;
      const tamperUrl = new URL(`${solandBaseUrl()}/_arkret/self/events`);
      tamperUrl.searchParams.set("realms", realmId);
      tamperUrl.searchParams.set("limit", "2");
      tamperUrl.searchParams.set("after", tampered);
      const tamperResp = await request.get(tamperUrl.toString(), {
        headers: authHeaders(token),
      });
      expect(tamperResp.status(), "tampered cursor is rejected 4xx").toBeGreaterThanOrEqual(400);
      expect(tamperResp.status(), "tampered cursor is a client error").toBeLessThan(500);
      expect(
        ["invalid_param", "cursor_expired", "invalid_cursor", "cursor_integrity_invalid"],
        "tampered cursor error code",
      ).toContain(wireErrCode(await tamperResp.json()));
    },
  );

  test(
    "Phase D: Idempotency-Key replay returns the cached first response; same key + different body returns duplicate_conflict",
    async ({ request }) => {
      // spec: api-conventions.md §6 (idempotency —
      //         same key + same canonical body → semantically equivalent result;
      //         same key + different canonical body → duplicate_conflict;
      //         server SHOULD persist idempotency mapping at least until the
      //         related Event is fully synced or expired).
      //
      // soland honours the generic `Idempotency-Key` header on POST
      // /_arkret/self/events, scoped to the authenticated principal: first
      // request executes + caches its response; same key + same canonical body
      // replays the cached first response; same key + a different canonical body
      // is `duplicate_conflict`. This is independent of Event-ID idempotency, so
      // the conflict probe uses a fresh event_id (only the reused key drives 409).
      const stamp = Date.now();
      const alice = uniqueUser(`ssc-idem-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const realmId = await createRealmViaApi(request, token, {
        title: `ssc idempotency-key ${stamp}`,
        historyVisibility: "shared",
        ownerDid: alice.did,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);
      const idempotencyKey = `ssc-${randomUUID()}`;

      const messageEnvelope = (body: string) =>
        signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.message.create",
          payload: {
            strand_id: strandId,
            track_name: "discussion",
            content: { kind: "ak.content.text", body },
          },
        });

      const countSeededEvents = async (): Promise<number> => {
        const events = await listRealmEventsViaApi(request, token, realmId, { limit: 100 });
        return events.filter((event) => {
          const payload = (event.payload ?? event) as { content?: { body?: unknown } };
          return typeof payload.content?.body === "string"
            ? (payload.content.body as string).startsWith(`idem body ${stamp}`)
            : false;
        }).length;
      };

      const before = await countSeededEvents();

      // R1 — first request under the key executes and is cached.
      const b1 = messageEnvelope(`idem body ${stamp} v1`);
      await alignSignedEventToActorFrontierApi(request, token, b1);
      const r1 = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { ...authHeaders(token), "idempotency-key": idempotencyKey },
        data: b1,
      });
      expect([200, 201], `R1 returned ${r1.status()}`).toContain(r1.status());
      const r1Body = await r1.json();
      expect(submittedEventId(r1Body), "R1 carries the submitted event_id").toBe(
        String(b1.event_id),
      );
      expect(submittedEventOutcome(r1Body, String(b1.event_id))).toBe("accepted");

      // R2 — same key + SAME canonical body replays the cached first response.
      const r2 = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { ...authHeaders(token), "idempotency-key": idempotencyKey },
        data: b1,
      });
      expect([200, 201], `R2 returned ${r2.status()}`).toContain(r2.status());
      const r2Body = await r2.json();
      expect(submittedEventId(r2Body), "R2 mirrors R1 event_id (no new event)").toBe(
        String(b1.event_id),
      );
      expect(JSON.stringify(r2Body), "R2 is the cached first response").toBe(
        JSON.stringify(r1Body),
      );

      // R3 — same key + DIFFERENT canonical body (fresh event_id) → duplicate_conflict.
      const b2 = messageEnvelope(`idem body ${stamp} v2-divergent`);
      const r3 = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { ...authHeaders(token), "idempotency-key": idempotencyKey },
        data: b2,
      });
      expect(r3.status(), "same key + different body is 409").toBe(409);
      expect(wireErrCode(await r3.json()), "duplicate_conflict on key reuse").toBe(
        "duplicate_conflict",
      );

      // Side effect: exactly one new seeded event landed across R1..R3.
      const after = await countSeededEvents();
      expect(after - before, "exactly one event created across the idempotent sequence").toBe(1);
    },
  );

  test(
    "Phase E: event requiring an undeclared feature is rejected with unsupported_feature (fail-closed)",
    async ({ request }) => {
      // spec: api-conventions.md §5.1 (unsupported_feature is reserved for
      //         Event.requirements.features[] / requirements.critical_extensions[]
      //         pointing at a feature this implementation has NOT advertised),
      //       service-surface.md §2.4 (services must publish supported_features).
      const describe = await request.get(`${solandBaseUrl()}/_arkret/describe`);
      expect(describe.status()).toBe(200);
      const description = await describe.json();
      const declared = new Set<string>([
        ...((description.supported_features ?? []) as string[]),
        ...((description.implemented_features ?? []) as string[]),
        ...((description.experimental_features ?? []) as string[]),
      ]);
      const undeclaredFeature = "ak.feature.mimi_room_passthrough.v1";
      expect(declared.has(undeclaredFeature), "fixture feature must be undeclared").toBe(false);

      const alice = uniqueUser("ssc-phase-e");
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const eventId = `ak:event:01904100-0000-7000-8000-${Date.now()
        .toString()
        .slice(-12)
        .padStart(12, "0")}`;
      const envelope = signedEventEnvelope({
        actorDid: alice.did,
        eventId,
        realmId: "ak:realm:01904100-0000-7000-8000-000000001101",
        kind: "ak.message.create",
        payload: {
          strand_id: "ak:strand:01904100-0000-7000-8000-000000001101",
          track_name: "discussion",
          content: { kind: "ak.content.text", body: "must not accept unknown feature" },
        },
      });
      (envelope.requirements as { features: string[] }).features = [undeclaredFeature];

      const resp = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { authorization: `Bearer ${token}` },
        data: envelope,
      });
      expect(resp.status()).toBeGreaterThanOrEqual(400);
      const body = await resp.json();
      expect(wireErrCode(body)).toBe("unsupported_feature");
      expect(JSON.stringify(body)).not.toContain('"accepted"');
      expect(JSON.stringify(body)).not.toContain(eventId);
    },
  );

  test(
    "Phase E2: unknown fail-closed critical extension is rejected with unsupported_feature",
    async ({ request }) => {
      // spec: api-conventions.md section 5.1 uses unsupported_feature for
      // unknown Event.requirements.critical_extensions[] entries that are
      // declared fail_closed.
      const criticalExtension = "ak.extension.cotest.unknown_fail_closed.v1";
      const alice = uniqueUser("ssc-phase-e2");
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const eventId = `ak:event:01904100-0000-7000-8000-${Date.now()
        .toString()
        .slice(-12)
        .padStart(12, "0")}`;
      const envelope = signedEventEnvelope({
        actorDid: alice.did,
        eventId,
        realmId: "ak:realm:01904100-0000-7000-8000-000000001102",
        kind: "ak.message.create",
        payload: {
          strand_id: "ak:strand:01904100-0000-7000-8000-000000001102",
          track_name: "discussion",
          content: {
            kind: "ak.content.text",
            body: "must not accept unknown fail-closed critical extension",
          },
        },
      });
      (
        envelope.requirements as {
          critical_extensions: Array<{
            id: string;
            fail_closed: boolean;
            extension_scope: string;
          }>;
        }
      ).critical_extensions = [
        {
          id: criticalExtension,
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
      expect(resp.status()).toBeLessThan(600);
      const body = await resp.json();
      expect(wireErrCode(body)).toBe("unsupported_feature");
      expect(JSON.stringify(body)).not.toContain('"accepted"');
      expect(JSON.stringify(body)).not.toContain(eventId);
    },
  );
});

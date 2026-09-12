// Sync — Service Surface Contract (describe / errors / pagination / idempotency)
// Contract: e2e/scenarios/sync/service-surface-contract.md
// Spec: sync/service-surface.md §3, §3.0, §17 (canonical ServiceDescribe + supported profiles and verification evidence)
//       sync/api-conventions.md §4 (success envelope), §5/§5.1/§5.2 (error envelope, unknown path,
//                                   method_not_allowed, unsupported_feature),
//                                §6 (idempotency), §7/§7.1 (opaque cursor + list pagination),
//                                §11 (feature discovery)
//       sync/service-api-schema.mdx §2 (canonical ServiceDescribe required fields)
//
// Both soland (`soland/src/routing/system/describe.rs` + `soland/src/wire.rs`) and coauth
// (`coauth/crates/backend/src/handlers/arkret.rs::server_describe`) already serve
// `GET /_arkret/describe` with the supported profiles and verification evidence layer in place, so the two
// describe probes are LIVE today. Phase A.E1 (claim_kind partition), Phase B
// (error envelope), Phase E (unsupported_feature fail-closed), Phase C (opaque
// list-pagination cursor on `ak.self.events.read.scan.v1`) and Phase D (generic
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
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import {
  createRealmViaApi,
  listRealmEventsViaApi,
} from "../../helpers/api";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  alignSignedEventToActorFrontierApi,
  authHeaders,
  canonicalJson,
  prepareSignedEventCbsApi,
  refreshEventEnvelopeProof,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type ProblemDetails = {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  instance?: string;
};

async function expectCanonicalSolandErrorEnvelope(request: APIRequestContext) {
  const unknown = await request.get(
    `${solandBaseUrl()}/_arkret/self/__definitely_does_not_exist__/probe`,
  );
  expect(unknown.status(), "unknown API path status").toBe(404);
  expect(unknown.headers()["content-type"] ?? "", "unknown path content-type").toContain(
    "application/problem+json",
  );
  const unknownBody = (await unknown.json()) as ProblemDetails;
  expect(unknownBody).toMatchObject({
    type: "https://arkret.org/problems/unrecognized_endpoint",
    status: 404,
  });
  expect(unknownBody.detail, "unknown path error message").toBeTruthy();
  expect(unknownBody.instance, "unknown path request_id").toMatch(/^ak:[a-z_]+:/);

  const wrongMethod = await request.post(`${solandBaseUrl()}/_arkret/describe`);
  expect(wrongMethod.status(), "known path wrong method status").toBe(405);
  expect(wrongMethod.headers()["content-type"] ?? "", "wrong method content-type").toContain(
    "application/problem+json",
  );
  expect(wrongMethod.headers()["allow"] ?? "", "wrong method Allow header").toContain("GET");
  const wrongMethodBody = (await wrongMethod.json()) as ProblemDetails;
  expect(wrongMethodBody).toMatchObject({
    type: "https://arkret.org/problems/method_not_allowed",
    status: 405,
  });
  expect(wrongMethodBody.detail, "wrong method error message").toBeTruthy();
  expect(wrongMethodBody.instance, "wrong method request_id").toMatch(/^ak:[a-z_]+:/);
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
          type: "https://arkret.org/problems/unrecognized_endpoint",
          title: "Unrecognized endpoint",
          status: 404,
          detail: "only the shared describe binding is exposed by this fixture",
          instance: `ak:request:${randomUUID()}`,
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
          type: "https://arkret.org/problems/param_invalid",
          title: "Param invalid",
          status: 400,
          detail: serviceKind
            ? `service_kind ${JSON.stringify(serviceKind)} is not available on this binding`
            : "service_kind is required when multiple roles share this binding",
          instance: `ak:request:${randomUUID()}`,
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
    // spec: service-surface.md §3 (canonical shape), §3.0 (supported profiles and verification evidence),
    //       §17 (line-level interop required fields); service-api-schema.mdx §2.
    //
    // Asserts the canonical fields are present, conformance claims remain
    // bound to supported profiles, and dev-mode posture forces verified_profiles == [].
    const resp = await request.get(`${solandBaseUrl()}/_arkret/describe`);
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"] ?? "").toContain("application/json");
    const body = await resp.json();

    // §17 — canonical ServiceDescribe required fields
    expect(body.service_id, "service_id").toBeTruthy();
    expect(body.trust_domain, "trust_domain").toMatch(/^ak:trust_domain:/);
    expect(body.service_kind, "service_kind").toBe("station");
    expect(body.protocol_version, "protocol_version").toBe("1.0");
    expect(Array.isArray(body.supported_profiles), "supported_profiles is array").toBe(true);
    expect(Array.isArray(body.supported_operation_bundles), "supported_operation_bundles is array").toBe(true);
    expect(Array.isArray(body.transport_bindings), "transport_bindings is array").toBe(true);
    expect(body.transport_bindings.length, "≥1 binding").toBeGreaterThanOrEqual(1);
    expect(body.transport_bindings[0].kind, "http_json binding").toBe("http_json");
    expect(Array.isArray(body.supported_features), "supported_features is array").toBe(true);
    expect(body.auth_metadata, "auth_metadata present").toBeTruthy();
    expect(body.limits, "limits present").toBeTruthy();
    expect(body.plaintext_visibility, "plaintext_visibility present").toBeTruthy();
    expect(typeof body.development_mode, "development_mode boolean").toBe("boolean");

    // §3.0 — supported profiles and verification evidence
    expect(body).not.toHaveProperty("claimed_profiles");
    expect(body).not.toHaveProperty("ingest_modes");
    expect(Array.isArray(body.verified_profiles), "verified_profiles array").toBe(true);
    expect(Array.isArray(body.interop_surfaces), "interop_surfaces array").toBe(true);

    // §3.0 — when development_mode=true, verified_profiles MUST be empty.
    if (body.development_mode === true) {
      expect(body.verified_profiles, "dev-mode verified_profiles is empty").toEqual([]);
    }

    expect(body.supported_operation_bundles, "exposes principal describe bundle").toContain(
      "ak.operation_bundle.station.describe.v1",
    );
    expect(body.supported_operation_bundles, "exposes principal HTTP core bundle").toContain(
      "ak.operation_bundle.station.http_core.v1",
    );

    await testInfo.attach("soland-describe", {
      body: JSON.stringify(body, null, 2),
      contentType: "application/json",
    });
  });

  test("soland describe accepts only its registered role selector", async ({
    request,
  }) => {
    const selected = await request.get(
      `${solandBaseUrl()}/_arkret/describe?service_kind=station`,
    );
    expect(selected.status()).toBe(200);
    expect((await selected.json()).service_kind).toBe("station");

    const rejected = await request.get(
      `${solandBaseUrl()}/_arkret/describe?service_kind=private_auth_process`,
    );
    expect(rejected.status()).toBe(400);
    expect(wireErrCode(await rejected.json())).toBe("param_invalid");
  });
});

test.describe("private authentication process surface @fully-implemented", () => {
  test("coauth exposes no public Arkret service description", async ({ request }) => {
    const baseUrl = coauthBaseUrl();
    test.skip(!baseUrl, "coauth not configured (COTEST_COAUTH_BASE_URL unset)");
    const response = await request.get(`${baseUrl}/_arkret/describe`);
    expect(response.status()).toBeGreaterThanOrEqual(400);
  });
});

test.describe("shared public describe binding @fully-implemented", () => {
  test("selects the Station role and rejects private process selectors", async ({
    request,
  }) => {
    const stationResponse = await request.get(
      `${solandBaseUrl()}/_arkret/describe?service_kind=station`,
    );
    expect(stationResponse.status()).toBe(200);
    const station = (await stationResponse.json()) as Record<string, unknown>;

    const shared = await startSharedDescribeBinding({
      station,
    });
    try {
      const missing = await request.get(`${shared.baseUrl}/_arkret/describe`);
      expect(missing.status()).toBe(400);
      expect(wireErrCode(await missing.json())).toBe("param_invalid");

      const invalid = await request.get(
        `${shared.baseUrl}/_arkret/describe?service_kind=directory_service`,
      );
      expect(invalid.status()).toBe(400);
      expect(wireErrCode(await invalid.json())).toBe("param_invalid");

      const selectedStation = await request.get(
        `${shared.baseUrl}/_arkret/describe?service_kind=station`,
      );
      const selectedPrivateProcess = await request.get(
        `${shared.baseUrl}/_arkret/describe?service_kind=private_auth_process`,
      );
      expect(selectedStation.status()).toBe(200);
      expect(selectedPrivateProcess.status()).toBe(400);
      const selectedStationBody =
        (await selectedStation.json()) as Record<string, unknown>;
      expect(selectedStationBody).toEqual(station);
      expect(selectedStationBody.service_kind).toBe("station");
    } finally {
      await shared.close();
    }
  });
});

// ---------- Mixed: broader live service-surface probes ----------

test.describe("service surface contract — error envelope, pagination, idempotency, fail-closed", () => {
  test(
    "Phase A.E1: verified profiles are evidence for the sole supported profile declaration",
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
      const supported = body.supported_profiles as string[];
      expect(body).not.toHaveProperty("claimed_profiles");
      const verified = body.verified_profiles as ProfileClaim[];

      expect(Array.isArray(supported), "supported_profiles is array").toBe(true);
      expect(Array.isArray(verified), "verified_profiles is array").toBe(true);
      const supportedIds = new Set(supported);
      expect(supportedIds.size, "supported profiles are unique").toBe(supported.length);
      for (const profileId of supported) {
        expect(typeof profileId, "supported profile ID").toBe("string");
        expect(profileId).not.toBe("");
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
          supportedIds.has(profileId),
          `${profileId} verification evidence must belong to a supported profile`,
        ).toBe(true);
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
    "Phase B: unknown path returns 404 unrecognized_endpoint with RFC 9457 Problem Details",
    async ({ request }) => {
      // spec: api-conventions.md §5 (RFC 9457 Problem Details; `type` is the
      //         sole stable machine discriminator),
      //       §5.2 (404 unrecognized_endpoint, MUST NOT return HTML / stack /
      //         framework error, MUST terminate at routing layer with no side effects).
      await expectCanonicalSolandErrorEnvelope(request);
    },
  );

  test(
    "Phase D0: Event ID replay is idempotent and body drift fails identity validation",
    async ({ request }) => {
      // spec: api-conventions.md §6 (`event_id` idempotency path) and
      //       §4.2 (`ak.self.events.command.submit.v1` write surface).
      //
      // Matrix Complement's transaction replay coverage maps most directly to
      // Arkret's canonical Event ID replay: exact same Event is duplicate/no-op;
      // A changed preimage under an old id fails models/event-and-patch.md
      // section 2 proof verification before that id may enter duplicate lookup.
      const stamp = Date.now();
      const alice = uniqueUser(`ssc-event-id-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const realmId = await createRealmViaApi(request, token, {
        title: `ssc event idempotency ${stamp}`,
        historyAccess: "all_history_for_current_members",
        ownerId: alice.id,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);
      const body = `event id replay ${stamp}`;
      const envelope = signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.message.create",
        payload: {
          strand_id: strandId,
          track_name: "discussion",
          content: { kind: "ak.content.text", body },
        },
      });
      await prepareSignedEventCbsApi(request, token, envelope);
      await alignSignedEventToActorFrontierApi(request, token, envelope);
      const eventId = String(envelope.event_id);
      const submitUrl = `${solandBaseUrl()}/_arkret/self/events`;

      const first = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { ...authHeaders(token, "POST", submitUrl), "content-type": "application/json" },
        data: canonicalJson({ event: envelope }),
      });
      expect([200, 201], `first submit returned ${first.status()}`).toContain(first.status());
      const firstBody = await first.json();
      expect(submittedEventId(firstBody)).toBe(eventId);
      expect(submittedEventOutcome(firstBody, eventId)).toBe("accepted");

      const duplicate = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { ...authHeaders(token, "POST", submitUrl), "content-type": "application/json" },
        data: canonicalJson({ event: envelope }),
      });
      expect(duplicate.status(), `duplicate submit status`).toBe(200);
      const duplicateBody = await duplicate.json();
      expect(submittedEventId(duplicateBody)).toBe(eventId);
      expect(submittedEventOutcome(duplicateBody, eventId)).toBe("duplicate");

      const eventsAfterDuplicate = await listRealmEventsViaApi(request, token, realmId);
      expect(eventsAfterDuplicate.filter((event) => event.event_id === eventId)).toHaveLength(1);

      const drift = signedEventEnvelope({
        actorId: alice.id,
        realmId,
        eventId,
        kind: "ak.message.create",
        payload: {
          strand_id: strandId,
          track_name: "discussion",
          content: { kind: "ak.content.text", body: `${body} drift` },
        },
      });
      drift.auth_context = envelope.auth_context;
      refreshEventEnvelopeProof(drift);
      // Deliberately reuse the accepted request identity with different content.
      // Ordinary signing helpers derive a new id; this negative request must not.
      drift.event_id = eventId;
      const conflict = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { ...authHeaders(token, "POST", submitUrl), "content-type": "application/json" },
        data: canonicalJson({ event: drift }),
      });
      expect(conflict.status(), "changed Event preimage must fail before duplicate lookup").toBe(422);
      expect(wireErrCode(await conflict.json())).toBe("schema_violation");

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
      //         invalid → param_invalid; expired → cursor_expired),
      //       §7.1 (list pagination response: { <items_field>, next_cursor, has_more };
      //         client paginates by `has_more`, follows `next_cursor`).
      //
      // The `ak.self.events.read.scan.v1` list surface at QUERY /_arkret/self/events
      // is the first list endpoint to reach the §7.1 wire shape exactly:
      // `{ events, next_cursor: "ak:cursor:<base64url>", has_more, prev_cursor }`.
      const stamp = Date.now();
      const alice = uniqueUser(`ssc-page-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const realmId = await createRealmViaApi(request, token, {
        title: `ssc pagination ${stamp}`,
        historyAccess: "all_history_for_current_members",
        ownerId: alice.id,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);

      // Seed ≥5 list-visible messages so a limit=2 page leaves ≥2 more pages.
      const seededEventIds: string[] = [];
      for (let i = 0; i < 6; i += 1) {
        const envelope = signedEventEnvelope({
          actorId: alice.id,
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
      // api-conventions §7.1: Event scan has_more means older history only.
      const fetchPage = async (before?: string) => {
        const url = new URL(`${solandBaseUrl()}/_arkret/self/events`);
        const resp = await request.fetch(url.toString(), {
          method: "QUERY",
          headers: { ...authHeaders(token, "QUERY", url.toString()), "content-type": "application/json" },
          data: canonicalJson({
            realm_ids: [realmId],
            order: "descending",
            limit: 2,
            ...(before ? { before } : {}),
          }),
        });
        expect(resp.status(), "list page status").toBe(200);
        const body = (await resp.json()) as {
          events?: Array<{ event_id?: string }>;
          prev_cursor?: string;
          has_more?: boolean;
        };
        expect(
          Array.isArray(body.events),
          "page events[] is array",
        ).toBe(true);
        expect(typeof body.has_more, "has_more boolean MUST be present").toBe("boolean");
        return body;
      };

      // Walk pages strictly by has_more / prev_cursor, collecting only the
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
        if (page.prev_cursor !== undefined) {
          // §7 — opaque ak:cursor token; decoding it MUST NOT reveal any seeded id.
          expect(page.prev_cursor, "prev_cursor wire form").toMatch(cursorRe);
          const decoded = Buffer.from(
            page.prev_cursor.slice("ak:cursor:".length),
            "base64url",
          ).toString("utf8");
          for (const id of seededEventIds) {
            expect(decoded, "cursor is opaque (no seeded id leaks)").not.toContain(id);
          }
        }
        if (page.has_more === true) {
          sawHasMoreTrue = true;
          expect(page.prev_cursor, "has_more=true MUST carry prev_cursor").toMatch(cursorRe);
        }
        if (page.has_more !== true || !page.prev_cursor) {
          break;
        }
        cursor = page.prev_cursor;
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

      // Tampered cursor → encoding.md §8.3 closed set. Flipping the final
      // base64url character corrupts the canonical JSON body, so this is a
      // *syntax* failure: the mapping is pinned to top-level `param_invalid`
      // with reason `invalid_cursor` — `cursor_expired` is reserved for TTL
      // expiry and `cursor_integrity_invalid` for handle lookup / binding
      // failures; a bare `invalid_cursor` error code is outside the closed set.
      const firstPage = await fetchPage();
      const validCursor = firstPage.prev_cursor;
      expect(validCursor, "first page must carry a prev_cursor to tamper").toMatch(cursorRe);
      const flippedChar = validCursor![validCursor!.length - 1] === "A" ? "B" : "A";
      const tampered = validCursor!.slice(0, -1) + flippedChar;
      const tamperUrl = new URL(`${solandBaseUrl()}/_arkret/self/events`);
      const tamperResp = await request.fetch(tamperUrl.toString(), {
        method: "QUERY",
        headers: { ...authHeaders(token, "QUERY", tamperUrl.toString()), "content-type": "application/json" },
        data: canonicalJson({ realm_ids: [realmId], order: "descending", limit: 2, before: tampered }),
      });
      expect(tamperResp.status(), "tampered cursor is param_invalid (HTTP 400)").toBe(400);
      const tamperBody = (await tamperResp.json()) as { reason_code?: string };
      expect(wireErrCode(tamperBody), "tampered cursor error code").toBe("param_invalid");
      expect(
        tamperBody.reason_code,
        "syntax failure carries reason invalid_cursor",
      ).toBe("invalid_cursor");
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
        historyAccess: "all_history_for_current_members",
        ownerId: alice.id,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);
      const idempotencyKey = `ssc-${randomUUID()}`;

      const messageEnvelope = (body: string) =>
        signedEventEnvelope({
          actorId: alice.id,
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

      const submitUrl = `${solandBaseUrl()}/_arkret/self/events`;
      // R1 — first request under the key executes and is cached.
      const b1 = messageEnvelope(`idem body ${stamp} v1`);
      await prepareSignedEventCbsApi(request, token, b1);
      await alignSignedEventToActorFrontierApi(request, token, b1);
      const r1 = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { ...authHeaders(token, "POST", submitUrl), "idempotency-key": idempotencyKey, "content-type": "application/json" },
        data: canonicalJson({ event: b1 }),
      });
      expect([200, 201], `R1 returned ${r1.status()}`).toContain(r1.status());
      const r1Body = await r1.json();
      expect(submittedEventId(r1Body), "R1 carries the submitted event_id").toBe(
        String(b1.event_id),
      );
      expect(submittedEventOutcome(r1Body, String(b1.event_id))).toBe("accepted");

      // R2 — same key + SAME canonical body replays the cached first response.
      const r2 = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { ...authHeaders(token, "POST", submitUrl), "idempotency-key": idempotencyKey, "content-type": "application/json" },
        data: canonicalJson({ event: b1 }),
      });
      expect([200, 201], `R2 returned ${r2.status()}`).toContain(r2.status());
      const r2Body = await r2.json();
      expect(submittedEventId(r2Body), "R2 mirrors R1 event_id (no new event)").toBe(
        String(b1.event_id),
      );
      expect(canonicalJson(r2Body) === canonicalJson(r1Body),
        "R2 is the exact cached first response (body omitted from diagnostics)").toBe(true);

      // R3 — same key + DIFFERENT canonical body (fresh event_id) → duplicate_conflict.
      const b2 = messageEnvelope(`idem body ${stamp} v2-divergent`);
      await prepareSignedEventCbsApi(request, token, b2);
      await alignSignedEventToActorFrontierApi(request, token, b2);
      const r3 = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: { ...authHeaders(token, "POST", submitUrl), "idempotency-key": idempotencyKey, "content-type": "application/json" },
        data: canonicalJson({ event: b2 }),
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
      ]);
      const undeclaredFeature = "ak.feature.mimi_room_passthrough.v1";
      expect(declared.has(undeclaredFeature), "fixture feature must be undeclared").toBe(false);

      const alice = uniqueUser("ssc-phase-e");
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const realmId = await createRealmViaApi(request, token, {
        title: `unsupported feature ${Date.now()}`,
        historyAccess: "all_history_for_current_members",
        ownerId: alice.id,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);
      const envelope = signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.message.create",
        payload: {
          strand_id: strandId,
          track_name: "discussion",
          content: { kind: "ak.content.text", body: "must not accept unknown feature" },
        },
      });
      await prepareSignedEventCbsApi(request, token, envelope);
      await alignSignedEventToActorFrontierApi(request, token, envelope);
      (envelope.requirements as { features: string[] }).features = [undeclaredFeature];
      refreshEventEnvelopeProof(envelope);
      const eventId = String(envelope.event_id);

      const submitUrl = `${solandBaseUrl()}/_arkret/self/events`;
      const resp = await request.post(submitUrl, {
        headers: { ...authHeaders(token, "POST", submitUrl), "content-type": "application/json" },
        data: canonicalJson({ event: envelope }),
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
      const realmId = await createRealmViaApi(request, token, {
        title: `unsupported critical extension ${Date.now()}`,
        historyAccess: "all_history_for_current_members",
        ownerId: alice.id,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);
      const envelope = signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.message.create",
        payload: {
          strand_id: strandId,
          track_name: "discussion",
          content: {
            kind: "ak.content.text",
            body: "must not accept unknown fail-closed critical extension",
          },
        },
      });
      await prepareSignedEventCbsApi(request, token, envelope);
      await alignSignedEventToActorFrontierApi(request, token, envelope);
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
      const eventId = String(envelope.event_id);

      const submitUrl = `${solandBaseUrl()}/_arkret/self/events`;
      const resp = await request.post(submitUrl, {
        headers: { ...authHeaders(token, "POST", submitUrl), "content-type": "application/json" },
        data: canonicalJson({ event: envelope }),
      });
      expect(resp.status()).toBeGreaterThanOrEqual(400);
      expect(resp.status()).toBeLessThan(600);
      const body = await resp.json();
      expect(wireErrCode(body)).toBe("unsupported_feature");
      expect(JSON.stringify(body)).not.toContain('"accepted"');
      expect(JSON.stringify(body)).not.toContain(String(envelope.event_id));
    },
  );
});

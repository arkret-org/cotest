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
// list-pagination cursor on `ak.self.committed_event.read.scan.v1`) and Phase D (full-body
// `canonical_hash` replay identity of POST /_arkret/self/events) are all live on
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
  authHeaders,
  canonicalJson,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
import { ensureRegistered, issueUserSession, uniqueUser } from "../../helpers/users";

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
  const commit = record.commit as Record<string, unknown> | undefined;
  if (typeof commit?.event_ref === "string") {
    return commit.event_ref;
  }
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
  if (record.status === "committed") {
    return "accepted";
  }
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
      "ak.operation_bundle.station.http_core_current.v1",
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
      const token = await issueUserSession(request, alice);
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
    "Phase C: committed stream scan is gap-free and non-overlapping across pages",
    async ({ request }) => {
      // A committed stream is paged by position. `before_position` is exclusive,
      // and `truncated` tells the reader whether older positions remain.
      const stamp = Date.now();
      const alice = uniqueUser(`ssc-page-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const token = await issueUserSession(request, alice);
      const realmId = await createRealmViaApi(request, token, {
        title: `ssc pagination ${stamp}`,
        historyAccess: "all_history_for_current_members",
        ownerId: alice.id,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);

      // Seed enough messages to require several pages after the bootstrap.
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

      const scanUrl = `${solandBaseUrl()}/_arkret/self/streams/scan`;
      const fetchPage = async (beforePosition: number | null) => {
        const response = await request.post(scanUrl, {
          headers: { ...authHeaders(token, "POST", scanUrl), "content-type": "application/json" },
          data: canonicalJson({
            realm_id: realmId,
            stream_ref: { kind: "realm", realm_id: realmId },
            before_position: beforePosition,
            limit: 2,
          }),
        });
        expect(response.status(), "stream scan page status").toBe(200);
        const body = (await response.json()) as {
          committed_events: Array<{
            commit: { stream_position: number; event_ref: string };
            event: { event_id: string };
          }>;
          truncated: boolean;
        };
        expect(Array.isArray(body.committed_events)).toBe(true);
        expect(typeof body.truncated).toBe("boolean");
        return body;
      };

      const pageSeededIds: string[][] = [];
      const seenPositions = new Set<number>();
      let beforePosition: number | null = null;
      let previousPosition: number | undefined;
      let sawTruncated = false;
      for (let guard = 0; guard < 20; guard += 1) {
        const page = await fetchPage(beforePosition);
        expect(page.committed_events.length).toBeGreaterThan(0);
        expect(page.committed_events.length).toBeLessThanOrEqual(2);
        pageSeededIds.push(page.committed_events
          .map(({ commit, event }) => {
            expect(commit.event_ref).toBe(event.event_id);
            expect(seenPositions.has(commit.stream_position), "stream position repeated").toBe(false);
            if (previousPosition !== undefined) {
              expect(commit.stream_position, "stream scan skipped a position").toBe(previousPosition - 1);
            }
            previousPosition = commit.stream_position;
            seenPositions.add(commit.stream_position);
            return event.event_id;
          })
          .filter((id) => seededSet.has(id)));
        if (!page.truncated) break;
        sawTruncated = true;
        beforePosition = previousPosition!;
      }
      expect(sawTruncated, "limit=2 must require another page").toBe(true);
      expect(previousPosition, "scan reaches the Realm stream genesis").toBe(0);

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

      const malformed = await request.post(scanUrl, {
        headers: { ...authHeaders(token, "POST", scanUrl), "content-type": "application/json" },
        data: canonicalJson({
          realm_id: realmId,
          stream_ref: { kind: "realm", realm_id: realmId },
          after_position: null,
          before_position: null,
          limit: 2,
        }),
      });
      expect(malformed.status(), "both scan directions are rejected").toBe(422);
      expect(wireErrCode(await malformed.json())).toBe("schema_violation");
    },
  );

  test(
    "Phase D: exact Event-submit replay returns the original commit; a different body is an independent request",
    async ({ request }) => {
      // spec: operation-registry.json registers
      //   `ak.self.events.command.submit.v1` as `canonical_hash / full_body /
      //   retry_safe=true`; api-conventions.md §6 makes the full canonical
      //   request body the replay identity (scoped to principal + operation)
      //   and §6.2 lets a byte-identical retry return the original branch
      //   outcome or an equivalent idempotent result. authority-commit-log.md
      //   §3/§4: an exact retry returns the same Commit, reported as
      //   `committed` or `duplicate`, and never takes a new position.
      //   `Idempotency-Key` is not this operation's request identity, so no
      //   header is sent; key-reuse `duplicate_conflict` belongs to operations
      //   registered with `idempotency_mechanism=idempotency_key`.
      const stamp = Date.now();
      const alice = uniqueUser(`ssc-idem-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const token = await issueUserSession(request, alice);
      const realmId = await createRealmViaApi(request, token, {
        title: `ssc exact replay ${stamp}`,
        historyAccess: "all_history_for_current_members",
        ownerId: alice.id,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);

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
      const submit = async (event: Record<string, unknown>) =>
        await request.post(submitUrl, {
          headers: { ...authHeaders(token, "POST", submitUrl), "content-type": "application/json" },
          data: canonicalJson({ event }),
        });

      // R1 — the first request commits the Event.
      const b1 = messageEnvelope(`idem body ${stamp} v1`);
      const r1 = await submit(b1);
      expect([200, 201], `R1 returned ${r1.status()}`).toContain(r1.status());
      const r1Body = await r1.json();
      expect(submittedEventId(r1Body), "R1 carries the submitted event_id").toBe(
        String(b1.event_id),
      );
      expect(r1Body.status).toBe("committed");

      // R2 — the byte-identical request is the same request identity: it
      // returns the same Commit and creates nothing.
      const r2 = await submit(b1);
      expect([200, 201], `R2 returned ${r2.status()}`).toContain(r2.status());
      const r2Body = await r2.json();
      expect(["committed", "duplicate"]).toContain(r2Body.status);
      expect(
        canonicalJson(r2Body.commit) === canonicalJson(r1Body.commit),
        "R2 returns the exact first Commit (body omitted from diagnostics)",
      ).toBe(true);

      // R3 — a different canonical body is a different request identity and
      // an independent Event.
      const b2 = messageEnvelope(`idem body ${stamp} v2`);
      const r3 = await submit(b2);
      expect([200, 201], `R3 returned ${r3.status()}`).toContain(r3.status());
      const r3Body = await r3.json();
      expect(r3Body.status).toBe("committed");
      expect(submittedEventId(r3Body)).toBe(String(b2.event_id));
      expect(canonicalJson(r3Body.commit) === canonicalJson(r1Body.commit)).toBe(false);

      const after = await countSeededEvents();
      expect(after - before, "one Event per distinct request identity").toBe(2);
    },
  );

  // spec: api-conventions.md section 5.1 and models/event-and-patch.md section 2
  // - a current-v1 Event has no generic `requirements` / `critical_extensions`
  // carrier; a top-level occurrence is a schema_violation and MUST NOT be
  // disguised as feature negotiation (unsupported_feature is reserved for
  // registered wire features the v1 support matrix marks unsupported).
  // forbidden-wire-fields.json registers `requirements` as a forbidden field.
  for (const retired of [
    {
      phase: "Phase E",
      member: "requirements",
      value: { features: ["ak.feature.mimi_room_passthrough.v1"] },
    },
    {
      phase: "Phase E2",
      member: "critical_extensions",
      value: [
        {
          id: "ak.extension.cotest.unknown_fail_closed.v1",
          fail_closed: true,
          extension_scope: "payload",
        },
      ],
    },
  ]) {
    test(
      `${retired.phase}: an Event carrying a top-level \`${retired.member}\` carrier is a schema_violation, not unsupported_feature`,
      async ({ request }) => {
        const alice = uniqueUser(`ssc-${retired.member}`);
        await ensureRegistered(request, alice);
        const token = await issueUserSession(request, alice);
        const realmId = await createRealmViaApi(request, token, {
          title: `retired ${retired.member} carrier ${Date.now()}`,
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
            content: { kind: "ak.content.text", body: `must not accept ${retired.member}` },
          },
        });
        const eventId = String(envelope.event_id);
        // The SDK cannot derive an identity for a closed envelope with an
        // unregistered member, so the member is injected after signing: the
        // closed Event schema must reject it before any proof evaluation.
        const tampered = { ...envelope, [retired.member]: retired.value };

        const submitUrl = `${solandBaseUrl()}/_arkret/self/events`;
        const resp = await request.post(submitUrl, {
          headers: { ...authHeaders(token, "POST", submitUrl), "content-type": "application/json" },
          data: canonicalJson({ event: tampered }),
        });
        const text = await resp.text();
        expect(resp.status(), text).toBe(422);
        const body = JSON.parse(text);
        expect(wireErrCode(body), text).toBe("schema_violation");
        expect(text).not.toContain('"committed"');
        expect(text).not.toContain(eventId);

        const events = await listRealmEventsViaApi(request, token, realmId, { limit: 100 });
        expect(JSON.stringify(events)).not.toContain(eventId);
      },
    );
  }
});

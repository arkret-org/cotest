// Core object invariants — common fields, patch precondition CAS, lifecycle
// cascade, relation cardinality, view projection fallback.
//
// Contract: e2e/scenarios/models/core-object-invariants.md
// Spec refs:
//   - models/common-fields.md §3 (Common Object Fields), §5 / §5.1 (lifecycle
//     state machine + canonical reason codes)
//   - models/event-and-patch.md §2.2 (Event Envelope required fields),
//     §4.2.4 / §4.2.5 (redactable / reducer-managed field protection)
//   - models/realm-and-space.md §2.5 / §2.5.1 (Realm tombstone / destroy
//     cascade), §3.4 (Space lifecycle, space_has_live_dependents)
//   - models/relation.md §3.2 (cardinality table, dedup rule), §4.4
//     (cross-Realm structural constraint)
//   - models/views.md §2.2 (kind is response family), §6 / §6.3 (Board
//     projection derived from query → contains → strand)
//
// Phases A and D are live. Phases B, C, and E are test.fixme: each pins a
// registered spec contract, but still needs the corresponding sealing path,
// reducer, or projection before promotion.

import { type APIRequestContext, expect, test } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import type { ActorId } from "../../helpers/generated/spec-wire-objects";
import { stepShot } from "../../helpers/screenshots";
import {
  accountActorId,
  alignSignedEventToActorFrontierApi,
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  prepareSignedEventCbsApi,
  readAcceptedSeal,
  retypeEventDerivedId,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  openUserPage,
  selfPathHeadersForDpopSession,
  uniqueUser,
} from "../../helpers/users";

// Shared Strand factory with its registered stage independent of metadata.
async function createStrandApi(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  title: string,
): Promise<string> {
  const createdAt = canonicalTimestamp();
  // `ak.strand.create` derives the object id from the create Event, so the
  // payload MUST NOT carry `id` (`object_id_not_event_derived`). Retype the
  // finished envelope's event id instead of minting one up front.
  const envelope = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.strand.create",
    createdAt,
    payload: {
      object: {
        schema: "ak.schema.strand.v1",
        realm_id: realmId,
        metadata: { title },
        stage: "planned",
        tracks: { discussion: { enabled: true, is_primary: true } },
        created_by: accountActorId(actorId),
        created_at: createdAt,
      },
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    context: `create strand ${title}`,
  });
  return retypeEventDerivedId(String(envelope.event_id), "strand");
}

type RealmSealBasis = {
  leaves: string[];
  control_event_set_root: string;
  state_root: string;
};

async function fetchRealmSealBasis(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<RealmSealBasis> {
  // `ak.self.seals.read.frontier.v1` is the only registered Realm Seal
  // discovery surface and accepts a closed QUERY body.
  const frontierUrl = `${solandBaseUrl()}/_arkret/self/seals/frontier`;
  const response = await request.fetch(frontierUrl, {
    method: "QUERY",
    headers: {
      ...authHeaders(token, "QUERY", frontierUrl),
      "content-type": "application/json",
    },
    data: canonicalJson({ realm_id: realmId }),
  });
  const body = (await response.json()) as {
    frontier?: {
      kind?: unknown;
      seal_basis?: { leaves?: unknown };
    };
  };
  expect(
    response.ok(),
    `read Realm Seal frontier returned ${response.status()}: ${JSON.stringify(body)}`,
  ).toBeTruthy();
  expect(body.frontier?.kind).toBe("realm_seal");
  const leaves = body.frontier?.seal_basis?.leaves as string[] | undefined;
  expect(leaves).toEqual([expect.stringMatching(/^ak:seal:/)]);
  const seal = await readAcceptedSeal(request, token, realmId, leaves![0]);
  expect(seal.control_event_set_root).toMatch(/^(sha256|blake3):[0-9a-f]{64}$/);
  expect(seal.state_root).toMatch(/^(sha256|blake3):[0-9a-f]{64}$/);
  return {
    leaves: [leaves![0]],
    control_event_set_root: String(seal.control_event_set_root),
    state_root: String(seal.state_root),
  };
}

// `ak.relation.create` derives `ak:relation:` from the create Event, so the
// object MUST NOT carry an `id` (`object_id_not_event_derived`).
function relationObject(args: {
  realmId: string;
  relationKind: string;
  fromRef: string;
  toRef: string;
  actorId: string;
}): Record<string, unknown> {
  return {
    schema: "ak.schema.relation.v1",
    realm_id: args.realmId,
    relation_kind: args.relationKind,
    from_ref: args.fromRef,
    to_ref: args.toRef,
    created_by: accountActorId(args.actorId),
    created_at: canonicalTimestamp(),
  };
}

test.describe.configure({ mode: "serial" });

test.describe("core object invariants", () => {
  test("Phase A — newly created Realm exposes spec §3 common fields (id, created_at, actor, lifecycle_state equivalents) on the read-back wire", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      `s-coinv-alice-${stamp}`,
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("core object invariants browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const alicePage = aliceFlow.page;
    const authFor = (method: string, url: string) =>
      selfPathHeadersForDpopSession(aliceFlow.session, method, url);

    try {
      // ── Step 1-2: alice creates Realm R via the standard setup wizard
      // (same path messaging/triad-collaboration uses).
      const realmId = await alicePage.createRealm({
        title: `models/core-object-invariants Realm ${stamp}`,
        summary: "core object invariants coverage",
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
      });
      expect(realmId).toMatch(/^ak:realm:/);
      await stepShot(alicePage.page, testInfo, "A-alice-realm-created");

      // ── Step 3: read back the Realm via the soland API and verify the
      // spec §3 common-field equivalents on the RealmLifecycleResponse
      // serializer. Current wire shape (soland/src/wire.rs
      // RealmLifecycleView): { realm_id, owner_id, members, deleted, ... }.
      //   - realm_id  ↔ spec `id`              (typed ak:realm: prefix)
      //   - owner_id  ↔ current owner authority (DID, actor reference)
      //   - members   ↔ membership invariant   (must contain owner)
      //   - deleted   ↔ spec `lifecycle_state` (false ⇒ active)
      const realmUrl = `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
      const realmRes = await request.get(realmUrl, {
        headers: authFor("GET", realmUrl),
      });
      expect(realmRes.status()).toBe(200);
      const realmBody = (await realmRes.json()) as {
        ok?: boolean;
        realm_id?: string;
        owner_id?: string;
        member_ids?: string[];
        deleted?: boolean;
      };
      // Common-field 1: `id` (typed ak:realm: prefix).
      expect(realmBody.realm_id).toBe(realmId);
      expect(realmBody.realm_id).toMatch(/^ak:realm:/);
      // Common-field 2: actor reference through the canonical owner field.
      expect(realmBody.owner_id).toBe(alice.id);
      // Membership invariant: owner must always appear in members.
      expect(Array.isArray(realmBody.member_ids)).toBe(true);
      expect(realmBody.member_ids).toContainEqual(accountActorId(alice.id));
      // Common-field 3: `lifecycle_state` equivalent (deleted=false ⇒ active).
      expect(realmBody.deleted).toBe(false);

      // ── Step 4: read the event log for this Realm to recover the
      // `created_at` + `event_id` + `actor_id` + `kind` fields that
      // RealmLifecycleResponse does not currently surface. The events
      // query response items are canonical Event Envelopes. The required
      // security scope is carried by scope_ref; top-level realm_id is not a
      // required producer field.
      const eventsUrl = `${solandBaseUrl()}/_arkret/self/events`;
      const eventsRes = await request.fetch(eventsUrl, {
        method: "QUERY",
        data: canonicalJson({ realm_ids: [realmId], limit: 20 }),
        headers: {
          ...authFor("QUERY", eventsUrl),
          "content-type": "application/json",
        },
      });
      expect(eventsRes.status()).toBe(200);
      const eventsBody = (await eventsRes.json()) as {
        events?: Array<{
          event_id?: string;
          kind?: string;
          actor_id?: ActorId;
          created_at?: string;
          scope_ref?: { kind?: string; realm_id?: string };
        }>;
      };
      const events = eventsBody.events ?? [];
      expect(events.length).toBeGreaterThan(0);

      // Find the Realm lifecycle / create event — soland writes lifecycle
      // ops via record_space_lifecycle_operation, so the kind is in the
      // ak.realm.* family. We accept any ak.realm.* kind to stay
      // resilient to soland's exact lifecycle op naming.
      const lifecycleEvent =
        events.find((event) => event.kind?.startsWith("ak.realm.")) ??
        events[0];
      expect(lifecycleEvent).toBeTruthy();
      // Common-field (Event Envelope §2.2): event_id.
      expect(lifecycleEvent.event_id).toMatch(/^ak:event:/);
      // Common-field (§2.2 / §3): created_at (RFC 3339, MUST end with Z).
      expect(lifecycleEvent.created_at).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/,
      );
      // Common-field (§2.2): actor_id.
      expect(lifecycleEvent.actor_id).toEqual(accountActorId(alice.id));
      // Common-field: kind (§2.2 — Event Envelope `kind`).
      expect(typeof lifecycleEvent.kind).toBe("string");
      expect(lifecycleEvent.kind?.length ?? 0).toBeGreaterThan(0);
      // Realm genesis omits realm_id from both the top-level envelope and
      // scope_ref to avoid a digest cycle. Its Realm id is self-authenticating
      // through retype(event_id, "realm").
      if (lifecycleEvent.kind === "ak.realm.create") {
        expect(lifecycleEvent.scope_ref).toEqual({ kind: "realm_genesis" });
        expect(retypeEventDerivedId(lifecycleEvent.event_id!, "realm")).toBe(
          realmId,
        );
      } else {
        expect(lifecycleEvent.scope_ref?.realm_id).toBe(realmId);
      }

      await stepShot(
        alicePage.page,
        testInfo,
        "A-alice-common-fields-verified",
      );
    } finally {
      await alicePage.close();
    }
  });

  // ── Phase B — registered Control Move CAS.
  // `ak.strand.update` is a data-plane Event in the event-kind registry and
  // MUST NOT carry preconditions[] or seal_basis. The registered v1 CAS surface
  // for this invariant is `ak.strand.move`: it writes the default-control-plane
  // `ak.component.strand.position.v1:<board_space_id>:<strand_id>` cas_register.
  // A stale head_eq MUST reject the whole Move; a subsequent fresh Move from
  // the same accepted position proves that the rejected effect did not land.
  test.fixme(// @blocking-on: soland#accepted-control-move-seal-finalization
  // @user-promise: e2e/scenarios/models/core-object-invariants.md (Phase B)
  // @expected-live-by: 2026Q3
  "Phase B — stale ak.strand.move head_eq rejects atomically; the same seal basis admits a fresh position CAS", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s-coinv-b-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `core-invariants B ${stamp}`,
      ownerId: alice.id,
    });

    const strandId = await createStrandApi(
      request,
      aliceToken,
      alice.id,
      realmId,
      `core-invariants strand ${stamp}`,
    );
    const boardSpaceId = typedId("space");
    const sourceListId = typedId("space");
    const staleExpectedListId = typedId("space");
    const targetListId = typedId("space");
    const positionCell = `ak:cell:ak.component.strand.position.v1:${boardSpaceId}:${strandId}`;

    const initialBasis = await fetchRealmSealBasis(
      request,
      aliceToken,
      realmId,
    );
    const initialPosition = { list_space_id: sourceListId, rank: "m" };
    const initialMove = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.move",
      preconditions: [
        {
          cell_id: positionCell,
          predicate: { op: "head_eq", value: null },
        },
      ],
      sealBasis: initialBasis,
      payload: {
        board_space_id: boardSpaceId,
        strand_id: strandId,
        target_space_id: sourceListId,
        rank: "m",
      },
    });
    await alignSignedEventToActorFrontierApi(request, aliceToken, initialMove);
    await submitSignedEventApi(request, aliceToken, initialMove, {
      context: "establish initial Strand position",
    });

    await expect
      .poll(() => fetchRealmSealBasis(request, aliceToken, realmId), {
        message:
          "initial Strand position Control Move becomes covered by a later Seal",
        timeout: 30_000,
      })
      .not.toEqual(initialBasis);
    const acceptedBasis = await fetchRealmSealBasis(
      request,
      aliceToken,
      realmId,
    );
    const staleMoveEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.move",
      preconditions: [
        {
          cell_id: positionCell,
          predicate: {
            op: "head_eq",
            value: { list_space_id: staleExpectedListId, rank: "m" },
          },
        },
      ],
      sealBasis: acceptedBasis,
      payload: {
        board_space_id: boardSpaceId,
        strand_id: strandId,
        from_space_id: staleExpectedListId,
        target_space_id: targetListId,
        rank: "z",
        expected_position: { space_id: staleExpectedListId, rank: "m" },
      },
    });
    await alignSignedEventToActorFrontierApi(
      request,
      aliceToken,
      staleMoveEnvelope,
    );
    const staleMove = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: { event: staleMoveEnvelope },
      },
    );
    expect(staleMove.status()).toBe(409);
    expect(wireErrCode(await staleMove.json())).toBe("failed_precondition");

    const basisAfterReject = await fetchRealmSealBasis(
      request,
      aliceToken,
      realmId,
    );
    expect(basisAfterReject).toEqual(acceptedBasis);
    const freshMove = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.move",
      preconditions: [
        {
          cell_id: positionCell,
          predicate: { op: "head_eq", value: initialPosition },
        },
      ],
      sealBasis: basisAfterReject,
      payload: {
        board_space_id: boardSpaceId,
        strand_id: strandId,
        from_space_id: sourceListId,
        target_space_id: targetListId,
        rank: "z",
        expected_position: { space_id: sourceListId, rank: "m" },
      },
    });
    await alignSignedEventToActorFrontierApi(request, aliceToken, freshMove);
    await submitSignedEventApi(request, aliceToken, freshMove, {
      context: "fresh Strand position CAS after stale rejection",
    });
  });

  // ── Phase C — Cascade / archive / delete.
  // Non-cascading archive/restore is covered by project-simulation and the
  // domain lifecycle regressions. `ak.space.tombstone` still lacks a
  // `space_has_live_dependents` precondition (apply_space_container.rs only
  // checks the source lifecycle state → `space_already_terminal`), so the
  // live-dependents refusal is not yet wired. This remains an implementation
  // gap against realm-and-space section 3.4, not a product exception.
  test.fixme(// @blocking-on: soland#space-lifecycle-spec-convergence
  // @user-promise: e2e/scenarios/models/core-object-invariants.md (Phase C)
  // @expected-live-by: 2026Q3
  "Phase C — ak.space.archive does NOT cascade; tombstone with live dependents fails; post-tombstone writes are rejected", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s-coinv-c-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `core-invariants C ${stamp}`,
      ownerId: alice.id,
    });
    const createdAt = canonicalTimestamp();
    // `ak.space.create` derives `ak:space:` from the create Event, so the
    // object carries no `id` and the caller retypes the finished envelope.
    const parentSpaceEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.space.create",
      createdAt,
      payload: {
        object: {
          schema: "ak.schema.space.v1",
          realm_id: realmId,
          kind: "board",
          metadata: { title: `core-invariants parent ${stamp}` },
          created_by: accountActorId(alice.id),
          created_at: createdAt,
        },
      },
    });
    await submitSignedEventApi(request, aliceToken, parentSpaceEnvelope, {
      context: "create parent board space",
    });
    const parentSpaceId = retypeEventDerivedId(
      String(parentSpaceEnvelope.event_id),
      "space",
    );

    // Archiving the parent leaves independently owned child lifecycle intact.
    const archiveRes = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: { event: signedEventEnvelope({
          actorId: alice.id,
          realmId,
          kind: "ak.space.archive",
          payload: { space_id: parentSpaceId },
        }) },
      },
    );
    expect(archiveRes.ok()).toBeTruthy();

    // Tombstone with a live dependent MUST fail with space_has_live_dependents
    // (not yet enforced by soland).
    const tombFail = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: { event: signedEventEnvelope({
          actorId: alice.id,
          realmId,
          kind: "ak.space.tombstone",
          payload: { space_id: parentSpaceId },
        }) },
      },
    );
    expect(tombFail.status()).toBeGreaterThanOrEqual(400);
    expect(wireErrCode(await tombFail.json())).toBe(
      "space_has_live_dependents",
    );
  });

  // ── Phase D — Relation cardinality (PROMOTED).
  // soland's relation reducer (reducer/apply_relations.rs) is fully wired:
  // - has_default_view default cardinality is many_to_one, so a second active
  //   edge from the same from_ref auto-tombstones the prior winner (the
  //   relation list MUST show ≤ 1 active edge).
  // - duplicate (realm_id, relation_kind, from_ref, to_ref) writes dedupe.
  // - structural `contains` across Realms is rejected with
  //   `cross_realm_structural_relation` (HTTP 412) — relation.md §4.4.
  // Reads use the product-private `/_soland/self/relations` projection list.
  test("Phase D — has_default_view enforces many_to_one; duplicate Relation create is idempotent; cross-Realm contains rejected", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s-coinv-d-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `core-invariants D ${stamp}`,
      ownerId: alice.id,
    });

    // `has_default_view` is many_to_one on (from_ref, relation_kind). The
    // relation reducer requires a structural from_ref endpoint
    // (`ak:strand:`/`ak:space:`) to be projected, so anchor the edges on a
    // real Strand created via the proven ak.strand.create path. The
    // `ak:view:` to_ref does not need a local projection (View objects are
    // not reduced today), so two synthetic view ids are valid targets.
    const sourceRef = await createStrandApi(
      request,
      aliceToken,
      alice.id,
      realmId,
      `has_default_view anchor ${stamp}`,
    );
    const v1 = typedId("view");
    const v2 = typedId("view");

    const createDefaultView = async (viewId: string, relationId: string) =>
      submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorId: alice.id,
          realmId,
          kind: "ak.relation.create",
          payload: {
            relation: relationObject({
              realmId,
              relationKind: "has_default_view",
              fromRef: sourceRef,
              toRef: viewId,
              actorId: alice.id,
            }),
          },
        }),
        { context: `has_default_view -> ${viewId}` },
      );

    // First default-view edge succeeds.
    await createDefaultView(v1, typedId("relation"));
    // Second default-view edge for the same source: many_to_one means one
    // edge is auto-tombstoned, leaving exactly 1 active edge. The surviving
    // concurrent mutually exclusive edges cannot acquire active status from
    // digest ordering. The projection exposes at most one active edge and
    // normally none until an explicit complete-head resolution.
    await createDefaultView(v2, typedId("relation"));

    const activeEdges = await request.get(
      `${solandBaseUrl()}/_soland/self/relations?from_ref=${encodeURIComponent(sourceRef)}&relation_kind=has_default_view&state=active`,
      { headers: authHeaders(aliceToken) },
    );
    expect(activeEdges.ok()).toBeTruthy();
    const edgesBody = await activeEdges.json();
    const activeItems = (edgesBody.items ?? []) as Array<{ to_ref?: string }>;
    // many_to_one: at most one active edge for this (from_ref, relation_kind).
    expect(activeItems.length).toBeLessThanOrEqual(1);
    if (activeItems.length === 1) {
      expect([v1, v2]).toContain(activeItems[0].to_ref);
    }

    // A fully-duplicate edge (same relation_id) is idempotent — re-submitting
    // the same signed envelope is accepted by the events submit surface.
    const dupRelationId = typedId("relation");
    const duplicateEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation: relationObject({
          realmId,
          relationKind: "has_default_view",
          fromRef: sourceRef,
          toRef: v2,
          actorId: alice.id,
        }),
      },
    });
    await submitSignedEventApi(request, aliceToken, duplicateEnvelope, {
      context: `create duplicate relation ${dupRelationId}`,
    });
    const dupAgain = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: { ...authHeaders(aliceToken, "POST", `${solandBaseUrl()}/_arkret/self/events`), "content-type": "application/json" },
        data: canonicalJson({ event: duplicateEnvelope }),
      },
    );
    expect(dupAgain.status(), "exact accepted Event replay must remain successful").toBe(200);

    // Cross-Realm structural `contains` MUST fail (relation.md §4.4). Create a
    // strand in another Realm and try to `contains` it from this Realm.
    const realmB = await createRealmApi(request, aliceToken, {
      title: `core-invariants D other ${stamp}`,
      ownerId: alice.id,
    });
    const strandInA = await createStrandApi(
      request,
      aliceToken,
      alice.id,
      realmId,
      `card in A ${stamp}`,
    );
    const strandInB = await createStrandApi(
      request,
      aliceToken,
      alice.id,
      realmB,
      `card in B ${stamp}`,
    );
    const crossRealmEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation: relationObject({
          realmId,
          relationKind: "contains",
          fromRef: strandInA,
          toRef: strandInB,
          actorId: alice.id,
        }),
      },
    });
    await prepareSignedEventCbsApi(request, aliceToken, crossRealmEnvelope);
    await alignSignedEventToActorFrontierApi(
      request,
      aliceToken,
      crossRealmEnvelope,
    );
    const crossRealm = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: { ...authHeaders(aliceToken, "POST", `${solandBaseUrl()}/_arkret/self/events`), "content-type": "application/json" },
        data: canonicalJson({ event: crossRealmEnvelope }),
      },
    );
    expect(crossRealm.status()).toBe(409);
    const crossRealmBody = await crossRealm.json();
    expect(wireErrCode(crossRealmBody), JSON.stringify(crossRealmBody)).toBe(
      "failed_precondition",
    );
    expect(
      crossRealmBody.reason_code ?? crossRealmBody.details?.reason_code,
      JSON.stringify(crossRealmBody),
    ).toBe(
      "cross_realm_structural_relation",
    );
  });
});

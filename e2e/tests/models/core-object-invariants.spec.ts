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
import type {
  ActorId,
  CommitStreamHead,
} from "../../helpers/generated/spec-wire-objects";
import { stepShot } from "../../helpers/screenshots";
import {
  accountActorId,
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  retypeEventDerivedId,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
  readCommitStreamHeadApi,
  scanRealmStreamApi,
} from "../../helpers/soland-api";
import { relationCreatePayload } from "../../helpers/relation-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueUserSession,
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

/// The Realm's accepted commit head, as the probe for "did accepted state
/// advance". A rejected Event produces no RealmCommit, so the head is
/// unchanged by construction.
async function fetchRealmCommitHead(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<CommitStreamHead | undefined> {
  return await readCommitStreamHeadApi(request, token, realmId);
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
      const scan = await scanRealmStreamApi(request, aliceFlow.session.grantJwt, realmId, { limit: 20 });
      const events = scan.events as Array<{
        event_id?: string;
        kind?: string;
        actor_id?: ActorId;
        created_at?: string;
        scope_ref?: { kind?: string; realm_id?: string };
      }>;
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
  // `ak.component.strand.position.v1:<board_space_id>:<strand_id>` sequenced state.
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
    const aliceToken = await issueUserSession(request, alice);
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

    const initialHead = await fetchRealmCommitHead(
      request,
      aliceToken,
      realmId,
    );
    const initialPosition = { list_space_id: sourceListId, rank: "m" };
    const initialMove = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.move",
      payload: {
        board_space_id: boardSpaceId,
        strand_id: strandId,
        target_space_id: sourceListId,
        rank: "m",
      },
    });
    await submitSignedEventApi(request, aliceToken, initialMove, {
      context: "establish initial Strand position",
    });

    await expect
      .poll(() => fetchRealmCommitHead(request, aliceToken, realmId), {
        message:
          "the initial Strand position move advances the Realm commit head",
        timeout: 30_000,
      })
      .not.toEqual(initialHead);
    const acceptedHead = await fetchRealmCommitHead(
      request,
      aliceToken,
      realmId,
    );
    const staleMoveEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.move",
      payload: {
        board_space_id: boardSpaceId,
        strand_id: strandId,
        from_space_id: staleExpectedListId,
        target_space_id: targetListId,
        rank: "z",
        expected_position: { list_space_id: staleExpectedListId, rank: "m" },
      },
    });
    const staleMove = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(aliceToken, "POST", `${solandBaseUrl()}/_arkret/self/events`),
        data: { event: staleMoveEnvelope },
      },
    );
    expect(staleMove.status()).toBe(409);
    expect(wireErrCode(await staleMove.json())).toBe("failed_precondition");

    const headAfterReject = await fetchRealmCommitHead(
      request,
      aliceToken,
      realmId,
    );
    expect(headAfterReject).toEqual(acceptedHead);
    const freshMove = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.move",
      payload: {
        board_space_id: boardSpaceId,
        strand_id: strandId,
        from_space_id: sourceListId,
        target_space_id: targetListId,
        rank: "z",
        expected_position: { list_space_id: sourceListId, rank: "m" },
      },
    });
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
    const aliceToken = await issueUserSession(request, alice);
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
        headers: authHeaders(aliceToken, "POST", `${solandBaseUrl()}/_arkret/self/events`),
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
        headers: authHeaders(aliceToken, "POST", `${solandBaseUrl()}/_arkret/self/events`),
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

  // ── Phase D — Relation primary conflict domain CAS (relation.md section 6).
  // - has_default_view registers a `from` domain: the first create at a
  //   never-written domain (`expected_revision=null`) wins; a second create on
  //   the same active domain is `failed_precondition` with zero writes, so the
  //   relation list shows exactly the first edge. No implicit auto-tombstone.
  // - an exact accepted Event replay returns the original Commit.
  // - structural `contains` across Realms is rejected with
  //   `cross_realm_structural_relation` (HTTP 409) — relation.md section 4.4.
  // Reads use the product-private `/_soland/self/relations` list.
  test("Phase D — has_default_view is one active value per from domain; exact Relation replay is idempotent; cross-Realm contains rejected", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s-coinv-d-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `core-invariants D ${stamp}`,
      ownerId: alice.id,
    });

    const sourceRef = await createStrandApi(
      request,
      aliceToken,
      alice.id,
      realmId,
      `has_default_view anchor ${stamp}`,
    );
    const v1 = typedId("view");
    const v2 = typedId("view");
    const eventsUrl = `${solandBaseUrl()}/_arkret/self/events`;
    const postEvent = (envelope: Record<string, unknown>) =>
      request.post(eventsUrl, {
        headers: {
          ...authHeaders(aliceToken, "POST", eventsUrl),
          "content-type": "application/json",
        },
        data: canonicalJson({ event: envelope }),
      });
    const defaultView = (viewId: string) =>
      signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.relation.create",
        payload: relationCreatePayload({
          relationKind: "has_default_view",
          fromRef: sourceRef,
          toRef: viewId,
        }),
      });

    await submitSignedEventApi(request, aliceToken, defaultView(v1), {
      context: `has_default_view -> ${v1}`,
    });
    const headBeforeSecond = await fetchRealmCommitHead(request, aliceToken, realmId);
    const second = await postEvent(defaultView(v2));
    expect(second.status(), await second.text()).toBe(409);
    expect(wireErrCode(await second.json())).toBe("failed_precondition");
    expect(await fetchRealmCommitHead(request, aliceToken, realmId)).toEqual(
      headBeforeSecond,
    );

    const relationsUrl = `${solandBaseUrl()}/_soland/self/relations?from_ref=${encodeURIComponent(sourceRef)}&relation_kind=has_default_view&state=active`;
    const activeEdges = await request.get(relationsUrl, {
      headers: authHeaders(aliceToken, "GET", relationsUrl),
    });
    expect(activeEdges.ok()).toBeTruthy();
    const activeItems = ((await activeEdges.json()).items ?? []) as Array<{
      to_ref?: string;
    }>;
    expect(activeItems.map((item) => item.to_ref)).toEqual([v1]);

    // An exact accepted Event replay is idempotent and returns the original
    // Commit.
    const duplicateEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.relation.create",
      payload: relationCreatePayload({
        relationKind: "references",
        fromRef: sourceRef,
        toRef: v2,
      }),
    });
    const first = await submitSignedEventApi(request, aliceToken, duplicateEnvelope, {
      context: "create references relation",
    });
    const dupAgain = await postEvent(duplicateEnvelope);
    expect(dupAgain.status(), "exact accepted Event replay must remain successful").toBe(200);
    const replay = (await dupAgain.json()) as Record<string, unknown>;
    expect(replay.status).toBe("duplicate");
    expect(replay.commit).toEqual(first.commit);

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
      payload: relationCreatePayload({
        relationKind: "contains",
        fromRef: strandInA,
        toRef: strandInB,
      }),
    });
    const crossRealm = await postEvent(crossRealmEnvelope);
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

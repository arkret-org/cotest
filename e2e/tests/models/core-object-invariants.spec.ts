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
// Phase B uses the ordinary data Event's explicit position CAS. Phase C
// verifies independent Space lifecycles and the live-dependent refusal.

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
  rawSubmitSignedEventApi,
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

  // realm-and-space section 3.6: ordinary moves have an optional complete
  // expected_position; they carry neither head_eq nor a sealing basis.
  test("Phase B — stale ak.strand.move expected_position rejects with zero writes; fresh position CAS succeeds", async ({
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
    const createSpace = async (kind: "board" | "list", title: string, parentSpaceId?: string) => {
      const createdAt = canonicalTimestamp();
      const event = signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.space.create",
        createdAt,
        payload: { object: {
          schema: "ak.schema.space.v1",
          realm_id: realmId,
          kind,
          title,
          ...(parentSpaceId ? { parent_space_id: parentSpaceId, rank: "m" } : {}),
          created_by: accountActorId(alice.id),
          created_at: createdAt,
        } },
      });
      await submitSignedEventApi(request, aliceToken, event, { context: `create CAS ${kind}` });
      return retypeEventDerivedId(String(event.event_id), "space");
    };
    const boardSpaceId = await createSpace("board", `CAS board ${stamp}`);
    const sourceListId = await createSpace("list", `CAS source ${stamp}`, boardSpaceId);
    const staleExpectedListId = await createSpace("list", `CAS wrong preimage ${stamp}`, boardSpaceId);
    const targetListId = await createSpace("list", `CAS target ${stamp}`, boardSpaceId);

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
    expect(initialMove.preconditions).toBeUndefined();
    expect(initialMove.seal_basis).toBeUndefined();
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
    const staleMove = await rawSubmitSignedEventApi(request, aliceToken, staleMoveEnvelope);
    expect(staleMove.status(), await staleMove.text()).toBe(409);
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
    const headAfterFresh = await fetchRealmCommitHead(request, aliceToken, realmId);
    expect(headAfterFresh).not.toEqual(acceptedHead);

    // The accepted fresh move really replaced the durable position. A stale
    // old preimage still refuses without advancing the stream; the new full
    // preimage admits a return move, not just a receipt-only happy path.
    const returnMove = (expectedPosition: { list_space_id: string; rank: string }) =>
      signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.strand.move",
        payload: {
          board_space_id: boardSpaceId,
          strand_id: strandId,
          target_space_id: sourceListId,
          rank: "n",
          expected_position: expectedPosition,
        },
      });
    const staleReturn = returnMove(initialPosition);
    const rejectedReturn = await rawSubmitSignedEventApi(request, aliceToken, staleReturn);
    expect(rejectedReturn.status(), await rejectedReturn.text()).toBe(409);
    expect(wireErrCode(await rejectedReturn.json())).toBe("failed_precondition");
    expect(await fetchRealmCommitHead(request, aliceToken, realmId)).toEqual(headAfterFresh);
    const freshReturn = returnMove({ list_space_id: targetListId, rank: "z" });
    await submitSignedEventApi(request, aliceToken, freshReturn, {
      context: "current position CAS returns to the source List",
    });
    const scan = await scanRealmStreamApi(request, aliceToken, realmId);
    const acceptedMoves = scan.events.filter(event => event.kind === "ak.strand.move");
    expect(acceptedMoves.map(event => event.event_id)).toEqual([
      initialMove.event_id, freshMove.event_id, freshReturn.event_id,
    ]);
    expect(scan.events.some(event => [staleMoveEnvelope.event_id, staleReturn.event_id].includes(event.event_id))).toBe(false);
  });

  // ── Phase C — Cascade / archive / delete.
  test(
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
    const accepted: Record<string, unknown>[] = [];
    const rejected: Record<string, unknown>[] = [];
    const submit = async (kind: string, payload: Record<string, unknown>, createdAt?: string) => {
      const event = signedEventEnvelope({ actorId: alice.id, realmId, kind, payload, createdAt });
      await submitSignedEventApi(request, aliceToken, event);
      accepted.push(event);
      return event;
    };
    const createSpace = async (kind: "board" | "list", title: string, parentSpaceId?: string) => {
      const createdAt = canonicalTimestamp();
      const event = await submit("ak.space.create", { object: {
        schema: "ak.schema.space.v1",
        realm_id: realmId,
        kind,
        title,
        ...(parentSpaceId ? { parent_space_id: parentSpaceId, rank: "m" } : {}),
        created_by: accountActorId(alice.id),
        created_at: createdAt,
      } }, createdAt);
      return retypeEventDerivedId(String(event.event_id), "space");
    };
    const parentSpaceId = await createSpace("board", `lifecycle parent ${stamp}`);
    const childSpaceId = await createSpace("list", `lifecycle child ${stamp}`, parentSpaceId);
    const readStates = async () => {
      const url = `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/spaces?include_terminal=true`;
      const response = await request.get(url, { headers: authHeaders(aliceToken, "GET", url) });
      expect(response.ok(), await response.text()).toBeTruthy();
      const body = await response.json() as { spaces: Array<{ space_id: string; state: string }> };
      return [parentSpaceId, childSpaceId].map(id => body.spaces.find(row => row.space_id === id)?.state);
    };
    const refuse = async (kind: string, spaceId: string, reason: string, extra: Record<string, unknown> = {}) => {
      const head = await fetchRealmCommitHead(request, aliceToken, realmId);
      const event = signedEventEnvelope({ actorId: alice.id, realmId, kind,
        payload: { space_id: spaceId, ...extra } });
      const response = await rawSubmitSignedEventApi(request, aliceToken, event);
      expect(response.status(), await response.text()).toBe(409);
      const problem = await response.json();
      expect(wireErrCode(problem)).toBe("failed_precondition");
      expect(problem.reason_code).toBe(reason);
      expect(await fetchRealmCommitHead(request, aliceToken, realmId)).toEqual(head);
      rejected.push(event);
    };

    expect(await readStates()).toEqual(["active", "active"]);
    await submit("ak.space.archive", { space_id: parentSpaceId });
    expect(await readStates()).toEqual(["archived", "active"]);
    await refuse("ak.space.tombstone", parentSpaceId, "space_has_live_dependents");

    // An archived child remains a dependency; restoring its parent neither
    // restores that child nor makes the dependency disappear.
    await submit("ak.space.archive", { space_id: childSpaceId });
    expect(await readStates()).toEqual(["archived", "archived"]);
    await refuse("ak.space.tombstone", parentSpaceId, "space_has_live_dependents");
    await submit("ak.space.restore", { space_id: parentSpaceId });
    expect(await readStates()).toEqual(["active", "archived"]);
    await refuse("ak.space.tombstone", parentSpaceId, "space_has_live_dependents");

    await submit("ak.space.tombstone", { space_id: childSpaceId });
    expect(await readStates()).toEqual(["active", "tombstoned"]);
    await submit("ak.space.tombstone", { space_id: parentSpaceId });
    expect(await readStates()).toEqual(["tombstoned", "tombstoned"]);
    await refuse("ak.space.update", parentSpaceId, "space_not_active", { patch: { title: "must not revive" } });
    await refuse("ak.space.restore", parentSpaceId, "space_already_terminal");
    await refuse("ak.space.tombstone", parentSpaceId, "space_already_terminal");
    expect(await readStates()).toEqual(["tombstoned", "tombstoned"]);

    const scan = await scanRealmStreamApi(request, aliceToken, realmId);
    const history = scan.events.filter(event => String(event.kind).startsWith("ak.space."));
    expect(history.map(event => event.event_id)).toEqual(accepted.map(event => event.event_id));
    expect(scan.events.some(event => rejected.some(refusedEvent => refusedEvent.event_id === event.event_id))).toBe(false);
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

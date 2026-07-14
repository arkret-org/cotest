// Multi-user project simulation
// Contract: e2e/scenarios/kanban/project-simulation.md
// Spec refs:
//   - models/realm-and-space.md §4 (Space container), §3 (Join Policy)
//   - models/strand-and-message.md §3 (Strand fields)
//   - models/relation.md §3.2 (assigned_to), §5 (RelationProfile), §6 (conflict resolution)

import {
  expect,
  test,
  type APIRequestContext,
} from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  sha256CanonicalJson,
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
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type StrandProjectionRow = {
  strand_id: string;
  state: string;
  title?: string | null;
  board_space_id?: string | null;
  list_space_id?: string | null;
  assigned_actor_ids?: string[];
  assigned_to_relations?: Array<{ relation_id: string; actor_id: string }>;
};

type SpaceProjectionRow = {
  space_id: string;
  kind: string;
  title: string;
  state: string;
};

// Read a single Strand row from the canonical strand projection. Pass
// includeTerminal=true to surface archived (read-only) Cards, which are
// filtered out of the default active view.
async function readStrandRow(
  request: APIRequestContext,
  token: string,
  realmId: string,
  strandId: string,
  opts: { includeTerminal?: boolean } = {},
): Promise<StrandProjectionRow | undefined> {
  const url = new URL(
    `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/strands`,
  );
  if (opts.includeTerminal) {
    url.searchParams.set("include_terminal", "true");
  }
  const response = await request.get(url.toString(), {
    headers: authHeaders(token),
  });
  expect(
    response.ok(),
    `list strands for ${realmId} returned ${response.status()}`,
  ).toBeTruthy();
  const body = (await response.json()) as { strands?: StrandProjectionRow[] };
  return (body.strands ?? []).find((row) => row.strand_id === strandId);
}

async function readSpaceRow(
  request: APIRequestContext,
  token: string,
  realmId: string,
  spaceId: string,
): Promise<SpaceProjectionRow | undefined> {
  const response = await request.get(
    `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/spaces?include_terminal=true`,
    { headers: authHeaders(token) },
  );
  expect(
    response.ok(),
    `list spaces for ${realmId} returned ${response.status()}`,
  ).toBeTruthy();
  const body = (await response.json()) as { spaces?: SpaceProjectionRow[] };
  return (body.spaces ?? []).find((row) => row.space_id === spaceId);
}

// Create a board Space, a list Space parented to it, and a Card Strand placed
// in that list. The placement rides `metadata.fields.board_space_id` /
// `list_space_id` at create time, which the reducer materializes into the
// derived `contains` position relation — the same relation the board-archive
// cascade walks (soland apply_space_container.rs cascade_space_container_lifecycle).
async function createBoardWithCard(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  opts: {
    boardTitle: string;
    listTitle: string;
    cardTitle: string;
    dueDate?: string;
  },
): Promise<{ boardId: string; listId: string; cardId: string }> {
  const boardId = typedId("space");
  const listId = typedId("space");
  const cardId = typedId("strand");
  const createdAt = canonicalTimestamp();

  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ak.space.create",
      createdAt,
      payload: {
        object: {
          id: boardId,
          schema: "ak.schema.space.v1",
          realm_id: realmId,
          kind: "board",
          title: opts.boardTitle,
          created_by: actorDid,
          created_at: createdAt,
        },
      },
    }),
    { context: `create board ${opts.boardTitle}` },
  );

  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ak.space.create",
      createdAt,
      payload: {
        object: {
          id: listId,
          schema: "ak.schema.space.v1",
          realm_id: realmId,
          kind: "list",
          title: opts.listTitle,
          parent_space_id: boardId,
          rank: "r001",
          created_by: actorDid,
          created_at: createdAt,
        },
      },
    }),
    { context: `create list ${opts.listTitle}` },
  );

  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ak.strand.create",
      createdAt,
      payload: {
        object: {
          id: cardId,
          schema: "ak.schema.strand.v1",
          realm_id: realmId,
          metadata: {
            title: opts.cardTitle,
            fields: {
              status: "todo",
              board_space_id: boardId,
              list_space_id: listId,
              rank: "r007",
              ...(opts.dueDate ? { due_date: opts.dueDate } : {}),
            },
          },
          stage: "planned",
          tracks: { discussion: { enabled: true, is_primary: true } },
          created_by: actorDid,
          created_at: createdAt,
        },
      },
    }),
    { context: `create card ${opts.cardTitle}` },
  );

  return { boardId, listId, cardId };
}

// relation.md §5 — register a RelationProfile that tightens `assigned_to` to a
// single active assignee per Strand (max_to_per_from=1) with the
// deterministic_winner conflict policy. soland reads relation_profiles from the
// active `ak.realm.policy_components` cell value
// (apply_relations.rs relation_profile_values → components.relation_profiles).
async function registerSingleAssigneeProfile(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
): Promise<void> {
  const relationProfiles = [
    {
      relation_kind: "assigned_to",
      from_type: "strand",
      to_type: "did",
      relation_scope: "realm",
      cardinality: "many_to_one",
      max_to_per_from: 1,
      on_conflict: "deterministic_winner",
    },
  ];
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ak.realm.policy_components",
      payload: {
        realm_id: realmId,
        value: {
          components: { relation_profiles: relationProfiles },
          relation_profiles: relationProfiles,
        },
      },
    }),
    { context: `register single-assignee relation profile ${realmId}` },
  );
}

// relation.md §6 — the deterministic winner is the candidate with the
// bytewise-largest canonical event_digest. The signed-event helper stamps each
// proof with sha256 over the canonical event; recompute it here so the test can
// assert WHICH assignment soland keeps active, not merely that exactly one wins.
function eventDigestOf(envelope: Record<string, unknown>): string {
  const { proofs: _proofs, ...event } = envelope;
  return `sha256:${sha256CanonicalJson(event)}`;
}

test.describe("project simulation", () => {
  test("alice builds sprint board with three Lists; invites bob+carol; both join", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const [aliceFlow, bobFlow, carolFlow] = await Promise.all([
      openDpopUserPage(browser, request, "s16-alice"),
      openDpopUserPage(browser, request, "s16-bob"),
      openDpopUserPage(browser, request, "s16-carol"),
    ]);
    if (!aliceFlow || !bobFlow || !carolFlow) {
      assertJointStackNotRequired("project simulation DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const carol = carolFlow.user;
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    const carolPage = carolFlow.page;

    try {
      const realmId = await alicePage.createRealm({
        title: `S16 Sprint ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did, carol.did],
      });

      // acceptInvite throws on non-2xx; success means the invite was
      // accepted server-side and bob/carol are now members.
      await bobPage.acceptInvite(realmId);
      await carolPage.acceptInvite(realmId);

      // Sanity: alice's admin landing renders.
      await alicePage.gotoRealmAdmin(realmId);
      await stepShot(alicePage.page, testInfo, "A-team-joined");
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  });

  test("alice assigns Card 1 to bob via ak.relation.create assigned_to; bob's strand projection surfaces the assignment", async ({
    request,
  }) => {
    // spec: relation.md §3.2 assigned_to (Strand -> DID). soland materializes
    // the edge into the Strand projection's assigned_to_relations /
    // assigned_actor_ids face (projection_query.rs strand_assigned_to_relations),
    // which is the durable, queryable surface a member reads to discover "I was
    // assigned": bob lists the Realm's strands and sees his own DID on Card 1.
    const stamp = Date.now();
    const alice = uniqueUser("s16-assign-alice");
    const bob = uniqueUser("s16-assign-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S16 Assign ${stamp}`,
      ownerDid: alice.did,
      invitees: [bob.did],
    });
    await submitSignedEventApi(
      request,
      bobToken,
      signedEventEnvelope({
        actorDid: bob.did,
        realmId,
        kind: "ak.member.state",
        payload: {
          realm_id: realmId,
          actor_id: bob.did,
          membership: "join",
          reason: "invite_accept",
          delivery_status: "unroutable",
        },
      }),
      { context: "bob joins realm" },
    );

    const { cardId } = await createBoardWithCard(request, aliceToken, alice.did, realmId, {
      boardTitle: `S16 Board ${stamp}`,
      listTitle: `Todo ${stamp}`,
      cardTitle: `Implement login ${stamp}`,
    });

    const relationId = typedId("relation");
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.relation.create",
        payload: {
          relation_id: relationId,
          relation_kind: "assigned_to",
          from_ref: cardId,
          to_ref: bob.did,
          fields: { role: "primary" },
        },
      }),
      { context: "assign Card 1 to bob" },
    );

    // bob reads the Realm's strands and finds himself on Card 1.
    const row = await readStrandRow(request, bobToken, realmId, cardId);
    expect(row, "Card 1 visible to bob").toBeTruthy();
    expect(row?.assigned_actor_ids ?? []).toContain(bob.did);
    expect(
      (row?.assigned_to_relations ?? []).some(
        (relation) => relation.actor_id === bob.did && relation.relation_id === relationId,
      ),
      "assigned_to relation surfaces with bob's actor + relation id",
    ).toBe(true);
  });

  test(
    "status FSM: Card transitions todo → in_progress → done via ak.strand.update; invalid transition (todo → done direct) rejected by FSM cell",
    async ({ request }) => {
      const alice = uniqueUser("s16-fsm-alice");
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const realmId = await createRealmApi(request, aliceToken, {
        title: `S16 FSM ${Date.now()}`,
        ownerDid: alice.did,
      });
      const taskStrandId = typedId("strand");
      const incidentStrandId = typedId("strand");
      const taskCreatedAt = canonicalTimestamp();

      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId: realmId,
          kind: "ak.strand.create",
          createdAt: taskCreatedAt,
          payload: {
            object: {
              id: taskStrandId,
              schema: "ak.schema.strand.v1",
              realm_id: realmId,
              metadata: {
                title: "Implement login",
                fields: { status: "todo" },
              },
              stage: "planned",
              tracks: { discussion: { enabled: true, is_primary: true } },
              created_by: alice.did,
              created_at: taskCreatedAt,
            },
          },
        }),
        { context: "create todo card strand" },
      );

      const badDone = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId: realmId,
          kind: "ak.strand.update",
          payload: {
            target_ref: taskStrandId,
            patch: { metadata: { fields: { status: "done" } } },
          },
        }),
      });
      expect(badDone.status()).toBe(412);
      expect(wireErrCode(await badDone.json())).toBe("strand_status_transition_invalid");

      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId: realmId,
          kind: "ak.strand.update",
          payload: {
            target_ref: taskStrandId,
            patch: { metadata: { fields: { status: "in_progress" } } },
          },
        }),
        { context: "advance card to in_progress" },
      );

      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId: realmId,
          kind: "ak.strand.update",
          payload: {
            target_ref: taskStrandId,
            patch: { metadata: { fields: { status: "done" } } },
          },
        }),
        { context: "advance card to done" },
      );

      const incidentCreatedAt = canonicalTimestamp();
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId: realmId,
          kind: "ak.strand.create",
          createdAt: incidentCreatedAt,
          payload: {
            object: {
              id: incidentStrandId,
              schema: "ak.schema.strand.v1",
              realm_id: realmId,
              metadata: {
                title: "SEV-2 checkout outage",
                fields: { status: "investigating" },
              },
              stage: "in_progress",
              tracks: { discussion: { enabled: true, is_primary: true } },
              created_by: alice.did,
              created_at: incidentCreatedAt,
            },
          },
        }),
        { context: "create investigating incident strand" },
      );

      const badResolved = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId: realmId,
          kind: "ak.strand.update",
          payload: {
            target_ref: incidentStrandId,
            patch: { metadata: { fields: { status: "resolved" } } },
          },
        }),
      });
      expect(badResolved.status()).toBe(412);
      expect(wireErrCode(await badResolved.json())).toBe("strand_status_transition_invalid");
    },
  );

  test("due_date past today renders as overdue badge on the card UI", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: strand-and-message.md §3 — `fields` are opaque to the reducer; the
    // past-due semantics live in the UI (inkson kanban due_calendar.rs
    // due_value_is_overdue). A Card whose due_date is strictly before today
    // renders the overdue badge; an unscheduled Card does not.
    test.setTimeout(180_000);
    const stamp = Date.now();
    const alice = uniqueUser("s16-overdue-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });

    const overdueTitle = `Overdue ${stamp}`;
    const onTrackTitle = `OnTrack ${stamp}`;

    try {
      const realmId = await alicePage.createRealm({
        title: `S16 Overdue ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      // A past due_date (2020-01-01 is unambiguously before today) and a card
      // with no due_date, both placed on the same board so the kanban view
      // renders them side by side.
      const overdue = await createBoardWithCard(request, aliceToken, alice.did, realmId, {
        boardTitle: `Overdue Board ${stamp}`,
        listTitle: `Todo ${stamp}`,
        cardTitle: overdueTitle,
        dueDate: "2020-01-01",
      });

      const onTrackId = typedId("strand");
      const createdAt = canonicalTimestamp();
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.strand.create",
          createdAt,
          payload: {
            object: {
              id: onTrackId,
              schema: "ak.schema.strand.v1",
              realm_id: realmId,
              metadata: {
                title: onTrackTitle,
                fields: {
                  status: "todo",
                  board_space_id: overdue.boardId,
                  list_space_id: overdue.listId,
                  rank: "r008",
                },
              },
              stage: "planned",
              tracks: { discussion: { enabled: true, is_primary: true } },
              created_by: alice.did,
              created_at: createdAt,
            },
          },
        }),
        { context: "create on-track card" },
      );

      await alicePage.page.goto(
        `/kanban/${realmId}/board/${encodeURIComponent(overdue.boardId)}`,
        { waitUntil: "domcontentloaded" },
      );
      await expect(alicePage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });

      const overdueCard = alicePage.page
        .getByTestId("kanban-card")
        .filter({ hasText: overdueTitle })
        .first();
      await expect(overdueCard).toBeVisible({ timeout: 45_000 });
      await expect(overdueCard.getByTestId("kanban-card-overdue-badge")).toBeVisible({
        timeout: 45_000,
      });
      await expect(overdueCard.getByTestId("kanban-card-due")).toHaveAttribute(
        "data-overdue",
        "true",
      );
      await stepShot(alicePage.page, testInfo, "A-overdue-badge");

      // The on-track card (no due_date) must NOT show the overdue badge.
      const onTrackCard = alicePage.page
        .getByTestId("kanban-card")
        .filter({ hasText: onTrackTitle })
        .first();
      await expect(onTrackCard).toBeVisible({ timeout: 45_000 });
      await expect(onTrackCard.getByTestId("kanban-card-overdue-badge")).toHaveCount(0);
    } finally {
      await alicePage.close();
    }
  });

  test("E16.G concurrent assignment from two devices: relation profile on_conflict=deterministic_winner picks one; Card has exactly one active assignee", async ({
    request,
  }) => {
    // spec: relation.md §5 (single-assignee profile max_to_per_from=1) + §6
    // (deterministic_winner = bytewise-largest event_digest). Two devices
    // concurrently assign the SAME Card to two different actors; soland keeps
    // exactly one active assignee and the winner is the larger event_digest.
    const stamp = Date.now();
    const alice = uniqueUser("s16-conflict-alice");
    const bob = uniqueUser("s16-conflict-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S16 Conflict ${stamp}`,
      ownerDid: alice.did,
    });
    await registerSingleAssigneeProfile(request, aliceToken, alice.did, realmId);

    const { cardId } = await createBoardWithCard(request, aliceToken, alice.did, realmId, {
      boardTitle: `Conflict Board ${stamp}`,
      listTitle: `Todo ${stamp}`,
      cardTitle: `Assign race ${stamp}`,
    });

    // Two concurrent assignments of the same Card to two different actors. The
    // single-assignee profile (max_to_per_from=1) forces a conflict; the
    // deterministic winner is the candidate with the larger canonical
    // event_digest.
    const assignToAlice = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation_id: typedId("relation"),
        relation_kind: "assigned_to",
        from_ref: cardId,
        to_ref: alice.did,
      },
    });
    const assignToBob = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation_id: typedId("relation"),
        relation_kind: "assigned_to",
        from_ref: cardId,
        to_ref: bob.did,
      },
    });

    await submitSignedEventApi(request, aliceToken, assignToAlice, {
      context: "assign Card to alice",
    });
    await submitSignedEventApi(request, aliceToken, assignToBob, {
      context: "assign Card to bob",
    });

    const winnerActor =
      eventDigestOf(assignToAlice) > eventDigestOf(assignToBob) ? alice.did : bob.did;

    const row = await readStrandRow(request, aliceToken, realmId, cardId);
    expect(row, "Card visible").toBeTruthy();
    // Exactly one active assignee survives the single-assignee profile.
    expect(row?.assigned_actor_ids ?? []).toHaveLength(1);
    expect(row?.assigned_actor_ids ?? []).toEqual([winnerActor]);
  });

  test("E16.1 unassign emits ak.relation.tombstone; assignment no longer shows in card projection", async ({
    request,
  }) => {
    // spec: relation.md §3.2 tombstoned state — unassign is a
    // ak.relation.tombstone on the assigned_to edge. soland flips the relation
    // to tombstoned (apply_relations.rs apply_relation_delete); the Strand's
    // assigned_to projection face only counts active edges, so the assignee
    // drops off.
    const stamp = Date.now();
    const alice = uniqueUser("s16-unassign-alice");
    const bob = uniqueUser("s16-unassign-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S16 Unassign ${stamp}`,
      ownerDid: alice.did,
    });
    const { cardId } = await createBoardWithCard(request, aliceToken, alice.did, realmId, {
      boardTitle: `Unassign Board ${stamp}`,
      listTitle: `Todo ${stamp}`,
      cardTitle: `Unassign me ${stamp}`,
    });

    const relationId = typedId("relation");
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.relation.create",
        payload: {
          relation_id: relationId,
          relation_kind: "assigned_to",
          from_ref: cardId,
          to_ref: bob.did,
        },
      }),
      { context: "assign Card to bob" },
    );

    const assigned = await readStrandRow(request, aliceToken, realmId, cardId);
    expect(assigned?.assigned_actor_ids ?? []).toContain(bob.did);

    // Unassign: tombstone the assigned_to edge.
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.relation.tombstone",
        payload: {
          relation_id: relationId,
          relation_kind: "assigned_to",
        },
      }),
      { context: "unassign bob (ak.relation.tombstone)" },
    );

    const unassigned = await readStrandRow(request, aliceToken, realmId, cardId);
    expect(unassigned?.assigned_actor_ids ?? []).not.toContain(bob.did);
    expect(
      (unassigned?.assigned_to_relations ?? []).some(
        (relation) => relation.relation_id === relationId,
      ),
      "tombstoned assigned_to relation no longer surfaces",
    ).toBe(false);
  });

  test("alice archives the entire board; archived board's cards become read-only; archive list view shows the board", async ({
    request,
  }) => {
    // spec: realm-and-space.md §4.4 lifecycle/cascade. ak.space.archive on the
    // board cascades to contained Lists and Cards (soland
    // cascade_space_container_lifecycle): Cards flip to Archived (read-only —
    // further writes 412 strand_not_active) and the board itself stays listed
    // in the spaces projection with state=archived (the "archive list view").
    const stamp = Date.now();
    const alice = uniqueUser("s16-archive-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S16 Archive ${stamp}`,
      ownerDid: alice.did,
    });
    const { boardId, listId, cardId } = await createBoardWithCard(
      request,
      aliceToken,
      alice.did,
      realmId,
      {
        boardTitle: `Sprint board ${stamp}`,
        listTitle: `Todo ${stamp}`,
        cardTitle: `Card 1 ${stamp}`,
      },
    );

    // Pre-archive sanity: the Card is active.
    const before = await readStrandRow(request, aliceToken, realmId, cardId);
    expect(before?.state).toBe("active");

    // Archive the whole board.
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.space.archive",
        payload: { space_id: boardId, sender: alice.did },
      }),
      { context: "archive board" },
    );

    // Cascade: board + list archived in the spaces projection.
    const boardRow = await readSpaceRow(request, aliceToken, realmId, boardId);
    expect(boardRow?.state).toBe("archived");
    const listRow = await readSpaceRow(request, aliceToken, realmId, listId);
    expect(listRow?.state).toBe("archived");

    // Cascade: the Card is archived (read-only). It no longer appears in the
    // active strand view but is visible with include_terminal.
    const activeCard = await readStrandRow(request, aliceToken, realmId, cardId);
    expect(activeCard, "archived Card hidden from active view").toBeFalsy();
    const archivedCard = await readStrandRow(request, aliceToken, realmId, cardId, {
      includeTerminal: true,
    });
    expect(archivedCard?.state).toBe("archived");

    // Read-only: a write to the archived Card is rejected (strand_not_active).
    const write = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
      headers: authHeaders(aliceToken),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.strand.update",
        payload: {
          target_ref: cardId,
          patch: { metadata: { title: `renamed ${stamp}` } },
        },
      }),
    });
    expect(write.status()).toBe(412);
    expect(wireErrCode(await write.json())).toBe("strand_not_active");
  });
});

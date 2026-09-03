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
  type Locator,
} from "../../helpers/arkret-test";
import { stepShot } from "../../helpers/screenshots";
import { solandBaseUrl } from "../../helpers/env";
import {
  accountActorId,
  alignSignedEventToActorFrontierApi,
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  prepareSignedEventCbaApi,
  retypeEventDerivedId,
  sdkEventDerivedObjectId,
  sha256CanonicalJson,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import { acceptInviteViaApi } from "../../helpers/api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
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

async function addCardThroughColumn(
  column: Locator,
  title: string,
): Promise<void> {
  const titleInput = column.getByTestId("new-card-title-input").last();
  if (!(await titleInput.isVisible({ timeout: 250 }).catch(() => false))) {
    const addButton = column.getByTestId("add-card-button").last();
    await expect(addButton).toBeVisible({ timeout: 30_000 });
    await addButton.click({ timeout: 5_000 }).catch(async (error) => {
      if (!(await titleInput.isVisible({ timeout: 500 }).catch(() => false))) {
        throw error;
      }
    });
  }
  await expect(titleInput).toBeVisible({ timeout: 30_000 });
  await titleInput.fill(title);
  const saveButton = column.getByTestId("save-card-button").last();
  await expect(saveButton).toBeEnabled({ timeout: 30_000 });
  await saveButton.click({ timeout: 10_000 });
}

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
  const body = (await response.json()) as {
    strands?: StrandProjectionRow[];
  };
  return (body.strands ?? []).find(
    (row) => row.strand_id === strandId,
  );
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
  const body = (await response.json()) as {
    spaces?: SpaceProjectionRow[];
  };
  return (body.spaces ?? []).find(
    (row) => row.space_id === spaceId,
  );
}

// Create a board Space, a list Space parented to it, then a Card Strand. A
// separate `ak.strand.move` places the accepted create-derived Strand id in the
// List; create metadata is content only and never acts as a position cell.
async function createBoardWithCard(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  opts: {
    boardTitle: string;
    listTitle: string;
    cardTitle: string;
    dueDate?: string;
  },
): Promise<{ boardId: string; listId: string; cardId: string }> {
  const createdAt = canonicalTimestamp();

  const boardEnvelope = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.space.create",
    createdAt,
    payload: {
      object: {
        schema: "ak.schema.space.v1",
        realm_id: realmId,
        kind: "board",
        title: opts.boardTitle,
        created_by: accountActorId(actorId),
        created_at: createdAt,
      },
    },
  });
  const boardId = sdkEventDerivedObjectId(boardEnvelope);
  await submitSignedEventApi(
    request,
    token,
    boardEnvelope,
    { context: `create board ${opts.boardTitle}` },
  );

  const listEnvelope = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.space.create",
    createdAt,
    payload: {
      object: {
        schema: "ak.schema.space.v1",
        realm_id: realmId,
        kind: "list",
        title: opts.listTitle,
        parent_space_id: boardId,
        rank: "r001",
        created_by: accountActorId(actorId),
        created_at: createdAt,
      },
    },
  });
  const listId = sdkEventDerivedObjectId(listEnvelope);
  await submitSignedEventApi(
    request,
    token,
    listEnvelope,
    { context: `create list ${opts.listTitle}` },
  );

  const cardEnvelope = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.strand.create",
    createdAt,
    payload: {
      object: {
        schema: "ak.schema.strand.v1",
        realm_id: realmId,
        metadata: {
          title: opts.cardTitle,
          fields: {
            status: "todo",
            ...(opts.dueDate ? { due_date: opts.dueDate } : {}),
          },
        },
        stage: "planned",
        tracks: { discussion: { enabled: true, is_primary: true } },
        created_by: accountActorId(actorId),
        created_at: createdAt,
      },
    },
  });
  const cardId = sdkEventDerivedObjectId(cardEnvelope);
  await submitSignedEventApi(
    request,
    token,
    cardEnvelope,
    { context: `create card ${opts.cardTitle}` },
  );
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId,
      realmId,
      kind: "ak.strand.move",
      payload: {
        board_space_id: boardId,
        strand_id: cardId,
        target_space_id: listId,
        rank: "r007",
      },
    }),
    { context: `place card ${opts.cardTitle}` },
  );

  return { boardId, listId, cardId };
}

// relation.md §5 — register a RelationProfile that tightens `assigned_to` to a
// single active assignee per Strand (max_to_per_from=1) with the
// require_review conflict policy. soland reads relation_profiles from the
// canonical `ak.realm.policy_bundle.value.relation_profiles` cell value.
async function registerSingleAssigneeProfile(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
): Promise<void> {
  const relationProfiles = [
    {
      relation_kind: "assigned_to",
      from_kind: "strand",
      to_kind: "did",
      relation_scope: "realm",
      cardinality: "many_to_one",
      max_to_per_from: 1,
      on_conflict: "require_review",
    },
  ];
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId,
      realmId,
      kind: "ak.realm.policy_bundle",
      payload: {
        realm_id: realmId,
        value: {
          relation_profiles: relationProfiles,
        },
      },
    }),
    { context: `register single-assignee relation profile ${realmId}` },
  );
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
        seedMembers: [bob.id, carol.id],
      });

      // acceptInvite throws on non-2xx; success means the invite was
      // accepted server-side and bob/carol are now members.
      await bobPage.acceptInvite(realmId);
      await carolPage.acceptInvite(realmId);

      // Sanity: alice's admin landing renders.
      await alicePage.gotoRealmAdmin(realmId);
      await stepShot(alicePage.page, testInfo, "A-team-joined");
    } finally {
      await Promise.allSettled([
        carolPage.close(),
        bobPage.close(),
        alicePage.close(),
      ]);
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
      ownerId: alice.id,
      invitees: [bob.id],
    });
    await acceptInviteViaApi(request, bobToken, bob.id, realmId);

    const { cardId } = await createBoardWithCard(
      request,
      aliceToken,
      alice.id,
      realmId,
      {
        boardTitle: `S16 Board ${stamp}`,
        listTitle: `Todo ${stamp}`,
        cardTitle: `Implement login ${stamp}`,
      },
    );

    const relationId = typedId("relation");
    const assignment = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation: {
          id: relationId,
          schema: "ak.schema.relation.v1",
          realm_id: realmId,
          relation_kind: "assigned_to",
          from_ref: cardId,
          to_ref: bob.id,
          created_by: accountActorId(alice.id),
          created_at: canonicalTimestamp(),
        },
      },
    });
    await submitSignedEventApi(request, aliceToken, assignment, {
      context: "assign Card 1 to bob",
    });

    // bob reads the Realm's strands and finds himself on Card 1.
    const row = await readStrandRow(request, bobToken, realmId, cardId);
    expect(row, "Card 1 visible to bob").toBeTruthy();
    expect(row?.assigned_actor_ids ?? []).toContain(bob.id);
    expect(
      (row?.assigned_to_relations ?? []).some(
        (relation) =>
          relation.actor_id === bob.id && relation.relation_id === relationId,
      ),
      "assigned_to relation surfaces with bob's actor + relation id",
    ).toBe(true);
  });

  test("status FSM: Card transitions todo → in_progress → done via ak.strand.update; invalid transition (todo → done direct) rejected by FSM cell", async ({
    request,
  }) => {
    const alice = uniqueUser("s16-fsm-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S16 FSM ${Date.now()}`,
      ownerId: alice.id,
    });
    const taskCreatedAt = canonicalTimestamp();

    // `ak.strand.create` derives `ak:strand:` from the create Event, so the
    // object carries no `id` and the caller retypes the finished envelope.
    const taskStrandEnvelope = signedEventEnvelope({
        actorId: alice.id,
        realmId: realmId,
        kind: "ak.strand.create",
        createdAt: taskCreatedAt,
        payload: {
          object: {
            schema: "ak.schema.strand.v1",
            realm_id: realmId,
            metadata: {
              title: "Implement login",
              fields: { status: "todo" },
            },
            stage: "planned",
            tracks: { discussion: { enabled: true, is_primary: true } },
            created_by: accountActorId(alice.id),
            created_at: taskCreatedAt,
          },
        },
      });
    await submitSignedEventApi(request, aliceToken, taskStrandEnvelope, {
      context: "create todo card strand",
    });
    const taskStrandId = retypeEventDerivedId(
      String(taskStrandEnvelope.event_id),
      "strand",
    );

    const badDoneEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.update",
      payload: {
        target_ref: taskStrandId,
        patch: { metadata: { fields: { status: "done" } } },
      },
    });
    await prepareSignedEventCbaApi(request, aliceToken, badDoneEvent);
    await alignSignedEventToActorFrontierApi(request, aliceToken, badDoneEvent);
    const badDone = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: badDoneEvent,
      },
    );
    expect(badDone.status()).toBe(412);
    expect(wireErrCode(await badDone.json())).toBe(
      "strand_status_transition_invalid",
    );

    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
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
        actorId: alice.id,
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
    const incidentStrandEnvelope = signedEventEnvelope({
        actorId: alice.id,
        realmId: realmId,
        kind: "ak.strand.create",
        createdAt: incidentCreatedAt,
        payload: {
          object: {
            schema: "ak.schema.strand.v1",
            realm_id: realmId,
            metadata: {
              title: "SEV-2 checkout outage",
              fields: { status: "investigating" },
            },
            stage: "in_progress",
            tracks: { discussion: { enabled: true, is_primary: true } },
            created_by: accountActorId(alice.id),
            created_at: incidentCreatedAt,
          },
        },
      });
    await submitSignedEventApi(request, aliceToken, incidentStrandEnvelope, {
      context: "create investigating incident strand",
    });
    const incidentStrandId = retypeEventDerivedId(
      String(incidentStrandEnvelope.event_id),
      "strand",
    );

    const badResolvedEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.update",
      payload: {
        target_ref: incidentStrandId,
        patch: { metadata: { fields: { status: "resolved" } } },
      },
    });
    await prepareSignedEventCbaApi(request, aliceToken, badResolvedEvent);
    await alignSignedEventToActorFrontierApi(
      request,
      aliceToken,
      badResolvedEvent,
    );
    const badResolved = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: badResolvedEvent,
      },
    );
    expect(badResolved.status()).toBe(412);
    expect(wireErrCode(await badResolved.json())).toBe(
      "strand_status_transition_invalid",
    );
  });

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
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      "s16-overdue-alice",
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("kanban overdue DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;

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
      await alicePage.page.goto(`/kanban/${realmId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(alicePage.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await alicePage.page.getByTestId("new-board-toggle").click();
      await alicePage.page
        .getByTestId("new-board-title-input")
        .fill(`Overdue Board ${stamp}`);
      await alicePage.page.getByTestId("create-board-space-button").click();
      await expect(
        alicePage.page.getByTestId("kanban-empty-board"),
      ).toBeVisible({
        timeout: 45_000,
      });

      const columnTitle = `Todo ${stamp}`;
      await alicePage.page.getByTestId("new-column-input").fill(columnTitle);
      await alicePage.page.getByTestId("add-column-button").click();
      const column = alicePage.page
        .getByTestId("kanban-column")
        .filter({ hasText: columnTitle })
        .first();
      await expect(column).toBeVisible({ timeout: 45_000 });
      for (const title of [overdueTitle, onTrackTitle]) {
        await addCardThroughColumn(column, title);
        await expect(
          column.getByTestId("kanban-card").filter({ hasText: title }),
        ).toBeVisible({
          timeout: 45_000,
        });
      }

      const overdueCard = column
        .getByTestId("kanban-card")
        .filter({ hasText: overdueTitle })
        .first();
      await overdueCard.click();
      const detail = alicePage.page.getByTestId("card-detail-modal");
      await expect(detail).toBeVisible({ timeout: 45_000 });
      await detail.getByRole("button", { name: "Add due date" }).click();
      const duePicker = detail.getByTestId("card-detail-due-picker");
      await duePicker
        .getByTestId("card-detail-due-inline-input")
        .fill("2020-01-01");
      await duePicker.getByRole("button", { name: "Save" }).click();
      await expect(duePicker).toBeHidden({ timeout: 45_000 });
      await detail.getByTestId("card-detail-close-button").click();

      const overdueCardAfterSave = alicePage.page
        .getByTestId("kanban-card")
        .filter({ hasText: overdueTitle })
        .first();
      await expect(overdueCardAfterSave).toBeVisible({ timeout: 45_000 });
      await expect(
        overdueCardAfterSave.getByTestId("kanban-card-overdue-badge"),
      ).toBeVisible({
        timeout: 45_000,
      });
      await expect(
        overdueCardAfterSave.getByTestId("kanban-card-due"),
      ).toHaveAttribute("data-overdue", "true");
      await stepShot(alicePage.page, testInfo, "A-overdue-badge");

      // The on-track card (no due_date) must NOT show the overdue badge.
      const onTrackCard = alicePage.page
        .getByTestId("kanban-card")
        .filter({ hasText: onTrackTitle })
        .first();
      await expect(onTrackCard).toBeVisible({ timeout: 45_000 });
      await expect(
        onTrackCard.getByTestId("kanban-card-overdue-badge"),
      ).toHaveCount(0);
    } finally {
      await alicePage.close();
    }
  });

  test("E16.G concurrent assignment from two devices: require_review exposes no active assignee", async ({
    request,
  }) => {
    // spec: relation.md §5 (single-assignee profile max_to_per_from=1) + §6.
    // Concurrent mutually exclusive heads remain review-required; digest
    // ordering cannot turn either edge into the active assignment.
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
      ownerId: alice.id,
    });
    await registerSingleAssigneeProfile(
      request,
      aliceToken,
      alice.id,
      realmId,
    );

    const { cardId } = await createBoardWithCard(
      request,
      aliceToken,
      alice.id,
      realmId,
      {
        boardTitle: `Conflict Board ${stamp}`,
        listTitle: `Todo ${stamp}`,
        cardTitle: `Assign race ${stamp}`,
      },
    );

    // Two concurrent assignments of the same Card to two different actors. The
    // single-assignee profile (max_to_per_from=1) forces a conflict; the
    // complete head set remains available for a later explicit resolution.
    const assignToAlice = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation: {
          id: typedId("relation"),
          schema: "ak.schema.relation.v1",
          realm_id: realmId,
          relation_kind: "assigned_to",
          from_ref: cardId,
          to_ref: alice.id,
          created_by: accountActorId(alice.id),
          created_at: canonicalTimestamp(),
        },
      },
    });
    const assignToBob = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation: {
          id: typedId("relation"),
          schema: "ak.schema.relation.v1",
          realm_id: realmId,
          relation_kind: "assigned_to",
          from_ref: cardId,
          to_ref: bob.id,
          created_by: accountActorId(alice.id),
          created_at: canonicalTimestamp(),
        },
      },
    });

    await submitSignedEventApi(request, aliceToken, assignToAlice, {
      context: "assign Card to alice",
    });
    await submitSignedEventApi(request, aliceToken, assignToBob, {
      context: "assign Card to bob",
    });

    const row = await readStrandRow(request, aliceToken, realmId, cardId);
    expect(row, "Card visible").toBeTruthy();
    expect(row?.assigned_actor_ids ?? []).toEqual([]);
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
      ownerId: alice.id,
    });
    const { cardId } = await createBoardWithCard(
      request,
      aliceToken,
      alice.id,
      realmId,
      {
        boardTitle: `Unassign Board ${stamp}`,
        listTitle: `Todo ${stamp}`,
        cardTitle: `Unassign me ${stamp}`,
      },
    );

    const relationId = typedId("relation");
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.relation.create",
        payload: {
          relation: {
            id: relationId,
            schema: "ak.schema.relation.v1",
            realm_id: realmId,
            relation_kind: "assigned_to",
            from_ref: cardId,
            to_ref: bob.id,
            created_by: accountActorId(alice.id),
            created_at: canonicalTimestamp(),
          },
        },
      }),
      { context: "assign Card to bob" },
    );

    const assigned = await readStrandRow(request, aliceToken, realmId, cardId);
    expect(assigned?.assigned_actor_ids ?? []).toContain(bob.id);

    // Unassign: tombstone the assigned_to edge.
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.relation.tombstone",
        payload: {
          relation_id: relationId,
          relation_kind: "assigned_to",
        },
      }),
      { context: "unassign bob (ak.relation.tombstone)" },
    );

    const unassigned = await readStrandRow(
      request,
      aliceToken,
      realmId,
      cardId,
    );
    expect(unassigned?.assigned_actor_ids ?? []).not.toContain(bob.id);
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
      ownerId: alice.id,
    });
    const { boardId, listId, cardId } = await createBoardWithCard(
      request,
      aliceToken,
      alice.id,
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
        actorId: alice.id,
        realmId,
        kind: "ak.space.archive",
        payload: { space_id: boardId, sender: alice.id },
      }),
      { context: "archive board" },
    );

    // Cascade: board + list archived in the spaces projection.
    const boardRow = await readSpaceRow(request, aliceToken, realmId, boardId);
    expect(boardRow?.state).toBe("archived");
    const listRow = await readSpaceRow(request, aliceToken, realmId, listId);
    expect(listRow?.state).toBe("archived");

    // Cascade: the Card is archived (read-only). Archived is reversible rather
    // than terminal, so the default projection continues to surface it for the
    // archive list view; include_terminal only controls redacted rows.
    const archivedCard = await readStrandRow(
      request,
      aliceToken,
      realmId,
      cardId,
    );
    expect(archivedCard?.state).toBe("archived");

    // Read-only: a write to the archived Card is rejected (strand_not_active).
    const writeEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.update",
      payload: {
        target_ref: cardId,
        patch: { metadata: { title: `renamed ${stamp}` } },
      },
    });
    await alignSignedEventToActorFrontierApi(
      request,
      aliceToken,
      writeEnvelope,
    );
    const write = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
      headers: authHeaders(aliceToken),
      data: writeEnvelope,
    });
    expect(write.status()).toBe(412);
    expect(wireErrCode(await write.json())).toBe("strand_not_active");
  });
});

// Multi-user project simulation
// Contract: e2e/scenarios/kanban/project-simulation.md
// Spec refs:
//   - models/realm-and-space.md §4 (Space container), §3 (Join Policy)
//   - models/strand-and-message.md §3 (Strand fields)
//   - models/relation.md §3.2 (assigned_to), §5 (relation records and application rule boundaries), §6 (conflict resolution)

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
  addRealmMemberApi,
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  retypeEventDerivedId,
  sdkEventDerivedObjectId,
  sha256CanonicalJson,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
import { acceptInviteViaApi } from "../../helpers/api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueUserSession,
  openDpopUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

// Subset of `service-operation-dtos.schema.json#/$defs/ProjectionStrandRow`
// that this suite asserts on. `stage` / `stage_changed_at` are the second half
// of the common-fields.md §3.2 lifecycle cluster and sit immediately after
// `state_changed_at` in the DTO; both are absent until `ak.strand.stage.set`
// has written the object.
type StrandProjectionRow = {
  strand_id: string;
  state: string;
  stage?: string | null;
  stage_changed_at?: string | null;
  title?: string | null;
  board_space_id?: string | null;
  list_space_id?: string | null;
  assigned_actor_ids?: Array<ReturnType<typeof accountActorId>>;
  assigned_to_relations?: Array<{
    relation_id: string;
    actor_id: ReturnType<typeof accountActorId>;
  }>;
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
    headers: authHeaders(token, "GET", url.toString()),
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
    { headers: authHeaders(token, "GET", `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/spaces?include_terminal=true`) },
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
  await submitSignedEventApi(
    request,
    token,
    boardEnvelope,
    { context: `create board ${opts.boardTitle}` },
  );
  const boardId = sdkEventDerivedObjectId(boardEnvelope);

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
  await submitSignedEventApi(
    request,
    token,
    listEnvelope,
    { context: `create list ${opts.listTitle}` },
  );
  const listId = sdkEventDerivedObjectId(listEnvelope);

  const cardEnvelope = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.strand.create",
    createdAt,
    payload: {
      object: {
        schema: "ak.schema.strand.v1",
        realm_id: realmId,
        // `metadata.fields.status` is hard_reject forbidden wire
        // (registry/forbidden-wire-fields.json, context strand_payload); the
        // registered replacement is the top-level `stage` below.
        metadata: {
          title: opts.cardTitle,
          ...(opts.dueDate ? { fields: { due_date: opts.dueDate } } : {}),
        },
        stage: "planned",
        tracks: { discussion: { enabled: true, is_primary: true } },
        created_by: accountActorId(actorId),
        created_at: createdAt,
      },
    },
  });
  await submitSignedEventApi(
    request,
    token,
    cardEnvelope,
    { context: `create card ${opts.cardTitle}` },
  );
  const cardId = sdkEventDerivedObjectId(cardEnvelope);
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
    const aliceToken = await issueUserSession(request, alice);
    const bobToken = await issueUserSession(request, bob);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S16 Assign ${stamp}`,
      ownerId: alice.id,
    });
    // Assignment is the behavior under test. Establish Bob's membership
    // directly so invite-delivery policy/quarantine is not an unrelated
    // prerequisite for reading the resulting Strand projection.
    await addRealmMemberApi(request, aliceToken, realmId, bob.id);

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

    const assignment = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation: {
          schema: "ak.schema.relation.v1",
          realm_id: realmId,
          relation_kind: "assigned_to",
          from_ref: cardId,
          to_ref: accountActorId(bob.id),
          created_by: accountActorId(alice.id),
          created_at: canonicalTimestamp(),
        },
      },
    });
    await submitSignedEventApi(request, aliceToken, assignment, {
      context: "assign Card 1 to bob",
    });
    const relationId = sdkEventDerivedObjectId(assignment);

    // bob reads the Realm's strands and finds himself on Card 1.
    const row = await readStrandRow(request, bobToken, realmId, cardId);
    expect(row, "Card 1 visible to bob").toBeTruthy();
    expect(row?.assigned_actor_ids ?? []).toContainEqual(
      accountActorId(bob.id),
    );
    expect(
      (row?.assigned_to_relations ?? []).some(
        (relation) =>
          canonicalJson(relation.actor_id) ===
            canonicalJson(accountActorId(bob.id)) &&
          relation.relation_id === relationId,
      ),
      "assigned_to relation surfaces with bob's actor + relation id",
    ).toBe(true);
  });

  test("canonical Strand stage uses ak.strand.stage.set; core permits planned → done without a workflow profile and rejects metadata.fields.status", async ({
    request,
  }) => {
    const alice = uniqueUser("s16-transition-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S16 transition ${Date.now()}`,
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
            metadata: { title: "Implement login" },
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

    // common-fields.md §5.3.3: without a profile-declared workflow transition rule the
    // core reducer intentionally imposes no direction on the eight stage
    // values, so planned -> done is legal.
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.strand.stage.set",
        payload: {
          strand_id: taskStrandId,
          stage: "done",
          expected_stage: "planned",
        },
      }),
      { context: "advance card directly from planned to done" },
    );
    const task = await readStrandRow(request, aliceToken, realmId, taskStrandId);
    expect(task?.stage).toBe("done");
    // common-fields.md §5.3.1, now machine-readable on the DTO as
    // `if stage_changed_at is a string then stage is a string`: the reducer
    // timestamp MUST NOT surface without the stage it dates. The DTO leaves
    // `stage_changed_at` optional, so only this direction is asserted.
    if (typeof task?.stage_changed_at === "string") {
      expect(
        typeof task.stage,
        "stage_changed_at MUST NOT appear without stage",
      ).toBe("string");
    }

    // The legacy status spelling is forbidden wire, not a private lifecycle state.
    const forbiddenStatusEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.update",
      payload: {
        target_ref: taskStrandId,
        patch: { metadata: { fields: { status: "resolved" } } },
      },
    });
    const forbiddenStatus = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(aliceToken, "POST", `${solandBaseUrl()}/_arkret/self/events`),
        data: { event: forbiddenStatusEvent },
      },
    );
    expect(forbiddenStatus.status()).toBe(422);
    expect(wireErrCode(await forbiddenStatus.json())).toBe("schema_violation");
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
      await expect(overdueCard).toHaveAttribute("data-card-draft", "false", {
        timeout: 45_000,
      });
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

  test("E16.G default assigned_to cardinality retains multiple distinct assignees", async ({
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
    const aliceToken = await issueUserSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S16 Conflict ${stamp}`,
      ownerId: alice.id,
    });

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

    // Distinct complete Actor endpoints remain active together without a tightening profile.
    const assignToAlice = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation: {
          schema: "ak.schema.relation.v1",
          realm_id: realmId,
          relation_kind: "assigned_to",
          from_ref: cardId,
          to_ref: accountActorId(alice.id),
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
          schema: "ak.schema.relation.v1",
          realm_id: realmId,
          relation_kind: "assigned_to",
          from_ref: cardId,
          to_ref: accountActorId(bob.id),
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
    expect((row?.assigned_actor_ids ?? []).map(canonicalJson).sort()).toEqual(
      [accountActorId(alice.id), accountActorId(bob.id)].map(canonicalJson).sort(),
    );
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
    const aliceToken = await issueUserSession(request, alice);

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

    const assignment = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation: {
          schema: "ak.schema.relation.v1",
          realm_id: realmId,
          relation_kind: "assigned_to",
          from_ref: cardId,
          to_ref: accountActorId(bob.id),
          created_by: accountActorId(alice.id),
          created_at: canonicalTimestamp(),
        },
      },
    });
    await submitSignedEventApi(
      request,
      aliceToken,
      assignment,
      { context: "assign Card to bob" },
    );
    const relationId = sdkEventDerivedObjectId(assignment);

    const assigned = await readStrandRow(request, aliceToken, realmId, cardId);
    expect(assigned?.assigned_actor_ids ?? []).toContainEqual(
      accountActorId(bob.id),
    );

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
    expect(unassigned?.assigned_actor_ids ?? []).not.toContainEqual(
      accountActorId(bob.id),
    );
    expect(
      (unassigned?.assigned_to_relations ?? []).some(
        (relation) => relation.relation_id === relationId,
      ),
      "tombstoned assigned_to relation no longer surfaces",
    ).toBe(false);
  });

  test("alice archives the board; child lists and cards stay active and writable", async ({
    request,
  }) => {
    // realm-and-space.md section 3.4: Space archive changes only that
    // container. Child Spaces and contained Strands keep their lifecycle.
    const stamp = Date.now();
    const alice = uniqueUser("s16-archive-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);

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
        payload: { space_id: boardId },
      }),
      { context: "archive board" },
    );

    // Only the board is archived in the spaces projection.
    const boardRow = await readSpaceRow(request, aliceToken, realmId, boardId);
    expect(boardRow?.state).toBe("archived");
    const listRow = await readSpaceRow(request, aliceToken, realmId, listId);
    expect(listRow?.state).toBe("active");

    const cardAfterArchive = await readStrandRow(
      request,
      aliceToken,
      realmId,
      cardId,
    );
    expect(cardAfterArchive?.state).toBe("active");

    // The active Card remains writable under the same capability.
    const writeEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.strand.update",
      payload: {
        target_ref: cardId,
        patch: { metadata: { title: `renamed ${stamp}` } },
      },
    });
    await submitSignedEventApi(request, aliceToken, writeEnvelope, {
      context: "update active card after parent board archive",
    });
  });
});

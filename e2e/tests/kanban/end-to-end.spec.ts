// Kanban end-to-end
// Contract: e2e/scenarios/kanban/end-to-end.md
// Spec refs:
//   - models/realm-and-space.md §3 (Space containers), §3.5 (parent/rank basis)
//   - models/strand-and-message.md §2-§3 (Strand), §4.3 (discussion track)
//   - models/relation.md §3.2 (contains)

import {
  expect,
  test,
  type APIRequestContext,
  type Locator,
  type Page,
} from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  alignSignedEventToActorFrontierApi,
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  prepareSignedEventCbaApi,
  rawSubmitSignedEventApi,
  sdkEventDerivedObjectId,
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

test.describe.configure({ mode: "serial" });

// ---------------------------------------------------------------------------
// Shared rig for the "creator device, encrypted Realm" regression trio
// (description / synthesis / discussion comment). Each guards that a private
// Strand content path round-trips as an ENCRYPTED write on the SAME device that
// just created the Realm. The plaintext happy-paths above never arm the
// content-encryption floor (createRealm defaults encryption_profile to
// "none"), and encryption/key-backup.spec.ts A2 only reaches the encrypted
// kanban write on a RESTORED second device — never on the original creator
// device, which is the path this trio covers.
// ---------------------------------------------------------------------------

// The plaintext-vs-encrypted decision is client-side and the optimistic UI
// still renders typed text even when the server bounced the write, so any
// content_encryption_floor_violation on the wire is the source of truth.
function recordFloorViolations(page: Page): string[] {
  const hits: string[] = [];
  page.on("response", (response) => {
    if (
      !response.url().includes("/_arkret/self/events") ||
      response.request().method() !== "POST"
    ) {
      return;
    }
    void response
      .text()
      .then((body) => {
        if (body.includes("content_encryption_floor_violation")) {
          hits.push(`${response.status()} ${body.slice(0, 500)}`);
        }
      })
      .catch(() => {});
  });
  return hits;
}

function relationObject(args: {
  id: string;
  realmId: string;
  relationKind: string;
  fromRef: string;
  toRef: string;
  actorDid: string;
}): Record<string, unknown> {
  return {
    id: args.id,
    schema: "ak.schema.relation.v1",
    realm_id: args.realmId,
    relation_kind: args.relationKind,
    from_ref: args.fromRef,
    to_ref: args.toRef,
    created_by: args.actorDid,
    created_at: canonicalTimestamp(),
  };
}

async function addCardThroughColumn(column: Locator, title: string) {
  const titleInput = column.getByTestId("new-card-title-input").last();
  if (!(await titleInput.isVisible({ timeout: 250 }).catch(() => false))) {
    const addButton = column.getByTestId("add-card-button").last();
    await expect(addButton).toBeVisible({ timeout: 30_000 });
    await expect(addButton).toBeEnabled({ timeout: 30_000 });
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

async function buildEncryptedBoardAndCard(
  page: Page,
  realmId: string,
  stamp: number,
  cardTitle: string,
): Promise<void> {
  await page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
  await page.getByTestId("new-board-toggle").click();
  await page.getByTestId("new-board-title-input").fill(`Enc Board ${stamp}`);
  await page.getByTestId("create-board-space-button").click();
  await expect(page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
    timeout: 45_000,
  });
  const columnName = `Todo-${stamp}`;
  await page.getByTestId("new-column-input").fill(columnName);
  await page.getByTestId("add-column-button").click();
  const column = page.getByTestId("kanban-column").filter({ hasText: columnName }).first();
  await expect(column).toBeVisible({ timeout: 45_000 });
  await addCardThroughColumn(column, cardTitle);
  await expect(column.getByTestId("kanban-card").filter({ hasText: cardTitle })).toBeVisible({
    timeout: 45_000,
  });
}

// The card-detail rich editor renders its fallback <textarea> under a fixed
// testid regardless of slot (description vs synthesis), so both editors are
// driven the same way. Only one edit form is mounted at a time.
async function setCardDetailEditorValue(page: Page, value: string): Promise<void> {
  const input = page.getByTestId("card-detail-description-input");
  await expect(input).toBeAttached({ timeout: 45_000 });
  await input.evaluate((node, nextValue) => {
    const textarea = node as HTMLTextAreaElement;
    textarea.value = nextValue;
    textarea.dispatchEvent(
      new InputEvent("input", { bubbles: true, inputType: "insertText", data: nextValue }),
    );
  }, value);
}

// API-level Card creation that mirrors kanban/project-simulation's active
// ak.strand.create payload (full `object` with metadata.fields.status). Returns
// the new strand id so the API-driven reject tests below can target it without
// the brittle inkson kanban UI load path.
async function createCardStrandApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  title: string,
): Promise<string> {
  const createdAt = canonicalTimestamp();
  const envelope = signedEventEnvelope({
    actorDid,
    realmId,
    kind: "ak.strand.create",
    createdAt,
    payload: {
      object: {
        schema: "ak.schema.strand.v1",
        realm_id: realmId,
        metadata: {
          title,
          fields: { status: "todo" },
        },
        stage: "planned",
        tracks: { discussion: { enabled: true, is_primary: true } },
        created_by: actorDid,
        created_at: createdAt,
      },
    },
  });
  const strandId = sdkEventDerivedObjectId(envelope);
  await submitSignedEventApi(
    request,
    token,
    envelope,
    { context: `create card strand ${title}` },
  );
  return strandId;
}

async function createSpaceApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  kind: "board" | "list",
  title: string,
  parentSpaceId?: string,
): Promise<string> {
  const createdAt = canonicalTimestamp();
  const envelope = signedEventEnvelope({
    actorDid,
    realmId,
    kind: "ak.space.create",
    createdAt,
    payload: {
      object: {
        schema: "ak.schema.space.v1",
        realm_id: realmId,
        kind,
        title,
        ...(parentSpaceId
          ? { parent_space_id: parentSpaceId, rank: "m" }
          : {}),
        created_by: actorDid,
        created_at: createdAt,
      },
    },
  });
  const spaceId = sdkEventDerivedObjectId(envelope);
  await submitSignedEventApi(request, token, envelope, {
    context: `create ${kind} space ${title}`,
  });
  return spaceId;
}

test.describe("kanban end-to-end", () => {
  test("alice opens kanban, adds 3 columns, adds 2 cards in Todo, archives Card A, restores it", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const aliceFlow = await openDpopUserPage(browser, request, "kanban-alice");
    if (!aliceFlow) {
      assertJointStackNotRequired("kanban end-to-end browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;

    const cardA = `Card A ${stamp}`;
    const cardB = `Card B ${stamp}`;

    try {
      // Create a Realm so the kanban view has a selected Realm context.
      const realmId = await alicePage.createRealm({
        title: `Kanban Realm ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
      });
      // Kanban scopes writes to the selected Realm; navigate with the explicit
      // realm_id so the route resolves to the freshly-created Realm (plain
      // `/kanban` falls back to the first preview, which on a fresh session
      // is the hardcoded demo Realm the test user is NOT a member of, and
      // every ak.strand.* event would 403 with capability_denied).
      await alicePage.page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await alicePage.page.getByTestId("new-board-toggle").click();
      await alicePage.page
        .getByTestId("new-board-title-input")
        .fill(`Sprint 23 ${stamp}`);
      await alicePage.page.getByTestId("create-board-space-button").click();
      await expect(alicePage.page.getByTestId("kanban-empty-board")).toContainText(
        /No lists yet/,
        { timeout: 30_000 },
      );
      await stepShot(alicePage.page, testInfo, "A-kanban-open");

      // Add three columns (lists).
      for (const columnName of [`Todo-${stamp}`, `InProgress-${stamp}`, `Done-${stamp}`]) {
        await alicePage.page.getByTestId("new-column-input").fill(columnName);
        await alicePage.page.getByTestId("add-column-button").click();
        await expect(
          alicePage.page.getByTestId("kanban-column").filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await stepShot(alicePage.page, testInfo, "B-three-columns");

      const todoColumn = alicePage.page
        .getByTestId("kanban-column")
        .filter({ hasText: `Todo-${stamp}` })
        .first();

      // Add two cards in Todo. Each "add-card-button" click reveals the
      // new-card-title-input; fill + save.
      for (const cardName of [cardA, cardB]) {
        await addCardThroughColumn(todoColumn, cardName);
        await expect(
          todoColumn.getByTestId("kanban-card").filter({ hasText: cardName }),
        ).toBeVisible({ timeout: 30_000 });
      }
      await stepShot(alicePage.page, testInfo, "C-two-cards");

      // Archive Card A → it should disappear from the active column.
      // The card-archive-button is hidden until the parent .board-card is
      // hovered, so hover the card first to make it actionable.
      const cardALocator = todoColumn
        .getByTestId("kanban-card")
        .filter({ hasText: cardA })
        .first();
      await cardALocator.hover();
      await cardALocator.getByTestId("card-archive-button").click();
      await expect(todoColumn.getByTestId("kanban-card").filter({ hasText: cardA })).toHaveCount(0, {
        timeout: 30_000,
      });
      // Card A appears in archived list.
      await expect(
        alicePage.page.getByTestId("kanban-archived-card-row").filter({ hasText: cardA }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "D-card-archived");

      // Restore Card A from archive — it should reappear on the board.
      const archivedRow = alicePage.page
        .getByTestId("kanban-archived-card-row")
        .filter({ hasText: cardA })
        .first();
      await archivedRow.getByTestId("card-restore-button").click();
      await expect(
        alicePage.page.getByTestId("kanban-card").filter({ hasText: cardA }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "E-card-restored");
    } finally {
      await alicePage.close();
    }
  });

  test("stale cross-list move: cas-register accepts the winner and rejects the stale move with cas_conflict", async ({
    request,
  }) => {
    // spec: realm-and-space.md §3.6 — ak.strand.move writes the strand
    // position on the Move/Seal cas-register; concurrent moves of the same
    // Card race for the same actor frontier. soland's actor_seq frontier is
    // the cas-register guard (event_log/submit.rs): the first move advances
    // the frontier, a second move stamped behind it is rejected with
    // cas_conflict ("actor_seq is older than the accepted actor frontier").
    // The reason is cas_conflict, not cas_register_conflict (that code does
    // not exist in soland).
    const stamp = Date.now();
    const alice = uniqueUser("kanban-cas-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `Kanban CAS ${stamp}`,
      ownerDid: alice.did,
    });
    const cardId = await createCardStrandApi(
      request,
      aliceToken,
      alice.did,
      realmId,
      `CAS Card ${stamp}`,
    );

    const boardSpaceId = await createSpaceApi(
      request,
      aliceToken,
      alice.did,
      realmId,
      "board",
      `CAS Board ${stamp}`,
    );
    const inProgressListId = await createSpaceApi(
      request,
      aliceToken,
      alice.did,
      realmId,
      "list",
      `CAS In Progress ${stamp}`,
      boardSpaceId,
    );
    const doneListId = await createSpaceApi(
      request,
      aliceToken,
      alice.did,
      realmId,
      "list",
      `CAS Done ${stamp}`,
      boardSpaceId,
    );

    const winnerMove = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.strand.move",
      payload: {
        strand_id: cardId,
        board_space_id: boardSpaceId,
        target_space_id: inProgressListId,
        rank: "m",
      },
    });
    const loserMove = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.strand.move",
      payload: {
        strand_id: cardId,
        board_space_id: boardSpaceId,
        target_space_id: doneListId,
        rank: "m",
      },
    });
    await prepareSignedEventCbaApi(request, aliceToken, winnerMove);
    await prepareSignedEventCbaApi(request, aliceToken, loserMove);
    await alignSignedEventToActorFrontierApi(request, aliceToken, winnerMove);
    await alignSignedEventToActorFrontierApi(request, aliceToken, loserMove);
    // Winner is accepted (submitSignedEventApi asserts 200/201).
    await submitSignedEventApi(request, aliceToken, winnerMove, {
      context: "concurrent move winner",
    });
    await createCardStrandApi(
      request,
      aliceToken,
      alice.did,
      realmId,
      `CAS frontier advance ${stamp}`,
    );

    // Loser targets the SAME card but is stamped behind the accepted frontier
    // → cas_conflict. It still has to use the canonical lease/publication
    // rail; the negative helper disables only the normal automatic frontier
    // repair so that the stale verdict remains observable.
    const loserResponse = await rawSubmitSignedEventApi(
      request,
      aliceToken,
      loserMove,
      { retryActorFrontier: false },
    );
    const loserBody = await loserResponse.json();
    const loserReason =
      wireErrCode(loserBody) ?? loserBody.rejected?.[0]?.reason_code;
    expect(loserReason, JSON.stringify(loserBody)).toBe("cas_conflict");
  });

  test("cross-realm contains relation rejected with reason=cross_realm_structural_relation", async ({
    request,
  }) => {
    // spec: models/relation.md §4 — structural relations (contains /
    // belongs_to) MUST NOT cross Realm boundaries. soland resolves both
    // endpoints' home Realms (apply_relations.rs check_relation_cross_realm →
    // SDK validate_structural_relation_same_realm) and rejects a contains
    // edge whose endpoints live in different Realms with
    // cross_realm_structural_relation. A Strand→Strand contains stays a
    // directly-writable weak relation, so a Strand from_ref (not a ak:space:
    // from_ref, which is the derived Board/List containment) reaches this
    // check instead of relation_kind_contains_derived.
    const stamp = Date.now();
    const alice = uniqueUser("kanban-crossrealm-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmA = await createRealmApi(request, aliceToken, {
      title: `Kanban Realm A ${stamp}`,
      ownerDid: alice.did,
    });
    const realmB = await createRealmApi(request, aliceToken, {
      title: `Kanban Realm B ${stamp}`,
      ownerDid: alice.did,
    });
    const cardInA = await createCardStrandApi(
      request,
      aliceToken,
      alice.did,
      realmA,
      `Card in A ${stamp}`,
    );
    const cardInB = await createCardStrandApi(
      request,
      aliceToken,
      alice.did,
      realmB,
      `Card in B ${stamp}`,
    );

    // contains edge in realm A pointing at a Card that lives in realm B.
    const crossRealm = signedEventEnvelope({
      actorDid: alice.did,
      realmId: realmA,
      kind: "ak.relation.create",
      payload: {
        relation: relationObject({
          id: typedId("relation"),
          realmId: realmA,
          relationKind: "contains",
          fromRef: cardInA,
          toRef: cardInB,
          actorDid: alice.did,
        }),
      },
    });
    await prepareSignedEventCbaApi(request, aliceToken, crossRealm);
    await alignSignedEventToActorFrontierApi(
      request,
      aliceToken,
      crossRealm,
    );
    const response = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      { headers: authHeaders(aliceToken), data: crossRealm },
    );
    expect(response.status()).toBe(412);
    expect(wireErrCode(await response.json())).toBe(
      "cross_realm_structural_relation",
    );
  });

  test("commenting on an archived strand is rejected by reducer (no writes on archived Strand)", async ({
    request,
  }) => {
    // spec: common-fields.md §5.1 — writes on a non-active object MUST fail
    // with strand_not_active. Posting into a Card's discussion track after it
    // is archived is a track mutation (ak.strand.tracks.update); soland gates
    // it on the parent Strand lifecycle in apply_objects/strand.rs
    // (check_strand_tracks_transition admission preflight + apply_strand_track_touch
    // reducer defence-in-depth), both returning strand_not_active.
    const stamp = Date.now();
    const alice = uniqueUser("kanban-archived-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `Kanban Archived ${stamp}`,
      ownerDid: alice.did,
    });
    const cardId = await createCardStrandApi(
      request,
      aliceToken,
      alice.did,
      realmId,
      `Archived Card ${stamp}`,
    );

    // Archive the Card (ak.strand.archive, target_ref). Accepted: the strand
    // is Active before this transition.
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.strand.archive",
        payload: { target_ref: cardId },
      }),
      { context: "archive card strand" },
    );

    // Post into the archived Card's discussion track → strand_not_active.
    const trackWrite = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.strand.tracks.update",
      payload: {
        strand_id: cardId,
        patch: { discussion: { enabled: true } },
      },
    });
    await alignSignedEventToActorFrontierApi(
      request,
      aliceToken,
      trackWrite,
    );
    const response = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      { headers: authHeaders(aliceToken), data: trackWrite },
    );
    expect(response.status()).toBe(412);
    expect(wireErrCode(await response.json())).toBe("strand_not_active");
  });

  test("column drag handles expose stable targets and reorder columns locally", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      `kanban-column-drag-alice-${stamp}`,
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("kanban column drag browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;

    const first = `First-${stamp}`;
    const second = `Second-${stamp}`;
    const third = `Third-${stamp}`;

    try {
      const realmId = await alicePage.createRealm({
        title: `Kanban Column Drag ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });
      await alicePage.page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await alicePage.page.getByTestId("new-board-toggle").click();
      await alicePage.page.getByTestId("new-board-title-input").fill(`Column Drag ${stamp}`);
      await alicePage.page.getByTestId("create-board-space-button").click();
      await expect(alicePage.page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
        timeout: 30_000,
      });

      for (const columnName of [first, second, third]) {
        await alicePage.page.getByTestId("new-column-input").fill(columnName);
        await alicePage.page.getByTestId("add-column-button").click();
        await expect(
          alicePage.page.getByTestId("kanban-column").filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }

      const firstColumn = alicePage.page.getByTestId("kanban-column").filter({ hasText: first });
      const thirdColumn = alicePage.page.getByTestId("kanban-column").filter({ hasText: third });
      await expect(firstColumn.getByTestId("column-drop-target-before")).toHaveCount(1);
      await expect(thirdColumn.getByTestId("column-drag-handle")).toBeVisible();

      await thirdColumn
        .getByTestId("column-drag-handle")
        .dragTo(firstColumn.getByTestId("column-drop-target-before"), { force: true });
      await stepShot(alicePage.page, testInfo, "column-handles-reordered");

      const labels = await alicePage.page.getByTestId("kanban-column-title").allTextContents();
      const firstIndex = labels.findIndex((label) => label.includes(first));
      const secondIndex = labels.findIndex((label) => label.includes(second));
      const thirdIndex = labels.findIndex((label) => label.includes(third));
      expect(thirdIndex).toBeGreaterThanOrEqual(0);
      expect(firstIndex).toBeGreaterThanOrEqual(0);
      expect(secondIndex).toBeGreaterThanOrEqual(0);
      expect(thirdIndex).toBeLessThan(firstIndex);
      expect(firstIndex).toBeLessThan(secondIndex);
    } finally {
      await alicePage.close();
    }
  });

  test("reordering lists (drag column) updates board's child_order cell", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: realm-and-space.md Space-container rank projection basis
    const stamp = Date.now();
    const aliceFlow = await openDpopUserPage(browser, request, "kanban-order-alice", {
      prepareMlsDevice: false,
    });
    if (!aliceFlow) {
      assertJointStackNotRequired("kanban order DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;

    const first = `First-${stamp}`;
    const second = `Second-${stamp}`;
    const third = `Third-${stamp}`;

    try {
      const realmId = await alicePage.createRealm({
        title: `Kanban Order ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });
      await alicePage.page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await alicePage.page.getByTestId("new-board-toggle").click();
      await alicePage.page.getByTestId("new-board-title-input").fill(`Order Board ${stamp}`);
      await alicePage.page.getByTestId("create-board-space-button").click();
      await expect(alicePage.page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
        timeout: 30_000,
      });
      await expect
        .poll(() => alicePage.page.url(), { timeout: 30_000 })
        .toContain("/board/ak:space:");
      const boardId = decodeURIComponent(
        new URL(alicePage.page.url()).pathname.split("/board/")[1]?.split("/")[0] ?? "",
      );
      expect(boardId).toMatch(/^ak:space:/);

      for (const columnName of [first, second, third]) {
        await alicePage.page.getByTestId("new-column-input").fill(columnName);
        await alicePage.page.getByTestId("add-column-button").click();
        await expect(
          alicePage.page.getByTestId("kanban-column").filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }

      const firstColumn = alicePage.page.getByTestId("kanban-column").filter({ hasText: first });
      const thirdColumn = alicePage.page.getByTestId("kanban-column").filter({ hasText: third });
      await thirdColumn.getByTestId("column-drag-handle").dragTo(
        firstColumn.getByTestId("column-drop-target-before"),
        { force: true },
      );
      await stepShot(alicePage.page, testInfo, "columns-reordered");

      const labels = await alicePage.page.getByTestId("kanban-column-title").allTextContents();
      const firstIndex = labels.findIndex((label) => label.includes(first));
      const secondIndex = labels.findIndex((label) => label.includes(second));
      const thirdIndex = labels.findIndex((label) => label.includes(third));
      expect(thirdIndex).toBeGreaterThanOrEqual(0);
      expect(firstIndex).toBeGreaterThanOrEqual(0);
      expect(secondIndex).toBeGreaterThanOrEqual(0);
      expect(thirdIndex).toBeLessThan(firstIndex);
      expect(firstIndex).toBeLessThan(secondIndex);

      await expect
        .poll(
          async () => {
            const cellResp = await request.get(
              `${solandBaseUrl()}/_soland/self/spaces/${encodeURIComponent(boardId)}/cells/ak.component.child_order.v1`,
              {
                headers: selfPathHeadersForDpopSession(
                  aliceFlow.session,
                  "GET",
                  `${solandBaseUrl()}/_soland/self/spaces/${encodeURIComponent(boardId)}/cells/ak.component.child_order.v1`,
                ),
              },
            );
            if (cellResp.status() !== 200) {
              return false;
            }
            const cellText = JSON.stringify(await cellResp.json());
            const thirdServerIndex = cellText.indexOf(third);
            const firstServerIndex = cellText.indexOf(first);
            const secondServerIndex = cellText.indexOf(second);
            return (
              thirdServerIndex >= 0 &&
              firstServerIndex >= 0 &&
              secondServerIndex >= 0 &&
              thirdServerIndex < firstServerIndex &&
              firstServerIndex < secondServerIndex
            );
          },
          { timeout: 30_000 },
        )
        .toBe(true);
    } finally {
      await alicePage.close();
    }
  });

  // Regression: creator-device "add description on a fresh encrypted Realm".
  //
  // The happy-path kanban tests above build PLAINTEXT Realms — createRealm
  // leaves encryption_profile unset, which defaults to "none" (see
  // helpers/users.ts + soland-api.ts), so soland's content-encryption floor
  // (operations.rs validate_content_encryption_floor) is never armed and the
  // card detail only ever carries a `title`, never a private `body`. The
  // inkson setup wizard, however, defaults new Realms to `mls_rfc9420` (the
  // "Encrypted" badge). Adding a Strand description writes the private `body`
  // patch path, so on an encrypted Realm the client MUST encrypt it before
  // submit; if it ships plaintext, soland rejects the ak.strand.update with 412
  // `content_encryption_floor_violation` (exactly the failure reported from
  // the UI). encryption/key-backup.spec.ts A2 exercises this only on a
  // RESTORED second device — never on the original creator device, which is
  // the path this guards.
  test("alice adds a strand description on a freshly-created MLS-encrypted realm; soland accepts the encrypted ak.strand.update (no content_encryption_floor_violation)", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(180_000);
    const stamp = Date.now();
    const aliceFlow = await openDpopUserPage(browser, request, "kanban-enc-desc-alice");
    if (!aliceFlow) {
      assertJointStackNotRequired("encrypted kanban description DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;

    const cardTitle = `Encrypted Card ${stamp}`;
    const description = `Encrypted description body ${stamp}`;

    // The plaintext-vs-encrypted decision is client-side, and on the buggy
    // path the optimistic UI still renders the typed text even though the
    // server bounced the write — so the network verdict, not the rendered
    // DOM, is the source of truth. Record any events submit that soland
    // rejects with the content-encryption floor reason.
    const floorViolations: string[] = [];
    alicePage.page.on("response", (response) => {
      if (
        !response.url().includes("/_arkret/self/events") ||
        response.request().method() !== "POST"
      ) {
        return;
      }
      void response
        .text()
        .then((body) => {
          if (body.includes("content_encryption_floor_violation")) {
            floorViolations.push(`${response.status()} ${body.slice(0, 500)}`);
          }
        })
        .catch(() => {});
    });

    try {
      // Encrypted Realm — mirrors the inkson setup-wizard default. This is the
      // single line that distinguishes this case from the plaintext happy
      // paths above and arms the content-encryption floor.
      const realmId = await alicePage.createRealm({
        title: `Encrypted Kanban ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        encryptionProfile: "mls_rfc9420",
      });

      await alicePage.page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });

      // Board + one column + one card (title only).
      await alicePage.page.getByTestId("new-board-toggle").click();
      await alicePage.page.getByTestId("new-board-title-input").fill(`Enc Board ${stamp}`);
      await alicePage.page.getByTestId("create-board-space-button").click();
      await expect(alicePage.page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
        timeout: 45_000,
      });

      const todoColumnName = `Todo-${stamp}`;
      await alicePage.page.getByTestId("new-column-input").fill(todoColumnName);
      await alicePage.page.getByTestId("add-column-button").click();
      const todoColumn = alicePage.page
        .getByTestId("kanban-column")
        .filter({ hasText: todoColumnName })
        .first();
      await expect(todoColumn).toBeVisible({ timeout: 45_000 });

      await todoColumn.getByTestId("add-card-button").click();
      await todoColumn.getByTestId("new-card-title-input").fill(cardTitle);
      await todoColumn.getByTestId("save-card-button").click();
      const cardLocator = todoColumn
        .getByTestId("kanban-card")
        .filter({ hasText: cardTitle })
        .first();
      await expect(cardLocator).toBeVisible({ timeout: 45_000 });
      await stepShot(alicePage.page, testInfo, "A-encrypted-card-created");

      // Open the card → Description tab → add a description through the UI.
      // The Description editor binds to the Strand's private `body` field, which
      // is exactly what the content-encryption floor inspects.
      await cardLocator.click();
      await expect(alicePage.page.getByTestId("card-detail-modal")).toBeVisible({ timeout: 45_000 });
      await alicePage.page.getByTestId("card-detail-tab-description").click();
      await alicePage.page.getByTestId("card-detail-add-description-button").click();

      const editor = alicePage.page.getByTestId("card-detail-description-input");
      await expect(editor).toBeAttached({ timeout: 45_000 });
      await editor.evaluate((node, value) => {
        const textarea = node as HTMLTextAreaElement;
        textarea.value = value;
        textarea.dispatchEvent(
          new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }),
        );
      }, description);

      // The encrypted ak.strand.update submit must reach soland and be accepted,
      // not bounced by the content-encryption floor.
      const strandUpdate = alicePage.page.waitForResponse(
        (response) =>
          response.url().includes("/_arkret/self/events") &&
          response.request().method() === "POST" &&
          (response.request().postData() ?? "").includes("ak.strand.update"),
        { timeout: 60_000 },
      );
      await alicePage.page.getByTestId("card-detail-save-button").click();

      const response = await strandUpdate;
      const responseBody = await response.text();
      expect(
        responseBody.includes("content_encryption_floor_violation"),
        `ak.strand.update for the description hit the content-encryption floor — the client shipped plaintext body to an encrypted Realm: ${response.status()} ${responseBody.slice(0, 500)}`,
      ).toBe(false);
      expect(
        response.status(),
        `ak.strand.update should be accepted; body=${responseBody.slice(0, 500)}`,
      ).toBeLessThan(400);
      // Prove the write was actually ENCRYPTED, not a false-green on a
      // plaintext realm: the private description must not appear verbatim in
      // the submitted payload (it should be an MLS encrypted envelope).
      expect(
        (response.request().postData() ?? "").includes(description),
        `description leaked as plaintext into the ak.strand.update body — the realm was not actually encrypted or the client skipped MLS encryption`,
      ).toBe(false);

      // UI corroboration: the description renders and no encrypted-write error
      // surfaces anywhere in the detail panel.
      await expect(alicePage.page.getByTestId("card-description-panel")).toContainText(description, {
        timeout: 120_000,
      });
      await expect(
        alicePage.page.getByText(/content_encryption_floor_violation|blocks plaintext/i),
      ).toHaveCount(0);
      expect(floorViolations, floorViolations.join("\n")).toEqual([]);
      await stepShot(alicePage.page, testInfo, "B-encrypted-description-saved");
    } finally {
      await alicePage.close();
    }
  });

  // Regression: encrypted Strand SYNTHESIS on the creator device. `synthesis` is
  // a distinct private content path from `body` (see soland operations.rs
  // strand_operation_carries_plaintext_private_content / inkson
  // KANBAN_PRIVATE_STRAND_PATCH_PATHS) and rides its own client encryption +
  // commit code path, so it needs its own guard.
  test("alice adds a strand synthesis on a freshly-created MLS-encrypted realm; soland accepts the encrypted ak.strand.update", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(180_000);
    const stamp = Date.now();
    const aliceFlow = await openDpopUserPage(browser, request, "kanban-enc-synth-alice");
    if (!aliceFlow) {
      assertJointStackNotRequired("encrypted kanban synthesis DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;

    const cardTitle = `Synthesis Card ${stamp}`;
    const synthesis = `Encrypted synthesis note ${stamp}`;
    const floorViolations = recordFloorViolations(alicePage.page);

    try {
      const realmId = await alicePage.createRealm({
        title: `Encrypted Kanban Synthesis ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        encryptionProfile: "mls_rfc9420",
      });
      await buildEncryptedBoardAndCard(alicePage.page, realmId, stamp, cardTitle);

      await alicePage.page
        .getByTestId("kanban-card")
        .filter({ hasText: cardTitle })
        .first()
        .click();
      await expect(alicePage.page.getByTestId("card-detail-modal")).toBeVisible({ timeout: 45_000 });
      await alicePage.page.getByTestId("card-detail-tab-synthesis").click();
      await alicePage.page.getByTestId("card-detail-new-synthesis-button").click();
      await setCardDetailEditorValue(alicePage.page, synthesis);

      const strandUpdate = alicePage.page.waitForResponse(
        (response) =>
          response.url().includes("/_arkret/self/events") &&
          response.request().method() === "POST" &&
          (response.request().postData() ?? "").includes("ak.strand.update"),
        { timeout: 60_000 },
      );
      await alicePage.page.getByTestId("card-detail-save-button").click();

      const response = await strandUpdate;
      const responseBody = await response.text();
      expect(
        responseBody.includes("content_encryption_floor_violation"),
        `synthesis ak.strand.update hit the content-encryption floor — client shipped plaintext synthesis: ${response.status()} ${responseBody.slice(0, 500)}`,
      ).toBe(false);
      expect(
        response.status(),
        `synthesis ak.strand.update should be accepted; body=${responseBody.slice(0, 500)}`,
      ).toBeLessThan(400);
      expect(
        (response.request().postData() ?? "").includes(synthesis),
        `synthesis leaked as plaintext into the ak.strand.update body — realm not actually encrypted or client skipped MLS encryption`,
      ).toBe(false);

      await expect(alicePage.page.getByTestId("card-synthesis-panel")).toContainText(synthesis, {
        timeout: 120_000,
      });
      expect(floorViolations, floorViolations.join("\n")).toEqual([]);
      await stepShot(alicePage.page, testInfo, "encrypted-synthesis-saved");
    } finally {
      await alicePage.close();
    }
  });

  // Regression: encrypted Strand DISCUSSION comment on the creator device.
  //
  // Historical regression: this path used to submit plaintext ak.message.create
  // envelopes from the discussion composer. The client now routes chat sends
  // through secure_send and SDK encrypted-envelope construction; this test pins
  // that soland accepts the encrypted event and that plaintext does not appear
  // in the submitted request body.
  test("alice posts a strand discussion comment on a freshly-created MLS-encrypted realm; soland accepts the encrypted ak.message.create", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(180_000);
    const stamp = Date.now();
    const aliceFlow = await openDpopUserPage(browser, request, "kanban-enc-disc-alice");
    if (!aliceFlow) {
      assertJointStackNotRequired("encrypted kanban discussion DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;

    const cardTitle = `Discussion Card ${stamp}`;
    const comment = `Encrypted discussion comment ${stamp}`;
    const floorViolations = recordFloorViolations(alicePage.page);

    try {
      const realmId = await alicePage.createRealm({
        title: `Encrypted Kanban Discussion ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        encryptionProfile: "mls_rfc9420",
      });
      await buildEncryptedBoardAndCard(alicePage.page, realmId, stamp, cardTitle);

      await alicePage.page
        .getByTestId("kanban-card")
        .filter({ hasText: cardTitle })
        .first()
        .click();
      await expect(alicePage.page.getByTestId("card-detail-modal")).toBeVisible({ timeout: 45_000 });
      await alicePage.page.getByTestId("card-detail-tab-discussion").click();
      await expect(alicePage.page.getByTestId("chat-panel")).toBeVisible({ timeout: 45_000 });

      const messageCreate = alicePage.page.waitForResponse(
        (response) =>
          response.url().includes("/_arkret/self/events") &&
          response.request().method() === "POST" &&
          (response.request().postData() ?? "").includes("ak.message.create"),
        { timeout: 60_000 },
      );
      await alicePage.page.getByTestId("chat-input").fill(comment);
      await alicePage.page.getByTestId("send-chat-button").click();

      const response = await messageCreate;
      const responseBody = await response.text();
      expect(
        responseBody.includes("content_encryption_floor_violation"),
        `discussion comment hit the content-encryption floor: ${response.status()} ${responseBody.slice(0, 500)}`,
      ).toBe(false);
      expect(
        response.status(),
        `discussion ak.message.create should be accepted (encrypted), not rejected; body=${responseBody.slice(0, 500)}`,
      ).toBeLessThan(400);
      expect(
        (response.request().postData() ?? "").includes(comment),
        `comment leaked as plaintext into the ak.message.create body — realm not actually encrypted or client skipped MLS encryption`,
      ).toBe(false);

      await expect(alicePage.page.getByTestId("chat-panel")).toContainText(comment, {
        timeout: 120_000,
      });
      expect(floorViolations, floorViolations.join("\n")).toEqual([]);
      await stepShot(alicePage.page, testInfo, "encrypted-discussion-comment");
    } finally {
      await alicePage.close();
    }
  });
});

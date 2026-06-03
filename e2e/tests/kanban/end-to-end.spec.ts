// Kanban end-to-end
// Contract: e2e/scenarios/kanban/end-to-end.md
// Spec refs:
//   - models/realm-and-space.md §3 (Space containers), §3.5 (parent/rank basis)
//   - models/flow-and-message.md §2-§3 (Flow), §4.3 (discussion track)
//   - models/relation.md §3.2 (contains)

import { expect, test, type Page } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

// ---------------------------------------------------------------------------
// Shared rig for the "creator device, encrypted Realm" regression trio
// (description / synthesis / discussion comment). Each guards that a private
// Flow content path round-trips as an ENCRYPTED write on the SAME device that
// just created the Realm. The plaintext happy-paths above never arm the
// content-encryption floor (createSpace defaults encryption_profile to
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
      !response.url().includes("/_cokret/self/events") ||
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

async function buildEncryptedBoardAndCard(
  page: Page,
  spaceId: string,
  stamp: number,
  cardTitle: string,
): Promise<void> {
  await page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
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
  await column.getByTestId("add-card-button").click();
  await column.getByTestId("new-card-title-input").fill(cardTitle);
  await column.getByTestId("save-card-button").click();
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

test.describe("kanban end-to-end", () => {
  test("alice opens kanban, adds 3 columns, adds 2 cards in Todo, archives Card A, restores it", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("kanban-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    const cardA = `Card A ${stamp}`;
    const cardB = `Card B ${stamp}`;

    try {
      // Create a space so the kanban view has a selected_space context.
      const spaceId = await alicePage.createSpace({
        title: `Kanban Space ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });
      // Kanban scopes writes to selected_space; navigate with the explicit
      // space_id so the route resolves to the freshly-created space (plain
      // `/kanban` falls back to the first preview, which on a fresh session
      // is the hardcoded demo space the test user is NOT a member of, and
      // every cx.flow.* event would 403 with capability_denied).
      await alicePage.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
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
        await todoColumn.getByTestId("add-card-button").click();
        await todoColumn.getByTestId("new-card-title-input").fill(cardName);
        await todoColumn.getByTestId("save-card-button").click();
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

  test.fixme(
    // @blocking-on: soland#kanban-end-to-end-gap
    // @user-promise: e2e/scenarios/kanban/end-to-end.md
    // @expected-live-by: 2026Q3
    "concurrent cross-list move: cas-register accepts one winner, rejects the other with cas_register_conflict",
    async () => {
      // spec: realm-and-space.md / operations-sync.md flow position basis
    },
  );

  test.fixme(
    // @blocking-on: soland#kanban-end-to-end-gap
    // @user-promise: e2e/scenarios/kanban/end-to-end.md
    // @expected-live-by: 2026Q3
    "cross-space contains relation rejected with reason=cross_space_structural_relation",
    async () => {
      // spec: models/relation.md §3.2 — structural relations MUST stay
      // within a single Space. Server enforcement landed (relation.rs
      // cross-space check), but driving the test through the kanban UI
      // is brittle (yougen page load + kanban panel render hits 180s
      // timeout under joint-e2e contention). Re-enable once a
      // programmatic flow-creation helper (signed ck.flow.create POST)
      // lands or yougen's kanban view stabilizes its load timing.
    },
  );

  test.fixme(
    // @blocking-on: soland#kanban-end-to-end-gap
    // @user-promise: e2e/scenarios/kanban/end-to-end.md
    // @expected-live-by: 2026Q3
    "commenting on an archived flow is rejected by reducer (no writes on archived Flow)",
    async () => {
      // spec: common-fields.md lifecycle archived-state write constraints
    },
  );

  test("column drag handles expose stable targets and reorder columns locally", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("kanban-column-drag-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    const first = `First-${stamp}`;
    const second = `Second-${stamp}`;
    const third = `Third-${stamp}`;

    try {
      const spaceId = await alicePage.createSpace({
        title: `Kanban Column Drag ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });
      await alicePage.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
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
      await expect(firstColumn.getByTestId("column-drop-target-before")).toBeVisible();
      await expect(thirdColumn.getByTestId("column-drag-handle")).toBeVisible();

      await thirdColumn
        .getByTestId("column-drag-handle")
        .dragTo(firstColumn.getByTestId("column-drop-target-before"));
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
    const alice = uniqueUser("kanban-order-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    const first = `First-${stamp}`;
    const second = `Second-${stamp}`;
    const third = `Third-${stamp}`;

    try {
      const spaceId = await alicePage.createSpace({
        title: `Kanban Order ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });
      await alicePage.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
      await alicePage.page.getByTestId("new-board-toggle").click();
      await alicePage.page.getByTestId("new-board-title-input").fill(`Order Board ${stamp}`);
      await alicePage.page.getByTestId("create-board-space-button").click();
      await expect(alicePage.page.getByTestId("kanban-empty-board")).toContainText(/No lists yet/, {
        timeout: 30_000,
      });
      const boardId = await alicePage.page
        .getByTestId("board-space-select")
        .evaluate((node) => (node as HTMLSelectElement).value);
      expect(boardId).toMatch(/^ck:space:/);

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
              `${solandBaseUrl()}/_cokret/self/spaces/${encodeURIComponent(boardId)}/cells/cx.component.child_order.v1`,
              { headers: { authorization: `Bearer ${aliceToken}` } },
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
  // The happy-path kanban tests above build PLAINTEXT spaces — createSpace
  // leaves encryption_profile unset, which defaults to "none" (see
  // helpers/users.ts + soland-api.ts), so soland's content-encryption floor
  // (operations.rs validate_content_encryption_floor) is never armed and the
  // card detail only ever carries a `title`, never a private `body`. The
  // yougen setup wizard, however, defaults new Realms to `mls_rfc9420` (the
  // "Encrypted" badge). Adding a Flow description writes the private `body`
  // patch path, so on an encrypted Realm the client MUST encrypt it before
  // submit; if it ships plaintext, soland rejects the ck.flow.update with 412
  // `content_encryption_floor_violation` (exactly the failure reported from
  // the UI). encryption/key-backup.spec.ts A2 exercises this only on a
  // RESTORED second device — never on the original creator device, which is
  // the path this guards.
  test("alice adds a flow description on a freshly-created MLS-encrypted realm; soland accepts the encrypted ck.flow.update (no content_encryption_floor_violation)", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(180_000);
    const stamp = Date.now();
    const alice = uniqueUser("kanban-enc-desc-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

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
        !response.url().includes("/_cokret/self/events") ||
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
      // Encrypted Realm — mirrors the yougen setup-wizard default. This is the
      // single line that distinguishes this case from the plaintext happy
      // paths above and arms the content-encryption floor.
      const spaceId = await alicePage.createSpace({
        title: `Encrypted Kanban ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });

      await alicePage.page.goto(`/kanban/${spaceId}`, { waitUntil: "domcontentloaded" });
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
      // The Description editor binds to the Flow's private `body` field, which
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

      // The encrypted ck.flow.update submit must reach soland and be accepted,
      // not bounced by the content-encryption floor.
      const flowUpdate = alicePage.page.waitForResponse(
        (response) =>
          response.url().includes("/_cokret/self/events") &&
          response.request().method() === "POST" &&
          (response.request().postData() ?? "").includes("ck.flow.update"),
        { timeout: 60_000 },
      );
      await alicePage.page.getByTestId("card-detail-save-button").click();

      const response = await flowUpdate;
      const responseBody = await response.text();
      expect(
        responseBody.includes("content_encryption_floor_violation"),
        `ck.flow.update for the description hit the content-encryption floor — the client shipped plaintext body to an encrypted Realm: ${response.status()} ${responseBody.slice(0, 500)}`,
      ).toBe(false);
      expect(
        response.status(),
        `ck.flow.update should be accepted; body=${responseBody.slice(0, 500)}`,
      ).toBeLessThan(400);
      // Prove the write was actually ENCRYPTED, not a false-green on a
      // plaintext realm: the private description must not appear verbatim in
      // the submitted payload (it should be an MLS encrypted envelope).
      expect(
        (response.request().postData() ?? "").includes(description),
        `description leaked as plaintext into the ck.flow.update body — the realm was not actually encrypted or the client skipped MLS encryption`,
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

  // Regression: encrypted Flow SYNTHESIS on the creator device. `synthesis` is
  // a distinct private content path from `body` (see soland operations.rs
  // flow_operation_carries_plaintext_private_content / yougen
  // KANBAN_PRIVATE_FLOW_PATCH_PATHS) and rides its own client encryption +
  // commit code path, so it needs its own guard.
  test("alice adds a flow synthesis on a freshly-created MLS-encrypted realm; soland accepts the encrypted ck.flow.update", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(180_000);
    const stamp = Date.now();
    const alice = uniqueUser("kanban-enc-synth-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    const cardTitle = `Synthesis Card ${stamp}`;
    const synthesis = `Encrypted synthesis note ${stamp}`;
    const floorViolations = recordFloorViolations(alicePage.page);

    try {
      const spaceId = await alicePage.createSpace({
        title: `Encrypted Kanban Synthesis ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });
      await buildEncryptedBoardAndCard(alicePage.page, spaceId, stamp, cardTitle);

      await alicePage.page
        .getByTestId("kanban-card")
        .filter({ hasText: cardTitle })
        .first()
        .click();
      await expect(alicePage.page.getByTestId("card-detail-modal")).toBeVisible({ timeout: 45_000 });
      await alicePage.page.getByTestId("card-detail-tab-synthesis").click();
      await alicePage.page.getByTestId("card-detail-new-synthesis-button").click();
      await setCardDetailEditorValue(alicePage.page, synthesis);

      const flowUpdate = alicePage.page.waitForResponse(
        (response) =>
          response.url().includes("/_cokret/self/events") &&
          response.request().method() === "POST" &&
          (response.request().postData() ?? "").includes("ck.flow.update"),
        { timeout: 60_000 },
      );
      await alicePage.page.getByTestId("card-detail-save-button").click();

      const response = await flowUpdate;
      const responseBody = await response.text();
      expect(
        responseBody.includes("content_encryption_floor_violation"),
        `synthesis ck.flow.update hit the content-encryption floor — client shipped plaintext synthesis: ${response.status()} ${responseBody.slice(0, 500)}`,
      ).toBe(false);
      expect(
        response.status(),
        `synthesis ck.flow.update should be accepted; body=${responseBody.slice(0, 500)}`,
      ).toBeLessThan(400);
      expect(
        (response.request().postData() ?? "").includes(synthesis),
        `synthesis leaked as plaintext into the ck.flow.update body — realm not actually encrypted or client skipped MLS encryption`,
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

  // Regression: encrypted Flow DISCUSSION comment on the creator device.
  //
  // CONFIRMED BUG (parked — fix is a sizable SDK+yougen feature). Two layers:
  //   1. The kanban card Discussion composer's default Send (chat.rs
  //      `send-chat-button`) ships PLAINTEXT ck.message.create unconditionally;
  //      soland accepts it (ck.message.create is not gated by the content
  //      encryption floor — only cx.flow.* is). The encrypt path
  //      (`run_local_mls_encrypt`) was additionally wasm-stubbed.
  //   2. Deeper: even when the encrypt path runs, yougen builds the message
  //      `encrypted_payload` from the loose `core::EncryptedPayload`
  //      (group.encrypt_payload), which does NOT conform to soland's
  //      ck.schema.encrypted_envelope.v1 — it is missing `version`,
  //      `aad_visibility_event_id`, `aad.{realm_id,event_kind}`, `aad_digest`,
  //      and key_ref.algorithm must be "MLS". So an encrypted message is
  //      rejected with schema_violation. (kanban flow content "works" only
  //      because flow patch values aren't validated against that envelope
  //      schema.) The conforming builder exists in the SDK
  //      (cokret-rust-sdk crates/sdk/src/mls.rs MessageCrypto::encrypt_with_aad);
  //      yougen's chat send must be wired to it. Promote once that lands.
  test("alice posts a flow discussion comment on a freshly-created MLS-encrypted realm; soland accepts the encrypted ck.message.create", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(180_000);
    const stamp = Date.now();
    const alice = uniqueUser("kanban-enc-disc-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    const cardTitle = `Discussion Card ${stamp}`;
    const comment = `Encrypted discussion comment ${stamp}`;
    const floorViolations = recordFloorViolations(alicePage.page);

    try {
      const spaceId = await alicePage.createSpace({
        title: `Encrypted Kanban Discussion ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });
      await buildEncryptedBoardAndCard(alicePage.page, spaceId, stamp, cardTitle);

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
          response.url().includes("/_cokret/self/events") &&
          response.request().method() === "POST" &&
          (response.request().postData() ?? "").includes("ck.message.create"),
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
        `discussion ck.message.create should be accepted (encrypted), not rejected; body=${responseBody.slice(0, 500)}`,
      ).toBeLessThan(400);
      expect(
        (response.request().postData() ?? "").includes(comment),
        `comment leaked as plaintext into the ck.message.create body — realm not actually encrypted or client skipped MLS encryption`,
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

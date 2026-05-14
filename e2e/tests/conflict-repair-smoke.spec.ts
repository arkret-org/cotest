import { expect, test } from "@playwright/test";
import { stepShot } from "../helpers/screenshots";
import { ensureRegistered, issueDevSession, openUserPage, uniqueUser } from "../helpers/users";

test.describe.configure({ mode: "serial" });

const SEED_SPACE_ID = "cx:space:demo-conflict-repair";
const MEMBER_CELL = "cx:cell:cx.component.member.state.v1:did:web:victim.example";
const GRANT_CELL = "cx:cell:cx.component.capability.grant.v1:cx.grant.demo-alpha";

// Anchor view seeded into localStorage so the Repair section renders the
// bottom-cells banner + side-by-side heads without us having to drive a
// real concurrent-Move scenario through soland. Mirrors the wire shape
// `LocalAnchorView::from_sync_body` expects (yougen/src/local_state.rs).
const seededLocalState = {
  anchor_views: {
    [SEED_SPACE_ID]: {
      frontier: ["cx:anchor:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      leaves: [],
      state_root: "cx:state:sha256:abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca",
      bottom_cells: {
        [MEMBER_CELL]: {
          status: "expose",
          heads: [
            {
              move_id: "cx:event:joined",
              value: { membership: "join" },
            },
            {
              move_id: "cx:event:banned",
              value: { membership: "ban", reason: "abuse" },
            },
          ],
        },
        [GRANT_CELL]: {
          status: "expose",
          heads: [
            {
              move_id: "cx:event:granted",
              value: { status: "active", scope: "cx.flow.write" },
            },
            {
              move_id: "cx:event:revoked",
              value: { status: "revoked", reason: "key_compromise" },
            },
          ],
        },
      },
    },
  },
};

test("conflict-repair: bottom banner renders, prefer-safer-side prefills ban over join and revoked over active", async ({
  browser,
  request,
}, testInfo) => {
  const user = uniqueUser("repair");
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);

  try {
    // Seed the local anchor view BEFORE the app boots so the
    // LocalStateStore hydrates with our two bottom_cells. Mirrors the
    // pattern users.ts already uses for yougen.config.v1.
    await actor.page.context().addInitScript((state) => {
      window.localStorage.setItem("yougen.local_state.v1", JSON.stringify(state));
    }, seededLocalState);

    // Navigate straight to the Repair section. The route segment
    // /space/:space_id/admin/:section is defined in yougen/src/routes.rs.
    const targetUrl = `/space/${SEED_SPACE_ID}/admin/repair`;
    await actor.page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    await expect(actor.page.getByTestId("space-admin-panel")).toBeVisible({ timeout: 120_000 });

    // Banner appears for at least one bottom-expose cell.
    const banner = actor.page.getByTestId("bottom-cells-banner");
    await expect(banner).toBeVisible();
    await stepShot(actor.page, testInfo, "01-bottom-cells-banner");

    // Both seeded cells render as bottom-cell-row entries.
    await expect(actor.page.getByTestId("bottom-cell-row")).toHaveCount(2);

    // Each cell contributed two heads — so four side-by-side head value
    // panels in total.
    await expect(actor.page.getByTestId("bottom-cell-head-value")).toHaveCount(4);

    // The repair dialog itself is present.
    await expect(actor.page.getByTestId("conflict-repair-dialog")).toBeVisible();

    // Two safer-side buttons — one per security-relevant cell family.
    const saferButtons = actor.page.getByTestId("prefer-safer-side-button");
    await expect(saferButtons).toHaveCount(2);

    // The button carries both data-testid and data-cell — use a
    // compound CSS selector that escapes the colons inside the value.
    // (filter({has: ...}) would not work here because data-cell is on
    // the button itself, not a descendant.)
    const saferButtonForCell = (cellId: string) =>
      actor.page.locator(
        `button[data-testid="prefer-safer-side-button"][data-cell="${cellId.replace(/"/g, '\\"')}"]`,
      );

    // Member.state safer-side: ban beats join.
    await saferButtonForCell(MEMBER_CELL).click();
    const winnerInput = actor.page.getByTestId("repair-winner-json-input");
    await expect(winnerInput).toHaveValue(/"membership":\s*"ban"/);
    await expect(actor.page.getByTestId("repair-target-cell-input")).toHaveValue(MEMBER_CELL);
    await expect(actor.page.getByTestId("repair-head-a-input")).toHaveValue("cx:event:joined");
    await expect(actor.page.getByTestId("repair-head-b-input")).toHaveValue("cx:event:banned");
    await stepShot(actor.page, testInfo, "02-prefer-safer-member-state-ban");

    // Capability.grant safer-side: revoked beats active.
    await saferButtonForCell(GRANT_CELL).click();
    await expect(winnerInput).toHaveValue(/"status":\s*"revoked"/);
    await expect(actor.page.getByTestId("repair-target-cell-input")).toHaveValue(GRANT_CELL);
    await expect(actor.page.getByTestId("repair-head-a-input")).toHaveValue("cx:event:granted");
    await expect(actor.page.getByTestId("repair-head-b-input")).toHaveValue("cx:event:revoked");
    await stepShot(actor.page, testInfo, "03-prefer-safer-capability-revoked");
  } finally {
    await actor.close();
  }
});

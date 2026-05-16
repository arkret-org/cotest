// Multi-user project simulation
// Contract: e2e/scenarios/kanban/project-simulation.md
// Spec refs:
//   - models/space-and-place.md §4 (Place), §3 (Join Policy)
//   - models/flow-and-message.md §3 (Flow fields)
//   - models/relation.md §3.2 (assigned_to), §6 (conflict resolution)

import { test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("project simulation", () => {
  test("alice builds sprint board with three Lists; invites bob+carol; both join", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s16-alice");
    const bob = uniqueUser("s16-bob");
    const carol = uniqueUser("s16-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const carolToken = await issueDevSession(request, carol);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
    const carolPage = await openUserPage(browser, carol, { sessionToken: carolToken });

    try {
      const spaceId = await alicePage.createSpace({
        title: `S16 Sprint ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did, carol.did],
      });

      // acceptInvite throws on non-2xx; success means the invite was
      // accepted server-side and bob/carol are now members.
      await bobPage.acceptInvite(spaceId);
      await carolPage.acceptInvite(spaceId);

      // Sanity: alice's admin landing renders.
      await alicePage.gotoSpaceAdmin(spaceId);
      await stepShot(alicePage.page, testInfo, "A-team-joined");
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  });

  test.fixme(
    "alice assigns Card 1 to bob via cx.relation.create assigned_to; bob's notifications surface the assignment",
    async () => {
      // spec: relation.md §3.2 assigned_to
      // soland gap: assigned_to relation kind + notification projection.
    },
  );

  test.fixme(
    "status FSM: Card transitions todo → in_progress → done via cx.flow.update; invalid transition (todo → done direct) rejected by FSM cell",
    async () => {
      // spec: flow-and-message.md §3 + space-and-place.md §3.8 FSM analogy.
    },
  );

  test.fixme(
    "due_date past today renders as overdue badge on the card UI",
    async () => {
      // spec: flow-and-message.md §3 (fields are opaque to reducer; UI semantics).
    },
  );

  test.fixme(
    "E16.G concurrent assignment from two devices: relation profile on_conflict=deterministic_winner picks one; Card has exactly one active assignee",
    async () => {
      // spec: relation.md §6
    },
  );

  test.fixme(
    "E16.1 unassign emits cx.relation.tombstone; assignment no longer shows in card UI",
    async () => {
      // spec: relation.md §3.2 tombstoned state
    },
  );

  test.fixme(
    "alice archives the entire board; archived board's cards become read-only; archive list view shows the board",
    async () => {
      // spec: space-and-place.md §4.4 lifecycle/cascade
    },
  );
});

// Multi-user project simulation
// Contract: e2e/scenarios/kanban/project-simulation.md
// Spec refs:
//   - models/realm-and-space.md §4 (Space container), §3 (Join Policy)
//   - models/strand-and-message.md §3 (Strand fields)
//   - models/relation.md §3.2 (assigned_to), §6 (conflict resolution)

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
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
    const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionCredential: bobToken });
    const carolPage = await openUserPage(browser, carol, { sessionCredential: carolToken });

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

  test.fixme(
    // @blocking-on: soland#kanban-project-simulation-gap
    // @user-promise: e2e/scenarios/kanban/project-simulation.md
    // @expected-live-by: 2026Q3
    "alice assigns Card 1 to bob via ck.relation.create assigned_to; bob's notifications surface the assignment",
    async () => {
      // spec: relation.md §3.2 assigned_to
      // soland gap: assigned_to relation kind + notification projection.
    },
  );

  test(
    "status FSM: Card transitions todo → in_progress → done via ck.strand.update; invalid transition (todo → done direct) rejected by FSM cell",
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
          kind: "ck.strand.create",
          createdAt: taskCreatedAt,
          payload: {
            object: {
              id: taskStrandId,
              schema: "ck.schema.strand.v1",
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

      const badDone = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId: realmId,
          kind: "ck.strand.update",
          payload: {
            strand_id: taskStrandId,
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
          kind: "ck.strand.update",
          payload: {
            strand_id: taskStrandId,
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
          kind: "ck.strand.update",
          payload: {
            strand_id: taskStrandId,
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
          kind: "ck.strand.create",
          createdAt: incidentCreatedAt,
          payload: {
            object: {
              id: incidentStrandId,
              schema: "ck.schema.strand.v1",
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

      const badResolved = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId: realmId,
          kind: "ck.strand.update",
          payload: {
            strand_id: incidentStrandId,
            patch: { metadata: { fields: { status: "resolved" } } },
          },
        }),
      });
      expect(badResolved.status()).toBe(412);
      expect(wireErrCode(await badResolved.json())).toBe("strand_status_transition_invalid");
    },
  );

  test.fixme(
    // @blocking-on: soland#kanban-project-simulation-gap
    // @user-promise: e2e/scenarios/kanban/project-simulation.md
    // @expected-live-by: 2026Q3
    "due_date past today renders as overdue badge on the card UI",
    async () => {
      // spec: strand-and-message.md §3 (fields are opaque to reducer; UI semantics).
    },
  );

  test.fixme(
    // @blocking-on: soland#kanban-project-simulation-gap
    // @user-promise: e2e/scenarios/kanban/project-simulation.md
    // @expected-live-by: 2026Q3
    "E16.G concurrent assignment from two devices: relation profile on_conflict=deterministic_winner picks one; Card has exactly one active assignee",
    async () => {
      // spec: relation.md §6
    },
  );

  test.fixme(
    // @blocking-on: soland#kanban-project-simulation-gap
    // @user-promise: e2e/scenarios/kanban/project-simulation.md
    // @expected-live-by: 2026Q3
    "E16.1 unassign emits ck.relation.tombstone; assignment no longer shows in card UI",
    async () => {
      // spec: relation.md §3.2 tombstoned state
    },
  );

  test.fixme(
    // @blocking-on: soland#kanban-project-simulation-gap
    // @user-promise: e2e/scenarios/kanban/project-simulation.md
    // @expected-live-by: 2026Q3
    "alice archives the entire board; archived board's cards become read-only; archive list view shows the board",
    async () => {
      // spec: realm-and-space.md §4.4 lifecycle/cascade
    },
  );
});

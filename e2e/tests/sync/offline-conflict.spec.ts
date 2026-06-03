// Offline edit / reconnect sync / conflict repair (bottom_cells)
// Contract: e2e/scenarios/sync/offline-conflict.md
// Spec: sync/client-sync.md §2, sync/operations-sync.md §2-§2.1, authz/event-auth-state-resolution.md §2, §8.1

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  allowPlaintextMessagesViaApi,
  createSharedSpaceViaApi,
  listSpaceEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import {
  authHeaders,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
  type JointUser,
  type JointUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("offline sync + conflict repair", () => {
  test("minimal reconnect smoke: bob misses alice writes while away, then events query catches up", async ({
    request,
  }) => {
    // Live slice for G2.T3: the true offline outbox send path is still
    // fixme below, but the existing sync surface can prove reconnect
    // backfill for messages written while the peer was disconnected.
    const stamp = Date.now();
    const alice = uniqueUser("g2t3-offline-alice");
    const bob = uniqueUser("g2t3-offline-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const m1 = `G2.T3 reconnect m1 ${stamp}`;
    const m2 = `G2.T3 reconnect m2 ${stamp}`;

    const spaceId = await createSharedSpaceViaApi(
      request,
      alice,
      aliceToken,
      bob,
      bobToken,
      {
        title: `G2.T3 Offline Backfill ${stamp}`,
        discoverability: "listed",
        historyVisibility: "shared",
      },
    );
    await allowPlaintextMessagesViaApi(request, aliceToken, spaceId);

    const before = JSON.stringify(await listSpaceEventsViaApi(request, bobToken, spaceId));
    expect(before).not.toContain(m1);
    expect(before).not.toContain(m2);

    await sendPlaintextMessageViaApi(request, aliceToken, spaceId, m1, { actorDid: alice.did });
    await sendPlaintextMessageViaApi(request, aliceToken, spaceId, m2, { actorDid: alice.did });

    await expect
      .poll(async () => JSON.stringify(await listSpaceEventsViaApi(request, bobToken, spaceId)), {
        timeout: 30_000,
      })
      .toContain(m1);
    const after = JSON.stringify(await listSpaceEventsViaApi(request, bobToken, spaceId));
    expect(after).toContain(m2);
  });

  test.fixme(
    // @blocking-on: soland#sync-offline-conflict-gap
    // @user-promise: e2e/scenarios/sync/offline-conflict.md
    // @expected-live-by: 2026Q3
    "bob composes a message while offline; on reconnect the message persists and is visible to alice",
    async () => {
      // spec: sync/client-sync.md §2 (outbox + reconnect flush)
      // yougen gap: no client-side outbox observed today; send on offline
      // returns failure with no retry queue. Spec contract is "compose
      // during partition + auto-flush on reconnect"; until yougen ships
      // an outbox + status indicator, this stays fixme.
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-offline-conflict-gap
    // @user-promise: e2e/scenarios/sync/offline-conflict.md
    // @expected-live-by: 2026Q3
    "during offline window alice writes; on bob's reconnect both writes are visible with deterministic ordering",
    async () => {
      // spec: sync/operations-sync.md §2
    },
  );

  test("concurrent writes to the same cas-register cell trigger bottom_expose; bottom-cells-banner shows the conflict", async ({
    browser,
    request,
  }) => {
    const fixture = await createBottomConflictFixture(browser, request, "banner");
    try {
      await fixture.bobPage.gotoSpaceAdminSection(fixture.spaceId, "repair");
      await expect(fixture.bobPage.page.getByTestId("bottom-cells-banner")).toBeVisible({
        timeout: 30_000,
      });
      await expect(fixture.bobPage.page.getByTestId("bottom-cell-row")).toContainText(
        "status=expose",
      );
      await expect(fixture.bobPage.page.getByTestId("bottom-cell-head")).toHaveCount(2);
      await expect(fixture.bobPage.page.getByTestId("prefer-safer-side-button")).toBeVisible();
    } finally {
      await closeBottomFixture(fixture);
    }
  });

  test("bob clicks prefer-safer-side-button to repair; reducer accepts repair Move with state_witness + inclusion_proof; banner clears", async ({
    browser,
    request,
  }) => {
    const fixture = await createBottomConflictFixture(browser, request, "repair");
    try {
      await fixture.bobPage.gotoSpaceAdminSection(fixture.spaceId, "repair");
      await expect(fixture.bobPage.page.getByTestId("bottom-cells-banner")).toBeVisible({
        timeout: 30_000,
      });
      await fixture.bobPage.page.getByTestId("prefer-safer-side-button").click();
      await expect(fixture.bobPage.page.getByTestId("repair-target-cell-input")).toHaveValue(
        /ck:cell:cx\.component\.realm\.organization\.v1:/,
      );
      await expect(fixture.bobPage.page.getByTestId("repair-winner-json-input")).toHaveValue(
        new RegExp(fixture.aliceTitle),
      );
      await fixture.bobPage.page.getByTestId("repair-submit-button").click();
      await expect(fixture.bobPage.page.getByTestId("space-admin-panel")).toContainText(
        /repair event .*state=accepted/,
        { timeout: 30_000 },
      );

      await expect
        .poll(async () => listBottomCells(request, fixture.bobToken, fixture.spaceId), {
          timeout: 30_000,
        })
        .toEqual([]);

      await fixture.bobPage.gotoSpaceAdminSection(fixture.spaceId, "repair");
      await expect(fixture.bobPage.page.getByTestId("bottom-cells-banner")).toHaveCount(0);
    } finally {
      await closeBottomFixture(fixture);
    }
  });

  test.fixme(
    // @blocking-on: soland#sync-offline-conflict-gap
    // @user-promise: e2e/scenarios/sync/offline-conflict.md
    // @expected-live-by: 2026Q3
    "long offline → on reconnect, pull-operations backfills missing events; bob's timeline catches up to head",
    async () => {
      // spec: sync/federation.md §4.2 (single-server uses same pull endpoint)
    },
  );
});

type BottomConflictFixture = {
  alice: JointUser;
  bob: JointUser;
  aliceToken: string;
  bobToken: string;
  bobPage: JointUserPage;
  spaceId: string;
  aliceTitle: string;
};

async function createBottomConflictFixture(
  browser: Parameters<typeof openUserPage>[0],
  request: APIRequestContext,
  label: string,
): Promise<BottomConflictFixture> {
  const stamp = Date.now();
  const alice = uniqueUser(`bottom-${label}-alice`);
  const bob = uniqueUser(`bottom-${label}-bob`);
  await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
  const [aliceToken, bobToken] = await Promise.all([
    issueDevSession(request, alice),
    issueDevSession(request, bob),
  ]);
  const spaceId = await createSharedSpaceViaApi(
    request,
    alice,
    aliceToken,
    bob,
    bobToken,
    {
      title: `bottom conflict ${label} ${stamp}`,
      historyVisibility: "shared",
    },
  );
  const basis = `ck:anchor:sha256:${"0".repeat(64)}`;
  const aliceTitle = `renamed by alice ${stamp}`;
  const bobTitle = `renamed by bob ${stamp}`;
  await submitRealmTitleUpdate(request, aliceToken, alice.did, spaceId, aliceTitle, basis);
  await submitRealmTitleUpdate(request, bobToken, bob.did, spaceId, bobTitle, basis);
  const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
  return { alice, bob, aliceToken, bobToken, bobPage, spaceId, aliceTitle };
}

async function submitRealmTitleUpdate(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  spaceId: string,
  title: string,
  anchorRef: string,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId: spaceId,
      kind: "cx.realm.update",
      anchorRef,
      payload: {
        target_ref: spaceId,
        patch: {
          title: { "$op": "set", value: title },
        },
      },
    }),
    { context: `realm title update ${title}` },
  );
}

async function listBottomCells(
  request: APIRequestContext,
  token: string,
  spaceId: string,
) {
  const response = await request.get(
    `${solandBaseUrl()}/_soland/admin/spaces/${encodeURIComponent(spaceId)}/bottom`,
    { headers: authHeaders(token) },
  );
  const text = await response.text();
  expect(response.status(), `list bottom cells: ${text}`).toBe(200);
  return JSON.parse(text);
}

async function closeBottomFixture(fixture: BottomConflictFixture) {
  await fixture.bobPage.close();
}

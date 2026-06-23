// Offline edit / reconnect sync / conflict repair (bottom_cells)
// Contract: e2e/scenarios/sync/offline-conflict.md
// Spec: sync/client-sync.md §2, sync/operations-sync.md §2-§2.1, authz/event-auth-state-resolution.md §2, §8.1

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  allowPlaintextMessagesViaApi,
  createSharedRealmViaApi,
  listRealmEventsViaApi,
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
    // Live slice for G2.T3: the browser outbox send path is covered in
    // sync/offline-queue-replay; this scenario proves reconnect backfill for
    // messages written while the peer was disconnected.
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

    const realmId = await createSharedRealmViaApi(
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
    await allowPlaintextMessagesViaApi(request, aliceToken, realmId);

    const before = JSON.stringify(await listRealmEventsViaApi(request, bobToken, realmId));
    expect(before).not.toContain(m1);
    expect(before).not.toContain(m2);

    await sendPlaintextMessageViaApi(request, aliceToken, realmId, m1, { actorDid: alice.did });
    await sendPlaintextMessageViaApi(request, aliceToken, realmId, m2, { actorDid: alice.did });

    await expect
      .poll(async () => JSON.stringify(await listRealmEventsViaApi(request, bobToken, realmId)), {
        timeout: 30_000,
      })
      .toContain(m1);
    const after = JSON.stringify(await listRealmEventsViaApi(request, bobToken, realmId));
    expect(after).toContain(m2);
  });

  // The browser outbox path is covered by sync/offline-queue-replay. This
  // scenario keeps the server catchup invariant live: a client that has not
  // polled during another actor's writes observes those writes in canonical
  // order once it queries again.
  test(
    "during offline window alice writes; on bob's reconnect both writes are visible with deterministic ordering",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser("g2t3-order-alice");
      const bob = uniqueUser("g2t3-order-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const messages = [
        `G2.T3 ordered m1 ${stamp}`,
        `G2.T3 ordered m2 ${stamp}`,
        `G2.T3 ordered m3 ${stamp}`,
      ];

      const realmId = await createSharedRealmViaApi(
        request,
        alice,
        aliceToken,
        bob,
        bobToken,
        {
          title: `G2.T3 ordered catchup ${stamp}`,
          discoverability: "listed",
          historyVisibility: "shared",
        },
      );
      await allowPlaintextMessagesViaApi(request, aliceToken, realmId);

      expect(
        orderedMessageBodies(
          await listRealmEventsViaApi(request, bobToken, realmId),
          messages,
        ),
      ).toEqual([]);

      for (const body of messages) {
        await sendPlaintextMessageViaApi(request, aliceToken, realmId, body, {
          actorDid: alice.did,
        });
      }

      await expect
        .poll(
          async () =>
            orderedMessageBodies(
              await listRealmEventsViaApi(request, bobToken, realmId),
              messages,
            ),
          { timeout: 30_000 },
        )
        .toEqual(messages);
    },
  );

  test("concurrent realm title updates do not create bottom_expose diagnostics", async ({
    browser,
    request,
  }) => {
    const fixture = await createBottomConflictFixture(browser, request, "banner");
    try {
      const bottomCells = await listBottomCells(request, fixture.bobToken, fixture.realmId);
      expect(bottomCells).toEqual([]);

      await fixture.bobPage.gotoRealmAdminSection(fixture.realmId, "repair");
      await expect(fixture.bobPage.page.getByTestId("realm-admin-panel")).toBeVisible();
      await expect(fixture.bobPage.page.getByTestId("prefer-safer-side-button")).toHaveCount(0);
    } finally {
      await closeBottomFixture(fixture);
    }
  });

  test("repair surface remains read-only when no registered bottom repair kind exists", async ({
    browser,
    request,
  }) => {
    const fixture = await createBottomConflictFixture(browser, request, "read-only");
    try {
      const before = await listBottomCells(request, fixture.bobToken, fixture.realmId);
      expect(before).toEqual([]);
      await fixture.bobPage.gotoRealmAdminSection(fixture.realmId, "repair");
      await expect(fixture.bobPage.page.getByTestId("prefer-safer-side-button")).toHaveCount(0);
      await expect(fixture.bobPage.page.getByTestId("repair-target-cell-input")).toHaveCount(0);
      await expect(fixture.bobPage.page.getByTestId("repair-winner-json-input")).toHaveCount(0);
      await expect(fixture.bobPage.page.getByTestId("repair-submit-button")).toHaveCount(0);

      const after = await listBottomCells(request, fixture.bobToken, fixture.realmId);
      expect(after).toHaveLength(before.length);
    } finally {
      await closeBottomFixture(fixture);
    }
  });

  test.fixme(
    // @blocking-on: soland#sync-offline-conflict-gap
    // @user-promise: e2e/scenarios/sync/offline-conflict.md
    // @expected-live-by: 2026Q3
    "long offline → on reconnect, peer events query backfills missing events; bob's timeline catches up to head",
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
  realmId: string;
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
  const realmId = await createSharedRealmViaApi(
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
  await submitRealmTitleUpdate(request, aliceToken, alice.did, realmId, aliceTitle, basis);
  await submitRealmTitleUpdate(request, bobToken, bob.did, realmId, bobTitle, basis);
  const bobPage = await openUserPage(browser, bob, { sessionCredential: bobToken });
  return { alice, bob, aliceToken, bobToken, bobPage, realmId, aliceTitle };
}

async function submitRealmTitleUpdate(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  title: string,
  anchorRef: string,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId: realmId,
      kind: "ck.realm.update",
      anchorRef,
      payload: {
        target_ref: realmId,
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
  realmId: string,
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${solandBaseUrl()}/_soland/admin/realms/${encodeURIComponent(realmId)}/bottom`,
    { headers: authHeaders(token) },
  );
  const text = await response.text();
  expect(response.status(), `list bottom cells: ${text}`).toBe(200);
  return JSON.parse(text);
}

function orderedMessageBodies(
  events: Array<Record<string, unknown>>,
  bodies: string[],
): string[] {
  const wanted = new Set(bodies);
  return events.flatMap((event) => {
    const body = messageBody(event);
    if (body && wanted.has(body)) {
      return [body];
    }
    const serialized = JSON.stringify(event);
    const fallback = bodies.find((candidate) => serialized.includes(candidate));
    return fallback ? [fallback] : [];
  });
}

function messageBody(event: Record<string, unknown>): string | undefined {
  const payload = event.payload;
  if (!isRecord(payload)) {
    return undefined;
  }
  const content = payload.content;
  if (!isRecord(content)) {
    return undefined;
  }
  return typeof content.body === "string" ? content.body : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function closeBottomFixture(fixture: BottomConflictFixture) {
  await fixture.bobPage.close();
}

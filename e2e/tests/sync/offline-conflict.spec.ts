// Offline edit / reconnect sync / conflict repair (bottom_cells)
// Contract: e2e/scenarios/sync/offline-conflict.md
// Spec: sync/client-sync.md §2, sync/operations-sync.md §2-§2.1, authz/event-auth-state-resolution.md §2, §8.1

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import {
  acceptInviteApi,
  authHeaders,
  createRealmApi,
  listInvitesApi,
  makeFederationEvent,
  peerEventFrontierApi,
  pushFederationEvents,
  queryPeerEventsApi,
  queryRealmEventsApi,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import { hasDualSoland, solandBaseUrl, solandServiceDid } from "../../helpers/env";
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

  test(
    "long offline → on reconnect, peer events query backfills missing events; bob's timeline catches up to head",
    async ({ request }) => {
      // spec: sync/federation.md §4.2 (pull / backfill uses the same peer events
      // query endpoint). Mirrors the federation "peer query recovery" active
      // test: while bob is offline alice writes, and on reconnect the missing
      // event is pulled via GET /_arkret/peer/events and bob's timeline catches
      // up to head.
      test.skip(
        !hasDualSoland(),
        "requires dual soland topology — pass -DualSoland to scripts/run-joint-e2e.ps1",
      );

      const stamp = Date.now();
      const alice = uniqueUser(`g2t3-backfill-alice-${stamp}`);
      const bob = uniqueUser(`g2t3-backfill-bob-${stamp}`);
      await ensureRegistered(request, alice, { server: "alpha" });
      await ensureRegistered(request, bob, { server: "beta" });
      const aliceToken = await issueDevSession(request, alice, {
        server: "alpha",
      });
      const bobToken = await issueDevSession(request, bob, { server: "beta" });

      const realmId = await createRealmApi(
        request,
        aliceToken,
        {
          title: `G2.T3 offline backfill ${stamp}`,
          discoverability: "listed",
          history_visibility: "shared",
          invitees: [bob.did],
          ownerDid: alice.did,
          plaintext_visible_services: [
            solandServiceDid("alpha"),
            solandServiceDid("beta"),
          ],
          federation_policy: "open",
        },
        { server: "alpha" },
      );
      const betaInvite = await waitForInvite(
        request,
        bobToken,
        bob.did,
        realmId,
        "beta",
      );
      await acceptInviteApi(
        request,
        bobToken,
        bob.did,
        betaInvite.realm_id,
        betaInvite.id,
        { server: "beta" },
      );
      await waitForMember(request, aliceToken, bob.did, realmId, "alpha");

      // Offline window: alice writes an event that bob never pulled.
      const missingBody = `offline backfill ${stamp}`;
      const missingEvent = makeFederationEvent({
        realmId,
        kind: "ak.message.create",
        actorDid: alice.did,
        payload: {
          strand_id: typedId("strand"),
          track_name: "discussion",
          content: {
            kind: "ak.content.text",
            body: missingBody,
          },
        },
      });
      await pushFederationEvents(request, [missingEvent], {
        origin: solandServiceDid("alpha"),
        destination: solandServiceDid("alpha"),
        server: "alpha",
        realmId,
        idempotencyKey: `${solandServiceDid("alpha")}#cotest-offline-source`,
      });
      await waitForEventBody(request, aliceToken, realmId, missingBody, "alpha");

      // Bob's server has not seen the event while offline.
      const betaBeforeEvents = await queryRealmEventsApi(
        request,
        bobToken,
        realmId,
        { server: "beta", limit: 100 },
      );
      expect(JSON.stringify(betaBeforeEvents)).not.toContain(missingBody);
      const alphaFrontier = await peerEventFrontierApi(request, realmId, {
        server: "alpha",
      });
      const betaFrontierBefore = await peerEventFrontierApi(request, realmId, {
        server: "beta",
      });
      expect(betaFrontierBefore.frontier_root).not.toBe(
        alphaFrontier.frontier_root,
      );

      // On reconnect: pull the missing event via the peer events query endpoint
      // and ingest it so bob's timeline catches up.
      const backfill = await queryPeerEventsApi(request, {
        server: "alpha",
        sourceDid: solandServiceDid("beta"),
        realmId,
        limit: 100,
      });
      const backfilledEvents = (backfill.events ?? [])
        .map((entry: { event?: Record<string, unknown> }) => entry.event)
        .filter(Boolean) as Array<Record<string, unknown>>;
      expect(backfilledEvents.map((event) => event.event_id)).toContain(
        missingEvent.event_id,
      );
      const ingest = await pushFederationEvents(request, backfilledEvents, {
        origin: solandServiceDid("alpha"),
        destination: solandServiceDid("beta"),
        server: "beta",
        realmId,
        idempotencyKey: `${solandServiceDid("beta")}#cotest-offline-backfill`,
      });
      expect(ingest.rejected ?? []).toEqual([]);
      expect(ingest.accepted).toContain(String(missingEvent.event_id));
      await waitForEventBody(request, bobToken, realmId, missingBody, "beta");

      // Timeline caught up to head: bob's frontier now covers alpha's heads.
      const betaFrontierAfter = await peerEventFrontierApi(request, realmId, {
        server: "beta",
      });
      for (const eventId of alphaFrontier.heads) {
        expect(betaFrontierAfter.heads).toContain(eventId);
      }
    },
  );
});

async function waitForInvite(
  request: APIRequestContext,
  token: string,
  inviteeDid: string,
  realmId: string,
  server: "alpha" | "beta",
) {
  let found:
    | {
        id: string;
        realm_id: string;
        invitee?: string;
        state?: string;
        status?: string;
      }
    | undefined;
  await expect
    .poll(
      async () => {
        const invites = await listInvitesApi(request, token, { server });
        found = invites.find(
          (invite) =>
            invite.invitee === inviteeDid && invite.realm_id === realmId,
        );
        return Boolean(found);
      },
      { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
    )
    .toBeTruthy();
  return found!;
}

async function waitForMember(
  request: APIRequestContext,
  token: string,
  memberDid: string,
  realmId: string,
  server: "alpha" | "beta",
) {
  await expect
    .poll(
      async () => {
        const response = await request.get(
          `${solandBaseUrl(server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
          { headers: authHeaders(token) },
        );
        if (!response.ok()) {
          return false;
        }
        const body = await response.json();
        return Array.isArray(body.members) && body.members.includes(memberDid);
      },
      { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
    )
    .toBeTruthy();
}

async function waitForEventBody(
  request: APIRequestContext,
  token: string,
  realmId: string,
  bodyText: string,
  server: "alpha" | "beta",
) {
  await expect
    .poll(
      async () => {
        const body = await queryRealmEventsApi(request, token, realmId, {
          server,
          limit: 100,
        });
        const events = Array.isArray(body.events) ? body.events : [];
        return events.some((event) => JSON.stringify(event).includes(bodyText));
      },
      { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
    )
    .toBeTruthy();
}

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
  const basis = `ak:anchor:sha256:${"0".repeat(64)}`;
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
      kind: "ak.realm.update",
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

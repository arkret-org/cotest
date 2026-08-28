// Offline edit / reconnect sync / conflict repair (bottom_cells)
// Contract: e2e/scenarios/sync/offline-conflict.md
// Spec: sync/client-sync.md §2, sync/operations-sync.md §2-§2.1, authz/event-auth-state-resolution.md §2, §8.1

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import {
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import {
  acceptInviteApi,
  advanceEnvelopeToActorFrontier,
  authHeaders,
  createRealmApi,
  listInvitesApi,
  makeFederationEvent,
  pushFederationEvents,
  queryPeerEventsApi,
  queryRealmEventsApi,
  readRealmSealBasis,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  waitForRealmControlIdleApi,
} from "../../helpers/soland-api";
import {
  hasDualSoland,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
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
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
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
      {
        title: `G2.T3 Offline Backfill ${stamp}`,
        discoverability: "listed",
        historyAccess: "all_history_for_current_members",
      },
    );
    const before = JSON.stringify(
      await listRealmEventsViaApi(request, bobToken, realmId),
    );
    expect(before).not.toContain(m1);
    expect(before).not.toContain(m2);

    await sendPlaintextMessageViaApi(request, aliceToken, realmId, m1, {
      actorId: alice.id,
    });
    await sendPlaintextMessageViaApi(request, aliceToken, realmId, m2, {
      actorId: alice.id,
    });

    await expect
      .poll(
        async () =>
          JSON.stringify(
            await listRealmEventsViaApi(request, bobToken, realmId),
          ),
        {
          timeout: 30_000,
        },
      )
      .toContain(m1);
    const after = JSON.stringify(
      await listRealmEventsViaApi(request, bobToken, realmId),
    );
    expect(after).toContain(m2);
  });

  // The browser outbox path is covered by sync/offline-queue-replay. This
  // scenario keeps the server catchup invariant live: a client that has not
  // polled during another actor's writes observes those writes in canonical
  // order once it queries again.
  test("during offline window alice writes; on bob's reconnect both writes are visible with deterministic ordering", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("g2t3-order-alice");
    const bob = uniqueUser("g2t3-order-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
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
      {
        title: `G2.T3 ordered catchup ${stamp}`,
        discoverability: "listed",
        historyAccess: "all_history_for_current_members",
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
        actorId: alice.id,
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
  });

  test("causally ordered realm title updates do not create bottom_expose diagnostics", async ({
    browser,
    request,
  }) => {
    const fixture = await createBottomConflictFixture(
      browser,
      request,
      "banner",
    );
    try {
      const bottomCells = await listBottomCells(
        request,
        fixture.bobToken,
        fixture.realmId,
      );
      expect(bottomCells).toEqual([]);

      await fixture.bobPage.gotoRealmAdminSection(fixture.realmId, "repair");
      await expect(
        fixture.bobPage.page.getByTestId("realm-admin-panel"),
      ).toBeVisible();
      await expect(
        fixture.bobPage.page.getByTestId("prefer-safer-side-button"),
      ).toHaveCount(0);
    } finally {
      await closeBottomFixture(fixture);
    }
  });

  test("repair surface remains read-only when no registered bottom repair kind exists", async ({
    browser,
    request,
  }) => {
    const fixture = await createBottomConflictFixture(
      browser,
      request,
      "read-only",
    );
    try {
      const before = await listBottomCells(
        request,
        fixture.bobToken,
        fixture.realmId,
      );
      expect(before).toEqual([]);
      await fixture.bobPage.gotoRealmAdminSection(fixture.realmId, "repair");
      await expect(
        fixture.bobPage.page.getByTestId("prefer-safer-side-button"),
      ).toHaveCount(0);
      await expect(
        fixture.bobPage.page.getByTestId("repair-target-cell-input"),
      ).toHaveCount(0);
      await expect(
        fixture.bobPage.page.getByTestId("repair-winner-json-input"),
      ).toHaveCount(0);
      await expect(
        fixture.bobPage.page.getByTestId("repair-submit-button"),
      ).toHaveCount(0);

      const after = await listBottomCells(
        request,
        fixture.bobToken,
        fixture.realmId,
      );
      expect(after).toHaveLength(before.length);
    } finally {
      await closeBottomFixture(fixture);
    }
  });

  test("long offline → on reconnect, peer events query backfills missing events; bob's timeline catches up to head", async ({
    request,
  }) => {
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
    const alice = uniqueUser(`g2t3-backfill-alice-${stamp}`, "alpha");
    const bob = uniqueUser(`g2t3-backfill-bob-${stamp}`, "beta");
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
        history_access: "all_history_for_current_members",
        invitees: [bob.id],
        invitee_service_ids: { [bob.id]: solandServiceId("beta") },
        ownerId: alice.id,
        creator_service_id: solandServiceId("alpha"),
        plaintext_visible_services: [
          solandServiceId("alpha"),
          solandServiceId("beta"),
        ],
        federation_policy: "open",
      },
      { server: "alpha" },
    );
    const betaInvite = await waitForInvite(
      request,
      bobToken,
      bob.id,
      realmId,
      "beta",
    );
    await acceptInviteApi(
      request,
      bobToken,
      bob.id,
      betaInvite.realm_id,
      betaInvite.id,
      { server: "beta" },
    );
    await waitForMember(request, aliceToken, bob.id, realmId, "alpha");

    // Offline window: alice writes an event that bob never pulled.
    const missingBody = `offline payload body ${stamp}`;
    const missingEvent = makeFederationEvent({
      realmId,
      kind: "ak.message.create",
      actorId: alice.id,
      payload: {
        strand_id: typedId("strand"),
        track_name: "discussion",
        content: {
          kind: "ak.content.text",
          body: missingBody,
        },
      },
    });
    await advanceEnvelopeToActorFrontier(
      request,
      aliceToken,
      missingEvent,
      "alpha",
    );
    const alphaEventsBeforeOfflineWrite = await queryRealmEventsApi(
      request,
      aliceToken,
      realmId,
      { server: "alpha", limit: 100 },
    );
    const creatorBindingEvent = (
      Array.isArray(alphaEventsBeforeOfflineWrite.events)
        ? alphaEventsBeforeOfflineWrite.events
        : []
    ).find((event) => {
      if (!event || typeof event !== "object") {
        return false;
      }
      const envelope = event as Record<string, unknown>;
      const payload =
        envelope.payload && typeof envelope.payload === "object"
          ? (envelope.payload as Record<string, unknown>)
          : undefined;
      const binding =
        payload?.delivery_binding &&
        typeof payload.delivery_binding === "object"
          ? (payload.delivery_binding as Record<string, unknown>)
          : undefined;
      return (
        envelope.kind === "ak.member.state" &&
        payload?.actor_id === alice.id &&
        payload.membership === "join" &&
        binding?.recipient_id === solandServiceId("alpha")
      );
    }) as Record<string, unknown> | undefined;
    expect(
      creatorBindingEvent?.event_id,
      "creator routable delivery-binding frontier",
    ).toEqual(expect.any(String));
    await pushFederationEvents(request, [missingEvent], {
      // Relay through the configured peer profile. A service's own
      // ServiceDescribe is not negotiated as a remote profile.
      origin: solandServiceId("beta"),
      destination: solandServiceId("alpha"),
      server: "alpha",
      realmId,
      idempotencyKey: `${solandServiceId("beta")}#cotest-offline-source`,
      serviceBindingFrontier: [String(creatorBindingEvent!.event_id)],
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
    // On reconnect: pull the missing event via the peer events query endpoint
    // and ingest it so bob's timeline catches up.
    const backfill = await queryPeerEventsApi(request, {
      server: "alpha",
      sourceServiceId: solandServiceId("beta"),
      realmId,
      limit: 100,
    });
    const backfilledEvents = backfill.events ?? [];
    expect(backfilledEvents.map((event) => event.event_id)).toContain(
      missingEvent.event_id,
    );
    const betaBeforeEventIds = new Set(
      (Array.isArray(betaBeforeEvents.events)
        ? (betaBeforeEvents.events as Array<Record<string, unknown>>)
        : []
      )
        .map((event) => event.event_id)
        .filter((eventId): eventId is string => typeof eventId === "string"),
    );
    const eventsToIngest = backfilledEvents.filter(
      (event) =>
        typeof event.event_id === "string" &&
        !betaBeforeEventIds.has(event.event_id),
    );
    expect(eventsToIngest.map((event) => event.event_id)).toContain(
      missingEvent.event_id,
    );
    const betaBindingEvent = backfilledEvents.find((event) => {
      const payload =
        event.payload && typeof event.payload === "object"
          ? (event.payload as Record<string, unknown>)
          : undefined;
      const target =
        payload?.invite_delivery_target &&
        typeof payload.invite_delivery_target === "object"
          ? (payload.invite_delivery_target as Record<string, unknown>)
          : undefined;
      return (
        event.kind === "ak.invite.create" &&
        payload?.invitee === bob.id &&
        target?.recipient_id === solandServiceId("beta")
      );
    });
    expect(
      betaBindingEvent?.event_id,
      "beta invite delivery-binding frontier",
    ).toEqual(expect.any(String));
    const ingest = await pushFederationEvents(request, eventsToIngest, {
      origin: solandServiceId("alpha"),
      destination: solandServiceId("beta"),
      server: "beta",
      realmId,
      idempotencyKey: `${solandServiceId("beta")}#cotest-offline-backfill`,
      serviceBindingFrontier: [String(betaBindingEvent!.event_id)],
    });
    expect(ingest.rejected ?? []).toEqual([]);
    expect(ingest.accepted).toContain(String(missingEvent.event_id));
    await waitForEventBody(request, bobToken, realmId, missingBody, "beta");

    // Timeline caught up: beta's peer-readable event set now covers every
    // event returned by alpha for this Realm. The standard peer frontier
    // surface is intentionally fail-closed for this profile.
    const betaAfter = await queryPeerEventsApi(request, {
      server: "beta",
      sourceServiceId: solandServiceId("alpha"),
      realmId,
      limit: 100,
    });
    const betaAfterEventIds = new Set(
      (betaAfter.events ?? [])
        .map((event) => event.event_id)
        .filter((eventId): eventId is string => typeof eventId === "string"),
    );
    for (const event of backfilledEvents) {
      expect(betaAfterEventIds).toContain(String(event.event_id));
    }
  });
});

async function waitForInvite(
  request: APIRequestContext,
  token: string,
  inviteeId: string,
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
            invite.invitee === inviteeId && invite.realm_id === realmId,
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
  memberId: string,
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
        return Array.isArray(body.members) && body.members.includes(memberId);
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
  browser: Parameters<typeof openDpopUserPage>[0],
  request: APIRequestContext,
  label: string,
): Promise<BottomConflictFixture> {
  const stamp = Date.now();
  const alice = uniqueUser(`bottom-${label}-alice`);
  const bobFlow = await openDpopUserPage(
    browser,
    request,
    `bottom-${label}-bob-${stamp}`,
    { prepareMlsDevice: false },
  );
  expect(bobFlow, "bottom repair fixture requires the joint DPoP stack").toBeDefined();
  const bob = bobFlow!.user;
  await ensureRegistered(request, alice);
  const [aliceToken, bobToken] = await Promise.all([
    issueDevSession(request, alice),
    issueDevSession(request, bob),
  ]);
  const initialTitle = `bottom conflict ${label} ${stamp}`;
  const realmId = await createSharedRealmViaApi(
    request,
    alice,
    aliceToken,
    bob,
    {
      title: initialTitle,
      historyAccess: "all_history_for_current_members",
    },
  );
  const aliceTitle = `renamed by alice ${stamp}`;
  const bobTitle = `renamed by bob ${stamp}`;
  await waitForRealmControlIdleApi(request, aliceToken, realmId);
  const beforeAliceUpdate = await readRealmSealBasis(
    request,
    aliceToken,
    realmId,
  );
  await submitRealmTitleUpdate(
    request,
    aliceToken,
    alice.id,
    realmId,
    aliceTitle,
    initialTitle,
  );
  await waitForRealmControlIdleApi(request, aliceToken, realmId, {
    afterControlEventSetRoot: String(beforeAliceUpdate.control_event_set_root),
  });
  await submitRealmTitleUpdate(
    request,
    bobToken,
    bob.id,
    realmId,
    bobTitle,
    aliceTitle,
  );
  await waitForRealmControlIdleApi(request, bobToken, realmId);
  const bobPage = bobFlow!.page;
  return { alice, bob, aliceToken, bobToken, bobPage, realmId, aliceTitle };
}

async function submitRealmTitleUpdate(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  title: string,
  previousTitle: string,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId,
      realmId: realmId,
      kind: "ak.realm.profile",
      preconditions: [
        {
          cell: "ak:cell:ak.component.realm.profile.v1:null",
          predicate: {
            op: "head_eq",
            value: {
              schema: "ak.schema.realm_profile.v1",
              title: previousTitle,
            },
          },
        },
      ],
      payload: {
        schema: "ak.schema.realm_profile.v1",
        title,
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

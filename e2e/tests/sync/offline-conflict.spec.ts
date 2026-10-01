// Offline edit / reconnect sync / ordered Realm profile succession
// Contract: e2e/scenarios/sync/offline-conflict.md
// Spec: sync/client-sync.md §2, sync/operations-sync.md §9, authz/event-auth-state-resolution.md §6, §8

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { grantInviteConsentArkret } from "../../helpers/contact-api";
import {
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import {
  acceptPreparedInviteApi,
  authHeaders,
  createRealmApi,
  grantCapabilityEventApi,
  pushCommittedRowsApi,
  queryRealmEventsApi,
  resolveDefaultStrandId,
  scanPeerRealmStreamRowsApi,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
  waitForInviteDeliveryApi,
} from "../../helpers/soland-api";
import {
  hasServerCount,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import {
  allowExplicitInviteNotifications,
  ensureRegistered,
  issueUserSession,
  openDpopUserPage,
  uniqueUser,
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
      issueUserSession(request, alice),
      issueUserSession(request, bob),
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
      issueUserSession(request, alice),
      issueUserSession(request, bob),
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
        await listRealmEventsViaApi(request, bobToken, realmId, { order: "ascending" }),
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
            await listRealmEventsViaApi(request, bobToken, realmId, { order: "ascending" }),
            messages,
          ),
        { timeout: 30_000 },
      )
      .toEqual(messages);
  });

  test("causally ordered realm title updates commit in order and the successor is the current profile", async ({
    browser,
    request,
  }) => {
    // spec: authz/event-auth-state-resolution.md section 6 - the current value
    // of a typed target is the last accepted write on its stream, ordered only
    // by the governance Station's stream_position; concurrent writes serialize
    // into positions and never produce a multi-head that needs repair.
    // models/realm-and-space.md section 2.3.A and event-kind-registry.json
    // (ak.realm.profile result_projection "set") make every accepted profile
    // Event a wholesale replacement of the realm_profile singleton.
    const fixture = await createRealmProfileSuccessionFixture(browser, request);
    try {
      await expect
        .poll(
          async () =>
            realmProfileTitles(
              await listRealmEventsViaApi(request, fixture.bobToken, fixture.realmId, {
                limit: 100,
              }),
              [fixture.aliceTitle, fixture.bobTitle],
            ),
          { timeout: 30_000 },
        )
        .toEqual([fixture.aliceTitle, fixture.bobTitle]);

      await fixture.bobPage.gotoRealmAdminSection(fixture.realmId, "profile");
      const profile = fixture.bobPage.page.getByTestId("realm-profile");
      await expect(profile).toBeVisible({ timeout: 60_000 });
      await expect(profile.getByTestId("realm-name-input")).toHaveValue(
        fixture.bobTitle,
        { timeout: 60_000 },
      );
    } finally {
      await fixture.bobPage.close();
    }
  });

  test("long offline → on reconnect, the authorized peer stream scan backfills missing Commits; bob's timeline catches up to head", async ({
    request,
  }) => {
    // spec: sync/federation.md §3 — recovery reads each authorized stream
    // through ak.peer.committed_event.read.scan.v1 and replicates the exact
    // (RealmCommit, Event) pairs through committed_replication; QUERY
    // peer/events is not a v1 read surface.
    test.skip(
      !hasServerCount(2),
      "requires two-server topology — pass -ServerCount 2 to scripts/run-joint-e2e.ps1",
    );

    const stamp = Date.now();
    const alice = uniqueUser(`g2t3-backfill-alice-${stamp}`, "server1");
    const bob = uniqueUser(`g2t3-backfill-bob-${stamp}`, "server2");
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueUserSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueUserSession(request, bob, { server: "server2" });

    await grantInviteConsentArkret(request, bobToken, bob, alice.id, {
      server: "server2", peerStationId: solandServiceId("server1"),
    });
    // createRealmApi addresses the invitation with explicit_address evidence.
    await allowExplicitInviteNotifications(request, bobToken, "server2");
    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: `G2.T3 offline backfill ${stamp}`,
        discoverability: "listed",
        history_access: "since_join",
        invitees: [bob.id],
        invitee_ids: { [bob.id]: solandServiceId("server2") },
        ownerId: alice.id,
        creator_id: solandServiceId("server1"),
        plaintext_visible_services: [
          solandServiceId("server1"),
          solandServiceId("server2"),
        ],
        federation_policy: "open",
      },
      { server: "server1" },
    );
    // bob joins through his own Station, which forwards the exact Event to
    // the governance Station and answers with its RealmCommit.
    await resolveDefaultStrandId(request, aliceToken, realmId, { server: "server1" });
    const invitation = await waitForInviteDeliveryApi(request, bobToken, bob.id, realmId, "server2");
    await acceptPreparedInviteApi(request, bobToken, bob.id, realmId, invitation.id, { server: "server2" });
    const realmUrl = `${solandBaseUrl("server2")}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
    await expect.poll(async () => {
      const response = await request.get(realmUrl, { headers: authHeaders(bobToken, "GET", realmUrl) });
      expect([200, 404], "the member's own join baseline must not hide service errors")
        .toContain(response.status());
      if (response.status() === 404) return false;
      const realm = await response.json() as { member_ids?: Array<{
        kind?: string; account_id?: { station_id?: string; principal_id?: string };
      }> };
      return realm.member_ids?.some((member) => member.kind === "account" &&
        member.account_id?.station_id === solandServiceId("server2") &&
        member.account_id?.principal_id === bob.id) === true;
    }, { timeout: 45_000, intervals: [1_000, 2_000, 5_000] }).toBe(true);

    // Offline window: alice writes while bob is away.
    const missingBody = `offline payload body ${stamp}`;
    const sent = await sendMessageApi(request, aliceToken, realmId, missingBody, {
      server: "server1",
    });
    await waitForEventBody(request, aliceToken, realmId, missingBody, "server1");

    // On reconnect server2 reads its authorized Realm stream from server1 and
    // replicates every exact pair it does not yet hold, in stream order.
    const server2Before = await queryRealmEventsApi(request, bobToken, realmId, {
      server: "server2",
      limit: 100,
    });
    const server2BeforeIds = new Set(
      (Array.isArray(server2Before.events)
        ? (server2Before.events as Array<Record<string, unknown>>)
        : []
      ).map((event) => String(event.event_id)),
    );
    const rows = await scanPeerRealmStreamRowsApi(request, {
      server: "server1",
      sourceServiceId: solandServiceId("server2"),
      realmId,
    });
    expect(rows.map((row) => row.event.event_id)).toContain(sent.event_id);
    const missing = rows.filter((row) => !server2BeforeIds.has(String(row.event.event_id))).slice(0, 100);
    if (missing.length > 0) {
      const ingest = await pushCommittedRowsApi(request, missing, {
        origin: solandServiceId("server1"),
        destination: solandServiceId("server2"),
        server: "server2",
        realmId,
      });
      expect(
        ingest.replication_outcomes.filter((outcome) => outcome.status === "rejected"),
        JSON.stringify(ingest),
      ).toEqual([]);
    }
    await waitForEventBody(request, bobToken, realmId, missingBody, "server2");

    // Timeline caught up: server2 now holds every Commit the scan disclosed,
    // each exactly once.
    const server2After = await queryRealmEventsApi(request, bobToken, realmId, {
      server: "server2",
      limit: 100,
    });
    const server2AfterIds = (Array.isArray(server2After.events)
      ? (server2After.events as Array<Record<string, unknown>>)
      : []
    ).map((event) => String(event.event_id));
    expect(new Set(server2AfterIds).size).toBe(server2AfterIds.length);
    for (const row of rows) {
      expect(server2AfterIds).toContain(String(row.event.event_id));
    }
  });
});

async function waitForEventBody(
  request: APIRequestContext,
  token: string,
  realmId: string,
  bodyText: string,
  server: "server1" | "server2",
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

type RealmProfileSuccessionFixture = {
  bobToken: string;
  bobPage: JointUserPage;
  realmId: string;
  aliceTitle: string;
  bobTitle: string;
};

async function createRealmProfileSuccessionFixture(
  browser: Parameters<typeof openDpopUserPage>[0],
  request: APIRequestContext,
): Promise<RealmProfileSuccessionFixture> {
  const stamp = Date.now();
  const alice = uniqueUser(`profile-succession-alice`);
  const bobFlow = await openDpopUserPage(
    browser,
    request,
    `profile-succession-bob-${stamp}`,
    { prepareMlsDevice: false },
  );
  expect(bobFlow, "profile succession fixture requires the joint DPoP stack").toBeDefined();
  const bob = bobFlow!.user;
  await ensureRegistered(request, alice);
  const [aliceToken, bobToken] = await Promise.all([
    issueUserSession(request, alice),
    issueUserSession(request, bob),
  ]);
  const initialTitle = `profile succession ${stamp}`;
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
  // Membership is not an authorization source (capabilities.md section 3.2):
  // bob writes the Realm profile under an explicit `ak.realm.profile` grant.
  // Its registry row requires `allowed_write_fields`, and a profile Event is a
  // complete replacement of the closed realm-profile value, so the grant
  // covers every profile member (constraint-schema.md sections 4.1 and 16.2).
  await grantCapabilityEventApi(request, aliceToken, {
    ownerId: alice.id,
    realmId,
    subjectId: bob.id,
    actions: ["ak.realm.profile"],
    constraints: [
      {
        constraint_kind: "field_access",
        effect: "allow",
        evaluation_class: "stateless",
        allowed_write_fields: ["title", "summary", "avatar_blob_ref"],
      },
    ],
  });
  const aliceTitle = `renamed by alice ${stamp}`;
  const bobTitle = `renamed by bob ${stamp}`;
  await submitRealmTitleUpdate(request, aliceToken, alice.id, realmId, aliceTitle);
  await submitRealmTitleUpdate(request, bobToken, bob.id, realmId, bobTitle);
  return { bobToken, bobPage: bobFlow!.page, realmId, aliceTitle, bobTitle };
}

async function submitRealmTitleUpdate(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  title: string,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId,
      realmId: realmId,
      kind: "ak.realm.profile",
      payload: {
        schema: "ak.schema.realm_profile.v1",
        title,
      },
    }),
    { context: `realm title update ${title}` },
  );
}

/// Titles of the committed `ak.realm.profile` Events in RealmCommit stream
/// order, restricted to the titles this fixture authored.
function realmProfileTitles(
  events: Array<Record<string, unknown>>,
  titles: string[],
): string[] {
  const wanted = new Set(titles);
  return events.flatMap((event) => {
    if (event.kind !== "ak.realm.profile" || !isRecord(event.payload)) {
      return [];
    }
    const title = event.payload.title;
    return typeof title === "string" && wanted.has(title) ? [title] : [];
  });
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

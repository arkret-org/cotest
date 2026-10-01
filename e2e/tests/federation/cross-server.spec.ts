// Cross-server federation
// Contract: e2e/scenarios/federation/cross-server.md
// Spec refs:
//   - sync/federation.md §2.1-§2.4 (trust roots, Event verification, profiles)
//   - §3.1-§3.2 DID server identity + RFC 9421 request signature
//   - §4.1 push protocol, §4.1.0 push sequence
//   - §4.2 authorized per-stream backfill and continuity
//   - §5.1 cross-domain invite
//
// Peer surfaces exercised (spec v1):
//   - POST /_arkret/peer/events, `committed_replication` branch: exact
//     source-committed (RealmCommit, Event) pairs, per-item stored|duplicate|
//     rejected outcomes (authority-commit-operations.schema.json)
//   - POST /_arkret/peer/streams/scan: per-stream replication read
//     (ak.peer.committed_event.read.scan.v1); QUERY peer/events is not v1
//   - own-Station join: self/realm-joins/prepare + self Event submit, which the
//     applicant's Station forwards to the current governance Station
//   - Realm fanout targets are the routing services of effective joined
//     members (federation.md §4.1.1)

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import {
  assertServerCountNotRequired,
  hasServerCount,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  acceptPreparedInviteApi,
  waitForInviteDeliveryApi,
  accountActorId,
  authHeaders,
  canonicalJson,
  createRealmApi,
  grantCapabilityEventApi,
  resolveDefaultStrandId,
  type StreamScanOutcome,
  type CommittedEventFullView,
  pushCommittedRowsApi,
  pushFederationEvents,
  rawPushFederationEvents,
  replicationOutcomesOutside,
  queryRealmEventsApi,
  readCommitStreamHeadApi,
  scanPeerRealmStreamRowsApi,
  sendMessageApi,
  sendPreparedMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  createDpopUserSession,
  allowExplicitInviteNotifications,
  ensureRegistered,
  issueInviteLocatorToken,
  issueUserSession,
  openDpopUserPage,
  openDpopUserPageFromSession,
  selfPathHeadersForDpopSession,
  uniqueUser,
} from "../../helpers/users";

test.beforeEach(() => {
  if (!hasServerCount(2)) {
    assertServerCountNotRequired("cross-server federation", 2);
    test.skip(
      true,
      "S2 requires two-server topology — pass -ServerCount 2 to scripts/run-joint-e2e.ps1",
    );
  }
});

function accountActorRoutesThrough(
  value: unknown,
  stationId: string,
  principalId?: string,
): boolean {
  if (!value || typeof value !== "object") return false;
  const actor = value as Record<string, unknown>;
  if (actor.kind !== "account" || !actor.account_id || typeof actor.account_id !== "object") {
    return false;
  }
  const account = actor.account_id as Record<string, unknown>;
  return (
    account.station_id === stationId &&
    (principalId === undefined || account.principal_id === principalId)
  );
}

/// Directed-invite join through the invitee's own Station: the invitation
/// arrives as `ak.account.invite_delivery` account data (invite-addressing.md
/// §7), and the join is prepared and submitted to that same Station, which
/// forwards the exact Event to the current governance Station.
async function joinFromOwnStation(
  request: APIRequestContext,
  token: string,
  inviteeId: string,
  realmId: string,
  server: "server1" | "server2",
) {
  const invitation = await waitForInviteDeliveryApi(request, token, inviteeId, realmId, server);
  return await acceptPreparedInviteApi(request, token, inviteeId, realmId, invitation.id, { server });
}

/// The self read of one committed Event at `server`, or the HTTP status when
/// the Station does not disclose it to this caller.
async function committedEventStatus(
  request: APIRequestContext,
  token: string,
  eventId: string,
  server: "server1" | "server2",
): Promise<number> {
  const url = `${solandBaseUrl(server)}/_arkret/self/committed-events/${eventId}`;
  const response = await request.get(url, { headers: authHeaders(token, "GET", url) });
  return response.status();
}

async function waitForMember(
  request: APIRequestContext,
  token: string,
  memberId: string,
  realmId: string,
  server: "server1" | "server2",
  memberServer: "server1" | "server2",
) {
  await expect
    .poll(
      async () => {
        const url = `${solandBaseUrl(server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
        const response = await request.get(url, { headers: authHeaders(token, "GET", url) });
        expect([200, 404], "membership baseline read uses the member's exact AccountId")
          .toContain(response.status());
        if (response.status() === 404) return false;
        const body = await response.json();
        return Array.isArray(body.member_ids) && body.member_ids.some(
          (member: unknown) => accountActorRoutesThrough(member, solandServiceId(memberServer), memberId),
        );
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
  server: "server1" | "server2",
) {
  await expect
    .poll(
      async () => {
        const body = await queryRealmEventsApi(request, token, realmId, {
          server,
          limit: 100,
          waitForJoinedCut: true,
        });
        const events = Array.isArray(body.events) ? body.events : [];
        return events.some((event) => JSON.stringify(event).includes(bodyText));
      },
      { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
    )
    .toBeTruthy();
}

function unsignedPeerHeaders(
  sourceServiceId: string,
  destinationServiceId: string,
): Record<string, string> {
  return {
    "source-service-id": sourceServiceId,
    "destination-service-id": destinationServiceId,
    "source-trust-domain": trustDomainFromServiceId(sourceServiceId),
    "destination-trust-domain": trustDomainFromServiceId(destinationServiceId),
  };
}

function trustDomainFromServiceId(serviceId: string): string {
  if (
    serviceId !== solandServiceId("server1") &&
    serviceId !== solandServiceId("server2")
  ) {
    throw new Error(`unexpected local federation service id: ${serviceId}`);
  }
  return "ak:trust_domain:local.host";
}

test.describe("cross-server federation", () => {
  test.describe.configure({ mode: "serial" });
  test("both soland instances expose the peer Event submit and peer stream scan endpoints", async ({
    request,
  }) => {
    // Sanity: both servers up and exposing the federation surface.
    const server1Health = await request.get(`${solandBaseUrl("server1")}/health`);
    expect(server1Health.ok()).toBeTruthy();
    const server2Health = await request.get(`${solandBaseUrl("server2")}/health`);
    expect(server2Health.ok()).toBeTruthy();

    // POST without auth/body should not 404 — both registered peer paths
    // (ak.peer.events.command.submit.v1, ak.peer.committed_event.read.scan.v1)
    // MUST exist.
    for (const path of ["/_arkret/peer/events", "/_arkret/peer/streams/scan"]) {
      const probe = await request.post(`${solandBaseUrl("server2")}${path}`, { data: {} });
      expect(probe.status(), path).not.toBe(404);
    }
  });

  test("unsigned peer stream scan is rejected", async ({ request }) => {
    const realmId = typedId("realm");
    const response = await request.post(
      `${solandBaseUrl("server2")}/_arkret/peer/streams/scan`,
      {
        data: canonicalJson({
          realm_id: realmId,
          stream_ref: { kind: "realm", realm_id: realmId },
          after_position: null,
          limit: 1,
        }),
        headers: {
          "content-type": "application/json",
          ...unsignedPeerHeaders(
            solandServiceId("server1"),
            solandServiceId("server2"),
          ),
        },
      },
    );
    expect(
      response.ok(),
      `unsigned peer scan unexpectedly returned ${response.status()}: ${await response.text()}`,
    ).toBeFalsy();
    expect(response.status()).toBeLessThan(500);
  });

  test("alice uses canonical DPoP browser auth on server1 while bob holds an independent dev API session on server2", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const aliceSession = await createDpopUserSession(
      request,
      `s2-alice-${stamp}`,
      { server: "server1" },
    );
    const bob = uniqueUser(`s2-bob-${stamp}`);
    await ensureRegistered(request, bob, { server: "server2" });
    const bobToken = await issueUserSession(request, bob, { server: "server2" });
    expect(aliceSession, "server1 DPoP session").toBeTruthy();

    const alicePageSession = await openDpopUserPageFromSession(
      browser,
      aliceSession,
      { server: "server1", prepareMlsDevice: false },
    );
    const alicePage = alicePageSession!.page;

    try {
      await alicePage.gotoHome();
      expect(alicePage.serverUrl).toBe(solandBaseUrl("server1"));

      // Each principal context binds to its own server.
      const aliceMeUrl = `${solandBaseUrl("server1")}/_soland/self/account/me`;
      const aliceMeResp = await request.get(aliceMeUrl, {
        headers: selfPathHeadersForDpopSession(
          aliceSession!,
          "GET",
          aliceMeUrl,
        ),
      });
      expect(aliceMeResp.ok()).toBeTruthy();
      const aliceMe = await aliceMeResp.json();
      expect(aliceMe.principal_id).toBe(aliceSession!.user.id);

      const bobMeUrl = `${solandBaseUrl("server2")}/_soland/self/account/me`;
      const bobMeResp = await request.get(bobMeUrl, {
        headers: authHeaders(bobToken, "GET", bobMeUrl),
      });
      expect(bobMeResp.ok()).toBeTruthy();
      const bobMe = await bobMeResp.json();
      expect(bobMe.principal_id).toBe(bob.id);
    } finally {
      await alicePage.close();
    }
  });

  test("alice@server1 creates a space and invites bob (whose DID lives on server2); UI surfaces the invite locally", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const bob = uniqueUser(`s2-bob-${stamp}`);
    await ensureRegistered(request, bob, { server: "server2" });
    const bobToken = await issueUserSession(request, bob, { server: "server2" });
    const bobLocatorToken = await issueInviteLocatorToken(
      request,
      bobToken,
      "server2",
    );

    const alice = await openDpopUserPage(
      browser,
      request,
      `s2-alice-${stamp}`,
      {
        server: "server1",
      },
    );
    test.skip(!alice, "canonical DPoP session requires managed Coauth");
    const alicePage = alice!.page;

    try {
      const realmId = await alicePage.createRealm({
        title: `S2 Cross-server ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
      });
      await alicePage.inviteFromAdmin(realmId, bob.id, undefined, {
        token: bobLocatorToken,
        serverUrl: solandBaseUrl("server2"),
      });
      await stepShot(alicePage.page, testInfo, "server1-invite-issued");

      // The invite MUST be visible in server1's space-invites list right after issuing.
      await alicePage.page
        .getByTestId("members-section-pending-invites")
        .click();
      // Same attribute rename as spaces/moderation-ban: the row carries
      // `data-member-id` holding the canonical ActorId key, so match the
      // principal id as a substring.
      const aliceInviteRow = alicePage.page.locator(
        `[data-testid="pending-invite-row"][data-member-id*="${bob.id}"]`,
      );
      await expect(aliceInviteRow).toBeVisible({ timeout: 30_000 });
    } finally {
      await alicePage.close();
    }
  });

  test("server1→server2 committed replication smoke: a Station hosting no joined member refuses the Realm; after the member's own join the exact committed pair is held", async ({
    request,
  }) => {
    // federation.md §4.1.1: a remote Station enters the committed-replication
    // target set only through a hosted effective joined member, and the
    // receiver re-verifies that hosted membership from committed history.
    const stamp = Date.now();
    const alice = uniqueUser(`s2-replica-alice-${stamp}`, "server1");
    const bob = uniqueUser(`s2-replica-bob-${stamp}`, "server2");
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueUserSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueUserSession(request, bob, { server: "server2" });
    await allowExplicitInviteNotifications(request, bobToken, "server2");
    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: `S2 committed replication ${stamp}`,
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
      },
      { server: "server1" },
    );
    const server1RealmEvents = await queryRealmEventsApi(
      request,
      aliceToken,
      realmId,
      { server: "server1", limit: 100 },
    );
    const bootstrapEvents = (
      Array.isArray(server1RealmEvents.events)
        ? (server1RealmEvents.events as Array<Record<string, unknown>>)
        : []
    ).filter((event) => event.kind !== "ak.invite.create");
    expect(bootstrapEvents.length).toBeGreaterThan(0);

    // server2 hosts no joined member yet: every exact, validly signed pair is
    // refused item by item and nothing is stored.
    const refused = await pushFederationEvents(request, bootstrapEvents, {
      origin: solandServiceId("server1"),
      destination: solandServiceId("server2"),
      server: "server2",
      realmId,
    });
    expect(
      replicationOutcomesOutside(bootstrapEvents, refused, ["rejected"]),
      "a Station without a hosted joined member must not hold the Realm",
    ).toEqual([]);

    await resolveDefaultStrandId(request, aliceToken, realmId, { server: "server1" });
    await joinFromOwnStation(request, bobToken, bob.id, realmId, "server2");
    await waitForMember(request, aliceToken, bob.id, realmId, "server1", "server2");
    await waitForMember(request, bobToken, bob.id, realmId, "server2", "server2");

    const body = `committed replication smoke ${stamp}`;
    const sent = await sendMessageApi(request, aliceToken, realmId, body, {
      server: "server1",
    });
    await waitForEventBody(request, bobToken, realmId, body, "server2");

    // server2 now reads the Realm stream from its governance Station and the
    // exact pair it already holds replays as `duplicate`, twice.
    const rows = await scanPeerRealmStreamRowsApi(request, {
      server: "server1",
      sourceServiceId: solandServiceId("server2"),
      realmId,
    });
    const row = rows.find((candidate) => candidate.event.event_id === sent.event_id);
    expect(row, "the governance Station discloses the committed message to server2").toBeTruthy();
    expect(row!.commit.commit_id).toBe(sent.commit_id);
    for (const attempt of ["first", "exact replay"]) {
      const outcome = await pushCommittedRowsApi(request, [row!], {
        origin: solandServiceId("server1"),
        destination: solandServiceId("server2"),
        server: "server2",
        realmId,
      });
      expect(outcome.replication_outcomes, attempt).toEqual([{ status: "duplicate" }]);
    }
    expect(await committedEventStatus(request, bobToken, sent.event_id, "server2")).toBe(200);
  });

  test("server1 invite UI event reaches bob@server2, whose own-Station join is committed by server1", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const bob = uniqueUser(`s2-auto-bob-${stamp}`, "server2");
    await ensureRegistered(request, bob, { server: "server2" });
    const bobToken = await issueUserSession(request, bob, { server: "server2" });
    const bobLocatorToken = await issueInviteLocatorToken(
      request,
      bobToken,
      "server2",
    );

    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      `s2-auto-alice-${stamp}`,
      {
        server: "server1",
        prepareMlsDevice: false,
      },
    );
    test.skip(!aliceFlow, "canonical DPoP session requires managed Coauth");
    if (!aliceFlow) {
      return;
    }
    const alicePage = aliceFlow.page;

    try {
      const realmId = await alicePage.createRealm({
        title: `S2 auto federation ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
      });
      await alicePage.inviteFromAdmin(realmId, bob.id, undefined, {
        token: bobLocatorToken,
        serverUrl: solandBaseUrl("server2"),
      });
      await stepShot(alicePage.page, testInfo, "server1-auto-invite-issued");

      await joinFromOwnStation(request, bobToken, bob.id, realmId, "server2");
      const server1RealmUrl =
        `${solandBaseUrl("server1")}/_arkret/self/realms/` +
        encodeURIComponent(realmId);
      await expect
        .poll(
          async () => {
            const response = await request.get(server1RealmUrl, {
              headers: selfPathHeadersForDpopSession(
                aliceFlow.session,
                "GET",
                server1RealmUrl,
              ),
            });
            if (!response.ok()) {
              return false;
            }
            const body = (await response.json()) as { member_ids?: unknown[] };
            return (body.member_ids ?? []).some((member) =>
              accountActorRoutesThrough(member, solandServiceId("server2"), bob.id),
            );
          },
          { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBeTruthy();
    } finally {
      await alicePage.close();
    }
  });

  test("peer stream scan recovery: server2 reads a committed message from server1 through ak.peer.committed_event.read.scan.v1 and holds it exactly once", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-backfill-alice-${stamp}`, "server1");
    const bob = uniqueUser(`s2-backfill-bob-${stamp}`, "server2");
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueUserSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueUserSession(request, bob, { server: "server2" });
    await allowExplicitInviteNotifications(request, bobToken, "server2");

    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: `S2 backfill ${stamp}`,
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
      },
      { server: "server1" },
    );
    await resolveDefaultStrandId(request, aliceToken, realmId, { server: "server1" });
    await joinFromOwnStation(request, bobToken, bob.id, realmId, "server2");
    await waitForMember(request, aliceToken, bob.id, realmId, "server1", "server2");
    await waitForMember(request, bobToken, bob.id, realmId, "server2", "server2");

    const missingBody = `recovered through peer scan ${stamp}`;
    const sent = await sendMessageApi(request, aliceToken, realmId, missingBody, {
      server: "server1",
    });

    // Recovery reads the one authorized stream from its governance Station
    // (federation.md §3) and replicates the exact pair; whether the durable
    // outbox got there first only decides stored versus duplicate.
    const rows = await scanPeerRealmStreamRowsApi(request, {
      server: "server1",
      sourceServiceId: solandServiceId("server2"),
      realmId,
    });
    const row = rows.find((candidate) => candidate.event.event_id === sent.event_id);
    expect(row, "server2 may read the committed message on the Realm stream").toBeTruthy();
    const positions = rows.map((candidate) => Number(candidate.commit.stream_position));
    expect(positions).toEqual([...positions].sort((left, right) => left - right));
    const ingest = await pushCommittedRowsApi(request, [row!], {
      origin: solandServiceId("server1"),
      destination: solandServiceId("server2"),
      server: "server2",
      realmId,
    });
    expect(["stored", "duplicate"]).toContain(ingest.replication_outcomes[0].status);
    await waitForEventBody(request, bobToken, realmId, missingBody, "server2");

    const server2After = await queryRealmEventsApi(request, bobToken, realmId, {
      server: "server2",
      limit: 100,
    });
    const server2AfterIds = (Array.isArray(server2After.events)
      ? (server2After.events as Array<Record<string, unknown>>)
      : []
    ).map((event) => String(event.event_id));
    expect(server2AfterIds.filter((eventId) => eventId === sent.event_id)).toHaveLength(1);
  });

  test("membership-terminating fanout: after bob@server2 leaves, server1 delivers no later Realm Commit to server2 (federation.md §4.1.1)", async ({
    request,
  }) => {
    // federation.md §4.1.1: the fanout target set is the routing services of
    // the effective joined members of the accepted Realm view. Once the only
    // member server2 hosts has left, server2 is no longer a target, and a
    // grant or peer relationship never re-creates delivery authority.
    const stamp = Date.now();
    const alice = uniqueUser(`s2-leave-alice-${stamp}`, "server1");
    const bob = uniqueUser(`s2-leave-bob-${stamp}`, "server2");
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueUserSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueUserSession(request, bob, { server: "server2" });
    await allowExplicitInviteNotifications(request, bobToken, "server2");

    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: `S2 leave fanout ${stamp}`,
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
      },
      { server: "server1" },
    );
    await resolveDefaultStrandId(request, aliceToken, realmId, { server: "server1" });
    await joinFromOwnStation(request, bobToken, bob.id, realmId, "server2");
    await waitForMember(request, aliceToken, bob.id, realmId, "server1", "server2");
    await waitForMember(request, bobToken, bob.id, realmId, "server2", "server2");

    // Baseline: while bob is joined, server2 is a routable target.
    const beforeBody = `before leave ${stamp}`;
    await sendMessageApi(request, aliceToken, realmId, beforeBody, {
      server: "server1",
    });
    await waitForEventBody(request, bobToken, realmId, beforeBody, "server2");

    // bob leaves through his own Station, which forwards the exact Event to
    // the governance Station.
    await submitSignedEventApi(request, bobToken, signedEventEnvelope({
      actorId: bob.id,
      server: "server2",
      realmId,
      kind: "ak.member.state",
      payload: { member_id: accountActorId(bob.id, "server2"), membership: "leave" },
    }), { server: "server2", context: "bob leaves the Realm from server2" });
    await expect
      .poll(
        async () => {
          const url = `${solandBaseUrl("server1")}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
          const response = await request.get(url, { headers: authHeaders(aliceToken, "GET", url) });
          const body = response.ok() ? await response.json() as { member_ids?: unknown[] } : {};
          return (body.member_ids ?? []).some((member) =>
            accountActorRoutesThrough(member, solandServiceId("server2"), bob.id),
          );
        },
        { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
      )
      .toBe(false);

    // A message after the leave is still accepted on server1 …
    const afterBody = `after leave ${stamp}`;
    const after = await sendMessageApi(request, aliceToken, realmId, afterBody, {
      server: "server1",
    });
    await waitForEventBody(request, aliceToken, realmId, afterBody, "server1");

    // … but server2 never holds its Commit: poll long enough that a fanout
    // would have arrived.
    await expect
      .poll(
        async () => await committedEventStatus(request, bobToken, after.event_id, "server2"),
        { timeout: 20_000, intervals: [1_000, 2_000, 4_000] },
      )
      .toBe(404);
    await new Promise((resolve) => setTimeout(resolve, 5_000));
    expect(await committedEventStatus(request, bobToken, after.event_id, "server2")).toBe(404);
  });

  test("RFC 9421 signature failure: tampered Signature header makes server2 reject the entire batch with 4xx", async ({
    request,
  }) => {
    // The body is an exact accepted pair, so only the transport signature is
    // wrong: service authentication precedes any inner object (§3.2).
    const stamp = Date.now();
    const alice = uniqueUser(`s2-rfc9421-alice-${stamp}`, "server1");
    await ensureRegistered(request, alice, { server: "server1" });
    const aliceToken = await issueUserSession(request, alice, { server: "server1" });
    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: `S2 RFC 9421 ${stamp}`,
        ownerId: alice.id,
        creator_id: solandServiceId("server1"),
      },
      { server: "server1" },
    );
    const sent = await sendMessageApi(request, aliceToken, realmId, `tampered signature ${stamp}`, {
      server: "server1",
    });
    const response = await rawPushFederationEvents(request, [{ event_id: sent.event_id }], {
      origin: solandServiceId("server1"),
      destination: solandServiceId("server2"),
      server: "server2",
      realmId,
      tamperSignature: true,
    });
    const text = await response.text();
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(response.status()).toBeLessThan(500);
    // federation.md §3.2/§8.3 minimal disclosure: every auth failure folds to a
    // single indistinguishable envelope. The key_rotation_hint is audit-only
    // (soland signature_error → tracing::warn) and MUST NOT leak in the body.
    expect(text).not.toContain("key_rotation_hint");
    expect(text).toContain("federation request authentication failed");
  });
});

test.describe("prepared authoring and join", () => {
  test.describe.configure({ mode: "default" });
  for (const largeHistory of [false, true]) {
    test(`two-way timeline messaging${largeHistory ? " after paged governance history" : ""}: alice@server1 and bob@server2 exchange messages and both servers converge on identical effective state`, async ({
      request,
    }, testInfo) => {
      test.setTimeout(600_000);
      const stamp = Date.now();
      const aliceSession = await createDpopUserSession(request, `s2-msg-alice-${stamp}`, { server: "server1" });
      const bobSession = await createDpopUserSession(request, `s2-msg-bob-${stamp}`, { server: "server2" });
      if (!aliceSession || !bobSession) throw new Error("prepared authoring requires real Coauth sessions");
      const charlieSession = largeHistory
        ? await createDpopUserSession(request, `s2-history-charlie-${stamp}`, { server: "server1" })
        : undefined;
      if (largeHistory && !charlieSession) throw new Error("historical member requires a real Coauth session");
      await allowExplicitInviteNotifications(request, bobSession, "server2");
      if (charlieSession) await allowExplicitInviteNotifications(request, charlieSession, "server1");
      const alice = aliceSession.user;
      const bob = bobSession.user;
      const charlie = charlieSession?.user;
      const aliceToken = aliceSession.grantJwt;
      const bobToken = bobSession.grantJwt;
      const charlieToken = charlieSession?.grantJwt;

      const realmId = await createRealmApi(
        request,
        aliceToken,
        {
          title: `S2 two-way ${stamp}`,
          discoverability: "listed",
          history_access: "since_join",
          invitees: [bob.id, ...(charlie ? [charlie.id] : [])],
          invitee_ids: {
            [bob.id]: solandServiceId("server2"),
            ...(charlie ? { [charlie.id]: solandServiceId("server1") } : {}),
          },
          ownerId: alice.id,
          creator_id: solandServiceId("server1"),
          plaintext_visible_services: [
            solandServiceId("server1"),
            solandServiceId("server2"),
          ],
        },
        { server: "server1" },
      );

      await test.step("owner prepares, signs and exact-replays a message", async () => {
        await sendPreparedMessageApi(request, aliceToken, realmId, `owner ready ${stamp}`, {
          server: "server1",
        });
      });

      if (charlie && charlieToken) {
        const invitation = await waitForInviteDeliveryApi(request, charlieToken, charlie.id, realmId, "server1");
        const beforeJoin = await readCommitStreamHeadApi(request, aliceToken, realmId, { server: "server1" });
        const joined = await acceptPreparedInviteApi(request, charlieToken, charlie.id, realmId, invitation.id, { server: "server1" });
        // The join advanced the Realm's own stream by exactly the commits it
        // caused, and the accepted head is a later position than before it.
        const afterJoin = await readCommitStreamHeadApi(request, aliceToken, realmId, { server: "server1" });
        expect(afterJoin, "join must advance the Realm commit stream").toBeTruthy();
        expect(afterJoin!.stream_position).toBeGreaterThan(beforeJoin?.stream_position ?? -1);
        expect(String(joined.event_id)).toMatch(/^ak:event:/);
        await waitForMember(request, aliceToken, charlie.id, realmId, "server1", "server1");
        await submitSignedEventApi(request, charlieToken, signedEventEnvelope({
          actorId: charlie.id,
          realmId,
          kind: "ak.member.state",
          payload: { member_id: accountActorId(charlie.id, "server1"), membership: "leave" },
        }), { server: "server1", controlObserverToken: aliceToken });

        // One immutable Schema subject keeps the current Snapshot bounded.
        // Distinct signed Events of the same definition create real accepted
        // history; changing the occupied subject's bytes is forbidden.
        const payload = { value: {
          $schema: "https://json-schema.org/draft/2020-12/schema",
          $id: "ak.schema.bootstrap_history_0.v1",
          type: "object",
          description: `Historical schema: ${"x".repeat(512 * 1024)}`,
        } };
        const acceptedSchemas = new Set<string>();
        for (let index = 0; index < 18; index += 1) {
          const event = signedEventEnvelope({
            actorId: alice.id, realmId, kind: "ak.schema.define", payload,
          });
          await submitSignedEventApi(request, aliceToken, event, {
            server: "server1", context: `accept historical schema Event ${index}`,
          });
          acceptedSchemas.add(String(event.event_id));
        }
        expect(acceptedSchemas.size).toBe(18);
        const observedSchemas = new Set<string>();
        let historicalPayloadBytes = 0;
        let afterPosition: number | null = null;
        let historyPages = 0;
        const streamRef = { kind: "realm", realm_id: realmId };
        const scanUrl = `${solandBaseUrl("server1")}/_arkret/self/streams/scan`;
        for (;;) {
          historyPages += 1;
          expect(historyPages, "historical scan must make bounded progress").toBeLessThanOrEqual(100);
          const response = await request.post(scanUrl, {
            headers: { ...authHeaders(aliceToken, "POST", scanUrl), "content-type": "application/json" },
            data: canonicalJson({ realm_id: realmId, stream_ref: streamRef, after_position: afterPosition, limit: 5 }),
          });
          expect(response.status(), response.ok() ? "accepted historical stream scan" : await response.text()).toBe(200);
          const scan = await response.json() as StreamScanOutcome;
          expect(scan.committed_events.length).toBeGreaterThan(0);
          expect(scan.committed_events.length).toBeLessThanOrEqual(5);
          for (const row of scan.committed_events) {
            expect(row.commit.stream_ref).toEqual(streamRef);
            if (!("event" in row)) throw new Error("the owner's historical Schema readback must be full");
            expect(row.event.event_id).toBe(row.commit.event_ref);
            const position = Number(row.commit.stream_position);
            expect(Number.isSafeInteger(position)).toBe(true);
            if (afterPosition !== null) expect(position).toBe(afterPosition + 1);
            afterPosition = position;
            const eventId = String(row.event.event_id);
            if (acceptedSchemas.has(eventId)) {
              expect(observedSchemas.has(eventId), "a historical Schema is read exactly once").toBe(false);
              expect(row.event.payload).toEqual(payload);
              observedSchemas.add(eventId);
              historicalPayloadBytes += Buffer.byteLength(canonicalJson(row.event.payload), "utf8");
            }
          }
          expect(typeof scan.truncated).toBe("boolean");
          if (!scan.truncated) break;
        }
        expect([...observedSchemas].sort()).toEqual([...acceptedSchemas].sort());
        expect(historyPages).toBeGreaterThan(1);
        expect(historicalPayloadBytes).toBeGreaterThan(8 * 1024 * 1024);
        await testInfo.attach("accepted-history-audit.json", {
          body: JSON.stringify({ schema_subjects: 1, accepted_schema_events: observedSchemas.size,
            accepted_payload_bytes: historicalPayloadBytes, stream_scan_pages: historyPages,
            final_stream_position: afterPosition }),
          contentType: "application/json",
        });
      }

      const server2Invite = await waitForInviteDeliveryApi(
        request,
        bobToken,
        bob.id,
        realmId,
        "server2",
      );
      await acceptPreparedInviteApi(
        request,
        bobToken,
        bob.id,
        server2Invite.realm_id,
        server2Invite.id,
        {
          server: "server2",
        },
      );
      await waitForMember(request, aliceToken, bob.id, realmId, "server1", "server2");
      await waitForMember(request, bobToken, bob.id, realmId, "server2", "server2");
      const messageGrant = await grantCapabilityEventApi(request, aliceToken, {
        ownerId: alice.id,
        realmId,
        subjectId: bob.id,
        subjectServer: "server2",
        actions: ["ak.message.create"],
        server: "server1",
      });
      const grantUrl = `${solandBaseUrl("server2")}/_arkret/self/committed-events/${messageGrant.eventId}`;
      await expect.poll(async () => {
        const response = await request.get(grantUrl, { headers: authHeaders(bobToken, "GET", grantUrl) });
        expect([200, 404], "the member's exact grant read must not bypass a service error").toContain(response.status());
        if (!response.ok()) return false;
        const pair = await response.json() as CommittedEventFullView;
        expect(pair.commit?.event_ref).toBe(messageGrant.eventId);
        expect(pair.event?.event_id).toBe(messageGrant.eventId);
        return true;
      }, { timeout: 60_000, intervals: [500, 1_000, 2_000] }).toBe(true);

      const aliceBody = `alice from server1 ${stamp}`;
      await sendPreparedMessageApi(request, aliceToken, realmId, aliceBody, {
        server: "server1",
      });
      await waitForEventBody(request, bobToken, realmId, aliceBody, "server2");

      const bobBody = `bob from server2 ${stamp}`;
      await sendPreparedMessageApi(request, bobToken, realmId, bobBody, {
        server: "server2",
      });
      await waitForEventBody(request, aliceToken, realmId, bobBody, "server1");
    });
  }
  });

// Cross-server federation
// Contract: e2e/scenarios/federation/cross-server.md
// Spec refs:
//   - sync/federation.md §2.1-§2.4 (trust roots, Anchor finality, profiles)
//   - §3.1-§3.2 DID server identity + RFC 9421 request signature
//   - §4.1 push protocol, §4.1.0 push sequence
//   - §4.2 pull / backfill, §4.5 fork detection / frontier exchange
//   - §5.1 cross-domain invite
//
// Soland implementation status (2026-05 audit):
//   ✓ POST /_arkret/peer/events handler routed and ingests events
//   ✓ GET  /_arkret/peer/events cursor-based
//   ✓ Per-event accepted / rejected partial-accept
//   ✓ Idempotent by event_id
//   ✓ SOLAND_FEDERATION_PEERS env wires peer URLs + peer service DIDs
//   ✓ Outbound push worker POSTs local invite/message Events to peers
//   ✓ ak.invite.create, ak.member.state join, and ak.message.create trigger federation push
//   ✓ peer events query pulls peer pages and ingests missing local Events
//   ✓ peer events frontier exposes deterministic Event ID coverage
//   ✓ inbound RFC 9421 HTTP Message Signature rejects tampered batches
//   ✓ reducer profile resolved from each Event's authenticated CBS
//   ✓ §4.4 capability revoke fanout: revoking a peer's service delegation
//     stops outbound federation push to that peer

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import {
  assertServerCountNotRequired,
  hasServerCount,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import type { InviteDeliveryRequestBody } from "../../helpers/generated/spec-wire-objects";
import {
  acceptInviteApi,
  acceptPreparedInviteApi,
  waitForInviteDeliveryApi,
  waitForRealmControlIdleApi,
  accountActorId,
  advanceEnvelopeToActorFrontier,
  authHeaders,
  canonicalJson,
  queryPeerEventsApi,
  createRealmApi,
  dispatchSelfInviteApi,
  grantServiceCapabilityApi,
  listInvitesApi,
  makeFederationEvent,
  peerEventFrontierApi,
  pushFederationEvents,
  rawPushFederationEvents,
  queryRealmEventsApi,
  readAcceptedSealBundle,
  revokeCapabilityApi,
  sendMessageApi,
  sendPreparedMessageApi,
  selfInviteDispatchBody,
  sha256CanonicalJson,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  createDpopUserSession,
  allowExplicitInviteNotifications,
  ensureRegistered,
  issueInviteLocatorToken,
  issueDevSession,
  openDpopUserPage,
  openDpopUserPageFromSession,
  openUserPage,
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

async function waitForInvite(
  request: APIRequestContext,
  token: string,
  inviteeId: string,
  realmId: string,
  server: "server1" | "server2",
) {
  let found:
    | {
        id: string;
        realm_id: string;
        invitee_id?: string;
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
            invite.invitee_account_id?.principal_id === inviteeId && invite.invitee_account_id.station_id === solandServiceId(server) && invite.realm_id === realmId,
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
  server: "server1" | "server2",
) {
  await expect
    .poll(
      async () => {
        const url = `${solandBaseUrl(server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
        const response = await request.get(url, { headers: authHeaders(token, "GET", url) });
        if (!response.ok()) {
          return false;
        }
        const body = await response.json();
        return Array.isArray(body.member_ids) && body.member_ids.some(
          (member: unknown) => member !== null && typeof member === "object" &&
            (member as { kind?: string }).kind === "account" &&
            (member as { account_id?: { principal_id?: string } }).account_id?.principal_id === memberId,
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
        });
        const events = Array.isArray(body.events) ? body.events : [];
        return events.some((event) => JSON.stringify(event).includes(bodyText));
      },
      { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
    )
    .toBeTruthy();
}

function unsignedPeerQueryHeaders(
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
  test("both soland instances expose peer events submit and query endpoints", async ({
    request,
  }) => {
    // Sanity: both servers up and exposing the federation surface.
    const server1Health = await request.get(`${solandBaseUrl("server1")}/health`);
    expect(server1Health.ok()).toBeTruthy();
    const server2Health = await request.get(`${solandBaseUrl("server2")}/health`);
    expect(server2Health.ok()).toBeTruthy();

    // POST without auth/body should not 404 — endpoint MUST exist.
    const pushProbe = await request.post(
      `${solandBaseUrl("server2")}/_arkret/peer/events`,
      {
        data: {},
      },
    );
    expect(pushProbe.status()).not.toBe(404);

    const pullProbe = await request.fetch(
      `${solandBaseUrl("server2")}/_arkret/peer/events`,
      { method: "QUERY", data: { realm_ids: ["ak:realm:probe"] } },
    );
    expect(pullProbe.status()).not.toBe(404);
  });

  test("unsigned peer QUERY pull is rejected", async ({ request }) => {
    const response = await request.fetch(
      `${solandBaseUrl("server2")}/_arkret/peer/events`,
      {
        method: "QUERY",
        data: { limit: 1 },
        headers: unsignedPeerQueryHeaders(
          solandServiceId("server1"),
          solandServiceId("server2"),
        ),
      },
    );
    expect(
      response.ok(),
      `unsigned peer QUERY unexpectedly returned ${response.status()}: ${await response.text()}`,
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
    const bobToken = await issueDevSession(request, bob, { server: "server2" });
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
        headers: { authorization: `Bearer ${bobToken}` },
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
    const bobToken = await issueDevSession(request, bob, { server: "server2" });
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

  test("server1→server2 federation push smoke delivers an invite-shaped Event to server2 pull + invite APIs", async ({
    request,
  }) => {
    // API-first smoke for G3.S0: the real server2 federation ingestion and pull
    // surfaces accept an server1-origin Event. The fully automatic inkson
    // invite/accept round trip remains pinned in the richer fixme below.
    const stamp = Date.now();
    const alice = uniqueUser(`s2-outbound-alice-${stamp}`, "server1");
    const bob = uniqueUser(`s2-outbound-bob-${stamp}`, "server2");
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueDevSession(request, bob, { server: "server2" });
    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: `S2 pushed invite ${stamp}`,
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
    ).sort(
      (left, right) =>
        Number(left.actor_seq ?? 0) - Number(right.actor_seq ?? 0),
    );
    const bootstrapPush = await pushFederationEvents(request, bootstrapEvents, {
      origin: solandServiceId("server1"),
      destination: solandServiceId("server2"),
      server: "server2",
      realmId,
      idempotencyKey: `${solandServiceId("server1")}#cotest-cross-server-bootstrap`,
    });
    expect(bootstrapPush.rejections ?? []).toEqual([]);
    expect([
      ...(bootstrapPush.accepted ?? []),
      ...(bootstrapPush.duplicate ?? []),
    ]).toHaveLength(bootstrapEvents.length);

    const frontierUrl = `${solandBaseUrl("server1")}/_arkret/self/seals/frontier`;
    const frontierResponse = await request.fetch(frontierUrl, {
      method: "QUERY",
      headers: {
        ...authHeaders(aliceToken, "QUERY", frontierUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({ realm_id: realmId }),
    });
    const frontierBody = (await frontierResponse.json()) as {
      frontier?: {
        kind?: unknown;
        seal_basis?: { leaves?: unknown };
      };
    };
    expect(
      frontierResponse.ok(),
      `read server1 Realm Seal frontier: ${JSON.stringify(frontierBody)}`,
    ).toBeTruthy();
    expect(frontierBody.frontier?.kind).toBe("realm_seal");
    const leaves = frontierBody.frontier?.seal_basis?.leaves as
      string[] | undefined;
    expect(leaves).toEqual([expect.stringMatching(/^ak:seal:/)]);
    const inviteBasisBundle = await readAcceptedSealBundle(
      request,
      aliceToken,
      realmId,
      leaves![0],
      "server1",
    );
    const locatorToken = await issueInviteLocatorToken(request, bobToken, "server2");
    const locatorResponse = await request.post(
      `${solandBaseUrl("server2")}/_arkret/open/invite-locators/resolve`,
      { data: { locator_token: locatorToken } },
    );
    expect(locatorResponse.status(), await locatorResponse.text()).toBe(200);
    type LocatorEvidence = Extract<InviteDeliveryRequestBody["introduction_evidence"], { kind: "locator_ref" }>;
    const locator = await locatorResponse.json() as LocatorEvidence["principal_locator"];
    const evidence: LocatorEvidence = { kind: "locator_ref", principal_locator: locator };
    const inviteEvent = makeFederationEvent({
      realmId,
      kind: "ak.invite.create",
      actorId: alice.id,
      sealBasis: {
        leaves: [leaves![0]],
      },
      payload: {
        invitee_account_id: locator.account_id,
        introduction_evidence_digest: `sha256:${sha256CanonicalJson(evidence)}`,
        expires_at: new Date(Date.now() + 86_400_000).toISOString(),
      },
    });
    await advanceEnvelopeToActorFrontier(
      request,
      aliceToken,
      inviteEvent,
      "server1",
    );
    await submitSignedEventApi(request, aliceToken, inviteEvent, {
      server: "server1",
      context: "submit server1 invite for federated Seal-closure delivery",
    });
    const delivery = await dispatchSelfInviteApi(request, aliceToken, selfInviteDispatchBody({
      eventId: String(inviteEvent.event_id),
      inviteAddress: {
        account_id: locator.account_id,
        service_resolution: locator.service_resolution,
        ...(locator.route_assistance ? { route_assistance: locator.route_assistance } : {}),
      },
      evidence,
    }), { server: "server1" });
    expect(delivery.status).toBe("accepted");

    await expect
      .poll(
        async () => {
          const invites = await listInvitesApi(request, bobToken, {
            server: "server2",
          });
          return invites.some(
            (item) => item.realm_id === realmId && item.invitee_account_id?.principal_id === bob.id && item.invitee_account_id.station_id === solandServiceId("server2"),
          );
        },
        { timeout: 20_000 },
      )
      .toBe(true);

    const replay = await pushFederationEvents(request, [inviteEvent], {
      origin: solandServiceId("server1"),
      destination: solandServiceId("server2"),
      server: "server2",
      realmId,
      idempotencyKey: `${solandServiceId("server1")}#cotest-cross-server-smoke`,
      cbsProofBundles: [inviteBasisBundle],
    });
    expect(replay.rejections ?? [], "accepted invite replay must not be rejected").toEqual([]);
    expect([...(replay.accepted ?? []), ...(replay.duplicate ?? [])]).toContain(
      inviteEvent.event_id,
    );

    const pullBody = await queryPeerEventsApi(request, {
      server: "server2",
      sourceServiceId: solandServiceId("server1"),
      realmId,
      limit: 10,
    });
    expect((pullBody.events ?? []).map((event) => event.event_id)).toContain(
      inviteEvent.event_id,
    );
    expect(
      (pullBody.events ?? []).filter(
        (event) => event.event_id === inviteEvent.event_id,
      ),
    ).toHaveLength(1);

    const invites = await listInvitesApi(request, bobToken, { server: "server2" });
    const invite = invites.find(
      (item) => item.realm_id === realmId && item.invitee_account_id?.principal_id === bob.id && item.invitee_account_id.station_id === solandServiceId("server2"),
    );
    expect(invite).toBeTruthy();
    await acceptInviteApi(
      request,
      bobToken,
      bob.id,
      invite!.realm_id,
      invite!.id,
      { server: "server2" },
    );

    const server2Space = await request.get(
      `${solandBaseUrl("server2")}/_arkret/self/realms/${encodeURIComponent(invite!.realm_id)}`,
      { headers: authHeaders(bobToken) },
    );
    expect(server2Space.ok()).toBeTruthy();
    const realm = await server2Space.json() as { member_roster_entries?: Array<{ actor_id: unknown; membership: string }> };
    expect(realm.member_roster_entries?.some((member) =>
      member.membership === "join" && accountActorRoutesThrough(member.actor_id, solandServiceId("server2"), bob.id),
    )).toBe(true);
  });

  test("server1 invite UI event fans out to server2 and standard peer Events propagates server2 acceptance back to server1", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const bob = uniqueUser(`s2-auto-bob-${stamp}`, "server2");
    await ensureRegistered(request, bob, { server: "server2" });
    const bobToken = await issueDevSession(request, bob, { server: "server2" });
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

      const server2Invite = await waitForInvite(
        request,
        bobToken,
        bob.id,
        realmId,
        "server2",
      );
      const acceptanceEvent = signedEventEnvelope({
        actorId: bob.id,
        realmId: server2Invite.realm_id,
        kind: "ak.invite.accept",
        payload: {
          invite_id: server2Invite.id,
          // Directed invite: the stored account is the only signed source the
          // live-target release write can derive its subject from, and
          // omitting it fails the registered pre-state requirement
          // (governance-objects.md section 5.3).
          invitee_account_id: accountActorId(bob.id, "server2").account_id,
        },
      });
      await submitSignedEventApi(request, bobToken, acceptanceEvent, {
        server: "server2",
      });
      const server1EventsUrl = `${solandBaseUrl("server1")}/_arkret/self/events`;
      const server1EventsResponse = await request.fetch(server1EventsUrl, {
        method: "QUERY",
        data: { realm_ids: [realmId], limit: 100 },
        headers: selfPathHeadersForDpopSession(
          aliceFlow.session,
          "QUERY",
          server1EventsUrl,
        ),
      });
      expect(
        server1EventsResponse.status(),
        await server1EventsResponse.text(),
      ).toBe(200);
      const server1Events = (await server1EventsResponse.json()) as {
        events?: Array<Record<string, unknown>>;
      };
      const server1BindingEvent = (
        Array.isArray(server1Events.events)
          ? (server1Events.events as Array<Record<string, unknown>>)
          : []
      ).find((event) => {
        if (event.kind !== "ak.member.state") {
          return false;
        }
        const payload = event.payload as Record<string, unknown> | undefined;
        return accountActorRoutesThrough(
          payload?.actor_id,
          solandServiceId("server1"),
        );
      });
      expect(server1BindingEvent?.event_id).toBeTruthy();
      const propagation = await pushFederationEvents(
        request,
        [acceptanceEvent],
        {
          origin: solandServiceId("server2"),
          destination: solandServiceId("server1"),
          server: "server1",
          realmId,
          idempotencyKey: `${solandServiceId("server2")}#${realmId}#acceptance`,
          serviceBindingFrontier: [String(server1BindingEvent!.event_id)],
        },
      );
      expect(propagation.rejections ?? []).toEqual([]);
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
            const body = (await response.json()) as { member_ids?: string[] };
            return body.member_ids?.includes(bob.id) ?? false;
          },
          { timeout: 45_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBeTruthy();
    } finally {
      await alicePage.close();
    }
  });

  test("peer query recovery: after a network partition, server2 fetches missing server1 events via QUERY /_arkret/peer/events", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-backfill-alice-${stamp}`, "server1");
    const bob = uniqueUser(`s2-backfill-bob-${stamp}`, "server2");
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueDevSession(request, bob, { server: "server2" });

    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: `S2 backfill ${stamp}`,
        discoverability: "listed",
        history_access: "all_history_for_current_members",
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
    const server2Invite = await waitForInvite(
      request,
      bobToken,
      bob.id,
      realmId,
      "server2",
    );
    await acceptInviteApi(
      request,
      bobToken,
      bob.id,
      server2Invite.realm_id,
      server2Invite.id,
      {
        server: "server2",
      },
    );
    await waitForMember(request, aliceToken, bob.id, realmId, "server1");

    const missingBody = `pulled after partition ${stamp}`;
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
      "server1",
    );
    const server1BeforePartitionWrite = await queryRealmEventsApi(
      request,
      aliceToken,
      realmId,
      { server: "server1", limit: 100 },
    );
    const server1BindingEvent = (
      Array.isArray(server1BeforePartitionWrite.events)
        ? (server1BeforePartitionWrite.events as Array<Record<string, unknown>>)
        : []
    ).find((event) => {
      if (event.kind !== "ak.member.state") {
        return false;
      }
      const payload = event.payload as Record<string, unknown> | undefined;
      return accountActorRoutesThrough(
        payload?.actor_id,
        solandServiceId("server1"),
      );
    });
    expect(server1BindingEvent?.event_id).toBeTruthy();

    const sourceWrite = await pushFederationEvents(request, [missingEvent], {
      origin: solandServiceId("server2"),
      destination: solandServiceId("server1"),
      server: "server1",
      realmId,
      idempotencyKey: `${solandServiceId("server2")}#cotest-partition-source`,
      serviceBindingFrontier: [String(server1BindingEvent!.event_id)],
    });
    expect(sourceWrite.rejections ?? []).toEqual([]);
    expect(sourceWrite.accepted ?? []).toContain(missingEvent.event_id);
    await waitForEventBody(request, aliceToken, realmId, missingBody, "server1");

    const server2BeforeEvents = await queryRealmEventsApi(
      request,
      bobToken,
      realmId,
      {
        server: "server2",
        limit: 100,
      },
    );
    expect(JSON.stringify(server2BeforeEvents)).not.toContain(missingBody);
    const server2BeforeIds = new Set(
      (Array.isArray(server2BeforeEvents.events)
        ? (server2BeforeEvents.events as Array<Record<string, unknown>>)
        : []
      ).map((event) => String(event.event_id)),
    );

    const backfill = await queryPeerEventsApi(request, {
      server: "server1",
      sourceServiceId: solandServiceId("server2"),
      realmId,
      limit: 100,
    });
    const backfilledEvents = backfill.events ?? [];
    const missingBackfillEvents = backfilledEvents.filter(
      (event) => !server2BeforeIds.has(String(event.event_id)),
    );
    expect(backfilledEvents.map((event) => event.event_id)).toContain(
      missingEvent.event_id,
    );
    const server2BindingEvent = backfilledEvents.find((event) => {
      if (event.kind !== "ak.invite.create") {
        return false;
      }
      const payload = event.payload as Record<string, unknown> | undefined;
      const target = payload?.invite_delivery_target as
        | { account_id?: { station_id?: string } }
        | undefined;
      return target?.account_id?.station_id === solandServiceId("server2");
    });
    expect(server2BindingEvent?.event_id).toBeTruthy();
    const ingest = await pushFederationEvents(request, missingBackfillEvents, {
      origin: solandServiceId("server1"),
      destination: solandServiceId("server2"),
      server: "server2",
      realmId,
      idempotencyKey: `${solandServiceId("server2")}#cotest-peer-query-recovery`,
      serviceBindingFrontier: [String(server2BindingEvent!.event_id)],
    });
    expect(ingest.rejections ?? []).toEqual([]);
    expect([...(ingest.accepted ?? []), ...(ingest.duplicate ?? [])]).toContain(
      String(missingEvent.event_id),
    );
    await waitForEventBody(request, bobToken, realmId, missingBody, "server2");

    const server2After = await queryRealmEventsApi(request, bobToken, realmId, {
      server: "server2",
      limit: 100,
    });
    const server2AfterIds = new Set(
      (Array.isArray(server2After.events)
        ? (server2After.events as Array<Record<string, unknown>>)
        : []
      ).map((event) => String(event.event_id)),
    );
    for (const event of backfilledEvents) {
      expect(server2AfterIds).toContain(String(event.event_id));
    }
  });

  test("Capability revoke fanout: after alice revokes server2's service delegation, server1 MUST stop pushing future events to server2 (§4.4)", async ({
    request,
  }) => {
    // spec: sync/federation.md §4.4 — once a service delegation grant whose
    // subject is a peer service DID is revoked, the source Station
    // MUST stop pushing future events for that Realm to the revoked peer.
    // soland: `ProjectionState::federation_delivery_revoked_peers` derives the
    // revoked-peer set from the durable capability grant cells and
    // `dynamic_peer_event_targets` (event_log/submit.rs) skips those peers.
    const stamp = Date.now();
    const alice = uniqueUser(`s2-revoke-alice-${stamp}`, "server1");
    const bob = uniqueUser(`s2-revoke-bob-${stamp}`, "server2");
    await ensureRegistered(request, alice, { server: "server1" });
    await ensureRegistered(request, bob, { server: "server2" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "server1",
    });
    const bobToken = await issueDevSession(request, bob, { server: "server2" });

    // Federated Realm: bob@server2 joins so server2 is a routable delivery target on server1.
    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: `S2 revoke fanout ${stamp}`,
        discoverability: "listed",
        history_access: "all_history_for_current_members",
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
    const server2Invite = await waitForInvite(
      request,
      bobToken,
      bob.id,
      realmId,
      "server2",
    );
    await acceptInviteApi(
      request,
      bobToken,
      bob.id,
      server2Invite.realm_id,
      server2Invite.id,
      { server: "server2" },
    );
    await waitForMember(request, aliceToken, bob.id, realmId, "server1");

    // Alice (Realm owner) grants a Realm-scoped capability to server2's service
    // actor, then confirms a baseline message still fans out to server2.
    const grantId = await grantServiceCapabilityApi(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      subjectServiceId: solandServiceId("server2"),
    });
    const beforeBody = `before revoke ${stamp}`;
    await sendMessageApi(request, aliceToken, realmId, beforeBody, {
      server: "server1",
    });
    await waitForEventBody(request, bobToken, realmId, beforeBody, "server2");

    // Revoke server2's service delegation. Per §4.4 the source server MUST stop
    // pushing future events to server2.
    await revokeCapabilityApi(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      grantId,
    });

    // A message sent after the revoke MUST still land on server1 (the revoke only
    // gates outbound federation push, not local acceptance) …
    const afterBody = `after revoke ${stamp}`;
    await sendMessageApi(request, aliceToken, realmId, afterBody, {
      server: "server1",
    });
    await waitForEventBody(request, aliceToken, realmId, afterBody, "server1");

    // … but MUST NOT be pushed to server2. Poll server2 long enough that a fanout would
    // have arrived, then assert the post-revoke body never appears while the
    // pre-revoke body remains visible (proves server2 was reachable before revoke).
    await expect
      .poll(
        async () => {
          const body = await queryRealmEventsApi(request, bobToken, realmId, {
            server: "server2",
            limit: 200,
          });
          const serialized = JSON.stringify(body);
          return {
            hasBefore: serialized.includes(beforeBody),
            hasAfter: serialized.includes(afterBody),
          };
        },
        { timeout: 20_000, intervals: [1_000, 2_000, 4_000] },
      )
      .toEqual({ hasBefore: true, hasAfter: false });

    // Final settle: re-confirm server2 never received the post-revoke event.
    const server2Final = await queryRealmEventsApi(request, bobToken, realmId, {
      server: "server2",
      limit: 200,
    });
    expect(JSON.stringify(server2Final)).not.toContain(afterBody);
  });

  test("RFC 9421 signature failure: tampered Signature header makes server2 reject the entire batch with 4xx", async ({
    request,
  }) => {
    const realmId = typedId("realm");
    const event = makeFederationEvent({
      realmId,
      kind: "ak.message.create",
      actorId: "ak:did_core:web:alice-rfc9421.example",
      payload: {
        strand_id: typedId("strand"),
        track_name: "discussion",
        content: {
          kind: "ak.content.text",
          body: `tampered signature ${Date.now()}`,
        },
      },
    });
    const response = await rawPushFederationEvents(request, [event], {
      origin: solandServiceId("server1"),
      destination: solandServiceId("server2"),
      server: "server2",
      realmId,
      idempotencyKey: `${solandServiceId("server1")}#cotest-rfc9421-negative`,
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
    }) => {
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
          history_access: "all_history_for_current_members",
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
        const beforeJoin = await waitForRealmControlIdleApi(request, aliceToken, realmId, { server: "server1" });
        const joined = await acceptPreparedInviteApi(request, charlieToken, charlie.id, realmId, invitation.id, { server: "server1", waitForStatus: false });
        const afterJoin = await waitForRealmControlIdleApi(request, aliceToken, realmId, {
          server: "server1", afterControlEventSetRoot: String(beforeJoin.control_event_set_root),
        });
        const covering = await readAcceptedSealBundle(request, aliceToken, realmId, (afterJoin.leaves as string[])[0], "server1");
        const joinDigest = joined.proofs[0].event_digest;
        expect((covering.seals as Array<{ delta?: string[] }>).some((seal) => seal.delta?.includes(joinDigest))).toBe(true);
        await waitForMember(request, aliceToken, charlie.id, realmId, "server1");
        await submitSignedEventApi(request, charlieToken, signedEventEnvelope({
          actorId: charlie.id,
          realmId,
          kind: "ak.member.state",
          payload: { member_id: accountActorId(charlie.id, "server1"), membership: "leave" },
        }), { server: "server1", controlObserverToken: aliceToken });

        // Eighteen real accepted Schema definition Control Moves contribute
        // more than 8 MiB before envelopes, Seals and signer evidence. The
        // applicant's Station has not joined while this history is authored.
        let historicalPayloadBytes = 0;
        for (let index = 0; index < 18; index += 1) {
          const payload = { value: {
            $schema: "https://json-schema.org/draft/2020-12/schema",
            $id: `ak.schema.bootstrap_history_${index}.v1`,
            type: "object",
            description: `Historical schema ${index}: ${"x".repeat(512 * 1024)}`,
          } };
          historicalPayloadBytes += Buffer.byteLength(canonicalJson(payload), "utf8");
          await submitSignedEventApi(request, aliceToken, signedEventEnvelope({
            actorId: alice.id, realmId, kind: "ak.schema.define", payload,
            preconditions: [{
              cell_id: `ak:cell:ak.component.schema.definition.v1:${payload.value.$id}`,
              predicate: { op: "head_eq", value: null },
            }],
          }), { server: "server1", context: `accept historical schema ${index}` });
        }
        expect(historicalPayloadBytes).toBeGreaterThan(8 * 1024 * 1024);
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
      await waitForMember(request, aliceToken, bob.id, realmId, "server1");

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

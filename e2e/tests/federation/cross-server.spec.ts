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
//   ✓ reducer profile resolved from each Event's authenticated CBA
//   ✓ §4.4 capability revoke fanout: revoking a peer's service delegation
//     stops outbound federation push to that peer

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import {
  assertDualSolandNotRequired,
  hasDualSoland,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  acceptInviteApi,
  advanceEnvelopeToActorFrontier,
  authHeaders,
  canonicalJson,
  queryPeerEventsApi,
  createRealmApi,
  grantServiceCapabilityApi,
  listInvitesApi,
  makeFederationEvent,
  peerEventFrontierApi,
  pushFederationEvents,
  rawPushFederationEvents,
  queryRealmEventsApi,
  readAcceptedSeal,
  revokeCapabilityApi,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  createDpopUserSession,
  ensureRegistered,
  issueInviteLocatorToken,
  issueDevSession,
  openDpopUserPage,
  openDpopUserPageFromSession,
  openUserPage,
  selfPathHeadersForDpopSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.beforeEach(() => {
  if (!hasDualSoland()) {
    assertDualSolandNotRequired("cross-server federation");
    test.skip(
      true,
      "S2 requires dual soland topology — pass -DualSoland to scripts/run-joint-e2e.ps1",
    );
  }
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
            invite.invitee_id === inviteeId && invite.realm_id === realmId,
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
        return Array.isArray(body.member_ids) && body.member_ids.includes(memberId);
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
    serviceId !== solandServiceId("alpha") &&
    serviceId !== solandServiceId("beta")
  ) {
    throw new Error(`unexpected local federation service id: ${serviceId}`);
  }
  return "ak:trust_domain:local.host";
}

test.describe("cross-server federation", () => {
  test("both soland instances expose peer events submit and query endpoints", async ({
    request,
  }) => {
    // Sanity: both servers up and exposing the federation surface.
    const alphaHealth = await request.get(`${solandBaseUrl("alpha")}/health`);
    expect(alphaHealth.ok()).toBeTruthy();
    const betaHealth = await request.get(`${solandBaseUrl("beta")}/health`);
    expect(betaHealth.ok()).toBeTruthy();

    // POST without auth/body should not 404 — endpoint MUST exist.
    const pushProbe = await request.post(
      `${solandBaseUrl("beta")}/_arkret/peer/events`,
      {
        data: {},
      },
    );
    expect(pushProbe.status()).not.toBe(404);

    const pullProbe = await request.fetch(
      `${solandBaseUrl("beta")}/_arkret/peer/events`,
      { method: "QUERY", data: { realm_ids: ["ak:realm:probe"] } },
    );
    expect(pullProbe.status()).not.toBe(404);
  });

  test("unsigned peer QUERY pull is rejected", async ({ request }) => {
    const response = await request.fetch(
      `${solandBaseUrl("beta")}/_arkret/peer/events`,
      {
        method: "QUERY",
        data: { limit: 1 },
        headers: unsignedPeerQueryHeaders(
          solandServiceId("alpha"),
          solandServiceId("beta"),
        ),
      },
    );
    expect(
      response.ok(),
      `unsigned peer QUERY unexpectedly returned ${response.status()}: ${await response.text()}`,
    ).toBeFalsy();
    expect(response.status()).toBeLessThan(500);
  });

  test("alice uses canonical DPoP browser auth on α while bob holds an independent dev API session on β", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const aliceSession = await createDpopUserSession(
      request,
      `s2-alice-${stamp}`,
      { server: "alpha" },
    );
    const bob = uniqueUser(`s2-bob-${stamp}`);
    await ensureRegistered(request, bob, { server: "beta" });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });
    expect(aliceSession, "alpha DPoP session").toBeTruthy();

    const alicePageSession = await openDpopUserPageFromSession(
      browser,
      aliceSession,
      { server: "alpha", prepareMlsDevice: false },
    );
    const alicePage = alicePageSession!.page;

    try {
      await alicePage.gotoHome();
      expect(alicePage.serverUrl).toBe(solandBaseUrl("alpha"));

      // Each principal context binds to its own server.
      const aliceMeUrl = `${solandBaseUrl("alpha")}/_soland/self/account/me`;
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

      const bobMeUrl = `${solandBaseUrl("beta")}/_soland/self/account/me`;
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

  test("alice@α creates a space and invites bob (whose DID lives on β); UI surfaces the invite locally", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const bob = uniqueUser(`s2-bob-${stamp}`);
    await ensureRegistered(request, bob, { server: "beta" });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });
    const bobLocatorToken = await issueInviteLocatorToken(
      request,
      bobToken,
      "beta",
    );

    const alice = await openDpopUserPage(
      browser,
      request,
      `s2-alice-${stamp}`,
      {
        server: "alpha",
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
        serverUrl: solandBaseUrl("beta"),
      });
      await stepShot(alicePage.page, testInfo, "alpha-invite-issued");

      // The invite MUST be visible in α's space-invites list right after issuing.
      await alicePage.page
        .getByTestId("members-section-pending-invites")
        .click();
      const aliceInviteRow = alicePage.page.locator(
        `[data-testid="pending-invite-row"][data-member-did="${bob.id}"], ` +
          `[data-testid="invite-row"][data-member-did="${bob.id}"]`,
      );
      await expect(aliceInviteRow).toBeVisible({ timeout: 30_000 });
    } finally {
      await alicePage.close();
    }
  });

  test("α→β federation push smoke delivers an invite-shaped Event to β pull + invite APIs", async ({
    request,
  }) => {
    // API-first smoke for G3.S0: the real β federation ingestion and pull
    // surfaces accept an α-origin Event. The fully automatic inkson
    // invite/accept round trip remains pinned in the richer fixme below.
    const stamp = Date.now();
    const alice = uniqueUser(`s2-outbound-alice-${stamp}`, "alpha");
    const bob = uniqueUser(`s2-outbound-bob-${stamp}`, "beta");
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
        title: `S2 pushed invite ${stamp}`,
        ownerId: alice.id,
        creator_id: solandServiceId("alpha"),
        plaintext_visible_services: [
          solandServiceId("alpha"),
          solandServiceId("beta"),
        ],
      },
      { server: "alpha" },
    );
    const alphaRealmEvents = await queryRealmEventsApi(
      request,
      aliceToken,
      realmId,
      { server: "alpha", limit: 100 },
    );
    const bootstrapEvents = (
      Array.isArray(alphaRealmEvents.events)
        ? (alphaRealmEvents.events as Array<Record<string, unknown>>)
        : []
    ).sort(
      (left, right) =>
        Number(left.actor_seq ?? 0) - Number(right.actor_seq ?? 0),
    );
    const bootstrapPush = await pushFederationEvents(request, bootstrapEvents, {
      origin: solandServiceId("alpha"),
      destination: solandServiceId("beta"),
      server: "beta",
      realmId,
      idempotencyKey: `${solandServiceId("alpha")}#cotest-cross-server-bootstrap`,
    });
    expect(bootstrapPush.rejections ?? []).toEqual([]);
    expect([
      ...(bootstrapPush.accepted ?? []),
      ...(bootstrapPush.duplicate ?? []),
    ]).toHaveLength(bootstrapEvents.length);

    const frontierUrl = `${solandBaseUrl("alpha")}/_arkret/self/seals/frontier`;
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
      `read α Realm Seal frontier: ${JSON.stringify(frontierBody)}`,
    ).toBeTruthy();
    expect(frontierBody.frontier?.kind).toBe("realm_seal");
    const leaves = frontierBody.frontier?.seal_basis?.leaves as
      string[] | undefined;
    expect(leaves).toEqual([expect.stringMatching(/^ak:seal:/)]);
    const acceptedSeal = await readAcceptedSeal(
      request,
      aliceToken,
      realmId,
      leaves![0],
      "alpha",
    );
    const inviteId = typedId("invite");
    const inviteEvent = makeFederationEvent({
      realmId,
      kind: "ak.invite.create",
      actorId: alice.id,
      sealBasis: {
        leaves: [leaves![0]],
        control_event_set_root: String(acceptedSeal.control_event_set_root),
        state_root: String(acceptedSeal.state_root),
      },
      payload: {
        invite_id: inviteId,
        invitee_id: bob.id,
        invite_delivery_target: {
          recipient_id: solandServiceId("beta"),
          recipient_kind: "station",
        },
        introduction_evidence_digest: `sha256:${"ab".repeat(32)}`,
        expires_at: new Date(Date.now() + 86_400_000).toISOString(),
      },
    });
    await advanceEnvelopeToActorFrontier(
      request,
      aliceToken,
      inviteEvent,
      "alpha",
    );
    await submitSignedEventApi(request, aliceToken, inviteEvent, {
      server: "alpha",
      context: "submit α invite for federated Seal-closure delivery",
    });

    await expect
      .poll(
        async () => {
          const invites = await listInvitesApi(request, bobToken, {
            server: "beta",
          });
          return invites.some(
            (item) => item.realm_id === realmId && item.invitee_id === bob.id,
          );
        },
        { timeout: 20_000 },
      )
      .toBe(true);

    const replay = await pushFederationEvents(request, [inviteEvent], {
      origin: solandServiceId("alpha"),
      destination: solandServiceId("beta"),
      server: "beta",
      realmId,
      idempotencyKey: `${solandServiceId("alpha")}#cotest-cross-server-smoke`,
    });
    expect([...(replay.accepted ?? []), ...(replay.duplicate ?? [])]).toContain(
      inviteEvent.event_id,
    );
    expect(replay.rejections ?? []).toEqual([]);

    const pullBody = await queryPeerEventsApi(request, {
      server: "beta",
      sourceServiceId: solandServiceId("alpha"),
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

    const invites = await listInvitesApi(request, bobToken, { server: "beta" });
    const invite = invites.find(
      (item) => item.realm_id === realmId && item.invitee_id === bob.id,
    );
    expect(invite).toBeTruthy();
    await acceptInviteApi(
      request,
      bobToken,
      bob.id,
      invite!.realm_id,
      invite!.id,
      { server: "beta" },
    );

    const betaSpace = await request.get(
      `${solandBaseUrl("beta")}/_arkret/self/realms/${encodeURIComponent(invite!.realm_id)}`,
      { headers: authHeaders(bobToken) },
    );
    expect(betaSpace.ok()).toBeTruthy();
    expect((await betaSpace.json()).member_ids ?? []).toContain(bob.id);
  });

  test("α invite UI event fans out to β and standard peer Events propagates β acceptance back to α", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const bob = uniqueUser(`s2-auto-bob-${stamp}`, "beta");
    await ensureRegistered(request, bob, { server: "beta" });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });
    const bobLocatorToken = await issueInviteLocatorToken(
      request,
      bobToken,
      "beta",
    );

    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      `s2-auto-alice-${stamp}`,
      {
        server: "alpha",
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
        serverUrl: solandBaseUrl("beta"),
      });
      await stepShot(alicePage.page, testInfo, "alpha-auto-invite-issued");

      const betaInvite = await waitForInvite(
        request,
        bobToken,
        bob.id,
        realmId,
        "beta",
      );
      const acceptanceEvent = signedEventEnvelope({
        actorId: bob.id,
        realmId: betaInvite.realm_id,
        kind: "ak.invite.accept",
        payload: {
          invite_id: betaInvite.id,
        },
      });
      await submitSignedEventApi(request, bobToken, acceptanceEvent, {
        server: "beta",
      });
      const alphaEventsUrl = `${solandBaseUrl("alpha")}/_arkret/self/events`;
      const alphaEventsResponse = await request.fetch(alphaEventsUrl, {
        method: "QUERY",
        data: { realm_ids: [realmId], limit: 100 },
        headers: selfPathHeadersForDpopSession(
          aliceFlow.session,
          "QUERY",
          alphaEventsUrl,
        ),
      });
      expect(
        alphaEventsResponse.status(),
        await alphaEventsResponse.text(),
      ).toBe(200);
      const alphaEvents = (await alphaEventsResponse.json()) as {
        events?: Array<Record<string, unknown>>;
      };
      const alphaBindingEvent = (
        Array.isArray(alphaEvents.events)
          ? (alphaEvents.events as Array<Record<string, unknown>>)
          : []
      ).find((event) => {
        if (event.kind !== "ak.member.state") {
          return false;
        }
        const payload = event.payload as
          | {
              delivery_binding?: {
                recipient_id?: string;
              };
            }
          | undefined;
        return (
          payload?.delivery_binding?.recipient_id ===
          solandServiceId("alpha")
        );
      });
      expect(alphaBindingEvent?.event_id).toBeTruthy();
      const propagation = await pushFederationEvents(
        request,
        [acceptanceEvent],
        {
          origin: solandServiceId("beta"),
          destination: solandServiceId("alpha"),
          server: "alpha",
          realmId,
          idempotencyKey: `${solandServiceId("beta")}#${realmId}#acceptance`,
          serviceBindingFrontier: [String(alphaBindingEvent!.event_id)],
        },
      );
      expect(propagation.rejections ?? []).toEqual([]);
      const alphaRealmUrl =
        `${solandBaseUrl("alpha")}/_arkret/self/realms/` +
        encodeURIComponent(realmId);
      await expect
        .poll(
          async () => {
            const response = await request.get(alphaRealmUrl, {
              headers: selfPathHeadersForDpopSession(
                aliceFlow.session,
                "GET",
                alphaRealmUrl,
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

  test("two-way timeline messaging: alice@α and bob@β exchange messages and both servers converge on identical effective state", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-msg-alice-${stamp}`, "alpha");
    const bob = uniqueUser(`s2-msg-bob-${stamp}`, "beta");
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
        title: `S2 two-way ${stamp}`,
        discoverability: "listed",
        history_access: "all_history_for_current_members",
        invitees: [bob.id],
        invitee_ids: { [bob.id]: solandServiceId("beta") },
        ownerId: alice.id,
        creator_id: solandServiceId("alpha"),
        plaintext_visible_services: [
          solandServiceId("alpha"),
          solandServiceId("beta"),
        ],
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
      {
        server: "beta",
      },
    );
    await waitForMember(request, aliceToken, bob.id, realmId, "alpha");

    const aliceBody = `alice from alpha ${stamp}`;
    await sendMessageApi(request, aliceToken, realmId, aliceBody, {
      server: "alpha",
    });
    await waitForEventBody(request, bobToken, realmId, aliceBody, "beta");

    const bobBody = `bob from beta ${stamp}`;
    await sendMessageApi(request, bobToken, realmId, bobBody, {
      server: "beta",
    });
    await waitForEventBody(request, aliceToken, realmId, bobBody, "alpha");
  });

  test("peer query recovery: after a network partition, β fetches missing α events via QUERY /_arkret/peer/events", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-backfill-alice-${stamp}`, "alpha");
    const bob = uniqueUser(`s2-backfill-bob-${stamp}`, "beta");
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
        title: `S2 backfill ${stamp}`,
        discoverability: "listed",
        history_access: "all_history_for_current_members",
        invitees: [bob.id],
        invitee_ids: { [bob.id]: solandServiceId("beta") },
        ownerId: alice.id,
        creator_id: solandServiceId("alpha"),
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
      {
        server: "beta",
      },
    );
    await waitForMember(request, aliceToken, bob.id, realmId, "alpha");

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
      "alpha",
    );
    const alphaBeforePartitionWrite = await queryRealmEventsApi(
      request,
      aliceToken,
      realmId,
      { server: "alpha", limit: 100 },
    );
    const alphaBindingEvent = (
      Array.isArray(alphaBeforePartitionWrite.events)
        ? (alphaBeforePartitionWrite.events as Array<Record<string, unknown>>)
        : []
    ).find((event) => {
      if (event.kind !== "ak.member.state") {
        return false;
      }
      const payload = event.payload as
        | {
            delivery_binding?: {
              recipient_id?: string;
            };
          }
        | undefined;
      return (
        payload?.delivery_binding?.recipient_id ===
        solandServiceId("alpha")
      );
    });
    expect(alphaBindingEvent?.event_id).toBeTruthy();

    const sourceWrite = await pushFederationEvents(request, [missingEvent], {
      origin: solandServiceId("beta"),
      destination: solandServiceId("alpha"),
      server: "alpha",
      realmId,
      idempotencyKey: `${solandServiceId("beta")}#cotest-partition-source`,
      serviceBindingFrontier: [String(alphaBindingEvent!.event_id)],
    });
    expect(sourceWrite.rejections ?? []).toEqual([]);
    expect(sourceWrite.accepted ?? []).toContain(missingEvent.event_id);
    await waitForEventBody(request, aliceToken, realmId, missingBody, "alpha");

    const betaBeforeEvents = await queryRealmEventsApi(
      request,
      bobToken,
      realmId,
      {
        server: "beta",
        limit: 100,
      },
    );
    expect(JSON.stringify(betaBeforeEvents)).not.toContain(missingBody);
    const betaBeforeIds = new Set(
      (Array.isArray(betaBeforeEvents.events)
        ? (betaBeforeEvents.events as Array<Record<string, unknown>>)
        : []
      ).map((event) => String(event.event_id)),
    );

    const backfill = await queryPeerEventsApi(request, {
      server: "alpha",
      sourceServiceId: solandServiceId("beta"),
      realmId,
      limit: 100,
    });
    const backfilledEvents = backfill.events ?? [];
    const missingBackfillEvents = backfilledEvents.filter(
      (event) => !betaBeforeIds.has(String(event.event_id)),
    );
    expect(backfilledEvents.map((event) => event.event_id)).toContain(
      missingEvent.event_id,
    );
    const betaBindingEvent = backfilledEvents.find((event) => {
      if (event.kind !== "ak.invite.create") {
        return false;
      }
      const payload = event.payload as
        | {
            invite_delivery_target?: {
              recipient_id?: string;
            };
          }
        | undefined;
      return (
        payload?.invite_delivery_target?.recipient_id ===
        solandServiceId("beta")
      );
    });
    expect(betaBindingEvent?.event_id).toBeTruthy();
    const ingest = await pushFederationEvents(request, missingBackfillEvents, {
      origin: solandServiceId("alpha"),
      destination: solandServiceId("beta"),
      server: "beta",
      realmId,
      idempotencyKey: `${solandServiceId("beta")}#cotest-peer-query-recovery`,
      serviceBindingFrontier: [String(betaBindingEvent!.event_id)],
    });
    expect(ingest.rejections ?? []).toEqual([]);
    expect([...(ingest.accepted ?? []), ...(ingest.duplicate ?? [])]).toContain(
      String(missingEvent.event_id),
    );
    await waitForEventBody(request, bobToken, realmId, missingBody, "beta");

    const betaAfter = await queryRealmEventsApi(request, bobToken, realmId, {
      server: "beta",
      limit: 100,
    });
    const betaAfterIds = new Set(
      (Array.isArray(betaAfter.events)
        ? (betaAfter.events as Array<Record<string, unknown>>)
        : []
      ).map((event) => String(event.event_id)),
    );
    for (const event of backfilledEvents) {
      expect(betaAfterIds).toContain(String(event.event_id));
    }
  });

  test("Capability revoke fanout: after alice revokes β's service delegation, α MUST stop pushing future events to β (§4.4)", async ({
    request,
  }) => {
    // spec: sync/federation.md §4.4 — once a service delegation grant whose
    // subject is a peer service DID is revoked, the source Station
    // MUST stop pushing future events for that Realm to the revoked peer.
    // soland: `ProjectionState::federation_delivery_revoked_peers` derives the
    // revoked-peer set from the durable capability grant cells and
    // `dynamic_peer_event_targets` (event_log/submit.rs) skips those peers.
    const stamp = Date.now();
    const alice = uniqueUser(`s2-revoke-alice-${stamp}`, "alpha");
    const bob = uniqueUser(`s2-revoke-bob-${stamp}`, "beta");
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "alpha",
    });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });

    // Federated Realm: bob@β joins so β is a routable delivery target on α.
    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: `S2 revoke fanout ${stamp}`,
        discoverability: "listed",
        history_access: "all_history_for_current_members",
        invitees: [bob.id],
        invitee_ids: { [bob.id]: solandServiceId("beta") },
        ownerId: alice.id,
        creator_id: solandServiceId("alpha"),
        plaintext_visible_services: [
          solandServiceId("alpha"),
          solandServiceId("beta"),
        ],
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

    // Alice (Realm owner) delegates the federation delivery binding policy to
    // β's service DID, then confirms a baseline message still fans out to β.
    const grantId = await grantServiceCapabilityApi(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      subjectServiceId: solandServiceId("beta"),
    });
    const beforeBody = `before revoke ${stamp}`;
    await sendMessageApi(request, aliceToken, realmId, beforeBody, {
      server: "alpha",
    });
    await waitForEventBody(request, bobToken, realmId, beforeBody, "beta");

    // Revoke β's service delegation. Per §4.4 the source server MUST stop
    // pushing future events to β.
    await revokeCapabilityApi(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      grantId,
    });

    // A message sent after the revoke MUST still land on α (the revoke only
    // gates outbound federation push, not local acceptance) …
    const afterBody = `after revoke ${stamp}`;
    await sendMessageApi(request, aliceToken, realmId, afterBody, {
      server: "alpha",
    });
    await waitForEventBody(request, aliceToken, realmId, afterBody, "alpha");

    // … but MUST NOT be pushed to β. Poll β long enough that a fanout would
    // have arrived, then assert the post-revoke body never appears while the
    // pre-revoke body remains visible (proves β was reachable before revoke).
    await expect
      .poll(
        async () => {
          const body = await queryRealmEventsApi(request, bobToken, realmId, {
            server: "beta",
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

    // Final settle: re-confirm β never received the post-revoke event.
    const betaFinal = await queryRealmEventsApi(request, bobToken, realmId, {
      server: "beta",
      limit: 200,
    });
    expect(JSON.stringify(betaFinal)).not.toContain(afterBody);
  });

  test("RFC 9421 signature failure: tampered Signature header makes β reject the entire batch with 4xx", async ({
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
      origin: solandServiceId("alpha"),
      destination: solandServiceId("beta"),
      server: "beta",
      realmId,
      idempotencyKey: `${solandServiceId("alpha")}#cotest-rfc9421-negative`,
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

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
//   ✓ service_binding_ref.reducer_profile_digest validated (whole-batch reject)
//   ✓ §4.4 capability revoke fanout: revoking a peer's service delegation
//     stops outbound federation push to that peer

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  assertDualSolandNotRequired,
  hasDualSoland,
  solandBaseUrl,
  solandServiceDid,
} from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  acceptInviteApi,
  authHeaders,
  queryPeerEventsApi,
  createRealmApi,
  grantServiceDelegationApi,
  listInvitesApi,
  makeFederationEvent,
  peerEventFrontierApi,
  pushFederationEvents,
  rawPushFederationEvents,
  queryRealmEventsApi,
  revokeCapabilityApi,
  sendMessageApi,
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
            invite.invitee === inviteeDid &&
            invite.realm_id === realmId,
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

function unsignedPeerGetHeaders(
  sourceDid: string,
  destinationDid: string,
): Record<string, string> {
  return {
    "source-service-did": sourceDid,
    "destination-service-did": destinationDid,
    "source-trust-domain": trustDomainFromServiceDid(sourceDid),
    "destination-trust-domain": trustDomainFromServiceDid(destinationDid),
  };
}

function trustDomainFromServiceDid(serviceDid: string): string {
  const webHost = serviceDid.startsWith("did:web:")
    ? serviceDid.slice("did:web:".length).split(":")[0]
    : undefined;
  const webvhHost = serviceDid.startsWith("did:webvh:")
    ? serviceDid.slice("did:webvh:".length).split(":")[1]
    : undefined;
  const keyScope = serviceDid.startsWith("did:key:")
    ? serviceDid.slice("did:key:".length)
    : undefined;
  const rawScope = webHost ?? webvhHost ?? keyScope ?? serviceDid;
  const scope = rawScope
    .split(/%3a/i)[0]
    .replace(/\.+$/, "")
    .toLowerCase()
    .replace(/[^a-z0-9.\-_:]/g, "");
  return `ak:trust_domain:${scope || "local"}`;
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

    const pullProbe = await request.get(
      `${solandBaseUrl("beta")}/_arkret/peer/events?realms=ak:realm:probe`,
    );
    expect(pullProbe.status()).not.toBe(404);
  });

  test("unsigned peer GET pull is rejected", async ({ request }) => {
    const response = await request.get(
      `${solandBaseUrl("beta")}/_arkret/peer/events?limit=1`,
      {
        headers: unsignedPeerGetHeaders(
          solandServiceDid("alpha"),
          solandServiceDid("beta"),
        ),
      },
    );
    expect(
      response.ok(),
      `unsigned peer GET unexpectedly returned ${response.status()}: ${await response.text()}`,
    ).toBeFalsy();
    expect(response.status()).toBeLessThan(500);
  });

  test("alice on α and bob on β are independently registered + dev-logged-in against their own server", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-alice-${stamp}`);
    const bob = uniqueUser(`s2-bob-${stamp}`);

    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "alpha",
    });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });

    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
      server: "alpha",
    });
    const bobPage = await openUserPage(browser, bob, {
      sessionCredential: bobToken,
      server: "beta",
    });

    try {
      await alicePage.gotoHome();
      expect(alicePage.serverUrl).toBe(solandBaseUrl("alpha"));
      await bobPage.gotoHome();
      expect(bobPage.serverUrl).toBe(solandBaseUrl("beta"));

      // Each principal context binds to its own server.
      const aliceMeResp = await request.get(
        `${solandBaseUrl("alpha")}/_soland/self/account/me`,
        {
          headers: { authorization: `Bearer ${aliceToken}` },
        },
      );
      expect(aliceMeResp.ok()).toBeTruthy();
      const aliceMe = await aliceMeResp.json();
      expect(aliceMe.did).toBe(alice.did);

      const bobMeResp = await request.get(
        `${solandBaseUrl("beta")}/_soland/self/account/me`,
        {
          headers: { authorization: `Bearer ${bobToken}` },
        },
      );
      expect(bobMeResp.ok()).toBeTruthy();
      const bobMe = await bobMeResp.json();
      expect(bobMe.did).toBe(bob.did);
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("alice@α creates a space and invites bob (whose DID lives on β); UI surfaces the invite locally", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-alice-${stamp}`);
    const bob = uniqueUser(`s2-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "alpha",
    });

    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
      server: "alpha",
    });

    try {
      const realmId = await alicePage.createRealm({
        title: `S2 Cross-server ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
      });
      await alicePage.inviteFromAdmin(realmId, bob.did);
      await stepShot(alicePage.page, testInfo, "alpha-invite-issued");

      // The invite MUST be visible in α's space-invites list right after issuing.
      const aliceInviteRow = alicePage.page.locator(
        `[data-testid="pending-invite-row"][data-member-did="${bob.did}"], ` +
          `[data-testid="invite-row"][data-member-did="${bob.did}"]`,
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
    const alice = uniqueUser(`s2-outbound-alice-${stamp}`);
    const bob = uniqueUser(`s2-outbound-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    await issueDevSession(request, alice, { server: "alpha" });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });

    const alphaDescribe = await request.get(
      `${solandBaseUrl("alpha")}/_arkret/describe`,
    );
    expect(alphaDescribe.ok()).toBeTruthy();
    const alphaDescribeBody = await alphaDescribe.json();
    expect(alphaDescribeBody.experimental_features ?? []).toContain(
      "federation.outbound_push.signed_intent",
    );

    const realmId = typedId("realm");
    const inviteEvent = makeFederationEvent({
      realmId,
      kind: "ak.member.state",
      payload: {
        realm_id: realmId,
        actor_id: bob.did,
        membership: "invite",
        realm_title: `S2 pushed invite ${stamp}`,
        discoverability: "public",
        history_visibility: "shared",
      },
    });

    const push = await pushFederationEvents(request, [inviteEvent], {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      server: "beta",
      realmId,
      idempotencyKey: `${solandServiceDid("alpha")}#cotest-cross-server-smoke`,
    });
    expect(push.accepted).toContain(inviteEvent.event_id);
    expect(push.rejected ?? []).toEqual([]);

    const replay = await pushFederationEvents(request, [inviteEvent], {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      server: "beta",
      realmId,
      idempotencyKey: `${solandServiceDid("alpha")}#cotest-cross-server-smoke`,
    });
    expect(replay.accepted).toContain(inviteEvent.event_id);
    expect(replay.rejected ?? []).toEqual([]);

    const pullBody = await queryPeerEventsApi(request, {
      server: "beta",
      realmId,
      limit: 10,
    });
    expect(
      (pullBody.events ?? []).map(
        (entry: { event?: { event_id?: string } }) => entry.event?.event_id,
      ),
    ).toContain(inviteEvent.event_id);
    expect(
      (pullBody.events ?? []).filter(
        (entry: { event?: { event_id?: string } }) =>
          entry.event?.event_id === inviteEvent.event_id,
      ),
    ).toHaveLength(1);

    const invites = await listInvitesApi(request, bobToken, { server: "beta" });
    const invite = invites.find(
      (item) => item.realm_id === realmId && item.invitee === bob.did,
    );
    expect(invite).toBeTruthy();
    await acceptInviteApi(
      request,
      bobToken,
      bob.did,
      invite!.realm_id,
      invite!.id,
      { server: "beta" },
    );

    const betaSpace = await request.get(
      `${solandBaseUrl("beta")}/_arkret/self/realms/${encodeURIComponent(invite!.realm_id)}`,
      { headers: authHeaders(bobToken) },
    );
    expect(betaSpace.ok()).toBeTruthy();
    expect((await betaSpace.json()).members ?? []).toContain(bob.did);
  });

  test("α invite UI event automatically fans out to β and β acceptance propagates back to α", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-auto-alice-${stamp}`);
    const bob = uniqueUser(`s2-auto-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    const aliceToken = await issueDevSession(request, alice, {
      server: "alpha",
    });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });

    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
      server: "alpha",
    });

    try {
      const realmId = await alicePage.createRealm({
        title: `S2 auto federation ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
      });
      await alicePage.inviteFromAdmin(realmId, bob.did);
      await stepShot(alicePage.page, testInfo, "alpha-auto-invite-issued");

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
    } finally {
      await alicePage.close();
    }
  });

  test("two-way timeline messaging: alice@α and bob@β exchange messages and both servers converge on identical effective state", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-msg-alice-${stamp}`);
    const bob = uniqueUser(`s2-msg-bob-${stamp}`);
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
        history_visibility: "shared",
        invitees: [bob.did],
        ownerDid: alice.did,
        plaintext_visible_services: [
          solandServiceDid("alpha"),
          solandServiceDid("beta"),
        ],
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
      {
        server: "beta",
      },
    );
    await waitForMember(request, aliceToken, bob.did, realmId, "alpha");

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

  test("peer query recovery: after a network partition, β fetches missing α events via GET /_arkret/peer/events", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s2-backfill-alice-${stamp}`);
    const bob = uniqueUser(`s2-backfill-bob-${stamp}`);
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
      {
        server: "beta",
      },
    );
    await waitForMember(request, aliceToken, bob.did, realmId, "alpha");

    const missingBody = `pulled after partition ${stamp}`;
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
      idempotencyKey: `${solandServiceDid("alpha")}#cotest-partition-source`,
    });
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
    const alphaFrontier = await peerEventFrontierApi(request, realmId, {
      server: "alpha",
    });
    const betaFrontierBefore = await peerEventFrontierApi(request, realmId, {
      server: "beta",
    });
    expect(betaFrontierBefore.frontier_root).not.toBe(
      alphaFrontier.frontier_root,
    );

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
      idempotencyKey: `${solandServiceDid("beta")}#cotest-peer-query-recovery`,
    });
    expect(ingest.rejected ?? []).toEqual([]);
    expect(ingest.accepted).toContain(
      String(missingEvent.event_id),
    );
    await waitForEventBody(request, bobToken, realmId, missingBody, "beta");

    const betaFrontierAfter = await peerEventFrontierApi(request, realmId, {
      server: "beta",
    });
    for (const eventId of alphaFrontier.heads) {
      expect(betaFrontierAfter.heads).toContain(eventId);
    }
  });

  test("reducer_profile_digest mismatch returns rejected with reason_code=reducer_profile_mismatch", async ({
    request,
  }) => {
    // spec: federation.md §4.1 service_binding_ref.reducer_profile_digest +
    // §4.1.1 receiver gate; registered vector
    // ak.vector.federation.reducer_profile_digest.v1: a digest diverging from
    // the receiver's registry-derived value MUST reject the WHOLE batch with
    // reducer_profile_mismatch — no partial accept.
    // soland: validated in event_log/admission.rs
    // (validate_federation_service_binding) and wired into the federation
    // submit path before any event admission.
    const realmId = typedId("realm");
    const event = makeFederationEvent({
      realmId,
      kind: "ak.message.create",
      actorDid: "did:web:alice-reducer-mismatch.example",
      payload: {
        strand_id: typedId("strand"),
        track_name: "discussion",
        content: {
          kind: "ak.content.text",
          body: `reducer profile mismatch probe ${Date.now()}`,
        },
      },
    });
    const response = await rawPushFederationEvents(request, [event], {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      server: "beta",
      realmId,
      idempotencyKey: `${solandServiceDid("alpha")}#cotest-reducer-profile-mismatch`,
      // Well-formed sha256:<hex> that cannot equal β's registry-derived
      // digest for ak.profile.federation_minimal.v1.
      reducerProfileDigestOverride: `sha256:${"9".repeat(64)}`,
    });
    const body = (await response.json()) as {
      accepted?: string[];
      duplicate?: string[];
      rejected?: Array<Record<string, unknown>>;
    };
    // Whole-batch rejection: either an error envelope carrying the code, or a
    // rejected[] entry per event with reason_code=reducer_profile_mismatch.
    expect(body.accepted ?? []).toEqual([]);
    expect(body.duplicate ?? []).toEqual([]);
    if (response.ok()) {
      const rejected = body.rejected ?? [];
      expect(rejected.map((entry) => entry.id ?? entry.event_id)).toContain(
        String(event.event_id),
      );
      for (const entry of rejected) {
        expect(entry.reason_code).toBe("reducer_profile_mismatch");
      }
    } else {
      expect(wireErrCode(body)).toBe("reducer_profile_mismatch");
    }
  });

  test("Capability revoke fanout: after alice revokes β's service delegation, α MUST stop pushing future events to β (§4.4)", async ({
    request,
  }) => {
    // spec: sync/federation.md §4.4 — once a service delegation grant whose
    // subject is a peer service DID is revoked, the source Principal Server
    // MUST stop pushing future events for that Realm to the revoked peer.
    // soland: `ProjectionState::federation_delivery_revoked_peers` derives the
    // revoked-peer set from the durable capability grant cells and
    // `dynamic_peer_event_targets` (event_log/submit.rs) skips those peers.
    const stamp = Date.now();
    const alice = uniqueUser(`s2-revoke-alice-${stamp}`);
    const bob = uniqueUser(`s2-revoke-bob-${stamp}`);
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
        history_visibility: "shared",
        invitees: [bob.did],
        ownerDid: alice.did,
        plaintext_visible_services: [
          solandServiceDid("alpha"),
          solandServiceDid("beta"),
        ],
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

    // Alice (Realm owner) delegates the federation delivery binding policy to
    // β's service DID, then confirms a baseline message still fans out to β.
    const grantId = await grantServiceDelegationApi(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      subjectServiceDid: solandServiceDid("beta"),
    });
    const beforeBody = `before revoke ${stamp}`;
    await sendMessageApi(request, aliceToken, realmId, beforeBody, {
      server: "alpha",
    });
    await waitForEventBody(request, bobToken, realmId, beforeBody, "beta");

    // Revoke β's service delegation. Per §4.4 the source server MUST stop
    // pushing future events to β.
    await revokeCapabilityApi(request, aliceToken, {
      ownerDid: alice.did,
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
      actorDid: "did:web:alice-rfc9421.example",
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
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      server: "beta",
      realmId,
      idempotencyKey: `${solandServiceDid("alpha")}#cotest-rfc9421-negative`,
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

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
//   ✓ POST /_cokret/peer/federation/push-operations handler routed and ingests events
//   ✓ GET  /_cokret/peer/federation/pull-operations cursor-based
//   ✓ Per-event accepted / rejected partial-accept
//   ✓ Idempotent by operation_id
//   ✓ SOLAND_FEDERATION_PEERS env wires peer URLs + peer service DIDs
//   ✓ Outbound push worker POSTs local invite/message operations to peers
//   ✓ ck.invite.create, ck.member.state join, and ck.message.create trigger federation push
//   ✓ backfill-operations pulls peer pages and ingests missing local operations
//   ✓ operation-frontier exposes deterministic operation-id coverage
//   ✓ inbound RFC 9421 HTTP Message Signature rejects tampered batches
//   ✗ service_binding_ref.reducer_profile_digest NOT validated

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  hasDualSoland,
  solandBaseUrl,
  solandServiceDid,
} from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  acceptInviteApi,
  authHeaders,
  backfillFederationOperations,
  createSpaceApi,
  listInvitesApi,
  makeOperation,
  operationFrontierApi,
  pushFederationOperations,
  rawPushFederationOperations,
  querySpaceEventsApi,
  sendMessageApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.beforeEach(() => {
  test.skip(
    !hasDualSoland(),
    "S2 requires dual soland topology — pass -DualSoland to scripts/run-joint-e2e.ps1",
  );
});

async function waitForInvite(
  request: APIRequestContext,
  token: string,
  inviteeDid: string,
  spaceId: string,
  server: "alpha" | "beta",
) {
  let found:
    | {
        invite_id: string;
        space_id: string;
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
            invite.space_id.replace(/^ck:space:/, "ck:realm:") ===
              spaceId.replace(/^ck:space:/, "ck:realm:"),
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
  spaceId: string,
  server: "alpha" | "beta",
) {
  await expect
    .poll(
      async () => {
        const response = await request.get(
          `${solandBaseUrl(server)}/_soland/self/spaces/${encodeURIComponent(spaceId)}`,
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
  spaceId: string,
  bodyText: string,
  server: "alpha" | "beta",
) {
  await expect
    .poll(
      async () => {
        const body = await querySpaceEventsApi(request, token, spaceId, {
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

test.describe("cross-server federation", () => {
  test("both soland instances expose /federation/push-operations and /federation/pull-operations endpoints", async ({
    request,
  }) => {
    // Sanity: both servers up and exposing the federation surface.
    const alphaHealth = await request.get(`${solandBaseUrl("alpha")}/health`);
    expect(alphaHealth.ok()).toBeTruthy();
    const betaHealth = await request.get(`${solandBaseUrl("beta")}/health`);
    expect(betaHealth.ok()).toBeTruthy();

    // POST without auth/body should not 404 — endpoint MUST exist.
    const pushProbe = await request.post(
      `${solandBaseUrl("beta")}/_cokret/peer/federation/push-operations`,
      {
        data: {},
      },
    );
    expect(pushProbe.status()).not.toBe(404);

    const pullProbe = await request.get(
      `${solandBaseUrl("beta")}/_cokret/peer/federation/pull-operations?space_id=ck:space:probe`,
    );
    expect(pullProbe.status()).not.toBe(404);
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
      sessionToken: aliceToken,
      server: "alpha",
    });
    const bobPage = await openUserPage(browser, bob, {
      sessionToken: bobToken,
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
      sessionToken: aliceToken,
      server: "alpha",
    });

    try {
      const spaceId = await alicePage.createSpace({
        title: `S2 Cross-server ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
      });
      await alicePage.inviteFromAdmin(spaceId, bob.did);
      await stepShot(alicePage.page, testInfo, "alpha-invite-issued");

      // The invite MUST be visible in α's space-invites list right after issuing.
      const aliceInviteRow = alicePage.page
        .getByTestId("invite-row")
        .filter({ hasText: bob.did });
      await expect(aliceInviteRow).toBeVisible({ timeout: 30_000 });
    } finally {
      await alicePage.close();
    }
  });

  test("α→β federation push smoke delivers an invite-shaped operation to β pull + invite APIs", async ({
    request,
  }) => {
    // API-first smoke for G3.S0: the real β federation ingestion and pull
    // surfaces accept an α-origin operation. The fully automatic yougen
    // invite/accept round trip remains pinned in the richer fixme below.
    const stamp = Date.now();
    const alice = uniqueUser(`s2-outbound-alice-${stamp}`);
    const bob = uniqueUser(`s2-outbound-bob-${stamp}`);
    await ensureRegistered(request, alice, { server: "alpha" });
    await ensureRegistered(request, bob, { server: "beta" });
    await issueDevSession(request, alice, { server: "alpha" });
    const bobToken = await issueDevSession(request, bob, { server: "beta" });

    const alphaDescribe = await request.get(
      `${solandBaseUrl("alpha")}/_cokret/describe`,
    );
    expect(alphaDescribe.ok()).toBeTruthy();
    const alphaDescribeBody = await alphaDescribe.json();
    expect(alphaDescribeBody.experimental_features ?? []).toContain(
      "federation.outbound_push.signed_intent",
    );

    const spaceId = typedId("space");
    const inviteOperation = makeOperation({
      spaceId,
      objectType: "ck.member.state",
      payload: {
        actor_id: bob.did,
        member: bob.did,
        membership: "invite",
        space_title: `S2 pushed invite ${stamp}`,
        discoverability: "public",
        history_visibility: "shared",
      },
    });

    const push = await pushFederationOperations(request, [inviteOperation], {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      server: "beta",
      spaceId,
      serviceBindingRef: `${solandServiceDid("alpha")}#cotest-cross-server-smoke`,
    });
    expect(push.accepted).toContain(inviteOperation.operation_id);
    expect(push.rejected ?? []).toEqual([]);

    const replay = await pushFederationOperations(request, [inviteOperation], {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      server: "beta",
      spaceId,
      serviceBindingRef: `${solandServiceDid("alpha")}#cotest-cross-server-smoke`,
    });
    expect(replay.accepted).toContain(inviteOperation.operation_id);
    expect(replay.rejected ?? []).toEqual([]);

    const pull = await request.get(
      `${solandBaseUrl("beta")}/_cokret/peer/federation/pull-operations?space_id=${encodeURIComponent(spaceId)}&limit=10`,
    );
    expect(pull.ok()).toBeTruthy();
    const pullBody = await pull.json();
    expect(
      (pullBody.operations ?? []).map(
        (op: { operation_id: string }) => op.operation_id,
      ),
    ).toContain(inviteOperation.operation_id);
    expect(
      (pullBody.operations ?? []).filter(
        (op: { operation_id: string }) =>
          op.operation_id === inviteOperation.operation_id,
      ),
    ).toHaveLength(1);

    const projectedRealmId = spaceId.replace(/^ck:space:/, "ck:realm:");
    const invites = await listInvitesApi(request, bobToken, { server: "beta" });
    const invite = invites.find(
      (item) =>
        [spaceId, projectedRealmId].includes(item.space_id) &&
        item.invitee === bob.did,
    );
    expect(invite).toBeTruthy();
    await acceptInviteApi(
      request,
      bobToken,
      bob.did,
      invite!.space_id,
      invite!.invite_id,
      { server: "beta" },
    );

    const betaSpace = await request.get(
      `${solandBaseUrl("beta")}/_soland/self/spaces/${encodeURIComponent(invite!.space_id)}`,
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
      sessionToken: aliceToken,
      server: "alpha",
    });

    try {
      const spaceId = await alicePage.createSpace({
        title: `S2 auto federation ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
      });
      await alicePage.inviteFromAdmin(spaceId, bob.did);
      await stepShot(alicePage.page, testInfo, "alpha-auto-invite-issued");

      const betaInvite = await waitForInvite(
        request,
        bobToken,
        bob.did,
        spaceId,
        "beta",
      );
      await acceptInviteApi(
        request,
        bobToken,
        bob.did,
        betaInvite.space_id,
        betaInvite.invite_id,
        { server: "beta" },
      );
      await waitForMember(request, aliceToken, bob.did, spaceId, "alpha");
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

    const spaceId = await createSpaceApi(
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
      spaceId,
      "beta",
    );
    await acceptInviteApi(
      request,
      bobToken,
      bob.did,
      betaInvite.space_id,
      betaInvite.invite_id,
      {
        server: "beta",
      },
    );
    await waitForMember(request, aliceToken, bob.did, spaceId, "alpha");

    const aliceBody = `alice from alpha ${stamp}`;
    await sendMessageApi(request, aliceToken, spaceId, aliceBody, {
      server: "alpha",
    });
    await waitForEventBody(request, bobToken, spaceId, aliceBody, "beta");

    const bobBody = `bob from beta ${stamp}`;
    await sendMessageApi(request, bobToken, spaceId, bobBody, {
      server: "beta",
    });
    await waitForEventBody(request, aliceToken, spaceId, bobBody, "alpha");
  });

  test("Pull / backfill: after a network partition, β fetches missing α events via GET /_cokret/peer/federation/pull-operations", async ({
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

    const spaceId = await createSpaceApi(
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
      spaceId,
      "beta",
    );
    await acceptInviteApi(
      request,
      bobToken,
      bob.did,
      betaInvite.space_id,
      betaInvite.invite_id,
      {
        server: "beta",
      },
    );
    await waitForMember(request, aliceToken, bob.did, spaceId, "alpha");

    const missingBody = `pulled after partition ${stamp}`;
    const missingOperation = makeOperation({
      spaceId,
      objectType: "ck.message.create",
      payload: {
        event_id: typedId("event"),
        sender: alice.did,
        flow_id: typedId("flow"),
        track_name: "discussion",
        content: {
          kind: "ck.content.text",
          body: missingBody,
        },
      },
    });

    await pushFederationOperations(request, [missingOperation], {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("alpha"),
      server: "alpha",
      spaceId,
      serviceBindingRef: `${solandServiceDid("alpha")}#cotest-partition-source`,
    });
    await waitForEventBody(request, aliceToken, spaceId, missingBody, "alpha");

    const betaBeforeEvents = await querySpaceEventsApi(
      request,
      bobToken,
      spaceId,
      {
        server: "beta",
        limit: 100,
      },
    );
    expect(JSON.stringify(betaBeforeEvents)).not.toContain(missingBody);
    const alphaFrontier = await operationFrontierApi(request, spaceId, {
      server: "alpha",
    });
    const betaFrontierBefore = await operationFrontierApi(request, spaceId, {
      server: "beta",
    });
    expect(betaFrontierBefore.frontier_digest).not.toBe(
      alphaFrontier.frontier_digest,
    );

    const backfill = await backfillFederationOperations(request, {
      server: "beta",
      peerUrl: solandBaseUrl("alpha"),
      peerDid: solandServiceDid("alpha"),
      spaceId,
      limit: 100,
    });
    expect(backfill.rejected ?? []).toEqual([]);
    expect(backfill.accepted ?? []).toContain(
      String(missingOperation.operation_id),
    );
    await waitForEventBody(request, bobToken, spaceId, missingBody, "beta");

    const betaFrontierAfter = await operationFrontierApi(request, spaceId, {
      server: "beta",
    });
    for (const operationId of alphaFrontier.operation_ids) {
      expect(betaFrontierAfter.operation_ids).toContain(operationId);
    }
  });

  test.fixme(// @blocking-on: soland#federation-cross-server-gap
  // @user-promise: e2e/scenarios/federation/cross-server.md
  // @expected-live-by: 2026Q3
  "reducer_profile_digest mismatch returns rejected with reason_code=reducer_profile_mismatch", async () => {
    // spec: §4.1 reducer_profile_digest gate.
    // soland gap: reducer_profile_digest NOT validated.
    // Idempotent push replay is live in the API smoke above.
  });

  test.fixme(// @blocking-on: soland#federation-cross-server-gap
  // @user-promise: e2e/scenarios/federation/cross-server.md
  // @expected-live-by: 2026Q3
  "Capability revoke fanout: after alice revokes β's service delegation, α MUST stop pushing future events to β (§4.4)", async () => {
    // spec: §4.4 capability revoke fanout
    // soland gap: no service-delegation revoke fanout implemented.
  });

  test("RFC 9421 signature failure: tampered Signature header makes β reject the entire batch with 4xx", async ({
    request,
  }) => {
    const spaceId = typedId("space");
    const operation = makeOperation({
      spaceId,
      objectType: "ck.message.create",
      payload: {
        event_id: typedId("event"),
        sender: "did:web:alice-rfc9421.example",
        flow_id: typedId("flow"),
        track_name: "discussion",
        content: {
          kind: "ck.content.text",
          body: `tampered signature ${Date.now()}`,
        },
      },
    });
    const response = await rawPushFederationOperations(request, [operation], {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      server: "beta",
      spaceId,
      serviceBindingRef: `${solandServiceDid("alpha")}#cotest-rfc9421-negative`,
      tamperSignature: true,
    });
    const text = await response.text();
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(response.status()).toBeLessThan(500);
    expect(text).toContain("key_rotation_hint=refresh_origin_service_did");
  });
});

// Discussion track upgrade to a Circle-scoped private Flow (CKP-0007).
// Contract: e2e/scenarios/messaging/discussion-upgrade.md
// Spec refs:
//   - models/flow-and-message.md §5, §5.1 (scope_circle_id on Flow)
//   - models/circle.md (Circle primitive, membership and encryption boundary)
//   - models/relation.md (confidential_discussion_of)
//   - discovery/read-receipts.md §2.5 (scope override)

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  authHeaders,
  createSharedRealmViaApi,
  listReadMarkersViaApi,
  listRealmEventsViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import {
  resolveDefaultFlowId,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  type JointUser,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("discussion upgrade to Circle-scoped private Flow", () => {
  test("API inline discussion track preserves flow_id and thread_id", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "inline-track");
    const defaultFlowId = await resolveDefaultFlowId(request, fixture.aliceToken, fixture.realmId);
    const body = `inline discussion ${Date.now()}`;
    await submitSignedEventApi(
      request,
      fixture.aliceToken,
      signedEventEnvelope({
        actorDid: fixture.alice.did,
        realmId: fixture.realmId,
        kind: "ck.message.create",
        payload: {
          flow_id: defaultFlowId,
          track_name: "discussion",
          thread_id: "discussion",
          content: { kind: "ck.content.text", body },
          encrypted: false,
        },
      }),
      { context: "inline discussion message" },
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    const message = events.find((event) =>
      JSON.stringify(eventPayload(event)).includes(body),
    );
    expect(eventPayload(message)).toMatchObject({
      flow_id: defaultFlowId,
      track_name: "discussion",
      thread_id: "discussion",
    });
  });

  test("private discussion Flow stays on the same Realm frontier and carries Circle scope", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "same-realm");
    const publicFlowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "public F1",
    );
    const before = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      publicFlowId,
      "public discussion",
    );
    const promoted = await promoteDiscussionToPrivateFlowViaApi(
      request,
      fixture,
      publicFlowId,
      { members: [fixture.alice, fixture.bob] },
    );
    const after = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      promoted.privateFlowId,
      "private discussion",
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    const ids = events.map((event) => event.event_id);
    expect(ids).toEqual(expect.arrayContaining([before.event_id, after.event_id]));
    expect(JSON.stringify(eventById(events, after.event_id))).toContain(
      promoted.circleId,
    );
    expect(eventPayload(eventById(events, after.event_id))).toMatchObject({
      flow_id: promoted.privateFlowId,
      track_name: "discussion",
    });
  });

  test("Realm member outside the Circle cannot read Circle-scoped discussion messages", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("circle-visibility-alice");
    const carol = uniqueUser("circle-visibility-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, carol),
    ]);
    const [aliceToken, carolToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, carol),
    ]);
    const realmId = await createSharedRealmViaApi(
      request,
      alice,
      aliceToken,
      carol,
      carolToken,
      { title: `circle visibility ${stamp}`, historyVisibility: "shared" },
    );
    const publicFlowId = await createFlowViaApi(
      request,
      aliceToken,
      alice,
      realmId,
      "public visible F1",
    );
    const publicMessage = await createDiscussionMessageViaApi(
      request,
      aliceToken,
      alice,
      realmId,
      publicFlowId,
      "realm-visible message",
    );
    const promoted = await promoteDiscussionToPrivateFlowViaApi(
      request,
      {
        alice,
        bob: carol,
        aliceToken,
        bobToken: carolToken,
        realmId,
      },
      publicFlowId,
      { members: [alice] },
    );
    const privateMessage = await createDiscussionMessageViaApi(
      request,
      aliceToken,
      alice,
      realmId,
      promoted.privateFlowId,
      "circle-private message",
    );

    const carolEvents = await listRealmEventsViaApi(request, carolToken, realmId);
    const carolIds = carolEvents.map((event) => event.event_id);
    expect(carolIds).toContain(publicMessage.event_id);
    expect(carolIds).not.toContain(privateMessage.event_id);
  });

  test("Circle-scoped read receipt uses realm_id and remains scoped to the private Flow", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "circle-receipt");
    const publicFlowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "receipt public F1",
    );
    const promoted = await promoteDiscussionToPrivateFlowViaApi(
      request,
      fixture,
      publicFlowId,
      { members: [fixture.alice, fixture.bob] },
    );
    const privateMessage = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      promoted.privateFlowId,
      "private receipt target",
    );
    const sentAt = new Date();
    const receipt = await request.post(`${solandBaseUrl()}/_cokret/self/ephemeral`, {
      headers: authHeaders(fixture.bobToken),
      data: {
        kind: "ck.receipt.read",
        realm_id: fixture.realmId,
        actor_id: fixture.bob.did,
        device_id: fixture.bob.deviceId,
        sent_at: sentAt.toISOString(),
        expires_at: new Date(sentAt.getTime() + 30_000).toISOString(),
        payload: { event_id: privateMessage.event_id },
      },
    });
    expect(receipt.status()).toBe(200);
    expect(
      await listReadMarkersViaApi(request, fixture.aliceToken, fixture.realmId),
    ).toHaveLength(0);
  });

  test("alice and bob exchange messages on a Realm-default Flow's inline discussion track", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "inline-flow");
    const flowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "inline F1",
    );
    const aliceMessage = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      flowId,
      "F1 alice inline",
    );
    const bobMessage = await createDiscussionMessageViaApi(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.realmId,
      flowId,
      "F1 bob inline",
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const ids = events.map((event) => event.event_id);
    expect(ids).toEqual(
      expect.arrayContaining([aliceMessage.event_id, bobMessage.event_id]),
    );
    for (const id of [aliceMessage.event_id, bobMessage.event_id]) {
      expect(eventPayload(eventById(events, id))).toMatchObject({
        flow_id: flowId,
        track_name: "discussion",
      });
    }
  });

  test("promotion creates Circle, private Flow, and confidential_discussion_of relation", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "promote");
    const publicFlowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "promoted public F1",
    );
    const promoted = await promoteDiscussionToPrivateFlowViaApi(
      request,
      fixture,
      publicFlowId,
      { members: [fixture.alice, fixture.bob] },
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    expect(events.map((event) => event.event_kind)).toEqual(
      expect.arrayContaining([
        "ck.circle.create",
        "ck.flow.create",
        "ck.relation.create",
      ]),
    );
    expect(
      events.some(
        (event) =>
          event.event_kind === "ck.flow.update" &&
          JSON.stringify(eventPayload(event)).includes("scope_circle_id"),
      ),
    ).toBe(false);
    expect(eventPayload(findFlowCreate(events, promoted.privateFlowId))).toMatchObject({
      object: {
        id: promoted.privateFlowId,
        realm_id: fixture.realmId,
        scope_circle_id: promoted.circleId,
      },
    });
    expect(eventPayload(findRelationCreate(events, promoted.relationId))).toMatchObject({
      relation_id: promoted.relationId,
      relation_kind: "confidential_discussion_of",
      from_ref: promoted.privateFlowId,
      to_ref: publicFlowId,
      scope_circle_id: promoted.circleId,
    });
  });

  test("private discussion Flow can be MLS-backed while the Realm-default Flow stays plaintext", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "circle-e2ee");
    const publicFlowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "e2ee public F1",
    );
    const promoted = await promoteDiscussionToPrivateFlowViaApi(
      request,
      fixture,
      publicFlowId,
      {
        members: [fixture.alice, fixture.bob],
        circleEncryptionProfile: "mls_rfc9420",
      },
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    const realmCreate = events.find((event) => event.event_kind === "ck.realm.create");
    const circleCreate = findCircleCreate(events, promoted.circleId);
    expect(eventPayload(realmCreate)).toMatchObject({
      object: { encryption_profile: "none" },
    });
    expect(eventPayload(circleCreate)).toMatchObject({
      object: { encryption_profile: "mls_rfc9420" },
    });
  });

  test("unknown scope_circle_id on Flow create is rejected", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "orphan-scope");
    const orphanCircleId = typedId("circle");
    const response = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(fixture.aliceToken),
      data: signedEventEnvelope({
        actorDid: fixture.alice.did,
        realmId: fixture.realmId,
        kind: "ck.flow.create",
        payload: {
          object: flowObject(
            fixture.realmId,
            typedId("flow"),
            fixture.alice,
            "orphan scoped Flow",
            { scopeCircleId: orphanCircleId },
          ),
        },
      }),
    });
    const body = await response.text();
    expect(response.status(), body).not.toBe(200);
    expect(body).toMatch(/circle_unknown|circle_not_found|circle_realm_mismatch/);
  });

  test("scope_circle_id rebind on an existing Flow is rejected", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "rebind-scope");
    const flowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "rebind F1",
    );
    const circleId = await createDiscussionCircleViaApi(request, fixture, {
      members: [fixture.alice],
    });

    const response = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(fixture.aliceToken),
      data: signedEventEnvelope({
        actorDid: fixture.alice.did,
        realmId: fixture.realmId,
        kind: "ck.flow.update",
        payload: {
          target_ref: flowId,
          flow_id: flowId,
          patch: { scope_circle_id: { $op: "set", value: circleId } },
        },
      }),
    });
    const body = await response.text();
    expect(response.status(), body).not.toBe(200);
    expect(body).toContain("scope_rebind_forbidden");
  });
});

type DiscussionFixture = {
  alice: JointUser;
  bob: JointUser;
  aliceToken: string;
  bobToken: string;
  realmId: string;
};

async function createDiscussionFixture(
  request: APIRequestContext,
  label: string,
): Promise<DiscussionFixture> {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice`);
  const bob = uniqueUser(`${label}-bob`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
  ]);
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
      title: `${label} realm ${stamp}`,
      historyVisibility: "shared",
    },
  );
  await joinRealmMemberViaApi(request, aliceToken, alice, realmId, alice.did);
  return { alice, bob, aliceToken, bobToken, realmId };
}

async function createFlowViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  title: string,
  opts: { scopeCircleId?: string } = {},
) {
  const flowId = typedId("flow");
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ck.flow.create",
      payload: {
        object: flowObject(realmId, flowId, actor, title, opts),
      },
    }),
    { context: `create flow ${title}` },
  );
  return flowId;
}

function flowObject(
  realmId: string,
  flowId: string,
  actor: JointUser,
  title: string,
  opts: { scopeCircleId?: string } = {},
) {
  return {
    id: flowId,
    schema: "ck.schema.flow.v1",
    realm_id: realmId,
    title: `${title} ${Date.now()}`,
    stage: "draft",
    stage_changed_at: new Date().toISOString(),
    tracks: {
      discussion: {
        is_primary: true,
        profile: "discussion",
      },
    },
    ...(opts.scopeCircleId ? { scope_circle_id: opts.scopeCircleId } : {}),
    created_by: actor.did,
    created_at: new Date().toISOString(),
    fields: {},
  };
}

async function promoteDiscussionToPrivateFlowViaApi(
  request: APIRequestContext,
  fixture: DiscussionFixture,
  publicFlowId: string,
  opts: {
    members: JointUser[];
    circleEncryptionProfile?: "none" | "mls_rfc9420";
  },
) {
  const circleId = await createDiscussionCircleViaApi(request, fixture, opts);
  const privateFlowId = await createFlowViaApi(
    request,
    fixture.aliceToken,
    fixture.alice,
    fixture.realmId,
    "private discussion",
    { scopeCircleId: circleId },
  );
  const relationId = await createConfidentialDiscussionRelationViaApi(
    request,
    fixture.aliceToken,
    fixture.alice,
    fixture.realmId,
    privateFlowId,
    publicFlowId,
    circleId,
  );
  return { circleId, privateFlowId, relationId };
}

async function createDiscussionCircleViaApi(
  request: APIRequestContext,
  fixture: DiscussionFixture,
  opts: {
    members: JointUser[];
    circleEncryptionProfile?: "none" | "mls_rfc9420";
  },
) {
  const circleId = typedId("circle");
  await submitSignedEventApi(
    request,
    fixture.aliceToken,
    signedEventEnvelope({
      actorDid: fixture.alice.did,
      realmId: fixture.realmId,
      kind: "ck.circle.create",
      payload: {
        object: {
          id: circleId,
          schema: "ck.schema.circle.v1",
          realm_id: fixture.realmId,
          title: `private discussion ${Date.now()}`,
          display: {
            short_name: "DISC",
            color_token: "indigo",
            symbol: { kind: "glyph", glyph: "lock" },
          },
          directory_visibility: "members",
          join_rule: "invite",
          history_visibility: "joined",
          encryption_profile: opts.circleEncryptionProfile ?? "none",
          state: "active",
          created_by: fixture.alice.did,
          created_at: new Date().toISOString(),
        },
      },
    }),
    { context: `create circle ${circleId}` },
  );
  for (const member of opts.members) {
    await joinRealmMemberViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      member.did,
    );
    await submitCircleMemberStateViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      circleId,
      member.did,
      "active",
    );
  }
  return circleId;
}

async function joinRealmMemberViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  memberDid: string,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ck.member.state",
      payload: {
        actor_id: memberDid,
        member: memberDid,
        membership: "join",
        delivery_status: "unroutable",
      },
    }),
    { context: `join ${memberDid}` },
  );
}

async function submitCircleMemberStateViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  circleId: string,
  memberDid: string,
  state: "active" | "removed" | "banned" | "left" | "invited",
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ck.circle.member.state",
      payload: {
        circle_id: circleId,
        actor: memberDid,
        actor_id: memberDid,
        state,
        sender: actor.did,
      },
    }),
    { context: `circle ${circleId} member ${memberDid} -> ${state}` },
  );
}

async function createConfidentialDiscussionRelationViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  privateFlowId: string,
  publicFlowId: string,
  circleId: string,
) {
  const relationId = typedId("relation");
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ck.relation.create",
      payload: {
        relation_id: relationId,
        relation_kind: "confidential_discussion_of",
        from_ref: privateFlowId,
        to_ref: publicFlowId,
        scope_circle_id: circleId,
        fields: { role: "promoted_discussion" },
      },
    }),
    { context: `link private discussion ${privateFlowId}` },
  );
  return relationId;
}

async function createDiscussionMessageViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  flowId: string,
  body: string,
) {
  const envelope = signedEventEnvelope({
    actorDid: actor.did,
    realmId,
    kind: "ck.message.create",
    payload: {
      flow_id: flowId,
      track_name: "discussion",
      thread_id: "discussion",
      content: { kind: "ck.content.text", body: `${body} ${Date.now()}` },
      encrypted: false,
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    context: `discussion message ${body}`,
  });
  return { event_id: String(envelope.event_id) };
}

function eventById(
  events: Array<Record<string, unknown>>,
  eventId: string,
): Record<string, unknown> {
  const event = events.find((candidate) => candidate.event_id === eventId);
  expect(event, `event ${eventId}`).toBeTruthy();
  return event!;
}

function findCircleCreate(
  events: Array<Record<string, unknown>>,
  circleId: string,
): Record<string, unknown> {
  return findEventByPayload(events, "ck.circle.create", circleId);
}

function findFlowCreate(
  events: Array<Record<string, unknown>>,
  flowId: string,
): Record<string, unknown> {
  return findEventByPayload(events, "ck.flow.create", flowId);
}

function findRelationCreate(
  events: Array<Record<string, unknown>>,
  relationId: string,
): Record<string, unknown> {
  return findEventByPayload(events, "ck.relation.create", relationId);
}

function findEventByPayload(
  events: Array<Record<string, unknown>>,
  kind: string,
  needle: string,
): Record<string, unknown> {
  const event = events.find(
    (candidate) =>
      candidate.event_kind === kind &&
      JSON.stringify(eventPayload(candidate)).includes(needle),
  );
  expect(event, `${kind} carrying ${needle}`).toBeTruthy();
  return event!;
}

function eventPayload(event: Record<string, unknown> | undefined): Record<string, unknown> {
  const payload = event?.payload;
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    return payload as Record<string, unknown>;
  }
  return (event ?? {}) as Record<string, unknown>;
}

// Discussion track upgrade to a Circle-scoped private Strand (AKP-0007).
// Contract: e2e/scenarios/messaging/discussion-upgrade.md
// Spec refs:
//   - models/strand-and-message.md §5, §5.1 (scope_circle_id on Strand)
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
import { createTwoUserMessagingRealm } from "../../helpers/messaging-fixtures";
import {
  canonicalTimestamp,
  resolveDefaultStrandId,
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
import { grantCircleMemberManageCapability } from "../../helpers/circle-api";
import { withBroadcastEphemeralProof } from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

test.describe("discussion upgrade to Circle-scoped private Strand", () => {
  test("API inline discussion track preserves strand_id and track_name", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "inline-track");
    const defaultStrandId = await resolveDefaultStrandId(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const body = `inline discussion ${Date.now()}`;
    await submitSignedEventApi(
      request,
      fixture.aliceToken,
      signedEventEnvelope({
        actorDid: fixture.alice.did,
        realmId: fixture.realmId,
        kind: "ak.message.create",
        payload: {
          strand_id: defaultStrandId,
          track_name: "discussion",
          content: { kind: "ak.content.text", body },
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
      strand_id: defaultStrandId,
      track_name: "discussion",
    });
  });

  test("private discussion Strand stays on the same Realm frontier and carries Circle scope", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "same-realm");
    const publicStrandId = await createStrandViaApi(
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
      publicStrandId,
      "public discussion",
    );
    const promoted = await promoteDiscussionToPrivateStrandViaApi(
      request,
      fixture,
      publicStrandId,
      { members: [fixture.alice, fixture.bob] },
    );
    const after = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      promoted.privateStrandId,
      "private discussion",
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    const ids = events.map((event) => event.event_id);
    expect(ids).toEqual(
      expect.arrayContaining([before.event_id, after.event_id]),
    );
    expect(JSON.stringify(eventById(events, after.event_id))).toContain(
      promoted.circleId,
    );
    expect(eventPayload(eventById(events, after.event_id))).toMatchObject({
      strand_id: promoted.privateStrandId,
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
    const publicStrandId = await createStrandViaApi(
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
      publicStrandId,
      "realm-visible message",
    );
    const promoted = await promoteDiscussionToPrivateStrandViaApi(
      request,
      {
        alice,
        bob: carol,
        aliceToken,
        bobToken: carolToken,
        realmId,
      },
      publicStrandId,
      { members: [alice] },
    );
    const privateMessage = await createDiscussionMessageViaApi(
      request,
      aliceToken,
      alice,
      realmId,
      promoted.privateStrandId,
      "circle-private message",
    );

    const carolEvents = await listRealmEventsViaApi(
      request,
      carolToken,
      realmId,
    );
    const carolIds = carolEvents.map((event) => event.event_id);
    expect(carolIds).toContain(publicMessage.event_id);
    expect(carolIds).not.toContain(privateMessage.event_id);
  });

  test("Circle-scoped read receipt uses realm_id and remains scoped to the private Strand", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "circle-receipt");
    const publicStrandId = await createStrandViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "receipt public F1",
    );
    const promoted = await promoteDiscussionToPrivateStrandViaApi(
      request,
      fixture,
      publicStrandId,
      { members: [fixture.alice, fixture.bob] },
    );
    const privateMessage = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      promoted.privateStrandId,
      "private receipt target",
    );
    const sentAt = new Date();
    const sentAtIso = sentAt.toISOString();
    const receipt = await request.post(
      `${solandBaseUrl()}/_arkret/self/ephemeral`,
      {
        headers: authHeaders(fixture.bobToken),
        data: withBroadcastEphemeralProof({
          kind: "ak.receipt.read",
          realm_id: fixture.realmId,
          actor_id: fixture.bob.did,
          device_id: fixture.bob.deviceId,
          sent_at: sentAtIso,
          expires_at: new Date(sentAt.getTime() + 30_000).toISOString(),
          payload: {
            receipt_type: "read",
            schema: "ak.schema.read_receipt.v1",
            realm_id: fixture.realmId,
            actor_id: fixture.bob.did,
            read_scope: {
              kind: "strand",
              object_ref: promoted.privateStrandId,
              track_name: "discussion",
            },
            event_id: privateMessage.event_id,
            created_at: sentAtIso,
          },
        }),
      },
    );
    expect(receipt.status()).toBe(200);
    expect(
      await listReadMarkersViaApi(request, fixture.aliceToken, fixture.realmId),
    ).toHaveLength(0);
  });

  test("alice and bob exchange messages on a Realm-default Strand's inline discussion track", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "inline-strand");
    const strandId = await createStrandViaApi(
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
      strandId,
      "F1 alice inline",
    );
    const bobMessage = await createDiscussionMessageViaApi(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.realmId,
      strandId,
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
        strand_id: strandId,
        track_name: "discussion",
      });
    }
  });

  test("promotion creates Circle, private Strand, and confidential_discussion_of relation", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "promote");
    const publicStrandId = await createStrandViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "promoted public F1",
    );
    const promoted = await promoteDiscussionToPrivateStrandViaApi(
      request,
      fixture,
      publicStrandId,
      { members: [fixture.alice, fixture.bob] },
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    expect(events.map((event) => event.kind)).toEqual(
      expect.arrayContaining([
        "ak.circle.create",
        "ak.strand.create",
        "ak.relation.create",
      ]),
    );
    expect(
      events.some(
        (event) =>
          event.kind === "ak.strand.update" &&
          JSON.stringify(eventPayload(event)).includes("scope_circle_id"),
      ),
    ).toBe(false);
    expect(
      eventPayload(findStrandCreate(events, promoted.privateStrandId)),
    ).toMatchObject({
      object: {
        id: promoted.privateStrandId,
        realm_id: fixture.realmId,
        scope_circle_id: promoted.circleId,
      },
    });
    expect(
      eventPayload(findRelationCreate(events, promoted.relationId)),
    ).toMatchObject({
      relation: {
        id: promoted.relationId,
        kind: "confidential_discussion_of",
        from_ref: promoted.privateStrandId,
        to_ref: publicStrandId,
        scope_circle_id: promoted.circleId,
      },
    });
  });

  test("private discussion Strand can be MLS-backed while the Realm-default Strand stays plaintext", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "circle-e2ee");
    const publicStrandId = await createStrandViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "e2ee public F1",
    );
    const promoted = await promoteDiscussionToPrivateStrandViaApi(
      request,
      fixture,
      publicStrandId,
      {
        members: [fixture.alice, fixture.bob],
        circleEncryptionProfile: "mls_rfc9420",
      },
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const publicStrandCreate = findStrandCreate(events, publicStrandId);
    const circleCreate = findCircleCreate(events, promoted.circleId);
    expect(eventPayload(publicStrandCreate)).toMatchObject({
      object: {
        id: publicStrandId,
        realm_id: fixture.realmId,
      },
    });
    expect(JSON.stringify(eventPayload(publicStrandCreate))).not.toContain(
      "scope_circle_id",
    );
    expect(eventPayload(circleCreate)).toMatchObject({
      object: { encryption_profile: "mls_rfc9420" },
    });
  });

  test("unknown scope_circle_id on Strand create is rejected", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "orphan-scope");
    const orphanCircleId = typedId("circle");
    const createdAt = canonicalTimestamp();
    const response = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(fixture.aliceToken),
        data: signedEventEnvelope({
          actorDid: fixture.alice.did,
          realmId: fixture.realmId,
          kind: "ak.strand.create",
          createdAt,
          payload: {
            object: strandObject(
              fixture.realmId,
              typedId("strand"),
              fixture.alice,
              "orphan scoped Strand",
              createdAt,
              { scopeCircleId: orphanCircleId },
            ),
          },
        }),
      },
    );
    const body = await response.text();
    expect(response.status(), body).not.toBe(200);
    expect(body).toMatch(
      /circle_unknown|circle_not_found|circle_realm_mismatch/,
    );
  });

  test("scope_circle_id rebind on an existing Strand is rejected", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "rebind-scope");
    const strandId = await createStrandViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      "rebind F1",
    );
    const circleId = await createDiscussionCircleViaApi(request, fixture, {
      members: [fixture.alice],
    });

    const response = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(fixture.aliceToken),
        data: signedEventEnvelope({
          actorDid: fixture.alice.did,
          realmId: fixture.realmId,
          kind: "ak.strand.update",
          payload: {
            target_ref: strandId,
            patch: { scope_circle_id: { $op: "set", value: circleId } },
          },
        }),
      },
    );
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
  const fixture = await createTwoUserMessagingRealm(request, {
    label,
    title: `${label} realm ${stamp}`,
    realm: {
      historyVisibility: "shared",
    },
  });
  await joinRealmMemberViaApi(
    request,
    fixture.aliceToken,
    fixture.alice,
    fixture.realmId,
    fixture.alice.did,
  );
  return fixture;
}

async function createStrandViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  title: string,
  opts: { scopeCircleId?: string } = {},
) {
  const strandId = typedId("strand");
  const createdAt = canonicalTimestamp();
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ak.strand.create",
      createdAt,
      payload: {
        object: strandObject(realmId, strandId, actor, title, createdAt, opts),
      },
    }),
    { context: `create strand ${title}` },
  );
  return strandId;
}

function strandObject(
  realmId: string,
  strandId: string,
  actor: JointUser,
  title: string,
  createdAt: string,
  opts: { scopeCircleId?: string } = {},
) {
  return {
    id: strandId,
    schema: "ak.schema.strand.v1",
    realm_id: realmId,
    metadata: {
      title: `${title} ${Date.now()}`,
      fields: {},
    },
    tracks: {
      discussion: {
        enabled: true,
        is_primary: true,
        profile: "discussion",
      },
    },
    ...(opts.scopeCircleId ? { scope_circle_id: opts.scopeCircleId } : {}),
    created_by: actor.did,
    created_at: createdAt,
  };
}

async function promoteDiscussionToPrivateStrandViaApi(
  request: APIRequestContext,
  fixture: DiscussionFixture,
  publicStrandId: string,
  opts: {
    members: JointUser[];
    circleEncryptionProfile?: "none" | "mls_rfc9420";
  },
) {
  const circleId = await createDiscussionCircleViaApi(request, fixture, opts);
  const privateStrandId = await createStrandViaApi(
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
    privateStrandId,
    publicStrandId,
    circleId,
  );
  return { circleId, privateStrandId, relationId };
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
  const createdAt = canonicalTimestamp();
  await submitSignedEventApi(
    request,
    fixture.aliceToken,
    signedEventEnvelope({
      actorDid: fixture.alice.did,
      realmId: fixture.realmId,
      kind: "ak.circle.create",
      createdAt,
      payload: {
        object: {
          id: circleId,
          schema: "ak.schema.circle.v1",
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
          created_at: createdAt,
        },
      },
    }),
    { context: `create circle ${circleId}` },
  );
  await grantCircleMemberManageCapability(request, fixture.aliceToken, {
    ownerDid: fixture.alice.did,
    realmId: fixture.realmId,
    subjectDid: fixture.alice.did,
    circleId,
  });
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
      "join",
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
      kind: "ak.member.state",
      payload: {
        realm_id: realmId,
        actor_id: memberDid,
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
  membership: "join" | "invite" | "knock" | "leave" | "ban",
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ak.circle.member.state",
      payload: {
        circle_id: circleId,
        actor_id: memberDid,
        membership,
        actor_capability: {
          action: "ak.circle.member.manage",
          circle_id: circleId,
          allowed: true,
        },
      },
    }),
    { context: `circle ${circleId} member ${memberDid} -> ${membership}` },
  );
}

async function createConfidentialDiscussionRelationViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  privateStrandId: string,
  publicStrandId: string,
  circleId: string,
) {
  const relationId = typedId("relation");
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ak.relation.create",
      payload: {
        relation: {
          id: relationId,
          kind: "confidential_discussion_of",
          from_ref: privateStrandId,
          to_ref: publicStrandId,
          scope_circle_id: circleId,
          fields: { role: "promoted_discussion" },
        },
      },
    }),
    { context: `link private discussion ${privateStrandId}` },
  );
  return relationId;
}

async function createDiscussionMessageViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  strandId: string,
  body: string,
) {
  const envelope = signedEventEnvelope({
    actorDid: actor.did,
    realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      content: { kind: "ak.content.text", body: `${body} ${Date.now()}` },
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
  return findEventByPayload(events, "ak.circle.create", circleId);
}

function findStrandCreate(
  events: Array<Record<string, unknown>>,
  strandId: string,
): Record<string, unknown> {
  return findEventByPayload(events, "ak.strand.create", strandId);
}

function findRelationCreate(
  events: Array<Record<string, unknown>>,
  relationId: string,
): Record<string, unknown> {
  return findEventByPayload(events, "ak.relation.create", relationId);
}

function findEventByPayload(
  events: Array<Record<string, unknown>>,
  kind: string,
  needle: string,
): Record<string, unknown> {
  const event = events.find(
    (candidate) =>
      candidate.kind === kind &&
      JSON.stringify(eventPayload(candidate)).includes(needle),
  );
  expect(event, `${kind} carrying ${needle}`).toBeTruthy();
  return event!;
}

function eventPayload(
  event: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const payload = event?.payload;
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    return payload as Record<string, unknown>;
  }
  return (event ?? {}) as Record<string, unknown>;
}

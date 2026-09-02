// Discussion track upgrade to a Circle-scoped private Strand (AKP-0007).
// Contract: e2e/scenarios/messaging/discussion-upgrade.md
// Spec refs:
//   - models/strand-and-message.md §5, §5.1 (scope_circle_id on Strand)
//   - models/circle.md (Circle primitive, membership and encryption boundary)
//   - models/relation.md (confidential_discussion_of)
//   - discovery/read-receipts.md §2.5 (scope override)

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import {
  authHeaders,
  createSharedRealmViaApi,
  listReadMarkersViaApi,
  listRealmEventsViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import { createTwoUserMessagingRealm } from "../../helpers/messaging-fixtures";
import {
  accountActorId,
  alignSignedEventToActorFrontierApi,
  canonicalJson,
  canonicalTimestamp,
  prepareSignedEventCbaApi,
  rawSubmitSignedEventApi,
  retypeEventDerivedId,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  waitForRealmControlIdleApi,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  type JointUser,
  uniqueUser,
} from "../../helpers/users";
import { grantCircleMemberManageCapability } from "../../helpers/circle-api";
import {
  buildSignalEnvelope,
  captureSubmittedSignalEnvelope,
  prepareSignalEnvelope,
  signalPlaintext,
} from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

const circleScopeByStrand = new Map<
  string,
  { circleId: string; encryptionProfile: "none" | "mls_rfc9420" }
>();

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
        actorId: fixture.alice.id,
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
      { title: `circle visibility ${stamp}`, historyAccess: "all_history_for_current_members" },
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
    const fixture = await createDiscussionFixture(request, "circle-receipt", {
      signalMls: true,
    });
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
      {
        members: [fixture.alice, fixture.bob],
        circleEncryptionProfile: "mls_rfc9420",
      },
    );
    const privateMessage = await createDiscussionMessageViaApi(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.realmId,
      promoted.privateStrandId,
      "private encrypted receipt target",
    );
    const sentAt = new Date();
    const sentAtIso = sentAt.toISOString();
    const envelope = buildSignalEnvelope({
      actorId: fixture.bob.id,
      deviceId: fixture.bob.deviceId,
      realmId: fixture.realmId,
      scopeRef: {
        kind: "circle",
        realm_id: fixture.realmId,
        circle_id: promoted.circleId,
      },
      sentAt,
      plaintext: {
        kind: "ak.receipt.read",
        payload_sequence: Date.now(),
        receipt_kind: "read",
        schema: "ak.schema.read_receipt.v1",
        realm_id: fixture.realmId,
        actor_id: accountActorId(fixture.bob.id),
        read_scope: {
          kind: "strand",
          object_ref: promoted.privateStrandId,
          track_name: "discussion",
        },
        event_id: privateMessage.event_id,
        created_at: sentAtIso,
      },
    });
    const { result: receipt, envelopes } = await captureSubmittedSignalEnvelope(
      request,
      fixture.bobToken,
      fixture.aliceToken,
      fixture.realmId,
      envelope,
    );
    expect(receipt.status(), await receipt.text()).toBe(200);

    const received = envelopes.find((candidate) => {
      const plaintext = signalPlaintext(candidate);
      return (
        canonicalJson(candidate.sender_actor_id) === canonicalJson(accountActorId(fixture.bob.id)) &&
        plaintext.kind === "ak.receipt.read"
      );
    });
    expect(received, "alice received Circle-scoped encrypted receipt").toBeTruthy();
    if (!received) throw new Error("Circle receipt Signal missing");
    expect(received).not.toHaveProperty("kind");
    expect(received).not.toHaveProperty("read_scope");
    expect(received.scope_ref).toEqual({
      kind: "circle",
      realm_id: fixture.realmId,
      circle_id: promoted.circleId,
    });
    expect(signalPlaintext(received)).toMatchObject({
      kind: "ak.receipt.read",
      actor_id: accountActorId(fixture.bob.id),
      read_scope: {
        kind: "strand",
        object_ref: promoted.privateStrandId,
        track_name: "discussion",
      },
      event_id: privateMessage.event_id,
    });
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
        realm_id: fixture.realmId,
        scope_circle_id: promoted.circleId,
      },
    });
    expect(
      eventPayload(findRelationCreate(events, promoted.relationId)),
    ).toMatchObject({
      relation: {
        relation_kind: "confidential_discussion_of",
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
    const envelope = signedEventEnvelope({
      actorId: fixture.alice.id,
      realmId: fixture.realmId,
      kind: "ak.strand.create",
      createdAt,
      payload: {
        object: strandObject(
          fixture.realmId,
          fixture.alice,
          "orphan scoped Strand",
          createdAt,
          { scopeCircleId: orphanCircleId },
        ),
      },
    });
    const response = await rawSubmitSignedEventApi(
      request,
      fixture.aliceToken,
      envelope,
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

    const envelope = signedEventEnvelope({
      actorId: fixture.alice.id,
      realmId: fixture.realmId,
      kind: "ak.strand.update",
      payload: {
        target_ref: strandId,
        patch: { scope_circle_id: { $op: "set", value: circleId } },
      },
    });
    await alignSignedEventToActorFrontierApi(
      request,
      fixture.aliceToken,
      envelope,
    );
    await prepareSignedEventCbaApi(
      request,
      fixture.aliceToken,
      envelope,
    );
    const response = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: {
          ...authHeaders(fixture.aliceToken),
          "content-type": "application/json",
        },
        data: canonicalJson(envelope),
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
  opts: { signalMls?: boolean } = {},
): Promise<DiscussionFixture> {
  const stamp = Date.now();
  const fixture = await createTwoUserMessagingRealm(request, {
    label,
    title: `${label} realm ${stamp}`,
    realm: {
      historyAccess: opts.signalMls
        ? "since_join"
        : "all_history_for_current_members",
      ...(opts.signalMls
        ? { encryptionProfile: "mls_rfc9420" as const }
        : {}),
    },
  });
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
  const createdAt = canonicalTimestamp();
  const envelope = signedEventEnvelope({
    actorId: actor.id,
    realmId,
    kind: "ak.strand.create",
    scopeRef: opts.scopeCircleId
      ? {
          kind: "circle",
          realm_id: realmId,
          circle_id: opts.scopeCircleId,
        }
      : undefined,
    createdAt,
    payload: {
      object: strandObject(realmId, actor, title, createdAt, opts),
    },
  });
  await submitSignedEventApi(
    request,
    token,
    envelope,
    { context: `create strand ${title}` },
  );
  return retypeEventDerivedId(String(envelope.event_id), "strand");
}

function strandObject(
  realmId: string,
  actor: JointUser,
  title: string,
  createdAt: string,
  opts: { scopeCircleId?: string } = {},
) {
  return {
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
    created_by: accountActorId(actor.id),
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
  circleScopeByStrand.set(privateStrandId, {
    circleId,
    encryptionProfile: opts.circleEncryptionProfile ?? "none",
  });
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
  const createdAt = canonicalTimestamp();
  const envelope = signedEventEnvelope({
    actorId: fixture.alice.id,
    realmId: fixture.realmId,
    kind: "ak.circle.create",
    createdAt,
    payload: {
      object: {
        schema: "ak.schema.circle.v1",
        realm_id: fixture.realmId,
        title: `private discussion ${Date.now()}`,
        display: {
          short_name: "DISC",
          color_token: "indigo",
          symbol: { glyph: "lock" },
        },
        directory_visibility: "members",
        join_rule: "invite",
        history_access: "since_join",
        encryption_profile: opts.circleEncryptionProfile ?? "none",
        ...(opts.circleEncryptionProfile === "mls_rfc9420"
          ? { content_scheme: "mls_rfc9420" }
          : {}),
        state: "active",
        created_by: accountActorId(fixture.alice.id),
        created_at: createdAt,
      },
    },
  });
  await submitSignedEventApi(
    request,
    fixture.aliceToken,
    envelope,
    { context: "create discussion circle" },
  );
  const circleId = retypeEventDerivedId(String(envelope.event_id), "circle");
  await grantCircleMemberManageCapability(request, fixture.aliceToken, {
    ownerId: fixture.alice.id,
    realmId: fixture.realmId,
    subjectId: fixture.alice.id,
    circleId,
  });
  for (const member of opts.members) {
    await submitCircleMemberStateViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.realmId,
      circleId,
      member.id,
      "join",
    );
  }
  await waitForRealmControlIdleApi(
    request,
    fixture.aliceToken,
    fixture.realmId,
  );
  return circleId;
}

async function submitCircleMemberStateViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  circleId: string,
  memberId: string,
  membership: "join" | "invite" | "knock" | "leave" | "ban",
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId: actor.id,
      realmId,
      kind: "ak.circle.member.state",
      payload: {
        circle_id: circleId,
        member_id: accountActorId(memberId),
        membership,
      },
    }),
    { context: `circle ${circleId} member ${memberId} -> ${membership}` },
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
  const createdAt = canonicalTimestamp();
  const envelope = signedEventEnvelope({
    actorId: actor.id,
    realmId,
    kind: "ak.relation.create",
    createdAt,
    payload: {
      relation: {
        schema: "ak.schema.relation.v1",
        realm_id: realmId,
        relation_kind: "confidential_discussion_of",
        from_ref: privateStrandId,
        to_ref: publicStrandId,
        scope_circle_id: circleId,
        fields: { role: "promoted_discussion" },
        state: "active",
        created_by: accountActorId(actor.id),
        created_at: createdAt,
      },
    },
  });
  await submitSignedEventApi(
    request,
    token,
    envelope,
    { context: `link private discussion ${privateStrandId}` },
  );
  return retypeEventDerivedId(String(envelope.event_id), "relation");
}

async function createDiscussionMessageViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  strandId: string,
  body: string,
) {
  const circleScope = circleScopeByStrand.get(strandId);
  const circleId = circleScope?.circleId;
  const scopeRef = circleId
    ? {
        kind: "circle",
        realm_id: realmId,
        circle_id: circleId,
      }
    : undefined;
  let messageContent: Record<string, unknown>;
  if (circleScope?.encryptionProfile === "mls_rfc9420") {
    const basisProbe = buildSignalEnvelope({
      actorId: actor.id,
      deviceId: actor.deviceId,
      realmId,
      scopeRef,
      plaintext: {
        kind: "ak.typing",
        payload_sequence: Date.now(),
        strand_id: strandId,
        is_typing: false,
      },
    });
    await prepareSignalEnvelope(request, token, basisProbe);
    const preparedPayload = basisProbe.encrypted_payload as Record<
      string,
      unknown
    >;
    const preparedKeyRef = preparedPayload.key_ref as Record<string, unknown>;
    messageContent = {
      encrypted_content: {
        version: "1.0",
        content_type: "application/vnd.arkret.message+json",
        encryption_context: {
          epoch: Number(preparedPayload.epoch),
          group_state_ref: String(preparedKeyRef.group_state_ref),
        },
        ciphertext: Buffer.from(`${body} ${Date.now()}`, "utf8").toString(
          "base64url",
        ),
      },
    };
  } else {
    messageContent = {
      content: { kind: "ak.content.text", body: `${body} ${Date.now()}` },
    };
  }
  const envelope = signedEventEnvelope({
    actorId: actor.id,
    realmId,
    kind: "ak.message.create",
    scopeRef,
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      ...messageContent,
    },
  });
  await alignSignedEventToActorFrontierApi(request, token, envelope);
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
  return findEventByDerivedId(events, "ak.circle.create", "circle", circleId);
}

function findStrandCreate(
  events: Array<Record<string, unknown>>,
  strandId: string,
): Record<string, unknown> {
  return findEventByDerivedId(events, "ak.strand.create", "strand", strandId);
}

function findRelationCreate(
  events: Array<Record<string, unknown>>,
  relationId: string,
): Record<string, unknown> {
  return findEventByDerivedId(
    events,
    "ak.relation.create",
    "relation",
    relationId,
  );
}

function findEventByDerivedId(
  events: Array<Record<string, unknown>>,
  kind: string,
  objectKind: string,
  objectId: string,
): Record<string, unknown> {
  const event = events.find(
    (candidate) =>
      candidate.kind === kind &&
      typeof candidate.event_id === "string" &&
      retypeEventDerivedId(candidate.event_id, objectKind) === objectId,
  );
  expect(event, `${kind} deriving ${objectId}`).toBeTruthy();
  return event!;
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

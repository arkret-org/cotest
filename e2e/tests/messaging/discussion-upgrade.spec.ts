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
  canonicalJson,
  canonicalTimestamp,
  rawSubmitSignedEventApi,
  retypeEventDerivedId,
  resolveDefaultStrandId,
  scanRealmStreamApi,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import { relationCreatePayload } from "../../helpers/relation-api";
import {
  ensureRegistered,
  issueUserSession,
  type JointUser,
  uniqueUser,
} from "../../helpers/users";
import {
  addCircleMemberArkret,
  grantCircleMemberAddCapability,
} from "../../helpers/circle-api";
import {
  activateRealmMlsApi,
  addRealmMlsMemberApi,
  encryptMlsMessageContent,
  joinRealmMlsWelcomeApi,
  realmMlsCreatorGroupApi,
  readScopeMlsGroupCurrentApi,
  type MlsMemberGroup,
} from "../../helpers/soland-api/mls";
import {
  buildSignalEnvelope,
  captureSubmittedSignalEnvelope,
  signalPlaintext,
} from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

const circleScopeByStrand = new Map<
  string,
  { circleId: string; encryptionProfile: "none" | "mls_rfc9420" }
>();
const circleMlsMembers = new Map<string, Map<string, MlsMemberGroup>>();

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

    // Both streams belong to the same Realm; a Circle owns its own linear
    // commit stream (realm-commit.schema.json stream_ref `circle`), so the
    // private Message is read from that stream, not from the Realm stream.
    const realmEvents = await listRealmEventsViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    expect(realmEvents.map((event) => event.event_id)).toContain(before.event_id);
    expect(realmEvents.map((event) => event.event_id)).not.toContain(after.event_id);
    const circleScan = await scanRealmStreamApi(
      request,
      fixture.bobToken,
      fixture.realmId,
      {
        streamRef: {
          kind: "circle",
          realm_id: fixture.realmId,
          circle_id: promoted.circleId,
        },
      },
    );
    const events = circleScan.events.filter(
      (event): event is Record<string, unknown> => event !== undefined,
    );
    expect(events.map((event) => event.event_id)).toContain(after.event_id);
    expect(eventById(events, after.event_id).scope_ref).toEqual({
      kind: "circle",
      realm_id: fixture.realmId,
      circle_id: promoted.circleId,
    });
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
      issueUserSession(request, alice),
      issueUserSession(request, carol),
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
    expect((eventPayload(circleCreate).object as Record<string, unknown>))
      .not.toHaveProperty("encryption_profile");
    const scope = { kind: "circle", realm_id: fixture.realmId, circle_id: promoted.circleId };
    const current = await readScopeMlsGroupCurrentApi(
      request, fixture.aliceToken, fixture.realmId, scope,
    );
    expect(current, "Circle encryption requires an accepted MLS Genesis and Add").toMatchObject({
      effective_scope: scope, epoch: 1,
    });
    expect(current!.covered_key_access_revision).toBe(current!.current_key_access_revision);
    expect(await readScopeMlsGroupCurrentApi(
      request, fixture.aliceToken, fixture.realmId,
    ), "the parent Realm has no accepted MLS group").toBeUndefined();
    const privateMessage = await createDiscussionMessageViaApi(
      request, fixture.bobToken, fixture.bob, fixture.realmId,
      promoted.privateStrandId, "actual Circle MLS ciphertext",
    );
    const publicMessage = await createDiscussionMessageViaApi(
      request, fixture.aliceToken, fixture.alice, fixture.realmId,
      publicStrandId, "parent Realm plaintext",
    );
    const written = await listRealmEventsViaApi(request, fixture.aliceToken, fixture.realmId);
    expect(eventPayload(eventById(written, privateMessage.event_id)))
      .toHaveProperty("encrypted_content");
    expect(eventPayload(eventById(written, privateMessage.event_id))).not.toHaveProperty("content");
    expect(eventPayload(eventById(written, publicMessage.event_id))).toHaveProperty("content");
    expect(eventPayload(eventById(written, publicMessage.event_id)))
      .not.toHaveProperty("encrypted_content");
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
    const response = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: {
          ...authHeaders(fixture.aliceToken, "POST", `${solandBaseUrl()}/_arkret/self/events`),
          "content-type": "application/json",
        },
        data: canonicalJson({ event: envelope }),
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
        // common-fields.md section 4.5: `leave -> join` is written only by the
        // target itself (or its exact invite acceptance); v1 registers no
        // Circle invite, so each member self-joins, which circle.md section 8
        // (`ak.circle.member.add`) admits for a `public` Circle. `public` only
        // opens self-entry to parent Realm members; `directory_visibility`
        // keeps the Circle hidden from non-members.
        join_rule: "public",
        history_access: "since_join",
        // circle.schema.json is closed: a Circle is created plaintext and
        // carries no encryption profile or content scheme; its scope becomes
        // end-to-end encrypted only through an accepted `ak.mls.genesis`.
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
  const scopeRef = { kind: "circle", realm_id: fixture.realmId, circle_id: circleId };
  const encrypted = opts.circleEncryptionProfile === "mls_rfc9420";
  const groups = new Map<string, MlsMemberGroup>();
  if (encrypted && opts.members[0]?.id !== fixture.alice.id) {
    throw new Error("MLS discussion Circle must join its creator before adding peers");
  }
  for (const member of opts.members) {
    const memberToken =
      member.id === fixture.alice.id
        ? fixture.aliceToken
        : member.id === fixture.bob.id
          ? fixture.bobToken
          : undefined;
    if (!memberToken) {
      throw new Error(`Circle member ${member.id} has no session in this fixture`);
    }
    if (member.id !== fixture.alice.id) {
      await grantCircleMemberAddCapability(request, fixture.aliceToken, {
        ownerId: fixture.alice.id,
        realmId: fixture.realmId,
        subjectId: member.id,
        circleId,
      });
    }
    await addCircleMemberArkret(request, memberToken, circleId, {
      signerId: member.id,
      realmId: fixture.realmId,
      actorId: member.id,
      membership: "join",
    });
    if (encrypted) {
      const device = { ...member, token: memberToken };
      if (member.id === fixture.alice.id) {
        await activateRealmMlsApi(request, device, fixture.realmId, { scopeRef });
      } else {
        await addRealmMlsMemberApi(request, fixture.realmId, device, { scopeRef });
        groups.set(member.id, await joinRealmMlsWelcomeApi(
          request, fixture.realmId, device, { scopeRef },
        ));
      }
    }
  }
  if (encrypted) {
    groups.set(fixture.alice.id, await realmMlsCreatorGroupApi(
      request, fixture.realmId, { scopeRef },
    ));
    circleMlsMembers.set(circleId, groups);
  }
  return circleId;
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
  // relation.md section 3.2: the fact is committed in the private Strand's
  // Circle scope so non-members cannot enumerate it from the public side.
  const envelope = signedEventEnvelope({
    actorId: actor.id,
    realmId,
    kind: "ak.relation.create",
    createdAt,
    scopeRef: { kind: "circle", realm_id: realmId, circle_id: circleId },
    payload: relationCreatePayload({
      relationKind: "confidential_discussion_of",
      fromRef: privateStrandId,
      toRef: publicStrandId,
      scopeCircleId: circleId,
      fields: { role: "promoted_discussion" },
    }),
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
    const group = circleMlsMembers.get(circleScope.circleId)?.get(actor.id);
    if (!group) throw new Error("encrypted discussion author has no joined Circle MLS state");
    messageContent = {
      encrypted_content: encryptMlsMessageContent(group, {
        kind: "ak.content.text", body: `${body} ${Date.now()}`,
      }),
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

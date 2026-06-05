// Discussion track upgrade to a Circle-scoped Flow (CKP-0007).
// Contract: e2e/scenarios/messaging/discussion-upgrade.md
// Spec refs:
//   - models/flow-and-message.md §5, §5.1 (scope_circle_id on Flow)
//   - models/circle.md (Circle primitive, encryption boundary)
//   - models/space-hierarchy.md §3-§4 (parent/child confirmed edge)
//   - discovery/read-receipts.md §2.5 (scope override)
// History: prior to CKP-0007 the same upgrade lived under Flow.discussion_realm_ref;
// that field is hard-removed and no longer accepted on the wire.

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  authHeaders,
  createSharedRealmViaApi,
  listReadMarkersViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import {
  flowIdFromRealmId,
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

test.describe("discussion upgrade to child space", () => {
  test("API inline discussion track preserves flow_id and thread_id", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "inline-track");
    const body = `inline discussion ${Date.now()}`;
    await submitSignedEventApi(
      request,
      fixture.aliceToken,
      signedEventEnvelope({
        actorDid: fixture.alice.did,
        realmId: fixture.parentId,
        kind: "ck.message.create",
        payload: {
          flow_id: flowIdFromRealmId(fixture.parentId),
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
      fixture.parentId,
    );
    const message = events.find((event) =>
      JSON.stringify(event.payload).includes(body),
    );
    expect(message?.payload).toMatchObject({
      flow_id: flowIdFromRealmId(fixture.parentId),
      track_name: "discussion",
      thread_id: "discussion",
    });
  });

  test("API parent and child discussion realms keep message routes separate", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "route-separate");
    const childId = await createSharedRealmViaApi(
      request,
      fixture.alice,
      fixture.aliceToken,
      fixture.bob,
      fixture.bobToken,
      { title: `child route ${Date.now()}`, historyVisibility: "shared" },
    );
    const parentMessage = await sendPlaintextMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.parentId,
      `parent route ${Date.now()}`,
      { actorDid: fixture.alice.did },
    );
    const childMessage = await sendPlaintextMessageViaApi(
      request,
      fixture.aliceToken,
      childId,
      `child route ${Date.now()}`,
      { actorDid: fixture.alice.did },
    );

    const parentEvents = await listRealmEventsViaApi(
      request,
      fixture.bobToken,
      fixture.parentId,
    );
    const childEvents = await listRealmEventsViaApi(
      request,
      fixture.bobToken,
      childId,
    );
    expect(parentEvents.map((event) => event.event_id)).toContain(
      parentMessage.event_id,
    );
    expect(parentEvents.map((event) => event.event_id)).not.toContain(
      childMessage.event_id,
    );
    expect(childEvents.map((event) => event.event_id)).toContain(
      childMessage.event_id,
    );
    expect(childEvents.map((event) => event.event_id)).not.toContain(
      parentMessage.event_id,
    );
  });

  test("API child-only member cannot read parent joined-history messages", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("child-only-alice");
    const carol = uniqueUser("child-only-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, carol),
    ]);
    const [aliceToken, carolToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, carol),
    ]);
    const parentId = await createSharedRealmViaApi(
      request,
      alice,
      aliceToken,
      alice,
      aliceToken,
      { title: `parent joined ${stamp}`, historyVisibility: "joined" },
    );
    const parentMessage = await sendPlaintextMessageViaApi(
      request,
      aliceToken,
      parentId,
      `parent hidden ${stamp}`,
      { actorDid: alice.did },
    );
    await createSharedRealmViaApi(
      request,
      alice,
      aliceToken,
      carol,
      carolToken,
      {
        title: `child only ${stamp}`,
        historyVisibility: "shared",
      },
    );

    const response = await request.get(
      `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(parentId)}&limit=50`,
      { headers: authHeaders(carolToken) },
    );
    if (response.status() === 404) {
      expect(response.status()).toBe(404);
      return;
    }
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(
      (body.events ?? []).map(
        (event: Record<string, unknown>) => event.event_id,
      ),
    ).not.toContain(parentMessage.event_id);
  });

  test("API child discussion receipt is scoped to the child realm", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "child-receipt");
    const childId = await createSharedRealmViaApi(
      request,
      fixture.alice,
      fixture.aliceToken,
      fixture.bob,
      fixture.bobToken,
      { title: `child receipt ${Date.now()}`, historyVisibility: "shared" },
    );
    const childMessage = await sendPlaintextMessageViaApi(
      request,
      fixture.aliceToken,
      childId,
      `child receipt ${Date.now()}`,
      { actorDid: fixture.alice.did },
    );
    const sentAt = new Date();
    const receipt = await request.post(`${solandBaseUrl()}/_cokret/self/ephemeral`, {
      headers: authHeaders(fixture.bobToken),
      data: {
        kind: "ck.receipt.read",
        realm_id: childId,
        actor_id: fixture.bob.did,
        device_id: fixture.bob.deviceId,
        sent_at: sentAt.toISOString(),
        expires_at: new Date(sentAt.getTime() + 30_000).toISOString(),
        payload: { event_id: childMessage.event_id },
      },
    });
    expect(receipt.status()).toBe(200);

    expect(
      await listReadMarkersViaApi(request, fixture.aliceToken, childId),
    ).toHaveLength(0);
    expect(
      await listReadMarkersViaApi(
        request,
        fixture.aliceToken,
        fixture.parentId,
      ),
    ).toHaveLength(0);
  });

  test("alice creates Flow F1 in S_parent; alice and bob exchange messages on F1's inline discussion track", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "fixme-inline-flow");
    const flowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.parentId,
      "inline F1",
    );
    const aliceMessage = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.parentId,
      flowId,
      "F1 alice inline",
    );
    const bobMessage = await createDiscussionMessageViaApi(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.parentId,
      flowId,
      "F1 bob inline",
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.aliceToken,
      fixture.parentId,
    );
    const ids = events.map((event) => event.event_id);
    expect(ids).toEqual(
      expect.arrayContaining([aliceMessage.event_id, bobMessage.event_id]),
    );
    for (const id of [aliceMessage.event_id, bobMessage.event_id]) {
      expect(
        events.find((event) => event.event_id === id)?.payload,
      ).toMatchObject({ flow_id: flowId, track_name: "discussion" });
    }
  });

  test("alice promotes F1 to a Circle scope; F1.scope_circle_id = C.id; ck.circle.create on parent Realm", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "fixme-promote");
    const circleId = typedId("circle");
    const flowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.parentId,
      "promoted F1",
    );
    await setFlowScopeCircleViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.parentId,
      flowId,
      circleId,
    );

    const parentEvents = await listRealmEventsViaApi(
      request,
      fixture.bobToken,
      fixture.parentId,
    );
    expect(
      parentEvents.find((event) => event.event_kind === "ck.flow.update")
        ?.payload,
    ).toMatchObject({
      flow_id: flowId,
      patch: { scope_circle_id: { $op: "set", value: circleId } },
    });
    // The Circle creation event lives on the parent Realm; child Spaces
    // are no longer minted as part of the discussion-upgrade flow.
    expect(parentEvents.map((event) => event.event_kind)).toContain(
      "ck.circle.create",
    );
  });

  test("after promotion, new messages on F1 route to S_discussion, not S_parent; F1 comments view stitches pre+post messages from both spaces", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(
      request,
      "fixme-route-after-promote",
    );
    const childId = await createSharedRealmViaApi(
      request,
      fixture.alice,
      fixture.aliceToken,
      fixture.bob,
      fixture.bobToken,
      {
        title: `route promoted child ${Date.now()}`,
        historyVisibility: "shared",
      },
    );
    const flowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.parentId,
      "routed F1",
    );
    const pre = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.parentId,
      flowId,
      "pre promotion",
    );
    await setFlowDiscussionRealmViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.parentId,
      flowId,
      childId,
    );
    const post = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      childId,
      flowId,
      "post promotion",
    );

    const parentIds = (
      await listRealmEventsViaApi(request, fixture.bobToken, fixture.parentId)
    ).map((event) => event.event_id);
    const childIds = (
      await listRealmEventsViaApi(request, fixture.bobToken, childId)
    ).map((event) => event.event_id);
    expect(parentIds).toContain(pre.event_id);
    expect(parentIds).not.toContain(post.event_id);
    expect(childIds).toContain(post.event_id);
    expect(childIds).not.toContain(pre.event_id);
  });

  test("carol invited to S_discussion (not S_parent); carol sees only post-promotion messages; pre-promotion stays in S_parent and is invisible to carol", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("fixme-child-carol-alice");
    const bob = uniqueUser("fixme-child-carol-bob");
    const carol = uniqueUser("fixme-child-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const [aliceToken, bobToken, carolToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
      issueDevSession(request, carol),
    ]);
    const parentId = await createSharedRealmViaApi(
      request,
      alice,
      aliceToken,
      bob,
      bobToken,
      {
        title: `parent no cascade ${stamp}`,
        historyVisibility: "joined",
      },
    );
    const childId = await createSharedRealmViaApi(
      request,
      alice,
      aliceToken,
      carol,
      carolToken,
      {
        title: `child no cascade ${stamp}`,
        historyVisibility: "joined",
      },
    );
    const flowId = await createFlowViaApi(
      request,
      aliceToken,
      alice,
      parentId,
      "carol F1",
    );
    const pre = await createDiscussionMessageViaApi(
      request,
      aliceToken,
      alice,
      parentId,
      flowId,
      "parent-only pre promotion",
    );
    const post = await createDiscussionMessageViaApi(
      request,
      aliceToken,
      alice,
      childId,
      flowId,
      "child-only post promotion",
    );

    const parentResponse = await request.get(
      `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(parentId)}&limit=50`,
      { headers: authHeaders(carolToken) },
    );
    if (parentResponse.status() === 200) {
      const body = await parentResponse.json();
      expect(
        (body.events ?? []).map(
          (event: Record<string, unknown>) => event.event_id,
        ),
      ).not.toContain(pre.event_id);
    } else {
      expect(parentResponse.status()).toBe(404);
    }
    const childIds = (
      await listRealmEventsViaApi(request, carolToken, childId)
    ).map((event) => event.event_id);
    expect(childIds).toContain(post.event_id);
  });

  test("S_discussion can be E2EE while S_parent stays plaintext; parent's MLS key cannot decrypt child (spec §9)", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(request, "fixme-child-e2ee");
    const childId = await createSharedRealmViaApi(
      request,
      fixture.alice,
      fixture.aliceToken,
      fixture.bob,
      fixture.bobToken,
      {
        title: `e2ee child ${Date.now()}`,
        historyVisibility: "shared",
        encryptionProfile: "mls_rfc9420",
      },
    );

    const parentRealm = (
      await listRealmEventsViaApi(request, fixture.bobToken, fixture.parentId)
    ).find((event) => event.event_kind === "ck.realm.create");
    const childRealm = (
      await listRealmEventsViaApi(request, fixture.bobToken, childId)
    ).find((event) => event.event_kind === "ck.realm.create");
    expect(parentRealm?.payload).toMatchObject({
      object: { encryption_profile: "none" },
    });
    expect(childRealm?.payload).toMatchObject({
      object: { encryption_profile: "mls_rfc9420" },
    });
  });

  test("E21.1 orphan scope_circle_id update is projected verbatim", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(
      request,
      "fixme-orphan-discussion",
    );
    const flowId = await createFlowViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      fixture.parentId,
      "orphan F1",
    );
    const orphanCircleId = typedId("circle");
    const response = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(fixture.aliceToken),
      data: signedEventEnvelope({
        actorDid: fixture.alice.did,
        realmId: fixture.parentId,
        kind: "ck.flow.update",
        payload: {
          target_ref: flowId,
          flow_id: flowId,
          patch: { scope_circle_id: { $op: "set", value: orphanCircleId } },
        },
      }),
    });
    expect(response.status()).toBe(200);
    const events = await listRealmEventsViaApi(
      request,
      fixture.aliceToken,
      fixture.parentId,
    );
    expect(
      events.find(
        (event) =>
          event.event_kind === "ck.flow.update" &&
          JSON.stringify(event.payload).includes(orphanCircleId),
      )?.payload,
    ).toMatchObject({
      flow_id: flowId,
      patch: { scope_circle_id: { $op: "set", value: orphanCircleId } },
    });
  });

  test("E21.F read-receipts policy override: S_discussion.disclosure=required overrides S_parent.disclosure=optional", async ({
    request,
  }) => {
    const fixture = await createDiscussionFixture(
      request,
      "fixme-receipt-override",
    );
    const childId = await createSharedRealmViaApi(
      request,
      fixture.alice,
      fixture.aliceToken,
      fixture.bob,
      fixture.bobToken,
      { title: `receipt override ${Date.now()}`, historyVisibility: "shared" },
    );
    const childMessage = await createDiscussionMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.alice,
      childId,
      flowIdFromRealmId(childId),
      "receipt override child",
    );
    const sentAt = new Date();
    const receipt = await request.post(`${solandBaseUrl()}/_cokret/self/ephemeral`, {
      headers: authHeaders(fixture.bobToken),
      data: {
        kind: "ck.receipt.read",
        realm_id: childId,
        actor_id: fixture.bob.did,
        device_id: fixture.bob.deviceId,
        sent_at: sentAt.toISOString(),
        expires_at: new Date(sentAt.getTime() + 30_000).toISOString(),
        payload: { event_id: childMessage.event_id, disclosure: "required" },
      },
    });
    expect(receipt.status()).toBe(200);
    expect(
      await listReadMarkersViaApi(
        request,
        fixture.aliceToken,
        fixture.parentId,
      ),
    ).toHaveLength(0);
  });
});

async function createDiscussionFixture(
  request: APIRequestContext,
  label: string,
) {
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
  const parentId = await createSharedRealmViaApi(
    request,
    alice,
    aliceToken,
    bob,
    bobToken,
    {
      title: `${label} parent ${stamp}`,
      historyVisibility: "shared",
    },
  );
  return { alice, bob, aliceToken, bobToken, parentId };
}

async function createFlowViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  title: string,
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
        object: {
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
          created_by: actor.did,
          created_at: new Date().toISOString(),
          space_id: realmId,
          fields: {},
        },
      },
    }),
    { context: `create flow ${title}` },
  );
  return flowId;
}

async function setFlowScopeCircleViaApi(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  flowId: string,
  circleId: string,
) {
  // CKP-0007: promoting a Flow to its own confidential scope binds the
  // Flow to a Circle via `scope_circle_id`. The pre-CKP-0007 wire field
  // `discussion_realm_ref` is in `forbidden-wire-fields` (hard_reject).
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ck.circle.create",
      payload: {
        object: {
          id: circleId,
          schema: "ck.schema.circle.v1",
          realm_id: realmId,
          title: `circle for ${flowId}`,
          display: {
            short_name: "F1",
            color_token: "indigo",
            symbol: { kind: "glyph", glyph: "shield" },
          },
          directory_visibility: "members",
          join_rule: "invite",
          history_visibility: "joined",
          encryption_profile: "mls_rfc9420",
          state: "active",
          created_by: actor.did,
          created_at: new Date().toISOString(),
        },
      },
    }),
    { context: `create circle ${circleId}` },
  );
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ck.flow.update",
      payload: {
        target_ref: flowId,
        flow_id: flowId,
        patch: {
          scope_circle_id: { $op: "set", value: circleId },
        },
      },
    }),
    { context: `set scope_circle_id ${flowId}` },
  );
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

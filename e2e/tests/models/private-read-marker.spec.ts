// Private read marker (account-data marker + to-device cross-device sync)
// Contract: e2e/scenarios/models/private-read-marker.md
// Spec refs:
//   - models/private-objects.md §2-§3 (private objects; read marker schema + to-device propagation)
//   - discovery/read-receipts.md §3/§6 (private read cursor; cross-device sync; eventual consistency window)
//   - discovery/push-notifications.md (notification is client-side projection of marker)
//   - crypto-media/device-lifecycle.md §7  (to-device queue carries the marker fan-out)

import { createHash } from "node:crypto";
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import {
  createSharedRealmViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import {
  encryptMlsMessageContent,
  joinRealmMlsWelcomeApi,
  type MlsDevice,
  type MlsMemberGroup,
} from "../../helpers/soland-api/mls";
import {
  accountSubscribeDeltaApi,
  authHeaders,
  accountActorId,
  canonicalJson,
  createRealmApi,
  registeredEventVerificationMethod,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  createDpopUserSession,
  ensureRegistered,
  issueUserSession,
  pairSiblingDeviceSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

// soland fans the actor-private read-cursor update out to the *other* devices
// of the same actor through the to-device queue. A device polls
// `account/subscribe` and observes the update as a `ak.read_cursor.update`
// to-device envelope. Bounded sync window per scenarios/models §E10.1 (30s);
// the local harness converges far faster, so a single catchup poll suffices.
const READ_MARKER_UPDATE_KIND = "ak.read_cursor.update";

test.describe("private read marker", () => {
  // Non-fixme baseline: on a single device, writing the actor-private read
  // cursor through the canonical self surface and reading it back already
  // works today.
  test("single-device baseline: POST /read-cursors writes a marker visible to the same actor", async ({
    request,
  }) => {
    const { alice, aliceToken, realmId, position } = await readCursorFixture(
      request,
      "s11-prm-baseline",
    );

    const before = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken, "GET", `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`) },
    );
    expect(before.status()).toBe(200);
    const beforeBody = await before.json();
    expect(beforeBody.markers).toEqual([]);

    const mark = await postReadCursor(
      request,
      aliceToken,
      alice.id,
      alice.deviceId,
      realmId,
      { kind: "realm" },
      position,
    );
    expect(mark.status()).toBe(200);
    const markBody = await mark.json();
    expect(markBody.realm_id).toBe(realmId);
    expect(markBody.actor_id).toEqual(accountActorId(alice.id));
    expect(markBody.position).toEqual(position);
    expect(typeof markBody.updated_at).toBe("string");
    expect(markBody.updated_at).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );

    const after = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken, "GET", `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`) },
    );
    expect(after.status()).toBe(200);
    const afterBody = await after.json();
    expect(afterBody.markers).toContainEqual(
      expect.objectContaining({
        realm_id: realmId,
        actor_id: accountActorId(alice.id),
        read_scope: { kind: "realm" },
        position,
      }),
    );
  });

  test("read cursor is actor-private: alice's marker does not mutate bob state", async ({
    request,
  }) => {
    const stamp = Date.now();
    const {
      alice,
      aliceToken,
      realmId,
      position,
    } = await readCursorFixture(request, `s11-prm-alice-${stamp}`);
    const bob = uniqueUser(`s11-prm-bob-${stamp}`);
    await ensureRegistered(request, bob);
    const bobToken = await issueUserSession(request, bob);

    const bobBefore = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(bobToken, "GET", `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`) },
    );
    expect(bobBefore.status()).toBe(200);
    expect((await bobBefore.json()).markers).toEqual([]);

    const markAlice = await postReadCursor(
      request,
      aliceToken,
      alice.id,
      alice.deviceId,
      realmId,
      { kind: "realm" },
      position,
    );
    expect(markAlice.status()).toBe(200);
    const markAliceBody = await markAlice.json();
    expect(markAliceBody.actor_id).toEqual(accountActorId(alice.id));

    const aliceAfter = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken, "GET", `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`) },
    );
    expect(aliceAfter.status()).toBe(200);
    const aliceAfterBody = await aliceAfter.json();
    expect(aliceAfterBody.markers).toContainEqual(
      expect.objectContaining({
        actor_id: accountActorId(alice.id),
        position,
      }),
    );

    const bobAfter = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(bobToken, "GET", `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`) },
    );
    expect(bobAfter.status()).toBe(200);
    const bobAfterBody = await bobAfter.json();
    expect(bobAfterBody.markers).toEqual([]);
  });

  // Main strand: cross-device read-cursor propagation. alice holds two device
  // sessions on the same DID. device-1 advances the marker; soland fans the
  // actor-private update out to device-2's to-device queue, which device-2
  // observes on its next `account/subscribe` poll. mark-all-read from device-2
  // then propagates back to device-1.
  test("alice's read marker syncs across devices via to-device; mark-all-read advances marker on all devices within sync window", async ({
    request,
  }) => {
    const stamp = Date.now();
    const session = await createDpopUserSession(
      request,
      `s11-prm-xdev-${stamp}`,
    );
    if (!session) {
      assertJointStackNotRequired("private read-marker sibling pairing");
      test.skip(true, "joint Coauth endpoint is unavailable");
      return;
    }
    const alice = session.user;
    const device1 = alice.deviceId;
    const device2 = (await pairSiblingDeviceSession(request, session)).user.deviceId;
    const token1 = await issueUserSession(request, alice, { deviceId: device1 });
    const token2 = await issueUserSession(request, alice, { deviceId: device2 });

    const realmId = await createRealmApi(request, token1, {
      title: `read cursor xdev ${stamp}`,
      discoverability: "listed",
      history_access: "all_history_for_current_members",
      mls_activated: false,
      ownerId: alice.id,
    });

    const m2 = await sendAndResolvePosition(request, token1, realmId, alice.id, `M2 ${stamp}`);
    const m4 = await sendAndResolvePosition(request, token1, realmId, alice.id, `M4 ${stamp}`);

    // Phase C — device-1 records marker at M2.
    const markM2 = await postReadCursor(
      request,
      token1,
      alice.id,
      device1,
      realmId,
      { kind: "realm" },
      m2,
    );
    expect(markM2.status()).toBe(200);
    expect((await markM2.json()).device_id).toBe(device1);

    // Phase E — device-2 converges to M2 via the to-device channel.
    const device2Marker = await pollToDeviceReadMarker(request, token2, realmId);
    expect(device2Marker.content.position).toEqual(m2);
    expect(device2Marker.content.read_scope).toEqual({ kind: "realm" });
    expect(device2Marker.content.actor_id).toEqual(accountActorId(alice.id));
    // The update originates from device-1 (fan-out skips the writer's device).
    expect(device2Marker.content.device_id).toBe(device1);

    // Phase G — device-2 marks-all-read (advances to M4); device-1 converges.
    const markM4 = await postReadCursor(
      request,
      token2,
      alice.id,
      device2,
      realmId,
      { kind: "realm" },
      m4,
    );
    expect(markM4.status()).toBe(200);
    expect((await markM4.json()).device_id).toBe(device2);

    const device1Marker = await pollToDeviceReadMarker(request, token1, realmId, {
      expectPosition: m4,
    });
    expect(device1Marker.content.position).toEqual(m4);
    expect(device1Marker.content.device_id).toBe(device2);

    // Authoritative server-side convergence: both devices' read-cursor list
    // reflects the latest (HLC-max) position.
    for (const token of [token1, token2]) {
      const list = await request.get(
        `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
        { headers: authHeaders(token, "GET", `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`) },
      );
      expect(list.status()).toBe(200);
      const realmMarkers = (await list.json()).markers.filter(
        (marker: { read_scope?: { kind?: string } }) =>
          marker.read_scope?.kind === "realm",
      );
      expect(realmMarkers).toHaveLength(1);
      expect(realmMarkers[0].position).toEqual(m4);
    }
  });

  test("E10.1 multi-device read marker eventual consistency: device-2 may lag but converges to device-1's last write within bounded sync window (spec §3)", async ({
    request,
  }) => {
    const stamp = Date.now();
    const session = await createDpopUserSession(
      request,
      `s11-prm-ec-${stamp}`,
    );
    if (!session) {
      assertJointStackNotRequired("private read-marker eventual consistency");
      test.skip(true, "joint Coauth endpoint is unavailable");
      return;
    }
    const alice = session.user;
    const device1 = alice.deviceId;
    const device2 = (await pairSiblingDeviceSession(request, session)).user.deviceId;
    const token1 = await issueUserSession(request, alice, { deviceId: device1 });
    const token2 = await issueUserSession(request, alice, { deviceId: device2 });

    const realmId = await createRealmApi(request, token1, {
      title: `read cursor ec ${stamp}`,
      discoverability: "listed",
      history_access: "all_history_for_current_members",
      mls_activated: false,
      ownerId: alice.id,
    });

    const first = await sendAndResolvePosition(request, token1, realmId, alice.id, `EC1 ${stamp}`);
    const second = await sendAndResolvePosition(request, token1, realmId, alice.id, `EC2 ${stamp}`);

    // Two monotonically-advancing writes from device-1 in quick succession.
    for (const position of [first, second]) {
      const mark = await postReadCursor(
        request,
        token1,
        alice.id,
        device1,
        realmId,
        { kind: "realm" },
        position,
      );
      expect(mark.status()).toBe(200);
    }

    // device-2 may observe one or more intermediate to-device frames, but the
    // server-side read cursor (HLC-max convergence, spec §3.2/§6.5) MUST land
    // on the latest write. Bounded window: scenarios §E10.1 caps it at 30s.
    const converged = await pollToDeviceReadMarker(request, token2, realmId, {
      expectPosition: second,
    });
    expect(converged.content.position).toEqual(second);

    const list = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(token2, "GET", `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`) },
    );
    expect(list.status()).toBe(200);
    const realmMarkers = (await list.json()).markers.filter(
      (marker: { read_scope?: { kind?: string } }) =>
        marker.read_scope?.kind === "realm",
    );
    expect(realmMarkers).toHaveLength(1);
    expect(realmMarkers[0].position).toEqual(second);
  });

  test("E10.2 E2EE Realm message data never enters the account approval notification stream", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s11-prm-e2ee-alice-${stamp}`);
    const bob = uniqueUser(`s11-prm-e2ee-bob-${stamp}`);
    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    const aliceToken = await issueUserSession(request, alice);
    const bobToken = await issueUserSession(request, bob);

    // E2EE Realm (per_realm_mls encryption locus) founded by alice. bob's join
    // advances the scope's key-access revision, so the shared fixture admits
    // him with a covering Add Commit (encryption-and-audit.md §2.4.1, §2.5.2)
    // and bob joins the group from his Welcome.
    const realmId = await createSharedRealmViaApi(request, alice, aliceToken, bob, {
      title: `read cursor e2ee ${stamp}`,
      discoverability: "listed",
      historyAccess: "since_join",
      mlsActivated: true,
    });
    const strandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const bobDevice: MlsDevice = { id: bob.id, deviceId: bob.deviceId, token: bobToken };
    const bobGroup = await joinRealmMlsWelcomeApi(request, realmId, bobDevice);

    // bob sends an encrypted message that mentions alice. Message notifications
    // are derived locally from the timeline; the account notification stream is
    // closed to Agent runtime approvals.
    const secretBody = `TOP-SECRET-${stamp}`;
    const encryptedEvent = await sendEncryptedMentionMessage(
      request,
      bobToken,
      bobGroup,
      strandId,
      bob.id,
      alice.id,
      secretBody,
    );

    const delta = await accountSubscribeDeltaApi(request, aliceToken, {
      timeoutMs: 10_000,
    });
    const notifications = (delta.notifications ?? {}) as {
      items?: Array<Record<string, unknown>>;
    };
    const items = Array.isArray(notifications.items) ? notifications.items : [];
    expect(items.every((item) => item.type === "agent")).toBe(true);
    const serialized = JSON.stringify(notifications);
    expect(serialized).not.toContain(encryptedEvent);
    expect(serialized).not.toContain(secretBody);
  });

  test("E10.3 Circle-scoped private Strand read marker is isolated from Realm-default Strand marker (same realm_id, different read_scope)", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s11-prm-circle-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `read cursor circle ${stamp}`,
      discoverability: "listed",
      history_access: "all_history_for_current_members",
      mls_activated: false,
      ownerId: alice.id,
    });

    const mPublic = await sendAndResolvePosition(
      request,
      aliceToken,
      realmId,
      alice.id,
      `M_public ${stamp}`,
    );
    const mPrivate = await sendAndResolvePosition(
      request,
      aliceToken,
      realmId,
      alice.id,
      `M_private ${stamp}`,
    );
    const circleId = typedId("circle");

    // Realm-default marker.
    const markRealm = await postReadCursor(
      request,
      aliceToken,
      alice.id,
      alice.deviceId,
      realmId,
      { kind: "realm" },
      mPublic,
    );
    expect(markRealm.status()).toBe(200);

    // Circle-scoped private marker on the SAME realm_id, different read_scope.
    const markCircle = await postReadCursor(
      request,
      aliceToken,
      alice.id,
      alice.deviceId,
      realmId,
      { kind: "circle", container_ref: circleId },
      mPrivate,
    );
    expect(markCircle.status()).toBe(200);

    // Both markers coexist, keyed by (actor_id, realm_id, read_scope); the
    // Circle marker MUST NOT pollute the Realm-default marker and vice versa.
    const list = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken, "GET", `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`) },
    );
    expect(list.status()).toBe(200);
    const markers = (await list.json()).markers as Array<{
      read_scope: { kind: string; container_ref?: string };
      position: { event_id: string; hlc: string };
    }>;

    const realmMarker = markers.find((marker) => marker.read_scope.kind === "realm");
    const circleMarker = markers.find(
      (marker) =>
        marker.read_scope.kind === "circle" &&
        marker.read_scope.container_ref === circleId,
    );
    expect(realmMarker, "realm-default marker").toBeTruthy();
    expect(circleMarker, "circle-scoped marker").toBeTruthy();
    expect(realmMarker!.position).toEqual(mPublic);
    expect(circleMarker!.position).toEqual(mPrivate);
    expect(realmMarker!.position).not.toEqual(circleMarker!.position);
  });
});

async function readCursorFixture(
  request: APIRequestContext,
  label: string,
) {
  const stamp = Date.now();
  const alice = uniqueUser(label);
  await ensureRegistered(request, alice);
  const aliceToken = await issueUserSession(request, alice);
  const realmId = await createRealmApi(request, aliceToken, {
    title: `read cursor ${stamp}`,
    discoverability: "listed",
    history_access: "all_history_for_current_members",
    mls_activated: false,
    ownerId: alice.id,
  });
  const position = await sendAndResolvePosition(
    request,
    aliceToken,
    realmId,
    alice.id,
    `cursor target ${stamp}`,
  );
  return { alice, aliceToken, realmId, position };
}

async function postReadCursor(
  request: APIRequestContext,
  token: string,
  actorId: string,
  deviceId: string,
  realmId: string,
  readScope: { kind: string; container_ref?: string; track_name?: string },
  position: { event_id: string; hlc: string },
) {
  // read-receipts.md §6.1: the cursor is never updated in place, so the payload
  // carries no `updated_at`; the update time IS this envelope `created_at`, and
  // the derived `read_marker_outcome` takes it from there. A payload restating
  // it is a closed-shape violation (tasks/spec-done/2026-09-04-2130-read-cursor-advance-updated-at-envelope-equality.md).
  const updatedAt = new Date().toISOString();
  // The producer proof is the writing device's own: a sibling device signs
  // with its accepted key, never with the founding device's.
  const event = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.read_cursor.advance",
    createdAt: updatedAt,
    proofVerificationMethod: registeredEventVerificationMethod(actorId, deviceId),
    payload: {
      schema: "ak.schema.read_cursor.v1",
      actor_id: accountActorId(actorId),
      device_id: deviceId,
      realm_id: realmId,
      read_scope: readScope,
      position,
    },
  });
  const url = `${solandBaseUrl()}/_arkret/self/read-cursors`;
  return await request.post(url, {
    headers: {
      ...authHeaders(token, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({ advance_event: { event } }),
  });
}

// The Event envelope has no HLC field. A read cursor carries its own local
// clock alongside the accepted target Event ID.
let cursorPhysicalMs = 0;
async function sendAndResolvePosition(
  request: APIRequestContext,
  token: string,
  realmId: string,
  actorId: string,
  body: string,
): Promise<{ event_id: string; hlc: string }> {
  const message = await sendPlaintextMessageViaApi(request, token, realmId, body, {
    actorId,
  });
  cursorPhysicalMs = Math.max(Date.now(), cursorPhysicalMs + 1);
  const nodeId = createHash("sha256")
    .update(realmId)
    .update(actorId)
    .digest("hex")
    .slice(0, 8);
  return {
    event_id: message.event_id,
    hlc: `${cursorPhysicalMs.toString(16).padStart(12, "0")}-0000-${nodeId}`,
  };
}

// Poll `account/subscribe` until the actor's to-device queue carries a
// `ak.read_cursor.update` envelope for the given realm (optionally matching a
// specific position). Bounded by the scenario's 30s sync window.
async function pollToDeviceReadMarker(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { expectPosition?: { event_id: string; hlc: string } } = {},
): Promise<{ kind: string; content: Record<string, any> }> {
  const deadline = Date.now() + 30_000;
  let last: { kind: string; content: Record<string, any> } | undefined;
  while (Date.now() < deadline) {
    const delta = await accountSubscribeDeltaApi(request, token, {
      timeoutMs: 10_000,
    });
    const toDevice = (delta.to_device ?? {}) as { messages?: unknown };
    const messages = Array.isArray(toDevice.messages) ? toDevice.messages : [];
    for (const message of messages as Array<Record<string, any>>) {
      if (message.kind !== READ_MARKER_UPDATE_KIND) {
        continue;
      }
      const content = (message.content ?? {}) as Record<string, any>;
      if (content.realm_id !== realmId) {
        continue;
      }
      last = { kind: message.kind, content };
      if (!opts.expectPosition) {
        return last;
      }
      if (
        content.position?.event_id === opts.expectPosition.event_id &&
        content.position?.hlc === opts.expectPosition.hlc
      ) {
        return last;
      }
    }
  }
  if (last && !opts.expectPosition) {
    return last;
  }
  throw new Error(
    `pollToDeviceReadMarker: no ${READ_MARKER_UPDATE_KIND} for ${realmId} within sync window` +
      (opts.expectPosition ? ` matching ${opts.expectPosition.event_id}` : ""),
  );
}

// Send an MLS-encrypted message that mentions `mentionId`. The direct mention
// lives only in the sealed Content Block (message.schema.json
// content_block.mentions), so the Station never sees it; the plaintext
// `secretBody` is the canary the notification projection MUST NOT expose.
async function sendEncryptedMentionMessage(
  request: APIRequestContext,
  token: string,
  group: MlsMemberGroup,
  strandId: string,
  actorId: string,
  mentionId: string,
  secretBody: string,
): Promise<string> {
  const envelope = signedEventEnvelope({
    actorId,
    realmId: group.realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      encrypted_content: encryptMlsMessageContent(group, {
        kind: "ak.content.text",
        body: secretBody,
        format: "plain",
        mentions: [
          { kind: "mention", subject_account_id: accountActorId(mentionId).account_id },
        ],
      }),
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    context: `send encrypted mention ${group.realmId}`,
  });
  return String(envelope.event_id);
}

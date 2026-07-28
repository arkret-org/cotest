// Private read marker (account-data marker + to-device cross-device sync)
// Contract: e2e/scenarios/models/private-read-marker.md
// Spec refs:
//   - models/private-objects.md §2-§3 (private objects; read marker schema + to-device propagation)
//   - discovery/read-receipts.md §3/§6 (private read cursor; cross-device sync; eventual consistency window)
//   - discovery/push-notifications.md (notification is client-side projection of marker)
//   - crypto-media/device-lifecycle.md §7  (to-device queue carries the marker fan-out)

import { createHash } from "node:crypto";
import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  acceptInviteViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import {
  accountSubscribeDeltaApi,
  canonicalJson,
  createRealmApi,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
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
    const auth = { authorization: `Bearer ${aliceToken}` };

    const before = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: auth },
    );
    expect(before.status()).toBe(200);
    const beforeBody = await before.json();
    expect(beforeBody.markers).toEqual([]);

    const mark = await request.post(`${solandBaseUrl()}/_arkret/self/read-cursors`, {
      headers: auth,
      data: {
        realm_id: realmId,
        read_scope: { kind: "realm" },
        position,
      },
    });
    expect(mark.status()).toBe(200);
    const markBody = await mark.json();
    expect(markBody.realm_id).toBe(realmId);
    expect(markBody.actor_id).toBe(alice.did);
    expect(markBody.position).toEqual(position);
    expect(typeof markBody.updated_at).toBe("string");
    expect(markBody.updated_at).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );

    const after = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: auth },
    );
    expect(after.status()).toBe(200);
    const afterBody = await after.json();
    expect(afterBody.markers).toContainEqual(
      expect.objectContaining({
        realm_id: realmId,
        actor_id: alice.did,
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
    const bobToken = await issueDevSession(request, bob);
    const aliceAuth = { authorization: `Bearer ${aliceToken}` };
    const bobAuth = { authorization: `Bearer ${bobToken}` };

    const bobBefore = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: bobAuth },
    );
    expect(bobBefore.status()).toBe(200);
    expect((await bobBefore.json()).markers).toEqual([]);

    const markAlice = await request.post(`${solandBaseUrl()}/_arkret/self/read-cursors`, {
      headers: aliceAuth,
      data: {
        realm_id: realmId,
        read_scope: { kind: "realm" },
        position,
      },
    });
    expect(markAlice.status()).toBe(200);
    const markAliceBody = await markAlice.json();
    expect(markAliceBody.actor_id).toBe(alice.did);

    const aliceAfter = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: aliceAuth },
    );
    expect(aliceAfter.status()).toBe(200);
    const aliceAfterBody = await aliceAfter.json();
    expect(aliceAfterBody.markers).toContainEqual(
      expect.objectContaining({
        actor_id: alice.did,
        position,
      }),
    );

    const bobAfter = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: bobAuth },
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
    const alice = uniqueUser(`s11-prm-xdev-${stamp}`);
    await ensureRegistered(request, alice);
    const device1 = typedId("device");
    const device2 = typedId("device");
    const token1 = await issueDevSession(request, alice, { deviceId: device1 });
    const token2 = await issueDevSession(request, alice, { deviceId: device2 });

    const realmId = await createRealmApi(request, token1, {
      title: `read cursor xdev ${stamp}`,
      discoverability: "listed",
      history_visibility: "shared",
      encryption_profile: "none",
      ownerDid: alice.did,
    });

    const m2 = await sendAndResolvePosition(request, token1, realmId, alice.did, `M2 ${stamp}`);
    const m4 = await sendAndResolvePosition(request, token1, realmId, alice.did, `M4 ${stamp}`);

    // Phase C — device-1 records marker at M2.
    const markM2 = await request.post(`${solandBaseUrl()}/_arkret/self/read-cursors`, {
      headers: { authorization: `Bearer ${token1}` },
      data: { realm_id: realmId, read_scope: { kind: "realm" }, position: m2 },
    });
    expect(markM2.status()).toBe(200);
    expect((await markM2.json()).device_id).toBe(device1);

    // Phase E — device-2 converges to M2 via the to-device channel.
    const device2Marker = await pollToDeviceReadMarker(request, token2, realmId);
    expect(device2Marker.content.position).toEqual(m2);
    expect(device2Marker.content.read_scope).toEqual({ kind: "realm" });
    expect(device2Marker.content.actor_id).toBe(alice.did);
    // The update originates from device-1 (fan-out skips the writer's device).
    expect(device2Marker.content.device_id).toBe(device1);

    // Phase G — device-2 marks-all-read (advances to M4); device-1 converges.
    const markM4 = await request.post(`${solandBaseUrl()}/_arkret/self/read-cursors`, {
      headers: { authorization: `Bearer ${token2}` },
      data: { realm_id: realmId, read_scope: { kind: "realm" }, position: m4 },
    });
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
        { headers: { authorization: `Bearer ${token}` } },
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
    const alice = uniqueUser(`s11-prm-ec-${stamp}`);
    await ensureRegistered(request, alice);
    const device1 = typedId("device");
    const device2 = typedId("device");
    const token1 = await issueDevSession(request, alice, { deviceId: device1 });
    const token2 = await issueDevSession(request, alice, { deviceId: device2 });

    const realmId = await createRealmApi(request, token1, {
      title: `read cursor ec ${stamp}`,
      discoverability: "listed",
      history_visibility: "shared",
      encryption_profile: "none",
      ownerDid: alice.did,
    });

    const first = await sendAndResolvePosition(request, token1, realmId, alice.did, `EC1 ${stamp}`);
    const second = await sendAndResolvePosition(request, token1, realmId, alice.did, `EC2 ${stamp}`);

    // Two monotonically-advancing writes from device-1 in quick succession.
    for (const position of [first, second]) {
      const mark = await request.post(`${solandBaseUrl()}/_arkret/self/read-cursors`, {
        headers: { authorization: `Bearer ${token1}` },
        data: { realm_id: realmId, read_scope: { kind: "realm" }, position },
      });
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
      { headers: { authorization: `Bearer ${token2}` } },
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
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    // E2EE Realm (per_realm_mls encryption locus): bob is a member.
    const realmId = await createRealmApi(request, bobToken, {
      title: `read cursor e2ee ${stamp}`,
      discoverability: "listed",
      history_visibility: "shared",
      encryption_profile: "mls_rfc9420",
      content_scheme: "mls_exporter_aead_v1",
      invitees: [alice.did],
      ownerDid: bob.did,
    });
    await acceptInviteViaApi(request, aliceToken, alice.did, realmId);

    // bob sends an encrypted message that mentions alice. Message notifications
    // are derived locally from the timeline; the account notification stream is
    // closed to Agent runtime approvals.
    const secretBody = `TOP-SECRET-${stamp}`;
    const encryptedEvent = await sendEncryptedMentionMessage(
      request,
      bobToken,
      realmId,
      bob.did,
      alice.did,
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
    const aliceToken = await issueDevSession(request, alice);
    const auth = { authorization: `Bearer ${aliceToken}` };

    const realmId = await createRealmApi(request, aliceToken, {
      title: `read cursor circle ${stamp}`,
      discoverability: "listed",
      history_visibility: "shared",
      encryption_profile: "none",
      ownerDid: alice.did,
    });

    const mPublic = await sendAndResolvePosition(
      request,
      aliceToken,
      realmId,
      alice.did,
      `M_public ${stamp}`,
    );
    const mPrivate = await sendAndResolvePosition(
      request,
      aliceToken,
      realmId,
      alice.did,
      `M_private ${stamp}`,
    );
    const circleId = typedId("circle");

    // Realm-default marker.
    const markRealm = await request.post(`${solandBaseUrl()}/_arkret/self/read-cursors`, {
      headers: auth,
      data: { realm_id: realmId, read_scope: { kind: "realm" }, position: mPublic },
    });
    expect(markRealm.status()).toBe(200);

    // Circle-scoped private marker on the SAME realm_id, different read_scope.
    const markCircle = await request.post(`${solandBaseUrl()}/_arkret/self/read-cursors`, {
      headers: auth,
      data: {
        realm_id: realmId,
        read_scope: { kind: "circle", container_ref: circleId },
        position: mPrivate,
      },
    });
    expect(markCircle.status()).toBe(200);

    // Both markers coexist, keyed by (actor_id, realm_id, read_scope); the
    // Circle marker MUST NOT pollute the Realm-default marker and vice versa.
    const list = await request.get(
      `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: auth },
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
  const aliceToken = await issueDevSession(request, alice);
  const realmId = await createRealmApi(request, aliceToken, {
    title: `read cursor ${stamp}`,
    discoverability: "listed",
    history_visibility: "shared",
    encryption_profile: "none",
    ownerDid: alice.did,
  });
  const position = await sendAndResolvePosition(
    request,
    aliceToken,
    realmId,
    alice.did,
    `cursor target ${stamp}`,
  );
  return { alice, aliceToken, realmId, position };
}

// Send a plaintext message and return its canonical read-cursor position
// {event_id, hlc} resolved from the realm event log.
async function sendAndResolvePosition(
  request: APIRequestContext,
  token: string,
  realmId: string,
  actorDid: string,
  body: string,
): Promise<{ event_id: string; hlc: string }> {
  const message = await sendPlaintextMessageViaApi(request, token, realmId, body, {
    actorDid,
  });
  const events = await listRealmEventsViaApi(request, token, realmId, { limit: 50 });
  const event = events.find(
    (candidate) => candidate.event_id === message.event_id,
  ) as { event_id?: string; hlc?: string } | undefined;
  expect(event, `message event ${message.event_id}`).toBeTruthy();
  expect(typeof event!.hlc).toBe("string");
  return { event_id: message.event_id, hlc: event!.hlc! };
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

// Send an encrypted (E2EE) message that mentions `mentionDid`. The body is
// sealed (`encrypted_content` ciphertext); the plaintext `secretBody` is the
// canary the notification projection MUST NOT expose.
async function sendEncryptedMentionMessage(
  request: APIRequestContext,
  token: string,
  realmId: string,
  actorDid: string,
  mentionDid: string,
  secretBody: string,
): Promise<string> {
  const strandId = await resolveDefaultStrandId(request, token, realmId);
  const ciphertext = Buffer.from(`opaque-ciphertext-${secretBody}`, "utf8").toString(
    "base64url",
  );
  const envelope = signedEventEnvelope({
    actorDid,
    realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      mention_sidecar_digest: [mentionSidecarHash(realmId, mentionDid)],
      encrypted_content: encryptedEnvelope(ciphertext, realmId),
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    context: `send encrypted mention ${realmId}`,
  });
  return String(envelope.event_id);
}

function mentionSidecarHash(realmId: string, did: string): string {
  return createHash("sha256").update(`${realmId}|${did}`).digest("hex");
}

function encryptedEnvelope(
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  const aad = { realm_id: realmId, event_kind: "ak.message.create" };
  const payloadMetadata = {
    scheme: "mls_exporter_aead_v1",
    purpose: "mls_exporter_aead_content",
    aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    version: "1.0",
    group_id: "mls_test",
    epoch: 1,
    content_type: "application/vnd.arkret.message+json",
    aad_visibility_event_id: "hidden",
    aad,
    key_ref: {
      algorithm: "MLS-EXPORTER-AEAD",
      group_state_ref:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
  return {
    ...payloadMetadata,
    ciphertext,
    aad_digest: sha256Digest(canonicalJson(aad)),
    payload_digest: encryptedPayloadDigest(payloadMetadata, ciphertext),
  };
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function encryptedPayloadDigest(
  metadata: Record<string, unknown>,
  ciphertext: string,
): string {
  const hash = createHash("sha256");
  hash.update(Buffer.from(canonicalJson(metadata), "utf8"));
  hash.update(Buffer.from(ciphertext, "base64url"));
  return `sha256:${hash.digest("hex")}`;
}

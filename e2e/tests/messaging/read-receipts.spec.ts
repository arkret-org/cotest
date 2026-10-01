// Read receipts + privacy toggle
// Contract: e2e/scenarios/messaging/read-receipts.md
// Spec refs:
//   - discovery/read-receipts.md §2.1-§2.5 (ephemeral format, debounce, policy)
//   - §3.1-§3.2 (actor-private read marker)

import {
  expect,
  test,
  type APIRequestContext,
} from "../../helpers/arkret-test";
import {
  authHeaders,
  createSharedRealmViaApi,
  listReadMarkersViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import { createTwoUserMessagingRealm } from "../../helpers/messaging-fixtures";
import {
  accountActorId,
  canonicalJson,
  registeredEventVerificationMethod,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
  } from "../../helpers/soland-api";
import {
  encryptMlsMessageContent,
  realmMlsCreatorGroupApi,
} from "../../helpers/soland-api/mls";
import {
  createDpopUserSession,
  ensureRegistered,
  issueUserSession,
  pairSiblingDeviceSession,
  type JointUser,
  uniqueUser,
} from "../../helpers/users";
import {
  buildSignalEnvelope,
  captureSubmittedSignalEnvelope,
  postCallSignalRaw,
  prepareSignalEnvelope,
  signalPlaintext,
} from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

test.describe("read receipts + privacy", () => {
  test("encrypted receipt Signal reaches bob without creating a durable marker", async ({
    request,
  }) => {
    // Read receipts use the live encrypted Signal rail. Read cursors remain a
    // separate actor-private durable surface.
    const stamp = Date.now();
    const alice = uniqueUser("g2t7-receipt-alice");
    const bob = uniqueUser("g2t7-receipt-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
    ]);

    const realmId = await createSharedRealmViaApi(
      request,
      bob,
      bobToken,
      alice,
      {
        title: `G2.T7 Receipt ${stamp}`,
        discoverability: "listed",
        historyAccess: "since_join",
        mlsActivated: true,
      },
    );
    // read-receipts.md §2 defines the position as a message on the discussion
    // track. The Realm is MLS-only (its Genesis and alice's Add Commit are
    // accepted), so the target is a real MLS ciphertext at the current epoch.
    const target = await sendEncryptedReceiptMessage(
      request,
      bobToken,
      bob,
      realmId,
      `receipt-target-${stamp}`,
    );
    const targetEventId = target.event_id;

    const envelope = buildReceiptSignal({
      actor: alice,
      realmId,
      eventId: targetEventId,
      payloadSequence: 1,
    });
    const { result: receipt, envelopes } = await captureSubmittedSignalEnvelope(
      request,
      aliceToken,
      bobToken,
      realmId,
      envelope,
    );
    const receiptText = await receipt.text();
    expect(receipt.status(), receiptText).toBe(200);
    const receiptBody = JSON.parse(receiptText) as Record<string, unknown>;
    expect(receiptBody).toMatchObject({
      accepted: true,
      realm_id: realmId,
    });
    expect(receiptBody).not.toHaveProperty("kind");
    expect(receiptBody).not.toHaveProperty("event_id");

    const received = decryptedReceiptPayloads(envelopes).find(
      (payload) => payload.event_id === targetEventId,
    );
    expect(received).toMatchObject({
      actor_id: accountActorId(alice.id),
      event_id: targetEventId,
      read_scope: { kind: "realm" },
    });
    const receivedEnvelope = envelopes.find(
      (candidate) =>
        canonicalJson(candidate.sender_actor_id) === canonicalJson(accountActorId(alice.id)) &&
        signalPlaintext(candidate).kind === "ak.receipt.read",
    );
    expect(receivedEnvelope).toBeTruthy();
    expect(receivedEnvelope).not.toHaveProperty("kind");
    expect(receivedEnvelope).not.toHaveProperty("event_id");

    const [aliceMarkers, bobMarkers] = await Promise.all([
      listReadMarkersViaApi(request, aliceToken, realmId),
      listReadMarkersViaApi(request, bobToken, realmId),
    ]);
    expect(aliceMarkers).toHaveLength(0);
    expect(bobMarkers).toHaveLength(0);
  });

  test("session-class receipt Signal rejects TTL above 30 seconds", async ({
    request,
  }) => {
    const fixture = await createReceiptFixture(request, "ttl-too-long");
    const receipt = await postReceipt(
      request,
      fixture.aliceToken,
      receiptEnvelope(fixture, 30_001),
    );
    expect(receipt.status()).toBe(400);
    const body = await receipt.json();
    expect(JSON.stringify(body)).toContain("signal_ttl_out_of_range");
  });

  test("ak.receipt.read rejects already expired envelopes", async ({
    request,
  }) => {
    const fixture = await createReceiptFixture(request, "expired");
    const sentAt = new Date(Date.now() - 10_000);
    const receipt = await postReceipt(
      request,
      fixture.aliceToken,
      receiptEnvelope(fixture, 5_000, sentAt),
    );
    expect(receipt.status()).toBe(400);
    const body = await receipt.json();
    expect(JSON.stringify(body)).toContain("already expired");
  });

  test("ak.receipt.read rejects actor_id that does not match the bearer session", async ({
    request,
  }) => {
    const fixture = await createReceiptFixture(request, "actor-mismatch");
    const mismatched = buildReceiptSignal({
      actor: fixture.bob,
      realmId: fixture.realmId,
      eventId: fixture.message.event_id,
      payloadSequence: 1,
    });
    const receipt = await postReceipt(
      request,
      fixture.aliceToken,
      mismatched,
    );
    expect(receipt.status()).toBe(403);
    const body = await receipt.json();
    expect(JSON.stringify(body)).toContain("sender");
  });

  test("ak.receipt.read rejects non-members", async ({ request }) => {
    const fixture = await createReceiptFixture(request, "non-member");
    const outsider = uniqueUser("receipt-outsider");
    await ensureRegistered(request, outsider);
    const outsiderToken = await issueUserSession(request, outsider);
    const envelope = buildReceiptSignal({
      actor: outsider,
      realmId: fixture.realmId,
      eventId: fixture.message.event_id,
      payloadSequence: 1,
    });
    // Resolve a valid current scope basis through a member; the actual send is
    // still authorized as the outsider and must fail membership admission.
    await prepareSignalEnvelope(request, fixture.aliceToken, envelope);
    const receipt = await request.post(
      `${solandBaseUrl()}/_arkret/self/signal`,
      {
        headers: {
          ...authHeaders(outsiderToken, "POST", `${solandBaseUrl()}/_arkret/self/signal`),
          "content-type": "application/json",
        },
        data: canonicalJson(envelope),
      },
    );
    expect(receipt.status()).toBe(403);
    const body = (await receipt.json()) as { type?: string };
    // `read-receipts.md` §2.1 fixes the admission (the sender must be a joined
    // member of the declared signed Seal basis) but not the human-readable
    // detail string, so the contract to assert is the registered problem type.
    expect(body.type).toBe("https://arkret.org/problems/signal_class_denied");
  });

  test("alice reads N messages while preference=send_read_receipts true; bob sees alice's receipt at the highest visible event within debounce window", async ({
    request,
  }) => {
    const fixture = await createReceiptFixture(request, "highest-visible");
    await sendEncryptedReceiptMessage(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.realmId,
      `highest visible second ${Date.now()}`,
    );
    const highest = await sendEncryptedReceiptMessage(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.realmId,
      `highest visible third ${Date.now()}`,
    );
    const receipt = buildReceiptSignal({
      actor: fixture.alice,
      realmId: fixture.realmId,
      eventId: highest.event_id,
      payloadSequence: 3,
    });
    const { result: response, envelopes } =
      await captureSubmittedSignalEnvelope(
        request,
        fixture.aliceToken,
        fixture.bobToken,
        fixture.realmId,
        receipt,
      );
    expect(response.status(), await response.text()).toBe(200);
    expect(decryptedReceiptPayloads(envelopes)).toEqual([
      expect.objectContaining({ event_id: highest.event_id }),
    ]);
    expect(
      await listReadMarkersViaApi(request, fixture.bobToken, fixture.realmId),
    ).toHaveLength(0);
  });

  test("disclosure=disabled is enforced after receiver decryption, not by the relay", async ({
    request,
  }) => {
    // A compliant sender suppresses this signal. If a non-compliant client
    // sends anyway, the opaque relay cannot identify a receipt or read the
    // policy target; the receiver decrypts and drops it.
    const fixture = await createReceiptFixture(request, "disclosure-disabled");
    await setReadReceiptPolicy(request, fixture.bobToken, fixture, {
      disclosure: "disabled",
    });
    const { result: receipt, envelopes } =
      await captureSubmittedSignalEnvelope(
        request,
        fixture.aliceToken,
        fixture.bobToken,
        fixture.realmId,
        receiptEnvelope(fixture),
      );
    expect(receipt.status(), await receipt.text()).toBe(200);
    expect(decryptedReceiptPayloads(envelopes)).toHaveLength(1);
    expect(
      receiverVisibleReceiptPayloads(envelopes, {
        disclosure: "disabled",
      }),
    ).toHaveLength(0);
    expect(
      await listReadMarkersViaApi(request, fixture.bobToken, fixture.realmId),
    ).toHaveLength(0);
  });

  test("space disclosure can be re-enabled; blocked-window reads stay invisible", async ({
    request,
  }) => {
    const fixture = await createReceiptFixture(request, "disclosure-reenabled");
    await setReadReceiptPolicy(request, fixture.bobToken, fixture, {
      disclosure: "disabled",
    });
    const hiddenWindowMessage = await sendEncryptedReceiptMessage(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.realmId,
      `disabled-window ${Date.now()}`,
    );
    const blocked = buildReceiptSignal({
      actor: fixture.alice,
      realmId: fixture.realmId,
      eventId: hiddenWindowMessage.event_id,
      payloadSequence: 1,
    });
    const blockedCapture = await captureSubmittedSignalEnvelope(
      request,
      fixture.aliceToken,
      fixture.bobToken,
      fixture.realmId,
      blocked,
    );
    expect(
      blockedCapture.result.status(),
      await blockedCapture.result.text(),
    ).toBe(200);
    expect(
      receiverVisibleReceiptPayloads(blockedCapture.envelopes, {
        disclosure: "disabled",
      }),
    ).toHaveLength(0);

    await setReadReceiptPolicy(request, fixture.bobToken, fixture, {
      disclosure: "required",
    });
    const freshMessage = await sendEncryptedReceiptMessage(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.realmId,
      `reenabled-window ${Date.now()}`,
    );
    const receipt = buildReceiptSignal({
      actor: fixture.alice,
      realmId: fixture.realmId,
      eventId: freshMessage.event_id,
      payloadSequence: 2,
    });
    const freshCapture = await captureSubmittedSignalEnvelope(
      request,
      fixture.aliceToken,
      fixture.bobToken,
      fixture.realmId,
      receipt,
    );
    const responseBody = await freshCapture.result.json();
    expect(responseBody.accepted).toBe(true);
    expect(responseBody).not.toHaveProperty("kind");
    const visible = receiverVisibleReceiptPayloads(freshCapture.envelopes, {
      disclosure: "required",
    });
    expect(visible).toEqual([
      expect.objectContaining({ event_id: freshMessage.event_id }),
    ]);
    expect(
      JSON.stringify(visible),
    ).not.toContain(hiddenWindowMessage.event_id);
  });

  test("visibility=private is filtered by the receiver without server-side target routing", async ({
    request,
  }) => {
    const fixture = await createReceiptFixture(request, "disclosure-required");
    await setReadReceiptPolicy(request, fixture.bobToken, fixture, {
      disclosure: "required",
      visibility: "private",
    });
    const receipt = receiptEnvelope(fixture);
    const capture = await captureSubmittedSignalEnvelope(
      request,
      fixture.aliceToken,
      fixture.bobToken,
      fixture.realmId,
      receipt,
    );
    expect(capture.result.status()).toBe(200);
    const body = await capture.result.json();
    expect(body.accepted).toBe(true);
    expect(body.realm_id).toBe(fixture.realmId);
    expect(body).not.toHaveProperty("kind");
    expect(
      receiverVisibleReceiptPayloads(capture.envelopes, {
        disclosure: "required",
        visibility: "private",
        receiverId: fixture.bob.id,
        eventAuthors: {
          [fixture.message.event_id]: fixture.bob.id,
        },
      }),
    ).toHaveLength(1);
    expect(
      receiverVisibleReceiptPayloads(capture.envelopes, {
        disclosure: "required",
        visibility: "private",
        receiverId: fixture.alice.id,
        eventAuthors: {
          [fixture.message.event_id]: fixture.bob.id,
        },
      }),
    ).toHaveLength(0);
    expect(
      await listReadMarkersViaApi(request, fixture.bobToken, fixture.realmId),
    ).toHaveLength(0);
  });

  test("disclosure=disabled consistently filters repeated decrypted receipts", async ({
    request,
  }) => {
    const fixture = await createReceiptFixture(request, "disclosure-disabled-reason");
    await setReadReceiptPolicy(request, fixture.bobToken, fixture, {
      disclosure: "disabled",
    });
    const capture = await captureSubmittedSignalEnvelope(
      request,
      fixture.aliceToken,
      fixture.bobToken,
      fixture.realmId,
      receiptEnvelope(fixture),
    );
    expect(capture.result.status(), await capture.result.text()).toBe(200);
    expect(
      receiverVisibleReceiptPayloads(capture.envelopes, {
        disclosure: "disabled",
      }),
    ).toHaveLength(0);
  });

  test("actor-private read marker (ak.read_cursor.advance) syncs across alice's devices but does NOT broadcast to bob", async ({
    request,
  }) => {
    // spec: read-receipts.md §3.1-§3.2 / §6.6 — ak.read_cursor.advance is an
    // actor-private durable cursor (POST /_arkret/self/read-cursors). The
    // Principal/Sync Service returns it only to the same principal's authorized
    // devices (account-private projection read-back), never to other Realm
    // members. alice's second device is paired through the accepted-device
    // ceremony and holds its own Standard grant, and we assert: both alice
    // devices read the converged marker, bob reads none.
    const { fixture, aliceSession } = await createPairableReceiptFixture(
      request,
      "read-cursor-sync",
    );
    const aliceSecond = withDevice(
      fixture.alice,
      (await pairSiblingDeviceSession(request, aliceSession)).user.deviceId,
    );
    const aliceSecondToken = await issueUserSession(request, aliceSecond);

    const hlc = makeHlc(1);
    const advance = await advanceReadCursor(request, fixture.aliceToken, fixture.alice, {
      realm_id: fixture.realmId,
      read_scope: { kind: "realm" },
      position: { event_id: fixture.message.event_id, hlc },
    });
    expect(advance.status(), await advance.text()).toBe(200);
    const advanceBody = await advance.json();
    expect(advanceBody.actor_id).toEqual(accountActorId(fixture.alice.id));
    expect(advanceBody.position.event_id).toBe(fixture.message.event_id);

    // Alice's first device reads back its own cursor.
    const aliceMarkers = await listReadCursors(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    expect(aliceMarkers).toHaveLength(1);
    expect(aliceMarkers[0].actor_id).toEqual(accountActorId(fixture.alice.id));
    expect(aliceMarkers[0].position.event_id).toBe(fixture.message.event_id);

    // Alice's second device synchronizes the same account-private cursor.
    const aliceSecondMarkers = await listReadCursors(
      request,
      aliceSecondToken,
      fixture.realmId,
    );
    expect(aliceSecondMarkers).toHaveLength(1);
    expect(aliceSecondMarkers[0].actor_id).toEqual(accountActorId(fixture.alice.id));
    expect(aliceSecondMarkers[0].position.event_id).toBe(
      fixture.message.event_id,
    );

    // Bob is a Realm member but a different principal: the actor-private cursor
    // is never broadcast to him.
    const bobMarkers = await listReadCursors(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    expect(bobMarkers).toHaveLength(0);

    // The actor-private cursor also stays out of bob's shared Realm timeline.
    expect(
      await listReadMarkersViaApi(request, fixture.bobToken, fixture.realmId),
    ).toHaveLength(0);
  });

  test("E22.1 high-frequency scroll: debounce window ≥1s; only a single receipt covering the highest visible event is emitted", async ({
    request,
  }) => {
    // spec: read-receipts.md §2.3 — the Sync Service merges high-frequency
    // receipts for the same (realm, read_scope, actor): it MAY drop older
    // receipts and only broadcasts the monotonically-latest position; it MUST
    // NOT fan out every scroll increment as an independent push. Time-based
    // debounce is a client concern not observable here, so we express the
    // server-side merge contract directly: submitting several receipts that walk
    // up to the highest visible event leaves a single converged read-cursor
    // covering that highest event (members/private receipts never reach bob's
    // durable timeline).
    const fixture = await createReceiptFixture(request, "debounce-merge");
    const second = await sendEncryptedReceiptMessage(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.realmId,
      `debounce second ${Date.now()}`,
    );
    const highest = await sendEncryptedReceiptMessage(
      request,
      fixture.bobToken,
      fixture.bob,
      fixture.realmId,
      `debounce highest ${Date.now()}`,
    );

    // Three rapid "scroll" positions for the same realm scope; the cursor must
    // converge on the highest visible event only.
    const positions = [
      { event_id: fixture.message.event_id, hlc: makeHlc(1) },
      { event_id: second.event_id, hlc: makeHlc(2) },
      { event_id: highest.event_id, hlc: makeHlc(3) },
    ];
    for (const position of positions) {
      const response = await advanceReadCursor(
        request,
        fixture.aliceToken,
        fixture.alice,
        {
        realm_id: fixture.realmId,
        read_scope: { kind: "realm" },
        position,
        },
      );
      expect(response.status()).toBe(200);
    }

    const markers = await listReadCursors(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    // Single merged cursor for the (realm, realm-scope, actor) key — not three.
    expect(markers).toHaveLength(1);
    expect(markers[0].position.event_id).toBe(highest.event_id);
    expect(markers[0].position.hlc).toBe(makeHlc(3));

    // An out-of-order older position MUST NOT regress the merged cursor.
    const regress = await advanceReadCursor(
      request,
      fixture.aliceToken,
      fixture.alice,
      {
      realm_id: fixture.realmId,
      read_scope: { kind: "realm" },
      position: { event_id: second.event_id, hlc: makeHlc(2) },
      },
    );
    expect(regress.status()).toBe(200);
    const afterRegress = await listReadCursors(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    expect(afterRegress).toHaveLength(1);
    expect(afterRegress[0].position.event_id).toBe(highest.event_id);
  });

  test("E22.3 multi-device receipt coordination: HLC tie-break decides which device's marker fans out for shared receipt", async ({
    request,
  }) => {
    // spec: read-receipts.md §3.2 / §6.5 — concurrent read cursors for the same
    // actor/scope converge by HLC-max, and on equal HLC by device_id
    // lexicographic tiebreak. We submit two cursors carrying the SAME HLC from
    // two devices of one principal and assert the surviving marker is the one
    // from the lexicographically larger device_id, deterministically.
    const { fixture, aliceSession } = await createPairableReceiptFixture(
      request,
      "hlc-tiebreak",
    );
    const aliceSecond = withDevice(
      fixture.alice,
      (await pairSiblingDeviceSession(request, aliceSession)).user.deviceId,
    );
    const aliceSecondToken = await issueUserSession(request, aliceSecond);

    const lower =
      fixture.alice.deviceId < aliceSecond.deviceId
        ? { user: fixture.alice, token: fixture.aliceToken }
        : { user: aliceSecond, token: aliceSecondToken };
    const higher =
      fixture.alice.deviceId < aliceSecond.deviceId
        ? { user: aliceSecond, token: aliceSecondToken }
        : { user: fixture.alice, token: fixture.aliceToken };

    const tieHlc = makeHlc(7);
    // Submit the higher device first, then the lower device: server-receive
    // order favors the lower device under naive LWW, so a passing assertion
    // proves the HLC/device tiebreak — not arrival order — decides convergence.
    const first = await advanceReadCursor(request, higher.token, higher.user, {
      realm_id: fixture.realmId,
      read_scope: { kind: "realm" },
      position: { event_id: fixture.message.event_id, hlc: tieHlc },
    });
    expect(first.status()).toBe(200);
    const second = await advanceReadCursor(request, lower.token, lower.user, {
      realm_id: fixture.realmId,
      read_scope: { kind: "realm" },
      position: { event_id: fixture.message.event_id, hlc: tieHlc },
    });
    expect(second.status()).toBe(200);

    const markers = await listReadCursors(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    expect(markers).toHaveLength(1);
    // device_id tiebreak: the lexicographically larger device wins on equal HLC.
    expect(markers[0].device_id).toBe(higher.user.deviceId);

    // Bob (other principal) still sees no actor-private cursor.
    const bobMarkers = await listReadCursors(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    expect(bobMarkers).toHaveLength(0);
  });
});

type ReceiptFixture = Awaited<ReturnType<typeof createReceiptFixture>>;

async function createReceiptFixture(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  const fixture = await createTwoUserMessagingRealm(request, {
    label,
    owner: "bob",
    title: `${label} receipt ${stamp}`,
    realm: {
      discoverability: "listed",
      historyAccess: "since_join",
      mlsActivated: true,
    },
  });
  const message = await sendEncryptedReceiptMessage(
    request,
    fixture.bobToken,
    fixture.bob,
    fixture.realmId,
    `${label} message ${stamp}`,
  );
  return { ...fixture, message };
}

async function createPairableReceiptFixture(
  request: APIRequestContext,
  label: string,
) {
  const stamp = Date.now();
  const [aliceSession, bobSession] = await Promise.all([
    createDpopUserSession(request, `${label}-alice`),
    createDpopUserSession(request, `${label}-bob`),
  ]);
  expect(aliceSession, "alice canonical account session").toBeTruthy();
  expect(bobSession, "bob canonical account session").toBeTruthy();
  const alice = aliceSession!.user;
  const bob = bobSession!.user;
  const [aliceToken, bobToken] = await Promise.all([
    issueUserSession(request, alice),
    issueUserSession(request, bob),
  ]);
  const realmId = await createSharedRealmViaApi(
    request,
    bob,
    bobToken,
    alice,
    {
      title: `${label} receipt ${stamp}`,
      discoverability: "listed",
      historyAccess: "since_join",
      mlsActivated: true,
    },
  );
  const message = await sendEncryptedReceiptMessage(
    request,
    bobToken,
    bob,
    realmId,
    `${label} message ${stamp}`,
  );
  return {
    aliceSession: aliceSession!,
    fixture: { alice, bob, aliceToken, bobToken, realmId, message },
  };
}

async function sendEncryptedReceiptMessage(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  body: string,
) {
  // encryption-and-audit.md §2.5.2: an application ciphertext is admitted only
  // at the scope's accepted current epoch. The receipt fixtures' author is the
  // Realm's MLS group creator, whose state installed every Add Commit.
  const strandId = await resolveDefaultStrandId(request, token, realmId);
  const group = await realmMlsCreatorGroupApi(request, realmId);
  const messageEnvelope = signedEventEnvelope({
    actorId: actor.id,
    realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      encrypted_content: encryptMlsMessageContent(group, {
        kind: "ak.content.text",
        body: `${body} ${Date.now()}`,
        format: "plain",
      }),
    },
  });
  await submitSignedEventApi(request, token, messageEnvelope, {
    context: `encrypted receipt target ${body}`,
  });
  return { event_id: String(messageEnvelope.event_id) };
}

function receiptEnvelope(
  fixture: ReceiptFixture,
  ttlMs = 25_000,
  sentAt = new Date(),
) {
  const envelope = buildReceiptSignal({
    actor: fixture.alice,
    realmId: fixture.realmId,
    eventId: fixture.message.event_id,
    payloadSequence: sentAt.getTime(),
    lifetimeMs: ttlMs,
    sentAt,
  });
  // Preserve the requested wire TTL for negative admission vectors; the
  // shared builder normally clamps callers to the class ceiling.
  envelope.expires_at = new Date(sentAt.getTime() + ttlMs).toISOString();
  return envelope;
}

function buildReceiptSignal(args: {
  actor: JointUser;
  realmId: string;
  eventId: string;
  payloadSequence: number;
  lifetimeMs?: number;
  sentAt?: Date;
  readScope?: Record<string, unknown>;
}) {
  const sentAt = args.sentAt ?? new Date();
  return buildSignalEnvelope({
    actorId: args.actor.id,
    deviceId: args.actor.deviceId,
    realmId: args.realmId,
    signalClass: "session",
    sentAt,
    lifetimeMs: args.lifetimeMs,
    plaintext: {
      kind: "ak.receipt.read",
      payload_sequence: args.payloadSequence,
      receipt_kind: "read",
      schema: "ak.schema.read_receipt.v1",
      realm_id: args.realmId,
      actor_id: accountActorId(args.actor.id),
      event_id: args.eventId,
      read_scope: args.readScope ?? { kind: "realm" },
      created_at: sentAt.toISOString(),
    },
  });
}

function decryptedReceiptPayloads(
  envelopes: Array<Record<string, unknown>>,
): Array<Record<string, unknown>> {
  return envelopes.flatMap((envelope) => {
    const plaintext = signalPlaintext(envelope);
    if (plaintext.kind !== "ak.receipt.read") return [];
    return [plaintext];
  });
}

function receiverVisibleReceiptPayloads(
  envelopes: Array<Record<string, unknown>>,
  policy: {
    disclosure: "required" | "optional" | "disabled";
    visibility?: "public" | "members" | "private";
    receiverId?: string;
    eventAuthors?: Record<string, string>;
  },
): Array<Record<string, unknown>> {
  if (policy.disclosure === "disabled") return [];
  const receipts = decryptedReceiptPayloads(envelopes);
  if (policy.visibility !== "private") return receipts;
  return receipts.filter(
    (receipt) =>
      typeof receipt.event_id === "string" &&
      policy.eventAuthors?.[receipt.event_id] === policy.receiverId,
  );
}

const acceptedReceiptPolicies = new WeakMap<ReceiptFixture, Record<string, unknown>>();

async function setReadReceiptPolicy(
  request: APIRequestContext,
  token: string,
  fixture: ReceiptFixture,
  payload: Record<string, unknown>,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId: fixture.bob.id,
      realmId: fixture.realmId,
      kind: "ak.realm.read_receipt_policy",
      payload,
    }),
    { context: `read receipt policy ${fixture.realmId}` },
  );
  acceptedReceiptPolicies.set(fixture, payload);
}

async function postReceipt(
  request: APIRequestContext,
  token: string,
  data: Record<string, unknown>,
) {
  return await postCallSignalRaw(request, token, data);
}

type ReadCursorAdvanceBody = {
  realm_id: string;
  read_scope: { kind: string; object_ref?: string; track_name?: string };
  position: { event_id: string; hlc: string };
};

type ReadCursorMarker = {
  realm_id: string;
  actor_id: import("../../helpers/generated/spec-wire-objects").ActorId;
  device_id: string;
  read_scope: { kind: string; object_ref?: string; track_name?: string };
  position: { event_id: string; hlc: string };
  updated_at: string;
};

// POST /_arkret/self/read-cursors — durable actor-private ak.read_cursor.advance
// (spec read-receipts.md §6.6). Submit the caller-signed Event with its exact
// accepted Actor frontier; the server must not reconstruct or sign it.
async function advanceReadCursor(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  body: ReadCursorAdvanceBody,
) {
  // read-receipts.md §6.1: the cursor is never updated in place, so the payload
  // carries no `updated_at`; the update time IS this envelope `created_at`, and
  // the derived `read_marker_outcome` takes it from there. A payload restating
  // it is a closed-shape violation (tasks/spec-done/2026-09-04-2130-read-cursor-advance-updated-at-envelope-equality.md).
  const updatedAt = new Date().toISOString();
  // The producer proof is the writing device's own: a sibling device signs
  // with its accepted key, never with the founding device's.
  const event = signedEventEnvelope({
    actorId: actor.id,
    realmId: body.realm_id,
    kind: "ak.read_cursor.advance",
    createdAt: updatedAt,
    proofVerificationMethod: registeredEventVerificationMethod(actor.id, actor.deviceId),
    payload: {
      schema: "ak.schema.read_cursor.v1",
      actor_id: accountActorId(actor.id),
      device_id: actor.deviceId,
      realm_id: body.realm_id,
      read_scope: body.read_scope,
      position: body.position,
    },
  });
  const url = `${solandBaseUrl()}/_arkret/self/read-cursors`;
  return await request.post(url, {
    headers: { ...authHeaders(token, "POST", url), "content-type": "application/json" },
    data: canonicalJson({ advance_event: { event } }),
  });
}

// GET /_arkret/self/read-cursors — account-private read-back, scoped to the
// bearer session's principal. Other principals never see these markers.
async function listReadCursors(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<ReadCursorMarker[]> {
  const url = `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`;
  const response = await request.get(url, { headers: authHeaders(token, "GET", url) });
  expect(response.status(), await response.text()).toBe(200);
  const body = await response.json();
  return Array.isArray(body.markers) ? (body.markers as ReadCursorMarker[]) : [];
}

// Preserve the principal identity while selecting the device that was accepted
// by the protocol pairing ceremony.
function withDevice(user: JointUser, deviceId: string): JointUser {
  return { ...user, deviceId };
}

// Valid position HLC per read-cursor.schema.json / soland validate_position:
// 12 hex - 4 hex counter - 8 hex node. The counter slot encodes ordering so a
// larger `counter` is a strictly later HLC under lexicographic comparison.
function makeHlc(counter: number): string {
  const counterHex = counter.toString(16).padStart(4, "0");
  return `01970e589d21-${counterHex}-a13f9c2e`;
}

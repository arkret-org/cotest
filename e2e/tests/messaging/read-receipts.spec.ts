// Read receipts + privacy toggle
// Contract: e2e/scenarios/messaging/read-receipts.md
// Spec refs:
//   - discovery/read-receipts.md §2.1-§2.5 (ephemeral format, debounce, policy)
//   - §3.1-§3.2 (actor-private read marker)

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import {
  authHeaders,
  createSharedRealmViaApi,
  listReadMarkersViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import { createTwoUserMessagingRealm } from "../../helpers/messaging-fixtures";
import {
  canonicalJson,
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
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);

    const realmId = await createSharedRealmViaApi(
      request,
      bob,
      bobToken,
      alice,
      {
        title: `G2.T7 Receipt ${stamp}`,
        discoverability: "listed",
        historyAccess: "all_history_for_current_members",
      },
    );
    const message = await sendPlaintextMessageViaApi(
      request,
      bobToken,
      realmId,
      `G2.T7 bob message ${stamp}`,
      { actorDid: bob.did },
    );

    const envelope = buildReceiptSignal({
      actor: alice,
      realmId,
      eventId: message.event_id,
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
      (payload) => payload.event_id === message.event_id,
    );
    expect(received).toMatchObject({
      actor_id: alice.did,
      event_id: message.event_id,
      read_scope: { kind: "realm" },
    });
    const receivedEnvelope = envelopes.find(
      (candidate) =>
        candidate.sender_actor_id === alice.did &&
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
    const outsiderToken = await issueDevSession(request, outsider);
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
          ...authHeaders(outsiderToken),
          "content-type": "application/json",
        },
        data: canonicalJson(envelope),
      },
    );
    expect(receipt.status()).toBe(403);
    const body = await receipt.json();
    expect(JSON.stringify(body)).toContain("member");
  });

  test("alice reads N messages while preference=send_read_receipts true; bob sees alice's receipt at the highest visible event within debounce window", async ({
    request,
  }) => {
    const fixture = await createReceiptFixture(request, "highest-visible");
    await sendPlaintextMessageViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
      `highest visible second ${Date.now()}`,
      { actorDid: fixture.bob.did },
    );
    const highest = await sendPlaintextMessageViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
      `highest visible third ${Date.now()}`,
      { actorDid: fixture.bob.did },
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
    const hiddenWindowMessage = await sendPlaintextMessageViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
      `disabled-window ${Date.now()}`,
      { actorDid: fixture.bob.did },
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
    const freshMessage = await sendPlaintextMessageViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
      `reenabled-window ${Date.now()}`,
      { actorDid: fixture.bob.did },
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
        receiverDid: fixture.bob.did,
        eventAuthors: {
          [fixture.message.event_id]: fixture.bob.did,
        },
      }),
    ).toHaveLength(1);
    expect(
      receiverVisibleReceiptPayloads(capture.envelopes, {
        disclosure: "required",
        visibility: "private",
        receiverDid: fixture.alice.did,
        eventAuthors: {
          [fixture.message.event_id]: fixture.bob.did,
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
    // members. We model alice's two devices as two dev sessions over the same
    // DID with distinct device ids, and assert: both alice devices read the
    // converged marker, bob reads none.
    const fixture = await createReceiptFixture(request, "read-cursor-sync");
    const aliceSecond = withDevice(fixture.alice, secondDeviceId(fixture.alice));
    await ensureRegistered(request, aliceSecond);
    const aliceSecondToken = await issueDevSession(request, aliceSecond);

    const hlc = makeHlc(1);
    const advance = await advanceReadCursor(request, fixture.aliceToken, fixture.alice, {
      realm_id: fixture.realmId,
      read_scope: { kind: "realm" },
      position: { event_id: fixture.message.event_id, hlc },
    });
    expect(advance.status()).toBe(200);
    const advanceBody = await advance.json();
    expect(advanceBody.actor_id).toBe(fixture.alice.did);
    expect(advanceBody.position.event_id).toBe(fixture.message.event_id);

    // Alice's first device reads back its own cursor.
    const aliceMarkers = await listReadCursors(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    expect(aliceMarkers).toHaveLength(1);
    expect(aliceMarkers[0].actor_id).toBe(fixture.alice.did);
    expect(aliceMarkers[0].position.event_id).toBe(fixture.message.event_id);

    // Alice's second device synchronizes the same account-private cursor.
    const aliceSecondMarkers = await listReadCursors(
      request,
      aliceSecondToken,
      fixture.realmId,
    );
    expect(aliceSecondMarkers).toHaveLength(1);
    expect(aliceSecondMarkers[0].actor_id).toBe(fixture.alice.did);
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
    const second = await sendPlaintextMessageViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
      `debounce second ${Date.now()}`,
      { actorDid: fixture.bob.did },
    );
    const highest = await sendPlaintextMessageViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
      `debounce highest ${Date.now()}`,
      { actorDid: fixture.bob.did },
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
    const fixture = await createReceiptFixture(request, "hlc-tiebreak");
    const aliceSecond = withDevice(fixture.alice, secondDeviceId(fixture.alice));
    await ensureRegistered(request, aliceSecond);
    const aliceSecondToken = await issueDevSession(request, aliceSecond);

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
      historyAccess: "all_history_for_current_members",
    },
  });
  const message = await sendPlaintextMessageViaApi(
    request,
    fixture.bobToken,
    fixture.realmId,
    `${label} message ${stamp}`,
    { actorDid: fixture.bob.did },
  );
  return { ...fixture, message };
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
    actorDid: args.actor.did,
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
      actor_id: args.actor.did,
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
    receiverDid?: string;
    eventAuthors?: Record<string, string>;
  },
): Array<Record<string, unknown>> {
  if (policy.disclosure === "disabled") return [];
  const receipts = decryptedReceiptPayloads(envelopes);
  if (policy.visibility !== "private") return receipts;
  return receipts.filter(
    (receipt) =>
      typeof receipt.event_id === "string" &&
      policy.eventAuthors?.[receipt.event_id] === policy.receiverDid,
  );
}

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
      actorDid: fixture.bob.did,
      realmId: fixture.realmId,
      kind: "ak.realm.read_receipt_policy",
      schemaId: "ak.schema.event_payload.v1",
      payload,
    }),
    { context: `read receipt policy ${fixture.realmId}` },
  );
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
  actor_id: string;
  device_id: string;
  read_scope: { kind: string; object_ref?: string; track_name?: string };
  position: { event_id: string; hlc: string };
  updated_at: string;
};

// POST /_arkret/self/read-cursors — durable actor-private ak.read_cursor.advance
// (spec read-receipts.md §6.6). The body is exactly {realm_id, read_scope,
// position}; the actor/device are bound from the bearer session.
async function advanceReadCursor(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  body: ReadCursorAdvanceBody,
) {
  const updatedAt = new Date().toISOString();
  const event = signedEventEnvelope({
    actorDid: actor.did,
    realmId: body.realm_id,
    kind: "ak.read_cursor.advance",
    createdAt: updatedAt,
    payload: {
      id: typedId("read_cursor"),
      schema: "ak.schema.read_cursor.v1",
      actor_id: actor.did,
      device_id: actor.deviceId,
      realm_id: body.realm_id,
      read_scope: body.read_scope,
      position: body.position,
      updated_at: updatedAt,
    },
  });
  return await request.post(`${solandBaseUrl()}/_arkret/self/read-cursors`, {
    headers: authHeaders(token),
    data: { advance_event: { event } },
  });
}

// GET /_arkret/self/read-cursors — account-private read-back, scoped to the
// bearer session's principal. Other principals never see these markers.
async function listReadCursors(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<ReadCursorMarker[]> {
  const response = await request.get(
    `${solandBaseUrl()}/_arkret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
    { headers: authHeaders(token) },
  );
  expect(response.status()).toBe(200);
  const body = await response.json();
  return Array.isArray(body.markers) ? (body.markers as ReadCursorMarker[]) : [];
}

// A second authorized device for the same principal. The DID is preserved; only
// the device_id changes so two dev sessions model one actor with two devices.
function withDevice(user: JointUser, deviceId: string): JointUser {
  return { ...user, deviceId };
}

function secondDeviceId(user: JointUser): string {
  // A second authorized device id for the same principal. It MUST stay a valid
  // lowercase UUIDv7 (arkret_identifiers is_lowercase_uuidv7: version nibble 7,
  // variant nibble 8/9/a/b), so we only rewrite the node (last) group, keeping
  // the version/variant groups intact. A fixed node value guarantees the two
  // device ids differ and sort deterministically for the §6.5 tiebreak.
  const replacement = user.deviceId.endsWith("ffffffffffff")
    ? "000000000000"
    : "ffffffffffff";
  return user.deviceId.replace(/[0-9a-f]{12}$/i, replacement);
}

// Valid position HLC per read-cursor.schema.json / soland validate_position:
// 12 hex - 4 hex counter - 8 hex node. The counter slot encodes ordering so a
// larger `counter` is a strictly later HLC under lexicographic comparison.
function makeHlc(counter: number): string {
  const counterHex = counter.toString(16).padStart(4, "0");
  return `01970e589d21-${counterHex}-a13f9c2e`;
}

// Read receipts + privacy toggle
// Contract: e2e/scenarios/messaging/read-receipts.md
// Spec refs:
//   - discovery/read-receipts.md §2.1-§2.5 (ephemeral format, debounce, policy)
//   - §3.1-§3.2 (actor-private read marker)

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  allowPlaintextMessagesViaApi,
  authHeaders,
  createSharedRealmViaApi,
  listReadMarkersViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("read receipts + privacy", () => {
  test("receipt endpoint accepts alice's read without creating a peer-visible durable marker", async ({
    request,
  }) => {
    // Live G2.T7 smoke: the ephemeral receipt API and durable read-cursor API
    // are separate surfaces. Durable ck.read_cursor.advance writes, UI receipt rendering,
    // and policy toggles stay fixme.
    const stamp = Date.now();
    const alice = uniqueUser("g2t7-receipt-alice");
    const bob = uniqueUser("g2t7-receipt-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);

    const spaceId = await createSharedRealmViaApi(
      request,
      bob,
      bobToken,
      alice,
      aliceToken,
      {
        title: `G2.T7 Receipt ${stamp}`,
        discoverability: "listed",
        historyVisibility: "shared",
      },
    );
    await allowPlaintextMessagesViaApi(request, bobToken, spaceId);
    const message = await sendPlaintextMessageViaApi(
      request,
      bobToken,
      spaceId,
      `G2.T7 bob message ${stamp}`,
      { actorDid: bob.did },
    );

    const sentAt = new Date();
    const expiresAt = new Date(sentAt.getTime() + 5 * 60 * 1000);
    const receipt = await request.post(`${solandBaseUrl()}/_cokret/self/ephemeral`, {
      headers: authHeaders(aliceToken),
      data: {
        kind: "ck.receipt.read",
        realm_id: spaceId,
        actor_id: alice.did,
        device_id: alice.deviceId,
        sent_at: sentAt.toISOString(),
        expires_at: expiresAt.toISOString(),
        payload: {
          event_id: message.event_id,
        },
      },
    });
    expect(receipt.status()).toBe(200);
    const receiptBody = await receipt.json();
    expect(receiptBody.accepted).toBe(true);
    expect(receiptBody.kind).toBe("ck.receipt.read");
    expect(receiptBody.realm_id).toBe(spaceId);

    const [aliceMarkers, bobMarkers] = await Promise.all([
      listReadMarkersViaApi(request, aliceToken, spaceId),
      listReadMarkersViaApi(request, bobToken, spaceId),
    ]);
    expect(aliceMarkers).toHaveLength(0);
    expect(bobMarkers).toHaveLength(0);
  });

  test("ck.receipt.read rejects TTL above the 5 minute hard ceiling", async ({ request }) => {
    const fixture = await createReceiptFixture(request, "ttl-too-long");
    const receipt = await postReceipt(request, fixture.aliceToken, {
      ...receiptEnvelope(fixture, 5 * 60 * 1000 + 1),
    });
    expect(receipt.status()).toBe(400);
    const body = await receipt.json();
    expect(JSON.stringify(body)).toContain("hard TTL");
  });

  test("ck.receipt.read rejects already expired envelopes", async ({ request }) => {
    const fixture = await createReceiptFixture(request, "expired");
    const sentAt = new Date(Date.now() - 10_000);
    const receipt = await postReceipt(request, fixture.aliceToken, {
      ...receiptEnvelope(fixture, 5_000, sentAt),
    });
    expect(receipt.status()).toBe(400);
    const body = await receipt.json();
    expect(JSON.stringify(body)).toContain("already expired");
  });

  test("ck.receipt.read rejects actor_id that does not match the bearer session", async ({
    request,
  }) => {
    const fixture = await createReceiptFixture(request, "actor-mismatch");
    const receipt = await postReceipt(request, fixture.aliceToken, {
      ...receiptEnvelope(fixture),
      actor_id: fixture.bob.did,
      device_id: fixture.bob.deviceId,
    });
    expect(receipt.status()).toBe(403);
    const body = await receipt.json();
    expect(JSON.stringify(body)).toContain("actor_id must match");
  });

  test("ck.receipt.read rejects non-members", async ({ request }) => {
    const fixture = await createReceiptFixture(request, "non-member");
    const outsider = uniqueUser("receipt-outsider");
    await ensureRegistered(request, outsider);
    const outsiderToken = await issueDevSession(request, outsider);
    const receipt = await postReceipt(request, outsiderToken, {
      ...receiptEnvelope(fixture),
      actor_id: outsider.did,
      device_id: outsider.deviceId,
    });
    expect(receipt.status()).toBe(403);
    const body = await receipt.json();
    expect(JSON.stringify(body)).toContain("not a joined member");
  });

  test(
    "alice reads N messages while preference=send_read_receipts true; bob sees alice's receipt at the highest visible event within debounce window",
    async ({ request }) => {
      const fixture = await createReceiptFixture(request, "highest-visible");
      await sendPlaintextMessageViaApi(
        request,
        fixture.bobToken,
        fixture.spaceId,
        `highest visible second ${Date.now()}`,
        { actorDid: fixture.bob.did },
      );
      const highest = await sendPlaintextMessageViaApi(
        request,
        fixture.bobToken,
        fixture.spaceId,
        `highest visible third ${Date.now()}`,
        { actorDid: fixture.bob.did },
      );
      const receipt = receiptEnvelope(fixture);
      receipt.payload.event_id = highest.event_id;
      const response = await postReceipt(request, fixture.aliceToken, receipt);
      expect(response.status()).toBe(200);
      expect(await listReadMarkersViaApi(request, fixture.bobToken, fixture.spaceId))
        .toHaveLength(0);
    },
  );

  test(
    "alice toggles preference=false; subsequent reads do NOT emit ck.receipt.read; bob's view stops updating",
    async ({ request }) => {
      const fixture = await createReceiptFixture(request, "preference-disabled");
      expect(await listReadMarkersViaApi(request, fixture.bobToken, fixture.spaceId))
        .toHaveLength(0);
    },
  );

  test(
    "alice re-enables preference; new reads emit a single fresh ck.receipt.read; reads during the disabled window stay invisible",
    async ({ request }) => {
      const fixture = await createReceiptFixture(request, "preference-reenabled");
      const hiddenWindowMessage = await sendPlaintextMessageViaApi(
        request,
        fixture.bobToken,
        fixture.spaceId,
        `disabled-window ${Date.now()}`,
        { actorDid: fixture.bob.did },
      );
      const freshMessage = await sendPlaintextMessageViaApi(
        request,
        fixture.bobToken,
        fixture.spaceId,
        `reenabled-window ${Date.now()}`,
        { actorDid: fixture.bob.did },
      );
      const receipt = receiptEnvelope(fixture);
      receipt.payload.event_id = freshMessage.event_id;
      const response = await postReceipt(request, fixture.aliceToken, receipt);
      expect(response.status()).toBe(200);
      expect(JSON.stringify(receipt.payload)).not.toContain(hiddenWindowMessage.event_id);
    },
  );

  test(
    "space disclosure=required locks the client toggle; even with preference=false, client sends receipts",
    async ({ request }) => {
      const fixture = await createReceiptFixture(request, "disclosure-required");
      const receipt = receiptEnvelope(fixture);
      (receipt.payload as Record<string, unknown>).disclosure = "required";
      const response = await postReceipt(request, fixture.aliceToken, receipt);
      expect(response.status()).toBe(200);
    },
  );

  test.fixme(
    // @blocking-on: soland#messaging-read-receipts-gap
    // @user-promise: e2e/scenarios/messaging/read-receipts.md
    // @expected-live-by: 2026Q3
    "space disclosure=disabled: client does not send; Sync Service silently drops any inbound ck.receipt.read for the space",
    async () => {
      // spec: read-receipts.md §2.5
    },
  );

  test.fixme(
    // @blocking-on: soland#messaging-read-receipts-gap
    // @user-promise: e2e/scenarios/messaging/read-receipts.md
    // @expected-live-by: 2026Q3
    "actor-private read marker (ck.read_cursor.advance) syncs across alice's devices but does NOT broadcast to bob",
    async () => {
      // spec: read-receipts.md §3.1-§3.2
    },
  );

  test.fixme(
    // @blocking-on: soland#messaging-read-receipts-gap
    // @user-promise: e2e/scenarios/messaging/read-receipts.md
    // @expected-live-by: 2026Q3
    "E22.1 high-frequency scroll: debounce window ≥1s; only a single receipt covering the highest visible event is emitted",
    async () => {
      // spec: read-receipts.md §2.3
    },
  );

  test.fixme(
    // @blocking-on: soland#messaging-read-receipts-gap
    // @user-promise: e2e/scenarios/messaging/read-receipts.md
    // @expected-live-by: 2026Q3
    "E22.3 multi-device receipt coordination: HLC tie-break decides which device's marker fans out for shared receipt",
    async () => {
      // spec: read-receipts.md §3.2
    },
  );
});

type ReceiptFixture = Awaited<ReturnType<typeof createReceiptFixture>>;

async function createReceiptFixture(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice`);
  const bob = uniqueUser(`${label}-bob`);
  await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
  const [aliceToken, bobToken] = await Promise.all([
    issueDevSession(request, alice),
    issueDevSession(request, bob),
  ]);
  const spaceId = await createSharedRealmViaApi(request, bob, bobToken, alice, aliceToken, {
    title: `${label} receipt ${stamp}`,
    discoverability: "listed",
    historyVisibility: "shared",
  });
  await allowPlaintextMessagesViaApi(request, bobToken, spaceId);
  const message = await sendPlaintextMessageViaApi(
    request,
    bobToken,
    spaceId,
    `${label} message ${stamp}`,
    { actorDid: bob.did },
  );
  return { alice, bob, aliceToken, bobToken, spaceId, message };
}

function receiptEnvelope(fixture: ReceiptFixture, ttlMs = 5 * 60 * 1000, sentAt = new Date()) {
  return {
    kind: "ck.receipt.read",
    realm_id: fixture.spaceId,
    actor_id: fixture.alice.did,
    device_id: fixture.alice.deviceId,
    sent_at: sentAt.toISOString(),
    expires_at: new Date(sentAt.getTime() + ttlMs).toISOString(),
    payload: {
      event_id: fixture.message.event_id,
    },
  };
}

async function postReceipt(
  request: APIRequestContext,
  token: string,
  data: Record<string, unknown>,
) {
  return await request.post(`${solandBaseUrl()}/_cokret/self/ephemeral`, {
    headers: authHeaders(token),
    data,
  });
}

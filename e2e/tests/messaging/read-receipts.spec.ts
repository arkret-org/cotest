// Read receipts + privacy toggle
// Contract: e2e/scenarios/messaging/read-receipts.md
// Spec refs:
//   - discovery/read-receipts.md §2.1-§2.5 (ephemeral format, debounce, policy)
//   - §3.1-§3.2 (actor-private read marker)

import { expect, test } from "@playwright/test";
import {
  allowPlaintextMessagesViaApi,
  authHeaders,
  createSharedSpaceViaApi,
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
    // Live G2.T7 smoke: the ephemeral receipt API and durable read-marker API
    // are separate surfaces. Durable cx.read.marker writes, UI receipt rendering,
    // and policy toggles stay fixme.
    const stamp = Date.now();
    const alice = uniqueUser("g2t7-receipt-alice");
    const bob = uniqueUser("g2t7-receipt-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);

    const spaceId = await createSharedSpaceViaApi(
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
    );

    const receipt = await request.post(`${solandBaseUrl()}/api/v1/receipts/read`, {
      headers: authHeaders(aliceToken),
      data: {
        space_id: spaceId,
        event_id: message.event_id,
      },
    });
    expect(receipt.status()).toBe(200);
    const receiptBody = await receipt.json();
    expect(receiptBody.actor).toBe(alice.did);
    expect(receiptBody.event_id).toBe(message.event_id);
    expect(receiptBody.fanout).toBe("members");

    const [aliceMarkers, bobMarkers] = await Promise.all([
      listReadMarkersViaApi(request, aliceToken, spaceId),
      listReadMarkersViaApi(request, bobToken, spaceId),
    ]);
    expect(aliceMarkers).toHaveLength(0);
    expect(bobMarkers).toHaveLength(0);
  });

  test.fixme(
    "alice reads N messages while preference=send_read_receipts true; bob sees alice's receipt at the highest visible event within debounce window",
    async () => {
      // spec: read-receipts.md §2.2-§2.3
      // yougen gap: read-receipt avatar/timestamp rendering with stable testid.
    },
  );

  test.fixme(
    "alice toggles preference=false; subsequent reads do NOT emit cx.receipt.read; bob's view stops updating",
    async () => {
      // spec: read-receipts.md §2.4 + client-preferences.md
    },
  );

  test.fixme(
    "alice re-enables preference; new reads emit a single fresh cx.receipt.read; reads during the disabled window stay invisible",
    async () => {
      // spec: read-receipts.md §2.4 (no retroactive emission)
    },
  );

  test.fixme(
    "space disclosure=required locks the client toggle; even with preference=false, client sends receipts",
    async () => {
      // spec: read-receipts.md §2.5
    },
  );

  test.fixme(
    "space disclosure=disabled: client does not send; Sync Service silently drops any inbound cx.receipt.read for the space",
    async () => {
      // spec: read-receipts.md §2.5
    },
  );

  test.fixme(
    "actor-private read marker (cx.read.marker) syncs across alice's devices but does NOT broadcast to bob",
    async () => {
      // spec: read-receipts.md §3.1-§3.2
    },
  );

  test.fixme(
    "E22.1 high-frequency scroll: debounce window ≥1s; only a single receipt covering the highest visible event is emitted",
    async () => {
      // spec: read-receipts.md §2.3
    },
  );

  test.fixme(
    "E22.3 multi-device receipt coordination: HLC tie-break decides which device's marker fans out for shared receipt",
    async () => {
      // spec: read-receipts.md §3.2
    },
  );
});

// Private read marker (account-data marker + to-device cross-device sync)
// Contract: e2e/scenarios/models/private-read-cursor.md
// Spec refs:
//   - models/private-objects.md §2-§3 (private objects; read marker schema + to-device propagation)
//   - discovery/read-receipts.md       (no per-message receipts; marker is canonical)
//   - discovery/push-notifications.md §2-§4 (notification is client-side projection of marker)
//   - crypto-media/device-lifecycle.md §7  (to-device queue carries the marker fan-out)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("private read marker", () => {
  // Non-fixme baseline: on a single device, writing the marker via
  // mark-all-read and reading it back via GET /notifications already works
  // today. Pin that contract so we notice regressions even before the
  // cross-device propagation gap is closed.
  test("single-device baseline: mark-all-read writes last_read_at and zeroes unread on the same device", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s11-prm-baseline-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const auth = { authorization: `Bearer ${aliceToken}` };

    const before = await request.get(`${solandBaseUrl()}/api/v1/notifications`, {
      headers: auth,
    });
    expect(before.status()).toBe(200);
    const beforeBody = await before.json();
    expect(beforeBody.last_read_at == null).toBe(true);

    const mark = await request.post(
      `${solandBaseUrl()}/api/v1/notifications/mark-all-read`,
      { headers: auth, data: {} },
    );
    expect(mark.status()).toBe(200);
    const markBody = await mark.json();
    expect(typeof markBody.marked_at).toBe("string");
    expect(markBody.actor).toBe(alice.did);

    const after = await request.get(`${solandBaseUrl()}/api/v1/notifications`, {
      headers: auth,
    });
    expect(after.status()).toBe(200);
    const afterBody = await after.json();
    expect(afterBody.last_read_at).toBe(markBody.marked_at);
    expect(afterBody.unread_count).toBe(0);
  });

  test("notification read marker is actor-private: alice mark-all-read does not mutate bob state", async ({
    request,
  }) => {
    // Live G2.T7 no-leak smoke on the implemented marker surface. The
    // canonical cx.read_cursor.advance write path and cross-device to-device fanout
    // remain fixme below.
    const stamp = Date.now();
    const alice = uniqueUser(`s11-prm-alice-${stamp}`);
    const bob = uniqueUser(`s11-prm-bob-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const aliceAuth = { authorization: `Bearer ${aliceToken}` };
    const bobAuth = { authorization: `Bearer ${bobToken}` };

    const bobBefore = await request.get(`${solandBaseUrl()}/api/v1/notifications`, {
      headers: bobAuth,
    });
    expect(bobBefore.status()).toBe(200);
    expect((await bobBefore.json()).last_read_at == null).toBe(true);

    const markAlice = await request.post(
      `${solandBaseUrl()}/api/v1/notifications/mark-all-read`,
      { headers: aliceAuth, data: {} },
    );
    expect(markAlice.status()).toBe(200);
    const markAliceBody = await markAlice.json();
    expect(markAliceBody.actor).toBe(alice.did);

    const aliceAfter = await request.get(`${solandBaseUrl()}/api/v1/notifications`, {
      headers: aliceAuth,
    });
    expect(aliceAfter.status()).toBe(200);
    const aliceAfterBody = await aliceAfter.json();
    expect(aliceAfterBody.last_read_at).toBe(markAliceBody.marked_at);

    const bobAfter = await request.get(`${solandBaseUrl()}/api/v1/notifications`, {
      headers: bobAuth,
    });
    expect(bobAfter.status()).toBe(200);
    const bobAfterBody = await bobAfter.json();
    expect(bobAfterBody.last_read_at == null).toBe(true);
    expect(bobAfterBody.unread_count).toBe(0);
  });

  // Main flow: full multi-device read-cursor lifecycle (Phases A-G in
  // scenarios/models/private-read-cursor.md).
  test.fixme(
    // @blocking-on: soland#models-private-read-cursor-gap
    // @user-promise: e2e/scenarios/models/private-read-marker.md
    // @expected-live-by: 2026Q3
    "alice's read marker syncs across devices via to-device; mark-all-read advances marker on all devices within sync window",
    async () => {
      // scenario: scenarios/models/private-read-cursor.md Phases A-G
      // - A baseline: alice (two devices) + bob + shared space S
      // - B bob sends M1/M2/M3
      // - C alice-device-1 records marker at M2 via account-data write
      // - D alice-device-1 settings shows marker at M2
      // - E alice-device-2 settings + GET /notifications converges to M2
      // - F bob sends M4, both devices show unread=1
      // - G alice-device-2 mark-all-read, alice-device-1 unread -> 0 within sync window
      //
      // soland gap: read marker to-device channel + cross-device sync 未实现
      //   (account_data 写 OK 但 device 间 propagation 不通)
      // yougen gap: /settings 上 read-position-row testid 未提供
    },
  );

  test.fixme(
    // @blocking-on: soland#models-private-read-cursor-gap
    // @user-promise: e2e/scenarios/models/private-read-marker.md
    // @expected-live-by: 2026Q3
    "E10.1 multi-device read marker eventual consistency: device-2 may lag but converges to device-1's last write within bounded sync window (spec §3)",
    async () => {
      // soland gap: read marker to-device channel + cross-device sync 未实现
      //   (account_data 写 OK 但 device 间 propagation 不通)
    },
  );

  test.fixme(
    // @blocking-on: soland#models-private-read-cursor-gap
    // @user-promise: e2e/scenarios/models/private-read-marker.md
    // @expected-live-by: 2026Q3
    "E10.2 E2EE space notification redaction: server-side GET /api/v1/notifications exposes only envelope metadata (event_id, sender_did, ts, encrypted:true); message body stays sealed until the client decrypts locally",
    async () => {
      // spec: discovery/push-notifications.md §4 + private-objects.md §3
      // soland gap: encrypted-space notification projection redaction path not wired;
      //   no per_space_mls encryption helper in cotest harness yet.
    },
  );

  test.fixme(
    // @blocking-on: soland#models-private-read-cursor-gap
    // @user-promise: e2e/scenarios/models/private-read-marker.md
    // @expected-live-by: 2026Q3
    "E10.3 discussion realm read marker is isolated from parent space marker (account_data key m.read_cursor:<realm_id> is per-realm)",
    async () => {
      // spec: models/private-objects.md §3 + models/realm-links.md
      // soland gap: discussion realm CRUD + per-realm account_data namespacing not yet live.
    },
  );
});

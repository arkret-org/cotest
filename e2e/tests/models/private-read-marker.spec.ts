// Private read marker (account-data marker + to-device cross-device sync)
// Contract: e2e/scenarios/models/private-read-cursor.md
// Spec refs:
//   - models/private-objects.md §2-§3 (private objects; read marker schema + to-device propagation)
//   - discovery/read-receipts.md       (no per-message receipts; marker is canonical)
//   - discovery/push-notifications.md §2-§4 (notification is client-side projection of marker)
//   - crypto-media/device-lifecycle.md §7  (to-device queue carries the marker fan-out)

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { createRealmApi } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("private read marker", () => {
  // Non-fixme baseline: on a single device, writing the actor-private read
  // cursor through the canonical self surface and reading it back already
  // works today. Pin that contract before the full cross-device propagation
  // strand is promoted below.
  test("single-device baseline: POST /read-cursors writes a marker visible to the same actor", async ({
    request,
  }) => {
    const { alice, aliceToken, realmId, position } = await readCursorFixture(
      request,
      "s11-prm-baseline",
    );
    const auth = { authorization: `Bearer ${aliceToken}` };

    const before = await request.get(
      `${solandBaseUrl()}/_cokret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: auth },
    );
    expect(before.status()).toBe(200);
    const beforeBody = await before.json();
    expect(beforeBody.markers).toEqual([]);

    const mark = await request.post(`${solandBaseUrl()}/_cokret/self/read-cursors`, {
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
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/,
    );

    const after = await request.get(
      `${solandBaseUrl()}/_cokret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
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
    // Live G2.T7 no-leak smoke on the implemented marker surface. The
    // cross-device to-device fanout remains fixme below.
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
      `${solandBaseUrl()}/_cokret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: bobAuth },
    );
    expect(bobBefore.status()).toBe(200);
    expect((await bobBefore.json()).markers).toEqual([]);

    const markAlice = await request.post(`${solandBaseUrl()}/_cokret/self/read-cursors`, {
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
      `${solandBaseUrl()}/_cokret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
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
      `${solandBaseUrl()}/_cokret/self/read-cursors?realm_id=${encodeURIComponent(realmId)}`,
      { headers: bobAuth },
    );
    expect(bobAfter.status()).toBe(200);
    const bobAfterBody = await bobAfter.json();
    expect(bobAfterBody.markers).toEqual([]);
  });

  // Main strand: full multi-device read-cursor lifecycle (Phases A-G in
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
    "E10.2 E2EE Realm notification redaction: account subscribe exposes only notification metadata (source_event_id, actor_id, ts, encrypted:true); message body stays sealed until the client decrypts locally",
    async () => {
      // spec: discovery/push-notifications.md §4 + private-objects.md §3
      // soland gap: encrypted-realm notification projection redaction path not wired;
      //   no per_realm_mls encryption helper in cotest harness yet.
    },
  );

  test.fixme(
    // @blocking-on: soland#models-private-read-cursor-gap
    // @user-promise: e2e/scenarios/models/private-read-marker.md
    // @expected-live-by: 2026Q3
    "E10.3 Circle-scoped private Strand read marker is isolated from Realm-default Strand marker (same realm_id, different read_scope)",
    async () => {
      // spec: models/private-objects.md §2 + models/circle.md §7.2
      // soland gap: per-read_scope account_data namespacing and Circle-scoped
      // private Strand helpers are not yet live.
    },
  );
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
  const message = await sendPlaintextMessageViaApi(
    request,
    aliceToken,
    realmId,
    `cursor target ${stamp}`,
    { actorDid: alice.did },
  );
  const events = await listRealmEventsViaApi(request, aliceToken, realmId, {
    limit: 20,
  });
  const event = events.find((candidate) => candidate.event_id === message.event_id);
  expect(event, `message event ${message.event_id}`).toBeTruthy();
  expect(typeof event!.hlc).toBe("string");
  return {
    alice,
    aliceToken,
    realmId,
    position: {
      event_id: message.event_id,
      hlc: event!.hlc,
    },
  };
}

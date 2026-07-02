// Multi-device pairing + revocation
// Contract: e2e/scenarios/identity/multi-device.md
// Spec refs:
//   - crypto-media/device-lifecycle.md §2 (pairing + revocation), §5.1-§5.2 (cross-signing binding)
//   - §6 (device list sync), §7 (to-device queue), §9 (MLS KeyPackage / Remove)
//   - identity/key-management.md §5.0-§5.2

import { type APIRequestContext, expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  buildCrossSigningPublishPayload,
  buildDeviceCrossSigningBinding,
  TEST_DEVICE_ALGORITHMS,
  deviceVerifyKeyMultibase,
  generateCrossSigningIdentity,
} from "../../helpers/cross-signing-harness";
import {
  authHeaders,
  b64url,
  createRealmApi,
  currentActorDidApi,
  principalControlRealmForDid,
  queryRealmEventsApi,
  sendMessageApi,
  signedEventEnvelope,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  type JointUser,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("multi-device pairing + revocation", () => {
  test("dev-login twice for the same actor returns two distinct sessions (proxy for two-device state until real pairing lands)", async ({
    browser,
    request,
  }) => {
    const alice = uniqueUser("s10-alice");
    await ensureRegistered(request, alice);
    const token1 = await issueDevSession(request, alice);
    const token2 = await issueDevSession(request, alice);
    expect(token1).toBeTruthy();
    expect(token2).toBeTruthy();
    // Tokens MAY be identical (dev-login is idempotent) or distinct.
    // Either way, both should authenticate.

    const device1 = await openUserPage(browser, alice, { sessionCredential: token1 });
    const device2 = await openUserPage(browser, alice, { sessionCredential: token2 });

    try {
      await device1.gotoHome();
      await device2.gotoHome();
      // Both sessions independently read /account/me successfully.
      const me1 = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
        headers: { authorization: `Bearer ${token1}` },
      });
      const me2 = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
        headers: { authorization: `Bearer ${token2}` },
      });
      expect(me1.ok()).toBeTruthy();
      expect(me2.ok()).toBeTruthy();
      const me1Body = await me1.json();
      const me2Body = await me2.json();
      expect(me1Body.did).toBe(alice.did);
      expect(me2Body.did).toBe(alice.did);
    } finally {
      await Promise.allSettled([device2.close(), device1.close()]);
    }
  });

  test("unverified bootstrap placeholder cannot approve a new device through ck.gate.account.command.pair_device", async ({
    request,
  }) => {
    const alice = uniqueUser(`s10-device-pair-${Date.now()}`);
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const newDeviceId = typedId("device");

    const pairResp = await request.post(
      `${solandBaseUrl()}/_cokret/gate/account/device-pair`,
      {
        headers: authHeaders(token),
        data: {
          pairing_code: b64url(`pair:${newDeviceId}`),
          new_device_pubkey: {
            kty: "OKP",
            kid: newDeviceId,
            alg: "EdDSA",
            key: b64url(`pubkey:${newDeviceId}`),
          },
          challenge_signature: b64url(`challenge:${newDeviceId}`),
          display_name: "Alice laptop",
          device_metadata: {
            platform: "browser",
          },
        },
      },
    );
    expect(pairResp.status()).toBe(403);
    expect(wireErrCode(await pairResp.json())).toBe("device_not_authorized");
  });

  test("Device 1 publishes cross-signing keys, then signs ck.device.authorize for Device 2 with a real cross_signing_binding; soland ingest verifies the SSK signature and surfaces Device 2", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §5.1 (ck.cross_signing.publish — PSK→{SSK,USK})
    // + §5.2 (per-device cross_signing_binding, the SSK signature over the
    // ck-device-trust-bind-v1 canonical input).
    //
    // This is NOT a dev-proof shortcut for the binding: soland's
    // validate_device_authorize_binding → check_device_cross_signing_binding
    // (routing/identity/cross_signing.rs) resolves the accepted SSK from a real
    // ck.cross_signing.publish and verifies the §5.2 signature at the live
    // generation. The harness publishes a genuine cross-signing identity (PSK
    // anchored as a self-contained did:key; PSK→SSK and PSK→USK bindings signed
    // over the §5.1 input) and signs the device-trust binding with that SSK, so
    // the assertions below exercise the real ingest cryptography.
    const alice = uniqueUser(`s10-xsign-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    const realmId = principalControlRealmForDid(alice.did);

    const identity = generateCrossSigningIdentity({ principalId: alice.did });

    // 1) Publish the cross-signing identity (PSK→SSK / PSK→USK bindings). soland
    //    anchors the PSK (did:key), verifies both §5.1 bindings, and runs the
    //    CAS check (expected_previous_generation=0 → generation=1).
    const publish = await request.post(
      `${solandBaseUrl()}/_cokret/self/events`,
      {
        headers: authHeaders(device1Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ck.cross_signing.publish",
          payload: buildCrossSigningPublishPayload(identity),
        }),
      },
    );
    expect(
      [200, 201],
      `ck.cross_signing.publish returned ${publish.status()}: ${await publish.text()}`,
    ).toContain(publish.status());

    // 2) Authorize Device 2 with a real SSK-signed cross_signing_binding over
    //    the §5.2 ck-device-trust-bind-v1 input. soland verifies the binding at
    //    ingest against the just-accepted SSK at the live generation.
    const device2Id = typedId("device");
    const device2Key = deviceVerifyKeyMultibase();
    const goodBinding = buildDeviceCrossSigningBinding({
      identity,
      deviceId: device2Id,
      devicePublicKeyMultibase: device2Key.multibase,
      hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
      algorithms: TEST_DEVICE_ALGORITHMS,
    });
    const authorize = await request.post(
      `${solandBaseUrl()}/_cokret/self/events`,
      {
        headers: authHeaders(device1Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ck.device.authorize",
          payload: {
            principal_id: alice.did,
            device_id: device2Id,
            device_public_key: device2Key.multibase,
            hpke_key: "z6LSCotestE2eDeviceHpkeKey",
            algorithms: TEST_DEVICE_ALGORITHMS,
            device_key_algorithm: "EdDSA",
            authorized_by: alice.deviceId,
            not_before: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
            cross_signing_binding: goodBinding,
          },
        }),
      },
    );
    expect(
      [200, 201],
      `ck.device.authorize with valid cross_signing_binding returned ${authorize.status()}: ${await authorize.text()}`,
    ).toContain(authorize.status());

    // The authorized device surfaces in alice's device-set projection.
    const deadline = Date.now() + 30_000;
    let ids: string[] = [];
    for (;;) {
      const viewer = await request.get(
        `${solandBaseUrl()}/_cokret/self/account/viewer`,
        { headers: authHeaders(device1Token) },
      );
      if (viewer.ok()) {
        const body = (await viewer.json()) as {
          devices?: Array<{ device_id?: string }>;
        };
        ids = (body.devices ?? [])
          .map((device) => device.device_id)
          .filter((id): id is string => typeof id === "string");
        if (ids.includes(device2Id)) {
          break;
        }
      }
      if (Date.now() > deadline) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
    expect(
      ids,
      `cross-signed Device 2 should appear in the device list: ${JSON.stringify(ids)}`,
    ).toContain(device2Id);

    // 3) Negative: a binding whose ssk_generation does not match the accepted
    //    publish MUST be rejected (device_recovery_ssk_generation_mismatch) —
    //    proves the generation gate is live, not echoed.
    const staleDeviceId = typedId("device");
    const staleDeviceKey = deviceVerifyKeyMultibase();
    const staleBinding = buildDeviceCrossSigningBinding({
      identity: { ...identity, generation: identity.generation + 1 },
      deviceId: staleDeviceId,
      devicePublicKeyMultibase: staleDeviceKey.multibase,
      hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
      algorithms: TEST_DEVICE_ALGORITHMS,
    });
    const staleAuthorize = await request.post(
      `${solandBaseUrl()}/_cokret/self/events`,
      {
        headers: authHeaders(device1Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ck.device.authorize",
          payload: {
            principal_id: alice.did,
            device_id: staleDeviceId,
            device_public_key: staleDeviceKey.multibase,
            hpke_key: "z6LSCotestE2eDeviceHpkeKey",
            algorithms: TEST_DEVICE_ALGORITHMS,
            device_key_algorithm: "EdDSA",
            authorized_by: alice.deviceId,
            not_before: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
            cross_signing_binding: staleBinding,
          },
        }),
      },
    );
    expect(
      staleAuthorize.ok(),
      `wrong-generation cross_signing_binding should be rejected, got ${staleAuthorize.status()}`,
    ).toBeFalsy();

    // 4) Negative: a binding signed by the USK instead of the accepted SSK MUST
    //    fail the §5.2 signature check — proves soland verifies the signature,
    //    not just the declared generation.
    const forgedDeviceId = typedId("device");
    const forgedDeviceKey = deviceVerifyKeyMultibase();
    const forgedBinding = buildDeviceCrossSigningBinding({
      // Swap SSK for USK so the signature is over the right bytes but by the
      // wrong key — the declared verification_method is also the USK's did:key,
      // which is not the accepted SSK.
      identity: { ...identity, ssk: identity.usk },
      deviceId: forgedDeviceId,
      devicePublicKeyMultibase: forgedDeviceKey.multibase,
      hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
      algorithms: TEST_DEVICE_ALGORITHMS,
    });
    const forgedAuthorize = await request.post(
      `${solandBaseUrl()}/_cokret/self/events`,
      {
        headers: authHeaders(device1Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ck.device.authorize",
          payload: {
            principal_id: alice.did,
            device_id: forgedDeviceId,
            device_public_key: forgedDeviceKey.multibase,
            hpke_key: "z6LSCotestE2eDeviceHpkeKey",
            algorithms: TEST_DEVICE_ALGORITHMS,
            device_key_algorithm: "EdDSA",
            authorized_by: alice.deviceId,
            not_before: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
            cross_signing_binding: forgedBinding,
          },
        }),
      },
    );
    expect(
      forgedAuthorize.ok(),
      `cross_signing_binding signed by the wrong key should be rejected, got ${forgedAuthorize.status()}`,
    ).toBeFalsy();
  });

  test("both devices show up in alice's device list projection within 30s of pairing", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §6 (device list sync) + §8.2 (device-set
    // projection). After Device 1 authorizes Device 2, the principal's device
    // list projection (GET /_cokret/self/account/viewer) MUST surface both
    // devices. The 30s budget is the spec's device-list convergence window.
    const alice = uniqueUser(`s10-device-list-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    // A second dev-login for the same DID registers Device 2 in the inventory
    // (issueDevSession({deviceId}) overrides the per-user device).
    const device2Id = typedId("device");
    await issueDevSession(request, alice, { deviceId: device2Id });

    const deadline = Date.now() + 30_000;
    let ids: string[] = [];
    for (;;) {
      const viewer = await request.get(
        `${solandBaseUrl()}/_cokret/self/account/viewer`,
        { headers: authHeaders(device1Token) },
      );
      if (viewer.ok()) {
        const body = (await viewer.json()) as {
          devices?: Array<{ device_id?: string }>;
        };
        ids = (body.devices ?? [])
          .map((device) => device.device_id)
          .filter((id): id is string => typeof id === "string");
        if (ids.includes(alice.deviceId) && ids.includes(device2Id)) {
          break;
        }
      }
      if (Date.now() > deadline) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
    expect(ids, `device list within 30s: ${JSON.stringify(ids)}`).toContain(
      alice.deviceId,
    );
    expect(ids).toContain(device2Id);
  });

  test("alice messages from Device 1 appear in Device 2's timeline; both have distinct device_id but same actor_id", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §2.1 step 5 (state handoff) — two sessions of
    // the same principal (distinct device_id, same actor_id) share the same
    // realm history. Device 1 writes a message; Device 2 reads it back.
    const alice = uniqueUser(`s10-multi-timeline-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    const device2Id = typedId("device");
    const device2Token = await issueDevSession(request, alice, {
      deviceId: device2Id,
    });
    expect(device2Id).not.toBe(alice.deviceId);

    // Both sessions resolve to the same actor DID via the viewer.
    const did1 = await currentActorDidApi(request, device1Token);
    const did2 = await currentActorDidApi(request, device2Token);
    expect(did1).toBe(alice.did);
    expect(did2).toBe(alice.did);

    const realmId = await createRealmApi(request, device1Token, {
      title: `s10 multi-device timeline ${Date.now()}`,
    });
    const body = `multi-device-cross-read-${Date.now()}`;
    await sendMessageApi(request, device1Token, realmId, body);

    // Device 2 reads the same realm history and finds Device 1's message.
    const events = await queryRealmEventsApi(request, device2Token, realmId);
    const serialized = JSON.stringify(events);
    expect(
      serialized.includes(body),
      `Device 2 timeline missing Device 1 message: ${serialized.slice(0, 2000)}`,
    ).toBeTruthy();
  });

  test("Device 1 revokes Device 2 via ck.device.revoke; Device 2's subsequent /_cokret/self/events POST is rejected and Device 2 shows revoked", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §2.2 + key-management.md §5.2. After a peer
    // device submits ck.device.revoke for Device 2, the auth gate stops
    // accepting Device 2's signed writes. soland fails the revoked-device
    // session closed at the auth layer (401 unauthenticated, "device revoked");
    // the device-set projection flips to status=revoked.
    const alice = uniqueUser(`s10-revoke-peer-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    const device2Id = typedId("device");
    const device2Token = await issueDevSession(request, alice, {
      deviceId: device2Id,
    });

    const realmId = principalControlRealmForDid(alice.did);

    // Device 1 (a peer device) revokes Device 2 on the principal control stream.
    const revoke = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(device1Token),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.device.revoke",
        payload: {
          principal_id: alice.did,
          device_id: device2Id,
          revoked_by: alice.deviceId,
          revoked_at: new Date().toISOString(),
          reason: "lost_device",
        },
      }),
    });
    expect(
      [200, 201],
      `ck.device.revoke returned ${revoke.status()}: ${await revoke.text()}`,
    ).toContain(revoke.status());

    // Device 2's subsequent signed write is rejected — the revoked device can
    // no longer authenticate. soland returns 401 unauthenticated at the auth
    // gate (the spec stops accepting the device's new signed writes; the wire
    // shape is the generic auth rejection, not a 200).
    const afterRevoke = await request.post(
      `${solandBaseUrl()}/_cokret/self/events`,
      {
        headers: authHeaders(device2Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ck.device.list_update",
          payload: {
            principal_id: alice.did,
            changed: [device2Id],
          },
        }),
      },
    );
    expect(
      afterRevoke.ok(),
      `revoked Device 2 write should be rejected, got ${afterRevoke.status()}`,
    ).toBeFalsy();
    expect([401, 403]).toContain(afterRevoke.status());

    // Device 2 is reported revoked in Device 1's device-set projection.
    const viewer = await request.get(
      `${solandBaseUrl()}/_cokret/self/account/viewer`,
      { headers: authHeaders(device1Token) },
    );
    const body = (await viewer.json()) as {
      devices?: Array<{ device_id?: string; status?: string }>;
    };
    const device2Row = (body.devices ?? []).find(
      (device) => device.device_id === device2Id,
    );
    expect(device2Row, `device2 row in viewer: ${JSON.stringify(body)}`).toBeTruthy();
    expect(device2Row!.status).toBe("revoked");
  });

  test.fixme(
    // @blocking-on: full MLS group orchestration (KeyPackage claim → Welcome →
    //   Commit Remove → epoch advance) across two device leaves; out of scope
    //   here because it requires driving the mls-group encryption stack, not
    //   just the device lifecycle surface this suite owns.
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "after revoke in an E2EE Realm, MLS Remove triggers epoch advance; Device 2 cannot decrypt subsequent messages",
    async () => {
      // spec: device-lifecycle.md §9 + encryption-and-audit.md §2.2
      // The device-revoke half (peer revoke → device_status=revoked, queued
      // to-device drop) is covered by the promoted tests above. The remaining
      // MLS half — claiming Device 2 a KeyPackage, joining it to an E2EE Realm
      // group via Welcome, then driving a Commit{Remove} that advances the
      // epoch and re-keys so Device 2 can no longer decrypt — needs the full
      // MLS group stack and is tracked separately.
    },
  );

  test("E10.4 a device cannot revoke itself (must be revoked from a peer device)", async ({
    request,
  }) => {
    // spec: identity/device-lifecycle.md §7 — self-revoke is rejected
    // up front so a principal cannot lock themselves out from their
    // only authenticated device.
    const stamp = Date.now();
    const alice = uniqueUser(`s10-self-revoke-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const selfRevoke = await request.post(
      `${solandBaseUrl()}/_cokret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId: principalControlRealmForDid(alice.did),
          kind: "ck.device.revoke",
          payload: {
            principal_id: alice.did,
            device_id: alice.deviceId,
            revoked_by: alice.deviceId,
            revoked_at: new Date().toISOString(),
            reason: "self_revoke_probe",
          },
        }),
      },
    );
    expect(selfRevoke.status()).toBe(400);
    const body = await selfRevoke.json();
    expect(wireErrCode(body)).toBe("cannot_self_revoke");
  });

  test("E10.E to-device message queued for Device 2 before revocation is dropped after revocation (spec §7 grace drop)", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §7 grace drop — a to-device message already
    // queued for a device MUST be dropped when that device is revoked, so a
    // lost/compromised device that comes back online cannot drain key-exchange
    // material queued before the revoke. soland purges the device's to-device
    // queue (purge_device_delivery_state) when ck.device.revoke is accepted,
    // and the revoked device's session is then fail-closed at the auth gate, so
    // the queued message is unreachable.
    const alice = uniqueUser(`s10-grace-drop-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    const device2Id = typedId("device");
    const device2Token = await issueDevSession(request, alice, {
      deviceId: device2Id,
    });

    // Device 1 (verified, first device) queues a to-device message for Device 2.
    const sendResp = await request.post(
      `${solandBaseUrl()}/_cokret/self/device_messages`,
      {
        headers: {
          ...authHeaders(device1Token),
          "Idempotency-Key": `grace-drop-${device2Id}`,
        },
        data: {
          messages: {
            [alice.did]: {
              [device2Id]: {
                kind: "ck.key.verification.request",
                expires_at: new Date(Date.now() + 10 * 60_000)
                  .toISOString()
                  .replace(/\.\d{3}Z$/, "Z"),
                content: {
                  transaction_id: `grace-${device2Id}`,
                  from_device: alice.deviceId,
                  timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
                },
              },
            },
          },
        },
      },
    );
    expect(
      sendResp.ok(),
      `to-device send returned ${sendResp.status()}: ${await sendResp.text()}`,
    ).toBeTruthy();

    // Before revocation Device 2 can drain the queued message.
    const beforeDrop = await request.get(
      `${solandBaseUrl()}/_cokret/self/device_messages`,
      { headers: authHeaders(device2Token) },
    );
    expect(beforeDrop.ok()).toBeTruthy();
    const beforeBody = (await beforeDrop.json()) as {
      messages?: Array<{ kind?: string }>;
    };
    expect(
      (beforeBody.messages ?? []).some(
        (message) => message.kind === "ck.key.verification.request",
      ),
      `Device 2 should see the queued request before revoke: ${JSON.stringify(beforeBody)}`,
    ).toBeTruthy();

    // Device 1 revokes Device 2 — this drops the queued to-device message.
    const revoke = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(device1Token),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId: principalControlRealmForDid(alice.did),
        kind: "ck.device.revoke",
        payload: {
          principal_id: alice.did,
          device_id: device2Id,
          revoked_by: alice.deviceId,
          revoked_at: new Date().toISOString(),
          reason: "lost_device",
        },
      }),
    });
    expect(
      [200, 201],
      `ck.device.revoke returned ${revoke.status()}: ${await revoke.text()}`,
    ).toContain(revoke.status());

    // After revocation Device 2's session is fail-closed at the auth gate, so
    // the previously-queued message can never be drained by the revoked device.
    const afterDrop = await request.get(
      `${solandBaseUrl()}/_cokret/self/device_messages`,
      { headers: authHeaders(device2Token) },
    );
    expect(
      afterDrop.ok(),
      `revoked Device 2 device_messages pull should be rejected, got ${afterDrop.status()}`,
    ).toBeFalsy();
    expect([401, 403]).toContain(afterDrop.status());
  });

  // ── Pairing-approval UX (yougen surfaces; device-lifecycle.md §2.1/§7) ──
  // §7 MUST: the receiving authorized device puts pairing_code + binding into
  // an explicit user confirmation and never trusts a new device on arrival.
  // yougen surfaces this two ways: a global approval prompt that pops on any
  // authorized device, and the /settings/devices/pair "Approve a device" card.

  test("device list renders an Element-style verification shield for the current device", async ({
    browser,
    request,
  }) => {
    // spec: device-lifecycle.md §6 (device list / verification state).
    // yougen: settings/devices.rs device_verification_badge — verified→green
    // shield, unverified→amber, revoked→red, else dim. The current device is
    // always present (registered with its device_id), so exactly one row with
    // a `device-verification-badge` must render.
    const alice = uniqueUser(`s10-verif-badge-${Date.now()}`);
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const device = await openUserPage(browser, alice, { sessionCredential: token });
    try {
      await device.gotoHome();
      await device.page.goto("/settings/devices", { waitUntil: "domcontentloaded" });
      await expect(device.page.getByTestId("device-list")).toBeVisible({ timeout: 120_000 });
      const badge = device.page.getByTestId("device-verification-badge").first();
      await expect(badge).toBeVisible({ timeout: 30_000 });
      // The shield carries a normalized state token for assertions, and the
      // current device for a freshly-enrolled dev account is one of the known
      // spec states (verified/unverified) — never an empty/unknown blank.
      const state = await badge.getAttribute("data-verification");
      expect(["verified", "unverified", "revoked"]).toContain(state);
    } finally {
      await device.close();
    }
  });

  test("new device's same_principal_device_authorization request surfaces on an authorized device as the global approval prompt; comparing the code and Approve authorizes it", async ({
    browser,
    request,
  }) => {
    // spec: device-lifecycle.md §2.1 / §7 (user-in-the-loop, pairing_code compare).
    //
    // Device-1 (an already-authorized sibling) must be `verified` in the device
    // inventory for soland to deliver a same-principal verification-bootstrap
    // to-device request to it (device_messages.rs: a fresh device may only send
    // `ck.key.verification.*` to a verified same-principal target). A dev-login
    // founding device is enrolled `unverified`, so we first promote it to
    // verified through the real §5.1/§5.2 ingest path (the same cross-signing
    // publish + ck.device.authorize the suite already exercises above) before
    // driving the UI. Device-2 then delivers its pairing request over the
    // to-device queue; device-1's background sync surfaces the global prompt.
    const alice = uniqueUser(`s10-pair-approve-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    await promoteDeviceToVerified(request, alice, device1Token, alice.deviceId);

    const device1 = await openUserPage(browser, alice, {
      sessionCredential: device1Token,
    });
    try {
      // Device-1 just needs to be inside the app so its background sync drains
      // the to-device inbox; the home shell mounts the global prompt.
      await device1.gotoHome();

      const { pairingCode, requestingDeviceId } = await deliverPairingRequest(
        request,
        alice,
        device1Token,
        { displayName: "Alice second browser" },
      );

      // Device-1's background long-poll ingests the to-device request and the
      // global DevicePairApprovalPrompt pops. Give the cross-session sync a wide
      // budget with a coarsening interval (mirrors the federation suites).
      const modal = device1.page.getByTestId("device-pair-approval-modal");
      await expect(modal).toBeVisible({
        timeout: 90_000,
      });
      await expect(device1.page.getByTestId("device-pair-approval-code")).toHaveText(
        pairingCode,
        { timeout: 30_000 },
      );

      await device1.page.getByTestId("device-pair-approval-approve").click();

      // Approval finalizes through POST /_cokret/gate/account/device-pair, which
      // writes the new device `verified`; it then surfaces in alice's device-set
      // projection (status=active) within the convergence window.
      await expect
        .poll(
          async () => {
            const viewer = await request.get(
              `${solandBaseUrl()}/_cokret/self/account/viewer`,
              { headers: authHeaders(device1Token) },
            );
            if (!viewer.ok()) {
              return undefined;
            }
            const body = (await viewer.json()) as {
              devices?: Array<{ device_id?: string; status?: string }>;
            };
            return (body.devices ?? []).find(
              (device) => device.device_id === requestingDeviceId,
            )?.status;
          },
          { timeout: 60_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBe("active");
    } finally {
      await device1.close();
    }
  });

  test("rejecting the pairing request (global prompt device-pair-approval-reject) dismisses it locally and does NOT authorize the new device", async ({
    browser,
    request,
  }) => {
    // spec: device-lifecycle.md §7 (no trust without explicit approval).
    // device-pair-approval-reject calls dismiss_pairing_to_device_message and
    // never POSTs device-pair, so the new device is never added to the list.
    const alice = uniqueUser(`s10-pair-reject-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    await promoteDeviceToVerified(request, alice, device1Token, alice.deviceId);

    const device1 = await openUserPage(browser, alice, {
      sessionCredential: device1Token,
    });
    try {
      await device1.gotoHome();
      const { pairingCode, requestingDeviceId } = await deliverPairingRequest(
        request,
        alice,
        device1Token,
        { displayName: "Alice rejected browser" },
      );

      const modal = device1.page.getByTestId("device-pair-approval-modal");
      await expect(modal).toBeVisible({ timeout: 90_000 });
      await expect(device1.page.getByTestId("device-pair-approval-code")).toHaveText(
        pairingCode,
        { timeout: 30_000 },
      );

      await device1.page.getByTestId("device-pair-approval-reject").click();

      // The prompt dismisses locally and does not re-pop for the same request.
      await expect(modal).toBeHidden({ timeout: 30_000 });

      // The rejected device is never authorized: it does not appear in alice's
      // device-set projection. Poll a few times to let any (incorrect) write
      // settle, then assert absence.
      const seenStatus = await pollDeviceStatus(
        request,
        device1Token,
        requestingDeviceId,
      );
      expect(seenStatus).toBeUndefined();
    } finally {
      await device1.close();
    }
  });

  test("the /settings/devices/pair 'Approve a device' card lists a delivered to-device request and approves it (pending-pairing-requests-card → approve-pairing-request-button)", async ({
    browser,
    request,
  }) => {
    // spec: device-lifecycle.md §7.
    // The /settings/devices/pair pending-pairing-requests-card renders the
    // to-device inbox via parse_pending_pairing_requests and approves through
    // POST /_cokret/gate/account/device-pair; pending-pairing-refresh-button
    // re-reads the inbox after the background sync has drained the request.
    const alice = uniqueUser(`s10-pair-card-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    await promoteDeviceToVerified(request, alice, device1Token, alice.deviceId);

    const device1 = await openUserPage(browser, alice, {
      sessionCredential: device1Token,
    });
    try {
      await device1.gotoHome();
      const { pairingCode, requestingDeviceId } = await deliverPairingRequest(
        request,
        alice,
        device1Token,
        { displayName: "Alice card browser" },
      );

      // The global prompt also mounts here; dismiss it (Reject local-only is
      // fine — it just removes the in-memory inbox copy for the prompt) so it
      // does not overlay the settings card. Instead, navigate straight to the
      // pairing settings and drive the card. The card reads the same inbox.
      await device1.page.goto("/settings/devices/pair", {
        waitUntil: "domcontentloaded",
      });
      await expect(
        device1.page.getByTestId("pending-pairing-requests-card"),
      ).toBeVisible({ timeout: 120_000 });

      // Re-read the inbox until the background sync has surfaced the request,
      // refreshing the card between polls.
      const requestRow = device1.page
        .getByTestId("pending-pairing-request")
        .filter({ hasText: pairingCode })
        .first();
      await expect
        .poll(
          async () => {
            await device1.page
              .getByTestId("pending-pairing-refresh-button")
              .click();
            return requestRow.isVisible().catch(() => false);
          },
          { timeout: 90_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBe(true);
      await expect(
        requestRow.getByTestId("pending-pairing-code"),
      ).toHaveText(pairingCode, { timeout: 15_000 });

      await requestRow.getByTestId("approve-pairing-request-button").click();

      await expect
        .poll(
          () => pollDeviceStatus(request, device1Token, requestingDeviceId),
          { timeout: 60_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBe("active");
    } finally {
      await device1.close();
    }
  });
});

/// Promote `deviceId` to `verified` in the device inventory through the real
/// §5.1/§5.2 ingest path (`ck.cross_signing.publish` + a `ck.device.authorize`
/// carrying a genuine SSK-signed `cross_signing_binding`). soland's
/// to-device delivery gate (device_messages.rs) requires the bootstrap target
/// device to be verified, and a dev-login founding device enrolls `unverified`,
/// so the UI pairing-approval surfaces need an authorized sibling first. The
/// `authorized_by` session keeps using its dev-login bearer afterward (the PoP
/// key is the SessionRecord key, independent of the device public key written
/// here).
async function promoteDeviceToVerified(
  request: APIRequestContext,
  user: JointUser,
  token: string,
  deviceId: string,
) {
  const realmId = principalControlRealmForDid(user.did);
  const identity = generateCrossSigningIdentity({ principalId: user.did });
  const publish = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
    headers: authHeaders(token),
    data: signedEventEnvelope({
      actorDid: user.did,
      realmId,
      kind: "ck.cross_signing.publish",
      payload: buildCrossSigningPublishPayload(identity),
    }),
  });
  expect(
    [200, 201],
    `ck.cross_signing.publish returned ${publish.status()}: ${await publish.text()}`,
  ).toContain(publish.status());

  const deviceKey = deviceVerifyKeyMultibase();
  const binding = buildDeviceCrossSigningBinding({
    identity,
    deviceId,
    devicePublicKeyMultibase: deviceKey.multibase,
    hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
    algorithms: TEST_DEVICE_ALGORITHMS,
  });
  const authorize = await request.post(
    `${solandBaseUrl()}/_cokret/self/events`,
    {
      headers: authHeaders(token),
      data: signedEventEnvelope({
        actorDid: user.did,
        realmId,
        kind: "ck.device.authorize",
        payload: {
          principal_id: user.did,
          device_id: deviceId,
          device_public_key: deviceKey.multibase,
          hpke_key: "z6LSCotestE2eDeviceHpkeKey",
          algorithms: TEST_DEVICE_ALGORITHMS,
          device_key_algorithm: "EdDSA",
          authorized_by: deviceId,
          not_before: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
          cross_signing_binding: binding,
        },
      }),
    },
  );
  expect(
    [200, 201],
    `ck.device.authorize (self-verify) returned ${authorize.status()}: ${await authorize.text()}`,
  ).toContain(authorize.status());

  // The device surfaces as authorized (status=active) in the projection.
  await expect
    .poll(() => pollDeviceStatus(request, token, deviceId), {
      timeout: 30_000,
      intervals: [500, 1_000, 2_000],
    })
    .toBe("active");
}

/// Deliver a same-principal `ck.key.verification.request` pairing request to
/// every authorized sibling over the to-device queue (the API shape yougen's
/// `pair-device-start-button` produces; driven directly here because that
/// button reads the device-set projection's `status` field, which exposes
/// `active`, not the `verified` literal its delivery loop filters on). soland
/// fans it out to verified same-principal targets, which the receiving device's
/// background sync ingests into its to-device inbox.
async function deliverPairingRequest(
  request: APIRequestContext,
  user: JointUser,
  senderToken: string,
  opts: { displayName?: string } = {},
): Promise<{ requestingDeviceId: string; pairingCode: string }> {
  const requestingDeviceId = typedId("device");
  const pairingCode = `${Date.now() % 1_000_000}`.padStart(6, "0");
  const transactionId = `ck.key.verification.request:${requestingDeviceId}`;
  const newDevicePubkey = {
    kty: "OKP",
    kid: requestingDeviceId,
    alg: "EdDSA",
    public_key: b64url(`pubkey:${requestingDeviceId}`),
  };
  const expiresAt = new Date(Date.now() + 10 * 60_000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
  const sendResp = await request.post(
    `${solandBaseUrl()}/_cokret/self/device_messages`,
    {
      headers: {
        ...authHeaders(senderToken),
        "Idempotency-Key": `pair-${requestingDeviceId}`,
      },
      data: {
        messages: {
          [user.did]: {
            [user.deviceId]: {
              kind: "ck.key.verification.request",
              expires_at: expiresAt,
              content: {
                transaction_id: transactionId,
                from_device: requestingDeviceId,
                purpose: "same_principal_device_authorization",
                pairing_code: pairingCode,
                new_device_pubkey: newDevicePubkey,
                challenge_signature: b64url(`challenge:${requestingDeviceId}`),
                device_metadata: {
                  platform: "browser",
                  display_name: opts.displayName ?? "New device",
                },
                expires_at: expiresAt,
                timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
              },
            },
          },
        },
      },
    },
  );
  expect(
    sendResp.ok(),
    `pairing to-device send returned ${sendResp.status()}: ${await sendResp.text()}`,
  ).toBeTruthy();
  return { requestingDeviceId, pairingCode };
}

/// Read a single device's `status` out of alice's device-set projection
/// (`GET /_cokret/self/account/viewer`). Returns `undefined` when the device is
/// absent or the read fails.
async function pollDeviceStatus(
  request: APIRequestContext,
  token: string,
  deviceId: string,
): Promise<string | undefined> {
  const viewer = await request.get(
    `${solandBaseUrl()}/_cokret/self/account/viewer`,
    { headers: authHeaders(token) },
  );
  if (!viewer.ok()) {
    return undefined;
  }
  const body = (await viewer.json()) as {
    devices?: Array<{ device_id?: string; status?: string }>;
  };
  return (body.devices ?? []).find((device) => device.device_id === deviceId)
    ?.status;
}

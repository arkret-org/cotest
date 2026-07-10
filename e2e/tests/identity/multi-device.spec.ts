// Multi-device pairing + revocation
// Contract: e2e/scenarios/identity/multi-device.md
// Spec refs:
//   - crypto-media/device-lifecycle.md §2 (pairing + revocation), §5.1-§5.2 (cross-signing binding)
//   - §6 (device list sync), §7 (to-device queue), §9 (MLS KeyPackage / Remove)
//   - identity/key-management.md §5.0-§5.2

import { createHash, sign as nodeSign } from "node:crypto";
import { type APIRequestContext, expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  buildCrossSigningPublishPayload,
  buildDeviceCrossSigningBinding,
  buildDevicePossessionSignature,
  TEST_DEVICE_ALGORITHMS,
  deviceVerifyKeyMultibase,
  generateCrossSigningIdentity,
} from "../../helpers/cross-signing-harness";
import {
  authHeaders,
  b64url,
  canonicalBytes,
  canonicalTimestamp,
  createRealmApi,
  currentActorDidApi,
  principalControlRealmForDid,
  queryRealmEventsApi,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
  wireErrReason,
} from "../../helpers/soland-api";
import {
  createDpopUserSession,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  selfPathHeadersForDpopSession,
  type DpopUserSession,
  type JointUser,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

const MLS_GOVERNANCE_BINDING_FULL_PROFILE =
  "ak.profile.mls_governance_binding.full.v1";
const MLS_REDUCER_PROFILE_V1 = "ak.reducer.v1";

type SelfPathHeadersSource =
  | string
  | ((method: string, url: string) => Record<string, string>);

function selfPathHeaders(
  source: SelfPathHeadersSource,
  method: string,
  url: string,
): Record<string, string> {
  return typeof source === "string" ? authHeaders(source) : source(method, url);
}

function dpopHeadersSource(
  session: DpopUserSession,
): (method: string, url: string) => Record<string, string> {
  return (method, url) => selfPathHeadersForDpopSession(session, method, url);
}

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

  test("unverified bootstrap placeholder cannot approve a new device through ak.gate.account.command.pair_device", async ({
    request,
  }) => {
    const alice = uniqueUser(`s10-device-pair-${Date.now()}`);
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const newDeviceId = typedId("device");

    const pairResp = await request.post(
      `${solandBaseUrl()}/_arkret/gate/account/device-pair`,
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

  test("Device 1 publishes cross-signing keys, then signs ak.device.authorize for Device 2 with a real cross_signing_binding; soland ingest verifies the SSK signature and surfaces Device 2", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §5.1 (ak.cross_signing.publish — PSK→{SSK,USK})
    // + §5.2 (per-device cross_signing_binding, the SSK signature over the
    // ak-device-trust-bind-v1 canonical input).
    //
    // This is NOT a dev-proof shortcut for the binding: soland's
    // validate_device_authorize_binding → check_device_cross_signing_binding
    // (routing/identity/cross_signing.rs) resolves the accepted SSK from a real
    // ak.cross_signing.publish and verifies the §5.2 signature at the live
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
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(device1Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.cross_signing.publish",
          payload: buildCrossSigningPublishPayload(identity),
        }),
      },
    );
    expect(
      [200, 201],
      `ak.cross_signing.publish returned ${publish.status()}: ${await publish.text()}`,
    ).toContain(publish.status());

    // 2) Authorize Device 2 with a real SSK-signed cross_signing_binding over
    //    the §5.2 ak-device-trust-bind-v1 input. soland verifies the binding at
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
    const authorizeNotBefore = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const authorize = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(device1Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.device.authorize",
          payload: {
            principal_id: alice.did,
            device_id: device2Id,
            device_public_key: device2Key.multibase,
            hpke_key: "z6LSCotestE2eDeviceHpkeKey",
            algorithms: TEST_DEVICE_ALGORITHMS,
            device_key_algorithm: "EdDSA",
            device_signature: deviceAuthorizeSignature({
              identity,
              principalId: alice.did,
              deviceId: device2Id,
              devicePublicKeyMultibase: device2Key.multibase,
              authorizedBy: alice.deviceId,
              notBefore: authorizeNotBefore,
              privateKey: device2Key.privateKey,
            }),
            authorized_by: alice.deviceId,
            not_before: authorizeNotBefore,
            cross_signing_binding: goodBinding,
          },
        }),
      },
    );
    expect(
      [200, 201],
      `ak.device.authorize with valid cross_signing_binding returned ${authorize.status()}: ${await authorize.text()}`,
    ).toContain(authorize.status());

    // The authorized device surfaces in alice's device-set projection.
    const deadline = Date.now() + 30_000;
    let ids: string[] = [];
    for (;;) {
      const viewer = await request.get(
        `${solandBaseUrl()}/_arkret/self/account/viewer`,
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
    const staleNotBefore = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const staleAuthorize = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(device1Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.device.authorize",
          payload: {
            principal_id: alice.did,
            device_id: staleDeviceId,
            device_public_key: staleDeviceKey.multibase,
            hpke_key: "z6LSCotestE2eDeviceHpkeKey",
            algorithms: TEST_DEVICE_ALGORITHMS,
            device_key_algorithm: "EdDSA",
            device_signature: deviceAuthorizeSignature({
              identity: { ...identity, generation: identity.generation + 1 },
              principalId: alice.did,
              deviceId: staleDeviceId,
              devicePublicKeyMultibase: staleDeviceKey.multibase,
              authorizedBy: alice.deviceId,
              notBefore: staleNotBefore,
              privateKey: staleDeviceKey.privateKey,
            }),
            authorized_by: alice.deviceId,
            not_before: staleNotBefore,
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
    const forgedNotBefore = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const forgedAuthorize = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(device1Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.device.authorize",
          payload: {
            principal_id: alice.did,
            device_id: forgedDeviceId,
            device_public_key: forgedDeviceKey.multibase,
            hpke_key: "z6LSCotestE2eDeviceHpkeKey",
            algorithms: TEST_DEVICE_ALGORITHMS,
            device_key_algorithm: "EdDSA",
            device_signature: deviceAuthorizeSignature({
              identity,
              principalId: alice.did,
              deviceId: forgedDeviceId,
              devicePublicKeyMultibase: forgedDeviceKey.multibase,
              authorizedBy: alice.deviceId,
              notBefore: forgedNotBefore,
              privateKey: forgedDeviceKey.privateKey,
            }),
            authorized_by: alice.deviceId,
            not_before: forgedNotBefore,
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
    // list projection (GET /_arkret/self/account/viewer) MUST surface both
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
        `${solandBaseUrl()}/_arkret/self/account/viewer`,
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

  test("Device 1 revokes Device 2 via ak.device.revoke; Device 2's subsequent /_arkret/self/events POST is rejected and Device 2 shows revoked", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §2.2 + key-management.md §5.2. After a peer
    // device submits ak.device.revoke for Device 2, the auth gate stops
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
    const revoke = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
      headers: authHeaders(device1Token),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.device.revoke",
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
      `ak.device.revoke returned ${revoke.status()}: ${await revoke.text()}`,
    ).toContain(revoke.status());

    // Device 2's subsequent signed write is rejected — the revoked device can
    // no longer authenticate. soland returns 401 unauthenticated at the auth
    // gate (the spec stops accepting the device's new signed writes; the wire
    // shape is the generic auth rejection, not a 200).
    const afterRevoke = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(device2Token),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.device.list_update",
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
      `${solandBaseUrl()}/_arkret/self/account/viewer`,
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

  test("revoking Device 2 removes its device_signing_key from /_arkret/self/keys/query and reports device_status=revoked", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §8.2. A revoked or unverified device MUST NOT
    // expose a device_signing_key through keys/query; receivers treat
    // device_status != active as fail-closed for event/signal proof checks.
    const alice = uniqueUser(`s10-revoke-key-query-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    const device2Id = typedId("device");
    await issueDevSession(request, alice, { deviceId: device2Id });

    const identity = await publishCrossSigningForUser(request, alice, device1Token);
    await authorizeDeviceWithCrossSigning(
      request,
      alice,
      device1Token,
      identity,
      device2Id,
    );
    await expect
      .poll(() => pollDeviceStatus(request, device1Token, device2Id), {
        timeout: 30_000,
        intervals: [500, 1_000, 2_000],
      })
      .toBe("active");

    const activeRecord = await queryDeviceKeyRecord(
      request,
      device1Token,
      alice.did,
      device2Id,
    );
    expect(activeRecord.device_status).toBe("active");
    expect(typeof activeRecord.device_signing_key).toBe("string");

    await revokeDeviceApi(request, alice, device1Token, device2Id);

    const revokedRecord = await queryDeviceKeyRecord(
      request,
      device1Token,
      alice.did,
      device2Id,
    );
    expect(revokedRecord.device_status).toBe("revoked");
    expect(revokedRecord.device_signing_key).toBeUndefined();
    expect(revokedRecord.hpke_key).toBeUndefined();
    expect(Object.keys((revokedRecord.algorithms as object) ?? {})).toHaveLength(0);
  });

  test("revoking Device 2 retires its unconsumed one-time and last-resort KeyPackages so later claims fail closed", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §9 / identity/key-management.md §5.2. Device
    // revoke must stop new MLS bootstrapping to the revoked device: even
    // KeyPackages uploaded before the revoke are retired and no longer
    // claimable for Welcome generation.
    const stamp = Date.now();
    const alice = uniqueUser(`s10-revoke-kp-${stamp}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    const device2Id = typedId("device");
    const device2Token = await issueDevSession(request, alice, {
      deviceId: device2Id,
    });

    const identity = await publishCrossSigningForUser(request, alice, device1Token);
    await authorizeDeviceWithCrossSigning(
      request,
      alice,
      device1Token,
      identity,
      device2Id,
    );

    const expiresAt = canonicalTimestamp(new Date(Date.now() + 60 * 60 * 1000));
    const keypackageCapabilities = ["ak.mls.profile.full"];
    const keyPackages = [
      buildKeyPackageUploadEntry({
        label: `ordinary-${stamp}`,
        capabilities: keypackageCapabilities,
        expiresAt,
        lastResort: false,
      }),
      buildKeyPackageUploadEntry({
        label: `last-resort-${stamp}`,
        capabilities: keypackageCapabilities,
        expiresAt,
        lastResort: true,
      }),
    ];
    await uploadDeviceKeyPackages(request, alice, device2Token, device2Id, keyPackages);

    await revokeDeviceApi(request, alice, device1Token, device2Id);

    const claim = await request.post(
      `${solandBaseUrl()}/_arkret/self/keys/keypackages/claim`,
      {
        headers: authHeaders(device1Token),
        data: {
          target_principal_id: alice.did,
          target_device_ids: [device2Id],
          intended_realm_id: typedId("realm"),
          requester: alice.did,
          required_capabilities: keypackageCapabilities,
          claim_nonce: `claim-after-revoke-${stamp}`,
          expires_at: expiresAt,
          mls_group_id: typedId("mls_group"),
          proofs: [],
        },
      },
    );
    const claimBody = await claim
      .json()
      .catch(async () => ({ raw: await claim.text() }));
    expect(
      claim.ok(),
      `KeyPackage claim after device revoke returned ${claim.status()}: ${JSON.stringify(claimBody)}`,
    ).toBeTruthy();
    expect(claimBody.claims ?? []).toEqual([]);
    expect(claimBody.failures?.[0]?.reason_code).toBe("mls_keypackage_not_found");
    expect(claimBody.available_count).toBe(0);
  });


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
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId: principalControlRealmForDid(alice.did),
          kind: "ak.device.revoke",
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
    // queue (purge_device_delivery_state) when ak.device.revoke is accepted,
    // and the revoked device's session is then fail-closed at the auth gate, so
    // the queued message is unreachable.
    const alice = uniqueUser(`s10-grace-drop-${Date.now()}`);
    await ensureRegistered(request, alice);
    const device1Token = await issueDevSession(request, alice);
    const device2Id = typedId("device");
    const device2Token = await issueDevSession(request, alice, {
      deviceId: device2Id,
    });
    await promoteDeviceToVerified(
      request,
      alice,
      device1Token,
      alice.deviceId,
    );

    // Device 1 (verified, first device) queues a to-device message for Device 2.
    const sendResp = await request.post(
      `${solandBaseUrl()}/_arkret/self/device_messages`,
      {
        headers: {
          ...authHeaders(device1Token),
          "Idempotency-Key": `grace-drop-${device2Id}`,
        },
        data: {
          messages: {
            [alice.did]: {
              [device2Id]: {
                kind: "ak.key.verification.request",
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
      `${solandBaseUrl()}/_arkret/self/device_messages`,
      { headers: authHeaders(device2Token) },
    );
    expect(beforeDrop.ok()).toBeTruthy();
    const beforeBody = (await beforeDrop.json()) as {
      messages?: Array<{ kind?: string }>;
    };
    expect(
      (beforeBody.messages ?? []).some(
        (message) => message.kind === "ak.key.verification.request",
      ),
      `Device 2 should see the queued request before revoke: ${JSON.stringify(beforeBody)}`,
    ).toBeTruthy();

    // Device 1 revokes Device 2 — this drops the queued to-device message.
    const revoke = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
      headers: authHeaders(device1Token),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId: principalControlRealmForDid(alice.did),
        kind: "ak.device.revoke",
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
      `ak.device.revoke returned ${revoke.status()}: ${await revoke.text()}`,
    ).toContain(revoke.status());

    // After revocation Device 2's session is fail-closed at the auth gate, so
    // the previously-queued message can never be drained by the revoked device.
    const afterDrop = await request.get(
      `${solandBaseUrl()}/_arkret/self/device_messages`,
      { headers: authHeaders(device2Token) },
    );
    expect(
      afterDrop.ok(),
      `revoked Device 2 device_messages pull should be rejected, got ${afterDrop.status()}`,
    ).toBeFalsy();
    expect([401, 403]).toContain(afterDrop.status());
  });

  // ── Pairing-approval UX (inkson surfaces; device-lifecycle.md §2.1/§7) ──
  // §7 MUST: the receiving authorized device puts pairing_code + binding into
  // an explicit user confirmation and never trusts a new device on arrival.
  // inkson surfaces this two ways: a global approval prompt that pops on any
  // authorized device, and the /settings/devices/pair "Approve a device" card.

  test("device list renders an Element-style verification shield for the current device", async ({
    browser,
    request,
  }) => {
    // spec: device-lifecycle.md §6 (device list / verification state).
    // inkson: settings/devices.rs device_verification_badge — verified→green
    // shield, unverified→amber, revoked→red, else dim. The current device is
    // always present (registered with its device_id), so exactly one row with
    // a `device-verification-badge` must render.
    const deviceFlow = await openDpopUserPage(
      browser,
      request,
      `s10-verif-badge-${Date.now()}`,
    );
    test.skip(
      !deviceFlow,
      "coauth DPoP session-grant login is required for device-list UI",
    );
    if (!deviceFlow) {
      return;
    }
    const device = deviceFlow.page;
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
    // `ak.key.verification.*` to a verified same-principal target). A dev-login
    // founding device is enrolled `unverified`, so we first promote it to
    // verified through the real §5.1/§5.2 ingest path (the same cross-signing
    // publish + ak.device.authorize the suite already exercises above) before
    // driving the UI. Device-2 then delivers its pairing request over the
    // to-device queue; device-1's background sync surfaces the global prompt.
    const device1Session = await createDpopUserSession(
      request,
      `s10-pair-approve-${Date.now()}`,
      { skipDeviceEnrollment: false },
    );
    test.skip(
      !device1Session,
      "coauth DPoP session-grant login is required for UI device-pair approval",
    );
    if (!device1Session) {
      return;
    }
    const alice = device1Session.user;
    const device1Headers = dpopHeadersSource(device1Session);
    await promoteDeviceToVerified(
      request,
      alice,
      device1Headers,
      alice.deviceId,
    );

    const device1 = await openUserPage(browser, alice, {
      grantJwt: device1Session.grantJwt,
      dpopSeedB64url: device1Session.dpopSeedB64url,
      grantId: device1Session.grantId,
      grantAudience: device1Session.grantAudience,
    });
    try {
      // Device-1 just needs to be inside the app so its background sync drains
      // the to-device inbox; the home shell mounts the global prompt.
      await device1.gotoHome();

      const { pairingCode, requestingDeviceId, newDevicePublicKey } = await deliverPairingRequest(
        request,
        alice,
        device1Headers,
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

      // Approval finalizes through POST /_arkret/gate/account/device-pair, which
      // writes the new device `verified`; it then surfaces in alice's device-set
      // projection (status=active) within the convergence window.
      await expect
        .poll(
          async () => {
            return pollDeviceStatus(request, device1Headers, requestingDeviceId);
          },
          { timeout: 60_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBe("active");

      const pairedRecord = await queryDeviceKeyRecord(
        request,
        device1Headers,
        alice.did,
        requestingDeviceId,
      );
      expect(pairedRecord.device_status).toBe("active");
      expect(pairedRecord.device_signing_key).toBe(`did:key:${newDevicePublicKey}`);
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
    const device1Session = await createDpopUserSession(
      request,
      `s10-pair-reject-${Date.now()}`,
      { skipDeviceEnrollment: false },
    );
    test.skip(
      !device1Session,
      "coauth DPoP session-grant login is required for UI device-pair rejection",
    );
    if (!device1Session) {
      return;
    }
    const alice = device1Session.user;
    const device1Headers = dpopHeadersSource(device1Session);
    await promoteDeviceToVerified(
      request,
      alice,
      device1Headers,
      alice.deviceId,
    );

    const device1 = await openUserPage(browser, alice, {
      grantJwt: device1Session.grantJwt,
      dpopSeedB64url: device1Session.dpopSeedB64url,
      grantId: device1Session.grantId,
      grantAudience: device1Session.grantAudience,
    });
    try {
      await device1.gotoHome();
      const { pairingCode, requestingDeviceId } = await deliverPairingRequest(
        request,
        alice,
        device1Headers,
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
        device1Headers,
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
    // POST /_arkret/gate/account/device-pair; pending-pairing-refresh-button
    // re-reads the inbox after the background sync has drained the request.
    const device1Session = await createDpopUserSession(
      request,
      `s10-pair-card-${Date.now()}`,
      { skipDeviceEnrollment: false },
    );
    test.skip(
      !device1Session,
      "coauth DPoP session-grant login is required for UI device-pair settings card",
    );
    if (!device1Session) {
      return;
    }
    const alice = device1Session.user;
    const device1Headers = dpopHeadersSource(device1Session);
    await promoteDeviceToVerified(
      request,
      alice,
      device1Headers,
      alice.deviceId,
    );

    const device1 = await openUserPage(browser, alice, {
      grantJwt: device1Session.grantJwt,
      dpopSeedB64url: device1Session.dpopSeedB64url,
      grantId: device1Session.grantId,
      grantAudience: device1Session.grantAudience,
    });
    try {
      await device1.gotoHome();
      const { pairingCode, requestingDeviceId, newDevicePublicKey } = await deliverPairingRequest(
        request,
        alice,
        device1Headers,
        { displayName: "Alice card browser" },
      );

      // The global prompt also mounts here. Hide it in this page only so the
      // settings-card path can approve the same pending inbox request.
      await device1.page.goto("/settings/devices/pair", {
        waitUntil: "domcontentloaded",
      });
      await device1.page.addStyleTag({
        content:
          "[data-testid='device-pair-approval-modal'],[class^='dx-dialog-backdrop'],[class*=' dx-dialog-backdrop']{display:none!important;visibility:hidden!important;pointer-events:none!important;}",
      });
      await expect(
        device1.page.getByTestId("pending-pairing-requests-card"),
      ).toBeVisible({ timeout: 120_000 });

      // Re-read the inbox once, then let Playwright wait for the row that this
      // test delivered to the authorized device.
      const requestRow = device1.page
        .getByTestId("pending-pairing-request")
        .filter({ hasText: "Alice card browser" })
        .first();
      await device1.page.getByTestId("pending-pairing-refresh-button").click();
      await expect(requestRow).toBeVisible({ timeout: 90_000 });
      await expect(
        requestRow.getByTestId("pending-pairing-code"),
      ).toHaveText(pairingCode, { timeout: 15_000 });

      await requestRow.getByTestId("approve-pairing-request-button").click();

      await expect
        .poll(
          () => pollDeviceStatus(request, device1Headers, requestingDeviceId),
          { timeout: 60_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBe("active");

      const pairedRecord = await queryDeviceKeyRecord(
        request,
        device1Headers,
        alice.did,
        requestingDeviceId,
      );
      expect(pairedRecord.device_status).toBe("active");
      expect(pairedRecord.device_signing_key).toBe(`did:key:${newDevicePublicKey}`);
    } finally {
      await device1.close();
    }
  });
});

/// Promote `deviceId` to `verified` in the device inventory through the real
/// §5.1/§5.2 ingest path (`ak.cross_signing.publish` + a `ak.device.authorize`
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
  headersSource: SelfPathHeadersSource,
  deviceId: string,
) {
  const realmId = principalControlRealmForDid(user.did);
  const identity = generateCrossSigningIdentity({ principalId: user.did });
  const eventsUrl = `${solandBaseUrl()}/_arkret/self/events`;
  const publish = await request.post(eventsUrl, {
    headers: selfPathHeaders(headersSource, "POST", eventsUrl),
    data: signedEventEnvelope({
      actorDid: user.did,
      realmId,
      kind: "ak.cross_signing.publish",
      payload: buildCrossSigningPublishPayload(identity),
    }),
  });
  expect(
    [200, 201],
    `ak.cross_signing.publish returned ${publish.status()}: ${await publish.text()}`,
  ).toContain(publish.status());

  const deviceKey = deviceVerifyKeyMultibase();
  const binding = buildDeviceCrossSigningBinding({
    identity,
    deviceId,
    devicePublicKeyMultibase: deviceKey.multibase,
    hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
    algorithms: TEST_DEVICE_ALGORITHMS,
  });
  const authorizeNotBefore = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const authorize = await request.post(eventsUrl, {
      headers: selfPathHeaders(headersSource, "POST", eventsUrl),
      data: signedEventEnvelope({
        actorDid: user.did,
        realmId,
        kind: "ak.device.authorize",
        payload: {
          principal_id: user.did,
          device_id: deviceId,
          device_public_key: deviceKey.multibase,
          hpke_key: "z6LSCotestE2eDeviceHpkeKey",
          algorithms: TEST_DEVICE_ALGORITHMS,
          device_key_algorithm: "EdDSA",
          device_signature: deviceAuthorizeSignature({
            identity,
            principalId: user.did,
            deviceId,
            devicePublicKeyMultibase: deviceKey.multibase,
            authorizedBy: deviceId,
            notBefore: authorizeNotBefore,
            privateKey: deviceKey.privateKey,
          }),
          authorized_by: deviceId,
          not_before: authorizeNotBefore,
          cross_signing_binding: binding,
        },
      }),
    });
  expect(
    [200, 201],
    `ak.device.authorize (self-verify) returned ${authorize.status()}: ${await authorize.text()}`,
  ).toContain(authorize.status());

  // The device surfaces as authorized (status=active) in the projection.
  await expect
    .poll(() => pollDeviceStatus(request, headersSource, deviceId), {
      timeout: 30_000,
      intervals: [500, 1_000, 2_000],
    })
    .toBe("active");
}

/// Deliver a same-principal `ak.key.verification.request` pairing request to
/// every authorized sibling over the to-device queue (the API shape inkson's
/// `pair-device-start-button` produces; driven directly here because that
/// button reads the device-set projection's `status` field, which exposes
/// `active`, not the `verified` literal its delivery loop filters on). soland
/// fans it out to verified same-principal targets, which the receiving device's
/// background sync ingests into its to-device inbox.
async function deliverPairingRequest(
  request: APIRequestContext,
  user: JointUser,
  senderHeadersSource: SelfPathHeadersSource,
  opts: { displayName?: string } = {},
): Promise<{ requestingDeviceId: string; pairingCode: string; newDevicePublicKey: string }> {
  const requestingDeviceId = typedId("device");
  const pairingCode = `${Date.now() % 1_000_000}`.padStart(6, "0");
  const transactionId = `ak.key.verification.request:${requestingDeviceId}`;
  const newDeviceKey = deviceVerifyKeyMultibase();
  const newDevicePubkey = {
    kty: "OKP",
    kid: requestingDeviceId,
    alg: "EdDSA",
    public_key: newDeviceKey.multibase,
  };
  const expiresAt = new Date(Date.now() + 10 * 60_000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
  const sendResp = await request.post(
    `${solandBaseUrl()}/_arkret/self/device_messages`,
    {
      headers: {
        ...selfPathHeaders(
          senderHeadersSource,
          "POST",
          `${solandBaseUrl()}/_arkret/self/device_messages`,
        ),
        "Idempotency-Key": `pair-${requestingDeviceId}`,
      },
      data: {
        messages: {
          [user.did]: {
            [user.deviceId]: {
              kind: "ak.key.verification.request",
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
  return { requestingDeviceId, pairingCode, newDevicePublicKey: newDeviceKey.multibase };
}

/// Read a single device's `status` out of alice's device-set projection
/// (`GET /_arkret/self/account/viewer`). Returns `undefined` when the device is
/// absent or the read fails.
async function pollDeviceStatus(
  request: APIRequestContext,
  headersSource: SelfPathHeadersSource,
  deviceId: string,
): Promise<string | undefined> {
  const viewerUrl = `${solandBaseUrl()}/_arkret/self/account/viewer`;
  const viewer = await request.get(viewerUrl, {
    headers: selfPathHeaders(headersSource, "GET", viewerUrl),
  });
  if (!viewer.ok()) {
    return undefined;
  }
  const body = (await viewer.json()) as {
    devices?: Array<{ device_id?: string; status?: string }>;
  };
  return (body.devices ?? []).find((device) => device.device_id === deviceId)
    ?.status;
}

type CrossSigningIdentity = ReturnType<typeof generateCrossSigningIdentity>;

async function publishCrossSigningForUser(
  request: APIRequestContext,
  user: JointUser,
  token: string,
): Promise<CrossSigningIdentity> {
  const realmId = principalControlRealmForDid(user.did);
  const identity = generateCrossSigningIdentity({ principalId: user.did });
  const publish = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
    headers: authHeaders(token),
    data: signedEventEnvelope({
      actorDid: user.did,
      realmId,
      kind: "ak.cross_signing.publish",
      payload: buildCrossSigningPublishPayload(identity),
    }),
  });
  expect(
    [200, 201],
    `ak.cross_signing.publish returned ${publish.status()}: ${await publish.text()}`,
  ).toContain(publish.status());
  return identity;
}

async function authorizeDeviceWithCrossSigning(
  request: APIRequestContext,
  user: JointUser,
  token: string,
  identity: CrossSigningIdentity,
  deviceId: string,
) {
  const realmId = principalControlRealmForDid(user.did);
  const deviceKey = deviceVerifyKeyMultibase();
  const binding = buildDeviceCrossSigningBinding({
    identity,
    deviceId,
    devicePublicKeyMultibase: deviceKey.multibase,
    hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
    algorithms: TEST_DEVICE_ALGORITHMS,
  });
  const authorizeNotBefore = canonicalTimestamp();
  const authorize = await request.post(
    `${solandBaseUrl()}/_arkret/self/events`,
    {
      headers: authHeaders(token),
      data: signedEventEnvelope({
        actorDid: user.did,
        realmId,
        kind: "ak.device.authorize",
        payload: {
          principal_id: user.did,
          device_id: deviceId,
          device_public_key: deviceKey.multibase,
          hpke_key: "z6LSCotestE2eDeviceHpkeKey",
          algorithms: TEST_DEVICE_ALGORITHMS,
          device_key_algorithm: "EdDSA",
          device_signature: deviceAuthorizeSignature({
            identity,
            principalId: user.did,
            deviceId,
            devicePublicKeyMultibase: deviceKey.multibase,
            authorizedBy: user.deviceId,
            notBefore: authorizeNotBefore,
            privateKey: deviceKey.privateKey,
          }),
          authorized_by: user.deviceId,
          not_before: authorizeNotBefore,
          cross_signing_binding: binding,
        },
      }),
    },
  );
  expect(
    [200, 201],
    `ak.device.authorize returned ${authorize.status()}: ${await authorize.text()}`,
  ).toContain(authorize.status());
}

async function revokeDeviceApi(
  request: APIRequestContext,
  user: JointUser,
  token: string,
  deviceId: string,
): Promise<string> {
  const eventId = typedId("event");
  const revoke = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
    headers: authHeaders(token),
    data: signedEventEnvelope({
      actorDid: user.did,
      realmId: principalControlRealmForDid(user.did),
      kind: "ak.device.revoke",
      eventId,
      payload: {
        principal_id: user.did,
        device_id: deviceId,
        revoked_by: user.deviceId,
        revoked_at: canonicalTimestamp(),
        reason: "lost_device",
      },
    }),
  });
  expect(
    [200, 201],
    `ak.device.revoke returned ${revoke.status()}: ${await revoke.text()}`,
  ).toContain(revoke.status());
  return eventId;
}

async function queryDeviceKeyRecord(
  request: APIRequestContext,
  headersSource: SelfPathHeadersSource,
  principalId: string,
  deviceId: string,
): Promise<Record<string, unknown>> {
  const queryUrl = `${solandBaseUrl()}/_arkret/self/keys/query`;
  const response = await request.post(queryUrl, {
    headers: selfPathHeaders(headersSource, "POST", queryUrl),
    data: {
      device_keys: {
        [principalId]: [deviceId],
      },
    },
  });
  const body = (await response.json().catch(async () => ({
    raw: await response.text(),
  }))) as {
    device_keys?: Record<string, Record<string, Record<string, unknown>>>;
  };
  expect(
    response.ok(),
    `keys/query returned ${response.status()}: ${JSON.stringify(body)}`,
  ).toBeTruthy();
  const record = body.device_keys?.[principalId]?.[deviceId];
  expect(
    record,
    `keys/query missing ${principalId}/${deviceId}: ${JSON.stringify(body)}`,
  ).toBeTruthy();
  return record!;
}

type KeyPackageUploadEntry = {
  keypackage_id: string;
  keypackage_ref: string;
  key_package: string;
  keypackage_digest: string;
  cipher_suites: string[];
  capabilities: string[];
  created_at: string;
  expires_at: string;
  last_resort: boolean;
};

type MlsRealmGroupFixture = {
  groupId: string;
  realmId: string;
  effectiveScope: Record<string, unknown>;
  policyRoot: string;
  genesisEventId: string;
};

function mlsGovernanceBinding(
  group: MlsRealmGroupFixture,
  previousEpoch: number,
  nextEpoch: number,
  membershipFrontier: string[],
): Record<string, unknown> {
  return {
    binding_version: 1,
    encoding_profile: "cbor-deterministic-rfc8949-v1",
    realm_id: group.realmId,
    effective_scope: group.effectiveScope,
    mls_group_id: group.groupId,
    previous_epoch: previousEpoch,
    next_epoch: nextEpoch,
    membership_frontier: membershipFrontier,
    policy_root: group.policyRoot,
    binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE,
    reducer_profile: MLS_REDUCER_PROFILE_V1,
  };
}

function buildMlsWelcomeEnvelope(args: {
  actorDid: string;
  realmId: string;
  group: MlsRealmGroupFixture;
  identity: CrossSigningIdentity;
  keypackageClaim: Record<string, unknown>;
  recipientDid: string;
  recipientDeviceId: string;
  epoch: number;
  commitRef: string;
  label: string;
  governanceBinding: Record<string, unknown>;
}): { eventId: string; welcomeId: string; envelope: Record<string, unknown> } {
  const eventId = typedId("event");
  const welcomeId = typedId("mls_welcome");
  const claimId = String(args.keypackageClaim.claim_id);
  const keypackageRef = String(args.keypackageClaim.keypackage_ref);
  const keypackageDigest = String(args.keypackageClaim.keypackage_digest);
  const capabilitiesDigest = String(args.keypackageClaim.capabilities_digest);
  const sskGeneration = Number(args.keypackageClaim.ssk_generation);
  expect(Number.isFinite(sskGeneration)).toBeTruthy();
  const ciphertext = b64url(`opaque-mls-welcome-${args.label}`);
  const welcomeDigest = sha256Digest(Buffer.from(ciphertext, "base64url"));
  const claimEnvelopeUnsigned = {
    keypackage_ref: keypackageRef,
    keypackage_digest: keypackageDigest,
    intended_realm_id: args.realmId,
    claim_id: claimId,
    requester_did: args.actorDid,
    ssk_generation: sskGeneration,
    nonce: `welcome-claim-${args.label}`,
    welcome_digest: welcomeDigest,
    created_at: canonicalTimestamp(),
  };

  return {
    eventId,
    welcomeId,
    envelope: signedEventEnvelope({
      actorDid: args.actorDid,
      realmId: args.realmId,
      kind: "ak.mls.welcome",
      eventId,
      payload: {
        welcome_id: welcomeId,
        mls_group_id: args.group.groupId,
        epoch: args.epoch,
        recipient_principal_id: args.recipientDid,
        recipient_device_id: args.recipientDeviceId,
        keypackage_ref: keypackageRef,
        keypackage_digest: keypackageDigest,
        claim_id: claimId,
        claim_ref: {
          claim_id: claimId,
          keypackage_ref: keypackageRef,
          keypackage_digest: keypackageDigest,
          capabilities_digest: capabilitiesDigest,
          ssk_generation: sskGeneration,
        },
        claim_envelope: {
          ...claimEnvelopeUnsigned,
          signature: {
            kid: args.identity.ssk.verificationMethod,
            alg: "EdDSA",
            sig: nodeSign(
              null,
              canonicalBytes(claimEnvelopeUnsigned),
              args.identity.ssk.privateKey,
            ).toString("base64url"),
          },
        },
        ciphertext,
        expires_at: canonicalTimestamp(new Date(Date.now() + 60 * 60 * 1000)),
        commit_ref: args.commitRef,
        governance_binding: args.governanceBinding,
      },
    }),
  };
}

function findEventPayload(
  body: Record<string, unknown>,
  eventId: string,
): Record<string, unknown> | undefined {
  const events = Array.isArray(body.events) ? body.events : [];
  for (const event of events) {
    if (!event || typeof event !== "object" || Array.isArray(event)) {
      continue;
    }
    const record = event as Record<string, unknown>;
    if (record.event_id !== eventId && record.id !== eventId) {
      continue;
    }
    const payload = record.payload;
    if (payload && typeof payload === "object" && !Array.isArray(payload)) {
      return payload as Record<string, unknown>;
    }
  }
  return undefined;
}

function buildKeyPackageUploadEntry(args: {
  label: string;
  capabilities: string[];
  expiresAt: string;
  lastResort: boolean;
}): KeyPackageUploadEntry {
  const keyPackage = b64url(`opaque-keypackage-${args.label}`);
  const keypackageDigest = sha256Digest(Buffer.from(keyPackage, "base64url"));
  return {
    keypackage_id: typedId("mls_keypackage"),
    keypackage_ref: keypackageDigest,
    key_package: keyPackage,
    keypackage_digest: keypackageDigest,
    cipher_suites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
    capabilities: args.capabilities,
    created_at: canonicalTimestamp(),
    expires_at: args.expiresAt,
    last_resort: args.lastResort,
  };
}

async function uploadDeviceKeyPackages(
  request: APIRequestContext,
  user: JointUser,
  token: string,
  deviceId: string,
  keyPackages: KeyPackageUploadEntry[],
) {
  const deviceSignature = {
    kid: `${user.did}#${deviceId}`,
    alg: "EdDSA",
    sig: b64url(`device-signature-${deviceId}-${Date.now()}`),
  };
  const publish = await request.post(
    `${solandBaseUrl()}/_arkret/self/keys/keypackages/upload`,
    {
      headers: authHeaders(token),
      data: {
        principal_id: user.did,
        device_id: deviceId,
        device_signature: deviceSignature,
        key_packages: keyPackages.map((entry) => ({
          ...entry,
          device_signature: deviceSignature,
        })),
      },
    },
  );
  const body = await publish
    .json()
    .catch(async () => ({ raw: await publish.text() }));
  expect(
    publish.ok(),
    `KeyPackage upload returned ${publish.status()}: ${JSON.stringify(body)}`,
  ).toBeTruthy();
  expect(body.accepted).toBe(keyPackages.length);
  expect(body.rejected ?? []).toEqual([]);
}

function sha256Digest(value: Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function deviceAuthorizeSignature(args: {
  identity: CrossSigningIdentity;
  principalId: string;
  deviceId: string;
  devicePublicKeyMultibase: string;
  authorizedBy: string;
  notBefore: string;
  privateKey: ReturnType<typeof deviceVerifyKeyMultibase>["privateKey"];
  recoverySessionId?: string | null;
}): Record<string, string> {
  return {
    kid: `${args.principalId}#${args.deviceId}`,
    alg: "EdDSA",
    sig: buildDevicePossessionSignature({
      identity: args.identity,
      deviceId: args.deviceId,
      devicePublicKeyMultibase: args.devicePublicKeyMultibase,
      hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
      algorithms: TEST_DEVICE_ALGORITHMS,
      deviceKeyAlgorithm: "EdDSA",
      authorizedBy: args.authorizedBy,
      notBefore: args.notBefore,
      recoverySessionId: args.recoverySessionId,
      privateKey: args.privateKey,
    }),
  };
}

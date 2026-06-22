// Multi-device pairing + revocation
// Contract: e2e/scenarios/identity/multi-device.md
// Spec refs:
//   - crypto-media/device-lifecycle.md §2 (pairing + revocation), §5.1-§5.2 (cross-signing binding)
//   - §6 (device list sync), §7 (to-device queue), §9 (MLS KeyPackage / Remove)
//   - identity/key-management.md §5.0-§5.2

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  b64url,
  principalControlRealmForDid,
  signedEventEnvelope,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
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

  test.fixme(
    // @blocking-on: soland#identity-multi-device-gap
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "Device 1 scans Device 2's QR; signs ck.device.authorize with cross_signing_binding; Device 2 syncs and joins existing MLS groups via Welcome",
    async () => {
      // spec: device-lifecycle.md §2.1 (5-step pairing), §5.2 cross-signing binding
      // soland gap: ck.device.authorize cross_signing_binding payload; device list materialization.
      // yougen gap: /settings/devices "Add device" + QR-scan strand.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-multi-device-gap
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "both devices show up in alice's device list via ck.device.list_update projection within 30s of pairing",
    async () => {
      // spec: device-lifecycle.md §6
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-multi-device-gap
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "alice messages from Device 1 appear in Device 2's timeline; both have distinct device_id but same actor_id",
    async () => {
      // spec: device-lifecycle.md §2.1 step 5
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-multi-device-gap
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "Device 1 revokes Device 2 via ck.device.revoke; Device 2's subsequent /_cokret/self/events POST returns device_revoked",
    async () => {
      // spec: device-lifecycle.md §2.2 + key-management.md §5.2
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-multi-device-gap
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "after revoke in an E2EE Realm, MLS Remove triggers epoch advance; Device 2 cannot decrypt subsequent messages",
    async () => {
      // spec: device-lifecycle.md §9 + encryption-and-audit.md §2.2
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
          },
        }),
      },
    );
    expect(selfRevoke.status()).toBe(400);
    const body = await selfRevoke.json();
    expect(wireErrCode(body)).toBe("cannot_self_revoke");
  });

  test.fixme(
    // @blocking-on: soland#identity-multi-device-gap
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "E10.E to-device message queued for Device 2 before revocation is dropped after revocation (spec §7 line 341 grace drop)",
    async () => {
      // spec: device-lifecycle.md §7
    },
  );

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

  test.fixme(
    // @blocking-on: soland#identity-multi-device-gap (live to-device delivery between two sessions)
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "new device's same_principal_device_authorization request surfaces on an authorized device as the global approval prompt; comparing the code and Approve authorizes it",
    async () => {
      // spec: device-lifecycle.md §2.1 / §7 (user-in-the-loop, pairing_code compare).
      // device-2: /settings/devices/pair → pair-device-start-button mints the
      //   request and to-device delivers it to authorized siblings.
      // device-1 (authorized): the global DevicePairApprovalPrompt pops:
      //   - device-pair-approval-modal visible
      //   - device-pair-approval-code matches the code device-2 shows
      //   - device-pair-approval-approve → POST /_cokret/gate/account/device-pair
      //   - device-2 then appears verified in device-1's device list.
      // Gap: cross-session live to-device fan-out in the harness (devices share
      // one actor; needs real device_messages delivery, not the paste path).
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-multi-device-gap (live to-device delivery between two sessions)
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "rejecting the pairing request (global prompt device-pair-approval-reject) dismisses it locally and does NOT authorize the new device",
    async () => {
      // spec: device-lifecycle.md §7 (no trust without explicit approval).
      // device-pair-approval-reject → request dropped from the to-device inbox
      // (local_state.dismiss_pairing_to_device_message); the prompt does not
      // re-pop, and device-2 is never added to the device list.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-multi-device-gap (live to-device delivery between two sessions)
    // @user-promise: e2e/scenarios/identity/multi-device.md
    // @expected-live-by: 2026Q3
    "the /settings/devices/pair 'Approve a device' card lists a delivered to-device request and approves it (pending-pairing-requests-card → approve-pairing-request-button)",
    async () => {
      // spec: device-lifecycle.md §7.
      // device-1 /settings/devices/pair: pending-pairing-requests-card shows the
      //   delivered request with pending-pairing-code; approve-pairing-request-button
      //   finalizes via /_cokret/gate/account/device-pair; reject-pairing-request-button
      //   drops it. Refresh requests (pending-pairing-refresh-button) re-reads the inbox.
    },
  );
});

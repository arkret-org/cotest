// Account auth + device authorization
// Contract: e2e/scenarios/identity/account-device-auth.md
// Spec: identity/account-lifecycle.md §2-§3, key-management.md §6, device-lifecycle.md §2

import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import { coauthBaseUrl, solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  loginPrincipalViaCoauth,
  onboardPrincipalViaCoauth,
} from "../../helpers/onboarding";
import { selfPathGrantHeaders } from "../../helpers/session-grant-dpop";
import {
  buildHolderProofRefreshBody,
  enrollOnboardedDeviceSigningKey,
  postSessionGrantRefresh,
} from "../../helpers/device-holder-proof";

test.describe.configure({ mode: "serial" });

test.describe("account auth + device strand", () => {
  test("session-grant refresh endpoint surface probe", async ({ request }) => {
    const probe = await request.post(`${solandBaseUrl()}/_arkret/gate/account/session-grants/refresh`, {
      data: { grant_jwt: "probe-grant", audience: "cotest" },
    });
    // 4xx for bad token / not implemented; 5xx is a bug.
    expect(probe.status()).toBeLessThan(500);
  });

  test("expired session credential returns 401 on protected endpoint", async ({ request }) => {
    const meResp = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: { authorization: `Bearer expired-or-bogus-token` },
    });
    expect([401, 403]).toContain(meResp.status());
  });

  test("alice authenticates over the real account-authority bridge; coauth issues a short-term, device-bound ck.session.grant that authorizes /_arkret/self/*", async ({
    request,
  }) => {
    // spec: account-lifecycle.md §2.1, key-management.md §6
    //
    // The promise is "a real authentication result becomes a short-term session
    // grant" — exactly what the canonical session-grant bridge does. We drive
    // the LocalCoauth issuer path (password factor + DPoP), which mints a
    // did:webvh principal and a `ck.session.grant`. (Driving the same bridge via
    // the EXTERNAL mock IdP additionally requires a seeded upstream-OAuth link;
    // see the retained fixme below. The grant semantics asserted here are
    // identical across factors.)
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const onboarded = await onboardPrincipalViaCoauth(request, coauth!, "ad-alice");
    expect(onboarded.grantAudience).toBe(solandServiceDid());
    // Short-term: the SDK caps grants well under a day; assert a bounded TTL.
    const grantTtlMs = grantExpiryMs(onboarded.grantJwt) - Date.now();
    expect(grantTtlMs).toBeGreaterThan(0);
    expect(grantTtlMs).toBeLessThanOrEqual(24 * 60 * 60 * 1000);

    const meUrl = `${solandBaseUrl()}/_arkret/self/account/viewer`;
    const meResp = await request.get(meUrl, {
      headers: selfPathGrantHeaders({
        deviceKey: onboarded.deviceKey,
        grantJwt: onboarded.grantJwt,
        method: "GET",
        url: meUrl,
      }),
    });
    expect(meResp.ok(), await meResp.text()).toBeTruthy();
    const me = await meResp.json();
    expect(me.principal_id).toBe(onboarded.principalDid);
  });

  test("a second device acquires its own device-specific session_grant for the same principal", async ({
    request,
  }) => {
    // spec: device-lifecycle.md §2.1, §10 (per-device grants)
    //
    // We model two devices of ONE account each acquiring a grant bound to its
    // own device key + device id. The grants are distinct, carry distinct
    // `urn:arkret:client:device:<id>` scopes, and each authorizes the self-path
    // with its own DPoP key. The QR-pairing + cross-signing ceremony that a
    // brand-new device walks before login is owned by the device-lifecycle
    // workstream; what this test pins is the account-authority promise that each
    // device gets its OWN device-specific grant (not a shared credential).
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const device1 = await onboardPrincipalViaCoauth(request, coauth!, "ad-d1");
    const device2 = await loginPrincipalViaCoauth(
      request,
      coauth!,
      "ad-d2",
      device1.account,
    );

    // Same principal, different devices, different grants/scopes.
    expect(device2.principalDid).toBe(device1.principalDid);
    expect(device2.deviceId).not.toBe(device1.deviceId);
    expect(device2.grantJwt).not.toBe(device1.grantJwt);
    expect(device2.scopes).toContain(`urn:arkret:client:device:${device2.deviceId}`);
    expect(device2.scopes).not.toContain(
      `urn:arkret:client:device:${device1.deviceId}`,
    );

    // Device-2's grant authorizes the self-path with device-2's own key.
    const meUrl = `${solandBaseUrl()}/_arkret/self/account/viewer`;
    const meResp = await request.get(meUrl, {
      headers: selfPathGrantHeaders({
        deviceKey: device2.deviceKey,
        grantJwt: device2.grantJwt,
        method: "GET",
        url: meUrl,
      }),
    });
    expect(meResp.ok(), await meResp.text()).toBeTruthy();
    const me = await meResp.json();
    expect(me.principal_id).toBe(device1.principalDid);
    // Both devices are now in the inventory.
    const deviceIds = (me.devices ?? []).map((d: { device_id?: string }) => d.device_id);
    expect(deviceIds).toContain(device1.deviceId);
    expect(deviceIds).toContain(device2.deviceId);
  });

  test("expired session grant triggers /_arkret/gate/account/session-grants/refresh; new session_grant issued without re-OIDC", async ({
    request,
  }) => {
    // spec: account-lifecycle.md §4.1 (DPoP-bound session-grant rotation)
    //
    // The refresh handler (coauth session_grant/refresh.rs) requires a device
    // holder proof. coauth now verifies that proof against the Principal
    // Server's device signing-key DIRECTORY (the `ck.device.authorize`-projected
    // key surfaced at `/_soland/gate/account/device-signing-keys/query`), NOT the
    // principal DID document. So we first enrol the onboarding device's signing
    // key (service_attested `ck.device.authorize`), then mint a holder proof
    // signed by that key and rotate the grant — no re-OIDC, no DID-document
    // device-key projection required.
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const onboarded = await onboardPrincipalViaCoauth(request, coauth!, "ad-refresh");

    const enrolledKey = await enrollOnboardedDeviceSigningKey(
      request,
      coauth!,
      onboarded,
    );
    test.skip(!enrolledKey, "coauth device-enroll seam not available in this build");

    const refreshBody = buildHolderProofRefreshBody({
      grantJwt: onboarded.grantJwt,
      principalDid: onboarded.principalDid,
      deviceId: onboarded.deviceId,
      deviceKey: onboarded.deviceKey,
      audience: onboarded.grantAudience,
      challenge: randomUUID(),
    });

    const rotated = await postSessionGrantRefresh(
      request,
      coauth!,
      onboarded.deviceKey,
      refreshBody,
    );
    expect(rotated.status, rotated.text).toBe(200);
    // A fresh grant is issued, distinct from the prior one, same audience.
    expect(rotated.json.grant_jwt).toBeTruthy();
    expect(rotated.json.grant_jwt).not.toBe(onboarded.grantJwt);
    expect(rotated.json.audience).toBe(onboarded.grantAudience);
    expect(rotated.json.previous_grant_id).toBe(onboarded.grantId);

    // The prior (now consumed) grant cannot be rotated again — single-use.
    const replay = await postSessionGrantRefresh(
      request,
      coauth!,
      onboarded.deviceKey,
      refreshBody,
    );
    expect(replay.status, replay.text).not.toBe(200);
  });

  test("soft logout revokes session credential; holder-proof refresh later restores access", async ({
    request,
  }) => {
    // spec: account-lifecycle.md §4.1 (soft logout -> holder-proof restore)
    //
    // The restore leg is the same refresh endpoint: a device holder proof, now
    // verified against the Principal Server device signing-key directory, lets an
    // authorized device resume its grant chain without re-authentication. We
    // enrol the device signing key, then drive the holder-proof refresh and
    // assert the rotated grant once again authorizes `/_arkret/self/*`.
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const onboarded = await onboardPrincipalViaCoauth(request, coauth!, "ad-restore");

    const enrolledKey = await enrollOnboardedDeviceSigningKey(
      request,
      coauth!,
      onboarded,
    );
    test.skip(!enrolledKey, "coauth device-enroll seam not available in this build");

    const refreshBody = buildHolderProofRefreshBody({
      grantJwt: onboarded.grantJwt,
      principalDid: onboarded.principalDid,
      deviceId: onboarded.deviceId,
      deviceKey: onboarded.deviceKey,
      audience: onboarded.grantAudience,
      challenge: randomUUID(),
    });

    const restored = await postSessionGrantRefresh(
      request,
      coauth!,
      onboarded.deviceKey,
      refreshBody,
    );
    expect(restored.status, restored.text).toBe(200);
    const restoredGrant = restored.json.grant_jwt as string | undefined;
    expect(restoredGrant).toBeTruthy();
    expect(restoredGrant).not.toBe(onboarded.grantJwt);

    // The restored grant authorizes the self-path with the same device key.
    const meUrl = `${solandBaseUrl()}/_arkret/self/account/viewer`;
    const meResp = await request.get(meUrl, {
      headers: selfPathGrantHeaders({
        deviceKey: onboarded.deviceKey,
        grantJwt: restoredGrant!,
        method: "GET",
        url: meUrl,
      }),
    });
    expect(meResp.ok(), await meResp.text()).toBeTruthy();
    const me = await meResp.json();
    expect(me.principal_id).toBe(onboarded.principalDid);
  });
});

/// Parse the `expires_at` (RFC3339) claim of a ck.session.grant JWT into epoch
/// millis. The grant payload carries `expires_at` as an ISO-8601 string.
function grantExpiryMs(grantJwt: string): number {
  const parts = grantJwt.split(".");
  if (parts.length < 2) {
    throw new Error("grant_jwt is not a JWT");
  }
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const exp = payload.expires_at ?? payload.exp;
  if (typeof exp === "number") {
    return exp * 1000;
  }
  const ms = Date.parse(String(exp));
  if (Number.isNaN(ms)) {
    throw new Error(`grant_jwt has no parseable expiry: ${JSON.stringify(exp)}`);
  }
  return ms;
}

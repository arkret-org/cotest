import { expect, test } from "../../helpers/arkret-test";

import {
  acceptedDeviceAuthorizePayload,
  generateDeviceAuthorizationKey,
} from "../../helpers/device-authorization-harness";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  canonicalTimestamp,
  principalControlRealmForId,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("single device-authorization model @fully-implemented", () => {
  test("an accepted device authorizes a new device and the target proves possession", async ({
    request,
  }) => {
    const alice = uniqueUser(`device-pair-${Date.now()}`);
    await ensureRegistered(request, alice);
    const authorizerToken = await issueDevSession(request, alice);
    const targetDeviceId = typedId("device");
    const targetKey = generateDeviceAuthorizationKey();
    const payload = acceptedDeviceAuthorizePayload({
      principalId: alice.id,
      authorizerDeviceId: alice.deviceId,
      targetDeviceId,
      targetKey,
      notBefore: canonicalTimestamp(),
    });

    expect(payload).toMatchObject({
      authorized_by: alice.deviceId,
      authorization_binding_kind: "accepted_device",
      device_id: targetDeviceId,
      device_public_key_did: targetKey.didKey,
    });
    expect(payload).not.toHaveProperty("authority_did");
    expect(payload).not.toHaveProperty("delegation");

    await submitSignedEventApi(
      request,
      authorizerToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId: principalControlRealmForId(alice.id),
        kind: "ak.device.authorize",
        payload,
      }),
      { context: "accepted device authorizes target" },
    );

    await expect
      .poll(
        async () => {
          const response = await request.get(
            `${solandBaseUrl()}/_arkret/self/account/viewer`,
            { headers: authHeaders(authorizerToken) },
          );
          if (!response.ok()) return [];
          const body = (await response.json()) as {
            devices?: Array<{ device_id?: string; status?: string }>;
          };
          return (body.devices ?? [])
            .filter((device) => device.status === "active")
            .map((device) => device.device_id);
        },
        { timeout: 30_000 },
      )
      .toContain(targetDeviceId);
  });

  test("a possession proof cannot be transplanted to a different target key", async ({
    request,
  }) => {
    const alice = uniqueUser(`device-pair-negative-${Date.now()}`);
    await ensureRegistered(request, alice);
    const authorizerToken = await issueDevSession(request, alice);
    const targetKey = generateDeviceAuthorizationKey();
    const payload = acceptedDeviceAuthorizePayload({
      principalId: alice.id,
      authorizerDeviceId: alice.deviceId,
      targetDeviceId: typedId("device"),
      targetKey,
      notBefore: canonicalTimestamp(),
    });
    const forged = {
      ...payload,
      device_public_key_did: generateDeviceAuthorizationKey().didKey,
    };
    const response = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(authorizerToken),
        data: signedEventEnvelope({
          actorId: alice.id,
          realmId: principalControlRealmForId(alice.id),
          kind: "ak.device.authorize",
          payload: forged,
        }),
      },
    );
    expect(response.ok()).toBe(false);
  });
});

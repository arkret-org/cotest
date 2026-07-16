import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";

import {
  accountHandoffHeaders,
  createCanonicalAccountHandoff,
  registerUnboundCoauthPasswordAccount,
} from "../../helpers/coauth-register";
import { coauthBaseUrl, solandBaseUrl, solandServiceId } from "../../helpers/env";
import {
  dpopDeviceSeedB64url,
  generateDpopDeviceKey,
  mintDpopProof,
} from "../../helpers/session-grant-dpop";
import { cotestWire, typedId, wireErrCode } from "../../helpers/soland-api";

function deviceId(): string {
  return typedId("device");
}

function accountHandle(prefix: string): string {
  return `${prefix}-${randomUUID()}`.toLowerCase();
}

test.describe.configure({ mode: "serial" });

test.describe("canonical account handoff", () => {
  test("Principal Server pins the Account Authority enrollment DID", async ({ request }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const [principalResponse, authorityResponse] = await Promise.all([
      request.get(`${solandBaseUrl()}/_arkret/describe`),
      request.get(`${coauth}/_arkret/describe`),
    ]);
    expect(principalResponse.ok(), await principalResponse.text()).toBeTruthy();
    expect(authorityResponse.ok(), await authorityResponse.text()).toBeTruthy();
    const principal = await principalResponse.json();
    const authority = await authorityResponse.json();
    const expected = principal.auth_metadata?.account_authority?.enrollment_authority_did;
    const advertised = authority.auth_metadata?.account_authority?.enrollment_authority_did;
    expect(expected).toMatch(/^did:/);
    expect(advertised).toBe(expected);
  });

  test("same holder renews the lease while a second holder receives busy", async ({ request }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const account = await registerUnboundCoauthPasswordAccount(request, coauth!, {
      handle: accountHandle("handoff-lease"),
    });
    const device = deviceId();
    const firstKey = generateDpopDeviceKey();
    const first = await createCanonicalAccountHandoff(request, coauth!, {
      audience: solandServiceId(),
      deviceId: device,
      deviceKey: firstKey,
      account,
    });
    expect(first.binding.state).toBe("identity_creation_active");
    const firstLease = first.binding.identity_creation_lease as Record<string, unknown>;

    const renewed = await createCanonicalAccountHandoff(request, coauth!, {
      audience: solandServiceId(),
      deviceId: device,
      deviceKey: firstKey,
      account,
    });
    expect(renewed.binding.state).toBe("identity_creation_active");
    expect(renewed.binding.identity_creation_lease).toMatchObject({
      lease_id: firstLease.lease_id,
      fence: firstLease.fence,
    });

    const competing = await createCanonicalAccountHandoff(request, coauth!, {
      audience: solandServiceId(),
      deviceId: device,
      deviceKey: generateDpopDeviceKey(),
      account,
    });
    expect(competing.binding).toMatchObject({
      state: "identity_creation_busy",
      retry_after_ms: expect.any(Number),
    });
  });

  test("handoff authorization rejects a different key, htu, and ath", async ({ request }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const account = await registerUnboundCoauthPasswordAccount(request, coauth!, {
      handle: accountHandle("handoff-dpop"),
    });
    const handoff = await createCanonicalAccountHandoff(request, coauth!, {
      audience: solandServiceId(),
      deviceId: deviceId(),
      account,
    });
    const url = `${coauth}/_arkret/gate/account/identity-binding-challenges`;
    const wrongKey = generateDpopDeviceKey();
    const attempts = [
      mintDpopProof({
        deviceKey: wrongKey,
        method: "POST",
        url,
        grantJwt: handoff.accountHandoffGrant,
      }),
      mintDpopProof({
        deviceKey: handoff.deviceKey,
        method: "POST",
        url: `${coauth}/_arkret/gate/account/register`,
        grantJwt: handoff.accountHandoffGrant,
      }),
      mintDpopProof({
        deviceKey: handoff.deviceKey,
        method: "POST",
        url,
        grantJwt: handoff.accountHandoffGrant,
        athOverride: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      }),
    ];
    for (const dpop of attempts) {
      const response = await request.post(url, {
        data: {},
        headers: {
          authorization: `DPoP ${handoff.accountHandoffGrant}`,
          dpop,
        },
      });
      expect([401, 403], await response.text()).toContain(response.status());
    }
  });

  test("an unbound account session request returns 404 principal_unknown", async ({ request }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const account = await registerUnboundCoauthPasswordAccount(request, coauth!, {
      handle: accountHandle("handoff-unbound"),
    });
    const device = deviceId();
    const handoff = await createCanonicalAccountHandoff(request, coauth!, {
      audience: solandServiceId(),
      deviceId: device,
      account,
    });
    expect(handoff.binding.state).toBe("identity_creation_active");
    const body = cotestWire<Record<string, unknown>>("pre-registration-session-request", {
      principal_id: "did:webvh:z6mkfixture:unbound.example",
      device_id: device,
      requested_scope: [],
      account_handoff_grant: handoff.accountHandoffGrant,
      audience: solandServiceId(),
      expires_at: new Date(Date.now() + 4 * 60_000).toISOString(),
      dpop_seed_b64url: dpopDeviceSeedB64url(handoff.deviceKey),
    });
    const url = `${coauth}/_arkret/gate/account/session-grants`;
    const response = await request.post(url, {
      data: body,
      headers: accountHandoffHeaders({
        deviceKey: handoff.deviceKey,
        accountHandoffGrant: handoff.accountHandoffGrant,
        method: "POST",
        url,
      }),
    });
    const raw = await response.text();
    const error = raw ? JSON.parse(raw) : {};
    expect(response.status(), raw).toBe(404);
    expect(wireErrCode(error) ?? raw).toContain("principal_unknown");
  });
});

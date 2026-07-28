import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";

import {
  accountHandoffHeaders,
  createCanonicalAccountHandoff,
  registerUnboundCoauthPasswordAccount,
} from "../../helpers/coauth-register";
import {
  coauthBaseUrl,
  optionalEnv,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
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

type PrincipalRegistrationFixture = {
  did_operation: Record<string, unknown>;
  recovery_key: string;
  checkpoint: Record<string, unknown>;
  challenge_request: Record<string, unknown>;
};

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

  test("shared PostgreSQL makes challenge issue, replay, conflict, and consume cross-instance safe @fully-implemented", async ({
    request,
  }) => {
    const primary = coauthBaseUrl();
    const secondary = optionalEnv("COTEST_COAUTH_SECONDARY_BASE_URL")?.replace(/\/$/, "");
    test.skip(!primary, "coauth not started for this run");
    test.skip(
      !secondary,
      "start the joint harness with -DualCoauth to provision two Coauth processes over one PostgreSQL database",
    );

    const account = await registerUnboundCoauthPasswordAccount(request, primary!, {
      handle: accountHandle("handoff-cross-instance"),
    });
    const bootstrapDeviceId = deviceId();
    const handoff = await createCanonicalAccountHandoff(request, primary!, {
      audience: solandServiceId(),
      deviceId: bootstrapDeviceId,
      account,
    });
    expect(handoff.binding.state).toBe("identity_creation_active");
    const lease = handoff.binding.identity_creation_lease as Record<string, unknown>;
    expect(lease).toMatchObject({
      lease_id: expect.any(String),
      fence: expect.any(Number),
    });

    const [principalResponse, authorityResponse] = await Promise.all([
      request.get(`${solandBaseUrl()}/_arkret/describe`),
      request.get(`${primary}/_arkret/describe`),
    ]);
    expect(principalResponse.ok(), await principalResponse.text()).toBeTruthy();
    expect(authorityResponse.ok(), await authorityResponse.text()).toBeTruthy();
    const principalDescribe = (await principalResponse.json()) as Record<string, unknown>;
    const authorityDescribe = (await authorityResponse.json()) as Record<string, unknown>;
    const principalAuth = principalDescribe.auth_metadata as
      | { account_authority?: { enrollment_authority_did?: string } }
      | undefined;
    const authorityAuth = authorityDescribe.auth_metadata as
      | { account_authority?: { enrollment_authority_did?: string } }
      | undefined;
    const enrollmentAuthorityDid =
      principalAuth?.account_authority?.enrollment_authority_did;
    expect(enrollmentAuthorityDid).toMatch(/^did:/);
    expect(authorityAuth?.account_authority?.enrollment_authority_did).toBe(
      enrollmentAuthorityDid,
    );
    expect(principalDescribe.trust_domain).toMatch(/^ak:trust_domain:/);

    const fixture = cotestWire<PrincipalRegistrationFixture>(
      "principal-registration-fixture",
      {
        principal_server_url: solandBaseUrl(),
        gate_account_base: `${primary}/_arkret/gate/account`,
        handoff_request_id: handoff.requestId,
        identity_creation_lease: lease,
        device_id: bootstrapDeviceId,
        enrollment_authority_did: enrollmentAuthorityDid,
        trust_domain: principalDescribe.trust_domain,
      },
    );
    const challengePath = "/_arkret/gate/account/identity-binding-challenges";
    const publicChallengeUrl = `${primary}${challengePath}`;
    const issue = async (
      transportBase: string,
      body: Record<string, unknown>,
    ) =>
      request.post(`${transportBase}${challengePath}`, {
        data: body,
        // Both listeners intentionally share one configured public origin.
        // The proof binds that externally visible URI, while transportBase
        // selects which concrete Coauth process receives the request.
        headers: accountHandoffHeaders({
          deviceKey: handoff.deviceKey,
          accountHandoffGrant: handoff.accountHandoffGrant,
          method: "POST",
          url: publicChallengeUrl,
        }),
      });

    const issuedResponse = await issue(primary!, fixture.challenge_request);
    const issuedRaw = await issuedResponse.text();
    expect(issuedResponse.ok(), issuedRaw).toBeTruthy();
    const challenge = JSON.parse(issuedRaw) as Record<string, unknown>;
    expect(challenge).toMatchObject({
      challenge_id: expect.any(String),
      principal_id: fixture.checkpoint.did,
      dpop_jkt: handoff.deviceKey.thumbprint,
    });

    const replayResponse = await issue(secondary!, fixture.challenge_request);
    const replayRaw = await replayResponse.text();
    expect(replayResponse.ok(), replayRaw).toBeTruthy();
    expect(replayRaw).toBe(issuedRaw);

    const conflictingRequest = structuredClone(fixture.challenge_request);
    const originalFence = conflictingRequest.lease_fence;
    if (typeof originalFence !== "number") {
      throw new Error(
        `identity-binding challenge fixture omitted numeric lease_fence: ${JSON.stringify(conflictingRequest)}`,
      );
    }
    conflictingRequest.lease_fence = originalFence + 1;
    const conflictResponse = await issue(secondary!, conflictingRequest);
    const conflictRaw = await conflictResponse.text();
    expect(conflictResponse.status(), conflictRaw).toBe(409);
    expect(wireErrCode(JSON.parse(conflictRaw)) ?? conflictRaw).toContain(
      "duplicate_conflict",
    );

    const registerBody = cotestWire<Record<string, unknown>>(
      "identity-creation-register-request",
      {
        challenge,
        did_operation: fixture.did_operation,
        recovery_key: fixture.recovery_key,
        display_name: "Cross-instance account",
      },
    );
    const registerPath = "/_arkret/gate/account/register";
    const publicRegisterUrl = `${primary}${registerPath}`;
    const registeredResponse = await request.post(`${secondary}${registerPath}`, {
      data: registerBody,
      headers: accountHandoffHeaders({
        deviceKey: handoff.deviceKey,
        accountHandoffGrant: handoff.accountHandoffGrant,
        method: "POST",
        url: publicRegisterUrl,
      }),
    });
    const registeredRaw = await registeredResponse.text();
    expect(registeredResponse.ok(), registeredRaw).toBeTruthy();
    const registered = JSON.parse(registeredRaw) as {
      principal_id?: string;
      binding_receipt?: { binding_state?: string };
    };
    expect(registered).toMatchObject({
      principal_id: fixture.checkpoint.did,
      binding_receipt: { binding_state: "bound" },
    });

    const replayedRegisterResponse = await request.post(`${primary}${registerPath}`, {
      data: registerBody,
      headers: accountHandoffHeaders({
        deviceKey: handoff.deviceKey,
        accountHandoffGrant: handoff.accountHandoffGrant,
        method: "POST",
        url: publicRegisterUrl,
      }),
    });
    const replayedRegisterRaw = await replayedRegisterResponse.text();
    expect(replayedRegisterResponse.ok(), replayedRegisterRaw).toBeTruthy();
    expect(replayedRegisterRaw).toBe(registeredRaw);

    const renewedHandoff = await createCanonicalAccountHandoff(request, primary!, {
      audience: solandServiceId(),
      deviceId: bootstrapDeviceId,
      deviceKey: handoff.deviceKey,
      account,
    });
    expect(renewedHandoff.accountHandoffGrant).not.toBe(handoff.accountHandoffGrant);
    expect(renewedHandoff.binding).toMatchObject({
      state: "bound",
      principal_id: fixture.checkpoint.did,
    });
    const renewedGrantReplayResponse = await request.post(`${primary}${registerPath}`, {
      data: registerBody,
      headers: accountHandoffHeaders({
        deviceKey: renewedHandoff.deviceKey,
        accountHandoffGrant: renewedHandoff.accountHandoffGrant,
        method: "POST",
        url: publicRegisterUrl,
      }),
    });
    const renewedGrantReplayRaw = await renewedGrantReplayResponse.text();
    expect(renewedGrantReplayResponse.ok(), renewedGrantReplayRaw).toBeTruthy();
    expect(renewedGrantReplayRaw).toBe(registeredRaw);

    const conflictingRegisterBody = structuredClone(registerBody);
    conflictingRegisterBody.display_name = "Changed after challenge consumption";
    const consumedChallengeReuse = await request.post(`${primary}${registerPath}`, {
      data: conflictingRegisterBody,
      headers: accountHandoffHeaders({
        deviceKey: handoff.deviceKey,
        accountHandoffGrant: handoff.accountHandoffGrant,
        method: "POST",
        url: publicRegisterUrl,
      }),
    });
    const consumedChallengeReuseRaw = await consumedChallengeReuse.text();
    expect(
      consumedChallengeReuse.ok(),
      consumedChallengeReuseRaw,
    ).toBeFalsy();
    expect(
      wireErrCode(JSON.parse(consumedChallengeReuseRaw)) ??
        consumedChallengeReuseRaw,
    ).toContain("duplicate_conflict");
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
